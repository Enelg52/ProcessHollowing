package main

import (
	"flag"

	runpe "github.com/abdullah2993/go-runpe"
)

func main() {
	var src, dest string
	var console bool
	flag.StringVar(&src, "src", "C:\\Windows\\system32\\calc.exe", "Source executable")
	flag.StringVar(&dest, "dest", "C:\\Windows\\system32\\cmd.exe", "Destination executable")
	flag.BoolVar(&console, "console", true, "Create the process with the flag CREATE_NEW_CONSOLE (useful for process like cmd.exe)")
	flag.Parse()
	runpe.Inject(src, dest, console)
}
