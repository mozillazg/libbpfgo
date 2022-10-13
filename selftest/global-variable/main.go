package main

import (
	"fmt"
	"os"
	"time"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

type GoRodata struct {
	foo int64
	bar int64
	baz int64
}

func exitWithErr(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(-1)
}

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		exitWithErr(err)
	}
	defer bpfModule.Close()

	rodataMap, err := bpfModule.GetMap("main.rodata") //TODO: should be able to iterate over maps to find instead of by name
	if err != nil {
		exitWithErr(err)
	}

	x := GoRodata{6, 443, 333}
	err = rodataMap.SetROData(unsafe.Pointer(&x), unsafe.Sizeof(x))
	if err != nil {
		exitWithErr(err)
	}

	if err := bpfModule.BPFLoadObject(); err != nil {
		exitWithErr(err)
	}

	time.Sleep(time.Hour)
}
