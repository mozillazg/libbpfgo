package main

import (
	"fmt"
	"os"
	"time"

	bpf "github.com/aquasecurity/libbpfgo"
)

func exitWithErr(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(-1)
}

type Event struct {
	A uint64
	B [6]byte
}

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		exitWithErr(err)
	}
	defer bpfModule.Close()

	if err := bpfModule.InitGlobalVariable("abc", uint32(20)); err != nil {
		exitWithErr(err)
	}
	if err := bpfModule.InitGlobalVariable("efg", uint32(32)); err != nil {
		exitWithErr(err)
	}
	foobar := Event{uint64(3), [6]byte{'a', 'b'}}
	if err := bpfModule.InitGlobalVariable("foobar", foobar); err != nil {
		exitWithErr(err)
	}
	if err := bpfModule.InitGlobalVariable("foo", uint64(1024)); err != nil {
		exitWithErr(err)
	}
	if err := bpfModule.InitGlobalVariable("bar", uint32(233)); err != nil {
		exitWithErr(err)
	}
	if err := bpfModule.InitGlobalVariable("baz", uint32(666)); err != nil {
		exitWithErr(err)
	}
	if err := bpfModule.InitGlobalVariable("qux", uint32(888)); err != nil {
		exitWithErr(err)
	}

	if err := bpfModule.BPFLoadObject(); err != nil {
		exitWithErr(err)
	}

	time.Sleep(time.Hour * 12)
}
