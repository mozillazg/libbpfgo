package main

import "C"

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	bpf "github.com/aquasecurity/libbpfgo"
)

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

	err = bpfModule.BPFLoadObject()
	if err != nil {
		exitWithErr(err)
	}

	prog, err := bpfModule.GetProgram("iter__task")
	if err != nil {
		exitWithErr(err)
	}

	link, err := prog.AttachIter(bpf.IterOpts{})
	if err != nil {
		exitWithErr(err)
	}

	reader, err := link.Reader()
	if err != nil {
		exitWithErr(err)
	}
	defer reader.Close()

	for i := 0; i < 10; i++ {
		cmd := exec.Command("ping", "-w", "15", "bing.com")
		err := cmd.Start()
		if err != nil {
			exitWithErr(err)
		}
	}

	numberOfEventsReceived := 0
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) != 3 {
			fmt.Fprintf(os.Stderr, "invalid data retrieved\n")
		}
		if fields[2] == "ping" {
			numberOfEventsReceived++
		}
		if numberOfEventsReceived > 5 {
			break
		}
	}
	if numberOfEventsReceived <= 5 {
		err := fmt.Errorf("expect numberOfEventsReceived > 5 but got %d\n", numberOfEventsReceived)
		exitWithErr(err)
	}
}
