package main

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/signal"

	"context"
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 tracer tracer.c

func main()  {

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	var objs tracerObjects
	if err := loadTracerObjects(&objs, nil); err != nil{
		log.Print("Error loading eBPF objects:", err)
	}

	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.tracerPrograms.PrintOnExecveCall, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}

	//loop over /sys/kernel/debug/tracing/trace_pipe
	//seems the kernel sends tp events to this file so we can just read the file as we move along.
	const traceEventFileName = "/sys/kernel/debug/tracing/trace_pipe"
	traceEventFile, err := os.Open(traceEventFileName)
	if err != nil{
		log.Fatalf("error occurred whilst opening file %s: %s\n", traceEventFileName, err)
	}

	var fileScanner = bufio.NewScanner(traceEventFile)

	
	go func(){
		for fileScanner.Scan(){
			fmt.Println(fileScanner.Text())
		}
		if err := fileScanner.Err(); err != nil {
			if !errors.Is(err, fs.ErrClosed) {
				log.Println(err)
			}
		}
	}()

	defer tp.Close()

	<-ctx.Done()
}