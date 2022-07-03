//go:build linux
// +build linux

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf bpf/hello.bpf.c

import (
	"C"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)
import (
	"bufio"
	"fmt"

	"github.com/cilium/ebpf"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

const mapKey uint32 = 0

func TracePrint() {
	f, err := os.Open("/sys/kernel/debug/tracing/trace_pipe")
	if err != nil {
		fmt.Println("TracePrint failed to open trace pipe: %v", err)
		return
	}
	r := bufio.NewReader(f)
	b := make([]byte, 1000)
	for {
		len, err := r.Read(b)
		if err != nil {
			fmt.Println("TracePrint failed to read from trace pipe: %v", err)
			return
		}
		s := string(b[:len])
		fmt.Println(s)
	}
}

func main() {
	fn := "sys_execve"
	fnTcpConnect := "tcp_v4_connect"
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	must(rlimit.RemoveMemlock())

	objs := bpfObjects{}

	must(loadBpfObjects(&objs, nil))
	defer objs.Close()

	kp, err := link.Kprobe(fn, objs.Hello, nil)
	must(err)
	defer kp.Close()

	// kpTC, err := link.Kprobe(fnTcpConnect, objs.Tcpconnect, nil)
	kpTC, err := link.Kprobe(fnTcpConnect, &ebpf.Program{}, nil)
	must(err)
	defer kpTC.Close()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Println("Waiting for events..")

	go TracePrint()
	<-sig

}
