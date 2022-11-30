//go:build linux
// +build linux

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf bpf/hello.bpf.c -- -Ilibbpf/src

import (
	"C"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)
import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"unsafe"
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

// htons converts the unsigned short integer hostshort from host byte order to network byte order.
func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func main() {
	fn := "sys_execve"
	fnTcpConnect := "tcp_v4_connect"
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	must(rlimit.RemoveMemlock())

	objs := bpfObjects{}
	// objs.MyMap.Put()

	must(loadBpfObjects(&objs, nil))
	defer objs.Close()

	kp, err := link.Kprobe(fn, objs.Hello, nil)
	must(err)
	defer kp.Close()

	kpTC, err := link.Kprobe(fnTcpConnect, objs.Tcpconnect, nil)
	// kpTC, err := link.Kprobe(fnTcpConnect, , nil)
	must(err)
	defer kpTC.Close()

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, int(htons(syscall.ETH_P_ALL)))
	must(err)
	ifaceIndex := 0
	ifaceDocker := 0
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if strings.Contains(iface.Name, "wlp") {
			ifaceIndex = iface.Index
			break
		}

	}

	for _, iface := range ifaces {
		if strings.Contains(iface.Name, "br-17") {
			ifaceDocker = iface.Index
			break
		}

	}

	sll := syscall.SockaddrLinklayer{
		Ifindex:  ifaceIndex, //ip link show -> get the index number of the interface
		Protocol: htons(syscall.ETH_P_ALL),
	}

	err = syscall.Bind(fd, &sll)
	must(err)

	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, 50, objs.SocketFilter.FD())
	must(err)

	log.Printf("Attaching to ifnterface with index %v", ifaceIndex)
	iface, err := net.InterfaceByIndex(ifaceIndex)
	must(err)
	lxdp, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpBlock,
		Interface: iface.Index,
	})
	defer lxdp.Close()

	log.Printf("Attaching to docker ifnterface with index %v", ifaceDocker)
	iface2, err := net.InterfaceByIndex(ifaceDocker)
	must(err)
	lxdpDocker, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpBlock,
		Interface: iface2.Index,
	})
	defer lxdpDocker.Close()

	must(err)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Println("Waiting for events..")

	// go TracePrint()
	<-sig

}
