package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

var bpfprogramFile string = "../bpf/hello.bpf.o"

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func getTracepointID(eventName string) (uint64, error) {
	data, err := ioutil.ReadFile("/sys/kernel/debug/tracing/events/kprobes/" + eventName + "/id")
	if err != nil {
		return 0, fmt.Errorf("failed to read tracepoint ID for 'sys_enter_open': %v", err)
	}
	tid := strings.TrimSuffix(string(data), "\n")
	return strconv.ParseUint(tid, 10, 64)
}

func createTracepoint(eventName string) error {

	sysFile := "/sys/kernel/debug/tracing/kprobe_events"
	// sysFile := "./hello.txt"

	var out = "p:kprobes/" + eventName + "_est123 " + eventName
	// fmt.Println("Create event buff:", out)

	f, err := os.OpenFile(sysFile,
		os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		log.Println(err)
	}
	defer f.Close()

	if _, err := f.WriteString(out); err != nil {
		log.Printf("Bad: %v\n\n", err)
	}

	file, err := os.Open("/sys/kernel/debug/tracing/kprobe_events")

	if err != nil {
		log.Fatalf("failed to open")

	}

	scanner := bufio.NewScanner(file)

	scanner.Split(bufio.ScanLines)
	var text []string

	for scanner.Scan() {
		text = append(text, scanner.Text())
	}

	file.Close()
	for _, each_ln := range text {
		fmt.Println(each_ln)
	}
	/*
		f, err := os.OpenFile("/sys/kernel/debug/tracing/kprobe_events", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("Hello: %v", err)
			return err
		}
		if _, err := f.Write([]byte(out)); err != nil {
			log.Printf("Hello2: %v", err)
			return err
		}
		if err := f.Close(); err != nil {
			log.Printf("Hello3: %v", err)
			return err
		}
	*/

	// if err := ioutil.WriteFile("/sys/kernel/debug/tracing/kprobe_events", []byte(out), 0640); err != nil {
	// 	return err
	// }

	return nil
}

func main() {

	must(rlimit.RemoveMemlock())

	program, err := ioutil.ReadFile(bpfprogramFile)
	must(err)

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(program))
	must(err)

	coll, err := ebpf.NewCollection(spec)
	must(err)

	prog := coll.DetachProgram("hello")
	if prog == nil {
		panic("no program named hello found")
	}
	defer prog.Close()

	fmt.Println("Program file descriptor: ", prog.FD())

	must(createTracepoint("hello"))

	// eid, errGetTr := getTracepointID("hello_est123")
	// must(errGetTr)

	//Check
	/*attr := unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_TRACEPOINT,
		Config:      eid,
		Sample_type: unix.PERF_SAMPLE_RAW,
		Sample:      1,
		Wakeup:      1,
	}
	efd, err := unix.PerfEventOpen(&attr, -1, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		panic("Unable to open perf events:" + err.Error())
	}

	if _, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(efd), unix.PERF_EVENT_IOC_ENABLE, 0); err != 0 {
		panic("Unable to enable perf events:" + err.Error())
	}
	if _, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(efd), unix.PERF_EVENT_IOC_SET_BPF, uintptr(prog.FD())); err != 0 {
		panic("Unable to attach bpf program to perf events:" + err.Error())
	}
	for {
		fmt.Println("Waiting...")
		time.Sleep(10 * time.Second)
	}
	*/

}
