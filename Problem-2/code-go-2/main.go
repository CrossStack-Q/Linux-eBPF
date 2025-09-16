package main

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {

	spec, err := ebpf.LoadCollectionSpec("drop_process.o")

	if err != nil {
		log.Fatal(err)
	}

	objs := struct {
		DropOtherPorts *ebpf.Program `ebpf:"drop_other_ports"`
		ProcPort       *ebpf.Map     `ebpf:"proc_port"`
	}{}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatal(err)
	}

	defer objs.DropOtherPorts.Close()

	procName := [16]byte{}

	copy(procName[:], "myprocess")

	port := uint16(4040)

	if err := objs.ProcPort.Put(procName, port); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Restricting process 'myprocess' to port:", port)

	cgroupPath := "/sys/fs/cgroup/mygroup"

	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objs.DropOtherPorts,
	})

	if err != nil {
		log.Fatal(err)
	}

	defer l.Close()

	select {}

}
