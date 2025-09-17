package main

import (
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func ifaceIndex(name string) int {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		log.Fatalf("lookup network iface %q: %v", name, err)
	}
	return iface.Index
}

func main() {
	spec, err := ebpf.LoadCollectionSpec("drop_port.o")
	if err != nil {
		log.Fatal(err)
	}

	objs := struct {
		DropTcpPort *ebpf.Program `ebpf:"drop_tcp_port"`
		BlockedPort *ebpf.Map     `ebpf:"blocked_port"`
	}{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.DropTcpPort.Close()

	key := uint32(0)
	val := uint16(4040)
	if err := objs.BlockedPort.Put(key, val); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Blocking TCP port:", val)

	iface := "lo"
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.DropTcpPort,
		Interface: ifaceIndex(iface),
	})
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	select {}
}
