package main

import (
	"fmt"
)

type SockAddr struct {
	ProcessName string
	Port        uint16
}

func dropOtherPorts(ctx SockAddr, allowed map[string]uint16) bool {
	if port, ok := allowed[ctx.ProcessName]; ok {
		if ctx.Port == port {
			return true
		}
		return false
	}
	return true
}
func main() {
	allowed := map[string]uint16{
		"myprocess": 4040,
	}
	tests := []SockAddr{
		{"myprocess", 4040},
		{"myprocess", 9090},
		{"otherproc", 8080},
	}
	for _, t := range tests {
		if dropOtherPorts(t, allowed) {
			fmt.Printf("ALLOW: %s -> %d\n", t.ProcessName, t.Port)
		} else {
			fmt.Printf("DROP: %s -> %d\n", t.ProcessName, t.Port)
		}
	}
}
