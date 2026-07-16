package main

import (
	"fmt"

	"github.com/xen0bit/veepin/internal/ikev2/probe"
)

// runProbe drives a diagnostic exchange against a running server: handshake,
// address assignment, and one data packet. Unlike connect it needs no TUN device
// and no privileges.
func runProbe(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: veepin probe <protocol> [flags]\nprotocols: ikev2")
	}
	protocol, args := args[0], args[1:]
	if protocol != "ikev2" {
		return fmt.Errorf("unknown protocol %q (available: ikev2)", protocol)
	}
	return probe.Run(args)
}
