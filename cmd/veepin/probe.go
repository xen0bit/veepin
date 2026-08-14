package main

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/internal/ikev2/probe"
)

// runProbe answers one question — does the handshake work — without touching
// the host's routing table, its resolvers, or anything else it would have to be
// trusted to put back.
//
// It used to name one protocol of seventeen:
//
//	if protocol != "ikev2" {
//	    return fmt.Errorf("unknown protocol %q (available: ikev2)", protocol)
//	}
//
// while main.go's usage block and the README both presented it as a subcommand
// taking a protocol, in the same shape as connect and serve, which are generic
// over the registry. The question it answers is worth answering for the other
// sixteen.
//
// # Why ikev2 keeps its own path
//
// The generic implementation is `connect` with routing skipped: dial, report
// the Result, close. That needs a TUN, and therefore CAP_NET_ADMIN.
// internal/ikev2/probe predates it and does the exchange with no TUN at all, so
// it runs unprivileged -- which is a strictly better answer to "does the
// handshake work" and the reason it was written. Collapsing it into the generic
// path to save a branch would take that away from the one protocol that has it,
// so the branch stays and says why.
func runProbe(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: veepin probe <protocol> [flags]\nprotocols: %s",
			strings.Join(client.Protocols(), ", "))
	}
	protocol, args := args[0], args[1:]
	if !knownProtocol(protocol) {
		return fmt.Errorf("unknown protocol %q (available: %s)",
			protocol, strings.Join(client.Protocols(), ", "))
	}
	if protocol == "ikev2" {
		return probe.Run(args)
	}

	fs := flag.NewFlagSet("probe "+protocol, flag.ContinueOnError)
	timeout := fs.Duration("timeout", 30*time.Second,
		"give up if the handshake has not completed in this long")
	logCfg := bindLogFlags(fs)
	options, err := connectFlags(protocol, fs)
	if err != nil {
		return err
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	logger, err := logCfg.logger()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	start := time.Now()
	sess, res, err := client.Dial(ctx, protocol, options())
	if err != nil {
		return fmt.Errorf("probe %s: %w", protocol, err)
	}
	// Closed immediately and unconditionally. A probe that leaves a tunnel up
	// is a connect with a worse name, and the whole point is that it changes
	// nothing -- so the close is a defer as well, in case a report line panics.
	defer sess.Close()

	logger.Printf("probe %s: handshake completed in %s", protocol, time.Since(start).Round(time.Millisecond))
	logger.Printf("  interface   %s", res.TUNName)
	logger.Printf("  address     %s (netmask %s)", res.AssignedIP, res.Netmask)
	if res.AssignedIP6 != nil {
		logger.Printf("  address6    %s/%d", res.AssignedIP6, res.Prefix6)
	}
	logger.Printf("  gateway     %s (the server's OUTER address)", res.Gateway)
	logger.Printf("  DNS         %v", res.DNS)
	logger.Printf("  MTU         %d", res.MTU)
	if res.Layer2 {
		logger.Printf("  layer 2     the interface carries Ethernet frames, not IP")
	}
	// Reported rather than fatal, exactly as connect treats it: a protocol may
	// have a reason for something unusual, and this is a diagnostic -- saying
	// what looks wrong is the whole job.
	if err := res.Validate(); err != nil {
		logger.Printf("  WARNING     %v", err)
	}
	logger.Printf("probe %s: no routes, addresses or resolvers were changed", protocol)
	return nil
}
