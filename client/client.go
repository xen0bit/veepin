// Package client is the protocol-agnostic entry point for bringing up a VPN
// tunnel. It defines what every protocol produces — a Session and a Result —
// and a registry that dials one by name.
//
// It deliberately does NOT install addresses, routes or DNS: Dial returns the
// negotiated Result and the caller applies it. That is what lets the same dial
// path serve both the veepin command (which hands Result to dataplane's router)
// and the NetworkManager plugin (which hands Result to NM).
//
// Two ways in, for two kinds of caller:
//
//   - Go code that knows which protocol it wants uses the protocol package
//     directly and gets a typed config: ikev2.Dial(ctx, ikev2.Config{...}).
//   - Callers whose parameters arrive as strings — the CLI's flags, the NM
//     plugin's settings dictionary — use client.Dial(ctx, "ikev2", opts) and let
//     the registry parse them.
//
// Protocols register themselves in an init function, so a caller selects the
// protocols it can dial by importing them:
//
//	import _ "github.com/xen0bit/veepin/ikev2"
//
// The server side mirrors this exactly (see server.go): a protocol that can act
// as a responder registers with RegisterServer and is built by NewServer, so the
// veepin command dispatches `connect` and `serve` through the same registry
// shape. Not every protocol registers both — some are client-only — so Protocols
// and ServerProtocols are distinct sets.
//
// This package is CGO-free and depends only on the standard library, so it is
// safe to embed in the core binaries and to import from the separate nm/ module.
package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
)

// ErrAuth wraps a handshake failure caused by rejected credentials (a wrong PSK
// or EAP password). A Dial error satisfies errors.Is(err, ErrAuth), letting
// callers distinguish a bad password from a transport failure.
var ErrAuth = errors.New("authentication failed")

// ErrUnknownProtocol is returned by Dial when no protocol is registered under
// the requested name — usually a missing blank import of the protocol package.
var ErrUnknownProtocol = errors.New("unknown protocol")

// DefaultTunnelMTU is a conservative MTU for the inner interface. Tunnelling
// over a 1500-byte path leaves room for the outer IP+UDP+encapsulation
// overhead; 1400 is the customary safe value and avoids inner-path
// fragmentation. Protocols may report a different MTU in Result.
const DefaultTunnelMTU = 1400

// Result is the negotiated configuration a caller must apply to the system for
// the tunnel to carry traffic: the interface, its assigned address, the server
// gateway (for a host route so encapsulated packets do not recurse into the
// tunnel), and DNS.
type Result struct {
	// TUNName is the interface the data path is bound to (e.g. "tun0").
	TUNName string
	// AssignedIP is the internal address the server assigned. The caller adds
	// it to TUNName, which also creates the connected route for the tunnel
	// subnet -- so an address inside the tunnel needs no route of its own.
	AssignedIP net.IP
	// Netmask is the internal address's netmask, and with AssignedIP determines
	// the connected route above.
	Netmask net.IP

	// Gateway is the server's OUTER address -- the one the client dialled, on
	// the underlying network. It is not an address inside the tunnel.
	//
	// The caller pins a host route to it through the physical interface, so
	// that encapsulated packets are not themselves routed into the tunnel. That
	// is the only thing it is used for, and it is why the outer address is the
	// only correct value: a host route to an inner address would send the very
	// traffic the tunnel carries out the wrong interface.
	//
	// Nil is legitimate and means "install no host route". A mesh protocol
	// wants this -- peers are reached directly at many different underlay
	// addresses, so there is no single one to pin (see the nebula package).
	//
	// Getting this wrong is silent: the handshake succeeds, the interface comes
	// up, and every packet leaves by the wrong door. Validate catches the
	// common mistake of filling in an inner address.
	Gateway net.IP
	// DNS holds the internal DNS servers, if the server offered any.
	DNS []net.IP
	// MTU is the recommended inner-interface MTU.
	MTU int
}

// Validate reports configurations that cannot be right, so a protocol that
// fills in Result incorrectly is told rather than silently misrouting traffic.
//
// It is advisory. Callers are expected to log what it returns and continue: a
// protocol may have a reason for something unusual, and refusing to bring up a
// working tunnel over a heuristic would be worse than the mistake it catches.
//
// The check that earns its place is the Gateway one. That field is the server's
// outer address, and filling in an address from inside the tunnel instead
// produces a host route that sends the tunnel's own traffic out the physical
// interface -- a failure with no symptom except that nothing crosses. It is a
// mistake made twice while this tree was being written, in two protocols, and
// it is mechanically detectable.
func (r Result) Validate() error {
	if r.TUNName == "" {
		return errors.New("client: result names no interface")
	}
	if r.AssignedIP == nil {
		return errors.New("client: result assigns no address")
	}
	if r.MTU < 0 {
		return fmt.Errorf("client: result MTU is negative (%d)", r.MTU)
	}

	// Gateway is optional; nil means "no host route", which a mesh wants.
	if r.Gateway != nil && r.Netmask != nil {
		if v4, mask := r.AssignedIP.To4(), net.IP(r.Netmask).To4(); v4 != nil && mask != nil {
			subnet := net.IPNet{IP: v4.Mask(net.IPMask(mask)), Mask: net.IPMask(mask)}
			if subnet.Contains(r.Gateway) {
				return fmt.Errorf(
					"client: Gateway %s is inside the tunnel subnet %s; it must be the server's outer address, "+
						"or nil for a protocol with no single peer to route to",
					r.Gateway, subnet.String())
			}
		}
	}
	return nil
}

// Session is a running tunnel. Close tears it down and is safe to call from any
// goroutine; Wait blocks until that happens or ctx is cancelled.
type Session interface {
	Wait(ctx context.Context) error
	Close() error
}

// Dialer establishes one tunnel. A protocol's parsed options produce a Dialer,
// which Dial then runs.
type Dialer interface {
	// Dial performs the handshake and starts the data path, returning a running
	// Session and the Result the caller must apply. It installs no routes or
	// addresses. On error nothing is left running.
	Dial(ctx context.Context) (Session, Result, error)
}

// ParseFunc turns a protocol's string-keyed options into a Dialer, reporting an
// error for missing or malformed values.
type ParseFunc func(opts map[string]string) (Dialer, error)

var (
	mu        sync.RWMutex
	protocols = map[string]ParseFunc{}
)

// Register makes a protocol dialable by name. It is intended to be called from
// a protocol package's init function, and panics on a duplicate or empty name —
// both are programming errors, detected at startup.
func Register(protocol string, parse ParseFunc) {
	if protocol == "" {
		panic("client: Register with an empty protocol name")
	}
	if parse == nil {
		panic("client: Register with a nil ParseFunc for " + protocol)
	}
	mu.Lock()
	defer mu.Unlock()
	if _, dup := protocols[protocol]; dup {
		panic("client: protocol registered twice: " + protocol)
	}
	protocols[protocol] = parse
}

// Protocols lists the registered protocol names, sorted. Useful for CLI help
// and error messages.
func Protocols() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(protocols))
	for name := range protocols {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Dial brings up a tunnel with the named protocol, parsing opts through that
// protocol's registered ParseFunc.
//
// The context bounds setup only; once Dial returns, the tunnel's lifetime is
// the Session's.
func Dial(ctx context.Context, protocol string, opts map[string]string) (Session, Result, error) {
	mu.RLock()
	parse, ok := protocols[protocol]
	mu.RUnlock()
	if !ok {
		return nil, Result{}, fmt.Errorf("client: %w %q (registered: %v)",
			ErrUnknownProtocol, protocol, Protocols())
	}
	dialer, err := parse(opts)
	if err != nil {
		return nil, Result{}, fmt.Errorf("client: %s: %w", protocol, err)
	}
	return dialer.Dial(ctx)
}
