package client

import (
	"fmt"
	"net"
	"sort"
	"sync"
)

// Server is the protocol-agnostic view of a VPN server the veepin command drives.
// It mirrors the client side: where a Dialer produces a Session, a protocol's
// server package produces a Server. The command constructs one via NewServer,
// reads its tunnel networking to configure the host (address, forwarding, NAT),
// then runs it with ListenAndServe until Close.
//
// The split between construction and ListenAndServe is deliberate and matches the
// client's "Dial installs no routes" contract: NewServer opens the TUN and
// validates configuration but binds nothing and changes no host state, so the
// caller owns host networking. Both ikev2.Server and wireguard.Server satisfy it.
type Server interface {
	// ListenAndServe binds the protocol's sockets and serves clients until the
	// server is closed. It blocks.
	ListenAndServe() error
	// Close stops the server and releases the TUN and sockets.
	Close() error
	// TUNName is the name of the opened TUN interface.
	TUNName() string
	// Gateway is the server's own address inside the tunnel — the address clients
	// use as their gateway, and what the host route/NAT setup is anchored on.
	Gateway() net.IP
	// Network is the tunnel subnet the server assigns client addresses from.
	Network() *net.IPNet
}

// ServerParseFunc turns a protocol's string-keyed options into a constructed
// (not yet listening) Server, reporting an error for missing or malformed values.
// It is the server-side counterpart of ParseFunc.
type ServerParseFunc func(opts map[string]string) (Server, error)

var (
	serverMu    sync.RWMutex
	serverParse = map[string]ServerParseFunc{}
)

// RegisterServer makes a protocol serveable by name. Like Register, it is meant
// to be called from a protocol package's init function and panics on a duplicate
// or empty name — both are programming errors, detected at startup.
func RegisterServer(protocol string, parse ServerParseFunc) {
	if protocol == "" {
		panic("client: RegisterServer with an empty protocol name")
	}
	if parse == nil {
		panic("client: RegisterServer with a nil ServerParseFunc for " + protocol)
	}
	serverMu.Lock()
	defer serverMu.Unlock()
	if _, dup := serverParse[protocol]; dup {
		panic("client: server protocol registered twice: " + protocol)
	}
	serverParse[protocol] = parse
}

// ServerProtocols lists the protocols that can run as a server, sorted. Not every
// protocol that can Dial can also serve, so this is a distinct set from
// Protocols.
func ServerProtocols() []string {
	serverMu.RLock()
	defer serverMu.RUnlock()
	names := make([]string, 0, len(serverParse))
	for name := range serverParse {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// NewServer constructs a server for the named protocol from its options, parsing
// opts through that protocol's registered ServerParseFunc. The returned Server
// has its TUN open but is not yet listening: the caller configures host
// networking, then calls ListenAndServe.
func NewServer(protocol string, opts map[string]string) (Server, error) {
	serverMu.RLock()
	parse, ok := serverParse[protocol]
	serverMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("client: %w %q (server protocols: %v)",
			ErrUnknownProtocol, protocol, ServerProtocols())
	}
	srv, err := parse(opts)
	if err != nil {
		return nil, fmt.Errorf("client: %s: %w", protocol, err)
	}
	return srv, nil
}
