package client

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"
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

// DualStackServer is an optional Server capability: a server that also assigns
// clients an IPv6 address inside the tunnel, and therefore needs the host
// configured for it -- an address on the interface, forwarding, and NAT.
//
// It is optional rather than part of Server because one protocol of seventeen
// has it (ikev2's config mode), and widening Server would make every other
// facade answer a question it has no answer to.
//
// The types are netip rather than the net.IP/*net.IPNet of Gateway/Network
// above, which is a deliberate inconsistency: the v4 pair predates netip and
// changing it would touch every facade, while the v6 pair is netip at its
// source (dataplane.AddrPool6) and at its only consumer. Converting at this
// boundary would mean converting back, and netip.Prefix additionally has a zero
// value a caller can test -- IsValid -- where a nil *net.IPNet reads as an
// absent field and a bug equally well.
type DualStackServer interface {
	// Gateway6 is the server's own address inside the tunnel's IPv6 subnet. It
	// is the zero Addr when this server was configured without a v6 pool.
	Gateway6() netip.Addr
	// Network6 is the IPv6 subnet client addresses come from, or the zero
	// Prefix.
	Network6() netip.Prefix
}

// ServerParseFunc turns a protocol's string-keyed options into a constructed
// (not yet listening) Server, reporting an error for missing or malformed values.
// It is the server-side counterpart of ParseFunc.
type ServerParseFunc func(opts map[string]string) (Server, error)

var (
	serverMu    sync.RWMutex
	serverParse = map[string]ServerParseFunc{}
)

// OptSpec is metadata about one key a protocol accepts in its options map. The
// supervisor and management panel face use it to enumerate a protocol's surface
// -- render a form, validate an upload, redact secrets -- without constructing
// an instance, which (because NewServer opens a TUN) the panel cannot do.
//
// A spec is a static description of the protocol's surface. Its Key is the same
// string the Opt* const carries; it does not need to be echoed here from the
// facade code as a name, only as a value. Required marks the keys the parse
// function refuses to run without, so the panel can mark them required on the
// form. Secret marks the keys the management API redacts on read -- those that
// hold protocol keys, passphrases, and PSKs -- so a `curl /api/listeners/site-a`
// cannot leak them by accident.
type OptSpec struct {
	Key      string  `json:"key"`
	Help     string  `json:"help,omitempty"`
	Kind     OptKind `json:"kind,omitempty"`
	Required bool    `json:"required,omitempty"`
	Secret   bool    `json:"secret,omitempty"`
	Default  string  `json:"default,omitempty"`
	Generate string  `json:"generate,omitempty"`

	// Flag is the command-line spelling when it differs from Key. ikev2's key
	// is "gateway" and its flag has always been -server; renaming either would
	// break every runbook or every profile on disk, so the mapping is declared
	// here rather than inferred.
	//
	// Empty means the two are the same, which is the overwhelming majority.
	// It is deliberately not serialised: it is a fact about the command line,
	// and the management API and panel speak in keys.
	Flag string `json:"-"`
}

// OptKind is the panel-side type of an option value. It is loose -- the server
// parse functions read everything as string -- so that the kind is only a
// rendering hint, never a parse concern. A value sent over the API still
// arrives as a string the underlying protocol accepts as-is.
type OptKind string

const (
	OptStr       OptKind = "string"
	OptInt       OptKind = "int"
	OptBool      OptKind = "bool"
	OptCIDR      OptKind = "cidr"
	OptFilePath  OptKind = "file"
	OptCommaList OptKind = "list"
)

var (
	serverOpts = map[string][]OptSpec{}
)

// RegisterServerOpts declares option metadata for a protocol, alongside its
// RegisterServer side-effect call. It is optional -- a protocol that skips this
// is still dial- and serve-able, but the management panel falls back to a
// free-form JSON editor for it. Like RegisterServer it is meant for an init().
// Panics on a duplicate name to surface a registration bug at startup.
func RegisterServerOpts(protocol string, opts []OptSpec) {
	if protocol == "" {
		panic("client: RegisterServerOpts with an empty protocol name")
	}
	serverMu.Lock()
	defer serverMu.Unlock()
	if _, dup := serverOpts[protocol]; dup {
		panic("client: server opts registered twice: " + protocol)
	}
	serverOpts[protocol] = opts
}

// ServerOptsFor returns the claimed metadata for a registered server protocol,
// or nil/false when the facade did not declare any. Callers (the management API,
// the panel) use the second result to pick between a typed form and a free-form
// fallback; both paths are first-class.
func ServerOptsFor(protocol string) ([]OptSpec, bool) {
	serverMu.RLock()
	defer serverMu.RUnlock()
	opts, ok := serverOpts[protocol]
	return opts, ok
}

// PeerInfo is one peer a server protocol can describe. Fields that a protocol
// does not track (e.g. last handshake for a stateless protocol) are left at
// their zero value; the panel renders them with a consistent "unknown" marker.
type PeerInfo struct {
	ID            string `json:"id"`                       // protocol's own identifier (public key, cert CN, username)
	Name          string `json:"name,omitempty"`           // optional human label
	Address       string `json:"address"`                  // assigned tunnel address
	State         string `json:"state"`                    // "connected" or "disconnected"
	LastHandshake string `json:"last_handshake,omitempty"` // RFC 3339 time of last handshake, or empty

	// RxBytes and TxBytes are the inner bytes this peer has carried in and out
	// since its tunnel was established, and RxPackets/TxPackets the same in
	// packets. They answer the one question a handshake time cannot: is this
	// peer actually moving traffic, or merely connected?
	//
	// Inner bytes rather than on-the-wire, so the figure is comparable with
	// what an application thinks it sent and does not silently change meaning
	// between protocols with different encapsulation overheads.
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	TxPackets uint64 `json:"tx_packets"`

	// LastSeen is the RFC 3339 time an authenticated packet last arrived from
	// this peer, or empty if none has. It is distinct from LastHandshake in the
	// way that matters operationally: a peer that handshook an hour ago and has
	// been silent since looks identical to a healthy one by handshake time
	// alone, and different by this.
	LastSeen string `json:"last_seen,omitempty"`
}

// WithTraffic fills in a PeerInfo's counters from a dataplane.Pump snapshot.
//
// It takes the four numbers and a time rather than the dataplane type, so that
// this package keeps depending only on the standard library -- which is what
// lets the separate nm/ module import it. The parameter list is the price of
// that, and it is paid once per protocol rather than by every caller.
//
// ok is the "the data path could not tell us" case, which is not the same as
// zero: a protocol whose peer list is assembled without a pump behind it should
// leave the fields at their zero value and let the panel render them as unknown,
// rather than assert that nothing has crossed.
func (p PeerInfo) WithTraffic(rxPackets, rxBytes, txPackets, txBytes uint64, lastSeen time.Time, ok bool) PeerInfo {
	if !ok {
		return p
	}
	p.RxPackets, p.RxBytes = rxPackets, rxBytes
	p.TxPackets, p.TxBytes = txPackets, txBytes
	if !lastSeen.IsZero() {
		p.LastSeen = lastSeen.UTC().Format(time.RFC3339)
	}
	return p
}

// PeerDescriber is an optional interface a Server may implement to expose its
// peer list to the management API and panel. Protocols that do not implement it
// still serve; their peer list in the panel shows nothing (not "empty", which
// could be mistaken for "zero clients"). The interface is type-asserted by
// the management API, so a Server that returns it from its parse function is
// the one that contributes peer data; no registry change is needed.
type PeerDescriber interface {
	Peers() []PeerInfo
}

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
