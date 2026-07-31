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
