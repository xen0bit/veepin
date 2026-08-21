// Package dbusplugin implements the NetworkManager VPN plugin D-Bus contract
// (org.freedesktop.NetworkManager.VPN.Plugin) on top of this project's client
// package. NetworkManager spawns the service (as root), calls Connect/
// NeedSecrets/Disconnect, and listens for the StateChanged/Config/Ip4Config/
// Failure signals this plugin emits. NM — not the plugin — applies addressing
// and routing from the reported Ip4Config.
package dbusplugin

import (
	"context"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"strings"
	"sync"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"
	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/nm/internal/nmconfig"
)

// D-Bus identifiers for the plugin.
const (
	// BusNamePrefix is the root of every name this service may own. veepin
	// registers one service per protocol — BusNamePrefix + "." + protocol — so
	// that each is a separate VPN type in the OS's "Add VPN" list; see
	// data/nm-veepin-service.name.in. The D-Bus policy grants root own_prefix
	// over exactly this prefix.
	BusNamePrefix = "org.freedesktop.NetworkManager.veepin"
	ObjectPath    = dbus.ObjectPath("/org/freedesktop/NetworkManager/VPN/Plugin")
	Iface         = "org.freedesktop.NetworkManager.VPN.Plugin"
)

// BusNameFor is the well-known name serving one protocol's VPN type. It must
// match the service= of that protocol's .name descriptor byte for byte:
// NetworkManager spawns the program named there and waits for this name to
// appear on the bus.
func BusNameFor(protocol string) string { return BusNamePrefix + "." + protocol }

// NM_VPN_SERVICE_STATE (nm-vpn-dbus-interface.h). Emitted via StateChanged and
// exposed as the State property.
const (
	StateUnknown  uint32 = 0
	StateInit     uint32 = 1
	StateShutdown uint32 = 2
	StateStarting uint32 = 3
	StateStarted  uint32 = 4
	StateStopping uint32 = 5
	StateStopped  uint32 = 6
)

// NM_VPN_PLUGIN_FAILURE (nm-vpn-dbus-interface.h).
const (
	FailureLoginFailed   uint32 = 0
	FailureConnectFailed uint32 = 1
	FailureBadIPConfig   uint32 = 2
)

// Settings is the connection dictionary NM delivers, aliased here so the
// pending-connection field reads as what it holds.
type Settings = nmconfig.Settings

// Plugin holds the running plugin state: the bus connection, the current VPN
// session (if any), and the exposed State property.
type Plugin struct {
	conn    *dbus.Conn
	busName string
	log     *log.Logger
	props   *prop.Properties
	quit    chan struct{}
	closer  sync.Once

	mu         sync.Mutex
	state      uint32
	session    client.Session
	dialCancel context.CancelFunc // cancels an in-flight handshake

	// pending holds the connection an interactive Connect is waiting on
	// secrets for. It is non-nil only between emitting SecretsRequired and
	// receiving NewSecrets, and it holds the SETTINGS rather than the parsed
	// Connection because NewSecrets delivers a whole connection dict and the
	// merge has to happen on the dict.
	pending Settings
	// asked counts SecretsRequired rounds for the pending connection, so a
	// disagreement between what this plugin asks for and what the agent can
	// supply ends in a Failure rather than in the two of them trading messages
	// forever.
	asked int
}

// maxSecretsRounds bounds the SecretsRequired/NewSecrets exchange. NM's agent
// answers with whatever it has; if that still does not satisfy the protocol --
// a connection configured for a password on a gateway that wants a token, an
// agent the user keeps cancelling -- asking again gets the same answer. Three
// rounds is enough for the two-secret protocols (cisco, l2tp) to be asked once
// per secret with one to spare.
const maxSecretsRounds = 3

// New creates a Plugin bound to conn, claiming busName when Exported. busName
// is the service NetworkManager spawned this process for — it passes it as
// --bus-name — so one binary serves every per-protocol VPN type. An empty
// busName falls back to the bare prefix, which owns no VPN type but keeps a
// hand-run process from claiming a protocol's name by accident.
func New(conn *dbus.Conn, busName string, logger *log.Logger) *Plugin {
	if logger == nil {
		logger = log.New(log.Writer(), "nm-veepin: ", log.LstdFlags)
	}
	if busName == "" {
		busName = BusNamePrefix
	}
	return &Plugin{
		conn:    conn,
		busName: busName,
		log:     logger,
		quit:    make(chan struct{}),
		state:   StateInit,
	}
}

// BusName is the well-known name this plugin claims.
func (p *Plugin) BusName() string { return p.busName }

// Export claims the well-known name and exports the plugin object, its State
// property, and introspection data. Returns an error if the name is taken.
func (p *Plugin) Export() error {
	if err := p.conn.Export(p, ObjectPath, Iface); err != nil {
		return err
	}

	propsSpec := map[string]map[string]*prop.Prop{
		Iface: {
			"State": {Value: p.state, Writable: false, Emit: prop.EmitTrue, Callback: nil},
		},
	}
	props, err := prop.Export(p.conn, ObjectPath, propsSpec)
	if err != nil {
		return err
	}
	p.props = props

	node := &introspect.Node{
		Name: string(ObjectPath),
		Interfaces: []introspect.Interface{
			introspect.IntrospectData,
			prop.IntrospectData,
			pluginIntrospect(),
		},
	}
	if err := p.conn.Export(introspect.NewIntrospectable(node), ObjectPath,
		"org.freedesktop.DBus.Introspectable"); err != nil {
		return err
	}

	reply, err := p.conn.RequestName(p.busName, dbus.NameFlagDoNotQueue)
	if err != nil {
		return err
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		return &nameTakenError{p.busName}
	}
	p.log.Printf("exported %s on the bus", p.busName)
	return nil
}

// Wait blocks until the plugin has been asked to quit (Disconnect).
func (p *Plugin) Wait() { <-p.quit }

// --- D-Bus methods NM calls ---

// Connect starts the tunnel described by the connection settings. It returns
// quickly; the handshake runs asynchronously and its outcome is reported via
// signals.
func (p *Plugin) Connect(settings nmconfig.Settings) *dbus.Error {
	conn, err := nmconfig.Parse(settings)
	if err != nil {
		// A synchronous validation failure: report it as the method result. No
		// Failure signal — nothing was started.
		p.log.Printf("Connect: bad settings: %v", err)
		return dbus.MakeFailedError(err)
	}

	p.mu.Lock()
	if p.session != nil || p.dialCancel != nil {
		p.mu.Unlock()
		return dbus.MakeFailedError(errAlreadyConnected)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.dialCancel = cancel
	p.mu.Unlock()

	p.setState(StateStarting)
	go p.dial(ctx, conn)
	return nil
}

// ConnectInteractive is Connect with one difference that matters: when a secret
// the protocol needs is not in the connection, it asks for that secret instead
// of dialling without it.
//
// NM calls this first and falls back to Connect only if the plugin refuses it,
// so this is the path a desktop actually takes. Without the ask, a connection
// whose secrets are flagged NOT_SAVED and whose auth-dialog was dismissed
// reached the gateway with an empty password: the gateway refused it, the user
// saw a login failure for a password they were never asked for, and on a
// gateway that counts failures the attempt was charged against them.
//
// The details dict NM passes carries interactivity hints this plugin has no use
// for -- it has no UI of its own and asks through NM's agent either way -- so it
// is accepted and ignored rather than being a reason to refuse the method.
func (p *Plugin) ConnectInteractive(settings nmconfig.Settings, _ map[string]dbus.Variant) *dbus.Error {
	hints, err := nmconfig.MissingSecretHints(settings)
	if err != nil {
		p.log.Printf("ConnectInteractive: bad settings: %v", err)
		return dbus.MakeFailedError(err)
	}
	if len(hints) == 0 {
		return p.Connect(settings)
	}

	p.mu.Lock()
	if p.session != nil || p.dialCancel != nil || p.pending != nil {
		p.mu.Unlock()
		return dbus.MakeFailedError(errAlreadyConnected)
	}
	p.pending, p.asked = settings, 1
	p.mu.Unlock()

	p.setState(StateStarting)
	p.requestSecrets(hints)
	return nil
}

// NewSecrets delivers the secrets ConnectInteractive asked for, as a whole
// connection dict rather than as the missing values alone. It is the second
// half of the interactive flow and is only ever called after SecretsRequired.
//
// A connection arriving with nothing pending is refused rather than dialled.
// NM does not send one, and treating an unsolicited dict as a Connect would
// give any client on the bus a way to start a tunnel through a method that
// looks like it only updates one.
func (p *Plugin) NewSecrets(settings nmconfig.Settings) *dbus.Error {
	p.mu.Lock()
	pending := p.pending
	round := p.asked
	p.mu.Unlock()
	if pending == nil {
		return dbus.MakeFailedError(errNoSecretsPending)
	}

	hints, err := nmconfig.MissingSecretHints(settings)
	if err != nil {
		p.log.Printf("NewSecrets: bad settings: %v", err)
		p.clearPending()
		p.fail(FailureConnectFailed)
		return dbus.MakeFailedError(err)
	}
	if len(hints) > 0 {
		if round >= maxSecretsRounds {
			p.log.Printf("NewSecrets: still missing %v after %d rounds; giving up", hints, round)
			p.clearPending()
			// LoginFailed, not ConnectFailed: nothing was wrong with the
			// network, the credential never arrived. It is also what makes NM
			// offer the prompt again on the next activation rather than
			// remembering the connection as broken.
			p.fail(FailureLoginFailed)
			return nil
		}
		p.mu.Lock()
		p.pending, p.asked = settings, round+1
		p.mu.Unlock()
		p.requestSecrets(hints)
		return nil
	}

	p.clearPending()
	return p.Connect(settings)
}

// requestSecrets emits SecretsRequired, naming the keys still needed so NM's
// agent prompts for the right field. NeedSecrets cannot do this -- it answers
// with a *setting* name, so "vpn" is the most precise thing it is allowed to
// say and the agent has to guess.
func (p *Plugin) requestSecrets(hints []string) {
	msg := "The VPN needs " + strings.Join(hints, " and ")
	if err := p.conn.Emit(ObjectPath, Iface+".SecretsRequired", msg, hints); err != nil {
		p.log.Printf("emit SecretsRequired(%v): %v", hints, err)
		p.clearPending()
		p.fail(FailureConnectFailed)
		return
	}
	p.log.Printf("waiting for secrets: %v", hints)
}

// clearPending drops the connection an interactive Connect was holding.
func (p *Plugin) clearPending() {
	p.mu.Lock()
	p.pending, p.asked = nil, 0
	p.mu.Unlock()
}

// NeedSecrets reports which setting (if any) still needs secrets before Connect.
func (p *Plugin) NeedSecrets(settings nmconfig.Settings) (string, *dbus.Error) {
	name, err := nmconfig.MissingSecret(settings)
	if err != nil {
		return "", dbus.MakeFailedError(err)
	}
	return name, nil
}

// Disconnect tears the tunnel down and asks the service to exit.
func (p *Plugin) Disconnect() *dbus.Error {
	p.log.Printf("Disconnect requested")
	p.setState(StateStopping)
	p.mu.Lock()
	if p.dialCancel != nil {
		p.dialCancel() // abort an in-flight handshake
		p.dialCancel = nil
	}
	// A Disconnect while waiting on SecretsRequired has to drop the pending
	// connection too, or a NewSecrets arriving afterwards would start a tunnel
	// the user has already cancelled.
	p.pending, p.asked = nil, 0
	sess := p.session
	p.session = nil
	p.mu.Unlock()
	if sess != nil {
		sess.Close()
	}
	p.setState(StateStopped)
	p.stop()
	return nil
}

// --- internals ---

func (p *Plugin) dial(ctx context.Context, conn nmconfig.Connection) {
	sess, res, err := client.Dial(ctx, conn.Protocol, conn.Options)

	p.mu.Lock()
	p.dialCancel = nil
	aborted := ctx.Err() != nil
	p.mu.Unlock()

	if err != nil {
		if aborted {
			p.log.Printf("Connect: aborted by disconnect")
		} else {
			p.log.Printf("Connect: handshake failed: %v", err)
			p.fail(classifyFailure(err))
		}
		return
	}

	// Handshake succeeded. Publish the session unless a Disconnect raced in
	// while we were dialing (checked under the lock so the two orderings — set
	// then close, or cancel then skip — are both leak-free).
	p.mu.Lock()
	if ctx.Err() != nil {
		p.mu.Unlock()
		sess.Close()
		p.log.Printf("Connect: succeeded but aborted by disconnect")
		return
	}
	p.session = sess
	p.mu.Unlock()

	if cerr := p.emitConfig(res, conn.FullTunnel, conn.MTU); cerr != nil {
		p.log.Printf("Connect: emit config failed: %v", cerr)
		p.mu.Lock()
		p.session = nil
		p.mu.Unlock()
		sess.Close()
		p.fail(FailureBadIPConfig)
		return
	}
	p.setState(StateStarted)
	p.log.Printf("tunnel up: %s addr=%s dns=%v", res.TUNName, res.AssignedIP, res.DNS)
}

// classifyFailure maps a client.Dial error to an NM failure reason: a rejected
// credential becomes LoginFailed (so NM re-prompts for the secret), anything
// else ConnectFailed.
func classifyFailure(err error) uint32 {
	if errors.Is(err, client.ErrAuth) {
		return FailureLoginFailed
	}
	return FailureConnectFailed
}

// emitConfig sends the Config and Ip4Config signals NM applies to the system.
// mtuOverride, when > 0, replaces the client's default tunnel MTU.
func (p *Plugin) emitConfig(res client.Result, fullTunnel bool, mtuOverride int) error {
	mtu := res.MTU
	if mtuOverride > 0 {
		mtu = mtuOverride
	}
	gw := ip4ToNM(res.Gateway)
	cfg := map[string]dbus.Variant{
		"tundev":  dbus.MakeVariant(res.TUNName),
		"mtu":     dbus.MakeVariant(uint32(mtu)),
		"has-ip4": dbus.MakeVariant(true),
		"has-ip6": dbus.MakeVariant(false),
		"gateway": dbus.MakeVariant(gw),
	}
	if err := p.conn.Emit(ObjectPath, Iface+".Config", cfg); err != nil {
		return err
	}

	dns := make([]uint32, 0, len(res.DNS))
	for _, d := range res.DNS {
		dns = append(dns, ip4ToNM(d))
	}
	ip4 := map[string]dbus.Variant{
		"address":       dbus.MakeVariant(ip4ToNM(res.AssignedIP)),
		"prefix":        dbus.MakeVariant(prefixFromMask(res.Netmask)),
		"gateway":       dbus.MakeVariant(gw),
		"dns":           dbus.MakeVariant(dns),
		"mtu":           dbus.MakeVariant(uint32(mtu)),
		"never-default": dbus.MakeVariant(!fullTunnel),
	}
	return p.conn.Emit(ObjectPath, Iface+".Ip4Config", ip4)
}

func (p *Plugin) setState(s uint32) {
	p.mu.Lock()
	p.state = s
	p.mu.Unlock()
	p.publishState(s)
	if err := p.conn.Emit(ObjectPath, Iface+".StateChanged", s); err != nil {
		p.log.Printf("emit StateChanged(%d): %v", s, err)
	}
}

// publishState pushes the state onto the D-Bus property, and survives the bus
// having gone away underneath it.
//
// prop.Properties.SetMust documents itself as panicking "if the interface or
// the property name are invalid" -- both programming errors. It actually panics
// on ANY error from its internal set, and that includes the emit failing with
// "dbus: connection closed by user", which is not a programming error at all:
// it is what a shutdown looks like from here. The last thing this plugin does
// on the way down is setState(StateStopped), so the losing side of that race
// took the whole process out with a panic instead of exiting.
//
// Caught in CI rather than locally, and only once -- the window is the few
// microseconds between the bus connection closing and the final state update,
// which a loaded runner widens and a developer's machine almost never hits.
//
// There is no non-panicking setter on that type (Set is the D-Bus method
// handler and enforces writability), so this recovers rather than avoiding the
// call. A flag would narrow the window without closing it: the connection can
// close between the check and the call.
func (p *Plugin) publishState(s uint32) {
	if p.props == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			// Worth a line rather than silence: if this ever fires for a reason
			// other than shutdown, the state property has silently stopped
			// tracking the plugin and nothing else would say so.
			p.log.Printf("publishing State(%d) failed, most likely because the bus is gone: %v", s, r)
		}
	}()
	p.props.SetMust(Iface, "State", s)
}

func (p *Plugin) fail(reason uint32) {
	if err := p.conn.Emit(ObjectPath, Iface+".Failure", reason); err != nil {
		p.log.Printf("emit Failure(%d): %v", reason, err)
	}
	p.mu.Lock()
	sess := p.session
	p.session = nil
	p.mu.Unlock()
	if sess != nil {
		sess.Close()
	}
	p.setState(StateStopped)
	p.stop()
}

func (p *Plugin) stop() { p.closer.Do(func() { close(p.quit) }) }

// ip4ToNM converts an IPv4 address to the network-byte-order guint32 the NM VPN
// D-Bus API expects. On a little-endian host, the in-memory bytes of this value
// are the address in network order (a.b.c.d), which is what NM's ntop expects.
func ip4ToNM(ip net.IP) uint32 {
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(v4)
}

// prefixFromMask returns the CIDR prefix length of an IPv4 netmask.
func prefixFromMask(mask net.IP) uint32 {
	v4 := mask.To4()
	if v4 == nil {
		return 32
	}
	ones, _ := net.IPMask(v4).Size()
	return uint32(ones)
}
