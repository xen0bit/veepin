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
	"log"
	"net"
	"sync"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"
	"github.com/xen0bit/ikennkt/client"
	"github.com/xen0bit/ikennkt/nm/internal/nmconfig"
)

// D-Bus identifiers for the plugin.
const (
	BusName    = "org.freedesktop.NetworkManager.ikennkt"
	ObjectPath = dbus.ObjectPath("/org/freedesktop/NetworkManager/VPN/Plugin")
	Iface      = "org.freedesktop.NetworkManager.VPN.Plugin"
)

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

// Plugin holds the running plugin state: the bus connection, the current VPN
// session (if any), and the exposed State property.
type Plugin struct {
	conn   *dbus.Conn
	log    *log.Logger
	props  *prop.Properties
	quit   chan struct{}
	closer sync.Once

	mu      sync.Mutex
	state   uint32
	session *client.Session
}

// New creates a Plugin bound to conn.
func New(conn *dbus.Conn, logger *log.Logger) *Plugin {
	if logger == nil {
		logger = log.New(log.Writer(), "nm-ikennkt: ", log.LstdFlags)
	}
	return &Plugin{conn: conn, log: logger, quit: make(chan struct{}), state: StateInit}
}

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

	reply, err := p.conn.RequestName(BusName, dbus.NameFlagDoNotQueue)
	if err != nil {
		return err
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		return &nameTakenError{BusName}
	}
	p.log.Printf("exported %s on the bus", BusName)
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
		p.log.Printf("Connect: bad settings: %v", err)
		p.fail(FailureConnectFailed)
		return dbus.MakeFailedError(err)
	}

	p.mu.Lock()
	if p.session != nil {
		p.mu.Unlock()
		return dbus.MakeFailedError(errAlreadyConnected)
	}
	p.mu.Unlock()

	p.setState(StateStarting)
	go p.dial(conn)
	return nil
}

// ConnectInteractive behaves like Connect; interactive secret negotiation is not
// used (secrets arrive with the connection).
func (p *Plugin) ConnectInteractive(settings nmconfig.Settings, _ map[string]dbus.Variant) *dbus.Error {
	return p.Connect(settings)
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

func (p *Plugin) dial(conn nmconfig.Connection) {
	sess, res, err := client.Dial(context.Background(), conn.Client)
	if err != nil {
		p.log.Printf("Connect: handshake failed: %v", err)
		p.fail(FailureConnectFailed)
		return
	}
	p.mu.Lock()
	p.session = sess
	p.mu.Unlock()

	if err := p.emitConfig(res, conn.FullTunnel); err != nil {
		p.log.Printf("Connect: emit config failed: %v", err)
		sess.Close()
		p.fail(FailureBadIPConfig)
		return
	}
	p.setState(StateStarted)
	p.log.Printf("tunnel up: %s addr=%s dns=%v", res.TUNName, res.AssignedIP, res.DNS)
}

// emitConfig sends the Config and Ip4Config signals NM applies to the system.
func (p *Plugin) emitConfig(res client.Result, fullTunnel bool) error {
	gw := ip4ToNM(res.Gateway)
	cfg := map[string]dbus.Variant{
		"tundev":  dbus.MakeVariant(res.TUNName),
		"mtu":     dbus.MakeVariant(uint32(res.MTU)),
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
		"mtu":           dbus.MakeVariant(uint32(res.MTU)),
		"never-default": dbus.MakeVariant(!fullTunnel),
	}
	return p.conn.Emit(ObjectPath, Iface+".Ip4Config", ip4)
}

func (p *Plugin) setState(s uint32) {
	p.mu.Lock()
	p.state = s
	p.mu.Unlock()
	if p.props != nil {
		p.props.SetMust(Iface, "State", s)
	}
	if err := p.conn.Emit(ObjectPath, Iface+".StateChanged", s); err != nil {
		p.log.Printf("emit StateChanged(%d): %v", s, err)
	}
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
