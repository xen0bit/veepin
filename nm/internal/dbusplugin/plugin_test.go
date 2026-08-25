package dbusplugin

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/internal/vlog"
	"github.com/xen0bit/veepin/nm/internal/nmconfig"
)

// newTestBus starts a private session bus and returns a server connection (for
// the plugin) and a caller connection (to invoke it). It skips the test if
// dbus-daemon is unavailable.
func newTestBus(t *testing.T) (server, caller *dbus.Conn) {
	t.Helper()
	if _, err := exec.LookPath("dbus-daemon"); err != nil {
		t.Skip("dbus-daemon not available")
	}
	cmd := exec.Command("dbus-daemon", "--session", "--nofork", "--print-address")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start dbus-daemon: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatalf("read bus address: %v", err)
	}
	addr := strings.TrimSpace(line)
	go func() { _, _ = io.Copy(io.Discard, stdout) }()

	server = dialTestBus(t, addr)
	caller = dialTestBus(t, addr)
	t.Cleanup(func() { server.Close(); caller.Close() })
	return server, caller
}

func dialTestBus(t *testing.T, addr string) *dbus.Conn {
	t.Helper()
	c, err := dbus.Dial(addr)
	if err != nil {
		t.Fatalf("dial private bus: %v", err)
	}
	if err := c.Auth(nil); err != nil {
		t.Fatalf("auth: %v", err)
	}
	if err := c.Hello(); err != nil {
		t.Fatalf("hello: %v", err)
	}
	return c
}

func settings(data, secrets map[string]string) nmconfig.Settings {
	return nmconfig.Settings{
		"vpn": {
			"data":    dbus.MakeVariant(data),
			"secrets": dbus.MakeVariant(secrets),
		},
	}
}

// testBusName is one protocol's well-known name — the shape NetworkManager
// actually passes as --bus-name, rather than the bare prefix.
var testBusName = BusNameFor("ikev2")

func exportTestPlugin(t *testing.T, server *dbus.Conn) *Plugin {
	t.Helper()
	p := New(server, testBusName, vlog.Discard())
	if err := p.Export(); err != nil {
		t.Fatalf("export: %v", err)
	}
	return p
}

// TestExportClaimsTheRequestedName guards the flag NetworkManager relies on to
// tell one binary which VPN type it was spawned for: claiming a fixed name
// instead would leave NM waiting for a service that never appears on every
// protocol but one.
func TestExportClaimsTheRequestedName(t *testing.T) {
	server, caller := newTestBus(t)
	p := New(server, BusNameFor("wireguard"), vlog.Discard())
	if err := p.Export(); err != nil {
		t.Fatalf("export: %v", err)
	}
	if got := p.BusName(); got != "org.freedesktop.NetworkManager.veepin.wireguard" {
		t.Errorf("BusName() = %q", got)
	}

	var has bool
	if err := caller.BusObject().Call("org.freedesktop.DBus.NameHasOwner", 0,
		p.BusName()).Store(&has); err != nil {
		t.Fatalf("NameHasOwner: %v", err)
	}
	if !has {
		t.Errorf("%s was not claimed on the bus", p.BusName())
	}
}

// TestNewDefaultsToThePrefix documents the fallback: a hand-run process with no
// --bus-name owns the bare prefix, which backs no VPN type, rather than
// silently taking a protocol's name.
func TestNewDefaultsToThePrefix(t *testing.T) {
	if got := New(nil, "", vlog.Discard()).BusName(); got != BusNamePrefix {
		t.Errorf("BusName() = %q, want %q", got, BusNamePrefix)
	}
}

func TestNeedSecretsOverBus(t *testing.T) {
	server, caller := newTestBus(t)
	exportTestPlugin(t, server)
	obj := caller.Object(testBusName, ObjectPath)

	// PSK missing -> NM must supply "vpn" secrets.
	var name string
	err := obj.Call(Iface+".NeedSecrets", 0,
		settings(map[string]string{nmconfig.KeyGateway: "g", nmconfig.KeyLocalID: "id"},
			map[string]string{})).Store(&name)
	if err != nil {
		t.Fatalf("NeedSecrets call: %v", err)
	}
	if name != "vpn" {
		t.Errorf("NeedSecrets = %q, want vpn", name)
	}

	// PSK present -> nothing needed.
	err = obj.Call(Iface+".NeedSecrets", 0,
		settings(map[string]string{nmconfig.KeyGateway: "g", nmconfig.KeyLocalID: "id"},
			map[string]string{nmconfig.KeyPSK: "p"})).Store(&name)
	if err != nil {
		t.Fatalf("NeedSecrets call: %v", err)
	}
	if name != "" {
		t.Errorf("NeedSecrets = %q, want empty", name)
	}
}

func TestConnectBadSettingsReturnsError(t *testing.T) {
	server, caller := newTestBus(t)
	exportTestPlugin(t, server)
	obj := caller.Object(testBusName, ObjectPath)

	// Missing gateway -> Connect should fail synchronously.
	call := obj.Call(Iface+".Connect", 0,
		settings(map[string]string{nmconfig.KeyLocalID: "id"}, map[string]string{nmconfig.KeyPSK: "p"}))
	if call.Err == nil {
		t.Fatal("expected Connect to return an error for missing gateway")
	}
}

// TestConnectHandshakeFailureEmitsSignals drives the full method -> goroutine ->
// signal path without root: an unreachable server fails at DNS resolution before
// any TUN is opened, so we should see Starting, then Failure, then Stopped.
func TestConnectHandshakeFailureEmitsSignals(t *testing.T) {
	server, caller := newTestBus(t)
	exportTestPlugin(t, server)
	obj := caller.Object(testBusName, ObjectPath)

	if err := caller.AddMatchSignal(
		dbus.WithMatchInterface(Iface),
		dbus.WithMatchObjectPath(ObjectPath),
	); err != nil {
		t.Fatalf("add match: %v", err)
	}
	sigCh := make(chan *dbus.Signal, 32)
	caller.Signal(sigCh)

	call := obj.Call(Iface+".Connect", 0, settings(
		map[string]string{nmconfig.KeyGateway: "no-such-host.invalid", nmconfig.KeyLocalID: "client.example"},
		map[string]string{nmconfig.KeyPSK: "p"},
	))
	if call.Err != nil {
		t.Fatalf("Connect returned error: %v", call.Err)
	}

	var sawFailure, sawStopped, sawStarting bool
	deadline := time.After(5 * time.Second)
	for !sawFailure || !sawStopped {
		select {
		case sig := <-sigCh:
			switch sig.Name {
			case Iface + ".StateChanged":
				if len(sig.Body) == 1 {
					if s, ok := sig.Body[0].(uint32); ok {
						if s == StateStarting {
							sawStarting = true
						}
						if s == StateStopped {
							sawStopped = true
						}
					}
				}
			case Iface + ".Failure":
				if len(sig.Body) == 1 {
					if r, ok := sig.Body[0].(uint32); ok && r == FailureConnectFailed {
						sawFailure = true
					}
				}
			}
		case <-deadline:
			t.Fatalf("timeout; starting=%v failure=%v stopped=%v", sawStarting, sawFailure, sawStopped)
		}
	}
	if !sawStarting {
		t.Error("never saw StateChanged(Starting)")
	}
}

func TestClassifyFailure(t *testing.T) {
	if got := classifyFailure(fmt.Errorf("wrap: %w", client.ErrAuth)); got != FailureLoginFailed {
		t.Errorf("auth error -> %d, want FailureLoginFailed(%d)", got, FailureLoginFailed)
	}
	if got := classifyFailure(errors.New("connection refused")); got != FailureConnectFailed {
		t.Errorf("transport error -> %d, want FailureConnectFailed(%d)", got, FailureConnectFailed)
	}
}

// TestDisconnectDuringConnect exercises the race the P1 hardening targets: a
// Disconnect that arrives while a handshake is still in flight must cancel it
// and leave the plugin in the Stopped state with no leaked session. A silent
// UDP server keeps the handshake pending. Run under -race.
func TestDisconnectDuringConnect(t *testing.T) {
	silent, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer silent.Close()
	port := fmt.Sprintf("%d", silent.LocalAddr().(*net.UDPAddr).Port)

	server, caller := newTestBus(t)
	p := exportTestPlugin(t, server)
	obj := caller.Object(testBusName, ObjectPath)

	call := obj.Call(Iface+".Connect", 0, settings(
		map[string]string{nmconfig.KeyGateway: "127.0.0.1", nmconfig.KeyPort: port, nmconfig.KeyLocalID: "client.example"},
		map[string]string{nmconfig.KeyPSK: "p"},
	))
	if call.Err != nil {
		t.Fatalf("Connect: %v", call.Err)
	}

	// Give the handshake a moment to be genuinely in flight, then disconnect.
	time.Sleep(100 * time.Millisecond)
	if dcall := obj.Call(Iface+".Disconnect", 0); dcall.Err != nil {
		t.Fatalf("Disconnect: %v", dcall.Err)
	}

	// State must be Stopped and no session retained.
	v, err := obj.GetProperty(Iface + ".State")
	if err != nil {
		t.Fatalf("get State: %v", err)
	}
	if s, _ := v.Value().(uint32); s != StateStopped {
		t.Errorf("State = %d, want Stopped(%d)", s, StateStopped)
	}
	p.mu.Lock()
	leaked := p.session != nil
	p.mu.Unlock()
	if leaked {
		t.Error("session leaked after disconnect-during-connect")
	}
}

func TestStatePropertyReadable(t *testing.T) {
	server, caller := newTestBus(t)
	exportTestPlugin(t, server)
	obj := caller.Object(testBusName, ObjectPath)

	v, err := obj.GetProperty(Iface + ".State")
	if err != nil {
		t.Fatalf("get State property: %v", err)
	}
	if _, ok := v.Value().(uint32); !ok {
		t.Fatalf("State property type = %T, want uint32", v.Value())
	}
}

// waitForSignal reads from ch until one named sig arrives or the deadline
// passes, returning its body.
func waitForSignal(t *testing.T, ch <-chan *dbus.Signal, name string, d time.Duration) []any {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case sig := <-ch:
			if sig.Name == Iface+"."+name {
				return sig.Body
			}
		case <-deadline:
			t.Fatalf("no %s signal within %s", name, d)
			return nil
		}
	}
}

// watchSignals subscribes the caller connection to this plugin's signals.
func watchSignals(t *testing.T, caller *dbus.Conn) chan *dbus.Signal {
	t.Helper()
	if err := caller.AddMatchSignal(
		dbus.WithMatchInterface(Iface),
		dbus.WithMatchObjectPath(ObjectPath),
	); err != nil {
		t.Fatalf("add match: %v", err)
	}
	ch := make(chan *dbus.Signal, 32)
	caller.Signal(ch)
	return ch
}

// TestConnectInteractiveAsksRatherThanDiallingWithoutTheSecret is the whole
// point of the interactive flow. Before it, a connection whose secret was not
// present was dialled anyway: the gateway refused the empty password, the user
// was shown a login failure for a credential they were never asked for, and on
// a gateway that counts failures it was charged against them.
//
// The assertion is that no handshake started, which is why it checks for
// SecretsRequired and NOT for a Failure: a plugin that emitted both would have
// asked *and* dialled, which is the bug wearing the fix's clothes.
func TestConnectInteractiveAsksRatherThanDiallingWithoutTheSecret(t *testing.T) {
	server, caller := newTestBus(t)
	exportTestPlugin(t, server)
	obj := caller.Object(testBusName, ObjectPath)
	sigCh := watchSignals(t, caller)

	call := obj.Call(Iface+".ConnectInteractive", 0, settings(
		map[string]string{nmconfig.KeyGateway: "no-such-host.invalid", nmconfig.KeyLocalID: "client.example"},
		map[string]string{}, // no PSK
	), map[string]dbus.Variant{})
	if call.Err != nil {
		t.Fatalf("ConnectInteractive returned error: %v", call.Err)
	}

	body := waitForSignal(t, sigCh, "SecretsRequired", 5*time.Second)
	if len(body) != 2 {
		t.Fatalf("SecretsRequired body = %v, want (message, hints)", body)
	}
	hints, ok := body[1].([]string)
	if !ok {
		t.Fatalf("SecretsRequired hints = %T, want []string", body[1])
	}
	// The hint names the field, which is the thing NeedSecrets structurally
	// cannot say: it answers with a setting name, so "vpn" is as precise as it
	// is allowed to be and the agent has to guess which box to show.
	if len(hints) != 1 || hints[0] != nmconfig.KeyPSK {
		t.Errorf("hints = %v, want [%q]", hints, nmconfig.KeyPSK)
	}

	select {
	case sig := <-sigCh:
		if sig.Name == Iface+".Failure" {
			t.Fatalf("a Failure was emitted: the plugin asked for the secret AND dialled without it")
		}
	case <-time.After(500 * time.Millisecond):
	}
}

// TestConnectInteractiveDialsStraightAwayWhenNothingIsMissing keeps the ask
// from becoming an extra round trip on the common path, where NM's own
// NeedSecrets flow has already collected everything.
func TestConnectInteractiveDialsStraightAwayWhenNothingIsMissing(t *testing.T) {
	server, caller := newTestBus(t)
	exportTestPlugin(t, server)
	obj := caller.Object(testBusName, ObjectPath)
	sigCh := watchSignals(t, caller)

	call := obj.Call(Iface+".ConnectInteractive", 0, settings(
		map[string]string{nmconfig.KeyGateway: "no-such-host.invalid", nmconfig.KeyLocalID: "client.example"},
		map[string]string{nmconfig.KeyPSK: "p"},
	), map[string]dbus.Variant{})
	if call.Err != nil {
		t.Fatalf("ConnectInteractive returned error: %v", call.Err)
	}

	// The host does not resolve, so the handshake fails -- which is proof it
	// was attempted. What must NOT appear is a SecretsRequired.
	deadline := time.After(10 * time.Second)
	for {
		select {
		case sig := <-sigCh:
			if sig.Name == Iface+".SecretsRequired" {
				t.Fatal("asked for secrets that were already present")
			}
			if sig.Name == Iface+".Failure" {
				return
			}
		case <-deadline:
			t.Fatal("no Failure signal: the connection was never dialled")
		}
	}
}

// TestNewSecretsCompletesTheConnection walks the whole exchange: ask, answer,
// dial. The dial fails (the gateway does not resolve) and that is the proof it
// happened -- a plugin that swallowed NewSecrets would sit silent forever.
func TestNewSecretsCompletesTheConnection(t *testing.T) {
	server, caller := newTestBus(t)
	exportTestPlugin(t, server)
	obj := caller.Object(testBusName, ObjectPath)
	sigCh := watchSignals(t, caller)

	data := map[string]string{nmconfig.KeyGateway: "no-such-host.invalid", nmconfig.KeyLocalID: "client.example"}
	if call := obj.Call(Iface+".ConnectInteractive", 0,
		settings(data, map[string]string{}), map[string]dbus.Variant{}); call.Err != nil {
		t.Fatalf("ConnectInteractive: %v", call.Err)
	}
	waitForSignal(t, sigCh, "SecretsRequired", 5*time.Second)

	if call := obj.Call(Iface+".NewSecrets", 0,
		settings(data, map[string]string{nmconfig.KeyPSK: "p"})); call.Err != nil {
		t.Fatalf("NewSecrets: %v", call.Err)
	}
	waitForSignal(t, sigCh, "Failure", 10*time.Second)
}

// TestNewSecretsThatStillMissesGivesUp bounds the exchange. An agent that keeps
// answering without the secret -- a user dismissing the prompt, a connection
// configured for the wrong credential -- must end in a Failure rather than in
// the two of them trading messages forever.
//
// The reason is LoginFailed and not ConnectFailed: nothing was wrong with the
// network, the credential never arrived, and LoginFailed is what makes NM offer
// the prompt again next time instead of remembering the connection as broken.
func TestNewSecretsThatStillMissesGivesUp(t *testing.T) {
	server, caller := newTestBus(t)
	exportTestPlugin(t, server)
	obj := caller.Object(testBusName, ObjectPath)
	sigCh := watchSignals(t, caller)

	data := map[string]string{nmconfig.KeyGateway: "no-such-host.invalid", nmconfig.KeyLocalID: "client.example"}
	empty := settings(data, map[string]string{})
	if call := obj.Call(Iface+".ConnectInteractive", 0, empty, map[string]dbus.Variant{}); call.Err != nil {
		t.Fatalf("ConnectInteractive: %v", call.Err)
	}
	waitForSignal(t, sigCh, "SecretsRequired", 5*time.Second)

	for range maxSecretsRounds {
		if call := obj.Call(Iface+".NewSecrets", 0, empty); call.Err != nil {
			t.Fatalf("NewSecrets: %v", call.Err)
		}
	}
	body := waitForSignal(t, sigCh, "Failure", 5*time.Second)
	if len(body) != 1 || body[0].(uint32) != FailureLoginFailed {
		t.Errorf("Failure reason = %v, want FailureLoginFailed(%d)", body, FailureLoginFailed)
	}
}

// TestUnsolicitedNewSecretsIsRefused. NM only calls NewSecrets after
// SecretsRequired, so a connection arriving with nothing pending is either a
// bug or another client on the bus trying to start a tunnel through a method
// that looks like it only updates one. Treating it as a Connect would make that
// work.
func TestUnsolicitedNewSecretsIsRefused(t *testing.T) {
	server, caller := newTestBus(t)
	exportTestPlugin(t, server)
	obj := caller.Object(testBusName, ObjectPath)

	call := obj.Call(Iface+".NewSecrets", 0, settings(
		map[string]string{nmconfig.KeyGateway: "g", nmconfig.KeyLocalID: "id"},
		map[string]string{nmconfig.KeyPSK: "p"},
	))
	if call.Err == nil {
		t.Fatal("an unsolicited NewSecrets was accepted")
	}
}

// TestPublishStateSurvivesAClosedBus is the regression guard for a panic that
// killed the service on the way down.
//
// prop.Properties.SetMust panics on any error from its internal set, including
// the emit failing with "dbus: connection closed by user" -- which is not a
// programming error but what a shutdown looks like. The last thing this plugin
// does is setState(StateStopped), so losing that race took the process out with
// a panic instead of exiting.
//
// It closes the connection first and then publishes, which is the losing side
// of the race made deterministic.
func TestPublishStateSurvivesAClosedBus(t *testing.T) {
	server, _ := newTestBus(t)
	p := exportTestPlugin(t, server)

	_ = server.Close()
	// Must not panic. A failure here is a crashed VPN service, not a lost
	// property update.
	p.publishState(StateStopped)

	// And the guard has teeth: the underlying call really does panic on a
	// closed bus, so publishState is doing work rather than the API having
	// quietly become safe.
	func() {
		defer func() {
			if recover() == nil {
				t.Error("SetMust no longer panics on a closed bus; publishState's recover " +
					"is now dead code and the comment explaining it is wrong")
			}
		}()
		p.props.SetMust(Iface, "State", StateStopped)
	}()
}
