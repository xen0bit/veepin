package dbusplugin

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/xen0bit/ikennkt/client"
	"github.com/xen0bit/ikennkt/nm/internal/nmconfig"
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
	go io.Copy(io.Discard, stdout)

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

func exportTestPlugin(t *testing.T, server *dbus.Conn) *Plugin {
	t.Helper()
	p := New(server, log.New(io.Discard, "", 0))
	if err := p.Export(); err != nil {
		t.Fatalf("export: %v", err)
	}
	return p
}

func TestNeedSecretsOverBus(t *testing.T) {
	server, caller := newTestBus(t)
	exportTestPlugin(t, server)
	obj := caller.Object(BusName, ObjectPath)

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
	obj := caller.Object(BusName, ObjectPath)

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
	obj := caller.Object(BusName, ObjectPath)

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
	for !(sawFailure && sawStopped) {
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
	obj := caller.Object(BusName, ObjectPath)

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
	obj := caller.Object(BusName, ObjectPath)

	v, err := obj.GetProperty(Iface + ".State")
	if err != nil {
		t.Fatalf("get State property: %v", err)
	}
	if _, ok := v.Value().(uint32); !ok {
		t.Fatalf("State property type = %T, want uint32", v.Value())
	}
}
