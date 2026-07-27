package gp

// Option parsing, for both roles. These are the checks that run before anything
// is opened: parseOptions and parseServerOptions validate first, and NewServer
// validates before it touches the TUN. So every case here runs unprivileged,
// which is the point — the option surface is the part of a facade a unit test can
// actually reach, and it is where a mistake is silent rather than loud.

import (
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/xen0bit/veepin/client"
	igp "github.com/xen0bit/veepin/internal/gp"
)

func validClientOptions() map[string]string {
	return map[string]string{
		OptServer:   "gw.example.com",
		OptUser:     "alice",
		OptPassword: "hunter2",
	}
}

func TestParseOptions(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(map[string]string)
		wantErr string // substring the error must contain; empty means it must succeed
	}{
		{name: "the minimum is enough"},
		{
			name:    "server is required",
			mutate:  func(o map[string]string) { delete(o, OptServer) },
			wantErr: "server is required",
		},
		{
			name:    "user is required",
			mutate:  func(o map[string]string) { delete(o, OptUser) },
			wantErr: "user is required",
		},
		{
			name:    "port must be a number",
			mutate:  func(o map[string]string) { o[OptPort] = "https" },
			wantErr: "invalid port",
		},
		{
			name:    "port must be in range",
			mutate:  func(o map[string]string) { o[OptPort] = "70000" },
			wantErr: "invalid port",
		},
		{
			name:    "shape must be a number",
			mutate:  func(o map[string]string) { o[OptShape] = "lots" },
			wantErr: "invalid shape",
		},
		{
			name:    "shape must not be negative",
			mutate:  func(o map[string]string) { o[OptShape] = "-1" },
			wantErr: "invalid shape",
		},
		{
			name:    "a missing CA file is named",
			mutate:  func(o map[string]string) { o[OptCA] = "/nonexistent/ca.pem" },
			wantErr: "reading CA",
		},
		{name: "port is accepted", mutate: func(o map[string]string) { o[OptPort] = "8443" }},
		{name: "shape is accepted", mutate: func(o map[string]string) { o[OptShape] = "4096" }},
		{name: "insecure is accepted", mutate: func(o map[string]string) { o[OptInsecure] = "true" }},
		{name: "no-esp is accepted", mutate: func(o map[string]string) { o[OptNoESP] = "true" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := validClientOptions()
			if tt.mutate != nil {
				tt.mutate(opts)
			}
			d, err := parseOptions(opts)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("parseOptions(%v) = %v, want it to be accepted", opts, err)
				}
				if d == nil {
					t.Fatal("parseOptions returned a nil Dialer with no error")
				}
				return
			}
			if err == nil {
				t.Fatalf("parseOptions(%v) was accepted, want an error containing %q", opts, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestOptionsReachTheConfig proves each option is actually carried into the
// Config rather than merely accepted, which a round-trip through parseOptions is
// the only unprivileged way to check.
func TestOptionsReachTheConfig(t *testing.T) {
	opts := validClientOptions()
	opts[OptPort] = "8443"
	opts[OptShape] = "4096"
	opts[OptInsecure] = "true"
	opts[OptNoESP] = "true"
	opts[OptTUN] = "gp0"

	d, err := parseOptions(opts)
	if err != nil {
		t.Fatalf("parseOptions: %v", err)
	}
	cfg := d.(dialer).cfg
	if cfg.Server != "gw.example.com" || cfg.Username != "alice" || cfg.Password != "hunter2" {
		t.Errorf("credentials did not survive: %+v", cfg)
	}
	if cfg.Port != 8443 || cfg.Shape != 4096 || !cfg.Insecure || !cfg.NoESP || cfg.TUNName != "gp0" {
		t.Errorf("options did not survive: %+v", cfg)
	}
}

func validServerOptions() map[string]string {
	return map[string]string{
		OptServerUser: "alice",
		OptServerPass: "hunter2",
	}
}

func TestParseServerOptions(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(map[string]string)
		wantErr string
	}{
		{
			name:    "user and pass are required",
			mutate:  func(o map[string]string) { delete(o, OptServerUser); delete(o, OptServerPass) },
			wantErr: "user and pass are required",
		},
		{
			name:    "user alone is not enough",
			mutate:  func(o map[string]string) { delete(o, OptServerPass) },
			wantErr: "user and pass are required",
		},
		{
			name:    "port must be a number",
			mutate:  func(o map[string]string) { o[OptServerPort] = "https" },
			wantErr: "invalid port",
		},
		{
			name:    "esp-port must be a number",
			mutate:  func(o map[string]string) { o[OptServerESPPort] = "esp" },
			wantErr: "invalid esp-port",
		},
		{
			name:    "esp-port must be in range",
			mutate:  func(o map[string]string) { o[OptServerESPPort] = "0" },
			wantErr: "invalid esp-port",
		},
		{
			name:    "the public address must be an IP",
			mutate:  func(o map[string]string) { o[OptServerPublicIP] = "gw.example.com" },
			wantErr: "invalid public address",
		},
		{
			name:    "shape must not be negative",
			mutate:  func(o map[string]string) { o[OptServerShape] = "-1" },
			wantErr: "invalid shape",
		},
		{
			// The certificate is read after the cheap validation, so a run that
			// gets this far has passed everything above it.
			name:    "a certificate is required",
			wantErr: "certificate",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := validServerOptions()
			if tt.mutate != nil {
				tt.mutate(opts)
			}
			srv, err := parseServerOptions(opts)
			if err == nil {
				if srv != nil {
					_ = srv.Close()
				}
				t.Fatalf("parseServerOptions(%v) was accepted, want an error containing %q", opts, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestNewServerRejects(t *testing.T) {
	tests := []struct {
		name    string
		cfg     ServerConfig
		wantErr string
	}{
		{
			name:    "no keypair",
			cfg:     ServerConfig{Users: map[string]string{"alice": "hunter2"}},
			wantErr: "certificate and key are required",
		},
		{
			name:    "no users",
			cfg:     ServerConfig{Cert: []byte("x"), Key: []byte("y")},
			wantErr: "at least one user is required",
		},
		{
			name:    "unparsable keypair",
			cfg:     ServerConfig{Cert: []byte("x"), Key: []byte("y"), Users: map[string]string{"a": "b"}},
			wantErr: "server keypair",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, err := NewServer(tt.cfg)
			if err == nil {
				if srv != nil {
					_ = srv.Close()
				}
				t.Fatalf("NewServer accepted %+v, want an error containing %q", tt.cfg, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestIsRegistered guards the init() side effects the CLI depends on: without
// them `veepin connect gp` and `veepin serve gp` fail at run time with an
// unknown-protocol error, and nothing at compile time says so.
func TestIsRegistered(t *testing.T) {
	if !slices.Contains(client.Protocols(), "gp") {
		t.Errorf("gp is not in client.Protocols() = %v", client.Protocols())
	}
	if !slices.Contains(client.ServerProtocols(), "gp") {
		t.Errorf("gp is not in client.ServerProtocols() = %v", client.ServerProtocols())
	}
}

// TestNetmaskOf covers the fallback: a gateway that sends no netmask must still
// leave the client with one that puts the gateway on-link.
func TestNetmaskOf(t *testing.T) {
	withMask := igp.Config{Netmask: net.IPMask(net.IPv4(255, 255, 0, 0).To4())}
	if got := netmaskOf(withMask); !net.IP(got).Equal(net.IPv4(255, 255, 0, 0)) {
		t.Errorf("netmaskOf kept %v, want the gateway's 255.255.0.0", got)
	}
	if got := netmaskOf(igp.Config{}); !net.IP(got).Equal(net.IPv4(255, 255, 255, 0)) {
		t.Errorf("netmaskOf defaulted to %v, want 255.255.255.0", got)
	}
}

// TestOuterIP: an unresolvable name must yield nil rather than a wrong address,
// because nil means "install no host route" and a wrong one sends the tunnel's
// own traffic out the wrong door.
func TestOuterIP(t *testing.T) {
	if got := outerIP("198.51.100.7"); !got.Equal(net.IPv4(198, 51, 100, 7)) {
		t.Errorf("outerIP of a literal = %v", got)
	}
	if got := outerIP("no-such-host.invalid"); got != nil {
		t.Errorf("outerIP of an unresolvable name = %v, want nil", got)
	}
}

// TestResultGatewayIsTheOuterAddress is the mistake client.Result.Validate exists
// to catch, checked here at the one place this package fills the field in.
func TestResultGatewayIsTheOuterAddress(t *testing.T) {
	res := client.Result{
		TUNName:    "gp0",
		AssignedIP: net.IPv4(10, 50, 0, 7),
		Netmask:    net.IP(net.CIDRMask(24, 32)),
		Gateway:    outerIP("198.51.100.7"),
		MTU:        client.DefaultTunnelMTU,
	}
	if err := res.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}

	// The inner gateway address is what must be rejected.
	res.Gateway = net.IPv4(10, 50, 0, 1)
	if err := res.Validate(); err == nil {
		t.Error("Validate accepted an inner address as the Gateway")
	}
}
