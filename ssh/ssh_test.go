package ssh

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"strconv"
	"testing"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/xen0bit/veepin/client"
)

func TestParseCIDR(t *testing.T) {
	ip, mask, err := parseCIDR("10.200.0.2/30")
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(net.IPv4(10, 200, 0, 2)) {
		t.Errorf("ip = %v, want 10.200.0.2", ip)
	}
	if got := net.IP(mask).String(); got != "255.255.255.252" {
		t.Errorf("mask = %v, want 255.255.255.252", got)
	}
	if _, _, err := parseCIDR("nonsense"); err == nil {
		t.Error("parseCIDR accepted a non-CIDR string")
	}
}

func TestConfigValidate(t *testing.T) {
	base := Config{Server: "s", User: "u", Address: "10.0.0.2/30", Identity: "k"}
	if err := base.validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for name, mut := range map[string]func(*Config){
		"no server":  func(c *Config) { c.Server = "" },
		"no user":    func(c *Config) { c.User = "" },
		"no address": func(c *Config) { c.Address = "" },
		"no auth":    func(c *Config) { c.Identity = ""; c.Password = "" },
	} {
		c := base
		mut(&c)
		if err := c.validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func TestParseOptionsDefaultsPeerUnitToAny(t *testing.T) {
	d, err := parseOptions(map[string]string{
		OptServer: "s", OptUser: "u", OptAddress: "10.0.0.2/30", OptIdentity: "k",
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.(dialer).cfg.PeerUnit != -1 {
		t.Errorf("PeerUnit = %d, want -1 (any)", d.(dialer).cfg.PeerUnit)
	}
}

// TestServerRefusingEveryMethodIsClientErrAuth drives a real x/crypto/ssh server
// that accepts no password and asserts the facade turns its refusal into
// client.ErrAuth.
//
// The message is the contract here, and it is not ours. x/crypto/ssh exports no
// sentinel for a rejected login -- clientAuthenticate ends in a bare
// fmt.Errorf("ssh: unable to authenticate, ...") -- so authError matches the
// leading clause, exactly as x/crypto's own client_auth_test.go does to
// recognise the same condition. That is a string match on another module's
// prose, which this test exists to make loud: if a future x/crypto rewords it,
// this fails, rather than every wrong SSH password quietly becoming a retryable
// outage again and `veepin connect -retry` replaying it into sshd's MaxAuthTries.
func TestServerRefusingEveryMethodIsClientErrAuth(t *testing.T) {
	hostKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptossh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatal(err)
	}
	srvCfg := &cryptossh.ServerConfig{
		PasswordCallback: func(cryptossh.ConnMetadata, []byte) (*cryptossh.Permissions, error) {
			return nil, errors.New("no")
		},
	}
	srvCfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		nc, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		// The handshake is expected to fail; the server's job here is only to
		// get far enough to refuse.
		_, _, _, _ = cryptossh.NewServerConn(nc, srvCfg)
		_ = nc.Close()
	}()

	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = Dial(context.Background(), Config{
		Server:   host,
		Port:     p,
		User:     "someone",
		Password: "wrong",
		Address:  "10.200.0.2/30",
		Insecure: true,
		TUNName:  "veepin-test-never-opened",
		PeerUnit: -1,
	})
	if err == nil {
		t.Fatal("Dial succeeded against a server that accepts no credentials")
	}
	if !errors.Is(err, client.ErrAuth) {
		t.Fatalf("Dial error = %v\nwant one satisfying errors.Is(err, client.ErrAuth): "+
			"x/crypto/ssh's refusal is no longer recognised, so a wrong password now "+
			"reads as a retryable transport failure", err)
	}
}
