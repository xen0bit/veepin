package ike

import (
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/xen0bit/veepin/internal/ikev2/payload"
	"github.com/xen0bit/veepin/internal/ikev2/transform"
	"github.com/xen0bit/veepin/internal/vlog"
)

// gateServer starts a responder with the given PSK (possibly empty) and, when
// ca is non-nil, a server certificate from it. Every Child SA it installs is
// reported on the returned channel.
func gateServer(t *testing.T, psk []byte, ca *testCA) (p500 int, srv *Server, children chan *ChildSA) {
	t.Helper()
	p500 = freeUDPPort(t)
	children = make(chan *ChildSA, 4)
	cfg := Config{
		ListenIP: "127.0.0.1", Port500: p500, Port4500: freeUDPPort(t),
		PSK:       psk,
		LocalID:   FQDNIdentity("vpn.example"),
		Logger:    vlog.Discard(),
		OnChildSA: func(_ *IKESA, c *ChildSA) { children <- c },
	}
	if ca != nil {
		cfg.ServerCert = ca.issueTLS(t, "vpn.example", ecKey(t, elliptic.P256()))
		cfg.ClientCAs = ca.pool
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	time.Sleep(50 * time.Millisecond)
	return p500, srv, children
}

func gateInitiator(t *testing.T, p500 int, psk []byte) *initiator {
	t.Helper()
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: p500})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	return &initiator{tb: t, conn: conn, psk: psk, id: FQDNIdentity("initiator.test")}
}

// expectSilence asserts the responder sends nothing back within a short window.
func expectSilence(t *testing.T, it *initiator) {
	t.Helper()
	_ = it.conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 65535)
	_, err := it.conn.Read(buf)
	if err == nil {
		t.Fatal("responder answered a message it should have refused")
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read: %v", err)
	}
	_ = it.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
}

// TestCreateChildSABeforeIKEAuthIsRefused: the keys from IKE_SA_INIT come from
// an unauthenticated Diffie-Hellman, so a CREATE_CHILD_SA sealed under them
// proves nothing about who sent it. If this fails, a peer that never
// authenticated gets a Child SA whose ESP reaches the TUN.
func TestCreateChildSABeforeIKEAuthIsRefused(t *testing.T) {
	psk := []byte("gate-psk")
	p500, srv, children := gateServer(t, psk, nil)
	defer srv.Close()

	it := gateInitiator(t, p500, psk)
	it.doSAInit()

	tsAll := payload.TSPayload{Selectors: []payload.TrafficSelector{allTrafficV4()}}
	b := payload.NewBuilder()
	b.Add(payload.TypeSA, false, payload.MarshalSA(payload.SAPayload{
		Proposals: DefaultESPProposals(u32BE(newChildSPI())),
	}))
	b.Add(payload.TypeNonce, false, payload.MarshalNonce(randomNonce(32)))
	b.Add(payload.TypeTSi, false, payload.MarshalTS(tsAll))
	b.Add(payload.TypeTSr, false, payload.MarshalTS(tsAll))
	it.send(it.buildEnc(payload.CREATE_CHILD_SA, 1, b.FirstType(), b.Bytes()))

	expectSilence(t, it)
	select {
	case <-children:
		t.Fatal("a Child SA was installed for a peer that never authenticated")
	default:
	}

	// The refusal must not have consumed the message ID: the real IKE_AUTH
	// still goes through at ID 1.
	it.doAuth()
	select {
	case <-children:
	case <-time.After(2 * time.Second):
		t.Fatal("IKE_AUTH after the refused exchange did not establish a Child SA")
	}
}

// TestInformationalBeforeIKEAuthIsRefused: RFC 7296 §1.4 allows INFORMATIONAL
// only after the initial exchanges, and before then its keys authenticate no
// one.
func TestInformationalBeforeIKEAuthIsRefused(t *testing.T) {
	psk := []byte("gate-psk")
	p500, srv, _ := gateServer(t, psk, nil)
	defer srv.Close()

	it := gateInitiator(t, p500, psk)
	it.doSAInit()
	it.send(it.buildEnc(payload.INFORMATIONAL, 1, payload.NoNextPayload, nil))
	expectSilence(t, it)
}

// TestCertOnlyServerRefusesPSKAuth: a server configured with a certificate and
// no PSK must not evaluate method-2 AUTH under the empty key, which any peer
// can compute. If this fails, a certificate-only gateway admits anyone.
func TestCertOnlyServerRefusesPSKAuth(t *testing.T) {
	p500, srv, children := gateServer(t, nil, newTestCA(t))
	defer srv.Close()

	it := gateInitiator(t, p500, nil) // AUTH computed with an empty key
	it.doSAInit()

	idBody := idPayloadBody(it.id)
	authData := computePSKAuth(it.suite.PRF, nil, it.saInitReq, it.nr, it.keys.SKpi, idBody, nil)
	tsAll := payload.TSPayload{Selectors: []payload.TrafficSelector{allTrafficV4()}}
	b := payload.NewBuilder()
	b.Add(payload.TypeIDi, false, idBody)
	b.Add(payload.TypeAUTH, false, payload.MarshalAuth(payload.AuthPayload{
		Method: payload.AuthSharedKeyMIC, Data: authData,
	}))
	b.Add(payload.TypeSA, false, payload.MarshalSA(payload.SAPayload{
		Proposals: DefaultESPProposals(u32BE(newChildSPI())),
	}))
	b.Add(payload.TypeTSi, false, payload.MarshalTS(tsAll))
	b.Add(payload.TypeTSr, false, payload.MarshalTS(tsAll))
	it.send(it.buildEnc(payload.IKE_AUTH, 1, b.FirstType(), b.Bytes()))

	first, inner := it.openEnc(it.recv())
	inners, err := parseInnerPayloads(first, inner)
	if err != nil {
		t.Fatal(err)
	}
	if findInner(inners, payload.TypeSA) != nil || findInner(inners, payload.TypeAUTH) != nil {
		t.Fatal("certificate-only server accepted PSK authentication under an empty key")
	}
	select {
	case <-children:
		t.Fatal("a Child SA was installed after empty-key PSK authentication")
	default:
	}
}

// TestVerifyPeerPSKAuthRefusesAnEmptyKey pins the refusal where both roles
// share it, so a future caller cannot reintroduce the empty-key path.
func TestVerifyPeerPSKAuthRefusesAnEmptyKey(t *testing.T) {
	prf, err := transform.PRF(payload.PRF_HMAC_SHA2_256)
	if err != nil {
		t.Fatal(err)
	}
	want := computePSKAuth(prf, nil, []byte("m"), []byte("n"), []byte("k"), []byte("id"), nil)
	if err := verifyPeerPSKAuth(prf, nil, []byte("m"), []byte("n"), []byte("k"), []byte("id"), nil, want); !errors.Is(err, errNoPSK) {
		t.Fatalf("empty PSK: got %v, want errNoPSK", err)
	}
}

// TestCertClientChecksTheDialledHostWithoutRemoteID: with no RemoteID the
// client must still require the server's certificate to name the host it
// dialled. The test server's certificate names vpn.example and the client
// dials 127.0.0.1, so the connection must fail. If it succeeds, any holder of
// a trusted certificate can stand in for the gateway.
func TestCertClientChecksTheDialledHostWithoutRemoteID(t *testing.T) {
	ca := newTestCA(t)
	p500, p4500, srv, _ := certAuthServer(t, ca, ecKey(t, elliptic.P256()))
	defer srv.Close()

	client := NewClient(ClientConfig{
		ServerHost: "127.0.0.1", ServerPort: p500, NATTPort: p4500,
		LocalID:    FQDNIdentity("client.example"),
		ClientCert: ca.issueTLS(t, "client.example", ecKey(t, elliptic.P256())),
		CARoots:    ca.pool,
		Logger:     vlog.Discard(),
	})
	if _, err := client.Connect(); err == nil {
		client.Close()
		t.Fatal("client accepted a server certificate that does not name the dialled host")
	}
}

// TestCheckableIDTypeExcludesKeyID: certMatchesID passes KEY_ID without
// looking, so the client must treat it as uncheckable rather than as a match.
func TestCheckableIDTypeExcludesKeyID(t *testing.T) {
	if checkableIDType(payload.IDKeyID) {
		t.Fatal("KEY_ID reported as checkable against a certificate")
	}
	for _, ty := range []payload.IDType{payload.IDFQDN, payload.IDIPv4Addr, payload.IDIPv6Addr, payload.IDRFC822, payload.IDDERASN1DN} {
		if !checkableIDType(ty) {
			t.Fatalf("%v reported as uncheckable", ty)
		}
	}
}

// TestRequireServerUsageRefusesAClientOnlyCertificate: a certificate the CA
// issued for client use only must not authenticate a responder.
func TestRequireServerUsageRefusesAClientOnlyCertificate(t *testing.T) {
	cases := []struct {
		name string
		cert x509.Certificate
		ok   bool
	}{
		{"no EKU", x509.Certificate{}, true},
		{"serverAuth", x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, true},
		{"any", x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}, true},
		{"ipsecIKE", x509.Certificate{UnknownExtKeyUsage: []asn1.ObjectIdentifier{oidIPsecIKE}}, true},
		{"clientAuth only", x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, false},
	}
	for _, tc := range cases {
		err := requireServerUsage(&tc.cert)
		if (err == nil) != tc.ok {
			t.Errorf("%s: got %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

// TestRequirePostQuantumRefusesAClassicalResponder: pq-ikev2 promises a
// post-quantum key exchange or none. If this fails, the client completes a
// classical-only IKE SA while its name says otherwise, and a recording of the
// session is decryptable by whoever later breaks the classical group.
func TestRequirePostQuantumRefusesAClassicalResponder(t *testing.T) {
	p500, p4500 := freeUDPPort(t), freeUDPPort(t)
	srv, err := NewServer(Config{
		ListenIP: "127.0.0.1", Port500: p500, Port4500: p4500,
		PSK: []byte("test-psk"), LocalID: FQDNIdentity("vpn.example"),
		PublicIP: net.ParseIP("127.0.0.1"), Logger: vlog.Discard(),
		AssignAddr: func(AddressRequest) (Assignment, error) {
			return Assignment{IP4: net.IPv4(10, 8, 8, 8), Netmask: net.IPv4(255, 255, 255, 0)}, nil
		},
		classicalOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	defer srv.Close()
	time.Sleep(50 * time.Millisecond)

	for _, require := range []bool{false, true} {
		client := NewClient(ClientConfig{
			ServerHost: "127.0.0.1", ServerPort: p500, NATTPort: p4500,
			PSK: []byte("test-psk"), LocalID: FQDNIdentity("client.example"),
			PostQuantum: true, RequirePostQuantum: require, Logger: vlog.Discard(),
		})
		_, err := client.Connect()
		if err == nil {
			client.Close()
		}
		switch {
		case require && err == nil:
			t.Fatal("a client requiring post-quantum completed a classical-only handshake")
		case !require && err != nil:
			t.Fatalf("plain PostQuantum must still fall back: %v", err)
		}
	}
}

// TestNarrowingKeepsTheSelectorThatHoldsTheLease: strongSwan proposes a trap
// policy's ICMP-echo-only selector ahead of the full one. If this fails, a
// second Child SA is narrowed to echo requests, the server routes all of the
// lease's replies into it, and the peer drops them by policy.
func TestNarrowingKeepsTheSelectorThatHoldsTheLease(t *testing.T) {
	sa := newIKESA()
	sa.ClientIP = net.IPv4(10, 10, 10, 2).To4()
	tsi := payload.TSPayload{Selectors: []payload.TrafficSelector{
		{Type: payload.TSIPv4AddrRange, IPProtocol: 1, StartPort: 0x0800, EndPort: 0x0800,
			StartAddr: net.IPv4(172, 18, 0, 3).To4(), EndAddr: net.IPv4(172, 18, 0, 3).To4()},
		{Type: payload.TSIPv4AddrRange, StartPort: 0, EndPort: 0xffff,
			StartAddr: net.IPv4(10, 10, 10, 2).To4(), EndAddr: net.IPv4(10, 10, 10, 2).To4()},
	}}
	got, _ := narrowTSiToAssignment(tsi, sa)
	if len(got.Selectors) != 1 {
		t.Fatalf("got %d selectors", len(got.Selectors))
	}
	if s := got.Selectors[0]; s.IPProtocol != 0 || s.EndPort != 0xffff || !s.StartAddr.Equal(sa.ClientIP) {
		t.Fatalf("narrowed to %+v, want the lease with any protocol and port", s)
	}
}
