package ike

import (
	"bytes"
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/xen0bit/veepin/internal/ikev2/payload"
)

// capturingDataPath records Child SA lifecycle and MOBIKE peer-address updates,
// so a test can assert the server pushed a relocation into the data path. It
// implements ike.DataPath plus the peerAddrUpdater the MOBIKE path uses.
type capturingDataPath struct {
	added   chan *ChildSA
	updates chan *net.UDPAddr
}

func newCapturingDataPath() *capturingDataPath {
	return &capturingDataPath{
		added:   make(chan *ChildSA, 4),
		updates: make(chan *net.UDPAddr, 4),
	}
}

func (d *capturingDataPath) AddChild(sa *IKESA, c *ChildSA)    { d.added <- c }
func (d *capturingDataPath) RemoveChild(sa *IKESA, c *ChildSA) {}
func (d *capturingDataPath) UpdatePeerAddr(sa *IKESA, addr *net.UDPAddr) {
	d.updates <- addr
}

// mobikeServer starts a server whose DataPath captures MOBIKE updates.
func mobikeServer(t *testing.T) (p500, p4500 int, srv *Server, dp *capturingDataPath) {
	t.Helper()
	p500 = freeUDPPort(t)
	p4500 = freeUDPPort(t)
	dp = newCapturingDataPath()
	cfg := Config{
		ListenIP: "127.0.0.1", Port500: p500, Port4500: p4500,
		PSK:      []byte("mobike-psk"),
		LocalID:  FQDNIdentity("vpn.example"),
		PublicIP: net.ParseIP("127.0.0.1"),
		Logger:   log.New(io.Discard, "", 0),
		AssignAddr: func() (net.IP, net.IP, []net.IP, error) {
			return net.IPv4(10, 9, 9, 9), net.IPv4(255, 255, 255, 0), nil, nil
		},
		DataPath: dp,
	}
	var err error
	srv, err = NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	time.Sleep(50 * time.Millisecond)
	return p500, p4500, srv, dp
}

// newInitiator dials a fresh initiator socket to the server's IKE port.
func newInitiator(t *testing.T, host string, p500 int, psk []byte) *initiator {
	t.Helper()
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP(host), Port: p500})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	return &initiator{tb: t, conn: conn, psk: psk, id: FQDNIdentity("initiator.test")}
}

// rebind simulates a roam: it closes the initiator's socket and re-dials the
// same server from a new local port, so the server observes a new source
// address on the next message. The IKE SA state (SPIs, keys) is retained.
func (it *initiator) rebind(t *testing.T) {
	t.Helper()
	srv := it.conn.RemoteAddr().(*net.UDPAddr)
	it.conn.Close()
	conn, err := net.DialUDP("udp", nil, srv)
	if err != nil {
		t.Fatalf("rebind: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	it.conn = conn
}

// doAuthMobike is doAuth with a MOBIKE_SUPPORTED notify, returning whether the
// server confirmed MOBIKE in its response.
func (it *initiator) doAuthMobike(t *testing.T) bool {
	t.Helper()
	idBody := idPayloadBody(it.id)
	authData := computePSKAuth(it.suite.PRF, it.psk, it.saInitReq, it.nr, it.keys.SKpi, idBody)
	it.childOutSPI = newChildSPI()
	tsAll := payload.TSPayload{Selectors: []payload.TrafficSelector{allTrafficV4()}}
	cpReq := payload.CPPayload{Type: payload.CFGRequest, Attrs: []payload.CFGAttr{
		{Type: payload.CFGInternalIP4Address},
	}}

	b := payload.NewBuilder()
	b.Add(payload.TypeIDi, false, idBody)
	b.Add(payload.TypeAUTH, false, payload.MarshalAuth(payload.AuthPayload{
		Method: payload.AuthSharedKeyMIC, Data: authData,
	}))
	b.Add(payload.TypeCP, false, payload.MarshalCP(cpReq))
	b.Add(payload.TypeSA, false, payload.MarshalSA(payload.SAPayload{
		Proposals: []payload.Proposal{DefaultESPProposal(u32BE(it.childOutSPI))},
	}))
	b.Add(payload.TypeTSi, false, payload.MarshalTS(tsAll))
	b.Add(payload.TypeTSr, false, payload.MarshalTS(tsAll))
	addMobikeSupported(b)

	it.sendMsgID = 1
	it.send(it.buildEnc(payload.IKE_AUTH, 1, b.FirstType(), b.Bytes()))

	first, inner := it.openEnc(it.recv())
	inners, err := parseInnerPayloads(first, inner)
	if err != nil {
		t.Fatalf("AUTH resp inner parse: %v", err)
	}
	if findInner(inners, payload.TypeSA) == nil {
		t.Fatalf("AUTH resp did not carry a Child SA")
	}
	return findMobikeSupported(inners)
}

// sendUpdateSAAddresses drives an UPDATE_SA_ADDRESSES INFORMATIONAL from the
// initiator's current socket with a COOKIE2, returning the decoded response
// inner payloads.
func (it *initiator) sendUpdateSAAddresses(t *testing.T, msgID uint32, cookie2 []byte) []payload.RawPayload {
	t.Helper()
	local := it.conn.LocalAddr().(*net.UDPAddr)
	b := payload.NewBuilder()
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
		Protocol: payload.ProtoNone, Type: payload.UpdateSAAddresses,
	}))
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
		Protocol: payload.ProtoNone, Type: payload.NATDetectionSourceIP,
		Data: natDetectionHash(it.spiI, it.spiR, local.IP, uint16(local.Port)),
	}))
	srv := it.conn.RemoteAddr().(*net.UDPAddr)
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
		Protocol: payload.ProtoNone, Type: payload.NATDetectionDestinationIP,
		Data: natDetectionHash(it.spiI, it.spiR, srv.IP, uint16(srv.Port)),
	}))
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
		Protocol: payload.ProtoNone, Type: payload.Cookie2, Data: cookie2,
	}))
	it.send(it.buildEnc(payload.INFORMATIONAL, msgID, b.FirstType(), b.Bytes()))
	first, inner := it.openEnc(it.recv())
	inners, err := parseInnerPayloads(first, inner)
	if err != nil {
		t.Fatalf("UPDATE_SA_ADDRESSES resp inner parse: %v", err)
	}
	return inners
}

// TestMobikeServerRelocatesSA is the responder proof: after MOBIKE is
// negotiated, an UPDATE_SA_ADDRESSES from a brand-new source socket relocates
// the SA — the server echoes COOKIE2, pushes the new address into the data
// path, and updates the Child SA's return address — all without a new
// handshake.
func TestMobikeServerRelocatesSA(t *testing.T) {
	p500, p4500, srv, dp := mobikeServer(t)
	defer srv.Close()

	// Handshake on port 500, then move to 4500 like a real client (MOBIKE and
	// ESP both ride the NAT-T port).
	_ = p4500
	it := newInitiator(t, "127.0.0.1", p500, []byte("mobike-psk"))
	defer it.conn.Close()
	it.doSAInit()
	if !it.doAuthMobike(t) {
		t.Fatal("server did not confirm MOBIKE_SUPPORTED")
	}

	// Drain the initial AddChild.
	var child *ChildSA
	select {
	case child = <-dp.added:
	case <-time.After(2 * time.Second):
		t.Fatal("no Child SA established")
	}

	// Now "roam": rebind the initiator to a fresh local port and send
	// UPDATE_SA_ADDRESSES. The server must relocate to this new source address.
	it.rebind(t)
	newLocal := it.conn.LocalAddr().(*net.UDPAddr)
	cookie2 := randomNonce(16)
	inners := it.sendUpdateSAAddresses(t, 2, cookie2)

	// COOKIE2 must be echoed verbatim.
	echo := findNotify(inners, payload.Cookie2)
	if echo == nil || !bytes.Equal(echo.Data, cookie2) {
		t.Fatalf("server did not echo COOKIE2")
	}
	// The response must carry the server's NAT detection (so the peer
	// re-evaluates) — proof the update was accepted, not ignored.
	if findNotify(inners, payload.NATDetectionSourceIP) == nil {
		t.Fatalf("server did not return NAT detection on relocation")
	}

	// The data path must have been told the new return address.
	select {
	case addr := <-dp.updates:
		if addr.Port != newLocal.Port {
			t.Fatalf("data path moved to %s, want port %d", addr, newLocal.Port)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("data path was not told of the relocation")
	}

	// And the Child SA's own return address followed.
	srv.mu.RLock()
	sa := srv.byRSPI[it.spiR]
	srv.mu.RUnlock()
	if sa == nil {
		t.Fatal("SA vanished after relocation")
	}
	sa.mu.Lock()
	movedTo := child.PeerAddr
	saAddr := sa.RemoteAddr
	sa.mu.Unlock()
	if movedTo == nil || movedTo.Port != newLocal.Port {
		t.Fatalf("Child SA return address = %v, want port %d", movedTo, newLocal.Port)
	}
	if saAddr == nil || saAddr.Port != newLocal.Port {
		t.Fatalf("IKE SA remote address = %v, want port %d", saAddr, newLocal.Port)
	}
}

// TestClientRoam is the initiator proof: the production Client negotiates
// MOBIKE, then Roam() rebinds to a new local port and drives the
// UPDATE_SA_ADDRESSES exchange (verifying the server's COOKIE2 echo), and the
// server relocates the Child SA's return address to the client's new port.
func TestClientRoam(t *testing.T) {
	p500, p4500, srv, dp := mobikeServer(t)
	defer srv.Close()

	client := NewClient(ClientConfig{
		ServerHost: "127.0.0.1", ServerPort: p500, NATTPort: p4500,
		PSK:     []byte("mobike-psk"),
		LocalID: FQDNIdentity("client.example"),
		Logger:  log.New(io.Discard, "", 0),
	})
	if _, err := client.Connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()

	if !client.MobikeEnabled() {
		t.Fatal("client did not negotiate MOBIKE")
	}
	select {
	case <-dp.added:
	case <-time.After(2 * time.Second):
		t.Fatal("no Child SA established")
	}

	oldLocal := client.DataConn().LocalAddr().(*net.UDPAddr)
	if err := client.Roam(); err != nil {
		t.Fatalf("roam: %v", err)
	}
	newLocal := client.DataConn().LocalAddr().(*net.UDPAddr)
	if newLocal.Port == oldLocal.Port {
		t.Fatal("roam did not rebind to a new local port")
	}

	// The server must have relocated the data path to the new local port.
	select {
	case addr := <-dp.updates:
		if addr.Port != newLocal.Port {
			t.Fatalf("server relocated to %s, want the client's new port %d", addr, newLocal.Port)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server never relocated the SA after client roam")
	}
}

// TestClientRoamRequiresNegotiation confirms Roam fails cleanly when the peer
// is not MOBIKE-capable. A server built without our MOBIKE echo can't be
// constructed here (we always support it), so this drives the guard directly on
// a client that never connected.
func TestClientRoamRequiresNegotiation(t *testing.T) {
	client := NewClient(ClientConfig{
		ServerHost: "127.0.0.1", ServerPort: 500,
		PSK:     []byte("x"),
		LocalID: FQDNIdentity("client.example"),
		Logger:  log.New(io.Discard, "", 0),
	})
	if err := client.Roam(); err == nil {
		t.Fatal("Roam should fail before a MOBIKE-enabled connect")
	}
}

// TestMobikeUpdateIgnoredWithoutNegotiation confirms a peer cannot move an SA
// that never negotiated MOBIKE: the COOKIE2 is still echoed (a bare
// return-routability probe must work), but no relocation happens.
func TestMobikeUpdateIgnoredWithoutNegotiation(t *testing.T) {
	p500, p4500, srv, dp := mobikeServer(t)
	defer srv.Close()

	_ = p4500
	it := newInitiator(t, "127.0.0.1", p500, []byte("mobike-psk"))
	defer it.conn.Close()
	it.doSAInit()
	it.doAuth() // plain AUTH, no MOBIKE_SUPPORTED

	select {
	case <-dp.added:
	case <-time.After(2 * time.Second):
		t.Fatal("no Child SA established")
	}

	cookie2 := randomNonce(16)
	inners := it.sendUpdateSAAddresses(t, 2, cookie2)

	if echo := findNotify(inners, payload.Cookie2); echo == nil || !bytes.Equal(echo.Data, cookie2) {
		t.Fatalf("COOKIE2 must be echoed even on a non-MOBIKE SA")
	}
	// No relocation: the data path must not be told anything.
	select {
	case addr := <-dp.updates:
		t.Fatalf("non-MOBIKE SA was relocated to %s", addr)
	case <-time.After(300 * time.Millisecond):
	}
}
