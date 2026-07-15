package ike

import (
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xen0bit/ikennkt/internal/crypto"
	"github.com/xen0bit/ikennkt/internal/dataplane"
	"github.com/xen0bit/ikennkt/internal/esp"
)

// memTUN is an in-memory TUN device for the integration test: packets the
// server writes to it are captured and signalled.
type memTUN struct {
	mu      sync.Mutex
	written [][]byte
	sig     chan struct{}
}

func newMemTUN() *memTUN { return &memTUN{sig: make(chan struct{}, 16)} }

func (m *memTUN) Read(buf []byte) (int, error) {
	select {} // never produces outbound packets in this test
}
func (m *memTUN) Write(pkt []byte) (int, error) {
	m.mu.Lock()
	m.written = append(m.written, append([]byte(nil), pkt...))
	m.mu.Unlock()
	m.sig <- struct{}{}
	return len(pkt), nil
}
func (m *memTUN) last() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.written) == 0 {
		return nil
	}
	return m.written[len(m.written)-1]
}

// TestFullVPNFlow is the definitive end-to-end test: a client completes the
// IKEv2 handshake with NAT-T and CP, is assigned an internal address, and then
// sends a real IP packet through the ESP data path that must land on the
// server's TUN device.
func TestFullVPNFlow(t *testing.T) {
	psk := []byte("integration-psk")
	p500 := freeUDPPort(t)
	p4500 := freeUDPPort(t)

	pool, gateway, err := dataplane.NewAddrPool("10.20.30.0/24")
	if err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		ListenIP: "127.0.0.1",
		Port500:  p500,
		Port4500: p4500,
		PSK:      psk,
		LocalID:  FQDNIdentity("vpn.example"),
		PublicIP: net.ParseIP("127.0.0.1"),
		Logger:   log.New(io.Discard, "", 0),
		AssignAddr: func() (net.IP, net.IP, []net.IP, error) {
			ip, aerr := pool.Allocate()
			return ip, pool.Netmask(), []net.IP{net.ParseIP("1.1.1.1")}, aerr
		},
		ReleaseAddr: func(ip net.IP) { pool.Release(ip) },
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	tun := newMemTUN()
	pump := dataplane.NewPump(tun, srv.SendESP, log.New(io.Discard, "", 0))
	srv.SetDataPath(NewPumpDataPath(pump))
	go pump.Run()
	defer pump.Close()

	go func() { _ = srv.ListenAndServe() }()
	defer srv.Close()
	time.Sleep(50 * time.Millisecond)

	// --- Client handshake over the NAT-T port (simulating a client behind NAT
	// that has floated to 4500). We run the whole exchange on :4500 with the
	// non-ESP marker, as a real NATed client does after IKE_SA_INIT. ---
	serverAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: p500}
	cli, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	_ = cli.SetReadDeadline(time.Now().Add(3 * time.Second))

	it := &initiator{tb: t, conn: cli, psk: psk, id: FQDNIdentity("client.example")}
	it.doSAInit()
	it.doAuth()

	// The client must have been assigned an address from the pool.
	if it.assignedIP == nil {
		t.Fatal("client was not assigned an internal address via CP")
	}
	if !it.assignedIP.Equal(net.ParseIP("10.20.30.2")) {
		t.Fatalf("assigned IP = %v, want 10.20.30.2 (first pool host)", it.assignedIP)
	}
	t.Logf("client assigned %v (gateway %v)", it.assignedIP, gateway)

	// --- Data path: client sends an IP packet through ESP to the server. ---
	// Build the client-side ESP SA from the negotiated keys. The client's
	// outbound uses the initiator->responder keys; the server opens with those.
	outCipher, err := cryptoNewSKCipher(it.childES)
	if err != nil {
		t.Fatal(err)
	}
	inCipher, err := cryptoNewSKCipher(it.childES)
	if err != nil {
		t.Fatal(err)
	}
	clientESP := &esp.SA{
		SPIOut: it.childRespSPI, // server's inbound SPI
		SPIIn:  it.childOutSPI,
		Out: esp.Transform{
			Cipher: outCipher,
			Integ:  it.childES.Integ,
			EncKey: it.childEncI, IntegKey: it.childIntegI,
		},
		In: esp.Transform{
			Cipher: inCipher,
			Integ:  it.childES.Integ,
			EncKey: it.childEncR, IntegKey: it.childIntegR,
		},
	}

	// An IP packet from the client's assigned address to some internet host.
	innerPkt := buildIPv4(it.assignedIP, net.ParseIP("93.184.216.34"), []byte("GET / tunnel test"))
	espPkt, err := clientESP.Encapsulate(innerPkt, 4)
	if err != nil {
		t.Fatal(err)
	}

	// Send it to the server's NAT-T/ESP socket (raw ESP, non-zero SPI).
	espConn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: p4500})
	if err != nil {
		t.Fatal(err)
	}
	defer espConn.Close()
	if _, err := espConn.Write(espPkt); err != nil {
		t.Fatal(err)
	}

	// The server must decapsulate and write the inner packet to its TUN.
	select {
	case <-tun.sig:
	case <-time.After(2 * time.Second):
		t.Fatal("ESP packet from client never reached the server TUN")
	}
	got := tun.last()
	if !bytes.Equal(got, innerPkt) {
		t.Fatalf("TUN packet mismatch: got %d bytes, want %d", len(got), len(innerPkt))
	}
	t.Logf("inner packet (%d bytes) successfully traversed client -> ESP -> server TUN", len(got))
}

// cryptoNewSKCipher builds a fresh SK cipher instance for the ESP suite so the
// client and server hold independent cipher state.
func cryptoNewSKCipher(es ESPSuite) (crypto.SKCipher, error) {
	return crypto.NewSKCipher(es.EncrID, int(es.EncrKeyLn))
}

// buildIPv4 constructs a minimal IPv4/UDP packet.
func buildIPv4(src, dst net.IP, payload []byte) []byte {
	pkt := make([]byte, 20+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64 // TTL
	pkt[9] = 17 // UDP
	copy(pkt[12:16], src.To4())
	copy(pkt[16:20], dst.To4())
	copy(pkt[20:], payload)
	return pkt
}
