package dataplane

import (
	"bytes"
	"encoding/binary"
	"github.com/xen0bit/ikennkt/internal/crypto"
	"github.com/xen0bit/ikennkt/internal/esp"
	"github.com/xen0bit/ikennkt/internal/payload"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeTUN is an in-memory TUN device: writes are captured, reads block on an
// injected queue.
type fakeTUN struct {
	mu       sync.Mutex
	written  [][]byte
	writeSig chan struct{}
	readQ    chan []byte
}

func newFakeTUN() *fakeTUN {
	return &fakeTUN{writeSig: make(chan struct{}, 16), readQ: make(chan []byte, 16)}
}

func (f *fakeTUN) Read(buf []byte) (int, error) {
	pkt, ok := <-f.readQ
	if !ok {
		return 0, net.ErrClosed
	}
	n := copy(buf, pkt)
	return n, nil
}

func (f *fakeTUN) Write(pkt []byte) (int, error) {
	f.mu.Lock()
	f.written = append(f.written, append([]byte(nil), pkt...))
	f.mu.Unlock()
	f.writeSig <- struct{}{}
	return len(pkt), nil
}

func (f *fakeTUN) lastWrite() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.written) == 0 {
		return nil
	}
	return f.written[len(f.written)-1]
}

// fakeTunnel is an ESPTunnel backed by a pair of esp.SAs for a round trip.
type fakeTunnel struct {
	inSPI    uint32
	clientIP net.IP
	peer     *net.UDPAddr
	enc      func([]byte) ([]byte, error)
	dec      func([]byte) ([]byte, error)
}

func (t *fakeTunnel) InboundSPI() uint32                   { return t.inSPI }
func (t *fakeTunnel) ClientIP() net.IP                     { return t.clientIP }
func (t *fakeTunnel) PeerAddr() *net.UDPAddr               { return t.peer }
func (t *fakeTunnel) UDPEncap() bool                       { return true }
func (t *fakeTunnel) Encapsulate(p []byte) ([]byte, error) { return t.enc(p) }
func (t *fakeTunnel) Decapsulate(p []byte) ([]byte, error) { return t.dec(p) }

// makeIPv4 builds a minimal IPv4 packet with the given dst address and payload.
func makeIPv4(dst net.IP, payload []byte) []byte {
	pkt := make([]byte, 20+len(payload))
	pkt[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[9] = 17 // UDP
	copy(pkt[12:16], net.IPv4(10, 10, 10, 1).To4())
	copy(pkt[16:20], dst.To4())
	copy(pkt[20:], payload)
	return pkt
}

// TestPumpRoundTrip proves an IP packet written to TUN is ESP-encapsulated and
// routed to the right peer, and that an inbound ESP packet is decapsulated and
// written back to TUN.
func TestPumpRoundTrip(t *testing.T) {
	client := net.IPv4(10, 10, 10, 2).To4()
	peer := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 5), Port: 4500}

	// A pair of esp.SAs: the server side encrypts outbound with its Out keys,
	// and we decrypt here using a mirrored SA to simulate the client.
	serverSA, clientSA := espPair(t)

	sentCh := make(chan []byte, 4)
	send := func(esp []byte, to *net.UDPAddr, udpEncap bool) {
		if !to.IP.Equal(peer.IP) {
			t.Errorf("sent to wrong peer: %v", to)
		}
		sentCh <- esp
	}

	tun := newFakeTUN()
	pump := NewPump(tun, send, nil)

	tunnel := &fakeTunnel{
		inSPI:    serverSA.SPIIn,
		clientIP: client,
		peer:     peer,
		enc:      func(p []byte) ([]byte, error) { return serverSA.Encapsulate(p, 4) },
		dec: func(p []byte) ([]byte, error) {
			inner, _, err := serverSA.Decapsulate(p)
			return inner, err
		},
	}
	pump.AddTunnel(tunnel)

	go pump.Run()
	defer pump.Close()

	// --- Outbound: TUN -> ESP ---
	payload := []byte("hello over the tunnel")
	tun.readQ <- makeIPv4(client, payload)

	var espBytes []byte
	select {
	case espBytes = <-sentCh:
	case <-time.After(2 * time.Second):
		t.Fatal("no ESP packet sent for outbound TUN packet")
	}
	// The client side decrypts it and checks the inner packet survived.
	inner, _, err := clientSA.Decapsulate(espBytes)
	if err != nil {
		t.Fatalf("client decap failed: %v", err)
	}
	if !bytes.Equal(inner[20:], payload) {
		t.Fatalf("inner payload mismatch: %q", inner[20:])
	}

	// --- Inbound: ESP -> TUN ---
	// Client encrypts a packet to the server; the pump must demux by SPI and
	// write the inner packet to TUN.
	reply := makeIPv4(net.IPv4(10, 10, 10, 1), []byte("reply from client"))
	espIn, err := clientSA.Encapsulate(reply, 4)
	if err != nil {
		t.Fatal(err)
	}
	pump.HandleESP(espIn)

	select {
	case <-tun.writeSig:
	case <-time.After(2 * time.Second):
		t.Fatal("inbound ESP was not written to TUN")
	}
	got := tun.lastWrite()
	if !bytes.Equal(got, reply) {
		t.Fatalf("TUN write mismatch: got %d bytes", len(got))
	}
}

// TestPumpUnknownSPIDropped ensures an ESP packet with an unknown SPI is
// silently dropped (no TUN write).
func TestPumpUnknownSPIDropped(t *testing.T) {
	tun := newFakeTUN()
	pump := NewPump(tun, func([]byte, *net.UDPAddr, bool) {}, nil)
	esp := make([]byte, 40)
	binary.BigEndian.PutUint32(esp[:4], 0xdeadbeef)
	pump.HandleESP(esp)
	select {
	case <-tun.writeSig:
		t.Fatal("unknown SPI should not produce a TUN write")
	case <-time.After(200 * time.Millisecond):
	}
}

// espPair builds two esp.SAs that mirror each other: server.Out == client.In
// and vice versa, so packets encrypted by one decrypt on the other.
func espPair(t *testing.T) (server, client *esp.SA) {
	t.Helper()
	c1, err := crypto.NewSKCipher(payload.ENCR_AES_GCM_16, 256)
	if err != nil {
		t.Fatal(err)
	}
	c2, _ := crypto.NewSKCipher(payload.ENCR_AES_GCM_16, 256)
	c3, _ := crypto.NewSKCipher(payload.ENCR_AES_GCM_16, 256)
	c4, _ := crypto.NewSKCipher(payload.ENCR_AES_GCM_16, 256)
	keyA := bytes.Repeat([]byte{0xa1}, c1.KeyLen())
	keyB := bytes.Repeat([]byte{0xb2}, c1.KeyLen())
	const spiS, spiC = uint32(0x11111111), uint32(0x22222222)
	server = &esp.SA{
		SPIOut: spiC, SPIIn: spiS,
		Out: esp.Transform{Cipher: c1, EncKey: keyA},
		In:  esp.Transform{Cipher: c2, EncKey: keyB},
	}
	client = &esp.SA{
		SPIOut: spiS, SPIIn: spiC,
		Out: esp.Transform{Cipher: c3, EncKey: keyB},
		In:  esp.Transform{Cipher: c4, EncKey: keyA},
	}
	return server, client
}
