package dataplane

import (
	"bytes"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xen0bit/veepin/internal/ikev2/esp"
	"github.com/xen0bit/veepin/internal/ikev2/payload"
	"github.com/xen0bit/veepin/internal/ikev2/transform"
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

// fakeTunnel is a Tunnel backed by a pair of esp.SAs for a round trip.
type fakeTunnel struct {
	inSPI    uint32
	clientIP net.IP
	peer     *net.UDPAddr
	enc      func([]byte) ([]byte, error)
	dec      func([]byte) ([]byte, error)
}

func (t *fakeTunnel) InboundKey() uint32                   { return t.inSPI }
func (t *fakeTunnel) ClientIP() net.IP                     { return t.clientIP }
func (t *fakeTunnel) PeerAddr() *net.UDPAddr               { return t.peer }
func (t *fakeTunnel) Encapsulate(p []byte) ([]byte, error) { return t.enc(p) }
func (t *fakeTunnel) Decapsulate(p []byte) ([]byte, error) { return t.dec(p) }
func (t *fakeTunnel) SetPeerAddr(a *net.UDPAddr)           { t.peer = a }

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
	send := func(esp []byte, to *net.UDPAddr) {
		if !to.IP.Equal(peer.IP) {
			t.Errorf("sent to wrong peer: %v", to)
		}
		sentCh <- esp
	}

	tun := newFakeTUN()
	pump := NewPump(tun, send, SPIDemux, nil)

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
	// Deliver from an ESP source that differs from the IKE-derived peer, so the
	// return address must be updated to it (the road-warrior return-path fix).
	espSrc := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 4500}
	pump.HandleInbound(espIn, espSrc)

	select {
	case <-tun.writeSig:
	case <-time.After(2 * time.Second):
		t.Fatal("inbound ESP was not written to TUN")
	}
	got := tun.lastWrite()
	if !bytes.Equal(got, reply) {
		t.Fatalf("TUN write mismatch: got %d bytes", len(got))
	}
	if p := tunnel.PeerAddr(); p == nil || !p.IP.Equal(espSrc.IP) || p.Port != espSrc.Port {
		t.Fatalf("peer address not updated to ESP source: got %v, want %v", p, espSrc)
	}
}

// TestPumpUnknownSPIDropped ensures an ESP packet with an unknown SPI is
// silently dropped (no TUN write).
func TestPumpUnknownSPIDropped(t *testing.T) {
	tun := newFakeTUN()
	pump := NewPump(tun, func([]byte, *net.UDPAddr) {}, SPIDemux, nil)
	esp := make([]byte, 40)
	binary.BigEndian.PutUint32(esp[:4], 0xdeadbeef)
	pump.HandleInbound(esp, nil)
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
	c, err := transform.Cipher(payload.ENCR_AES_GCM_16, 256)
	if err != nil {
		t.Fatal(err)
	}
	keyA := bytes.Repeat([]byte{0xa1}, c.KeyLen())
	keyB := bytes.Repeat([]byte{0xb2}, c.KeyLen())
	// AEAD suite: IntegID stays zero.
	mk := func(encKey []byte) esp.Transform {
		return esp.Transform{
			EncrID:    payload.ENCR_AES_GCM_16,
			EncrKeyLn: 256,
			EncKey:    encKey,
		}
	}
	const spiS, spiC = uint32(0x11111111), uint32(0x22222222)
	server = &esp.SA{
		SPIOut: spiC, SPIIn: spiS,
		Out: mk(keyA), In: mk(keyB),
	}
	client = &esp.SA{
		SPIOut: spiS, SPIIn: spiC,
		Out: mk(keyB), In: mk(keyA),
	}
	return server, client
}

// TestSPIDemux covers the ESP key extractor, including the short-packet reject.
func TestSPIDemux(t *testing.T) {
	pkt := make([]byte, 8)
	binary.BigEndian.PutUint32(pkt[:4], 0xdeadbeef)
	key, ok := SPIDemux(pkt)
	if !ok || key != 0xdeadbeef {
		t.Fatalf("SPIDemux = %#x, %v; want 0xdeadbeef, true", key, ok)
	}
	if _, ok := SPIDemux([]byte{1, 2, 3}); ok {
		t.Fatal("SPIDemux accepted a 3-byte packet")
	}
}

// TestPumpDemuxIsPluggable is the point of the Demux seam: a protocol whose
// tunnel key is not an ESP SPI at offset 0 must route without the pump changing.
// This models WireGuard, whose receiver index sits at offset 4 and appears only
// on transport-data messages (type 4).
func TestPumpDemuxIsPluggable(t *testing.T) {
	const wgReceiverIndex = 0x11223344

	wgDemux := func(pkt []byte) (uint32, bool) {
		if len(pkt) < 8 || pkt[0] != 4 { // only transport-data messages carry it
			return 0, false
		}
		return binary.BigEndian.Uint32(pkt[4:8]), true
	}

	inner := makeIPv4(net.IPv4(10, 10, 10, 1), []byte("wireguard-shaped payload"))
	tun := newFakeTUN()
	pump := NewPump(tun, func([]byte, *net.UDPAddr) {}, wgDemux, nil)
	pump.AddTunnel(&fakeTunnel{
		inSPI:    wgReceiverIndex, // the tunnel's key, wherever it lives on the wire
		clientIP: net.IPv4(10, 10, 10, 2).To4(),
		peer:     &net.UDPAddr{IP: net.IPv4(203, 0, 113, 1), Port: 51820},
		dec:      func([]byte) ([]byte, error) { return inner, nil },
		enc:      func(p []byte) ([]byte, error) { return p, nil },
	})

	// A transport-data message carrying the receiver index at offset 4 routes.
	data := make([]byte, 16)
	data[0] = 4
	binary.BigEndian.PutUint32(data[4:8], wgReceiverIndex)
	pump.HandleInbound(data, nil)
	select {
	case <-tun.writeSig:
	case <-time.After(2 * time.Second):
		t.Fatal("packet with a non-SPI demux key was not routed to TUN")
	}
	if got := tun.lastWrite(); !bytes.Equal(got, inner) {
		t.Fatalf("TUN write mismatch: got %q", got)
	}

	// A handshake message (type 1) carries no receiver index: demux says no.
	handshake := make([]byte, 16)
	handshake[0] = 1
	binary.BigEndian.PutUint32(handshake[4:8], wgReceiverIndex)
	pump.HandleInbound(handshake, nil)
	select {
	case <-tun.writeSig:
		t.Fatal("a packet the demux rejected still reached TUN")
	case <-time.After(200 * time.Millisecond):
	}

	// The same bytes read as an ESP SPI would be a different key entirely, so
	// the default demux must not route this packet.
	espPump := NewPump(newFakeTUN(), func([]byte, *net.UDPAddr) {}, SPIDemux, nil)
	espPump.AddTunnel(&fakeTunnel{
		inSPI:    wgReceiverIndex,
		clientIP: net.IPv4(10, 10, 10, 2).To4(),
		dec:      func([]byte) ([]byte, error) { t.Fatal("SPIDemux must not match here"); return nil, nil },
	})
	espPump.HandleInbound(data, nil) // bytes[0:4] are 04 00 00 00, not the key
}
