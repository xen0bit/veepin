package transport

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/xen0bit/veepin/internal/wireguard/wire"
)

// pair builds the two Sessions of one WireGuard tunnel from a shared pair of
// keys. WireGuard crosses the directions: what one side sends with, the other
// receives with. Getting this wrong is the classic transport bug, so the tests
// build both ends from the same material and check traffic flows each way.
func pair(t testing.TB) (initiator, responder *Session) {
	t.Helper()
	var k1, k2 [wire.KeySize]byte
	for i := range k1 {
		k1[i] = byte(i + 1)
		k2[i] = byte(0x80 + i)
	}
	// Initiator sends with k1, receives with k2; the responder is the mirror.
	initiator, err := NewSession(k1, k2, 0x11111111, 0x22222222)
	if err != nil {
		t.Fatal(err)
	}
	responder, err = NewSession(k2, k1, 0x22222222, 0x11111111)
	if err != nil {
		t.Fatal(err)
	}
	return initiator, responder
}

// ipv4 makes a minimal well-formed IPv4 packet of a given total length so the
// receiver's length-based trim has something real to read.
func ipv4(total int) []byte {
	if total < 20 {
		total = 20
	}
	pkt := make([]byte, total)
	pkt[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	for i := 20; i < total; i++ {
		pkt[i] = byte(i)
	}
	return pkt
}

func TestSealOpenRoundTrip(t *testing.T) {
	a, b := pair(t)

	for _, size := range []int{20, 21, 64, 100, 1400} {
		inner := ipv4(size)
		msg, err := a.Seal(inner)
		if err != nil {
			t.Fatalf("seal %d: %v", size, err)
		}
		if typ, ok := wire.Type(msg); !ok || typ != wire.TypeTransportData {
			t.Fatalf("size %d: not a transport message", size)
		}
		got, err := b.Open(msg)
		if err != nil {
			t.Fatalf("open %d: %v", size, err)
		}
		if !bytes.Equal(got, inner) {
			t.Errorf("size %d: round trip mismatch\n got %x\nwant %x", size, got, inner)
		}
	}
}

// TestPaddingIsInvisible checks that a packet whose length is not a multiple of
// 16 is padded on the wire but trimmed back to exactly its IP length on receipt.
func TestPaddingIsInvisible(t *testing.T) {
	a, b := pair(t)
	inner := ipv4(21) // 21 pads to 32 on the wire
	msg, err := a.Seal(inner)
	if err != nil {
		t.Fatal(err)
	}
	// header + padded(32) + tag(16)
	wantWire := wire.TransportHeaderLen + 32 + wire.TagSize
	if len(msg) != wantWire {
		t.Errorf("wire length = %d, want %d (padded to a 16-octet boundary)", len(msg), wantWire)
	}
	got, err := b.Open(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 21 {
		t.Errorf("trimmed length = %d, want 21", len(got))
	}
}

// TestKeepalive covers the empty packet: it seals to a 32-octet message and
// opens back to nothing, which the data path must recognise and not write.
func TestKeepalive(t *testing.T) {
	a, b := pair(t)
	msg, err := a.Seal(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg) != wire.MinTransportData {
		t.Errorf("keepalive is %d octets, want %d", len(msg), wire.MinTransportData)
	}
	got, err := b.Open(msg)
	if err != nil {
		t.Fatalf("open keepalive: %v", err)
	}
	if got != nil {
		t.Errorf("keepalive opened to %x, want nil", got)
	}
}

// TestCounterAdvances checks that each sealed packet carries the next counter,
// starting at zero, since a repeated nonce would break the AEAD.
func TestCounterAdvances(t *testing.T) {
	a, _ := pair(t)
	for want := range uint64(5) {
		msg, err := a.Seal(ipv4(20))
		if err != nil {
			t.Fatal(err)
		}
		got, ok := wire.TransportCounter(msg)
		if !ok || got != want {
			t.Errorf("packet %d has counter %d", want, got)
		}
	}
}

// TestReplayRejected is the security property: a packet accepted once must not
// be accepted again, while a genuinely newer counter still is.
func TestReplayRejected(t *testing.T) {
	a, b := pair(t)
	first, _ := a.Seal(ipv4(20))
	second, _ := a.Seal(ipv4(20))

	if _, err := b.Open(append([]byte(nil), first...)); err != nil {
		t.Fatalf("first open: %v", err)
	}
	if _, err := b.Open(append([]byte(nil), first...)); err != ErrReplay {
		t.Errorf("replay of first: %v, want ErrReplay", err)
	}
	// A later counter is still accepted after the replay was rejected.
	if _, err := b.Open(append([]byte(nil), second...)); err != nil {
		t.Errorf("second open: %v", err)
	}
}

// TestOutOfOrderWithinWindow checks that reordering inside the window is
// accepted — WireGuard runs over UDP, so packets legitimately arrive out of
// order — while each is still accepted only once.
func TestOutOfOrderWithinWindow(t *testing.T) {
	a, b := pair(t)
	var msgs [][]byte
	for range 10 {
		m, _ := a.Seal(ipv4(20))
		msgs = append(msgs, m)
	}
	// Deliver 9,7,8,...,0 — all within one window.
	order := []int{9, 7, 8, 5, 6, 3, 4, 1, 2, 0}
	for _, idx := range order {
		if _, err := b.Open(append([]byte(nil), msgs[idx]...)); err != nil {
			t.Errorf("open packet %d: %v", idx, err)
		}
	}
	// Every one of them is now a replay.
	if _, err := b.Open(append([]byte(nil), msgs[4]...)); err != ErrReplay {
		t.Errorf("replay after reorder: %v, want ErrReplay", err)
	}
}

// TestWrongKeyFailsAuth checks that a session with mismatched keys cannot open a
// packet, and that the error is the opaque ErrDecrypt.
func TestWrongKeyFailsAuth(t *testing.T) {
	a, _ := pair(t)
	var wrong [wire.KeySize]byte
	bad, err := NewSession(wrong, wrong, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := a.Seal(ipv4(40))
	if _, err := bad.Open(msg); err != ErrDecrypt {
		t.Errorf("open under wrong key: %v, want ErrDecrypt", err)
	}
}

// TestTamperedPayloadFails checks that flipping a ciphertext bit is caught.
func TestTamperedPayloadFails(t *testing.T) {
	a, b := pair(t)
	msg, _ := a.Seal(ipv4(40))
	msg[wire.TransportHeaderLen+2] ^= 0x01
	if _, err := b.Open(msg); err != ErrDecrypt {
		t.Errorf("tampered payload: %v, want ErrDecrypt", err)
	}
}

// TestShortPacketRejected checks the length guard on Open.
func TestShortPacketRejected(t *testing.T) {
	_, b := pair(t)
	if _, err := b.Open(make([]byte, wire.MinTransportData-1)); err != ErrShort {
		t.Errorf("short packet: %v, want ErrShort", err)
	}
}

func TestIndexAccessors(t *testing.T) {
	a, _ := pair(t)
	if a.LocalIndex() != 0x11111111 || a.RemoteIndex() != 0x22222222 {
		t.Errorf("indices = %#x/%#x", a.LocalIndex(), a.RemoteIndex())
	}
}

// TestDataPathAllocations pins the per-packet allocation cost of the hot path:
// one allocation to seal (the output buffer, with the nonce built into its tail)
// and none to open (decrypt in place, nonce reused from the packet's own header).
// A regression means the AEAD nonce has started escaping to the heap again.
func TestDataPathAllocations(t *testing.T) {
	a, b := pair(t)
	inner := ipv4(1400)

	if n := testing.AllocsPerRun(100, func() {
		if _, err := a.Seal(inner); err != nil {
			t.Fatal(err)
		}
	}); n > 1 {
		t.Errorf("Seal allocates %.0f times per packet, want 1", n)
	}

	// Pre-seal a batch with distinct counters so Open sees fresh packets, and give
	// each run its own buffer since Open decrypts in place.
	const batch = 2048
	pkts := make([][]byte, batch)
	for i := range pkts {
		m, err := a.Seal(inner)
		if err != nil {
			t.Fatal(err)
		}
		pkts[i] = m
	}
	scratch := make([]byte, len(pkts[0]))
	i := 0
	if n := testing.AllocsPerRun(batch-1, func() {
		buf := scratch[:len(pkts[i])]
		copy(buf, pkts[i])
		i++
		if _, err := b.Open(buf); err != nil {
			t.Fatal(err)
		}
	}); n > 0 {
		t.Errorf("Open allocates %.0f times per packet, want 0", n)
	}
}
