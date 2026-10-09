package wire

import (
	"bytes"
	"testing"
	"time"
)

// TestMessageSizes pins the fixed sizes from the protocol paper §5.4. WireGuard
// has no length fields, so these numbers *are* the framing: if one drifts, a real
// peer rejects every message and the failure surfaces far from the cause.
func TestMessageSizes(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  int
		want int
	}{
		{"handshake initiation", SizeHandshakeInitiation, 148},
		{"handshake response", SizeHandshakeResponse, 92},
		{"cookie reply", SizeCookieReply, 64},
		{"transport header", TransportHeaderLen, 16},
		{"empty transport packet", MinTransportData, 32},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.want)
		}
	}

	// The initiation's fields must exactly fill its 148 octets.
	sum := 4 + 4 + KeySize + (KeySize + TagSize) + (TimestampLen + TagSize) + MACSize + MACSize
	if sum != SizeHandshakeInitiation {
		t.Errorf("initiation fields sum to %d, want %d", sum, SizeHandshakeInitiation)
	}
	// And the response's its 92.
	sum = 4 + 4 + 4 + KeySize + TagSize + MACSize + MACSize
	if sum != SizeHandshakeResponse {
		t.Errorf("response fields sum to %d, want %d", sum, SizeHandshakeResponse)
	}
}

func TestHandshakeInitiationRoundTrip(t *testing.T) {
	in := &HandshakeInitiation{Sender: 0x11223344}
	for i := range in.Ephemeral {
		in.Ephemeral[i] = byte(i)
	}
	for i := range in.Static {
		in.Static[i] = byte(0x40 + i)
	}
	for i := range in.Timestamp {
		in.Timestamp[i] = byte(0x80 + i)
	}
	for i := range in.MAC1 {
		in.MAC1[i] = byte(0xa0 + i)
	}
	for i := range in.MAC2 {
		in.MAC2[i] = byte(0xc0 + i)
	}

	buf := make([]byte, SizeHandshakeInitiation)
	msg, err := in.Marshal(buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg) != SizeHandshakeInitiation {
		t.Fatalf("marshalled %d octets, want %d", len(msg), SizeHandshakeInitiation)
	}
	// Type in octet 0, reserved zero, sender little-endian.
	if msg[0] != TypeHandshakeInitiation {
		t.Errorf("type = %d, want %d", msg[0], TypeHandshakeInitiation)
	}
	if msg[1]|msg[2]|msg[3] != 0 {
		t.Error("reserved octets are not zero")
	}
	if !bytes.Equal(msg[4:8], []byte{0x44, 0x33, 0x22, 0x11}) {
		t.Errorf("sender index is not little-endian: %x", msg[4:8])
	}

	out, err := ParseHandshakeInitiation(msg)
	if err != nil {
		t.Fatal(err)
	}
	if *out != *in {
		t.Error("initiation did not survive a round trip")
	}
}

func TestHandshakeResponseRoundTrip(t *testing.T) {
	in := &HandshakeResponse{Sender: 0xaabbccdd, Receiver: 0x11223344}
	for i := range in.Ephemeral {
		in.Ephemeral[i] = byte(0x10 + i)
	}
	for i := range in.Empty {
		in.Empty[i] = byte(0x50 + i)
	}
	for i := range in.MAC1 {
		in.MAC1[i] = byte(0x70 + i)
	}

	buf := make([]byte, SizeHandshakeResponse)
	msg, err := in.Marshal(buf)
	if err != nil {
		t.Fatal(err)
	}
	if msg[0] != TypeHandshakeResponse {
		t.Errorf("type = %d, want %d", msg[0], TypeHandshakeResponse)
	}
	out, err := ParseHandshakeResponse(msg)
	if err != nil {
		t.Fatal(err)
	}
	if *out != *in {
		t.Error("response did not survive a round trip")
	}
}

// TestMACRegions pins the MAC boundaries: mac1 covers everything before it, and
// mac2 everything before it — including mac1.
func TestMACRegions(t *testing.T) {
	init := make([]byte, SizeHandshakeInitiation)
	m1, m2, ok := MACRegions(init)
	if !ok {
		t.Fatal("initiation not recognised")
	}
	if len(m1) != 116 || len(m2) != 132 {
		t.Errorf("initiation MAC regions = %d/%d, want 116/132", len(m1), len(m2))
	}

	resp := make([]byte, SizeHandshakeResponse)
	m1, m2, ok = MACRegions(resp)
	if !ok {
		t.Fatal("response not recognised")
	}
	if len(m1) != 60 || len(m2) != 76 {
		t.Errorf("response MAC regions = %d/%d, want 60/76", len(m1), len(m2))
	}

	if _, _, ok := MACRegions(make([]byte, 40)); ok {
		t.Error("a non-handshake length reported MAC regions")
	}
}

// TestDemuxOnlyMatchesTransportData is the seam the pump depends on. The receiver
// index sits at offset 4, but only on type 4: the same offset on a handshake
// carries a *sender* index, and routing on it would deliver a handshake to a
// tunnel.
func TestDemuxOnlyMatchesTransportData(t *testing.T) {
	pkt := make([]byte, MinTransportData)
	pkt[0] = TypeTransportData
	pkt[4], pkt[5], pkt[6], pkt[7] = 0x44, 0x33, 0x22, 0x11 // little-endian

	key, ok := Demux(pkt)
	if !ok || key != 0x11223344 {
		t.Fatalf("Demux = %#x, %v; want 0x11223344, true", key, ok)
	}

	// Every other type must be refused, even though offset 4 holds a number.
	for _, typ := range []byte{TypeHandshakeInitiation, TypeHandshakeResponse, TypeCookieReply} {
		other := make([]byte, SizeHandshakeInitiation)
		other[0] = typ
		copy(other[4:8], pkt[4:8])
		if _, ok := Demux(other); ok {
			t.Errorf("Demux accepted message type %d", typ)
		}
	}

	// Too short to hold a header, and non-zero reserved octets.
	if _, ok := Demux(pkt[:MinTransportData-1]); ok {
		t.Error("Demux accepted a runt packet")
	}
	bad := append([]byte(nil), pkt...)
	bad[2] = 1
	if _, ok := Demux(bad); ok {
		t.Error("Demux accepted non-zero reserved octets")
	}
}

func TestTransportHeader(t *testing.T) {
	buf := make([]byte, TransportHeaderLen)
	if err := PutTransportHeader(buf, 0xdeadbeef, 0x0102030405060708); err != nil {
		t.Fatal(err)
	}
	if buf[0] != TypeTransportData || buf[1]|buf[2]|buf[3] != 0 {
		t.Errorf("bad header prefix: %x", buf[:4])
	}
	key, ok := Demux(append(buf, make([]byte, TagSize)...))
	if !ok || key != 0xdeadbeef {
		t.Errorf("receiver index did not survive: %#x", key)
	}
	ctr, ok := TransportCounter(buf)
	if !ok || ctr != 0x0102030405060708 {
		t.Errorf("counter = %#x, want 0x0102030405060708", ctr)
	}
	if err := PutTransportHeader(buf[:4], 1, 1); err != ErrShort {
		t.Errorf("short buffer error = %v, want ErrShort", err)
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	good := make([]byte, SizeHandshakeInitiation)
	good[0] = TypeHandshakeInitiation

	// Wrong length.
	if _, err := ParseHandshakeInitiation(good[:147]); err != ErrMalformed {
		t.Errorf("short initiation: %v, want ErrMalformed", err)
	}
	// Right length, wrong type.
	wrong := append([]byte(nil), good...)
	wrong[0] = TypeHandshakeResponse
	if _, err := ParseHandshakeInitiation(wrong); err != ErrMalformed {
		t.Errorf("wrong type: %v, want ErrMalformed", err)
	}
	// Reserved octets set.
	res := append([]byte(nil), good...)
	res[3] = 0xff
	if _, err := ParseHandshakeInitiation(res); err != ErrMalformed {
		t.Errorf("reserved set: %v, want ErrMalformed", err)
	}
	// A response-sized buffer is not an initiation.
	if _, err := ParseHandshakeResponse(good); err != ErrMalformed {
		t.Errorf("initiation parsed as response: %v", err)
	}
}

// TestTimestampMonotonic covers what the timestamp is actually for: rejecting a
// replayed handshake initiation. Only ordering matters, which is why the encoder
// need not track leap seconds.
func TestTimestampMonotonic(t *testing.T) {
	base := time.Unix(1700000000, 500)
	a := Timestamp(base)
	b := Timestamp(base.Add(time.Nanosecond))
	c := Timestamp(base.Add(time.Second))

	if !After(b, a) {
		t.Error("a nanosecond later did not compare later")
	}
	if !After(c, b) {
		t.Error("a second later did not compare later")
	}
	if After(a, a) {
		t.Error("a timestamp is strictly after itself")
	}
	if After(a, b) {
		t.Error("an earlier timestamp compared later")
	}
}

// TestTimestampEpoch pins the TAI64 labelling of the Unix epoch: 2^62. A wrong
// base would still be monotonic, and would still interop with itself, while
// being rejected by every real peer.
func TestTimestampEpoch(t *testing.T) {
	ts := Timestamp(time.Unix(0, 0))
	want := []byte{0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(ts[:], want) {
		t.Fatalf("TAI64N(epoch) = %x, want %x", ts, want)
	}
}

// TestCookieReplyRoundTrips: the encoder the responder now needs must produce
// exactly what the parser, and wireguard-go's MessageCookieReply, read back --
// receiver little-endian at 4, nonce at 8, sealed cookie at 32.
func TestCookieReplyRoundTrips(t *testing.T) {
	m := CookieReply{Receiver: 0x01020304}
	for i := range m.Nonce {
		m.Nonce[i] = byte(i)
	}
	for i := range m.Cookie {
		m.Cookie[i] = byte(0x80 + i)
	}
	b, err := m.Marshal(make([]byte, SizeCookieReply))
	if err != nil {
		t.Fatal(err)
	}
	if b[0] != TypeCookieReply || b[1] != 0 || b[2] != 0 || b[3] != 0 || b[4] != 0x04 || b[7] != 0x01 {
		t.Fatalf("header = %x, want type 3, zero reserved, receiver little-endian", b[:8])
	}
	got, err := ParseCookieReply(b)
	if err != nil {
		t.Fatal(err)
	}
	if *got != m {
		t.Fatal("the cookie reply did not round-trip")
	}
	for n := range SizeCookieReply {
		if _, err := ParseCookieReply(b[:n]); err == nil {
			t.Fatalf("a %d-octet prefix of a cookie reply parsed", n)
		}
	}
	if _, err := m.Marshal(make([]byte, SizeCookieReply-1)); err == nil {
		t.Fatal("Marshal wrote into a buffer too short for the message")
	}
}
