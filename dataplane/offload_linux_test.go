//go:build linux

package dataplane

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildTCP4 assembles an IPv4/TCP packet with the given payload. The checksum
// fields are left zero — the super-frames the kernel hands a TUN_F_CSUM device
// carry partial checksums, which segmentTSO4 must not trust anyway.
func buildTCP4(t *testing.T, id uint16, seq uint32, flags byte, payload []byte) []byte {
	t.Helper()
	pkt := make([]byte, 20+20+len(payload))
	pkt[0] = 0x45 // v4, ihl 20
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:6], id)
	pkt[6] = 0x40 // DF
	pkt[8] = 64   // TTL
	pkt[9] = protoTCP
	copy(pkt[12:16], []byte{10, 0, 0, 2})  // src
	copy(pkt[16:20], []byte{10, 99, 0, 7}) // dst
	tcp := pkt[20:]
	binary.BigEndian.PutUint16(tcp[0:2], 40000) // src port
	binary.BigEndian.PutUint16(tcp[2:4], 443)   // dst port
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	tcp[12] = 5 << 4 // data offset 20
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 64240) // window
	copy(tcp[20:], payload)
	return pkt
}

// checksumsValid verifies an IPv4/TCP segment the way a receiver would: the
// folded sum over the IP header, and over the TCP pseudo-header plus segment,
// must each come to 0xffff with the transmitted checksums in place.
func checksumsValid(t *testing.T, seg []byte) {
	t.Helper()
	ihl := int(seg[0]&0x0f) * 4
	if got := foldSum(onesComplementSum(0, seg[:ihl])); got != 0xffff {
		t.Errorf("IP header checksum does not verify: folded sum %#04x", got)
	}
	acc := onesComplementSum(0, seg[12:20])
	acc += protoTCP + uint32(len(seg)-ihl)
	acc = onesComplementSum(acc, seg[ihl:])
	if got := foldSum(acc); got != 0xffff {
		t.Errorf("TCP checksum does not verify: folded sum %#04x", got)
	}
}

func TestSegmentTSO4(t *testing.T) {
	payload := make([]byte, 2500)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	const (
		baseID  = 0x1234
		baseSeq = 1_000_000
		flags   = 0x19 // FIN|PSH|ACK: FIN and PSH must survive only on the last segment
	)
	super := buildTCP4(t, baseID, baseSeq, flags, payload)
	hdr := virtioNetHdr{gsoType: vnetGSOTCPv4, gsoSize: 1000, hdrLen: 40}

	var segs [][]byte
	n, err := segmentTSO4(super, hdr, &segs)
	if err != nil {
		t.Fatalf("segmentTSO4: %v", err)
	}
	if n != 3 {
		t.Fatalf("got %d segments, want 3 (2500 payload / 1000 gso)", n)
	}

	var reassembled []byte
	for i, want := range []int{1000, 1000, 500} {
		seg := segs[i]
		if len(seg) != 40+want {
			t.Fatalf("segment %d: length %d, want %d", i, len(seg), 40+want)
		}
		if got := binary.BigEndian.Uint16(seg[2:4]); got != uint16(40+want) {
			t.Errorf("segment %d: IP total length %d, want %d", i, got, 40+want)
		}
		if got := binary.BigEndian.Uint16(seg[4:6]); got != baseID+uint16(i) {
			t.Errorf("segment %d: IP ID %#04x, want %#04x", i, got, baseID+uint16(i))
		}
		if got := binary.BigEndian.Uint32(seg[24:28]); got != baseSeq+uint32(i*1000) {
			t.Errorf("segment %d: TCP seq %d, want %d", i, got, baseSeq+uint32(i*1000))
		}
		gotFlags := seg[33]
		if i == n-1 {
			if gotFlags != flags {
				t.Errorf("last segment: flags %#02x, want %#02x (FIN|PSH preserved)", gotFlags, flags)
			}
		} else if gotFlags != 0x10 { // ACK only
			t.Errorf("segment %d: flags %#02x, want %#02x (FIN|PSH cleared)", i, gotFlags, 0x10)
		}
		checksumsValid(t, seg)
		reassembled = append(reassembled, seg[40:]...)
	}
	if !bytes.Equal(reassembled, payload) {
		t.Error("reassembled segment payloads differ from the super-frame payload")
	}
}

// The scratch buffers make steady-state segmentation allocation-free, the same
// discipline the crypto data paths keep.
func TestSegmentTSO4Allocs(t *testing.T) {
	super := buildTCP4(t, 1, 1, 0x10, make([]byte, 8000))
	hdr := virtioNetHdr{gsoType: vnetGSOTCPv4, gsoSize: 1400, hdrLen: 40}
	var segs [][]byte
	if _, err := segmentTSO4(super, hdr, &segs); err != nil {
		t.Fatalf("warm-up: %v", err)
	}
	if avg := testing.AllocsPerRun(100, func() {
		if _, err := segmentTSO4(super, hdr, &segs); err != nil {
			t.Fatalf("segmentTSO4: %v", err)
		}
	}); avg != 0 {
		t.Errorf("segmentTSO4 allocates %.1f per super-frame in steady state, want 0", avg)
	}
}

func TestSegmentTSO4Rejects(t *testing.T) {
	var segs [][]byte
	cases := map[string][]byte{
		"not IPv4":  {0x60, 0, 0, 0},
		"truncated": buildTCP4(t, 1, 1, 0, make([]byte, 100))[:30],
	}
	notTCP := buildTCP4(t, 1, 1, 0, make([]byte, 100))
	notTCP[9] = 17
	cases["not TCP"] = notTCP
	for name, pkt := range cases {
		if _, err := segmentTSO4(pkt, virtioNetHdr{gsoSize: 50}, &segs); err == nil {
			t.Errorf("%s: accepted, want error", name)
		}
	}
	ok := buildTCP4(t, 1, 1, 0, make([]byte, 100))
	if _, err := segmentTSO4(ok, virtioNetHdr{gsoSize: 0}, &segs); err == nil {
		t.Error("zero gso_size: accepted, want error")
	}
}

// completePartialChecksum must implement the NIC-offload contract: with the
// pseudo-header sum stored in the checksum field, folding from csum_start and
// storing the complement yields exactly the checksum a from-scratch
// computation produces.
func TestCompletePartialChecksum(t *testing.T) {
	payload := []byte("partial checksum offload contract")
	pkt := make([]byte, 20+8+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[9] = 17 // UDP
	copy(pkt[12:16], []byte{192, 168, 1, 5})
	copy(pkt[16:20], []byte{10, 0, 0, 1})
	udp := pkt[20:]
	binary.BigEndian.PutUint16(udp[0:2], 5353)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	copy(udp[8:], payload)

	// The correct checksum, computed from scratch.
	acc := onesComplementSum(0, pkt[12:20])
	acc += 17 + uint32(len(udp))
	acc = onesComplementSum(acc, udp)
	want := ^foldSum(acc)

	// What the kernel hands a TUN_F_CSUM device: the pseudo-header sum parked
	// in the checksum field, csum_start/csum_offset pointing at it.
	pseudo := onesComplementSum(0, pkt[12:20])
	pseudo += 17 + uint32(len(udp))
	binary.BigEndian.PutUint16(udp[6:8], foldSum(pseudo))
	completePartialChecksum(pkt, 20, 6)

	if got := binary.BigEndian.Uint16(udp[6:8]); got != want {
		t.Errorf("completed checksum %#04x, want %#04x", got, want)
	}
}
