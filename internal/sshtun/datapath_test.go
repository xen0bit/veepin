package sshtun

import (
	"fmt"
	"testing"
)

func ipv4Packet(n int) []byte {
	p := make([]byte, n)
	p[0] = 0x45 // IPv4, so addressFamily recognises it
	for i := 1; i < n; i++ {
		p[i] = byte(i)
	}
	return p
}

var sshSizes = []int{64, 576, 1400}

// BenchmarkEncode measures prefixing an IP packet with the 4-octet address family
// the tun@openssh.com channel frames each packet with. The carrier is the SSH
// transport (x/crypto/ssh), so this prefix is the veepin-specific per-packet cost.
func BenchmarkEncode(b *testing.B) {
	for _, size := range sshSizes {
		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
			pkt := ipv4Packet(size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = Encode(pkt)
			}
		})
	}
}

func BenchmarkDecode(b *testing.B) {
	frame := Encode(ipv4Packet(1400))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, ok := Decode(frame); !ok {
			b.Fatal("decode failed")
		}
	}
}

// TestFramingAllocations pins the framing costs: Encode allocates once (the framed
// packet), Decode not at all (it returns a subslice of its input).
func TestFramingAllocations(t *testing.T) {
	pkt := ipv4Packet(1400)
	if n := testing.AllocsPerRun(100, func() { _ = Encode(pkt) }); n > 1 {
		t.Errorf("Encode allocates %.0f times, want 1", n)
	}
	frame := Encode(pkt)
	if n := testing.AllocsPerRun(100, func() {
		if _, ok := Decode(frame); !ok {
			t.Fatal("decode failed")
		}
	}); n > 0 {
		t.Errorf("Decode allocates %.0f times, want 0", n)
	}
}
