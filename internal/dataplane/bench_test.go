package dataplane

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/xen0bit/ikennkt/internal/crypto"
	"github.com/xen0bit/ikennkt/internal/esp"
	"github.com/xen0bit/ikennkt/internal/payload"
)

// discardTUN drops everything written to it and never yields reads; it isolates
// the pump's inbound demux+decap+write path from real device I/O.
type discardTUN struct{ writes int }

func (d *discardTUN) Read(buf []byte) (int, error) { select {} }
func (d *discardTUN) Write(pkt []byte) (int, error) {
	d.writes++
	return len(pkt), nil
}

// BenchmarkPumpInbound measures the inbound data-plane path: SPI demux, ESP
// decapsulation and TUN write, for one packet. This is the per-packet cost of
// traffic flowing from a client toward the internet.
func BenchmarkPumpInbound(b *testing.B) {
	sizes := []int{64, 576, 1400}
	for _, size := range sizes {
		b.Run(sizeName(size), func(b *testing.B) {
			serverSA, clientSA := benchESPPair(b)
			tun := &discardTUN{}
			pump := NewPump(tun, func([]byte, *net.UDPAddr, bool) {}, nil)

			client := net.IPv4(10, 0, 0, 2).To4()
			pump.AddTunnel(&benchTunnel{sa: serverSA, in: serverSA.SPIIn, ip: client})

			inner := make([]byte, size)
			inner[0] = 0x45
			binary.BigEndian.PutUint16(inner[2:4], uint16(size))
			// Pre-encapsulate a batch (distinct sequence numbers).
			const batch = 256
			pkts := make([][]byte, batch)
			for i := range pkts {
				e, err := clientSA.Encapsulate(inner, 4)
				if err != nil {
					b.Fatal(err)
				}
				pkts[i] = e
			}

			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if i%batch == 0 {
					// Reset the server SA's replay window so replayed sequence
					// numbers from the batch are accepted.
					serverSA.ResetReplayWindow()
				}
				pump.HandleESP(pkts[i%batch])
			}
		})
	}
}

// benchTunnel adapts an esp.SA to the ESPTunnel interface for the pump.
type benchTunnel struct {
	sa *esp.SA
	in uint32
	ip net.IP
}

func (t *benchTunnel) InboundSPI() uint32 { return t.in }
func (t *benchTunnel) ClientIP() net.IP   { return t.ip }
func (t *benchTunnel) PeerAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: net.IPv4(203, 0, 113, 1), Port: 4500}
}
func (t *benchTunnel) UDPEncap() bool { return true }
func (t *benchTunnel) Encapsulate(p []byte) ([]byte, error) {
	return t.sa.Encapsulate(p, 4)
}
func (t *benchTunnel) Decapsulate(p []byte) ([]byte, error) {
	inner, _, err := t.sa.Decapsulate(p)
	return inner, err
}

func benchESPPair(b *testing.B) (server, client *esp.SA) {
	b.Helper()
	mk := func() crypto.SKCipher {
		c, _ := crypto.NewSKCipher(payload.ENCR_AES_GCM_16, 256)
		return c
	}
	kA := make([]byte, mk().KeyLen())
	kB := make([]byte, mk().KeyLen())
	for i := range kA {
		kA[i] = byte(i)
		kB[i] = byte(255 - i)
	}
	const spiS, spiC = uint32(0x11111111), uint32(0x22222222)
	server = &esp.SA{
		SPIOut: spiC, SPIIn: spiS,
		Out: esp.Transform{Cipher: mk(), EncKey: kA},
		In:  esp.Transform{Cipher: mk(), EncKey: kB},
	}
	client = &esp.SA{
		SPIOut: spiS, SPIIn: spiC,
		Out: esp.Transform{Cipher: mk(), EncKey: kB},
		In:  esp.Transform{Cipher: mk(), EncKey: kA},
	}
	return server, client
}

func sizeName(n int) string {
	switch n {
	case 64:
		return "64B"
	case 576:
		return "576B"
	case 1400:
		return "1400B"
	default:
		return "other"
	}
}

// BenchmarkPumpOutbound measures the outbound data-plane path: route by
// destination IP, ESP-encapsulate, and hand to the send function. This is the
// per-packet cost of traffic flowing from the TUN toward a client.
func BenchmarkPumpOutbound(b *testing.B) {
	for _, size := range []int{64, 576, 1400} {
		b.Run(sizeName(size), func(b *testing.B) {
			serverSA, _ := benchESPPair(b)
			var sink int
			pump := NewPump(&discardTUN{}, func(esp []byte, _ *net.UDPAddr, _ bool) { sink += len(esp) }, nil)
			client := net.IPv4(10, 0, 0, 2).To4()
			pump.AddTunnel(&benchTunnel{sa: serverSA, in: serverSA.SPIIn, ip: client})

			// An inner IP packet destined for the client's assigned address.
			pkt := make([]byte, size)
			pkt[0] = 0x45
			binary.BigEndian.PutUint16(pkt[2:4], uint16(size))
			copy(pkt[16:20], client) // dst = client

			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				pump.routeOutbound(pkt)
			}
			_ = sink
		})
	}
}
