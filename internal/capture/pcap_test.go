package capture

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

// pcapBuilder assembles a classic pcap file the way tcpdump would, so the
// reader is tested against bytes rather than against its own writer.
type pcapBuilder struct {
	buf  bytes.Buffer
	bo   binary.ByteOrder
	link uint32
}

func newPCAP(bo binary.ByteOrder, link uint32) *pcapBuilder {
	b := &pcapBuilder{bo: bo, link: link}
	var hdr [pcapFileHeaderLen]byte
	// The magic is written in the file's own byte order, which is how a reader
	// learns that order at all.
	bo.PutUint32(hdr[0:4], 0xa1b2c3d4)
	bo.PutUint16(hdr[4:6], 2)
	bo.PutUint16(hdr[6:8], 4)
	bo.PutUint32(hdr[16:20], 65535)
	bo.PutUint32(hdr[20:24], link)
	b.buf.Write(hdr[:])
	return b
}

func (b *pcapBuilder) frame(payload []byte) {
	var hdr [pcapPacketHeaderLen]byte
	b.bo.PutUint32(hdr[0:4], 1700000000)
	b.bo.PutUint32(hdr[8:12], uint32(len(payload)))
	b.bo.PutUint32(hdr[12:16], uint32(len(payload)))
	b.buf.Write(hdr[:])
	b.buf.Write(payload)
}

func (b *pcapBuilder) Bytes() []byte { return b.buf.Bytes() }

// ethernet wraps an IP packet in an Ethernet header.
func ethernet(etherType uint16, ip []byte) []byte {
	f := make([]byte, ethernetHeaderLen, ethernetHeaderLen+len(ip))
	binary.BigEndian.PutUint16(f[12:14], etherType)
	return append(f, ip...)
}

// udp4 builds an IPv4/UDP datagram. fragOff is written verbatim so a test can
// mark the packet a fragment.
func udp4(src, dst netip.AddrPort, fragOff uint16, payload []byte) []byte {
	udp := make([]byte, udpHeaderLen+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], src.Port())
	binary.BigEndian.PutUint16(udp[2:4], dst.Port())
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[udpHeaderLen:], payload)

	ip := make([]byte, 20+len(udp))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	binary.BigEndian.PutUint16(ip[6:8], fragOff)
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], src.Addr().AsSlice())
	copy(ip[16:20], dst.Addr().AsSlice())
	copy(ip[20:], udp)
	return ip
}

func udp6(src, dst netip.AddrPort, nextHeader byte, payload []byte) []byte {
	udp := make([]byte, udpHeaderLen+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], src.Port())
	binary.BigEndian.PutUint16(udp[2:4], dst.Port())
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[udpHeaderLen:], payload)

	ip := make([]byte, 40+len(udp))
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(udp)))
	ip[6] = nextHeader
	ip[7] = 64
	copy(ip[8:24], src.Addr().AsSlice())
	copy(ip[24:40], dst.Addr().AsSlice())
	copy(ip[40:], udp)
	return ip
}

var (
	clientAddr = netip.MustParseAddrPort("172.20.0.3:500")
	serverAddr = netip.MustParseAddrPort("172.20.0.2:500")
)

// The magic doubles as the byte-order mark, and a reader that assumed one order
// would read every length backwards on a capture taken on the other kind of
// machine -- producing lengths in the gigabytes rather than an error.
func TestBothByteOrdersAndBothTimestampMagicsAreRead(t *testing.T) {
	for _, bo := range []binary.ByteOrder{binary.BigEndian, binary.LittleEndian} {
		for _, magic := range []uint32{0xa1b2c3d4, 0xa1b23c4d} {
			b := newPCAP(bo, linkEthernet)
			raw := b.Bytes()
			bo.PutUint32(raw[0:4], magic)
			b.frame(ethernet(0x0800, udp4(clientAddr, serverAddr, 0, []byte("hello"))))

			got, err := ReadPCAP(b.Bytes())
			if err != nil {
				t.Fatalf("%T magic %#x: %v", bo, magic, err)
			}
			if len(got) != 1 || string(got[0].Payload) != "hello" {
				t.Fatalf("%T magic %#x: got %+v", bo, magic, got)
			}
		}
	}
}

// The three link types a container capture can produce must all decode to the
// same datagram, because which one you get depends on whether the capture named
// an interface or used -i any -- a detail nobody remembers a year later.
func TestEveryContainerLinkTypeYieldsTheSameDatagram(t *testing.T) {
	payload := []byte{0xde, 0xad, 0xbe, 0xef}
	ip := udp4(clientAddr, serverAddr, 0, payload)

	sll := make([]byte, sllHeaderLen)
	binary.BigEndian.PutUint16(sll[14:16], 0x0800)
	sll = append(sll, ip...)

	for _, tc := range []struct {
		name  string
		link  uint32
		frame []byte
	}{
		{"ethernet", linkEthernet, ethernet(0x0800, ip)},
		{"linux sll", linkLinuxSLL, sll},
		{"raw ip", linkRaw, ip},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newPCAP(binary.LittleEndian, tc.link)
			b.frame(tc.frame)
			got, err := ReadPCAP(b.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 {
				t.Fatalf("got %d datagrams, want 1", len(got))
			}
			if got[0].Src != clientAddr || got[0].Dst != serverAddr {
				t.Fatalf("addresses: %v -> %v", got[0].Src, got[0].Dst)
			}
			if !bytes.Equal(got[0].Payload, payload) {
				t.Fatalf("payload %x", got[0].Payload)
			}
		})
	}
}

// A VLAN tag pushes the real ethertype four octets to the right. Reading the
// tag as the type gives 0x8100, which is neither IPv4 nor IPv6, so the datagram
// vanishes from the corpus without a word.
func TestVLANTaggedFramesStillYieldTheirDatagram(t *testing.T) {
	ip := udp4(clientAddr, serverAddr, 0, []byte("tagged"))
	f := make([]byte, ethernetHeaderLen)
	binary.BigEndian.PutUint16(f[12:14], 0x8100)
	tag := []byte{0x00, 0x64, 0x08, 0x00} // VLAN 100, then IPv4
	f = append(append(f, tag...), ip...)

	b := newPCAP(binary.LittleEndian, linkEthernet)
	b.frame(f)
	got, err := ReadPCAP(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || string(got[0].Payload) != "tagged" {
		t.Fatalf("got %+v", got)
	}
}

// A capture is full of ARP, ICMP and TCP, and skipping those is the point of a
// filter. Skipping them must not be confused with the case below.
func TestNonUDPFramesAreSkippedRatherThanFailing(t *testing.T) {
	arp := ethernet(0x0806, []byte{1, 2, 3, 4})
	tcp := udp4(clientAddr, serverAddr, 0, []byte("x"))
	tcp[9] = 6 // rewrite the protocol to TCP

	b := newPCAP(binary.LittleEndian, linkEthernet)
	b.frame(arp)
	b.frame(tcp)
	b.frame(ethernet(0x0800, udp4(clientAddr, serverAddr, 0, []byte("kept"))))

	got, err := ReadPCAP(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || string(got[0].Payload) != "kept" {
		t.Fatalf("got %+v", got)
	}
}

// This is the case that must NOT be a skip. Returning the first fragment as if
// it were the whole datagram would put a message in the corpus that no peer
// ever sent -- and IKE with certificates is exactly where oversized UDP lives,
// which is to say exactly where a corpus is most wanted.
func TestAFragmentedDatagramIsAnErrorAndNotASkip(t *testing.T) {
	for _, tc := range []struct {
		name  string
		frame []byte
	}{
		{"more-fragments set", ethernet(0x0800, udp4(clientAddr, serverAddr, 0x2000, []byte("first")))},
		{"nonzero offset", ethernet(0x0800, udp4(clientAddr, serverAddr, 0x00b9, []byte("later")))},
		{"v6 fragment header", ethernet(0x86dd, udp6(
			netip.MustParseAddrPort("[fd00::3]:500"),
			netip.MustParseAddrPort("[fd00::2]:500"), 44, []byte("piece")))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newPCAP(binary.LittleEndian, linkEthernet)
			b.frame(tc.frame)
			if _, err := ReadPCAP(b.Bytes()); err == nil {
				t.Fatal("a fragment was accepted as a whole datagram")
			}
		})
	}
}

func TestIPv6DatagramsAreDecoded(t *testing.T) {
	src := netip.MustParseAddrPort("[fd00::3]:4500")
	dst := netip.MustParseAddrPort("[fd00::2]:4500")
	b := newPCAP(binary.LittleEndian, linkEthernet)
	b.frame(ethernet(0x86dd, udp6(src, dst, 17, []byte("v6"))))

	got, err := ReadPCAP(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Src != src || got[0].Dst != dst || string(got[0].Payload) != "v6" {
		t.Fatalf("got %+v", got)
	}
}

// pcapng starts with 0x0a0d0d0a, not the classic magic. Tools write it by
// default in some builds, and the resulting "no datagrams" would read as an
// empty exchange rather than as the wrong file format.
func TestPcapngIsRefusedByName(t *testing.T) {
	ng := append([]byte{0x0a, 0x0d, 0x0d, 0x0a}, make([]byte, 40)...)
	_, err := ReadPCAP(ng)
	if err == nil {
		t.Fatal("accepted a pcapng file")
	}
	if got := err.Error(); !bytes.Contains([]byte(got), []byte("pcapng")) {
		t.Fatalf("error %q does not name pcapng", got)
	}
}

// Every prefix must be rejected or handled, never panic: a capture is a file
// off a container's filesystem, and a truncated one is the normal outcome of a
// cell that was torn down mid-write.
func TestEveryTruncationOfAPCAPIsRejected(t *testing.T) {
	b := newPCAP(binary.LittleEndian, linkEthernet)
	b.frame(ethernet(0x0800, udp4(clientAddr, serverAddr, 0, bytes.Repeat([]byte{7}, 40))))
	b.frame(ethernet(0x0800, udp4(serverAddr, clientAddr, 0, bytes.Repeat([]byte{8}, 40))))
	full := b.Bytes()

	for i := range len(full) {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on the first %d octets: %v", i, r)
				}
			}()
			_, _ = ReadPCAP(full[:i])
		}()
	}
}

// An IKE exchange is everything on 500 and 4500 and nothing else; the ESP data
// path that follows shares port 4500 and would otherwise swamp the corpus.
func TestFilterPortKeepsBothDirections(t *testing.T) {
	in := []Datagram{
		{Src: netip.MustParseAddrPort("10.0.0.1:500"), Dst: netip.MustParseAddrPort("10.0.0.2:500")},
		{Src: netip.MustParseAddrPort("10.0.0.2:500"), Dst: netip.MustParseAddrPort("10.0.0.1:500")},
		{Src: netip.MustParseAddrPort("10.0.0.1:53"), Dst: netip.MustParseAddrPort("10.0.0.2:53")},
	}
	if got := FilterPort(in, 500); len(got) != 2 {
		t.Fatalf("kept %d of 2 IKE datagrams", len(got))
	}
	if got := FilterPort(in, 500, 4500); len(got) != 2 {
		t.Fatalf("naming an absent port changed the result: %d", len(got))
	}
}

func FuzzReadPCAP(f *testing.F) {
	b := newPCAP(binary.LittleEndian, linkEthernet)
	b.frame(ethernet(0x0800, udp4(clientAddr, serverAddr, 0, []byte("seed"))))
	f.Add(b.Bytes())

	b6 := newPCAP(binary.BigEndian, linkRaw)
	b6.frame(udp6(netip.MustParseAddrPort("[fd00::3]:500"), netip.MustParseAddrPort("[fd00::2]:500"), 17, []byte("seed6")))
	f.Add(b6.Bytes())

	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := ReadPCAP(data)
		if err != nil {
			return
		}
		// Every returned payload must be a subslice of the input: the reader is
		// on the corpus path, and a payload that pointed at scratch memory
		// would be a corpus of whatever was reused next.
		for _, d := range got {
			if len(d.Payload) > len(data) {
				t.Fatalf("payload longer than the file it came from")
			}
		}
	})
}
