// Package aggfrag implements the AGGFRAG payload of RFC 9347 (IP-TFS): the
// aggregation and fragmentation format that replaces a plain inner IP packet
// inside an ESP SA once both peers have agreed USE_AGGFRAG.
//
// One AGGFRAG payload is a fixed-size header followed by a run of DataBlocks:
//
//	+--------+--------+--------+--------+
//	|SubType | Resv   |    BlockOffset  |   <- 4 octets, sub-type 0
//	+--------+--------+--------+--------+
//	| DataBlock | DataBlock | Pad ...   |
//	+-----------------------------------+
//
// BlockOffset is the whole point of the format and the field easiest to get
// wrong. It counts the octets at the START of the payload that finish a block
// begun in an earlier packet. Zero means the payload begins on a block
// boundary; a value equal to the payload length means the packet is entirely
// continuation and starts no new block. A sender that leaves it zero while
// prepending a continuation produces a stream only its own decoder can read --
// which is precisely the mutually-consistent bug class this tree tests against.
//
// A DataBlock carries no length field of its own. Its first nibble is the type,
// and RFC 9347 chose 0x4 and 0x6 to coincide with the IPv4 and IPv6 version
// values so the block's length is read from the inner IP header itself. 0x0 is
// padding, which runs to the end of the payload.
package aggfrag

import (
	"encoding/binary"
	"errors"
)

// ESPNextHeader is the ESP Next Header value that marks an AGGFRAG payload,
// replacing the 4 (IPv4) or 41 (IPv6) of an ordinary tunnel-mode SA.
const ESPNextHeader = 144

// Sub-types. Only the non-congestion-controlled form is implemented; the
// congestion-controlled one carries a 24-octet header with RTT and loss
// estimates and is only meaningful with a rate controller behind it.
const (
	SubTypeNonCongestionControlled = 0
	SubTypeCongestionControlled    = 1
)

// HeaderLen is the sub-type 0 header: one octet of sub-type, one reserved, and
// a 16-bit BlockOffset.
const HeaderLen = 4

// DataBlock type nibbles. Deliberately equal to the IP version values -- see
// the package comment.
const (
	BlockTypePad  = 0x0
	BlockTypeIPv4 = 0x4
	BlockTypeIPv6 = 0x6
)

// Drop-path errors are pre-built sentinels: a peer sending malformed payloads
// must cost no allocations to reject.
var (
	ErrShort       = errors.New("aggfrag: payload shorter than its header")
	ErrSubType     = errors.New("aggfrag: unsupported sub-type")
	ErrBlockOffset = errors.New("aggfrag: block offset past the end of the payload")
	ErrBlockType   = errors.New("aggfrag: unknown data block type")
)

// Header is a parsed sub-type 0 AGGFRAG header.
type Header struct {
	BlockOffset uint16
}

// AppendHeader writes a sub-type 0 header to dst.
func AppendHeader(dst []byte, blockOffset uint16) []byte {
	// The sub-type is a whole octet, not a nibble. It is zero here either way,
	// so writing it as a nibble would look correct and silently misplace
	// sub-type 1 the day it is added.
	dst = append(dst, SubTypeNonCongestionControlled, 0)
	return binary.BigEndian.AppendUint16(dst, blockOffset)
}

// ParseHeader reads a sub-type 0 header.
func ParseHeader(pkt []byte) (Header, error) {
	if len(pkt) < HeaderLen {
		return Header{}, ErrShort
	}
	if pkt[0] != SubTypeNonCongestionControlled {
		return Header{}, ErrSubType
	}
	return Header{BlockOffset: binary.BigEndian.Uint16(pkt[2:])}, nil
}

// Packer builds AGGFRAG payloads of a fixed size, carrying over the tail of any
// packet that did not fit.
//
// It is stateful because fragmentation is: when a packet is split, the
// remainder must lead the next payload and that payload's BlockOffset must say
// how many octets it occupies.
type Packer struct {
	// pending is the unsent tail of a packet split across payloads.
	pending []byte
	// buf is reused across calls so a steady send loop does not allocate.
	buf []byte
}

// NewPacker returns a Packer emitting payloads of at most size octets.
func NewPacker() *Packer { return &Packer{} }

// Pending reports whether a fragmented packet is still being sent. A
// constant-rate sender uses this to know it must emit another payload even
// with no new traffic queued.
func (p *Packer) Pending() bool { return len(p.pending) > 0 }

// Pack fills one payload of exactly size octets from the front of pkts,
// returning the payload and the packets it did not consume.
//
// Short payloads are padded to size with a pad block, which is what makes the
// output length independent of the traffic offered -- the property that gives
// IP-TFS its traffic-flow confidentiality. The returned slice is only valid
// until the next call.
func (p *Packer) Pack(pkts [][]byte, size int) (payload []byte, remaining [][]byte) {
	if size < HeaderLen+1 {
		return nil, pkts
	}
	room := size - HeaderLen

	// The continuation of a split packet leads the payload, and BlockOffset
	// records how much of it there is.
	var blockOffset int
	if len(p.pending) > 0 {
		blockOffset = min(len(p.pending), room)
	}

	p.buf = AppendHeader(p.buf[:0], uint16(blockOffset))
	if blockOffset > 0 {
		p.buf = append(p.buf, p.pending[:blockOffset]...)
		p.pending = p.pending[blockOffset:]
		if len(p.pending) == 0 {
			p.pending = nil
		}
		room -= blockOffset
	}

	// New blocks only start once the continuation is complete: a packet that is
	// still fragmenting owns the rest of this payload.
	if len(p.pending) == 0 {
		for len(pkts) > 0 {
			if room == 0 {
				break
			}
			pkt := pkts[0]
			if len(pkt) <= room {
				p.buf = append(p.buf, pkt...)
				room -= len(pkt)
				pkts = pkts[1:]
				continue
			}
			// Split: as much as fits goes here, the tail leads the next payload.
			p.buf = append(p.buf, pkt[:room]...)
			p.pending = pkt[room:]
			room = 0
			pkts = pkts[1:]
			break
		}
	}

	// Pad to the full size. A pad block's type nibble is 0, so zeros are a
	// well-formed pad block and the receiver stops at the first one.
	if room > 0 {
		p.buf = append(p.buf, make([]byte, room)...)
	}
	return p.buf, pkts
}

// Reassembler turns a stream of AGGFRAG payloads back into inner IP packets.
type Reassembler struct {
	// partial holds the leading octets of a block whose remainder has not
	// arrived. It is the only state reassembly needs.
	partial []byte
	// out is reused across Feed calls to hold the returned packet slices.
	out [][]byte
}

// NewReassembler returns a ready Reassembler.
func NewReassembler() *Reassembler { return &Reassembler{} }

// Feed consumes one AGGFRAG payload and returns the inner packets it completed.
//
// The returned packets alias the payload wherever a block arrived whole, so the
// caller must consume them before the next Feed. Only a block that actually
// spanned payloads is copied, because there is nowhere else to assemble it.
func (r *Reassembler) Feed(payload []byte) ([][]byte, error) {
	hdr, err := ParseHeader(payload)
	if err != nil {
		return nil, err
	}
	data := payload[HeaderLen:]
	off := int(hdr.BlockOffset)
	if off > len(data) {
		return nil, ErrBlockOffset
	}

	r.out = r.out[:0]

	if off > 0 {
		if r.partial == nil {
			// Continuation of a block we never saw the start of -- the earlier
			// payload was lost. Skip it; the blocks after it are still good.
			data = data[off:]
		} else {
			r.partial = append(r.partial, data[:off]...)
			pkt, complete := takeComplete(r.partial)
			if !complete {
				// Still short: the sender split this block across more than two
				// payloads, so nothing new starts here and the head must be
				// kept. Clearing it would lose a packet on every large transfer.
				return r.out, nil
			}
			r.out = append(r.out, pkt)
			r.partial = nil
			data = data[off:]
		}
	} else if r.partial != nil {
		// A payload beginning on a block boundary while a fragment is pending
		// means the continuation never arrived. Drop it rather than splice two
		// unrelated halves together.
		r.partial = nil
	}

	for len(data) > 0 {
		switch data[0] >> 4 {
		case BlockTypePad:
			// Padding runs to the end of the payload.
			return r.out, nil
		case BlockTypeIPv4, BlockTypeIPv6:
			n := innerLen(data)
			if n == 0 {
				// Not enough octets to even read the length: the block is split
				// across payloads and this is its head.
				r.partial = append(r.partial[:0], data...)
				return r.out, nil
			}
			if n > len(data) {
				r.partial = append(r.partial[:0], data...)
				return r.out, nil
			}
			r.out = append(r.out, data[:n])
			data = data[n:]
		default:
			return r.out, ErrBlockType
		}
	}
	return r.out, nil
}

// takeComplete returns the packet in b if b holds a whole one.
func takeComplete(b []byte) ([]byte, bool) {
	n := innerLen(b)
	if n == 0 || n > len(b) {
		return nil, false
	}
	return b[:n], true
}

// innerLen reads a block's length from the inner IP header it begins with,
// returning 0 when there are too few octets to tell. There is no length field
// in the block itself -- see the package comment.
func innerLen(b []byte) int {
	if len(b) < 1 {
		return 0
	}
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return 0
		}
		n := int(binary.BigEndian.Uint16(b[2:]))
		if n < 20 {
			return 0 // a malformed Total Length; treat as unreadable
		}
		return n
	case 6:
		if len(b) < 40 {
			return 0
		}
		return int(binary.BigEndian.Uint16(b[4:])) + 40
	}
	return 0
}
