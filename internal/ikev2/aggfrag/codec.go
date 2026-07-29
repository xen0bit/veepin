package aggfrag

import (
	"encoding/binary"
	"errors"
)

const UseAggFrag NotifyType = 16442

type NotifyType uint16

const ESPNextHeaderAGGFRAG = 144

const (
	SubTypeNonCongestionControlled = 0
	SubTypeCongestionControlled    = 1
)

const (
	BlockTypePad  = 0x0
	BlockTypeIPv4 = 0x4
	BlockTypeIPv6 = 0x6
)

type SubHeaderNonCC struct {
	BlockOffset uint16
}

func (h SubHeaderNonCC) Marshal() []byte {
	buf := make([]byte, 4)
	buf[0] = SubTypeNonCongestionControlled << 4
	binary.BigEndian.PutUint16(buf[2:], h.BlockOffset)
	return buf
}

func ParseSubHeaderNonCC(pkt []byte) (SubHeaderNonCC, error) {
	if len(pkt) < 4 {
		return SubHeaderNonCC{}, errors.New("aggfrag: sub-header too short")
	}
	return SubHeaderNonCC{
		BlockOffset: binary.BigEndian.Uint16(pkt[2:]),
	}, nil
}

func Pack(pkts [][]byte, mtu int, fragment []byte) ([]byte, []byte) {
	buf := make([]byte, 4, mtu)
	var nextFrag []byte

	if len(fragment) > 0 {
		head, rest := split(fragment, mtu-4)
		buf = append(buf, head...)
		if len(rest) > 0 {
			return buf, rest
		}
	}

	for _, pkt := range pkts {
		room := mtu - len(buf)
		if room < 4 {
			break
		}
		if len(pkt) <= room {
			buf = append(buf, pkt...)
		} else {
			buf = append(buf, pkt[:room]...)
			nextFrag = pkt[room:]
			break
		}
	}

	if len(nextFrag) == 0 {
		pad := make([]byte, mtu-len(buf))
		buf = append(buf, pad...)
	}

	return buf, nextFrag
}

func split(b []byte, n int) ([]byte, []byte) {
	if n >= len(b) {
		return b, nil
	}
	return b[:n], b[n:]
}

type Reassembler struct {
	buf []byte
}

func NewReassembler() *Reassembler {
	return &Reassembler{}
}

func (r *Reassembler) Feed(pkt []byte) ([][]byte, error) {
	if len(pkt) < 4 {
		return nil, errors.New("aggfrag: payload too short")
	}
	subHdr, err := ParseSubHeaderNonCC(pkt)
	if err != nil {
		return nil, err
	}
	data := pkt[4:]

	if int(subHdr.BlockOffset) > len(data) {
		return nil, errors.New("aggfrag: block offset exceeds payload")
	}

	if int(subHdr.BlockOffset) > 0 {
		if len(r.buf) > 0 {
			r.buf = append(r.buf, data[:subHdr.BlockOffset]...)
		} else {
			r.buf = append(r.buf[:0], data[:subHdr.BlockOffset]...)
		}
		var out [][]byte
		pkts, rest := parse(r.buf)
		out = append(out, pkts...)
		r.buf = rest
		tail := data[subHdr.BlockOffset:]
		pkts2, rest2 := parse(tail)
		out = append(out, pkts2...)
		r.buf = append(r.buf, rest2...)
		return out, nil
	}

	if len(r.buf) > 0 {
		b := append(r.buf, data...)
		pkts, rest := parse(b)
		r.buf = rest
		return pkts, nil
	}

	pkts, rest := parse(data)
	r.buf = rest
	return pkts, nil
}

func parse(data []byte) ([][]byte, []byte) {
	var out [][]byte
	for len(data) > 0 {
		if len(data) < 4 {
			return out, data
		}
		bt := data[0] >> 4
		switch bt {
		case BlockTypePad:
			return out, nil
		case BlockTypeIPv4, BlockTypeIPv6:
			l := innerLen(data)
			if l == 0 || l > len(data) {
				return out, data
			}
			ip := make([]byte, l)
			copy(ip, data[:l])
			out = append(out, ip)
			data = data[l:]
		default:
			data = data[1:]
		}
	}
	return out, nil
}

func innerLen(buf []byte) int {
	if len(buf) < 4 {
		return 0
	}
	ver := buf[0] >> 4
	switch ver {
	case 4:
		if len(buf) < 2 {
			return 0
		}
		return int(binary.BigEndian.Uint16(buf[2:]))
	case 6:
		if len(buf) < 4+40 {
			return 0
		}
		return int(binary.BigEndian.Uint16(buf[4:])) + 40
	}
	return 0
}
