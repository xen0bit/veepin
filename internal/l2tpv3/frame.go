package l2tpv3

import (
	"encoding/binary"
	"fmt"
)

// L2TPv3 data packet header over UDP (RFC 3931 section 3.2):
//
//	0                   1                   2                   3
//	+-------------------------------+-------------------------------+
//	| T=0, flags, Ver=3             | Reserved                      |
//	+---------------------------------------------------------------+
//	| Session ID (32 bits)                                          |
//	+---------------------------------------------------------------+
//	| Cookie (0, 4 or 8 octets)                                     |
//	+---------------------------------------------------------------+
//	| Default L2-Specific Sublayer (0 or 4 octets)                  |
//	+---------------------------------------------------------------+
//	| Ethernet frame                                                |
//	+---------------------------------------------------------------+

const (
	// l2tpHeaderLen is the fixed portion: flags+reserved (4) + session ID (4).
	l2tpHeaderLen = 8
	// sublayerLen is the Default L2-Specific Sublayer when present (S bit set).
	sublayerLen = 4
	// l2tpVer is the version field value for L2TPv3.
	l2tpVer = 3
)

// DataHeaderLen returns the total header overhead for a data packet given the
// cookie length and whether the sublayer is present.
func DataHeaderLen(cookieLen int, sublayer bool) int {
	n := l2tpHeaderLen + cookieLen
	if sublayer {
		n += sublayerLen
	}
	return n
}

// EncodeData appends an L2TPv3 data packet to dst and returns the result. It
// returns a subslice of dst when dst has sufficient capacity, or allocates.
// The Ethernet frame is NOT copied — the returned slice aliases frame when dst
// is nil or too small.
func EncodeData(dst []byte, sessionID uint32, cookie []byte, sublayer bool, frame []byte) []byte {
	hdrLen := DataHeaderLen(len(cookie), sublayer)
	total := hdrLen + len(frame)

	if cap(dst) < total {
		dst = make([]byte, 0, total)
	}
	dst = dst[:total]

	// Flags+ver: T=0 (data), reserved, version=3
	binary.BigEndian.PutUint16(dst[0:], l2tpVer)
	// Reserved (zero)
	binary.BigEndian.PutUint16(dst[2:], 0)
	// Session ID
	binary.BigEndian.PutUint32(dst[4:], sessionID)
	// Cookie (if any)
	if len(cookie) > 0 {
		copy(dst[8:], cookie)
	}
	// Sublayer (if present) — all zeros when sequencing is off
	if sublayer {
		// Default L2-Specific Sublayer: S=0 (no sequencing), reserved, sequence=0
		// All zeros.
		_ = dst[8+len(cookie)+3] // bounds check
	}
	// Ethernet frame
	copy(dst[hdrLen:], frame)

	return dst
}

// DataHeader carries the decoded fields from an L2TPv3 data packet header.
type DataHeader struct {
	SessionID  uint32
	Cookie     []byte // subslice of the original packet
	Sublayer   [4]byte
	HasSublayer bool
	// Frame is the Ethernet frame (subslice of input, zero-copy).
	Frame []byte
}

// DecodeData parses an L2TPv3 data packet from pkt, returning subslices of the
// input. It does not allocate. cookieLen and sublayer are per-session config
// chosen by the receiver; they must match what was negotiated.
func DecodeData(pkt []byte, cookieLen int, sublayer bool) (*DataHeader, error) {
	hdrLen := DataHeaderLen(cookieLen, sublayer)
	if len(pkt) < hdrLen {
		return nil, fmt.Errorf("l2tpv3: data packet too short: %d < %d", len(pkt), hdrLen)
	}

	// Verify version
	ver := binary.BigEndian.Uint16(pkt[0:])
	if ver != l2tpVer {
		return nil, fmt.Errorf("l2tpv3: bad version %d (want %d)", ver, l2tpVer)
	}
	// T bit must be 0 (data message)
	if ver&0x8000 != 0 {
		return nil, fmt.Errorf("l2tpv3: control message (T=1) in data path")
	}

	h := &DataHeader{
		SessionID: binary.BigEndian.Uint32(pkt[4:]),
		HasSublayer: sublayer,
	}

	if cookieLen > 0 {
		h.Cookie = pkt[8 : 8+cookieLen]
	}

	subOff := 8 + cookieLen
	if sublayer {
		copy(h.Sublayer[:], pkt[subOff:subOff+sublayerLen])
	}

	h.Frame = pkt[hdrLen:]
	return h, nil
}
