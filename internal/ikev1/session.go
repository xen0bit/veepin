package ikev1

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/xen0bit/veepin/internal/cryptoutil"
)

// Role selects the IKE role: the Initiator drives Main Mode and Quick Mode, the
// Responder answers.
type Role int

const (
	Initiator Role = iota
	Responder
)

// nonceLen is the length of the phase-1 and phase-2 nonces (RFC 2409 allows
// 8..256 octets).
const nonceLen = 16

// ESP transform IDs as the internal/ikev2/esp data path expects them (IANA IKEv2
// values), mapped from the IKEv1 phase-2 negotiation.
const (
	espEncrAESCBC        = 12 // ENCR_AES_CBC
	espAuthHMACSHA196    = 2  // AUTH_HMAC_SHA1_96
	espAuthHMACSHA256128 = 12 // AUTH_HMAC_SHA2_256_128
)

// Result is the keyed ESP transport SA a completed exchange yields, oriented for
// the local end and expressed in the transform IDs internal/ikev2/esp consumes.
type Result struct {
	EncrID    uint16 // ESP encryption transform (IKEv2 ID)
	EncrKeyLn uint16 // encryption key length in bits
	IntegID   uint16 // ESP integrity transform (IKEv2 ID)

	OutSPI, InSPI          uint32
	OutEncKey, OutIntegKey []byte
	InEncKey, InIntegKey   []byte

	// NATT reports that the exchange floated to the NAT-T port, so ESP is
	// UDP-encapsulated there. veepin always negotiates this.
	NATT bool
}

// Handler receives the exchange outcome.
type Handler interface {
	Established(Result)
	Failed(error)
}

// Config parameters one IKE session.
type Config struct {
	Role    Role
	PSK     []byte
	LocalIP net.IP
	PeerIP  net.IP
	// LocalPort and PeerPort are the source and destination ports of the initial
	// (pre-float) IKE datagrams. They are hashed into the NAT-D payloads, so they
	// must be what the wire actually carries, not the well-known 500.
	LocalPort, PeerPort uint16
	// Send transmits one IKE datagram. natt reports whether the session has
	// floated: the transport then sends from the NAT-T port with the non-ESP
	// marker rather than the plain IKE port.
	Send    func(msg []byte, natt bool) error
	Handler Handler
	Logger  *log.Logger
}

type sessionState int

const (
	stInit sessionState = iota
	stWaitMM2
	stWaitMM3
	stWaitMM4
	stWaitMM5
	stWaitMM6
	stWaitQM1
	stWaitQM2
	stWaitQM3
	stDone
	stFailed
)

// retransmit bounds an unanswered IKE message on a lossy path; a reliable path
// (loopback or an established ESP SA) never triggers it.
const (
	ikeRetransmitInterval = 2 * time.Second
	ikeMaxRetransmits     = 5
)

// Session drives one IKEv1 exchange for a single peer. It is transport-neutral:
// datagrams go out through cfg.Send and come in via HandleInbound.
type Session struct {
	cfg    Config
	logger *log.Logger

	mu    sync.Mutex
	state sessionState

	initCookie [8]byte
	respCookie [8]byte

	prop              ikeProposal
	propNum           uint8
	dh                cryptoutil.DHGroup
	localPub, peerPub []byte
	ni, nr            []byte // initiator, responder phase-1 nonces
	saBodyI           []byte // initiator's SA payload body, for HASH_I/HASH_R
	keys              *phase1

	// NAT traversal.
	peerNATT bool // the peer advertised a NAT-T vendor ID
	floated  bool // IKE (and ESP) have moved to the NAT-T port

	// Quick Mode.
	esp        espProposal
	qmMsgID    uint32
	qmIV       []byte
	qmNi, qmNr []byte
	inSPI      uint32 // our inbound ESP SPI
	outSPI     uint32 // peer's inbound ESP SPI (stamped on our outbound ESP)

	// Retransmission of the last message we sent. lastSentNATT pins it to the
	// port it originally went out on: the responder floats immediately after
	// sending MM4, and a retransmit of MM4 must still use the pre-float port.
	lastSent     []byte
	lastSentNATT bool
	timer        *time.Timer
	retries      int
}

// InitiatorCookie extracts the initiator cookie that opens every ISAKMP header.
// A server demultiplexes inbound IKE by it rather than by source address, since
// the NAT-T float moves a session to a different port mid-exchange.
func InitiatorCookie(msg []byte) ([8]byte, bool) {
	var c [8]byte
	if len(msg) < isakmpHeaderLen {
		return c, false
	}
	copy(c[:], msg[:8])
	return c, true
}

// NewSession builds an IKE session. The initiator must call Start; the responder
// begins on the first inbound message.
func NewSession(cfg Config) *Session {
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	return &Session{cfg: cfg, logger: logger}
}

// Start begins Main Mode (initiator only).
func (s *Session) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.Role != Initiator || s.state != stInit {
		return
	}
	_, _ = rand.Read(s.initCookie[:])
	if err := s.sendMM1(); err != nil {
		s.failLocked(err)
		return
	}
	s.state = stWaitMM2
}

// HandleInbound processes one inbound IKE datagram.
func (s *Session) HandleInbound(pkt []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == stDone || s.state == stFailed {
		return
	}
	h, first, rest, err := parseHeader(pkt)
	if err != nil {
		return
	}
	if err := s.dispatch(h, first, rest); err != nil {
		s.failLocked(err)
	}
}

func (s *Session) dispatch(h header, first uint8, rest []byte) error {
	switch s.cfg.Role {
	case Initiator:
		return s.dispatchInitiator(h, first, rest)
	default:
		return s.dispatchResponder(h, first, rest)
	}
}

// --- transmit / retransmit ---

func (s *Session) transmit(msg []byte) error {
	s.lastSent = msg
	s.lastSentNATT = s.floated
	s.retries = 0
	s.armTimer()
	return s.cfg.Send(msg, s.floated)
}

func (s *Session) armTimer() {
	if s.timer != nil {
		s.timer.Stop()
	}
	s.timer = time.AfterFunc(ikeRetransmitInterval, s.onRetransmit)
}

func (s *Session) onRetransmit() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == stDone || s.state == stFailed || s.lastSent == nil {
		return
	}
	s.retries++
	if s.retries > ikeMaxRetransmits {
		s.failLocked(fmt.Errorf("ikev1: exchange timed out"))
		return
	}
	_ = s.cfg.Send(s.lastSent, s.lastSentNATT)
	s.timer = time.AfterFunc(ikeRetransmitInterval, s.onRetransmit)
}

// advance clears the retransmit state once a message is accepted.
func (s *Session) advance() {
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	s.lastSent = nil
}

func (s *Session) failLocked(err error) {
	if s.state == stFailed || s.state == stDone {
		return
	}
	s.state = stFailed
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	s.cfg.Handler.Failed(err)
}

func (s *Session) mmHeader(exchange, flags uint8, msgID uint32) header {
	return header{initCookie: s.initCookie, respCookie: s.respCookie, exchange: exchange, flags: flags, messageID: msgID}
}

// nonce returns a fresh random nonce.
func nonce() []byte {
	b := make([]byte, nonceLen)
	_, _ = rand.Read(b)
	return b
}

func randSPI() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	v := binary.BigEndian.Uint32(b[:])
	if v == 0 {
		v = 1
	}
	return v
}

// constEq compares two byte slices in constant time.
func constEq(a, b []byte) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}
