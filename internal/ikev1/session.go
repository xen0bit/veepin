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
	Send    func([]byte) error
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

	// Quick Mode.
	esp        espProposal
	qmMsgID    uint32
	qmIV       []byte
	qmNi, qmNr []byte
	inSPI      uint32 // our inbound ESP SPI
	outSPI     uint32 // peer's inbound ESP SPI (stamped on our outbound ESP)

	// Retransmission of the last message we sent.
	lastSent []byte
	timer    *time.Timer
	retries  int
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
	s.retries = 0
	s.armTimer()
	return s.cfg.Send(msg)
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
	_ = s.cfg.Send(s.lastSent)
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
