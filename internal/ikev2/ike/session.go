package ike

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/xen0bit/veepin/internal/ikev2/eap"
	"github.com/xen0bit/veepin/internal/ikev2/payload"
)

// SAState is the lifecycle state of an IKE SA.
type SAState int

const (
	StateInitial SAState = iota
	StateSAInitDone
	StateEstablished
	StateDeleting
	StateClosed
)

func (s SAState) String() string {
	switch s {
	case StateInitial:
		return "INITIAL"
	case StateSAInitDone:
		return "SA_INIT_DONE"
	case StateEstablished:
		return "ESTABLISHED"
	case StateDeleting:
		return "DELETING"
	case StateClosed:
		return "CLOSED"
	default:
		return "UNKNOWN"
	}
}

// ChildSA is a negotiated ESP Child SA with directional keys.
type ChildSA struct {
	// SPIs are 4-octet ESP SPIs. Outbound uses the peer's SPI, inbound ours.
	InboundSPI  uint32
	OutboundSPI uint32

	Suite ESPSuite

	// Directional key material. "Local" is what we use to protect outbound
	// traffic; "Remote" is what the peer uses (we use it to open inbound).
	EncrOut, IntegOut []byte
	EncrIn, IntegIn   []byte

	TSi payload.TSPayload
	TSr payload.TSPayload

	// UDPEncap indicates ESP must be UDP-encapsulated (NAT-T, port 4500).
	UDPEncap bool
	// ClientIP is the internal tunnel address assigned to the peer via CP.
	ClientIP net.IP
	// PeerAddr is the transport address to send encapsulated ESP to (may have
	// floated to :4500 after NAT-T).
	PeerAddr *net.UDPAddr
}

// IKESA holds all state for one IKE Security Association.
type IKESA struct {
	mu sync.Mutex

	// SPIs identifying this IKE SA.
	InitiatorSPI uint64
	ResponderSPI uint64

	// WeAreInitiator is true if this end started the IKE_SA_INIT exchange.
	WeAreInitiator bool

	State SAState
	Suite Suite

	// DH exchange material (kept only until keys are derived).
	Ni, Nr    []byte
	SharedKey []byte

	Keys SAKeys

	// First IKE_SA_INIT messages, needed for AUTH computation.
	InitiatorSAInit []byte
	ResponderSAInit []byte

	// Peer identity from IKE_AUTH.
	PeerID payload.IDPayload

	// EAP state (for username/password auth). When eapServer is non-nil the SA
	// is mid-EAP; eapMSK holds the derived key once EAP succeeds. IDiForAuth is
	// the initiator's ID payload body, captured from the first IKE_AUTH so the
	// final AUTH can be verified after EAP completes.
	eapServer   *eap.Server
	eapMSK      []byte
	IDiForAuth  []byte
	eapEAPID    uint8
	EAPIdentity string
	// Child SA request payloads carried in the first (EAP-start) IKE_AUTH, held
	// until EAP completes and the Child SA is created.
	eapSApay  []byte
	eapTSipay []byte
	eapTSrpay []byte
	eapCPpay  []byte

	// Message ID windows (single-message window, RFC 7296 2.3). For each role
	// we track the next expected/next-to-send ID.
	RecvMsgID uint32 // next request ID we expect as responder
	SendMsgID uint32 // next request ID we will send as initiator

	// Remote transport address (updated if the peer floats to :4500).
	RemoteAddr *net.UDPAddr
	// OnPort4500 is true once the exchange has floated to the NAT-T port.
	OnPort4500 bool

	// NAT detection results from IKE_SA_INIT.
	NAT natInfo

	// MobikeEnabled is true once MOBIKE (RFC 4555) is negotiated in IKE_AUTH:
	// the peer may relocate this SA's addresses with an UPDATE_SA_ADDRESSES
	// INFORMATIONAL. peerMobike records that the peer advertised support,
	// captured while processing IKE_AUTH so the response builder (which runs in
	// finishIKEAuth for both the PSK and EAP flows) can echo the notify.
	MobikeEnabled bool
	peerMobike    bool

	// fragEnabled is true once IKE fragmentation (RFC 7383) is negotiated in
	// IKE_SA_INIT: the peer may deliver later protected messages as SKF
	// fragments, which fragReasm reassembles. veepin advertises support and
	// reassembles inbound fragments but never fragments its own output.
	fragEnabled bool
	fragReasm   fragReassembler

	// ClientIP is the internal address assigned to this peer via CP.
	ClientIP net.IP

	Children map[uint32]*ChildSA // keyed by inbound SPI

	CreatedAt time.Time
	lastSeen  time.Time
}

func newIKESA() *IKESA {
	return &IKESA{
		State:     StateInitial,
		Children:  make(map[uint32]*ChildSA),
		CreatedAt: time.Now(),
		lastSeen:  time.Now(),
	}
}

// touch records activity for liveness/expiry bookkeeping.
func (sa *IKESA) touch() { sa.lastSeen = time.Now() }

// dirForOutbound returns which directional keys this endpoint uses to protect
// outbound messages. The initiator protects with SK_ei/SK_ai; the responder
// with SK_er/SK_ar.
func (sa *IKESA) dirForOutbound() keyDir {
	if sa.WeAreInitiator {
		return dirInitiatorToResponder
	}
	return dirResponderToInitiator
}

// dirForInbound returns the directional keys used to open received messages.
func (sa *IKESA) dirForInbound() keyDir {
	if sa.WeAreInitiator {
		return dirResponderToInitiator
	}
	return dirInitiatorToResponder
}

// newIKESPI returns a random non-zero 8-octet IKE SPI.
func newIKESPI() uint64 {
	var b [8]byte
	for {
		_, _ = rand.Read(b[:])
		v := binary.BigEndian.Uint64(b[:])
		if v != 0 {
			return v
		}
	}
}

// newChildSPI returns a random non-zero 4-octet ESP SPI.
func newChildSPI() uint32 {
	var b [4]byte
	for {
		_, _ = rand.Read(b[:])
		v := binary.BigEndian.Uint32(b[:])
		if v != 0 {
			return v
		}
	}
}

// randomNonce returns a fresh nonce of the given length (RFC 7296 requires
// 16..256 octets and at least half the PRF key size).
func randomNonce(n int) []byte {
	if n < 16 {
		n = 16
	}
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}
