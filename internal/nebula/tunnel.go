package nebula

// A keyed tunnel to one peer.
//
// Once the Noise handshake completes, each side holds two transport keys — one
// per direction — and a counter that serves as both the replay identifier and
// the AEAD nonce. A data packet is the 16-octet header followed by the
// ciphertext, with the header itself authenticated as additional data, so the
// type, tunnel index and counter cannot be altered in flight.
//
// Nebula reserves counters 1 and 2 for the two handshake messages, so data
// traffic begins at 3. Seeding the counter and the replay window from that
// point is what keeps the handshake's own messages from later looking like
// packets that went missing.

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
)

// handshakeMessageCount is the number of messages the IX pattern exchanges, and
// therefore the number of message counters it consumes.
const handshakeMessageCount = 2

var (
	errNotForUs    = errors.New("nebula: packet does not authenticate for this tunnel")
	errReplayed    = errors.New("nebula: message counter replayed or outside the window")
	errShortPacket = errors.New("nebula: packet is too short to hold a header and tag")
)

// tunnel is an established session with one peer.
type tunnel struct {
	// localIndex is the identifier this host chose; the peer puts it in the
	// remote index field of everything it sends here.
	localIndex uint32
	// remoteIndex is the peer's identifier, which this host echoes.
	remoteIndex uint32

	// weInitiated records which side started the handshake. Two hosts can key a
	// tunnel to each other at the same time, and resolving that collision needs
	// a rule both sides can evaluate identically -- see Host.install.
	weInitiated bool

	cipher   noiseCipher
	send     cipher.AEAD
	recv     cipher.AEAD
	peerCert *Certificate
	// peerAddr is the overlay address the peer's certificate vouches for.
	peerAddr netip.Addr

	counter atomic.Uint64

	mu     sync.Mutex
	window *replayWindow
}

// newTunnel builds a tunnel from a completed handshake.
func newTunnel(c noiseCipher, weInitiated bool, localIndex, remoteIndex uint32, sendKey, recvKey [keySize]byte, peer *Certificate) (*tunnel, error) {
	sendAEAD, err := c.aead(sendKey[:])
	if err != nil {
		return nil, err
	}
	recvAEAD, err := c.aead(recvKey[:])
	if err != nil {
		return nil, err
	}

	addr, ok := peer.Address()
	if !ok {
		return nil, fmt.Errorf("nebula: peer certificate %q carries no overlay address", peer.Name)
	}

	t := &tunnel{
		localIndex:  localIndex,
		remoteIndex: remoteIndex,
		weInitiated: weInitiated,
		cipher:      c,
		send:        sendAEAD,
		recv:        recvAEAD,
		peerCert:    peer,
		peerAddr:    addr,
		window:      newReplayWindow(),
	}
	t.counter.Store(handshakeMessageCount)
	t.window.markSeen(handshakeMessageCount)
	return t, nil
}

// PeerAddr returns the overlay address the peer is authorized to use.
func (t *tunnel) PeerAddr() netip.Addr { return t.peerAddr }

// encrypt wraps a payload for transmission. The header is generated here rather
// than supplied so that the counter and the nonce cannot drift apart.
func (t *tunnel) encrypt(typ messageType, sub messageSubType, payload []byte) []byte {
	counter := t.counter.Add(1)
	h := header{
		Version:        headerVersion,
		Type:           typ,
		Subtype:        sub,
		RemoteIndex:    t.remoteIndex,
		MessageCounter: counter,
	}
	out := h.encode(make([]byte, 0, headerLen+len(payload)+tagSize))
	return t.send.Seal(out, t.cipher.nonce(counter), payload, out[:headerLen])
}

// decrypt authenticates and unwraps a received packet.
//
// The order here is the security-relevant part: the packet is authenticated
// before its counter touches the replay window. Admitting an unauthenticated
// counter would let anyone who can send a datagram advance the window and lock
// the tunnel out of its own peer's traffic.
func (t *tunnel) decrypt(pkt []byte) (header, []byte, error) {
	h, err := parseHeader(pkt)
	if err != nil {
		return header{}, nil, err
	}
	if len(pkt) < headerLen+tagSize {
		return header{}, nil, errShortPacket
	}

	pt, err := t.recv.Open(nil, t.cipher.nonce(h.MessageCounter), pkt[headerLen:], pkt[:headerLen])
	if err != nil {
		return header{}, nil, fmt.Errorf("%w: %w", errNotForUs, err)
	}

	t.mu.Lock()
	ok := t.window.accept(h.MessageCounter)
	t.mu.Unlock()
	if !ok {
		return header{}, nil, errReplayed
	}
	return h, pt, nil
}

// newLocalIndex picks the identifier this host will be addressed by. It has to
// be unpredictable: it is the only tunnel selector a packet carries, so a
// guessable one would let an off-path attacker aim forged packets at a
// specific session.
func newLocalIndex() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	idx := binary.BigEndian.Uint32(b[:])
	if idx == 0 {
		// Zero is how nebula spells "no index yet" in a handshake, so it is
		// not usable as a real one.
		idx = 1
	}
	return idx, nil
}
