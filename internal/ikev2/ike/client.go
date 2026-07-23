package ike

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/cryptoutil"
	"github.com/xen0bit/veepin/internal/ikev2/eap"
	"github.com/xen0bit/veepin/internal/ikev2/esp"
	"github.com/xen0bit/veepin/internal/ikev2/payload"
	"github.com/xen0bit/veepin/internal/ikev2/transform"
)

// ErrAuthFailed indicates the peer's authentication could not be verified —
// typically a wrong PSK or EAP password. Callers can errors.Is-check it to
// distinguish credential failures from transport/negotiation failures.
var ErrAuthFailed = errors.New("authentication failed")

// ClientConfig configures an IKEv2 client (initiator).
type ClientConfig struct {
	// ServerHost is the VPN server address (IP or hostname). Port defaults to
	// 500 for IKE; NAT-T floats to 4500 automatically.
	ServerHost string
	// ServerPort is the IKE port (default 500).
	ServerPort int
	// NATTPort is the port IKE floats to and ESP rides on (default 4500). It is
	// configurable only so tests can use an ephemeral port; production is 4500.
	NATTPort int

	// PSK authenticates the server (and the client too, unless EAP is used).
	PSK []byte
	// LocalID is the identity this client presents (IDi).
	LocalID Identity
	// RemoteID, if set, is checked against the server's IDr.
	RemoteID *Identity

	// EAPUsername/EAPPassword, if set, switch client authentication to
	// EAP-MSCHAPv2 (the server still authenticates itself with the PSK).
	EAPUsername string
	EAPPassword string

	Logger *log.Logger
}

// ClientResult holds the outcome of a successful handshake: the assigned
// internal configuration and the negotiated Child SA keys/parameters needed to
// run the data path.
type ClientResult struct {
	AssignedIP  net.IP
	Netmask     net.IP
	DNS         []net.IP
	ServerAddr  *net.UDPAddr // where ESP is sent (port 4500 under NAT-T)
	UDPEncap    bool
	InboundSPI  uint32 // our SPI (server sends ESP to this)
	OutboundSPI uint32 // server's SPI (we send ESP to this)
	Suite       ESPSuite
	EncKeyOut   []byte // initiator->responder encryption key (we encrypt with this)
	IntegKeyOut []byte
	EncKeyIn    []byte // responder->initiator (we decrypt with this)
	IntegKeyIn  []byte
}

// Client is an IKEv2 initiator. It performs the handshake and exposes the
// negotiated Child SA so a data-plane pump can move traffic. One Client manages
// a single IKE SA.
type Client struct {
	cfg  ClientConfig
	log  *log.Logger
	conn *net.UDPConn

	spiI, spiR uint64
	suite      Suite
	dh         cryptoutil.DHGroup
	ni, nr     []byte
	keys       SAKeys
	saInitReq  []byte
	saInitResp []byte
	sendMsgID  uint32
	on4500     bool // true once floated to NAT-T port 4500 (IKE needs the marker)

	// mobike is true once the server confirmed MOBIKE_SUPPORTED in IKE_AUTH,
	// which is the precondition for Roam.
	mobike bool

	result *ClientResult

	serverIDBody []byte // captured IDr body (for EAP final AUTH verification)

	mu     sync.Mutex
	closed bool
}

// NewClient creates an IKEv2 client from cfg.
func NewClient(cfg ClientConfig) *Client {
	if cfg.ServerPort == 0 {
		cfg.ServerPort = 500
	}
	if cfg.NATTPort == 0 {
		cfg.NATTPort = 4500
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(log.Writer(), "", log.LstdFlags)
	}
	return &Client{cfg: cfg, log: logger}
}

// Connect performs IKE_SA_INIT and IKE_AUTH (PSK or EAP), returning the
// negotiated configuration and Child SA on success.
func (c *Client) Connect() (*ClientResult, error) {
	raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", c.cfg.ServerHost, c.cfg.ServerPort))
	if err != nil {
		return nil, fmt.Errorf("resolve server: %w", err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, fmt.Errorf("dial server: %w", err)
	}
	// Publish the socket under the lock so a concurrent Close (used to abort an
	// in-flight handshake) observes it, and abort if Close already fired.
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		conn.Close()
		return nil, fmt.Errorf("client closed")
	}
	c.conn = conn
	c.mu.Unlock()
	if err := c.conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		c.conn.Close()
		return nil, fmt.Errorf("set read deadline: %w", err)
	}

	if err := c.saInit(); err != nil {
		c.conn.Close()
		return nil, fmt.Errorf("IKE_SA_INIT: %w", err)
	}
	c.log.Printf("ikev2 client: IKE_SA_INIT complete")

	// Float to the NAT-T port: IKE_AUTH and ESP both run on 4500 over one socket,
	// as RFC 3948 requires. Sharing the socket is what lets a standards-compliant
	// responder (e.g. strongSwan) send return ESP to our IKE source port.
	if err := c.floatToNATT(); err != nil {
		c.Close()
		return nil, fmt.Errorf("NAT-T float: %w", err)
	}

	if c.cfg.EAPUsername != "" {
		if err := c.authEAP(); err != nil {
			c.conn.Close()
			return nil, fmt.Errorf("IKE_AUTH (EAP): %w", err)
		}
	} else {
		if err := c.authPSK(); err != nil {
			c.conn.Close()
			return nil, fmt.Errorf("IKE_AUTH (PSK): %w", err)
		}
	}
	c.log.Printf("ikev2 client: authenticated, assigned %v", c.result.AssignedIP)
	// Clear the handshake read deadline; the data path (which now shares this
	// socket via DataConn) does its own blocking reads.
	_ = c.conn.SetReadDeadline(time.Time{})
	return c.result, nil
}

// floatToNATT switches the IKE socket to the server's NAT-T port (4500) after
// IKE_SA_INIT. It re-dials (a new local port is fine: a NAT-T responder tracks
// the peer's current source address), so IKE_AUTH and the ESP data path share
// one socket on 4500.
func (c *Client) floatToNATT() error {
	srv := c.conn.RemoteAddr().(*net.UDPAddr)
	nconn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: srv.IP, Port: c.cfg.NATTPort})
	if err != nil {
		return err
	}
	if err := nconn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		nconn.Close()
		return err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		nconn.Close()
		return fmt.Errorf("client closed")
	}
	old := c.conn
	c.conn = nconn
	c.on4500 = true
	c.mu.Unlock()
	old.Close()
	return nil
}

// writeIKE sends one IKE message, prefixing the 4-byte non-ESP marker once the
// socket has floated to 4500 (so the peer's ESP demux can tell IKE from ESP).
func (c *Client) writeIKE(pkt []byte) error {
	if c.on4500 {
		framed := make([]byte, 4+len(pkt))
		copy(framed[4:], pkt)
		_, err := c.conn.Write(framed)
		return err
	}
	_, err := c.conn.Write(pkt)
	return err
}

// DataConn returns the IKE socket (floated to 4500) for the data path to share
// for ESP. Ownership stays with the Client; Close closes it.
func (c *Client) DataConn() *net.UDPConn { return c.conn }

// --- IKE_SA_INIT ---

func (c *Client) saInit() error {
	c.spiI = newIKESPI()
	dh, err := transform.DH(payload.DH_CURVE25519)
	if err != nil {
		return err
	}
	c.dh = dh
	pub, err := dh.Generate()
	if err != nil {
		return err
	}
	c.ni = mustNonce(32)

	b := payload.NewBuilder()
	b.Add(payload.TypeSA, false, payload.MarshalSA(payload.SAPayload{Proposals: []payload.Proposal{DefaultIKEProposal()}}))
	b.Add(payload.TypeKE, false, payload.MarshalKE(payload.KEPayload{Group: payload.DH_CURVE25519, KeyData: pub}))
	b.Add(payload.TypeNonce, false, payload.MarshalNonce(c.ni))
	local := c.conn.LocalAddr().(*net.UDPAddr)
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
		Protocol: payload.ProtoNone, Type: payload.NATDetectionSourceIP,
		Data: natDetectionHash(c.spiI, 0, local.IP, uint16(local.Port)),
	}))
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
		Protocol: payload.ProtoNone, Type: payload.NATDetectionDestinationIP,
		Data: natDetectionHash(c.spiI, 0, net.IPv4zero, 0),
	}))
	chain := b.Bytes()

	hdr := payload.Header{
		InitiatorSPI: c.spiI, NextPayload: b.FirstType(), Version: 0x20,
		ExchangeType: payload.IKE_SA_INIT, Flags: payload.FlagInitiator, MessageID: 0,
		Length: uint32(payload.HeaderLen + len(chain)),
	}
	req := append(hdr.Marshal(nil), chain...)
	c.saInitReq = req
	if err := c.writeIKE(req); err != nil {
		return err
	}

	resp, err := c.readMessage()
	if err != nil {
		return err
	}
	c.saInitResp = append([]byte(nil), resp...)
	msg, err := payload.ParseMessage(resp)
	if err != nil {
		return err
	}
	if n := findNotifyError(msg); n != 0 {
		return fmt.Errorf("server rejected SA_INIT: notify %d", n)
	}
	c.spiR = msg.Header.ResponderSPI

	saPay := msg.Find(payload.TypeSA)
	kePay := msg.Find(payload.TypeKE)
	noncePay := msg.Find(payload.TypeNonce)
	if saPay == nil || kePay == nil || noncePay == nil {
		return fmt.Errorf("response missing SA/KE/Nonce")
	}
	sa, err := payload.ParseSA(saPay.Body)
	if err != nil {
		return err
	}
	suite, _, err := SelectIKESuite(sa)
	if err != nil {
		return fmt.Errorf("cannot resolve negotiated suite: %w", err)
	}
	c.suite = suite

	ke, _ := payload.ParseKE(kePay.Body)
	shared, err := c.dh.ComputeSecret(ke.KeyData)
	if err != nil {
		return err
	}
	c.nr = payload.ParseNonce(noncePay.Body)

	_, keys := DeriveIKEKeys(suite.PRF, shared, c.ni, c.nr, c.spiI, c.spiR,
		suite.encKeyLen(), suite.integKeyLen())
	c.keys = keys
	return nil
}

// --- IKE_AUTH (PSK) ---

func (c *Client) authPSK() error {
	idBody := idPayloadBody(c.cfg.LocalID)
	authData := computePSKAuth(c.suite.PRF, c.cfg.PSK, c.saInitReq, c.nr, c.keys.SKpi, idBody)

	inner, childOutSPI := c.buildAuthInner(idBody, &payload.AuthPayload{
		Method: payload.AuthSharedKeyMIC, Data: authData,
	})
	c.sendMsgID = 1
	pkt, err := c.seal(payload.IKE_AUTH, 1, inner.FirstType(), inner.Bytes())
	if err != nil {
		return err
	}
	if err := c.writeIKE(pkt); err != nil {
		return err
	}

	inners, err := c.recvInners()
	if err != nil {
		return err
	}
	// IKE_AUTH consumed message ID 1; the next initiator request (e.g. a MOBIKE
	// UPDATE_SA_ADDRESSES) is 2.
	c.sendMsgID = 2
	return c.finishAuth(inners, childOutSPI, c.cfg.PSK, false)
}

// --- IKE_AUTH (EAP-MSCHAPv2) ---

func (c *Client) authEAP() error {
	idBody := idPayloadBody(c.cfg.LocalID)

	// Message 1: IDi + CP + SA + TS, no AUTH (signals EAP).
	inner, childOutSPI := c.buildAuthInner(idBody, nil)
	c.sendMsgID = 1
	pkt, err := c.seal(payload.IKE_AUTH, 1, inner.FirstType(), inner.Bytes())
	if err != nil {
		return err
	}
	if err := c.writeIKE(pkt); err != nil {
		return err
	}

	// Response: IDr + server AUTH + EAP challenge.
	inners, err := c.recvInners()
	if err != nil {
		return err
	}
	if err := c.verifyServerAuth(inners, c.cfg.PSK, false); err != nil {
		return err
	}
	eapPay := findInner(inners, payload.TypeEAP)
	if eapPay == nil {
		return fmt.Errorf("server did not start EAP")
	}
	eapReq, err := eap.Parse(eapPay.Body)
	if err != nil {
		return err
	}
	ch, ok := eap.ParseChallenge(eapReq.Data)
	if !ok {
		return fmt.Errorf("EAP request was not an MSCHAPv2 challenge")
	}

	// Message 2: MSCHAPv2 response.
	respData, msk := ch.BuildResponse(c.cfg.EAPUsername, c.cfg.EAPPassword)
	if err := c.sendEAP(2, eap.Packet{Code: eap.CodeResponse, Identifier: eapReq.Identifier, Type: eap.TypeMSCHAPv2, Data: respData}); err != nil {
		return err
	}
	inners, err = c.recvInners()
	if err != nil {
		return err
	}
	eapPay = findInner(inners, payload.TypeEAP)
	if eapPay == nil {
		return fmt.Errorf("no EAP success (bad password?)")
	}
	successReq, _ := eap.Parse(eapPay.Body)
	if successReq.Code == eap.CodeRequest && len(successReq.Data) > 0 && successReq.Data[0] == 4 {
		return fmt.Errorf("server rejected credentials: %w", ErrAuthFailed)
	}

	// Message 3: acknowledge success.
	if err := c.sendEAP(3, eap.Packet{Code: eap.CodeResponse, Identifier: successReq.Identifier, Type: eap.TypeMSCHAPv2, Data: eap.SuccessResponseData()}); err != nil {
		return err
	}
	inners, err = c.recvInners()
	if err != nil {
		return err
	}
	if eapPay = findInner(inners, payload.TypeEAP); eapPay != nil {
		if final, _ := eap.Parse(eapPay.Body); final.Code != eap.CodeSuccess {
			return fmt.Errorf("expected EAP-Success, got code %d", final.Code)
		}
	}

	// Message 4: final AUTH keyed by the MSK.
	octets := AuthOctets(c.suite.PRF, c.saInitReq, c.nr, c.keys.SKpi, idBody)
	authData := PSKAuth(c.suite.PRF, msk, octets)
	b := payload.NewBuilder()
	b.Add(payload.TypeAUTH, false, payload.MarshalAuth(payload.AuthPayload{Method: payload.AuthSharedKeyMIC, Data: authData}))
	pkt, err = c.seal(payload.IKE_AUTH, 4, b.FirstType(), b.Bytes())
	if err != nil {
		return err
	}
	if err := c.writeIKE(pkt); err != nil {
		return err
	}

	inners, err = c.recvInners()
	if err != nil {
		return err
	}
	// The EAP flow consumed message IDs 1..4; the next initiator request is 5.
	c.sendMsgID = 5
	return c.finishAuth(inners, childOutSPI, msk, true)
}

func (c *Client) sendEAP(msgID uint32, p eap.Packet) error {
	b := payload.NewBuilder()
	b.Add(payload.TypeEAP, false, p.Marshal())
	pkt, err := c.seal(payload.IKE_AUTH, msgID, b.FirstType(), b.Bytes())
	if err != nil {
		return err
	}
	return c.writeIKE(pkt)
}

// buildAuthInner assembles the IKE_AUTH inner payloads. If auth is nil the AUTH
// payload is omitted (EAP mode). Returns the builder and our chosen Child SPI.
func (c *Client) buildAuthInner(idBody []byte, auth *payload.AuthPayload) (*payload.Builder, uint32) {
	childOutSPI := newChildSPI()
	tsAll := payload.TSPayload{Selectors: []payload.TrafficSelector{allTrafficV4()}}
	cpReq := payload.CPPayload{Type: payload.CFGRequest, Attrs: []payload.CFGAttr{
		{Type: payload.CFGInternalIP4Address},
		{Type: payload.CFGInternalIP4Netmask},
		{Type: payload.CFGInternalIP4DNS},
	}}

	b := payload.NewBuilder()
	b.Add(payload.TypeIDi, false, idBody)
	if auth != nil {
		b.Add(payload.TypeAUTH, false, payload.MarshalAuth(*auth))
	}
	b.Add(payload.TypeCP, false, payload.MarshalCP(cpReq))
	b.Add(payload.TypeSA, false, payload.MarshalSA(payload.SAPayload{Proposals: []payload.Proposal{DefaultESPProposal(u32BE(childOutSPI))}}))
	b.Add(payload.TypeTSi, false, payload.MarshalTS(tsAll))
	b.Add(payload.TypeTSr, false, payload.MarshalTS(tsAll))
	// Advertise MOBIKE (RFC 4555) so the server permits us to relocate this SA's
	// addresses later without a full re-handshake.
	addMobikeSupported(b)
	return b, childOutSPI
}

// verifyServerAuth checks the responder's IDr and AUTH payload. On the EAP
// final message the IDr is not resent, so a previously captured IDr is reused.
func (c *Client) verifyServerAuth(inners []payload.RawPayload, key []byte, eapMSK bool) error {
	authPay := findInner(inners, payload.TypeAUTH)
	if authPay == nil {
		return fmt.Errorf("response missing AUTH")
	}
	auth, err := payload.ParseAuth(authPay.Body)
	if err != nil {
		return err
	}

	// Resolve the responder identity: from this message if present, else from
	// the one captured earlier (EAP final AUTH omits IDr).
	var peerIDBody []byte
	if idrPay := findInner(inners, payload.TypeIDr); idrPay != nil {
		idr, _ := payload.ParseID(idrPay.Body)
		if c.cfg.RemoteID != nil {
			if idr.Type != c.cfg.RemoteID.Type || string(idr.Data) != string(c.cfg.RemoteID.Data) {
				return fmt.Errorf("server identity mismatch")
			}
		}
		peerIDBody = idPayloadBody(Identity{Type: idr.Type, Data: idr.Data})
		c.serverIDBody = peerIDBody
	} else if c.serverIDBody != nil {
		peerIDBody = c.serverIDBody
	} else {
		return fmt.Errorf("response missing IDr")
	}

	if eapMSK {
		octets := AuthOctets(c.suite.PRF, c.saInitResp, c.ni, c.keys.SKpr, peerIDBody)
		want := PSKAuth(c.suite.PRF, key, octets)
		if !equalBytes(want, auth.Data) {
			return fmt.Errorf("server AUTH (MSK) verification failed: %w", ErrAuthFailed)
		}
		return nil
	}
	if err := verifyPeerPSKAuth(c.suite.PRF, key, c.saInitResp, c.ni, c.keys.SKpr, peerIDBody, auth.Data); err != nil {
		return fmt.Errorf("%w: %v", ErrAuthFailed, err)
	}
	return nil
}

// finishAuth verifies server AUTH (unless already done for EAP), captures the
// CP assignment and derives the Child SA.
func (c *Client) finishAuth(inners []payload.RawPayload, childOutSPI uint32, authKey []byte, eapMSK bool) error {
	if err := c.verifyServerAuth(inners, authKey, eapMSK); err != nil {
		return err
	}

	// MOBIKE is enabled only if the server confirmed it (RFC 4555 3.1).
	c.mobike = findMobikeSupported(inners)

	res := &ClientResult{OutboundSPI: 0, InboundSPI: childOutSPI}

	// CP assignment.
	if cpPay := findInner(inners, payload.TypeCP); cpPay != nil {
		if cp, perr := payload.ParseCP(cpPay.Body); perr == nil {
			if v, ok := cp.AttrValue(payload.CFGInternalIP4Address); ok {
				res.AssignedIP = net.IP(v).To4()
			}
			if v, ok := cp.AttrValue(payload.CFGInternalIP4Netmask); ok {
				res.Netmask = net.IP(v).To4()
			}
			for _, a := range cp.Attrs {
				if a.Type == payload.CFGInternalIP4DNS && len(a.Value) == 4 {
					res.DNS = append(res.DNS, net.IP(a.Value).To4())
				}
			}
		}
	}
	if res.AssignedIP == nil {
		return fmt.Errorf("server did not assign an internal address")
	}

	// Child SA.
	saPay := findInner(inners, payload.TypeSA)
	if saPay == nil {
		return fmt.Errorf("no Child SA in response")
	}
	espSA, _ := payload.ParseSA(saPay.Body)
	es, _, serr := SelectESPSuite(espSA)
	if serr != nil {
		return fmt.Errorf("cannot resolve ESP suite: %w", serr)
	}
	res.Suite = es
	if len(espSA.Proposals) > 0 && len(espSA.Proposals[0].SPI) == 4 {
		res.OutboundSPI = beU32(espSA.Proposals[0].SPI)
	}

	// Derive Child keys (initiator perspective).
	encLen := es.Cipher.KeyLen()
	integLen := 0
	if es.Integ != nil {
		integLen = es.Integ.KeyLen
	}
	total := 2*encLen + 2*integLen
	km := DeriveChildKeys(c.suite.PRF, c.keys.SKd, nil, c.ni, c.nr, total)
	off := 0
	take := func(n int) []byte { b := km[off : off+n]; off += n; return b }
	res.EncKeyOut = take(encLen)
	if integLen > 0 {
		res.IntegKeyOut = take(integLen)
	}
	res.EncKeyIn = take(encLen)
	if integLen > 0 {
		res.IntegKeyIn = take(integLen)
	}

	// Server ESP endpoint: the NAT-T port the socket floated to (4500 in prod).
	srv := c.conn.RemoteAddr().(*net.UDPAddr)
	res.ServerAddr = &net.UDPAddr{IP: srv.IP, Port: srv.Port}
	res.UDPEncap = true

	c.result = res
	return nil
}

// --- MOBIKE (RFC 4555) ---

// MobikeEnabled reports whether MOBIKE was negotiated, i.e. whether Roam may be
// called. It is valid only after a successful Connect.
func (c *Client) MobikeEnabled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mobike
}

// Roam relocates the IKE SA and its Child SAs to a fresh local address after
// the client's network changed (RFC 4555). It re-dials the NAT-T socket from a
// new local port and sends an UPDATE_SA_ADDRESSES INFORMATIONAL — with fresh
// NAT-detection hashes and a COOKIE2 the responder must echo — over the new
// socket. On success the client's data socket (DataConn) is the new one, so a
// caller sharing that socket for ESP must re-fetch it.
//
// Roam is for a caller driving the data path itself; it must not run
// concurrently with itself. It leaves the new socket without a read deadline,
// matching the socket state Connect leaves for the data path.
func (c *Client) Roam() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return fmt.Errorf("client closed")
	}
	if !c.mobike {
		c.mu.Unlock()
		return fmt.Errorf("ike: MOBIKE was not negotiated")
	}
	srv := c.conn.RemoteAddr().(*net.UDPAddr)
	c.mu.Unlock()

	// New socket from a fresh local port to the same server (a NAT-T responder
	// tracks the peer's current source address, so a new local port is fine).
	nconn, err := net.DialUDP("udp", nil, srv)
	if err != nil {
		return fmt.Errorf("ike: roam dial: %w", err)
	}
	if err := nconn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		nconn.Close()
		return err
	}

	// Publish the new socket so writeIKE/readMessage use it, keeping the old to
	// restore on failure.
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		nconn.Close()
		return fmt.Errorf("client closed")
	}
	old := c.conn
	c.conn = nconn
	c.mu.Unlock()

	if err := c.sendUpdateSAAddresses(srv); err != nil {
		c.mu.Lock()
		c.conn = old
		c.mu.Unlock()
		nconn.Close()
		return err
	}
	old.Close()
	_ = c.conn.SetReadDeadline(time.Time{})
	return nil
}

// sendUpdateSAAddresses performs the UPDATE_SA_ADDRESSES exchange over the
// (already-swapped) new socket and verifies the responder echoed our COOKIE2.
func (c *Client) sendUpdateSAAddresses(srv *net.UDPAddr) error {
	local := c.conn.LocalAddr().(*net.UDPAddr)
	cookie2 := mustNonce(16)

	b := payload.NewBuilder()
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
		Protocol: payload.ProtoNone, Type: payload.UpdateSAAddresses,
	}))
	// Fresh NAT detection from the new local address to the same server.
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
		Protocol: payload.ProtoNone, Type: payload.NATDetectionSourceIP,
		Data: natDetectionHash(c.spiI, c.spiR, local.IP, uint16(local.Port)),
	}))
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
		Protocol: payload.ProtoNone, Type: payload.NATDetectionDestinationIP,
		Data: natDetectionHash(c.spiI, c.spiR, srv.IP, uint16(srv.Port)),
	}))
	// COOKIE2 return-routability probe; the responder must echo it.
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
		Protocol: payload.ProtoNone, Type: payload.Cookie2, Data: cookie2,
	}))

	msgID := c.sendMsgID
	pkt, err := c.seal(payload.INFORMATIONAL, msgID, b.FirstType(), b.Bytes())
	if err != nil {
		return err
	}
	if err := c.writeIKE(pkt); err != nil {
		return fmt.Errorf("ike: roam send: %w", err)
	}

	inners, err := c.recvInners()
	if err != nil {
		return fmt.Errorf("ike: roam response: %w", err)
	}
	echo := findMobikeCookie2(inners)
	if echo == nil || !equalBytes(echo, cookie2) {
		return fmt.Errorf("ike: roam return-routability failed (COOKIE2 not echoed)")
	}
	c.sendMsgID = msgID + 1
	return nil
}

// findMobikeCookie2 returns the COOKIE2 data among inners, or nil.
func findMobikeCookie2(inners []payload.RawPayload) []byte {
	if n := findNotify(inners, payload.Cookie2); n != nil {
		return n.Data
	}
	return nil
}

// --- helpers ---

func (c *Client) seal(ex payload.ExchangeType, msgID uint32, first payload.PayloadType, inner []byte) ([]byte, error) {
	hdr := payload.Header{
		InitiatorSPI: c.spiI, ResponderSPI: c.spiR, Version: 0x20,
		ExchangeType: ex, Flags: payload.FlagInitiator, MessageID: msgID,
	}
	return buildEncryptedMessage(hdr, c.suite, c.keys, dirInitiatorToResponder, first, inner)
}

func (c *Client) recvInners() ([]payload.RawPayload, error) {
	raw, err := c.readMessage()
	if err != nil {
		return nil, err
	}
	msg, err := payload.ParseMessage(raw)
	if err != nil {
		return nil, err
	}
	if n := findNotifyError(msg); n != 0 {
		return nil, fmt.Errorf("server error notify %d", n)
	}
	sk := msg.Find(payload.TypeSK)
	if sk == nil {
		return nil, fmt.Errorf("response has no SK payload")
	}
	first, inner, err := decryptSK(raw, msg.Header, *sk, c.suite, c.keys, dirResponderToInitiator)
	if err != nil {
		return nil, err
	}
	inners, err := parseInnerPayloads(first, inner)
	if err != nil {
		return nil, err
	}
	// A rejection arrives as an encrypted (inner) error notify; surface
	// AUTHENTICATION_FAILED as ErrAuthFailed so callers can tell a bad
	// credential from a transport failure.
	if n := findInnerNotifyError(inners); n != 0 {
		if n == uint16(payload.AuthenticationFailed) {
			return nil, fmt.Errorf("server: notify %d: %w", n, ErrAuthFailed)
		}
		return nil, fmt.Errorf("server error notify %d", n)
	}
	return inners, nil
}

// findInnerNotifyError returns the first error-class notify type (< 16384) among
// decrypted inner payloads, or 0 if none.
func findInnerNotifyError(inners []payload.RawPayload) uint16 {
	for _, p := range inners {
		if p.Type == payload.TypeNotify {
			n, err := payload.ParseNotify(p.Body)
			if err == nil && uint16(n.Type) < 16384 && n.Type != 0 {
				return uint16(n.Type)
			}
		}
	}
	return 0
}

// readMessage reads one UDP datagram, stripping the 4-byte non-ESP marker if
// present (NAT-T on port 4500).
func (c *Client) readMessage() ([]byte, error) {
	buf := make([]byte, 65535)
	n, err := c.conn.Read(buf)
	if err != nil {
		return nil, err
	}
	pkt := buf[:n]
	// Non-ESP marker: 4 zero octets prefixed to IKE on 4500.
	if len(pkt) >= 4 && pkt[0] == 0 && pkt[1] == 0 && pkt[2] == 0 && pkt[3] == 0 {
		pkt = pkt[4:]
	}
	return pkt, nil
}

// Close tears down the IKE SA socket. It is idempotent and may be called
// concurrently with an in-flight Connect to abort it (closing the socket
// unblocks Connect's blocked read).
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// BuildTunnel converts the negotiated client Child SA into a dataplane.Tunnel
// ready for the pump. The client uses the initiator key directions: it encrypts
// outbound with the initiator->responder keys and decrypts inbound with the
// responder->initiator keys.
func (r *ClientResult) BuildTunnel() (dataplane.Tunnel, error) {
	if r.Suite.EncrID == 0 {
		return nil, fmt.Errorf("ike: client result has no negotiated cipher")
	}
	sa := &esp.SA{
		SPIOut: r.OutboundSPI, // server's inbound SPI (we send to it)
		SPIIn:  r.InboundSPI,  // our SPI (server sends to it)
		Out: esp.Transform{
			EncrID: r.Suite.EncrID, EncrKeyLn: r.Suite.EncrKeyLn, IntegID: r.Suite.IntegID,
			EncKey: r.EncKeyOut, IntegKey: r.IntegKeyOut,
		},
		In: esp.Transform{
			EncrID: r.Suite.EncrID, EncrKeyLn: r.Suite.EncrKeyLn, IntegID: r.Suite.IntegID,
			EncKey: r.EncKeyIn, IntegKey: r.IntegKeyIn,
		},
	}
	t := &espTunnel{
		espSA: sa,
		inSPI: r.InboundSPI,
		// Client side: everything leaving the local TUN belongs to the one server,
		// so this tunnel carries all destinations.
		routes: defaultRoute(),
	}
	t.peer.Store(r.ServerAddr)
	return t, nil
}

func mustNonce(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// findNotifyError returns the first error-class notify type (< 16384) in a
// message, or 0 if none.
func findNotifyError(msg *payload.Message) uint16 {
	for _, p := range msg.Payloads {
		if p.Type == payload.TypeNotify {
			n, err := payload.ParseNotify(p.Body)
			if err == nil && uint16(n.Type) < 16384 && n.Type != 0 {
				return uint16(n.Type)
			}
		}
	}
	return 0
}
