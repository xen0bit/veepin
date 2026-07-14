package ike

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/xen0bit/ikennkt/internal/crypto"
	"github.com/xen0bit/ikennkt/internal/eap"
	"github.com/xen0bit/ikennkt/internal/esp"
	"github.com/xen0bit/ikennkt/internal/payload"
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
	dh         crypto.DHGroup
	ni, nr     []byte
	keys       crypto.SAKeys
	saInitReq  []byte
	saInitResp []byte
	sendMsgID  uint32

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
	c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	if err := c.saInit(); err != nil {
		c.conn.Close()
		return nil, fmt.Errorf("IKE_SA_INIT: %w", err)
	}
	c.log.Printf("ikev2 client: IKE_SA_INIT complete")

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
	return c.result, nil
}

// --- IKE_SA_INIT ---

func (c *Client) saInit() error {
	c.spiI = newIKESPI()
	dh, err := crypto.NewDHGroup(payload.DH_CURVE25519)
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
	if _, err := c.conn.Write(req); err != nil {
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

	_, keys := crypto.DeriveIKEKeys(suite.PRF, shared, c.ni, c.nr, c.spiI, c.spiR,
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
	if _, err := c.conn.Write(pkt); err != nil {
		return err
	}

	inners, err := c.recvInners()
	if err != nil {
		return err
	}
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
	if _, err := c.conn.Write(pkt); err != nil {
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
	octets := crypto.AuthOctets(c.suite.PRF, c.saInitReq, c.nr, c.keys.SKpi, idBody)
	authData := crypto.PSKAuth(c.suite.PRF, msk, octets)
	b := payload.NewBuilder()
	b.Add(payload.TypeAUTH, false, payload.MarshalAuth(payload.AuthPayload{Method: payload.AuthSharedKeyMIC, Data: authData}))
	pkt, err = c.seal(payload.IKE_AUTH, 4, b.FirstType(), b.Bytes())
	if err != nil {
		return err
	}
	if _, err := c.conn.Write(pkt); err != nil {
		return err
	}

	inners, err = c.recvInners()
	if err != nil {
		return err
	}
	return c.finishAuth(inners, childOutSPI, msk, true)
}

func (c *Client) sendEAP(msgID uint32, p eap.Packet) error {
	b := payload.NewBuilder()
	b.Add(payload.TypeEAP, false, p.Marshal())
	pkt, err := c.seal(payload.IKE_AUTH, msgID, b.FirstType(), b.Bytes())
	if err != nil {
		return err
	}
	_, err = c.conn.Write(pkt)
	return err
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
		octets := crypto.AuthOctets(c.suite.PRF, c.saInitResp, c.ni, c.keys.SKpr, peerIDBody)
		want := crypto.PSKAuth(c.suite.PRF, key, octets)
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
	km := crypto.DeriveChildKeys(c.suite.PRF, c.keys.SKd, nil, c.ni, c.nr, total)
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

	// Server ESP endpoint: under NAT-T this is the server on port 4500.
	srv := c.conn.RemoteAddr().(*net.UDPAddr)
	res.ServerAddr = &net.UDPAddr{IP: srv.IP, Port: 4500}
	res.UDPEncap = true

	c.result = res
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

// BuildTunnel converts the negotiated client Child SA into a dataplane.ESPTunnel
// ready for the pump. The client uses the initiator key directions: it encrypts
// outbound with the initiator->responder keys and decrypts inbound with the
// responder->initiator keys.
func (r *ClientResult) BuildTunnel() (*espTunnel, error) {
	if r.Suite.Cipher == nil {
		return nil, fmt.Errorf("ike: client result has no cipher")
	}
	outCipher, err := crypto.NewSKCipher(r.Suite.EncrID, int(r.Suite.EncrKeyLn))
	if err != nil {
		return nil, err
	}
	inCipher, err := crypto.NewSKCipher(r.Suite.EncrID, int(r.Suite.EncrKeyLn))
	if err != nil {
		return nil, err
	}
	var outInteg, inInteg *crypto.Integrity
	if r.Suite.Integ != nil {
		if outInteg, err = crypto.NewIntegrity(r.Suite.IntegID); err != nil {
			return nil, err
		}
		if inInteg, err = crypto.NewIntegrity(r.Suite.IntegID); err != nil {
			return nil, err
		}
	}
	sa := &esp.SA{
		SPIOut: r.OutboundSPI, // server's inbound SPI (we send to it)
		SPIIn:  r.InboundSPI,  // our SPI (server sends to it)
		Out: esp.Transform{
			Cipher: outCipher, Integ: outInteg,
			EncKey: r.EncKeyOut, IntegKey: r.IntegKeyOut,
		},
		In: esp.Transform{
			Cipher: inCipher, Integ: inInteg,
			EncKey: r.EncKeyIn, IntegKey: r.IntegKeyIn,
		},
	}
	return &espTunnel{
		espSA:    sa,
		inSPI:    r.InboundSPI,
		clientIP: r.AssignedIP,
		peer:     r.ServerAddr,
		udpEncap: r.UDPEncap,
	}, nil
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
