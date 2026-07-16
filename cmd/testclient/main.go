// Command testclient is a minimal IKEv2 initiator used to smoke-test a running
// ikev2d server: it performs IKE_SA_INIT + IKE_AUTH with PSK, requests a config
// address, then sends one ESP packet and reports the assigned address. It is a
// diagnostic tool, not a full client.
package main

import (
	crand "crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"runtime"
	"time"

	"github.com/xen0bit/veepin/internal/crypto"
	"github.com/xen0bit/veepin/internal/eap"
	"github.com/xen0bit/veepin/internal/esp"
	"github.com/xen0bit/veepin/internal/payload"
)

// Build metadata, stamped via -ldflags at release time (see .goreleaser.yaml).
// Defaults apply to `go build`/`go run` and development binaries.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	showVersion := flag.Bool("version", false, "print version information and exit")
	server := flag.String("server", "127.0.0.1:500", "server IKE address")
	espAddr := flag.String("esp", "127.0.0.1:4500", "server NAT-T/ESP address")
	psk := flag.String("psk", "", "pre-shared key")
	id := flag.String("id", "client.example", "client identity (FQDN)")
	user := flag.String("user", "", "EAP username (enables EAP-MSCHAPv2 instead of client PSK)")
	pass := flag.String("pass", "", "EAP password")
	flag.Parse()
	if *showVersion {
		fmt.Printf("testclient %s (commit %s, built %s, %s)\n",
			version, commit, date, runtime.Version())
		return
	}
	if *psk == "" {
		log.Fatal("-psk required")
	}

	c := &client{psk: []byte(*psk), id: payload.IDPayload{Type: payload.IDFQDN, Data: []byte(*id)}}
	c.eapUser = *user
	c.eapPass = *pass
	saddr, _ := net.ResolveUDPAddr("udp", *server)
	conn, err := net.DialUDP("udp", nil, saddr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		log.Fatal(err)
	}
	c.conn = conn

	if err := c.saInit(); err != nil {
		log.Fatalf("IKE_SA_INIT failed: %v", err)
	}
	log.Printf("IKE_SA_INIT ok (responder SPI %#x)", c.spiR)

	if *user != "" {
		if err := c.authEAP(); err != nil {
			log.Fatalf("EAP IKE_AUTH failed: %v", err)
		}
		log.Printf("EAP-MSCHAPv2 ok — user %q authenticated, assigned internal IP: %v", *user, c.assignedIP)
	} else {
		if err := c.auth(); err != nil {
			log.Fatalf("IKE_AUTH failed: %v", err)
		}
		log.Printf("IKE_AUTH (PSK) ok — assigned internal IP: %v", c.assignedIP)
	}

	if c.assignedIP == nil {
		log.Fatal("no address assigned")
	}

	// Send one ESP packet through the tunnel.
	if err := c.sendESP(*espAddr); err != nil {
		log.Fatalf("ESP send failed: %v", err)
	}
	log.Printf("sent one ESP-encapsulated IP packet to %s", *espAddr)
	fmt.Println("SUCCESS: handshake + address assignment + ESP data path all working")
}

type client struct {
	conn                      *net.UDPConn
	psk                       []byte
	id                        payload.IDPayload
	spiI, spiR                uint64
	suite                     resolvedSuite
	dh                        crypto.DHGroup
	ni, nr                    []byte
	keys                      crypto.SAKeys
	saInitReq, saInitResp     []byte
	assignedIP                net.IP
	childOutSPI, childRespSPI uint32
	espEncID                  uint16
	espKeyLn                  uint16
	encI, encR                []byte
	eapUser, eapPass          string
}

type resolvedSuite struct {
	prf      *crypto.PRF
	encKey   int
	integKey int
}

func (c *client) saInit() error {
	c.spiI = randU64()
	dh, err := crypto.NewDHGroup(payload.DH_CURVE25519)
	if err != nil {
		return err
	}
	c.dh = dh
	pub, _ := dh.Generate()
	c.ni = randBytes(32)

	b := payload.NewBuilder()
	b.Add(payload.TypeSA, false, payload.MarshalSA(payload.SAPayload{Proposals: []payload.Proposal{ikeProposal()}}))
	b.Add(payload.TypeKE, false, payload.MarshalKE(payload.KEPayload{Group: payload.DH_CURVE25519, KeyData: pub}))
	b.Add(payload.TypeNonce, false, payload.MarshalNonce(c.ni))
	local := c.conn.LocalAddr().(*net.UDPAddr)
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{Type: payload.NATDetectionSourceIP, Data: natHash(c.spiI, 0, local.IP, uint16(local.Port))}))
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{Type: payload.NATDetectionDestinationIP, Data: natHash(c.spiI, 0, net.IPv4zero, 0)}))
	chain := b.Bytes()
	hdr := payload.Header{InitiatorSPI: c.spiI, NextPayload: b.FirstType(), Version: 0x20, ExchangeType: payload.IKE_SA_INIT, Flags: payload.FlagInitiator, Length: uint32(payload.HeaderLen + len(chain))}
	req := append(hdr.Marshal(nil), chain...)
	c.saInitReq = req
	if _, err := c.conn.Write(req); err != nil {
		return err
	}

	resp := make([]byte, 65535)
	n, err := c.conn.Read(resp)
	if err != nil {
		return err
	}
	resp = resp[:n]
	c.saInitResp = append([]byte(nil), resp...)
	msg, err := payload.ParseMessage(resp)
	if err != nil {
		return err
	}
	c.spiR = msg.Header.ResponderSPI
	saPay := msg.Find(payload.TypeSA)
	kePay := msg.Find(payload.TypeKE)
	noncePay := msg.Find(payload.TypeNonce)
	if saPay == nil || kePay == nil || noncePay == nil {
		return fmt.Errorf("missing payloads in SA_INIT response")
	}
	ke, _ := payload.ParseKE(kePay.Body)
	shared, err := c.dh.ComputeSecret(ke.KeyData)
	if err != nil {
		return err
	}
	c.nr = payload.ParseNonce(noncePay.Body)
	prf, _ := crypto.NewPRF(payload.PRF_HMAC_SHA2_256)
	cipher, _ := crypto.NewSKCipher(payload.ENCR_AES_GCM_16, 256)
	c.suite = resolvedSuite{prf: prf, encKey: cipher.KeyLen(), integKey: 0}
	_, keys := crypto.DeriveIKEKeys(prf, shared, c.ni, c.nr, c.spiI, c.spiR, cipher.KeyLen(), 0)
	c.keys = keys
	return nil
}

func (c *client) auth() error {
	prf := c.suite.prf
	idBody := payload.MarshalID(c.id)
	inner := crypto.PSKAuth(prf, c.psk, crypto.AuthOctets(prf, c.saInitReq, c.nr, c.keys.SKpi, idBody))
	c.childOutSPI = randU32()
	tsAll := payload.TSPayload{Selectors: []payload.TrafficSelector{allTraffic()}}
	cpReq := payload.CPPayload{Type: payload.CFGRequest, Attrs: []payload.CFGAttr{{Type: payload.CFGInternalIP4Address}, {Type: payload.CFGInternalIP4Netmask}, {Type: payload.CFGInternalIP4DNS}}}

	b := payload.NewBuilder()
	b.Add(payload.TypeIDi, false, idBody)
	b.Add(payload.TypeAUTH, false, payload.MarshalAuth(payload.AuthPayload{Method: payload.AuthSharedKeyMIC, Data: inner}))
	b.Add(payload.TypeCP, false, payload.MarshalCP(cpReq))
	b.Add(payload.TypeSA, false, payload.MarshalSA(payload.SAPayload{Proposals: []payload.Proposal{espProposal(u32b(c.childOutSPI))}}))
	b.Add(payload.TypeTSi, false, payload.MarshalTS(tsAll))
	b.Add(payload.TypeTSr, false, payload.MarshalTS(tsAll))

	pkt, err := c.seal(payload.IKE_AUTH, 1, b.FirstType(), b.Bytes())
	if err != nil {
		return err
	}
	if _, err := c.conn.Write(pkt); err != nil {
		return err
	}

	resp := make([]byte, 65535)
	n, err := c.conn.Read(resp)
	if err != nil {
		return err
	}
	first, dec, err := c.open(resp[:n])
	if err != nil {
		return err
	}
	inners, err := parseInner(first, dec)
	if err != nil {
		return err
	}
	if cp := find(inners, payload.TypeCP); cp != nil {
		p, _ := payload.ParseCP(cp.Body)
		if v, ok := p.AttrValue(payload.CFGInternalIP4Address); ok {
			c.assignedIP = net.IP(v).To4()
		}
	}
	saPay := find(inners, payload.TypeSA)
	if saPay == nil {
		return fmt.Errorf("no Child SA in AUTH response")
	}
	espSA, _ := payload.ParseSA(saPay.Body)
	if len(espSA.Proposals) > 0 && len(espSA.Proposals[0].SPI) == 4 {
		c.childRespSPI = binary.BigEndian.Uint32(espSA.Proposals[0].SPI)
	}
	// Derive child keys (AES-GCM-256, no integ).
	cipher, _ := crypto.NewSKCipher(payload.ENCR_AES_GCM_16, 256)
	total := 2 * cipher.KeyLen()
	km := crypto.DeriveChildKeys(c.suite.prf, c.keys.SKd, nil, c.ni, c.nr, total)
	c.encI = km[:cipher.KeyLen()]
	c.encR = km[cipher.KeyLen():]
	c.espEncID = payload.ENCR_AES_GCM_16
	c.espKeyLn = 256
	return nil
}

func (c *client) sendESP(addr string) error {
	oc, _ := crypto.NewSKCipher(c.espEncID, int(c.espKeyLn))
	ic, _ := crypto.NewSKCipher(c.espEncID, int(c.espKeyLn))
	sa := &esp.SA{
		SPIOut: c.childRespSPI, SPIIn: c.childOutSPI,
		Out: esp.Transform{Cipher: oc, EncKey: c.encI},
		In:  esp.Transform{Cipher: ic, EncKey: c.encR},
	}
	pkt := ipv4(c.assignedIP, net.ParseIP("93.184.216.34"), []byte("hello tunnel"))
	enc, err := sa.Encapsulate(pkt, 4)
	if err != nil {
		return err
	}
	ea, _ := net.ResolveUDPAddr("udp", addr)
	ec, err := net.DialUDP("udp", nil, ea)
	if err != nil {
		return err
	}
	defer ec.Close()
	_, err = ec.Write(enc)
	return err
}

// --- helpers ---

func (c *client) seal(ex payload.ExchangeType, msgID uint32, first payload.PayloadType, inner []byte) ([]byte, error) {
	cipher, _ := crypto.NewSKCipher(payload.ENCR_AES_GCM_16, 256)
	ivLen, icvLen := cipher.IVLen(), cipher.ICVLen()
	ctLen := len(inner) + 1
	skLen := 4 + ivLen + ctLen + icvLen
	total := payload.HeaderLen + skLen
	hdr := payload.Header{InitiatorSPI: c.spiI, ResponderSPI: c.spiR, NextPayload: payload.TypeSK, Version: 0x20, ExchangeType: ex, Flags: payload.FlagInitiator, MessageID: msgID, Length: uint32(total)}
	aad := hdr.Marshal(nil)
	aad = append(aad, byte(first), 0, byte(skLen>>8), byte(skLen))
	padded := append(append([]byte(nil), inner...), 0)
	sealed, err := cipher.Seal(c.keys.SKei, nil, aad, padded)
	if err != nil {
		return nil, err
	}
	return append(aad, sealed...), nil
}

func (c *client) open(pkt []byte) (payload.PayloadType, []byte, error) {
	msg, err := payload.ParseMessage(pkt)
	if err != nil {
		return 0, nil, err
	}
	sk := msg.Find(payload.TypeSK)
	if sk == nil {
		return 0, nil, fmt.Errorf("no SK payload")
	}
	cipher, _ := crypto.NewSKCipher(payload.ENCR_AES_GCM_16, 256)
	bodyStart := len(pkt) - len(sk.Body)
	aad := pkt[:bodyStart]
	first := payload.PayloadType(pkt[bodyStart-4])
	padded, err := cipher.Open(c.keys.SKer, nil, aad, sk.Body)
	if err != nil {
		return 0, nil, err
	}
	if len(padded) == 0 {
		return first, nil, nil
	}
	padLen := int(padded[len(padded)-1])
	return first, padded[:len(padded)-padLen-1], nil
}

func parseInner(first payload.PayloadType, buf []byte) ([]payload.RawPayload, error) {
	var out []payload.RawPayload
	next := first
	off := 0
	for next != payload.NoNextPayload {
		if off+4 > len(buf) {
			return nil, fmt.Errorf("truncated")
		}
		this := next
		next = payload.PayloadType(buf[off])
		l := int(binary.BigEndian.Uint16(buf[off+2 : off+4]))
		if l < 4 || off+l > len(buf) {
			return nil, fmt.Errorf("bad length")
		}
		out = append(out, payload.RawPayload{Type: this, Body: buf[off+4 : off+l]})
		off += l
	}
	return out, nil
}

func find(ps []payload.RawPayload, t payload.PayloadType) *payload.RawPayload {
	for i := range ps {
		if ps[i].Type == t {
			return &ps[i]
		}
	}
	return nil
}

func ikeProposal() payload.Proposal {
	return payload.Proposal{Num: 1, Protocol: payload.ProtoIKE, Transforms: []payload.Transform{
		{Type: payload.TransformENCR, ID: payload.ENCR_AES_GCM_16, KeyLen: 256},
		{Type: payload.TransformPRF, ID: payload.PRF_HMAC_SHA2_256},
		{Type: payload.TransformDH, ID: payload.DH_CURVE25519},
	}}
}
func espProposal(spi []byte) payload.Proposal {
	return payload.Proposal{Num: 1, Protocol: payload.ProtoESP, SPI: spi, Transforms: []payload.Transform{
		{Type: payload.TransformENCR, ID: payload.ENCR_AES_GCM_16, KeyLen: 256},
		{Type: payload.TransformESN, ID: payload.ESN_NONE},
	}}
}
func allTraffic() payload.TrafficSelector {
	return payload.TrafficSelector{Type: payload.TSIPv4AddrRange, StartPort: 0, EndPort: 65535, StartAddr: net.IPv4zero.To4(), EndAddr: net.IP{255, 255, 255, 255}}
}
func ipv4(src, dst net.IP, pl []byte) []byte {
	p := make([]byte, 20+len(pl))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8] = 64
	p[9] = 17
	copy(p[12:16], src.To4())
	copy(p[16:20], dst.To4())
	copy(p[20:], pl)
	return p
}

func randU64() uint64      { b := randBytes(8); return binary.BigEndian.Uint64(b) }
func randU32() uint32      { b := randBytes(4); return binary.BigEndian.Uint32(b) }
func u32b(v uint32) []byte { return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)} }

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := crand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func natHash(spiI, spiR uint64, ip net.IP, port uint16) []byte {
	h := sha1.New()
	var s [8]byte
	binary.BigEndian.PutUint64(s[:], spiI)
	h.Write(s[:])
	binary.BigEndian.PutUint64(s[:], spiR)
	h.Write(s[:])
	if v4 := ip.To4(); v4 != nil {
		h.Write(v4)
	} else {
		h.Write(ip.To16())
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	h.Write(p[:])
	return h.Sum(nil)
}

// authEAP runs the EAP-MSCHAPv2 IKE_AUTH flow: an AUTH-less first request, the
// MSCHAPv2 challenge/response, EAP-Success, and the final MSK-based AUTH.
func (c *client) authEAP() error {
	prf := c.suite.prf
	idBody := payload.MarshalID(c.id)

	// IKE_AUTH #1: IDi, CP request, Child SA, TS — but NO AUTH (signals EAP).
	c.childOutSPI = randU32()
	tsAll := payload.TSPayload{Selectors: []payload.TrafficSelector{allTraffic()}}
	cpReq := payload.CPPayload{Type: payload.CFGRequest, Attrs: []payload.CFGAttr{{Type: payload.CFGInternalIP4Address}, {Type: payload.CFGInternalIP4Netmask}, {Type: payload.CFGInternalIP4DNS}}}
	b := payload.NewBuilder()
	b.Add(payload.TypeIDi, false, idBody)
	b.Add(payload.TypeCP, false, payload.MarshalCP(cpReq))
	b.Add(payload.TypeSA, false, payload.MarshalSA(payload.SAPayload{Proposals: []payload.Proposal{espProposal(u32b(c.childOutSPI))}}))
	b.Add(payload.TypeTSi, false, payload.MarshalTS(tsAll))
	b.Add(payload.TypeTSr, false, payload.MarshalTS(tsAll))
	pkt, err := c.seal(payload.IKE_AUTH, 1, b.FirstType(), b.Bytes())
	if err != nil {
		return err
	}
	if _, err := c.conn.Write(pkt); err != nil {
		return err
	}

	// Response: IDr, AUTH (server PSK), EAP challenge.
	inners, err := c.recvInners()
	if err != nil {
		return err
	}
	eapPay := find(inners, payload.TypeEAP)
	if eapPay == nil {
		return fmt.Errorf("no EAP challenge from server")
	}
	eapReq, err := eap.Parse(eapPay.Body)
	if err != nil {
		return err
	}
	ch, ok := eap.ParseChallenge(eapReq.Data)
	if !ok {
		return fmt.Errorf("EAP request was not an MSCHAPv2 challenge")
	}

	// IKE_AUTH #2: MSCHAPv2 response.
	respData, msk := ch.BuildResponse(c.eapUser, c.eapPass)
	eapResp := eap.Packet{Code: eap.CodeResponse, Identifier: eapReq.Identifier, Type: eap.TypeMSCHAPv2, Data: respData}
	b2 := payload.NewBuilder()
	b2.Add(payload.TypeEAP, false, eapResp.Marshal())
	pkt, _ = c.seal(payload.IKE_AUTH, 2, b2.FirstType(), b2.Bytes())
	if _, err := c.conn.Write(pkt); err != nil {
		return err
	}

	// Response: MSCHAPv2 Success request.
	inners, err = c.recvInners()
	if err != nil {
		return err
	}
	eapPay = find(inners, payload.TypeEAP)
	if eapPay == nil {
		return fmt.Errorf("no EAP success from server (bad password?)")
	}
	successReq, _ := eap.Parse(eapPay.Body)
	if successReq.Code == eap.CodeRequest && len(successReq.Data) > 0 && successReq.Data[0] == 4 {
		return fmt.Errorf("authentication failed (MSCHAPv2 failure)")
	}

	// IKE_AUTH #3: acknowledge success.
	ack := eap.Packet{Code: eap.CodeResponse, Identifier: successReq.Identifier, Type: eap.TypeMSCHAPv2, Data: eap.SuccessResponseData()}
	b3 := payload.NewBuilder()
	b3.Add(payload.TypeEAP, false, ack.Marshal())
	pkt, _ = c.seal(payload.IKE_AUTH, 3, b3.FirstType(), b3.Bytes())
	if _, err := c.conn.Write(pkt); err != nil {
		return err
	}

	// Response: EAP-Success.
	inners, err = c.recvInners()
	if err != nil {
		return err
	}
	if eapPay = find(inners, payload.TypeEAP); eapPay != nil {
		if final, _ := eap.Parse(eapPay.Body); final.Code != eap.CodeSuccess {
			return fmt.Errorf("expected EAP-Success, got code %d", final.Code)
		}
	}

	// IKE_AUTH #4: final AUTH from MSK.
	octets := crypto.AuthOctets(prf, c.saInitReq, c.nr, c.keys.SKpi, idBody)
	authData := crypto.PSKAuth(prf, msk, octets)
	b4 := payload.NewBuilder()
	b4.Add(payload.TypeAUTH, false, payload.MarshalAuth(payload.AuthPayload{Method: payload.AuthSharedKeyMIC, Data: authData}))
	pkt, _ = c.seal(payload.IKE_AUTH, 4, b4.FirstType(), b4.Bytes())
	if _, err := c.conn.Write(pkt); err != nil {
		return err
	}

	// Final response: server AUTH + Child SA + CP reply.
	inners, err = c.recvInners()
	if err != nil {
		return err
	}
	if find(inners, payload.TypeAUTH) == nil {
		return fmt.Errorf("no final AUTH from server")
	}
	if cp := find(inners, payload.TypeCP); cp != nil {
		p, _ := payload.ParseCP(cp.Body)
		if v, ok := p.AttrValue(payload.CFGInternalIP4Address); ok {
			c.assignedIP = net.IP(v).To4()
		}
	}
	saPay := find(inners, payload.TypeSA)
	if saPay == nil {
		return fmt.Errorf("no Child SA in final response")
	}
	espSA, _ := payload.ParseSA(saPay.Body)
	if len(espSA.Proposals) > 0 && len(espSA.Proposals[0].SPI) == 4 {
		c.childRespSPI = binary.BigEndian.Uint32(espSA.Proposals[0].SPI)
	}
	cipher, _ := crypto.NewSKCipher(payload.ENCR_AES_GCM_16, 256)
	total := 2 * cipher.KeyLen()
	km := crypto.DeriveChildKeys(prf, c.keys.SKd, nil, c.ni, c.nr, total)
	c.encI = km[:cipher.KeyLen()]
	c.encR = km[cipher.KeyLen():]
	c.espEncID = payload.ENCR_AES_GCM_16
	c.espKeyLn = 256
	return nil
}

// recvInners reads and decrypts one SK-protected message into inner payloads.
func (c *client) recvInners() ([]payload.RawPayload, error) {
	buf := make([]byte, 65535)
	n, err := c.conn.Read(buf)
	if err != nil {
		return nil, err
	}
	first, dec, err := c.open(buf[:n])
	if err != nil {
		return nil, err
	}
	return parseInner(first, dec)
}
