package ike

import (
	"net"

	"github.com/xen0bit/veepin/internal/ikev2/eap"
	"github.com/xen0bit/veepin/internal/ikev2/payload"
)

// handleIKEAuth processes an IKE_AUTH request. Two authentication modes are
// supported:
//
//   - PSK: the initiator includes an AUTH payload; we verify it and respond
//     with our AUTH plus the Child SA in a single round trip.
//   - EAP (username/password): the initiator omits AUTH (RFC 7296 2.16). We
//     respond with our own AUTH (PSK, server-side) plus the first EAP request,
//     then exchange EAP messages over further IKE_AUTH round trips, and finally
//     verify the initiator's AUTH computed from the EAP MSK before creating the
//     Child SA.
func (s *Server) handleIKEAuth(sa *IKESA, hdr payload.Header, inners []payload.RawPayload, remote *net.UDPAddr) {
	// Are we mid-EAP already? Then this request carries an EAP response (or the
	// final AUTH).
	if sa.eapServer != nil {
		s.handleEAPContinue(sa, hdr, inners, remote)
		return
	}

	authPay := findInner(inners, payload.TypeAUTH)
	idiPay := findInner(inners, payload.TypeIDi)
	if idiPay == nil {
		s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.AuthenticationFailed, remote)
		return
	}
	idi, err := payload.ParseID(idiPay.Body)
	if err != nil {
		s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.InvalidSyntax, remote)
		return
	}
	sa.PeerID = idi
	sa.IDiForAuth = idPayloadBody(Identity{Type: idi.Type, Data: idi.Data})
	sa.peerMobike = findMobikeSupported(inners)

	// No AUTH payload → the client wants EAP.
	if authPay == nil {
		if s.cfg.EAPCredentials == nil {
			s.log.Printf("ikev2: %s requested EAP but server has no credentials", remote)
			s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.AuthenticationFailed, remote)
			return
		}
		s.handleEAPStart(sa, hdr, inners, remote)
		return
	}

	// PSK path (single round trip).
	auth, err := payload.ParseAuth(authPay.Body)
	if err != nil {
		s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.InvalidSyntax, remote)
		return
	}
	if auth.Method != payload.AuthSharedKeyMIC {
		s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.AuthenticationFailed, remote)
		return
	}
	if err := verifyPeerPSKAuth(sa.Suite.PRF, s.cfg.PSK,
		sa.InitiatorSAInit, sa.Nr, sa.Keys.SKpi, sa.IDiForAuth, auth.Data); err != nil {
		s.log.Printf("ikev2: IKE_AUTH (PSK) from %s failed: %v", remote, err)
		s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.AuthenticationFailed, remote)
		return
	}

	// Build our AUTH (PSK) and finish with the Child SA in one response.
	localIDBody := idPayloadBody(s.cfg.LocalID)
	ourAuth := computePSKAuth(sa.Suite.PRF, s.cfg.PSK, sa.ResponderSAInit, sa.Ni, sa.Keys.SKpr, localIDBody)

	b := payload.NewBuilder()
	b.Add(payload.TypeIDr, false, localIDBody)
	b.Add(payload.TypeAUTH, false, payload.MarshalAuth(payload.AuthPayload{
		Method: payload.AuthSharedKeyMIC, Data: ourAuth,
	}))
	s.finishIKEAuth(sa, hdr, inners, b, remote)
}

// handleEAPStart responds to the first (AUTH-less) IKE_AUTH: it sends IDr, our
// PSK AUTH, and the first EAP request (an MSCHAPv2 Challenge). The Child SA is
// deferred until EAP completes.
func (s *Server) handleEAPStart(sa *IKESA, hdr payload.Header, inners []payload.RawPayload, remote *net.UDPAddr) {
	// Our AUTH uses PSK (the server authenticates itself with the PSK even when
	// the client uses EAP).
	localIDBody := idPayloadBody(s.cfg.LocalID)
	ourAuth := computePSKAuth(sa.Suite.PRF, s.cfg.PSK, sa.ResponderSAInit, sa.Ni, sa.Keys.SKpr, localIDBody)

	// Start EAP-MSCHAPv2.
	srv := eap.NewServer(s.cfg.EAPCredentials, s.cfg.EAPServerName)
	sa.eapEAPID = 1
	challenge, err := srv.Begin(sa.eapEAPID)
	if err != nil {
		s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.AuthenticationFailed, remote)
		return
	}
	sa.eapServer = srv

	// Remember the Child SA request payloads for use once EAP completes.
	if p := findInner(inners, payload.TypeSA); p != nil {
		sa.eapSApay = append([]byte(nil), p.Body...)
	}
	if p := findInner(inners, payload.TypeTSi); p != nil {
		sa.eapTSipay = append([]byte(nil), p.Body...)
	}
	if p := findInner(inners, payload.TypeTSr); p != nil {
		sa.eapTSrpay = append([]byte(nil), p.Body...)
	}
	if p := findInner(inners, payload.TypeCP); p != nil {
		sa.eapCPpay = append([]byte(nil), p.Body...)
	}

	b := payload.NewBuilder()
	b.Add(payload.TypeIDr, false, localIDBody)
	b.Add(payload.TypeAUTH, false, payload.MarshalAuth(payload.AuthPayload{
		Method: payload.AuthSharedKeyMIC, Data: ourAuth,
	}))
	b.Add(payload.TypeEAP, false, challenge.Marshal())

	sa.RecvMsgID = hdr.MessageID + 1
	s.respondEncrypted(sa, payload.IKE_AUTH, hdr.MessageID, b.FirstType(), b.Bytes(), remote)
	s.log.Printf("ikev2: EAP-MSCHAPv2 started with %s", remote)
}

// handleEAPContinue processes a follow-up IKE_AUTH during EAP. Each such request
// carries either an EAP response or, once EAP has succeeded, the final AUTH
// payload computed from the MSK.
func (s *Server) handleEAPContinue(sa *IKESA, hdr payload.Header, inners []payload.RawPayload, remote *net.UDPAddr) {
	sa.RecvMsgID = hdr.MessageID + 1

	// If EAP already succeeded, this message must carry the final AUTH.
	if sa.eapMSK != nil {
		s.handleEAPFinalAuth(sa, hdr, inners, remote)
		return
	}

	eapPay := findInner(inners, payload.TypeEAP)
	if eapPay == nil {
		s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.AuthenticationFailed, remote)
		return
	}
	resp, err := eap.Parse(eapPay.Body)
	if err != nil {
		s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.AuthenticationFailed, remote)
		return
	}

	next, done, err := sa.eapServer.HandlePeer(resp)
	if err != nil {
		s.log.Printf("ikev2: EAP with %s failed: %v", remote, err)
		// Send the EAP failure/next packet then an auth failure.
		b := payload.NewBuilder()
		b.Add(payload.TypeEAP, false, next.Marshal())
		s.respondEncrypted(sa, payload.IKE_AUTH, hdr.MessageID, b.FirstType(), b.Bytes(), remote)
		return
	}

	// Emit the next EAP packet (Challenge continuation, Success, or Failure).
	b := payload.NewBuilder()
	b.Add(payload.TypeEAP, false, next.Marshal())
	s.respondEncrypted(sa, payload.IKE_AUTH, hdr.MessageID, b.FirstType(), b.Bytes(), remote)

	if done {
		out := sa.eapServer.Outcome()
		if !out.Success {
			s.log.Printf("ikev2: EAP authentication failed for %q from %s", out.Username, remote)
			return
		}
		// EAP succeeded: stash the MSK. The client will now send a final
		// IKE_AUTH containing its AUTH payload computed from the MSK.
		sa.eapMSK = out.MSK
		sa.EAPIdentity = out.Username
		s.log.Printf("ikev2: EAP-MSCHAPv2 success for %q from %s", out.Username, remote)
	}
}

// handleEAPFinalAuth verifies the initiator's MSK-based AUTH and completes the
// exchange by creating the Child SA.
func (s *Server) handleEAPFinalAuth(sa *IKESA, hdr payload.Header, inners []payload.RawPayload, remote *net.UDPAddr) {
	authPay := findInner(inners, payload.TypeAUTH)
	if authPay == nil {
		s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.AuthenticationFailed, remote)
		return
	}
	auth, err := payload.ParseAuth(authPay.Body)
	if err != nil {
		s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.InvalidSyntax, remote)
		return
	}

	// The initiator signs InitiatorSAInit | Nr | prf(SK_pi, IDi'), keyed by the
	// EAP MSK instead of a PSK (RFC 7296 2.16).
	octets := AuthOctets(sa.Suite.PRF, sa.InitiatorSAInit, sa.Nr, sa.Keys.SKpi, sa.IDiForAuth)
	want := PSKAuth(sa.Suite.PRF, sa.eapMSK, octets)
	if !equalBytes(want, auth.Data) {
		s.log.Printf("ikev2: EAP final AUTH from %s failed", remote)
		s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.AuthenticationFailed, remote)
		return
	}

	// Our final AUTH, also keyed by the MSK.
	localIDBody := idPayloadBody(s.cfg.LocalID)
	respOctets := AuthOctets(sa.Suite.PRF, sa.ResponderSAInit, sa.Ni, sa.Keys.SKpr, localIDBody)
	ourAuth := PSKAuth(sa.Suite.PRF, sa.eapMSK, respOctets)

	b := payload.NewBuilder()
	b.Add(payload.TypeAUTH, false, payload.MarshalAuth(payload.AuthPayload{
		Method: payload.AuthSharedKeyMIC, Data: ourAuth,
	}))
	s.finishIKEAuth(sa, hdr, inners, b, remote)
}

// finishIKEAuth completes an IKE_AUTH exchange: it appends the optional CP
// reply and the Child SA to the response builder b (which already holds the
// identity/AUTH payloads as required by the auth mode), sends the encrypted
// response, and registers the Child SA.
func (s *Server) finishIKEAuth(sa *IKESA, hdr payload.Header, inners []payload.RawPayload,
	b *payload.Builder, remote *net.UDPAddr) {

	saPay := findInner(inners, payload.TypeSA)
	tsiPay := findInner(inners, payload.TypeTSi)
	tsrPay := findInner(inners, payload.TypeTSr)
	cpPay := findInner(inners, payload.TypeCP)

	// In the EAP flow the Child SA payloads arrived in the first IKE_AUTH, not
	// this final one; fall back to the saved copies.
	if saPay == nil && sa.eapSApay != nil {
		saPay = &payload.RawPayload{Type: payload.TypeSA, Body: sa.eapSApay}
	}
	if tsiPay == nil && sa.eapTSipay != nil {
		tsiPay = &payload.RawPayload{Type: payload.TypeTSi, Body: sa.eapTSipay}
	}
	if tsrPay == nil && sa.eapTSrpay != nil {
		tsrPay = &payload.RawPayload{Type: payload.TypeTSr, Body: sa.eapTSrpay}
	}
	if cpPay == nil && sa.eapCPpay != nil {
		cpPay = &payload.RawPayload{Type: payload.TypeCP, Body: sa.eapCPpay}
	}

	// MOBIKE: if the peer advertised support, confirm it. We always support it,
	// so the peer's advertisement alone enables address agility for this SA.
	if sa.peerMobike {
		sa.MobikeEnabled = true
		addMobikeSupported(b)
	}

	// CP address assignment.
	if cpPay != nil && s.cfg.AssignAddr != nil {
		if cpReply := s.buildCPReply(sa, cpPay); cpReply != nil {
			b.Add(payload.TypeCP, false, payload.MarshalCP(*cpReply))
		}
	}

	// Child SA negotiation.
	var respChild *ChildSA
	var acceptedESP payload.Proposal
	haveChild := saPay != nil && tsiPay != nil && tsrPay != nil
	if haveChild {
		if espSA, perr := payload.ParseSA(saPay.Body); perr == nil {
			if es, accepted, serr := SelectESPSuite(espSA); serr == nil {
				respChild, acceptedESP = s.setupChildSA(sa, es, accepted, tsiPay, tsrPay)
			}
		}
	}
	if respChild != nil {
		b.Add(payload.TypeSA, false, payload.MarshalSA(payload.SAPayload{
			Proposals: []payload.Proposal{acceptedESP},
		}))
		b.Add(payload.TypeTSi, false, tsiPay.Body)
		b.Add(payload.TypeTSr, false, tsrPay.Body)
	} else if haveChild {
		b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
			Protocol: payload.ProtoNone, Type: payload.TSUnacceptable,
		}))
	}

	sa.State = StateEstablished
	sa.RecvMsgID = hdr.MessageID + 1

	if respChild != nil {
		respChild.UDPEncap = sa.NAT.natDetected() || sa.OnPort4500
		respChild.ClientIP = sa.ClientIP
		respChild.PeerAddr = remote
	}

	s.respondEncrypted(sa, payload.IKE_AUTH, hdr.MessageID, b.FirstType(), b.Bytes(), remote)
	s.log.Printf("ikev2: established IKE SA with %s (id=%v, client ip=%v)", remote, sa.PeerID.Type, sa.ClientIP)

	if respChild != nil {
		sa.Children[respChild.InboundSPI] = respChild
		s.log.Printf("ikev2: Child SA up (in=%#x out=%#x udpencap=%v)",
			respChild.InboundSPI, respChild.OutboundSPI, respChild.UDPEncap)
		if s.cfg.DataPath != nil {
			s.cfg.DataPath.AddChild(sa, respChild)
		}
		if s.cfg.OnChildSA != nil {
			s.cfg.OnChildSA(sa, respChild)
		}
	}
}

// buildCPReply allocates an internal address and builds a CFG_REPLY.
func (s *Server) buildCPReply(sa *IKESA, cpPay *payload.RawPayload) *payload.CPPayload {
	req, err := payload.ParseCP(cpPay.Body)
	if err != nil || req.Type != payload.CFGRequest {
		return nil
	}
	ip, netmask, dns, err := s.cfg.AssignAddr()
	if err != nil || ip == nil {
		s.log.Printf("ikev2: address assignment failed: %v", err)
		return nil
	}
	sa.ClientIP = ip
	reply := &payload.CPPayload{Type: payload.CFGReply}
	reply.Attrs = append(reply.Attrs, payload.CFGAttr{Type: payload.CFGInternalIP4Address, Value: ip.To4()})
	if netmask != nil {
		reply.Attrs = append(reply.Attrs, payload.CFGAttr{Type: payload.CFGInternalIP4Netmask, Value: netmask.To4()})
	}
	for _, d := range dns {
		if v4 := d.To4(); v4 != nil {
			reply.Attrs = append(reply.Attrs, payload.CFGAttr{Type: payload.CFGInternalIP4DNS, Value: v4})
		}
	}
	return reply
}

// setupChildSA derives the Child SA keys and returns the ChildSA plus the
// accepted ESP proposal (with our inbound SPI substituted).
func (s *Server) setupChildSA(sa *IKESA, es ESPSuite, accepted payload.Proposal,
	tsiPay, tsrPay *payload.RawPayload) (*ChildSA, payload.Proposal) {

	var outboundSPI uint32
	if len(accepted.SPI) == 4 {
		outboundSPI = beU32(accepted.SPI)
	}
	inboundSPI := newChildSPI()
	accepted.SPI = u32BE(inboundSPI)

	tsi, _ := payload.ParseTS(tsiPay.Body)
	tsr, _ := payload.ParseTS(tsrPay.Body)

	encLen := es.Cipher.KeyLen()
	integLen := 0
	if es.Integ != nil {
		integLen = es.Integ.KeyLen
	}
	total := 2*encLen + 2*integLen
	km := DeriveChildKeys(sa.Suite.PRF, sa.Keys.SKd, nil, sa.Ni, sa.Nr, total)

	off := 0
	take := func(n int) []byte { b := km[off : off+n]; off += n; return b }
	encI := take(encLen)
	var integI []byte
	if integLen > 0 {
		integI = take(integLen)
	}
	encR := take(encLen)
	var integR []byte
	if integLen > 0 {
		integR = take(integLen)
	}

	child := &ChildSA{
		InboundSPI:  inboundSPI,
		OutboundSPI: outboundSPI,
		Suite:       es,
		EncrOut:     encR, IntegOut: integR,
		EncrIn: encI, IntegIn: integI,
		TSi: tsi, TSr: tsr,
	}
	return child, accepted
}

func findInner(inners []payload.RawPayload, t payload.PayloadType) *payload.RawPayload {
	for i := range inners {
		if inners[i].Type == t {
			return &inners[i]
		}
	}
	return nil
}

func beU32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
func u32BE(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}
