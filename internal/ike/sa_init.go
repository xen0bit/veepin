package ike

import (
	"net"

	"github.com/example/ikev2-go/internal/crypto"
	"github.com/example/ikev2-go/internal/payload"
)

// handleIKESAInit processes an IKE_SA_INIT request and sends the response.
//
//	Initiator                     Responder
//	HDR, SAi1, KEi, Ni,
//	  N(NAT_DETECTION_*)  -->
//	                      <--  HDR, SAr1, KEr, Nr, N(NAT_DETECTION_*)
func (s *Server) handleIKESAInit(pkt []byte, hdr payload.Header, remote *net.UDPAddr, on4500 bool) {
	if hdr.IsResponse() {
		return
	}
	msg, err := payload.ParseMessage(pkt)
	if err != nil {
		s.log.Printf("ikev2: SA_INIT parse from %s: %v", remote, err)
		return
	}

	saPay := msg.Find(payload.TypeSA)
	kePay := msg.Find(payload.TypeKE)
	noncePay := msg.Find(payload.TypeNonce)
	if saPay == nil || kePay == nil || noncePay == nil {
		s.sendUnauthNotify(hdr, remote, on4500, payload.InvalidSyntax)
		return
	}

	sa, err := payload.ParseSA(saPay.Body)
	if err != nil {
		s.sendUnauthNotify(hdr, remote, on4500, payload.InvalidSyntax)
		return
	}
	suite, accepted, err := SelectIKESuite(sa)
	if err != nil {
		s.sendUnauthNotify(hdr, remote, on4500, payload.NoProposalChosen)
		return
	}

	ke, err := payload.ParseKE(kePay.Body)
	if err != nil {
		s.sendUnauthNotify(hdr, remote, on4500, payload.InvalidSyntax)
		return
	}
	if ke.Group != suite.DHID {
		data := []byte{byte(suite.DHID >> 8), byte(suite.DHID)}
		s.sendUnauthNotifyData(hdr, remote, on4500, payload.InvalidKEPayload, data)
		return
	}

	dh, err := crypto.NewDHGroup(suite.DHID)
	if err != nil {
		s.sendUnauthNotify(hdr, remote, on4500, payload.NoProposalChosen)
		return
	}
	ourPub, err := dh.Generate()
	if err != nil {
		s.log.Printf("ikev2: DH generate: %v", err)
		return
	}
	shared, err := dh.ComputeSecret(ke.KeyData)
	if err != nil {
		s.log.Printf("ikev2: DH compute from %s: %v", remote, err)
		s.sendUnauthNotify(hdr, remote, on4500, payload.InvalidSyntax)
		return
	}

	newSA := newIKESA()
	newSA.InitiatorSPI = hdr.InitiatorSPI
	newSA.ResponderSPI = newIKESPI()
	newSA.WeAreInitiator = false
	newSA.Suite = suite
	newSA.RemoteAddr = remote
	newSA.OnPort4500 = on4500
	newSA.Ni = payload.ParseNonce(noncePay.Body)
	newSA.Nr = randomNonce(suite.PRF.PreferredKeyLen)
	newSA.SharedKey = shared
	newSA.InitiatorSAInit = append([]byte(nil), pkt...)

	// NAT detection (RFC 7296 2.23). Compare the peer-supplied hashes against
	// what we actually observe for source (the peer) and destination (us).
	newSA.NAT = s.detectNAT(msg, hdr, remote, on4500)

	_, keys := crypto.DeriveIKEKeys(
		suite.PRF, shared, newSA.Ni, newSA.Nr,
		newSA.InitiatorSPI, newSA.ResponderSPI,
		suite.encKeyLen(), suite.integKeyLen(),
	)
	newSA.Keys = keys
	newSA.State = StateSAInitDone

	// Build response: SAr1, KEr, Nr, NAT_DETECTION_SOURCE_IP, NAT_DETECTION_DESTINATION_IP.
	b := payload.NewBuilder()
	b.Add(payload.TypeSA, false, payload.MarshalSA(payload.SAPayload{
		Proposals: []payload.Proposal{accepted},
	}))
	b.Add(payload.TypeKE, false, payload.MarshalKE(payload.KEPayload{
		Group: suite.DHID, KeyData: ourPub,
	}))
	b.Add(payload.TypeNonce, false, payload.MarshalNonce(newSA.Nr))
	s.addNATDetection(b, newSA.InitiatorSPI, newSA.ResponderSPI, remote, on4500)

	chain := b.Bytes()
	respHdr := payload.Header{
		InitiatorSPI: newSA.InitiatorSPI,
		ResponderSPI: newSA.ResponderSPI,
		NextPayload:  b.FirstType(),
		Version:      0x20,
		ExchangeType: payload.IKE_SA_INIT,
		Flags:        payload.FlagResponse,
		MessageID:    0,
		Length:       uint32(payload.HeaderLen + len(chain)),
	}
	resp := append(respHdr.Marshal(nil), chain...)
	newSA.ResponderSAInit = append([]byte(nil), resp...)
	newSA.RecvMsgID = 1

	s.storeSA(newSA)
	s.send(resp, remote, on4500)
	s.log.Printf("ikev2: SA_INIT done with %s (rSPI=%#x, encr=%d prf=%d dh=%d, nat=%v)",
		remote, newSA.ResponderSPI, suite.EncrID, suite.PRFID, suite.DHID, newSA.NAT.natDetected())
}

// detectNAT compares the peer's NAT_DETECTION_* hashes against observed values.
// The initiator computes the destination hash over the server IP/port it is
// sending to, so we use our public IP and the port this datagram arrived on.
func (s *Server) detectNAT(msg *payload.Message, hdr payload.Header, remote *net.UDPAddr, on4500 bool) natInfo {
	var info natInfo
	var srcSeen, dstSeen bool

	ourPort := uint16(s.cfg.Port500)
	if on4500 {
		ourPort = uint16(s.cfg.Port4500)
	}
	ourIP := s.cfg.PublicIP
	if ourIP == nil {
		ourIP = net.IPv4zero
	}

	for _, p := range msg.FindAll(payload.TypeNotify) {
		n, err := payload.ParseNotify(p.Body)
		if err != nil {
			continue
		}
		switch n.Type {
		case payload.NATDetectionSourceIP:
			srcSeen = true
			// Source = the initiator, as we observe it on the wire.
			want := natDetectionHash(hdr.InitiatorSPI, hdr.ResponderSPI,
				remote.IP, uint16(remote.Port))
			if !equalBytes(want, n.Data) {
				info.peerBehindNAT = true
			}
		case payload.NATDetectionDestinationIP:
			dstSeen = true
			// Destination = us, as the initiator addressed us.
			want := natDetectionHash(hdr.InitiatorSPI, hdr.ResponderSPI, ourIP, ourPort)
			if !equalBytes(want, n.Data) {
				// Only trust this if we actually know our public IP.
				if s.cfg.PublicIP != nil {
					info.weAreBehindNAT = true
				}
			}
		}
	}
	if !srcSeen && !dstSeen {
		return natInfo{}
	}
	return info
}

// addNATDetection appends our own NAT_DETECTION_SOURCE_IP (this responder) and
// NAT_DETECTION_DESTINATION_IP (the initiator) notifies so the peer can detect
// NAT on its side too.
func (s *Server) addNATDetection(b *payload.Builder, spiI, spiR uint64, remote *net.UDPAddr, on4500 bool) {
	ourIP := s.cfg.PublicIP
	if ourIP == nil {
		ourIP = net.IPv4zero
	}
	ourPort := uint16(s.cfg.Port500)
	if on4500 {
		ourPort = uint16(s.cfg.Port4500)
	}
	// Source = us.
	srcHash := natDetectionHash(spiI, spiR, ourIP, ourPort)
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
		Protocol: payload.ProtoNone, Type: payload.NATDetectionSourceIP, Data: srcHash,
	}))
	// Destination = the initiator as we see it.
	dstHash := natDetectionHash(spiI, spiR, remote.IP, uint16(remote.Port))
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
		Protocol: payload.ProtoNone, Type: payload.NATDetectionDestinationIP, Data: dstHash,
	}))
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// sendUnauthNotify sends an unencrypted Notify response (IKE_SA_INIT errors).
func (s *Server) sendUnauthNotify(reqHdr payload.Header, remote *net.UDPAddr, on4500 bool, nt payload.NotifyType) {
	s.sendUnauthNotifyData(reqHdr, remote, on4500, nt, nil)
}

func (s *Server) sendUnauthNotifyData(reqHdr payload.Header, remote *net.UDPAddr, on4500 bool, nt payload.NotifyType, data []byte) {
	b := payload.NewBuilder()
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
		Protocol: payload.ProtoNone, Type: nt, Data: data,
	}))
	chain := b.Bytes()
	h := payload.Header{
		InitiatorSPI: reqHdr.InitiatorSPI,
		ResponderSPI: reqHdr.ResponderSPI,
		NextPayload:  b.FirstType(),
		Version:      0x20,
		ExchangeType: reqHdr.ExchangeType,
		Flags:        payload.FlagResponse,
		MessageID:    reqHdr.MessageID,
		Length:       uint32(payload.HeaderLen + len(chain)),
	}
	s.send(append(h.Marshal(nil), chain...), remote, on4500)
}
