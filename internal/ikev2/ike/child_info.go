package ike

import (
	"net"

	"github.com/xen0bit/veepin/internal/ikev2/payload"
)

// handleCreateChildSA processes a CREATE_CHILD_SA request. It supports
// creating a new Child SA (the rekey-Child and rekey-IKE variants are
// recognized via the REKEY_SA notify but treated as new-child creation for
// this build).
//
//	HDR, SK{[N(REKEY_SA)], SA, Ni, [KEi], TSi, TSr} -->
//	                    <-- HDR, SK{SA, Nr, [KEr], TSi, TSr}
func (s *Server) handleCreateChildSA(sa *IKESA, hdr payload.Header, inners []payload.RawPayload, remote *net.UDPAddr) {
	saPay := findInner(inners, payload.TypeSA)
	noncePay := findInner(inners, payload.TypeNonce)
	tsiPay := findInner(inners, payload.TypeTSi)
	tsrPay := findInner(inners, payload.TypeTSr)

	// Advance the responder message-ID window regardless of outcome.
	sa.RecvMsgID = hdr.MessageID + 1

	if saPay == nil || noncePay == nil || tsiPay == nil || tsrPay == nil {
		s.respondEncryptedNotify(sa, payload.CREATE_CHILD_SA, hdr.MessageID, payload.InvalidSyntax, remote)
		return
	}

	espSA, err := payload.ParseSA(saPay.Body)
	if err != nil {
		s.respondEncryptedNotify(sa, payload.CREATE_CHILD_SA, hdr.MessageID, payload.InvalidSyntax, remote)
		return
	}
	es, accepted, err := SelectESPSuite(espSA)
	if err != nil {
		s.respondEncryptedNotify(sa, payload.CREATE_CHILD_SA, hdr.MessageID, payload.NoProposalChosen, remote)
		return
	}

	// Fresh nonces for the child key derivation. Note: per RFC 7296 the child
	// KEYMAT uses Ni|Nr from *this* exchange. We reuse the sa.Ni/sa.Nr fields
	// transiently by deriving with the CREATE_CHILD_SA nonces.
	initNonce := payload.ParseNonce(noncePay.Body)
	respNonce := randomNonce(sa.Suite.PRF.PreferredKeyLen)

	// Swap in these nonces for derivation without disturbing the IKE SA nonces.
	savedNi, savedNr := sa.Ni, sa.Nr
	sa.Ni, sa.Nr = initNonce, respNonce
	child, acceptedESP := s.setupChildSA(sa, es, accepted, tsiPay, tsrPay)
	sa.Ni, sa.Nr = savedNi, savedNr

	// Response chain: SA, Nr, TSi, TSr.
	b := payload.NewBuilder()
	b.Add(payload.TypeSA, false, payload.MarshalSA(payload.SAPayload{
		Proposals: []payload.Proposal{acceptedESP},
	}))
	b.Add(payload.TypeNonce, false, payload.MarshalNonce(respNonce))
	b.Add(payload.TypeTSi, false, tsiPay.Body)
	b.Add(payload.TypeTSr, false, tsrPay.Body)

	child.UDPEncap = sa.NAT.natDetected() || sa.OnPort4500
	child.ClientIP = sa.ClientIP
	child.PeerAddr = remote

	s.respondEncrypted(sa, payload.CREATE_CHILD_SA, hdr.MessageID, b.FirstType(), b.Bytes(), remote)

	sa.Children[child.InboundSPI] = child
	s.log.Printf("ikev2: CREATE_CHILD_SA up with %s (in=%#x out=%#x)", remote, child.InboundSPI, child.OutboundSPI)
	if s.cfg.DataPath != nil {
		s.cfg.DataPath.AddChild(sa, child)
	}
	if s.cfg.OnChildSA != nil {
		s.cfg.OnChildSA(sa, child)
	}
}

// handleInformational processes an INFORMATIONAL request: DELETE payloads,
// liveness checks (empty request), and status notifies.
//
//	HDR, SK{[N,] [D,] [CP,]} -->
//	                    <-- HDR, SK{[N,] [D,]}
func (s *Server) handleInformational(sa *IKESA, hdr payload.Header, inners []payload.RawPayload, remote *net.UDPAddr) {
	sa.RecvMsgID = hdr.MessageID + 1

	// Liveness probe: an empty INFORMATIONAL request must get an empty
	// (but encrypted) response.
	if len(inners) == 0 {
		s.respondEncrypted(sa, payload.INFORMATIONAL, hdr.MessageID, payload.NoNextPayload, nil, remote)
		return
	}

	b := payload.NewBuilder()

	// MOBIKE (RFC 4555): UPDATE_SA_ADDRESSES relocates the SA, COOKIE2 is a
	// return-routability probe. Both append their response notifies to b.
	s.handleMobikeInformational(sa, inners, remote, b)

	deleteIKE := false
	var deletedChildSPIs [][]byte

	for _, p := range inners {
		if p.Type != payload.TypeDelete {
			continue
		}
		d, err := payload.ParseDelete(p.Body)
		if err != nil {
			continue
		}
		switch d.Protocol {
		case payload.ProtoIKE:
			// Peer is tearing down the whole IKE SA.
			deleteIKE = true
		case payload.ProtoESP:
			// Delete the named Child SAs; respond with our matching SPIs.
			for _, spi := range d.SPIs {
				if len(spi) != 4 {
					continue
				}
				out := beU32(spi)
				for in, c := range sa.Children {
					if c.OutboundSPI == out {
						deletedChildSPIs = append(deletedChildSPIs, u32BE(c.InboundSPI))
						if s.cfg.DataPath != nil {
							s.cfg.DataPath.RemoveChild(sa, c)
						}
						delete(sa.Children, in)
						s.log.Printf("ikev2: deleted Child SA (out=%#x) at peer request", out)
					}
				}
			}
		}
	}

	if len(deletedChildSPIs) > 0 {
		b.Add(payload.TypeDelete, false, payload.MarshalDelete(payload.DeletePayload{
			Protocol: payload.ProtoESP, SPISize: 4, SPIs: deletedChildSPIs,
		}))
	}

	// Send response (empty if we only processed an IKE delete).
	s.respondEncrypted(sa, payload.INFORMATIONAL, hdr.MessageID, b.FirstType(), b.Bytes(), remote)

	if deleteIKE {
		sa.State = StateClosed
		if s.cfg.DataPath != nil {
			for _, c := range sa.Children {
				s.cfg.DataPath.RemoveChild(sa, c)
			}
		}
		s.deleteSA(sa)
		s.log.Printf("ikev2: IKE SA with %s deleted at peer request", remote)
	}
}
