package ike

import (
	"bytes"
	"fmt"
	"net"

	"github.com/xen0bit/veepin/internal/crypto"
	"github.com/xen0bit/veepin/internal/payload"
)

// Identity describes a local or peer identity for IKE_AUTH.
type Identity struct {
	Type payload.IDType
	Data []byte
}

// FQDNIdentity builds an FQDN identity.
func FQDNIdentity(name string) Identity {
	return Identity{Type: payload.IDFQDN, Data: []byte(name)}
}

// IPIdentity builds an IPv4/IPv6 identity from an IP.
func IPIdentity(ip net.IP) Identity {
	if v4 := ip.To4(); v4 != nil {
		return Identity{Type: payload.IDIPv4Addr, Data: v4}
	}
	return Identity{Type: payload.IDIPv6Addr, Data: ip.To16()}
}

// idPayloadBody returns the ID payload body: type octet + 3 reserved + data.
// This is exactly what goes on the wire and what prf(SK_p, .) hashes.
func idPayloadBody(id Identity) []byte {
	return payload.MarshalID(payload.IDPayload{Type: id.Type, Data: id.Data})
}

// computePSKAuth returns the AUTH payload value for PSK authentication.
//
// signedOctets = realMessage | peerNonce | prf(SK_p<self>, IDpayloadBody)
// AUTH        = prf(prf(PSK, "Key Pad for IKEv2"), signedOctets)
//
// realMessage is this endpoint's own first IKE_SA_INIT message; peerNonce is
// the other party's nonce; skp is this endpoint's own SK_p (SK_pi if we are the
// initiator, SK_pr if responder).
func computePSKAuth(prf *crypto.PRF, psk, realMessage, peerNonce, skp, idBody []byte) []byte {
	octets := crypto.AuthOctets(prf, realMessage, peerNonce, skp, idBody)
	return crypto.PSKAuth(prf, psk, octets)
}

// verifyPeerPSKAuth checks the peer's AUTH payload under PSK.
//
// The peer signs: peerRealMessage | ourNonce | prf(peerSK_p, peerIDbody).
func verifyPeerPSKAuth(prf *crypto.PRF, psk, peerRealMessage, ourNonce, peerSKp, peerIDBody, gotAuth []byte) error {
	octets := crypto.AuthOctets(prf, peerRealMessage, ourNonce, peerSKp, peerIDBody)
	want := crypto.PSKAuth(prf, psk, octets)
	if !bytes.Equal(want, gotAuth) {
		return fmt.Errorf("ike: PSK authentication failed")
	}
	return nil
}
