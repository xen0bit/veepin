// Package ikev1 implements the IKEv1 (ISAKMP/Oakley, RFC 2407/2408/2409) key
// exchange that keys the IPsec transport-mode SA under L2TP/IPsec. It provides a
// Main Mode initiator and responder with pre-shared-key authentication, Quick
// Mode to negotiate an ESP transport SA for UDP/1701, and NAT-T (RFC 3947) so
// ESP floats to UDP/4500.
//
// This is the exchange every native-OS L2TP/IPsec client speaks (Windows, macOS,
// iOS, Android) and the mode a stock xl2tpd/strongSwan deployment uses, which is
// why L2TP/IPsec needs IKEv1 rather than the IKEv2 the rest of veepin runs. The
// cryptographic primitives (MODP DH, HMAC PRF, AES-CBC) come from
// internal/cryptoutil; the ESP data path is internal/ikev2/esp in transport mode.
package ikev1

// ISAKMP fixed version octet: major 1, minor 0 (RFC 2408 section 3.1).
const isakmpVersion = 0x10

// isakmpHeaderLen is the fixed ISAKMP header size in octets.
const isakmpHeaderLen = 28

// Exchange types (RFC 2408 section 3.1, RFC 2409).
const (
	exchangeMain          = 2  // Identity Protection (Main Mode)
	exchangeInformational = 5  // Informational
	exchangeQuick         = 32 // Quick Mode
)

// ISAKMP header flags.
const (
	flagEncryption = 0x01 // payloads after the header are encrypted
	flagCommit     = 0x02
)

// Payload types (RFC 2408 section 3.1, plus NAT-T from RFC 3947).
const (
	payloadNone      = 0
	payloadSA        = 1
	payloadProposal  = 2
	payloadTransform = 3
	payloadKE        = 4
	payloadID        = 5
	payloadHash      = 8
	payloadNonce     = 10
	payloadNotify    = 11
	payloadDelete    = 12
	payloadVendorID  = 13
	payloadNATD      = 20 // NAT-Discovery (RFC 3947); draft used 130
	payloadNATOA     = 21 // NAT-Original-Address; draft used 131
)

// IPsec DOI (RFC 2407).
const (
	doiIPsec              = 1
	situationIdentityOnly = 1
)

// Protocol IDs (RFC 2407 section 4.4.1).
const (
	protoISAKMP = 1
	protoESP    = 3
)

// Phase-1 (IKE) transform identifier: the only IKE transform is KEY_IKE.
const transformKeyIKE = 1

// ESP transform IDs (RFC 2407 section 4.4.4).
const (
	espTransform3DES = 3
	espTransformAES  = 12 // AES-CBC
)

// Phase-1 SA attribute types (RFC 2409 Appendix A). Encoded TV (basic) unless
// noted; Life Duration is TLV (variable).
const (
	attrEncryption   = 1
	attrHash         = 2
	attrAuthMethod   = 3
	attrGroup        = 4
	attrLifeType     = 11
	attrLifeDuration = 12
	attrKeyLength    = 14
)

// Phase-1 attribute values.
const (
	encrAES         = 7 // AES-CBC
	hashSHA         = 2 // SHA-1
	hashSHA2256     = 4 // SHA2-256
	authPSK         = 1 // pre-shared key
	groupMODP1024   = 2
	groupMODP2048   = 14
	lifeTypeSeconds = 1
)

// Phase-2 (IPsec DOI) SA attribute types (RFC 2407 section 4.5).
const (
	ipsecAttrLifeType     = 1
	ipsecAttrLifeDuration = 2
	ipsecAttrGroup        = 3
	ipsecAttrEncapMode    = 4
	ipsecAttrAuthAlg      = 5
	ipsecAttrKeyLength    = 6
)

// Encapsulation modes (RFC 2407 section 4.5, RFC 3947 section 5.2). The draft
// UDP-encapsulated values (61443/61444) are what many peers still send; we
// propose the RFC values and accept either.
const (
	encapTunnel            = 1
	encapTransport         = 2
	encapUDPTunnel         = 3
	encapUDPTransport      = 4
	encapUDPTransportDraft = 61443
	encapUDPTunnelDraft    = 61444
)

// Phase-2 authentication algorithms (RFC 2407 section 4.5).
const (
	authHMACSHA     = 2
	authHMACSHA2256 = 5
)

// ID types (RFC 2407 section 4.6.2.1).
const (
	idIPv4Addr       = 1
	idFQDN           = 2
	idUserFQDN       = 3
	idIPv4AddrSubnet = 4
)

// ipProtoUDP and l2tpPort are the transport-mode traffic selector for L2TP: the
// tunnel protects UDP datagrams on the L2TP port.
const (
	ipProtoUDP = 17
	l2tpPort   = 1701
)
