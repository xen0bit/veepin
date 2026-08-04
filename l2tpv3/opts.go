package l2tpv3

// Client option metadata for the Dial surface.
//
// The cookies are flagged Secret, and the argument that they are not is worth
// stating because this file used to make it: a cookie is a check value, not a
// credential, and it authenticates nothing. RFC 3931 5.4.3 is precise about what
// it is for -- "a modest level of protection against blind insertion of data" --
// and that protection is exactly as good as the cookie being unknown. Print it
// in a profile listing and the one property it has is gone. server.go has always
// flagged them, so the two tables disagreeing was also a redaction that depended
// on which endpoint you asked; TestSecretFlagsAgreeAcrossBothTables now refuses
// that.

import "github.com/xen0bit/veepin/client"

func init() {
	client.RegisterClientOpts("l2tpv3", []client.OptSpec{
		{Key: OptGateway, Kind: client.OptStr, Required: true, Help: "L2TPv3 peer host or IP"},
		{Key: OptPort, Kind: client.OptInt, Default: "1701", Help: "peer UDP port (default 1701)"},
		{Key: OptLocalPort, Kind: client.OptInt, Help: "local UDP port to bind (default: same as port; a static pseudowire is symmetric)"},
		{Key: OptSessionID, Kind: client.OptInt, Required: true, Help: "our session ID: what the peer sends to"},
		{Key: OptPeerSession, Kind: client.OptInt, Required: true, Help: "the peer's session ID: what we send to"},
		{Key: OptCookie, Kind: client.OptStr, Secret: true, Help: "hex cookie WE chose, verified on inbound packets (0, 4 or 8 octets)"},
		{Key: OptPeerCookie, Kind: client.OptStr, Secret: true, Help: "hex cookie the PEER chose, written on outbound packets"},
		{Key: OptSublayer, Kind: client.OptBool, Help: "carry the Default L2-Specific Sublayer (the Linux kernel sends one)"},
		{Key: OptCCID, Kind: client.OptInt, Help: "our Control Connection ID; with peer-ccid, enables HELLO keepalives"},
		{Key: OptPeerCCID, Kind: client.OptInt, Help: "the peer's Control Connection ID"},
		{Key: OptKeepalive, Kind: client.OptInt, Default: "30", Help: "HELLO interval in seconds (default 30)"},
		{Key: OptShape, Kind: client.OptInt, Default: "0", Help: "per-flow shaping budget in bytes; pads IP-bearing frames only (0 = off)"},
		{Key: OptTUN, Kind: client.OptStr, Help: "TAP interface name (empty = kernel picks)"},
	})
}
