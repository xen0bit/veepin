package l2tpv3

// Client option metadata for the Dial surface. The cookies are check values,
// not credentials, so none are flagged secret.

import "github.com/xen0bit/veepin/client"

func init() {
	client.RegisterClientOpts("l2tpv3", []client.OptSpec{
		{Key: OptGateway, Kind: client.OptStr, Required: true, Help: "L2TPv3 peer host or IP"},
		{Key: OptPort, Kind: client.OptInt, Default: "1701", Help: "peer UDP port (default 1701)"},
		{Key: OptLocalPort, Kind: client.OptInt, Help: "local UDP port to bind (default: same as port; a static pseudowire is symmetric)"},
		{Key: OptSessionID, Kind: client.OptInt, Required: true, Help: "our session ID: what the peer sends to"},
		{Key: OptPeerSession, Kind: client.OptInt, Required: true, Help: "the peer's session ID: what we send to"},
		{Key: OptCookie, Kind: client.OptStr, Help: "hex cookie WE chose, verified on inbound packets (0, 4 or 8 octets)"},
		{Key: OptPeerCookie, Kind: client.OptStr, Help: "hex cookie the PEER chose, written on outbound packets"},
		{Key: OptSublayer, Kind: client.OptBool, Help: "carry the Default L2-Specific Sublayer (the Linux kernel sends one)"},
		{Key: OptCCID, Kind: client.OptInt, Help: "our Control Connection ID; with peer-ccid, enables HELLO keepalives"},
		{Key: OptPeerCCID, Kind: client.OptInt, Help: "the peer's Control Connection ID"},
		{Key: OptKeepalive, Kind: client.OptInt, Default: "30", Help: "HELLO interval in seconds (default 30)"},
		{Key: OptShape, Kind: client.OptInt, Default: "0", Help: "per-flow shaping budget in bytes; pads IP-bearing frames only (0 = off)"},
		{Key: OptTUN, Kind: client.OptStr, Help: "TAP interface name (empty = kernel picks)"},
	})
}
