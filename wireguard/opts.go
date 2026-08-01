package wireguard

// Client option metadata for the Dial surface. Required mirrors the
// NetworkManager plugin's requireKeys: the non-secret minimum a connection
// cannot start without, with a wg-quick -config file excusing the individual
// keys. Secret mirrors secretMissing.

import "github.com/xen0bit/veepin/client"

func init() {
	client.RegisterClientOpts("wireguard", []client.OptSpec{
		{Key: OptConfig, Kind: client.OptFilePath, Help: "wg-quick style config file (supplies the keys below)"},
		// A client-side listen port, despite the shared spelling with the
		// server's: Config.applyOverrides reads it on the dial path to bind a
		// fixed source port, which is what keeps a NAT pinhole stable across
		// roams. Undeclared, it was readable by the parse and reachable from
		// nothing the operator drives.
		{Key: OptListenPort, Kind: client.OptInt, Help: "local UDP port to bind (0 = ephemeral; fixes the source port for a stable NAT pinhole)"},
		// Required, matching amneziawg's entry for the same field: both facades
		// fill the same wireguard.Config, and Config.resolve rejects an absent
		// private key before anything else. The two used to disagree.
		{Key: OptPrivateKey, Kind: client.OptStr, Secret: true, Required: true, Help: "our static private key, base64"},
		{Key: OptAddress, Kind: client.OptCIDR, Required: true, Help: "our tunnel address in CIDR form, e.g. 10.0.0.2/32"},
		{Key: OptPublicKey, Kind: client.OptStr, Required: true, Help: "peer static public key, base64"},
		{Key: OptPresharedKey, Kind: client.OptStr, Secret: true, Help: "optional preshared key, base64"},
		{Key: OptEndpoint, Kind: client.OptStr, Required: true, Help: "peer host:port, e.g. vpn.example.com:51820"},
		{Key: OptAllowedIPs, Kind: client.OptCommaList, Required: true, Default: "0.0.0.0/0", Help: "comma-separated destinations routed to the peer"},
		{Key: OptKeepalive, Kind: client.OptInt, Default: "0", Help: "persistent keepalive interval in seconds (0 = off)"},
		{Key: OptRekeySeconds, Kind: client.OptInt, Default: "120", Help: "seconds between key refreshes (0 = protocol default 120)"},
		{Key: OptDNS, Kind: client.OptCommaList, Help: "comma-separated DNS servers"},
		{Key: OptMTU, Kind: client.OptInt, Default: "1420", Help: "inner MTU (default 1420)"},
		{Key: OptShape, Kind: client.OptInt, Default: "0", Help: "per-flow upstream shaping budget in bytes (0 = off)"},
		{Key: OptTUNName, Kind: client.OptStr, Help: "TUN interface name (empty = kernel picks)"},
	})
}
