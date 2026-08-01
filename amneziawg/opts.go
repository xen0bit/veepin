package amneziawg

// Client option metadata for the Dial surface. The obfuscation parameters are
// not negotiated: both ends must be given identical values, exactly like a
// pre-shared key. The tunnel flags mirror the wireguard case.

import "github.com/xen0bit/veepin/client"

func init() {
	client.RegisterClientOpts("amneziawg", []client.OptSpec{
		{Key: OptPrivateKey, Kind: client.OptStr, Secret: true, Required: true, Help: "our static private key, base64"},
		{Key: OptPublicKey, Kind: client.OptStr, Required: true, Help: "the server's static public key, base64"},
		{Key: OptPresharedKey, Kind: client.OptStr, Secret: true, Help: "optional 32-byte pre-shared key, base64"},
		{Key: OptEndpoint, Kind: client.OptStr, Required: true, Help: "server host:port"},
		{Key: OptAddress, Kind: client.OptCIDR, Required: true, Help: "our tunnel address, e.g. 10.0.0.2/24"},
		{Key: OptAllowedIPs, Kind: client.OptCommaList, Default: "0.0.0.0/0", Help: "comma-separated allowed IPs"},
		{Key: OptDNS, Kind: client.OptCommaList, Help: "comma-separated DNS servers to install"},
		{Key: OptMTU, Kind: client.OptInt, Default: "0", Help: "tunnel MTU (0 = protocol default)"},
		{Key: OptShape, Kind: client.OptInt, Default: "0", Help: "per-flow upstream shaping budget in bytes (0 = off)"},
		{Key: OptTypeInit, Kind: client.OptInt, Default: "0", Help: "H1: message type replacing handshake initiation (0 = stock 1)"},
		{Key: OptTypeResp, Kind: client.OptInt, Default: "0", Help: "H2: message type replacing handshake response (0 = stock 2)"},
		{Key: OptTypeCookie, Kind: client.OptInt, Default: "0", Help: "H3: message type replacing cookie reply (0 = stock 3)"},
		{Key: OptTypeTrans, Kind: client.OptInt, Default: "0", Help: "H4: message type replacing transport data (0 = stock 4)"},
		{Key: OptPadInit, Kind: client.OptInt, Default: "0", Help: "S1: random bytes prepended to handshake initiation"},
		{Key: OptPadResp, Kind: client.OptInt, Default: "0", Help: "S2: random bytes prepended to handshake response"},
		{Key: OptPadCookie, Kind: client.OptInt, Default: "0", Help: "S3: random bytes prepended to cookie reply"},
		{Key: OptPadTrans, Kind: client.OptInt, Default: "0", Help: "S4: random bytes prepended to transport data"},
		{Key: OptJunkCount, Kind: client.OptInt, Default: "0", Help: "Jc: junk datagrams sent before the handshake (0 = none)"},
		{Key: OptJunkMin, Kind: client.OptInt, Default: "0", Help: "Jmin: smallest junk datagram in bytes"},
		{Key: OptJunkMax, Kind: client.OptInt, Default: "0", Help: "Jmax: largest junk datagram in bytes"},
		{Key: OptTUNName, Kind: client.OptStr, Help: "TUN interface name (empty = kernel picks)"},
	})
}
