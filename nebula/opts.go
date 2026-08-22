package nebula

// Client option metadata for the Dial surface. A nebula host's address and
// identity come from the certificate its CA signed, so there is no address or
// user option; the CA bundle, certificate and private key are the minimum.

import "github.com/xen0bit/veepin/client"

func init() {
	client.RegisterClientOpts("nebula", []client.OptSpec{
		{Key: OptCA, Kind: client.OptFilePath, Required: true, Help: "path to the CA certificate bundle"},
		{Key: OptCert, Kind: client.OptFilePath, Required: true, Help: "path to this host's certificate"},
		{Key: OptKey, Kind: client.OptFilePath, Secret: true, Required: true, Help: "path to this host's X25519 private key"},
		{Key: OptListen, Kind: client.OptStr, Default: ":4242", Help: "local UDP address to bind"},
		{Key: OptStaticHosts, Kind: client.OptCommaList, Help: "peer locations: 10.42.0.1=192.0.2.10:4242[,...];..."},
		{Key: OptLighthouses, Kind: client.OptCommaList, Help: "comma-separated lighthouse overlay addresses"},
		{Key: OptAmLighthouse, Kind: client.OptBool, Help: "answer lighthouse queries from other hosts"},
		{Key: OptRelays, Kind: client.OptCommaList, Help: "overlay addresses of hosts that may relay for us when a direct path fails"},
		{Key: OptRelayFor, Kind: client.OptBool, Help: "forward traffic for other hosts (a relay sees who talks to whom)"},
		{Key: OptCipher, Kind: client.OptStr, Default: "aes", Help: "aes (default) or chachapoly; must match the mesh"},
		{Key: OptMTU, Kind: client.OptInt, Default: "1300", Help: "inner MTU (default 1300)"},
		{Key: OptShape, Kind: client.OptInt, Default: "0", Help: "per-flow shaping budget in bytes for traffic this host sends; pads inside the AEAD (0 = off)"},
		client.TUNOpt(OptTUN),
	})
}
