package openvpn

// Client option metadata for the Dial surface. Required mirrors the
// NetworkManager plugin's requireKeys: an .ovpn -config file carries the remote
// (and usually the CA/cert), so without one a remote host is the minimum.

import "github.com/xen0bit/veepin/client"

func init() {
	client.RegisterClientOpts("openvpn", []client.OptSpec{
		{Key: OptConfig, Kind: client.OptFilePath, Help: ".ovpn profile (flags below override its values)"},
		{Key: OptRemote, Kind: client.OptStr, Required: true, Help: "server host or IP"},
		{Key: OptPort, Kind: client.OptInt, Default: "1194", Help: "server UDP port (default 1194)"},
		{Key: OptCA, Kind: client.OptFilePath, Help: "path to the CA certificate PEM"},
		{Key: OptCert, Kind: client.OptFilePath, Help: "path to the client certificate PEM"},
		{Key: OptKey, Kind: client.OptFilePath, Secret: true, Help: "path to the client private key PEM"},
		{Key: OptCipher, Kind: client.OptStr, Default: "AES-256-GCM", Help: "data cipher: AES-256-GCM (default) or AES-256-CBC"},
		{Key: OptAuth, Kind: client.OptStr, Default: "SHA1", Help: "HMAC digest for tls-auth and the CBC data channel (default SHA1)"},
		{Key: OptTLSAuth, Kind: client.OptFilePath, Help: "path to a --tls-auth static key"},
		{Key: OptTLSCrypt, Kind: client.OptFilePath, Help: "path to a --tls-crypt static key"},
		{Key: OptKeyDirection, Kind: client.OptInt, Default: "-1", Help: "tls-auth key direction: 0 or 1 (default: bidirectional)"},
		{Key: OptUsername, Kind: client.OptStr, Help: "auth-user-pass username"},
		{Key: OptPassword, Kind: client.OptStr, Secret: true, Help: "auth-user-pass password"},
		{Key: OptShape, Kind: client.OptInt, Default: "0", Help: "per-flow upstream shaping budget in bytes (0 = off)"},
		{Key: OptTUNName, Kind: client.OptStr, Help: "TUN interface name (empty = kernel picks)"},
	})
}
