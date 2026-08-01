package ssh

// Client option metadata for the Dial surface. An identity-key file is an
// alternative to a password, mirroring the NetworkManager plugin's handling.

import "github.com/xen0bit/veepin/client"

func init() {
	client.RegisterClientOpts("ssh", []client.OptSpec{
		{Key: OptServer, Kind: client.OptStr, Required: true, Help: "SSH server host or IP"},
		{Key: OptPort, Kind: client.OptInt, Default: "22", Help: "server TCP port (default 22)"},
		{Key: OptUser, Kind: client.OptStr, Required: true, Help: "SSH username"},
		// Secret like every other private-key path in the set (openvpn's key,
		// nebula's key, ikev2's key) -- what it points at is key material, and
		// the redaction paths key off this flag.
		{Key: OptIdentity, Kind: client.OptFilePath, Secret: true, Help: "path to a private key (alternative to a password)"},
		{Key: OptPassword, Kind: client.OptStr, Secret: true, Help: "password (if not using a key)"},
		{Key: OptKnownHosts, Kind: client.OptFilePath, Help: "known_hosts file for host-key verification"},
		{Key: OptInsecure, Kind: client.OptBool, Help: "skip host-key verification"},
		{Key: OptAddress, Kind: client.OptCIDR, Required: true, Help: "our tunnel address in CIDR form, e.g. 10.200.0.2/30"},
		{Key: OptPeer, Kind: client.OptStr, Help: "server tunnel address (point-to-point peer), e.g. 10.200.0.1"},
		{Key: OptPeerUnit, Kind: client.OptInt, Default: "-1", Help: "remote tun unit to request (default: any)"},
		{Key: OptDNS, Kind: client.OptCommaList, Help: "comma-separated DNS servers"},
		{Key: OptTUNName, Kind: client.OptStr, Help: "TUN interface name (empty = kernel picks)"},
	})
}
