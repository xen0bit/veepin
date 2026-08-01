package masque

// Client option metadata for the Dial surface.

import "github.com/xen0bit/veepin/client"

func init() {
	client.RegisterClientOpts("masque", []client.OptSpec{
		{Key: OptServer, Kind: client.OptStr, Required: true, Help: "MASQUE proxy host or IP"},
		{Key: OptPort, Kind: client.OptInt, Default: "443", Help: "proxy UDP port (default 443)"},
		{Key: OptAuthority, Kind: client.OptStr, Help: "HTTP :authority to present (default: server host)"},
		{Key: OptServerCA, Kind: client.OptFilePath, Help: "PEM bundle to verify the proxy against"},
		{Key: OptInsecure, Kind: client.OptBool, Help: "skip proxy certificate verification (self-signed proxies)"},
		{Key: OptTUN, Kind: client.OptStr, Help: "TUN interface name (empty = kernel picks)"},
	})
}
