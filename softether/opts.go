package softether

// Client option metadata for the Dial surface.

import "github.com/xen0bit/veepin/client"

func init() {
	client.RegisterClientOpts("softether", []client.OptSpec{
		{Key: OptServer, Kind: client.OptStr, Required: true, Help: "SoftEther VPN gateway host or IP"},
		{Key: OptPort, Kind: client.OptInt, Default: "443", Help: "gateway TLS port (default 443)"},
		{Key: OptUser, Kind: client.OptStr, Required: true, Help: "username"},
		{Key: OptPassword, Flag: "pass", Kind: client.OptStr, Secret: true, Help: "password"},
		{Key: OptHub, Kind: client.OptStr, Default: "VPN", Help: "virtual hub name (default VPN)"},
		{Key: OptInsecure, Kind: client.OptBool, Help: "skip gateway certificate verification (downgrades the transport to unauthenticated)"},
		{Key: OptTUN, Kind: client.OptStr, Help: "TAP interface name (empty = kernel picks)"},
		client.ShapeOpt(OptShape, "upstream"),
	})
}
