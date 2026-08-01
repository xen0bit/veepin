package pulse

// Client option metadata for the Dial surface.

import "github.com/xen0bit/veepin/client"

func init() {
	client.RegisterClientOpts("pulse", []client.OptSpec{
		{Key: OptServer, Kind: client.OptStr, Required: true, Help: "Ivanti Connect Secure gateway host or IP"},
		{Key: OptPort, Kind: client.OptInt, Default: "443", Help: "gateway HTTPS port (default 443)"},
		{Key: OptPath, Kind: client.OptStr, Default: "/", Help: "request path the IF-T/TLS upgrade is sent to"},
		{Key: OptUser, Kind: client.OptStr, Required: true, Help: "username"},
		{Key: OptPassword, Kind: client.OptStr, Secret: true, Help: "password"},
		{Key: OptCA, Kind: client.OptFilePath, Help: "PEM bundle to verify the gateway against"},
		{Key: OptInsecure, Kind: client.OptBool, Help: "skip TLS certificate verification (self-signed gateways)"},
		{Key: OptNoESP, Kind: client.OptBool, Help: "stay on the IF-T/TLS data path even where the gateway hands out ESP keys"},
		{Key: OptShape, Kind: client.OptInt, Default: "0", Help: "per-flow outbound shaping budget in bytes (0 = off)"},
		{Key: OptTUN, Kind: client.OptStr, Help: "TUN interface name (empty = kernel picks)"},
	})
}
