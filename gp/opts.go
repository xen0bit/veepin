package gp

// Client option metadata for the Dial surface.

import "github.com/xen0bit/veepin/client"

func init() {
	client.RegisterClientOpts("gp", []client.OptSpec{
		{Key: OptServer, Kind: client.OptStr, Required: true, Help: "GlobalProtect gateway host or IP"},
		{Key: OptPort, Kind: client.OptInt, Default: "443", Help: "gateway HTTPS port (default 443)"},
		{Key: OptUser, Kind: client.OptStr, Required: true, Help: "username"},
		{Key: OptPassword, Kind: client.OptStr, Secret: true, Help: "password"},
		{Key: OptCA, Kind: client.OptFilePath, Help: "PEM bundle to verify the gateway against"},
		{Key: OptInsecure, Kind: client.OptBool, Help: "skip TLS certificate verification (self-signed gateways)"},
		{Key: OptNoESP, Kind: client.OptBool, Help: "stay on the SSL tunnel even where the gateway hands out ESP keys"},
		client.ShapeOpt(OptShape, "outbound"),
		client.TUNOpt(OptTUN),
	})
}
