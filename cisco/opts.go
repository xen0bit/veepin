package cisco

// Client option metadata for the Dial surface. The group name selects which
// pre-shared key authenticates phase 1; the per-user credentials follow in
// XAuth, mirroring the NetworkManager plugin's requireKeys/secretMissing split.

import "github.com/xen0bit/veepin/client"

func init() {
	client.RegisterClientOpts("cisco", []client.OptSpec{
		{Key: OptServer, Kind: client.OptStr, Required: true, Help: "IPsec gateway host or IP"},
		{Key: OptPort, Kind: client.OptInt, Default: "500", Help: "gateway IKE port (default 500)"},
		{Key: OptGroup, Kind: client.OptStr, Required: true, Help: "group name presented as the phase-1 identity"},
		{Key: OptGroupPSK, Kind: client.OptStr, Secret: true, Required: true, Help: "the group's pre-shared key"},
		{Key: OptUser, Kind: client.OptStr, Required: true, Help: "XAuth username"},
		{Key: OptPassword, Kind: client.OptStr, Secret: true, Help: "XAuth password"},
		{Key: OptShape, Kind: client.OptInt, Default: "0", Help: "per-flow outbound shaping budget in bytes (0 = off)"},
		{Key: OptTUN, Kind: client.OptStr, Help: "TUN interface name (empty = kernel picks)"},
	})
}
