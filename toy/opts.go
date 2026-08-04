package toy

// Client option metadata for the Dial surface. TOY is deliberately insecure;
// the secret is named and flagged so the form makes that impossible to miss.

import "github.com/xen0bit/veepin/client"

func init() {
	client.RegisterClientOpts("toy", []client.OptSpec{
		{Key: OptServer, Kind: client.OptStr, Required: true, Help: "TOY server host or IP"},
		{Key: OptPort, Kind: client.OptInt, Default: "5555", Help: "server UDP port (default 5555)"},
		{Key: OptUser, Kind: client.OptStr, Required: true, Help: "username"},
		{Key: OptSecret, Kind: client.OptStr, Secret: true, Required: true, Help: "shared secret; provides no real protection"},
		client.TUNOpt(OptTUN),
	})
}
