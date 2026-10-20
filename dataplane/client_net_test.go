package dataplane

import (
	"net"
	"testing"
)

// TestFullTunnelBlocksTheFamilyItCarriesNoAddressIn: a full tunnel assigned
// only IPv4 used to leave IPv6 on the physical link, so a dual-stack host sent
// every IPv6 flow in the clear while reporting full-tunnel=true. If this
// fails, that leak is back.
func TestFullTunnelBlocksTheFamilyItCarriesNoAddressIn(t *testing.T) {
	v4, v6 := net.IPv4(10, 0, 0, 2), net.ParseIP("fd00::2")
	cases := []struct {
		name           string
		cfg            ClientNetConfig
		hostV6         bool
		block4, block6 bool
	}{
		{"v4-only tunnel, dual-stack host", ClientNetConfig{FullTunnel: true, AssignedIP: v4}, true, false, true},
		{"v4-only tunnel, host without IPv6", ClientNetConfig{FullTunnel: true, AssignedIP: v4}, false, false, false},
		{"v6-only tunnel", ClientNetConfig{FullTunnel: true, AssignedIP6: v6}, true, true, false},
		{"dual-stack tunnel", ClientNetConfig{FullTunnel: true, AssignedIP: v4, AssignedIP6: v6}, true, false, false},
		{"split tunnel", ClientNetConfig{AssignedIP: v4}, true, false, false},
		{"opted out", ClientNetConfig{FullTunnel: true, AssignedIP: v4, AllowUnroutedFamily: true}, true, false, false},
	}
	for _, tc := range cases {
		b4, b6 := unroutedFamilies(tc.cfg, tc.hostV6)
		if b4 != tc.block4 || b6 != tc.block6 {
			t.Errorf("%s: got block4=%v block6=%v, want %v %v", tc.name, b4, b6, tc.block4, tc.block6)
		}
	}
}
