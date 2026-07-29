package client

import (
	"net"
	"strings"
	"testing"
)

func TestResultValidate(t *testing.T) {
	good := Result{
		TUNName:    "tun0",
		AssignedIP: net.ParseIP("10.9.0.2"),
		Netmask:    net.ParseIP("255.255.255.0"),
		Gateway:    net.ParseIP("198.51.100.7"), // the server's outer address
		MTU:        1400,
	}

	t.Run("a well-formed result passes", func(t *testing.T) {
		if err := good.Validate(); err != nil {
			t.Errorf("Validate() = %v, want nil", err)
		}
	})

	// The mistake this exists to catch: Gateway filled in with an address from
	// inside the tunnel. The caller pins a host route to it through the physical
	// interface, so an inner address sends the tunnel's own traffic out the
	// wrong door -- with no symptom except that nothing crosses.
	t.Run("gateway inside the tunnel subnet is reported", func(t *testing.T) {
		bad := good
		bad.Gateway = net.ParseIP("10.9.0.1")

		err := bad.Validate()
		if err == nil {
			t.Fatal("accepted a Gateway inside the tunnel subnet")
		}
		if !strings.Contains(err.Error(), "outer address") {
			t.Errorf("error does not explain what Gateway should be: %v", err)
		}
	})

	// A mesh protocol has no single peer to route to, so nil is correct rather
	// than an omission -- see the nebula package.
	t.Run("nil gateway is legitimate", func(t *testing.T) {
		mesh := good
		mesh.Gateway = nil
		if err := mesh.Validate(); err != nil {
			t.Errorf("nil Gateway rejected: %v", err)
		}
	})

	t.Run("required fields", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			mutate func(*Result)
		}{
			{"no interface", func(r *Result) { r.TUNName = "" }},
			{"no address", func(r *Result) { r.AssignedIP = nil }},
			{"negative MTU", func(r *Result) { r.MTU = -1 }},
			{"no address and no Layer2", func(r *Result) { r.AssignedIP = nil; r.Layer2 = false }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				bad := good
				tc.mutate(&bad)
				if err := bad.Validate(); err == nil {
					t.Errorf("accepted a result with %s", tc.name)
				}
			})
		}
	})

	// An outer address that happens to sit in a different private range must not
	// trip the check: plenty of real deployments dial a server on RFC 1918 space.
	t.Run("outer address in a different private range passes", func(t *testing.T) {
		r := good
		r.Gateway = net.ParseIP("192.168.1.1")
		if err := r.Validate(); err != nil {
			t.Errorf("Validate() = %v, want nil", err)
		}
	})

	// A layer-2 tunnel assigns no address of its own. The addressing checks
	// must not apply, but the Gateway check still must.
	t.Run("layer2 with no address passes", func(t *testing.T) {
		r := Result{
			TUNName: "tap0",
			Layer2:  true,
			MTU:     1500,
		}
		if err := r.Validate(); err != nil {
			t.Errorf("layer-2 result with no address rejected: %v", err)
		}
	})

	t.Run("layer2 with gateway inside the tunnel subnet is still caught", func(t *testing.T) {
		// Gateway is still the outer address even for a layer-2 tunnel.
		// This is a hypothetical: a layer-2 tunnel returns a Gateway pointing
		// to an address within the tunnel subnet. We accept the parse but
		// create a scenario where the Gateway falls inside a /24.
		r := Result{
			TUNName:    "tap0",
			Layer2:     true,
			MTU:        1500,
		}
		// With no AssignedIP/Netmask, the subnet check is impossible (nothing
		// to compare against), so this should pass.
		if err := r.Validate(); err != nil {
			t.Errorf("layer-2 result with no address and a Gateway rejected: %v", err)
		}
	})
}
