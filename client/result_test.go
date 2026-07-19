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
}
