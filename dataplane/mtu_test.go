package dataplane

import "testing"

func TestInnerMTU(t *testing.T) {
	for _, tc := range []struct {
		name     string
		path     int
		overhead int
		want     int
	}{
		// The two derivations that protocols in this tree actually ship.
		{"wireguard over IPv6", DefaultPathMTU, OuterUDP6 + 32, 1420},
		{"toy over IPv4", DefaultPathMTU, OuterUDP4 + 20, 1452},

		// A path smaller than ethernet is the case ICMP fragmentation-needed
		// reports, and the whole point of deriving rather than asserting.
		{"PPPoE path", 1492, OuterUDP4 + 32, 1432},
		{"IPv6 minimum link", 1280, OuterUDP6 + 32, 1200},

		// Below the floor the answer is clamped rather than absurd.
		{"path smaller than the overhead", 40, 100, MinInnerMTU},
		{"just under the floor", OuterUDP4 + MinInnerMTU - 1, OuterUDP4, MinInnerMTU},
		{"exactly the floor", OuterUDP4 + MinInnerMTU, OuterUDP4, MinInnerMTU},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := InnerMTU(tc.path, tc.overhead); got != tc.want {
				t.Errorf("InnerMTU(%d, %d) = %d, want %d", tc.path, tc.overhead, got, tc.want)
			}
		})
	}
}

// The header sizes are what the derivations rest on. If one of these is wrong
// every MTU computed from it is wrong by the same amount, and the symptom is a
// black hole rather than a failed test -- so they are asserted directly.
func TestHeaderSizes(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  int
		want int
	}{
		{"IPv4 header without options", IPv4HeaderLen, 20},
		{"IPv6 fixed header", IPv6HeaderLen, 40},
		{"UDP header", UDPHeaderLen, 8},
		{"UDP over IPv4", OuterUDP4, 28},
		{"UDP over IPv6", OuterUDP6, 48},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.want)
			}
		})
	}
}
