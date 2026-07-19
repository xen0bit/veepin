package toy

import (
	"testing"

	"github.com/xen0bit/veepin/dataplane"
	itoy "github.com/xen0bit/veepin/internal/toy"
)

// TOY's MTU is derived from its own wire format, so the arithmetic is checked
// against the sizes it depends on rather than against a copied literal. A test
// that just restated 1452 would pass for the wrong reason if the header grew.
func TestDefaultMTULeavesRoomForEveryHeader(t *testing.T) {
	const path = dataplane.DefaultPathMTU

	// A full-size inner packet, once encapsulated, must still fit the path.
	onWire := defaultMTU + itoy.Overhead + dataplane.OuterUDP4
	if onWire != path {
		t.Errorf("a %d-octet inner packet occupies %d octets on a %d-octet path; "+
			"the MTU wastes %d octets or overflows by %d",
			defaultMTU, onWire, path, path-onWire, onWire-path)
	}

	// And it must be the exact figure, not merely a safe one: an MTU that fits
	// but is needlessly small costs throughput on every packet, forever.
	if defaultMTU != 1452 {
		t.Errorf("defaultMTU = %d, want 1452", defaultMTU)
	}
}
