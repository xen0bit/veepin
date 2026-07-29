package main

import "testing"

// TestMaskBitsHandlesALayer2Server: a layer-2 server (L2TPv3) has no tunnel
// subnet, so Network() is nil. maskBits used to dereference it, which crashed
// `veepin serve l2tpv3` on startup before it ever bound a socket -- found by the
// interop cell, not by any unit test, which is the argument for the cell.
func TestMaskBitsHandlesALayer2Server(t *testing.T) {
	if got := maskBits(nil); got != 0 {
		t.Errorf("maskBits(nil) = %d, want 0", got)
	}
}
