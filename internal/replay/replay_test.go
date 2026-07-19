package replay

import "testing"

func TestAcceptsInOrder(t *testing.T) {
	w := New()
	for i := uint64(1); i <= 100; i++ {
		if !w.Accept(i) {
			t.Fatalf("counter %d was rejected", i)
		}
	}
	if w.Highest() != 100 {
		t.Errorf("Highest = %d, want 100", w.Highest())
	}
}

func TestRejectsDuplicates(t *testing.T) {
	w := New()
	if !w.Accept(5) {
		t.Fatal("first delivery rejected")
	}
	if w.Accept(5) {
		t.Error("accepted an immediate duplicate")
	}
}

// UDP reorders, so packets arriving late but inside the window must still be
// accepted; a strictly-increasing check would drop real traffic.
func TestAcceptsOutOfOrderWithinWindow(t *testing.T) {
	w := New()
	if !w.Accept(50) {
		t.Fatal("newest packet rejected")
	}
	for i := uint64(1); i < 50; i++ {
		if !w.Accept(i) {
			t.Errorf("late counter %d was rejected", i)
		}
	}
	for i := uint64(1); i < 50; i++ {
		if w.Accept(i) {
			t.Errorf("counter %d was accepted twice", i)
		}
	}
}

func TestRejectsTooOld(t *testing.T) {
	w := New()
	if !w.Accept(Size * 4) {
		t.Fatal("a far-ahead counter was rejected")
	}
	if w.Accept(1) {
		t.Error("accepted a counter far outside the window")
	}
}

// The step this package exists to get right: after the window slides, slots it
// passed over must be clear, or a counter that never arrived is mistaken for one
// that did once the counter space wraps the bitmap.
func TestSlotsAreClearedAsTheWindowSlides(t *testing.T) {
	w := NewSize(64)

	if !w.Accept(1) {
		t.Fatal("counter 1 rejected")
	}
	// Jump forward by exactly one window, so counter 65 maps to the same slot
	// counter 1 used.
	if !w.Accept(65) {
		t.Fatal("counter 65 rejected")
	}
	// 64 was never seen and is still inside the window; it must be accepted.
	if !w.Accept(64) {
		t.Error("a counter that never arrived was treated as already seen")
	}
	// 65 itself is a genuine duplicate.
	if w.Accept(65) {
		t.Error("accepted a duplicate of the highest counter")
	}
}

// A jump larger than the whole window clears everything, so nothing stale
// survives from before it.
func TestLargeJumpClearsTheWindow(t *testing.T) {
	w := NewSize(64)
	for i := uint64(1); i <= 64; i++ {
		w.Accept(i)
	}
	if !w.Accept(10_000) {
		t.Fatal("a far-ahead counter was rejected")
	}
	// Inside the new window, previously unseen: must be accepted rather than
	// blocked by a stale bit from the old one.
	if !w.Accept(9_990) {
		t.Error("a stale bit survived a window-clearing jump")
	}
}

func TestMarkSeen(t *testing.T) {
	w := New()
	w.MarkSeen(2)
	if w.Accept(1) || w.Accept(2) {
		t.Error("a counter consumed by the handshake was accepted as data")
	}
	if !w.Accept(3) {
		t.Error("the first data counter was rejected")
	}
}
