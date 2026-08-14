package softether

import (
	"sync"
	"testing"
)

// ethFrameTo builds a minimal Ethernet frame from src to dst.
func ethFrameTo(dst, src MACAddr) []byte {
	f := make([]byte, 64)
	copy(f[0:6], dst[:])
	copy(f[6:12], src[:])
	f[12], f[13] = 0x08, 0x00 // IPv4
	return f
}

// The finding this closes: the server opened a TAP, named it, closed it, and
// never read or wrote a frame through it. The switch forwarded between sessions
// only, so the host's own interface was not on the switch at all -- which is why
// every SoftEther interop cell was a dash, and why reading that as "not built
// yet" kept it hidden.
func TestAFrameFromAClientReachesTheLocalInterface(t *testing.T) {
	s := NewServer(nil, NewBridge(DefaultAgeTime), MACAddr{}, nil, nil)

	var mu sync.Mutex
	var got [][]byte
	local := s.AttachLocal(func(frame []byte) error {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, append([]byte(nil), frame...))
		return nil
	})

	// A frame arriving on some client port, addressed to a MAC the bridge has
	// not learned: it floods, and the local port must be one of the places it
	// floods to.
	clientPort := s.bridge.NewPort()
	frame := ethFrameTo(MACAddr{0x02, 0, 0, 0, 0, 0x02}, MACAddr{0x02, 0, 0, 0, 0, 0x01})
	parsed, ok := ParseFrame(frame)
	if !ok {
		t.Fatal("test frame does not parse")
	}
	dests := s.bridge.Forward(parsed, clientPort).Destinations
	if dests == nil {
		dests = s.bridge.FloodPorts(clientPort)
	}
	s.deliver(dests, frame, clientPort)

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("the local interface received %d frames, want 1 — the host is not on the switch", len(got))
	}
	_ = local
}

// A switch never sends a frame back out the port it arrived on, and the local
// port is an ordinary port in that respect too. Without the exclusion, every
// frame the host sends is handed straight back to it.
func TestAFrameFromTheLocalInterfaceIsNotEchoedToIt(t *testing.T) {
	s := NewServer(nil, NewBridge(DefaultAgeTime), MACAddr{}, nil, nil)

	var mu sync.Mutex
	echoed := 0
	s.AttachLocal(func([]byte) error {
		mu.Lock()
		defer mu.Unlock()
		echoed++
		return nil
	})
	// Another port, so the flood has somewhere to go and the test is not
	// passing because there were no destinations at all.
	s.bridge.NewPort()

	s.InjectLocal(ethFrameTo(MACAddr{0x02, 0, 0, 0, 0, 0x02}, MACAddr{0x02, 0, 0, 0, 0, 0x01}))

	mu.Lock()
	defer mu.Unlock()
	if echoed != 0 {
		t.Errorf("the local interface got its own frame back %d times", echoed)
	}
}

// The bridge learns the host's MAC from a frame it injects, so a later frame
// addressed to it is forwarded rather than flooded. That is what makes the
// server's segment a real switch port and not a broadcast sink.
func TestInjectingLearnsTheLocalInterfacesMAC(t *testing.T) {
	s := NewServer(nil, NewBridge(DefaultAgeTime), MACAddr{}, nil, nil)
	local := s.AttachLocal(func([]byte) error { return nil })

	host := MACAddr{0x02, 0, 0, 0, 0, 0x01}
	s.InjectLocal(ethFrameTo(MACAddr{0x02, 0, 0, 0, 0, 0x02}, host))

	if got := s.bridge.Lookup(host); got != local {
		t.Errorf("the bridge resolved the host's MAC to port %d, want the local port %d", got, local)
	}
}

// Detaching must take the port out of the switch, so frames stop being handed
// to a writer whose device is closing.
func TestDetachLocalTakesTheHostOffTheSwitch(t *testing.T) {
	s := NewServer(nil, NewBridge(DefaultAgeTime), MACAddr{}, nil, nil)
	delivered := 0
	local := s.AttachLocal(func([]byte) error { delivered++; return nil })
	s.DetachLocal()

	clientPort := s.bridge.NewPort()
	frame := ethFrameTo(MACAddr{0x02, 0, 0, 0, 0, 0x02}, MACAddr{0x02, 0, 0, 0, 0, 0x01})
	s.deliver([]PortID{local}, frame, clientPort)

	if delivered != 0 {
		t.Errorf("a detached local interface still received %d frames", delivered)
	}
}
