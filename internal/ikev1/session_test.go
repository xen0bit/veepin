package ikev1

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// capture records the outcome of one session.
type capture struct {
	res  chan Result
	fail chan error
}

func newCapture() *capture {
	return &capture{res: make(chan Result, 1), fail: make(chan error, 1)}
}

func (c *capture) Established(r Result) { c.res <- r }
func (c *capture) Failed(err error)     { c.fail <- err }

func TestMainAndQuickModeSelfInterop(t *testing.T) {
	initCap := newCapture()
	respCap := newCapture()

	toResp := make(chan []byte, 32)
	toInit := make(chan []byte, 32)

	initiator := NewSession(Config{
		Role:    Initiator,
		PSK:     []byte("shared-secret"),
		LocalIP: net.IPv4(10, 0, 0, 2),
		PeerIP:  net.IPv4(10, 0, 0, 1),
		Send:    func(b []byte) error { toResp <- b; return nil },
		Handler: initCap,
	})
	responder := NewSession(Config{
		Role:    Responder,
		PSK:     []byte("shared-secret"),
		LocalIP: net.IPv4(10, 0, 0, 1),
		PeerIP:  net.IPv4(10, 0, 0, 2),
		Send:    func(b []byte) error { toInit <- b; return nil },
		Handler: respCap,
	})

	done := make(chan struct{})
	defer close(done)
	go pumpIKE(done, toResp, responder)
	go pumpIKE(done, toInit, initiator)

	initiator.Start()

	initRes := waitResult(t, "initiator", initCap)
	respRes := waitResult(t, "responder", respCap)

	// The two ends must mirror: each side's outbound SA is the other's inbound.
	if initRes.OutSPI != respRes.InSPI || initRes.InSPI != respRes.OutSPI {
		t.Errorf("SPI mismatch: init(out=%x,in=%x) resp(out=%x,in=%x)",
			initRes.OutSPI, initRes.InSPI, respRes.OutSPI, respRes.InSPI)
	}
	mirror(t, "enc  init.out/resp.in", initRes.OutEncKey, respRes.InEncKey)
	mirror(t, "integ init.out/resp.in", initRes.OutIntegKey, respRes.InIntegKey)
	mirror(t, "enc  init.in/resp.out", initRes.InEncKey, respRes.OutEncKey)
	mirror(t, "integ init.in/resp.out", initRes.InIntegKey, respRes.OutIntegKey)

	// The negotiated suite should be AES-256 + HMAC-SHA2-256 (first preference).
	if initRes.EncrID != espEncrAESCBC || initRes.EncrKeyLn != 256 || initRes.IntegID != espAuthHMACSHA256128 {
		t.Errorf("suite = (encr %d, keyLn %d, integ %d), want AES-256/SHA2-256",
			initRes.EncrID, initRes.EncrKeyLn, initRes.IntegID)
	}
	if len(initRes.OutEncKey) != 32 || len(initRes.OutIntegKey) != 32 {
		t.Errorf("key lengths = (enc %d, integ %d), want 32/32", len(initRes.OutEncKey), len(initRes.OutIntegKey))
	}
}

func mirror(t *testing.T, name string, a, b []byte) {
	t.Helper()
	if len(a) == 0 || !bytes.Equal(a, b) {
		t.Errorf("%s not mirrored: %x vs %x", name, a, b)
	}
}

func pumpIKE(done <-chan struct{}, in <-chan []byte, dst *Session) {
	for {
		select {
		case b := <-in:
			dst.HandleInbound(b)
		case <-done:
			return
		}
	}
}

func waitResult(t *testing.T, who string, c *capture) Result {
	t.Helper()
	select {
	case r := <-c.res:
		return r
	case err := <-c.fail:
		t.Fatalf("%s failed: %v", who, err)
	case <-time.After(3 * time.Second):
		t.Fatalf("%s timed out", who)
	}
	return Result{}
}
