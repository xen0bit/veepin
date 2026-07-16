package wireguard

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/xen0bit/veepin/internal/wireguard/noise"
)

// TestClientRekeyDispatch drives the rekey handshake path. Unlike the initial
// handshake, which reads the socket directly, a rekey runs while readLoop owns
// the socket: doHandshake registers a pending handshake and sends an initiation,
// and readLoop must recognise the responder's reply as a handshake response and
// hand it back by receiver index. A completed keypair proves that setPending →
// deliverResponse → doHandshake handoff, which is the new client machinery.
func TestClientRekeyDispatch(t *testing.T) {
	var clientPriv, serverPriv [32]byte
	for i := range clientPriv {
		clientPriv[i] = byte(i + 1)
		serverPriv[i] = byte(i + 100)
	}
	serverPub, err := noise.PublicKey(serverPriv)
	if err != nil {
		t.Fatal(err)
	}
	clientPub, err := noise.PublicKey(clientPriv)
	if err != nil {
		t.Fatal(err)
	}

	// A real responder for one initiation: it completes the handshake so the
	// reply actually decrypts, which is what makes doHandshake's Consume succeed.
	serverKP := make(chan *noise.Keypair, 1)
	handleErr := make(chan error, 1)
	fail := func(err error) []byte {
		select {
		case handleErr <- err:
		default:
		}
		return nil
	}
	addr, _ := udpResponder(t, func(req []byte) []byte {
		r, err := noise.NewResponder(serverPriv)
		if err != nil {
			return fail(err)
		}
		peerStatic, _, err := r.Consume(req)
		if err != nil {
			return fail(err)
		}
		if peerStatic != clientPub {
			return fail(fmt.Errorf("peer static mismatch"))
		}
		resp, kp, err := r.Response([32]byte{}) // no PSK
		if err != nil {
			return fail(err)
		}
		serverKP <- kp
		return resp
	})

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	s := &session{
		conn:     conn,
		logger:   discardLogger(),
		noiseCfg: noise.Config{LocalStatic: clientPriv, RemoteStatic: serverPub},
		done:     make(chan struct{}),
		stop:     make(chan struct{}),
	}
	go s.readLoop()
	t.Cleanup(func() {
		conn.Close() // unblocks readLoop
		<-s.done
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	kp, err := s.doHandshake(ctx)
	if err != nil {
		t.Fatalf("doHandshake via readLoop dispatch: %v", err)
	}

	select {
	case err := <-handleErr:
		t.Fatalf("responder: %v", err)
	default:
	}

	// The two keypairs must be reciprocal: our sender index is what the peer
	// addresses us by, and vice versa — the property the pump relies on to demux.
	sk := <-serverKP
	if kp.Local != sk.Remote || kp.Remote != sk.Local {
		t.Errorf("indices not paired: client{L:%#x R:%#x} server{L:%#x R:%#x}",
			kp.Local, kp.Remote, sk.Local, sk.Remote)
	}
	if kp.Send != sk.Recv || kp.Recv != sk.Send {
		t.Error("transport keys not reciprocal across the handshake")
	}
}
