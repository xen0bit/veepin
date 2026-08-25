package nebula

// The server role.
//
// Nebula has no server in the sense the other protocols here use the word. What
// `veepin serve nebula` runs is a lighthouse: an ordinary mesh member, with an
// ordinary certificate, that additionally answers questions about where other
// members are and helps two NATed hosts punch towards each other.
//
// So this is the same engine Dial runs, with AmLighthouse set. It is a separate
// entry point because the lifecycle differs — a lighthouse is expected to stay
// up at a stable address, and it is the one host in a mesh that usually needs to
// be directly reachable.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/xen0bit/veepin/client"
)

func init() {
	client.RegisterServer("nebula", parseServerOptions)
	client.RegisterServerOpts("nebula", []client.OptSpec{
		{Key: OptCA, Kind: client.OptFilePath, Required: true, Help: "path to the CA certificate bundle"},
		{Key: OptCert, Kind: client.OptFilePath, Required: true, Help: "path to this lighthouse's certificate"},
		{Key: OptKey, Kind: client.OptFilePath, Required: true, Secret: true, Help: "path to this lighthouse's X25519 private key"},
		{Key: OptListen, Kind: client.OptStr, Default: ":4242", Help: "local UDP address to bind (default :4242)"},
		{Key: OptStaticHosts, Kind: client.OptStr, Help: "peer locations: 10.42.0.1=192.0.2.10:4242[,...];..."},
		{Key: OptCipher, Kind: client.OptStr, Help: "aes (default) or chachapoly; must match the mesh"},
		{Key: OptMTU, Kind: client.OptInt, Default: "1300", Help: "inner MTU (default 1300)"},
		{Key: OptShape, Kind: client.OptInt, Default: "0", Help: "per-flow shaping budget in bytes for traffic this host sends; pads inside the AEAD (0 = off)"},
		client.TUNOpt(OptTUN),
	})
}

// ServerConfig configures a lighthouse.
type ServerConfig struct {
	Config
}

// Server is a running lighthouse.
type Server struct {
	cfg  ServerConfig
	sess *Session

	mu      sync.Mutex
	started bool
	closed  bool
	done    chan struct{}
}

// NewServer prepares a lighthouse. Nothing binds until ListenAndServe.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.CAPath == "" || cfg.CertPath == "" || cfg.KeyPath == "" {
		return nil, errors.New("nebula: ca, cert and key are all required")
	}
	// A lighthouse that does not answer queries is just a host, and would
	// silently fail to do the one job it was started for.
	cfg.AmLighthouse = true
	return &Server{cfg: cfg, done: make(chan struct{})}, nil
}

// ListenAndServe runs the lighthouse until it is closed.
func (s *Server) ListenAndServe() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	if s.started {
		s.mu.Unlock()
		return errors.New("nebula: server already started")
	}
	s.started = true
	s.mu.Unlock()

	sess, _, err := Dial(context.Background(), s.cfg.Config)
	if err != nil {
		return err
	}

	s.mu.Lock()
	if s.closed {
		// Close raced ahead of the bind; do not leave the host running.
		s.mu.Unlock()
		return sess.Close()
	}
	s.sess = sess
	s.mu.Unlock()

	<-s.done
	return sess.Close()
}

// Close stops the lighthouse.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.done)
	s.mu.Unlock()
	return nil
}

// Abandon implements client.AbandonableServer. Nebula is the one server here
// that owns no TUN of its own: the lighthouse runs as a host, and the TUN
// belongs to the Session that ListenAndServe dials. So this reaches through the
// session to the same descriptor every other facade closes directly.
//
// It takes s.mu, which the rest of this file's contract permits: nothing holds
// this mutex across a blocking call. Close latches a flag and closes a channel
// under it, and the teardown that can block -- sess.Close in ListenAndServe --
// runs holding nothing.
func (s *Server) Abandon() {
	s.mu.Lock()
	sess := s.sess
	s.mu.Unlock()
	if sess != nil && sess.tun != nil {
		sess.tun.Close()
	}
}

// Server implements client.AbandonableServer, so the supervisor can take its
// descriptors back when Close overruns. Asserted here because the interface is
// found by type assertion at the one call site: without this, a renamed or
// re-signatured Abandon compiles fine and the assertion silently starts failing,
// which reads as the leak coming back.
var _ client.AbandonableServer = (*Server)(nil)

// TUNName is the interface the lighthouse is bound to.
func (s *Server) TUNName() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sess == nil {
		return ""
	}
	return s.sess.tun.Name()
}

// Gateway is the lighthouse's own overlay address.
//
// A mesh has no gateway: peers reach each other directly, and nothing routes
// through the lighthouse. This reports its own address so callers that anchor
// an interface on it get something coherent.
func (s *Server) Gateway() net.IP {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sess == nil {
		return nil
	}
	return net.IP(s.sess.Addr().AsSlice())
}

// Network is the overlay subnet, taken from the lighthouse's certificate rather
// than from configuration -- in nebula the CA decides it.
func (s *Server) Network() *net.IPNet {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sess == nil {
		return nil
	}
	addr := s.sess.Addr()
	return &net.IPNet{
		IP:   net.IP(addr.AsSlice()).Mask(net.CIDRMask(s.prefixBits(), 32)),
		Mask: net.CIDRMask(s.prefixBits(), 32),
	}
}

// prefixBits is the overlay prefix length from the certificate.
func (s *Server) prefixBits() int {
	if s.sess == nil {
		return 32
	}
	return s.sess.host.OverlayBits()
}

// parseServerOptions turns registry options into a Server.
func parseServerOptions(opts map[string]string) (client.Server, error) {
	d, err := parseOptions(opts)
	if err != nil {
		return nil, err
	}
	cfg := d.(dialer).cfg

	if v := opts[OptListen]; v == "" {
		// A lighthouse has to be findable, so default it to the well-known port
		// explicitly rather than leaving it to chance.
		cfg.Listen = ":" + strconv.Itoa(defaultPort)
	}

	srv, err := NewServer(ServerConfig{Config: cfg})
	if err != nil {
		return nil, fmt.Errorf("nebula: %w", err)
	}
	return srv, nil
}
