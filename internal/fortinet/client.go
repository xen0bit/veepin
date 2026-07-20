package fortinet

// The client engine: the HTTPS login, then the framed PPP data path.
//
// Login is ordinary HTTP over the caller's TLS-configured http.Client (with a
// cookie jar, so the SVPNCOOKIE flows from the login to the config fetch). The
// data path is separate: the caller opens a fresh TLS connection, sends the
// tunnel GET, and hands the raw connection here, where PPP runs over the 6-octet
// framing until the link carries IP.

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/xen0bit/veepin/internal/mschap"
	"github.com/xen0bit/veepin/internal/ppp"
)

// ErrAuth reports rejected credentials, so a caller can tell a bad password from
// a transport failure.
var ErrAuth = errors.New("fortinet: authentication failed")

// networkUpTimeout bounds how long the data path waits for IPCP to bring the
// link up before giving up.
const networkUpTimeout = 20 * time.Second

// Login performs the /remote/logincheck exchange and fetches the tunnel config.
// hc must carry a cookie jar so the SVPNCOOKIE it receives is sent on the config
// fetch. base is the server's https:// origin. It returns the parsed config and
// the SVPNCOOKIE value, which the caller puts on the tunnel request.
func Login(hc *http.Client, base, username, password, realm string) (Config, string, error) {
	form := BuildLoginForm(username, password, realm)
	resp, err := hc.Post(base+PathLoginCheck, "application/x-www-form-urlencoded", strings.NewReader(form))
	if err != nil {
		return Config{}, "", fmt.Errorf("fortinet: login request: %w", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	result, err := ParseLoginResult(string(body))
	if err != nil {
		return Config{}, "", err
	}
	if result.Ret != 1 {
		return Config{}, "", fmt.Errorf("%w: login returned ret=%d", ErrAuth, result.Ret)
	}

	cookie := cookieValue(hc, base)
	if cookie == "" {
		return Config{}, "", fmt.Errorf("fortinet: server issued no %s", CookieName)
	}

	redir := result.Redir
	if redir == "" {
		redir = PathConfigXML
	}
	cfgResp, err := hc.Get(base + redir)
	if err != nil {
		return Config{}, "", fmt.Errorf("fortinet: config request: %w", err)
	}
	cfgBody, _ := io.ReadAll(cfgResp.Body)
	_ = cfgResp.Body.Close()

	cfg, err := ParseConfigXML(cfgBody)
	if err != nil {
		return Config{}, "", err
	}
	return cfg, cookie, nil
}

// TunnelRequest is the raw HTTP request that turns a fresh TLS connection into
// the framed PPP tunnel. The caller writes it, then hands the connection to
// RunClient; no HTTP response follows on success (the server begins framing PPP
// immediately), which is why this is written by hand rather than through
// net/http.
func TunnelRequest(host, cookie string) []byte {
	return []byte("GET " + PathTunnel + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: Mozilla/5.0 SV1\r\n" +
		"Cookie: " + CookieName + "=" + cookie + "\r\n" +
		"\r\n")
}

// Client is an established Fortinet tunnel.
type Client struct {
	link *pppLink
	cfg  Config
}

// AssignedConfig is the tunnel configuration the login returned.
func (c *Client) AssignedConfig() Config { return c.cfg }

// RunClient drives PPP over the tunnel connection and binds it to tun. conn must
// already have had the tunnel GET written to it. cfg is the configuration from
// Login, used for the returned Result; the link itself confirms the address over
// IPCP.
func RunClient(conn net.Conn, cfg Config, tun io.ReadWriteCloser, logger *log.Logger) (*Client, error) {
	return runClient(conn, cfg, tun, logger, false)
}

// RunDTLSClient is RunClient over the UDP data channel: conn is the established
// DTLS session from DialDTLS, which has already presented the cookie, and each
// datagram carries exactly one framed record.
func RunDTLSClient(conn net.Conn, cfg Config, tun io.ReadWriteCloser, logger *log.Logger) (*Client, error) {
	return runClient(conn, cfg, tun, logger, true)
}

func runClient(conn net.Conn, cfg Config, tun io.ReadWriteCloser, logger *log.Logger, datagram bool) (*Client, error) {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	h := &clientHandler{ready: make(chan struct{}), closed: make(chan error, 1)}

	// The link is the PPP transport, so it is built first; the session is created
	// with it and then registered back on the link for inbound control frames.
	// No PPP-level credentials: the SVPNCOOKIE already authenticated, so the
	// server will not request authentication and the link goes LCP->IPCP.
	link := &pppLink{conn: conn, tun: tun, ownsTUN: true, datagram: datagram, logger: logger, done: make(chan struct{})}
	sess := ppp.New("", "", link, h)
	link.client = sess

	go link.readLoop()
	sess.Start()

	select {
	case <-h.ready:
		go link.tunLoop()
		logger.Printf("fortinet: tunnel up, assigned %s", cfg.AssignedIP)
		return &Client{link: link, cfg: cfg}, nil
	case err := <-h.closed:
		_ = link.Close()
		return nil, fmt.Errorf("fortinet: link closed during setup: %w", err)
	case <-time.After(networkUpTimeout):
		_ = link.Close()
		return nil, fmt.Errorf("fortinet: timed out waiting for the link to come up")
	}
}

// AttachDTLS adds an established DTLS session to a running tunnel and makes it
// the egress, which is how a real client uses the UDP channel: the TLS tunnel
// stays open as the fallback, and losing UDP costs a detach rather than the
// tunnel. conn comes from DialDTLS, which has already presented the cookie.
func (c *Client) AttachDTLS(conn net.Conn) { c.link.attachDTLS(conn) }

// Wait blocks until the tunnel stops.
func (c *Client) Wait() error { return c.link.Wait() }

// Close tears the tunnel down.
func (c *Client) Close() error { return c.link.Close() }

// clientHandler bridges PPP lifecycle events to the setup handshake.
type clientHandler struct {
	ready  chan struct{}
	closed chan error
	cfg    ppp.IPConfig
	once   sync.Once
}

func (h *clientHandler) Authenticated(_ [mschap.NTResponseLen]byte) {}
func (h *clientHandler) NetworkUp(cfg ppp.IPConfig) {
	h.cfg = cfg
	h.once.Do(func() { close(h.ready) })
}
func (h *clientHandler) Closed(err error) {
	select {
	case h.closed <- err:
	default:
	}
}

// cookieValue pulls the SVPNCOOKIE out of the client's jar for the server URL.
func cookieValue(hc *http.Client, base string) string {
	if hc.Jar == nil {
		return ""
	}
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}
	for _, c := range hc.Jar.Cookies(u) {
		if c.Name == CookieName {
			return c.Value
		}
	}
	return ""
}
