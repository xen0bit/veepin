package anyconnect

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// tunIO is the userspace TUN the data path reads IP from and writes IP to.
// *dataplane.TUN satisfies it; tests supply a fake.
type tunIO interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
}

// maxAuthRounds bounds the credential exchange. Servers differ in how many forms
// they present — one asking for username and password together, or two in
// sequence — so the client loops, and this stops a server that keeps re-asking
// from looping forever.
const maxAuthRounds = 8

// ClientConfig configures the AnyConnect client engine.
type ClientConfig struct {
	// Host is the server as it appears in the Host header and TLS SNI, without a
	// port unless it is non-standard.
	Host string
	// Hostname is the local name reported to the server, which shows it in its
	// session list. Cosmetic.
	Hostname string
	Username string
	Password string
	// BaseMTU is the path MTU the client reports; the server's reply may lower it.
	BaseMTU int
	Logger  *log.Logger
}

// Client is a running AnyConnect tunnel over one TLS connection: it
// authenticates, issues CONNECT, and then moves IP packets between the TUN and
// the CSTP data channel.
type Client struct {
	cfg    ClientConfig
	conn   net.Conn
	br     *bufio.Reader
	tun    tunIO
	logger *log.Logger

	// writeMu serializes writes: the TUN pump, the keepalive timer and DPD
	// replies all send on the same connection.
	writeMu sync.Mutex

	mu       sync.Mutex
	closed   bool
	closeErr error
	done     chan struct{}
}

// NewClient builds a client over an established TLS connection and a TUN. The
// connection must already be authenticated at the TLS layer; this drives the
// HTTP exchange on top of it.
func NewClient(conn net.Conn, tun tunIO, cfg ClientConfig) *Client {
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	return &Client{
		cfg:    cfg,
		conn:   conn,
		br:     bufio.NewReaderSize(conn, maxPayload+headerLen),
		tun:    tun,
		logger: logger,
		done:   make(chan struct{}),
	}
}

// Handshake authenticates and opens the tunnel, returning the addressing the
// server assigned. It does not start the data path; call Run for that.
func (c *Client) Handshake() (TunnelConfig, error) {
	cookie, err := c.authenticate()
	if err != nil {
		return TunnelConfig{}, err
	}
	c.logger.Printf("anyconnect: authenticated as %s", c.cfg.Username)
	return c.connect(cookie)
}

// authenticate runs the XML credential exchange and returns the session cookie.
func (c *Client) authenticate() (string, error) {
	msg := initMessage()
	for round := range maxAuthRounds {
		path := "/"
		if round > 0 {
			path = authPath
		}
		resp, body, err := c.postXML(path, msg)
		if err != nil {
			return "", err
		}
		reply, err := parseConfigAuth(body)
		if err != nil {
			return "", err
		}
		switch reply.Type {
		case "complete":
			if cookie := sessionCookieFrom(resp, reply); cookie != "" {
				return cookie, nil
			}
			return "", errors.New("anyconnect: server completed authentication without a session cookie")
		case "auth-request":
			if reply.Auth.Error != "" {
				return "", fmt.Errorf("anyconnect: authentication rejected: %s", reply.Auth.Error)
			}
			if reply.Auth.Form == nil || len(reply.Auth.Form.Inputs) == 0 {
				return "", errors.New("anyconnect: server asked for credentials but presented no form")
			}
			msg = answerForm(reply.Auth.Form, c.cfg.Username, c.cfg.Password)
		default:
			return "", fmt.Errorf("anyconnect: unexpected auth message type %q", reply.Type)
		}
	}
	return "", fmt.Errorf("anyconnect: authentication did not complete in %d rounds", maxAuthRounds)
}

// sessionCookieFrom finds the session token, which servers deliver either as a
// Set-Cookie header or in the completion message's session-token element.
func sessionCookieFrom(resp *http.Response, reply configAuth) string {
	for _, ck := range resp.Cookies() {
		if ck.Name == sessionCookie && ck.Value != "" {
			return ck.Value
		}
	}
	return reply.SessionToken
}

// postXML sends one message of the authentication exchange and reads its reply.
func (c *Client) postXML(path string, msg configAuth) (*http.Response, []byte, error) {
	body, err := marshalConfigAuth(msg)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequest(http.MethodPost, "https://"+c.cfg.Host+path, bytes.NewReader(body))
	if err != nil {
		return nil, nil, fmt.Errorf("anyconnect: build %s request: %w", msg.Type, err)
	}
	req.Host = c.cfg.Host
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ContentLength = int64(len(body))

	if err := req.Write(c.conn); err != nil {
		return nil, nil, fmt.Errorf("anyconnect: send %s: %w", msg.Type, err)
	}
	resp, err := http.ReadResponse(c.br, req)
	if err != nil {
		return nil, nil, fmt.Errorf("anyconnect: read %s reply: %w", msg.Type, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("anyconnect: read %s body: %w", msg.Type, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("anyconnect: %s returned %s", msg.Type, resp.Status)
	}
	return resp, respBody, nil
}

// connect issues the CONNECT that converts the connection into a tunnel.
func (c *Client) connect(cookie string) (TunnelConfig, error) {
	baseMTU := c.cfg.BaseMTU
	if baseMTU == 0 {
		baseMTU = defaultMTU
	}
	hostname := c.cfg.Hostname
	if hostname == "" {
		hostname = "veepin"
	}
	req, err := buildConnectRequest(c.cfg.Host, cookie, hostname, baseMTU)
	if err != nil {
		return TunnelConfig{}, err
	}
	if err := req.Write(c.conn); err != nil {
		return TunnelConfig{}, fmt.Errorf("anyconnect: send CONNECT: %w", err)
	}
	resp, err := http.ReadResponse(c.br, req)
	if err != nil {
		return TunnelConfig{}, fmt.Errorf("anyconnect: read CONNECT reply: %w", err)
	}
	// A CONNECT response has no body to consume — the connection becomes the
	// tunnel — so the body is closed without reading.
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return TunnelConfig{}, fmt.Errorf("anyconnect: CONNECT refused: %s", resp.Status)
	}
	cfg, err := parseTunnelConfig(resp.Header)
	if err != nil {
		return TunnelConfig{}, err
	}
	c.logger.Printf("anyconnect: tunnel up, address %s netmask %s mtu %d", cfg.Address, cfg.Netmask, cfg.MTU)
	return cfg, nil
}

// Run moves packets until the tunnel closes. It blocks.
func (c *Client) Run(keepalive time.Duration) error {
	go c.tunLoop()
	if keepalive > 0 {
		go c.keepaliveLoop(keepalive)
	}
	c.readLoop()
	<-c.done
	return c.closeErr
}

// readLoop reads CSTP packets and dispatches them.
func (c *Client) readLoop() {
	for {
		typ, payload, err := readPacket(c.br)
		if err != nil {
			c.fail(fmt.Errorf("anyconnect: read: %w", err))
			return
		}
		switch typ {
		case typeData:
			if _, err := c.tun.Write(payload); err != nil {
				c.fail(fmt.Errorf("anyconnect: TUN write: %w", err))
				return
			}
		case typeDPDReq:
			// A DPD probe must be echoed with its payload intact, which is also how
			// the peer measures path MTU.
			if err := c.send(typeDPDResp, payload); err != nil {
				c.fail(err)
				return
			}
		case typeDPDResp, typeKeepalive:
		case typeDisconnect, typeTerminate:
			c.fail(fmt.Errorf("anyconnect: server closed the session"))
			return
		case typeCompressed:
			c.fail(errors.New("anyconnect: server sent compressed data, which was not negotiated"))
			return
		}
	}
}

// tunLoop pumps IP packets from the TUN into the tunnel.
func (c *Client) tunLoop() {
	buf := make([]byte, maxPayload)
	for {
		n, err := c.tun.Read(buf)
		if err != nil {
			c.fail(fmt.Errorf("anyconnect: TUN read: %w", err))
			return
		}
		if err := c.send(typeData, buf[:n]); err != nil {
			c.fail(err)
			return
		}
	}
}

// keepaliveLoop holds the connection open through idle NAT timeouts.
func (c *Client) keepaliveLoop(every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if err := c.send(typeKeepalive, nil); err != nil {
				c.fail(err)
				return
			}
		case <-c.done:
			return
		}
	}
}

func (c *Client) send(typ byte, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if _, err := c.conn.Write(marshal(typ, payload)); err != nil {
		return fmt.Errorf("anyconnect: write: %w", err)
	}
	return nil
}

// Close tears the tunnel down, sending a DISCONNECT so the server can release
// the session rather than waiting for the connection to time out.
func (c *Client) Close() error {
	c.mu.Lock()
	already := c.closed
	c.mu.Unlock()
	if !already {
		_ = c.send(typeDisconnect, []byte{0})
	}
	c.fail(nil)
	return c.closeErr
}

// fail closes the client once, recording the first error to arrive.
func (c *Client) fail(err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.closeErr = err
	c.mu.Unlock()

	close(c.done)
	c.conn.Close()
}
