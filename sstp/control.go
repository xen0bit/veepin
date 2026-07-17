package sstp

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"

	"github.com/xen0bit/veepin/internal/mschap"
	"github.com/xen0bit/veepin/internal/sstp/wire"
)

// httpConnect performs the HTTP CONNECT handshake over a TLS connection.
func httpConnect(conn io.ReadWriter, host string) error {
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", host, host)
	if _, err := io.WriteString(conn, req); err != nil {
		return fmt.Errorf("sstp: CONNECT write: %w", err)
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return fmt.Errorf("sstp: CONNECT response: %w", err)
	}
	if !strings.Contains(line, "200") {
		return fmt.Errorf("sstp: CONNECT rejected: %s", strings.TrimSpace(line))
	}
	for {
		line, err = br.ReadString('\n')
		if err != nil {
			return fmt.Errorf("sstp: CONNECT headers: %w", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	return nil
}

// sendCallConnectRequest sends SSTP_MSG_CALL_CONNECT_REQUEST. It carries only the
// Encapsulated Protocol ID attribute (PPP); the crypto-binding nonce is chosen by
// the server and returned in the Call Connect Ack, not requested here.
func sendCallConnectRequest(w io.Writer) error {
	attrs := []wire.Attribute{
		{ID: wire.AttrEncapsulatedProtocolID, Value: []byte{0x00, wire.ProtocolPPP}},
	}
	pkt, err := wire.EncodeControl(wire.MsgCallConnectRequest, attrs)
	if err != nil {
		return err
	}
	_, err = w.Write(pkt)
	return err
}

// readCallConnectAck reads the CallConnectAck response and returns the server's
// crypto-binding nonce. The nonce (MS-SSTP 2.2.3, Reserved(3) | HashBitmap(1) |
// Nonce(32)) is echoed back in the CallConnected message, so the client must use
// the server's value rather than generating its own.
func readCallConnectAck(r io.Reader) (nonce []byte, err error) {
	control, body, err := wire.ReadPacket(r)
	if err != nil {
		return nil, fmt.Errorf("read CallConnectAck: %w", err)
	}
	if !control {
		return nil, fmt.Errorf("expected a control packet")
	}
	msg, err := wire.ParseControl(body)
	if err != nil {
		return nil, fmt.Errorf("parse CallConnectAck: %w", err)
	}
	switch msg.Type {
	case wire.MsgCallConnectAck:
	case wire.MsgCallConnectNak:
		return nil, fmt.Errorf("server rejected the connection (CallConnectNak)")
	default:
		return nil, fmt.Errorf("unexpected response %#x", msg.Type)
	}

	cbr, ok := msg.Attribute(wire.AttrCryptoBindingReq)
	if !ok {
		return nil, fmt.Errorf("CallConnectAck missing the crypto-binding request")
	}
	if len(cbr.Value) < 4+wire.NonceLen {
		return nil, fmt.Errorf("%w: short crypto-binding request", wire.ErrMalformed)
	}
	if cbr.Value[3]&wire.CertHashSHA256 == 0 {
		return nil, fmt.Errorf("server does not offer SHA-256 crypto binding (bitmap %#x)", cbr.Value[3])
	}
	return append([]byte(nil), cbr.Value[4:4+wire.NonceLen]...), nil
}

// buildCallConnected builds a fully-formed SSTP_MSG_CALL_CONNECTED packet. The
// compound MAC covers the whole control message with its own MAC field zeroed, so
// the packet is built once with a zero MAC, the MAC is computed over the message
// body (everything after the 4-octet packet header), and its trailing bytes are
// patched in place.
func buildCallConnected(nonce, serverCertDER []byte, hlak [mschap.HLAKLen]byte) ([]byte, error) {
	cmk := DeriveCMK(hlak)
	certHash := sha256Sum(serverCertDER)

	val := BuildCBValue(nonce, certHash, make([]byte, wire.CompoundMACLen))
	pkt, err := wire.EncodeControl(wire.MsgCallConnected,
		[]wire.Attribute{{ID: wire.AttrCryptoBinding, Value: val}})
	if err != nil {
		return nil, err
	}

	mac := hmacSha256(cmk, pkt[wire.HeaderLen:])
	copy(pkt[len(pkt)-wire.CompoundMACLen:], mac)
	return pkt, nil
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func hmacSha256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
