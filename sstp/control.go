package sstp

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
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

// sendCallConnectRequest sends SSTP_MSG_CALL_CONNECT_REQUEST.
func sendCallConnectRequest(w io.Writer) error {
	attrs := []wire.Attribute{
		{ID: wire.AttrEncapsulatedProtocolID, Value: []byte{0x00, 0x01}},
		{ID: wire.AttrCryptoBindingReq, Value: []byte{0x02, 0x02, 0x00, 0x00}},
	}
	pkt, err := wire.EncodeControl(wire.MsgCallConnectRequest, attrs)
	if err != nil {
		return err
	}
	_, err = w.Write(pkt)
	return err
}

// readCallConnectAck reads the CallConnectAck/Nak response.
func readCallConnectAck(r io.Reader) error {
	_, body, err := wire.ReadPacket(r)
	if err != nil {
		return fmt.Errorf("read CallConnectAck: %w", err)
	}
	msg, err := wire.ParseControl(body)
	if err != nil {
		return fmt.Errorf("parse CallConnectAck: %w", err)
	}
	switch msg.Type {
	case wire.MsgCallConnectAck:
		return nil
	case wire.MsgCallConnectNak:
		if attr, ok := msg.Attribute(wire.AttrNoError); ok && len(attr.Value) >= 4 {
			return fmt.Errorf("server rejected: code %x", attr.Value)
		}
		return fmt.Errorf("CallConnectNak")
	default:
		return fmt.Errorf("unexpected response %#x", msg.Type)
	}
}

// buildCallConnected builds a fully-formed SSTP_MSG_CALL_CONNECTED packet.
func buildCallConnected(nonce, serverCertDER []byte, hlak [mschap.HLAKLen]byte) ([]byte, error) {
	cmk := DeriveCMK(hlak)
	certHash := sha256Sum(serverCertDER)

	val := BuildCBValue(nonce, certHash, make([]byte, wire.CompoundMACLen))
	pkt, err := wire.EncodeControl(wire.MsgCallConnected,
		[]wire.Attribute{{ID: wire.AttrCryptoBinding, Value: val}})
	if err != nil {
		return nil, err
	}

	_, body, err := wire.ReadPacket(bytes.NewReader(pkt))
	if err != nil {
		return nil, err
	}

	mac := hmacSha256(cmk, body)

	val2 := BuildCBValue(nonce, certHash, mac)
	return wire.EncodeControl(wire.MsgCallConnected,
		[]wire.Attribute{{ID: wire.AttrCryptoBinding, Value: val2}})
}

// sendCallConnected sends the crypto-bound CallConnected message.
func sendCallConnected(w io.Writer, nonce, serverCertDER []byte, hlak [mschap.HLAKLen]byte) error {
	pkt, err := buildCallConnected(nonce, serverCertDER, hlak)
	if err != nil {
		return err
	}
	_, err = w.Write(pkt)
	return err
}

// generateNonce returns 32 cryptographically random bytes.
func generateNonce() ([]byte, error) {
	n := make([]byte, wire.NonceLen)
	if _, err := rand.Read(n); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	return n, nil
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
