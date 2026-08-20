package softether

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// readSignatureFrom runs the server's opening exchange against a canned request
// stream, returning what it wrote back.
func readSignatureFrom(t *testing.T, requests string) (*bytes.Buffer, error) {
	t.Helper()
	var out bytes.Buffer
	err := readSignature(bufio.NewReader(strings.NewReader(requests)), &out)
	return &out, err
}

func signaturePost() string {
	return fmt.Sprintf("POST %s HTTP/1.1\r\nHost: h\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s",
		httpVPNTarget2, httpContentTypeJPEG, len(httpVPNTargetPostData), httpVPNTargetPostData)
}

// TestTheSignatureNeedNotBeTheFirstRequest is the bug this file was written
// for. SoftEther's own vpnclient opens with `GET /` and posts the signature
// second; a server that judged the first request refused every real client on
// its opening move. veepin's own client posts the signature immediately, so
// nothing in the tree noticed for as long as the row existed.
func TestTheSignatureNeedNotBeTheFirstRequest(t *testing.T) {
	out, err := readSignatureFrom(t, "GET / HTTP/1.1\r\nHost: h\r\n\r\n"+signaturePost())
	if err != nil {
		t.Fatalf("readSignature rejected a client that probed first: %v", err)
	}
	// And the probe must have been answered, or the client never sends the
	// second request: it is waiting on a response to the first.
	resp, rerr := http.ReadResponse(bufio.NewReader(bytes.NewReader(out.Bytes())), nil)
	if rerr != nil {
		t.Fatalf("the probe went unanswered: %v", rerr)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("probe answered %s, want 403 (HttpSendForbidden's)", resp.Status)
	}
	if !strings.EqualFold(resp.Header.Get("Connection"), "Keep-Alive") {
		t.Errorf("probe answered with Connection: %q — the client reconnects rather than "+
			"sending its signature on this connection", resp.Header.Get("Connection"))
	}
}

// TestTheSignatureStillWorksAsTheFirstRequest keeps the loop from costing the
// common case. veepin's own client, and any client that skips the probe, posts
// the signature immediately.
func TestTheSignatureStillWorksAsTheFirstRequest(t *testing.T) {
	out, err := readSignatureFrom(t, signaturePost())
	if err != nil {
		t.Fatalf("readSignature rejected an immediate signature: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("wrote %d bytes before the hello; a client expecting the hello "+
			"next will read this as one", out.Len())
	}
}

// TestAPeerThatNeverSignsIsCutOff. Without a bound, anything that speaks HTTP
// holds a goroutine and a TLS connection for as long as it keeps asking, which
// costs it one request each and costs the server a session.
func TestAPeerThatNeverSignsIsCutOff(t *testing.T) {
	probes := strings.Repeat("GET / HTTP/1.1\r\nHost: h\r\n\r\n", maxRequestsBeforeSignature+5)
	if _, err := readSignatureFrom(t, probes); err == nil {
		t.Fatalf("readSignature accepted %d requests without a signature",
			maxRequestsBeforeSignature+5)
	}
}

// TestAMethodTheReferenceDoesNotServeEndsTheConnection. The reference answers
// GET, HEAD and POST and sends 501 to anything else; continuing to read after
// one keeps a connection alive for a peer that has already identified itself as
// something other than a VPN client.
func TestAMethodTheReferenceDoesNotServeEndsTheConnection(t *testing.T) {
	if _, err := readSignatureFrom(t, "OPTIONS * HTTP/1.1\r\nHost: h\r\n\r\n"+signaturePost()); err == nil {
		t.Error("readSignature kept reading after a method the reference refuses")
	}
}

// TestASignatureToTheWrongTargetIsNotASignature. The signature goes to
// connect.cgi and every control PACK to vpn.cgi. A POST to the second is a
// browser-shaped request at this stage, not an early control message, and
// treating it as a signature would let a peer skip the step entirely.
func TestASignatureToTheWrongTargetIsNotASignature(t *testing.T) {
	wrong := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: h\r\nContent-Length: %d\r\n\r\n%s",
		httpVPNTarget, len(httpVPNTargetPostData), httpVPNTargetPostData)
	out, err := readSignatureFrom(t, wrong+signaturePost())
	if err != nil {
		t.Fatalf("readSignature gave up rather than answering and reading on: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("403")) {
		t.Error("a POST to the control target was not answered as a non-VPN request")
	}
}

// TestTheForbiddenPageEscapesTheTarget. The target is peer-supplied and lands
// in an HTML body. The reference runs ReplaceUnsafeCharInTarget over it for the
// same reason.
func TestTheForbiddenPageEscapesTheTarget(t *testing.T) {
	body := forbiddenBody("/<script>alert(1)</script>")
	if strings.Contains(body, "<script>") {
		t.Errorf("the 403 page reflected markup from the request target:\n%s", body)
	}
}
