package gp

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestTunnelQuery(t *testing.T) {
	cases := []struct {
		name      string
		line      string
		wantQuery string
		wantOK    bool
	}{
		{
			// Exactly what the reference client sends: no headers at all.
			name:      "reference client",
			line:      "GET " + PathTunnel + "?user=alice&authcookie=deadbeef HTTP/1.1\r\n",
			wantQuery: "user=alice&authcookie=deadbeef",
			wantOK:    true,
		},
		{
			name:      "no query",
			line:      "GET " + PathTunnel + " HTTP/1.1\r\n",
			wantQuery: "",
			wantOK:    true,
		},
		{
			name:      "absolute form",
			line:      "GET https://gw.example" + PathTunnel + "?user=a HTTP/1.1\r\n",
			wantQuery: "user=a",
			wantOK:    true,
		},
		{name: "another path", line: "POST " + PathLogin + " HTTP/1.1\r\n"},
		{name: "the login path", line: "GET " + PathLogin + " HTTP/1.1\r\n"},
		{name: "wrong method", line: "POST " + PathTunnel + " HTTP/1.1\r\n"},
		{name: "not a request line", line: "garbage\r\n"},
		{name: "empty", line: "\r\n"},
		{
			// A path that merely starts with the tunnel's must not be diverted.
			name: "prefix only",
			line: "GET " + PathTunnel + "x HTTP/1.1\r\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			query, ok := tunnelQuery([]byte(tc.line))
			if ok != tc.wantOK || query != tc.wantQuery {
				t.Errorf("tunnelQuery(%q) = %q, %v; want %q, %v", tc.line, query, ok, tc.wantQuery, tc.wantOK)
			}
		})
	}
}

func TestReadLine(t *testing.T) {
	br := bufio.NewReader(strings.NewReader("first\r\nsecond\r\n"))
	line, err := readLine(br, 64)
	if err != nil {
		t.Fatalf("readLine: %v", err)
	}
	if string(line) != "first\r\n" {
		t.Errorf("line = %q", line)
	}
	// The reader must be positioned exactly at the next line.
	rest, _ := io.ReadAll(br)
	if string(rest) != "second\r\n" {
		t.Errorf("rest = %q", rest)
	}
}

// TestReadLineRefusesAnEndlessLine: a peer that never sends a newline must not
// make the gateway buffer without bound.
func TestReadLineRefusesAnEndlessLine(t *testing.T) {
	br := bufio.NewReader(strings.NewReader(strings.Repeat("x", 4096)))
	if _, err := readLine(br, 64); !errors.Is(err, io.ErrShortBuffer) {
		t.Errorf("error = %v, want %v", err, io.ErrShortBuffer)
	}
}

func TestReadLineAtEOF(t *testing.T) {
	br := bufio.NewReader(strings.NewReader(""))
	if _, err := readLine(br, 64); !errors.Is(err, io.EOF) {
		t.Errorf("error = %v, want EOF", err)
	}
}

func TestDiscardHead(t *testing.T) {
	cases := []struct {
		name string
		in   string
		rest string
	}{
		{"no headers", "\r\npackets", "packets"},
		{"some headers", "Host: gw\r\nUser-Agent: x\r\n\r\npackets", "packets"},
		{"bare newlines", "Host: gw\n\npackets", "packets"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			br := bufio.NewReader(strings.NewReader(tc.in))
			if err := discardHead(br, 8192); err != nil {
				t.Fatalf("discardHead: %v", err)
			}
			rest, _ := io.ReadAll(br)
			if string(rest) != tc.rest {
				t.Errorf("rest = %q, want %q", rest, tc.rest)
			}
		})
	}
}

// TestDiscardHeadRefusesAnEndlessHead bounds the other direction: many short
// header lines that never end must be refused too.
func TestDiscardHeadRefusesAnEndlessHead(t *testing.T) {
	br := bufio.NewReader(strings.NewReader(strings.Repeat("X: y\r\n", 4096)))
	if err := discardHead(br, 1024); !errors.Is(err, io.ErrShortBuffer) {
		t.Errorf("error = %v, want %v", err, io.ErrShortBuffer)
	}
}
