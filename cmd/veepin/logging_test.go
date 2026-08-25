package main

import (
	"bytes"
	"encoding/json"
	"log"
	"log/slog"
	"strings"
	"testing"

	"github.com/xen0bit/veepin/internal/debuglog"
)

// The default output is byte-for-byte what it was. A slog TextHandler would
// render every line as `time=... level=INFO msg="..."`, which is strictly worse
// to read at a terminal -- being able to choose json is the feature, not being
// made to.
func TestTheDefaultFormatIsTheLineItAlwaysWas(t *testing.T) {
	fs := newTestFlagSet()
	l := bindLogFlags(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if l.format != "text" || l.level != "info" {
		t.Fatalf("defaults changed: format=%q level=%q", l.format, l.level)
	}
	var buf bytes.Buffer
	logger, err := l.loggerTo(&buf)
	if err != nil {
		t.Fatal(err)
	}
	logger.Printf("connected on %s", "tun0")

	line := buf.String()
	if strings.Contains(line, "msg=") || strings.Contains(line, "level=") {
		t.Errorf("the text format became structured: %q", line)
	}
	if !strings.HasSuffix(strings.TrimRight(line, "\n"), "connected on tun0") {
		t.Errorf("line = %q, want it to end with the message", line)
	}
}

// json is the point of the item: one slog record per line, so a log shipper can
// read what the supervisor emits instead of the panel's log ring being the only
// consumer that can.
func TestJSONFormatEmitsOneRecordPerLine(t *testing.T) {
	fs := newTestFlagSet()
	l := bindLogFlags(fs)
	if err := fs.Parse([]string{"-log-format", "json"}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	logger, err := l.loggerTo(&buf)
	if err != nil {
		t.Fatal(err)
	}
	logger.Printf("connected on %s", "tun0")

	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("output is not one JSON record: %v (%q)", err, buf.String())
	}
	if got, _ := rec["msg"].(string); !strings.Contains(got, "connected on tun0") {
		t.Errorf("msg = %q", got)
	}
	if got, _ := rec["level"].(string); got != "INFO" {
		t.Errorf("level = %q, want INFO", got)
	}
}

// Above info the informational stream goes nowhere -- and now only the
// informational stream does. TestTheLevelFiltersPerLineNotPerStream below is
// the other half, and it is the one that would have failed before internal/vlog
// existed.
func TestAboveInfoTheInformationalStreamIsSuppressed(t *testing.T) {
	for _, level := range []string{"warn", "error"} {
		t.Run(level, func(t *testing.T) {
			fs := newTestFlagSet()
			l := bindLogFlags(fs)
			if err := fs.Parse([]string{"-log-level", level}); err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			logger, err := l.loggerTo(&buf)
			if err != nil {
				t.Fatal(err)
			}
			logger.Printf("connected on tun0")
			if buf.Len() != 0 {
				t.Errorf("-log-level=%s still printed %q", level, buf.String())
			}
		})
	}
}

// info keeps writing, which is the default and must not be suppressed by a
// comparison that treats "no explicit level" as "quiet".
func TestInfoStillWrites(t *testing.T) {
	fs := newTestFlagSet()
	l := bindLogFlags(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	logger, err := l.loggerTo(&buf)
	if err != nil {
		t.Fatal(err)
	}
	logger.Printf("connected on tun0")
	if buf.Len() == 0 {
		t.Error("the default level discards its own output")
	}
}

// -log-level=debug is the one switch for protocol-level detail, replacing the
// per-protocol environment variables that had started to accumulate. It has to
// reach internal/debuglog, since the protocol packages cannot import main.
func TestDebugLevelReachesTheProtocolPackages(t *testing.T) {
	t.Cleanup(func() { debuglog.SetEnabled(false) })

	fs := newTestFlagSet()
	l := bindLogFlags(fs)
	if err := fs.Parse([]string{"-log-level", "debug"}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.logger(); err != nil {
		t.Fatal(err)
	}
	if !debuglog.Enabled() {
		t.Error("-log-level=debug did not reach internal/debuglog, so no protocol will print detail")
	}

	fs = newTestFlagSet()
	l = bindLogFlags(fs)
	if err := fs.Parse([]string{"-log-level", "info"}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.logger(); err != nil {
		t.Fatal(err)
	}
	if debuglog.Enabled() {
		t.Error("debug stayed on after the level came back down")
	}
}

// A misspelled level or format is an error, not a silent fallback to the
// default. Silently ignoring it is how an operator ends up believing they are
// capturing json and finding text in their log pipeline.
func TestAMisspelledLevelOrFormatIsRefused(t *testing.T) {
	for _, args := range [][]string{
		{"-log-level", "verbose"},
		{"-log-format", "logfmt"},
	} {
		fs := newTestFlagSet()
		l := bindLogFlags(fs)
		if err := fs.Parse(args); err != nil {
			t.Fatal(err)
		}
		if _, err := l.logger(); err == nil {
			t.Errorf("%v was accepted", args)
		}
	}
}

func TestParseLevelAcceptsTheUsualSpellings(t *testing.T) {
	for in, want := range map[string]slog.Level{
		"":        slog.LevelInfo,
		"INFO":    slog.LevelInfo,
		"debug":   slog.LevelDebug,
		"Warn":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"ERROR":   slog.LevelError,
	} {
		got, err := parseLevel(in)
		if err != nil {
			t.Errorf("parseLevel(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("parseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestTheLevelFiltersPerLineNotPerStream is what item 12 of the claims-and-reach
// plan was about, and it is the assertion that says the fix landed.
//
// Before internal/vlog the tree logged through *log.Logger, which has no
// per-call level: -log-level=warn could only point the whole logger at
// io.Discard, so a protocol reporting a real problem was suppressed along with
// the chatter. Now the level is chosen at the call site and warn means what it
// says.
func TestTheLevelFiltersPerLineNotPerStream(t *testing.T) {
	fs := newTestFlagSet()
	l := bindLogFlags(fs)
	if err := fs.Parse([]string{"-log-level", "warn"}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	logger, err := l.loggerTo(&buf)
	if err != nil {
		t.Fatal(err)
	}

	logger.Printf("connected on tun0")
	if buf.Len() != 0 {
		t.Errorf("-log-level=warn printed an informational line: %q", buf.String())
	}

	logger.Warnf("peer %s rejected our proposal", "198.51.100.7")
	if !strings.Contains(buf.String(), "rejected our proposal") {
		t.Errorf("-log-level=warn dropped a warning too (%q); the level is still a gate on the "+
			"whole stream rather than a filter within it", buf.String())
	}

	buf.Reset()
	logger.Errorf("tunnel down: %v", "no route")
	if !strings.Contains(buf.String(), "tunnel down") {
		t.Errorf("-log-level=warn dropped an error: %q", buf.String())
	}
}

// TestTheTextLineIsByteForByteWhatLogPackagePrinted is the guard on the format
// itself, and it is not a stylistic preference.
//
// Twenty-eight interop cells assert substrings of veepin's own log output, the
// management panel serves the stream to a browser as free text, and every
// runbook in doc/usage quotes lines from it. A slog.TextHandler would render
// `time=... level=INFO msg="connected on tun0"` -- quoting the message and
// moving the timestamp -- and every one of those would break at once, quietly,
// as a line that stopped matching rather than a test that failed here.
func TestTheTextLineIsByteForByteWhatLogPackagePrinted(t *testing.T) {
	var ours bytes.Buffer
	fs := newTestFlagSet()
	l := bindLogFlags(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	logger, err := l.loggerTo(&ours)
	if err != nil {
		t.Fatal(err)
	}

	var theirs bytes.Buffer
	stdlib := log.New(&theirs, "", log.LstdFlags|log.Lmicroseconds)

	const msg = "ikev2: client 10.0.0.2 up, assigned 10.0.0.2 (peer-id 3)"
	logger.Printf("%s", msg)
	stdlib.Printf("%s", msg)

	// The timestamps differ in their last digits, so compare the shape: same
	// length, same field layout, same message tail.
	got, want := ours.String(), theirs.String()
	if len(got) != len(want) {
		t.Fatalf("line length %d, want %d\n got: %q\nwant: %q", len(got), len(want), got, want)
	}
	gotStamp, wantStamp := got[:len("2006/01/02 15:04:05.000000")], want[:len("2006/01/02 15:04:05.000000")]
	for i := range gotStamp {
		gc, wc := gotStamp[i], wantStamp[i]
		sameShape := gc == wc || (isDigit(gc) && isDigit(wc))
		if !sameShape {
			t.Fatalf("timestamp differs at %d: got %q, want %q", i, got, want)
		}
	}
	if got[len(gotStamp):] != want[len(wantStamp):] {
		t.Errorf("after the timestamp: got %q, want %q", got[len(gotStamp):], want[len(wantStamp):])
	}
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }
