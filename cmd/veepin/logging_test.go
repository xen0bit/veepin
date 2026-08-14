package main

import (
	"bytes"
	"encoding/json"
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

// Above info the informational stream goes nowhere. This is the whole of what
// the level can mean while the tree logs through *log.Logger, and it is honest
// because a fatal error returns to main and reaches stderr through run(),
// never through this logger.
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
