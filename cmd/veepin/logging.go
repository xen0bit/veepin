package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"strings"

	"github.com/xen0bit/veepin/internal/debuglog"
)

// Logging: one level and one shape, on log/slog.
//
// Before this there was one *log.Logger at LstdFlags|Lmicroseconds everywhere,
// no level, no structure, and one ad-hoc per-protocol escape hatch
// (VEEPIN_SSTP_DEBUG) that existed because someone needed exactly this and
// there was nowhere to put it. The supervisor's log ring then served those
// lines to the panel as free text.
//
// # What the level can and cannot do, stated plainly
//
// The tree logs through *log.Logger, which has no per-call level: every line a
// protocol writes is one call to Printf. Reclassifying several hundred of those
// into slog calls is a much larger change than this item is worth, so the level
// here is a gate on the stream rather than a filter within it:
//
//	debug   everything, including the per-protocol detail that used to need
//	        VEEPIN_SSTP_DEBUG
//	info    the default, and exactly what the command printed before
//	warn    the informational stream is suppressed
//	error   likewise
//
// warn and error are honest rather than half-implemented, because of how this
// command reports failure: a fatal error returns up to main and is printed to
// stderr by run(), never through the logger. So "suppress the informational
// stream" leaves errors visible, which is what an operator asking for
// -log-level=error wants. It does mean a protocol that logs a non-fatal problem
// through the same *log.Logger is suppressed with the rest, and that is the
// limitation to know about.
//
// log/slog is the standard library, so the dependency contract at the top of
// the README is untouched.

// logFlags are the logging flags, bound on every subcommand that logs.
type logFlags struct {
	level  string
	format string
}

func bindLogFlags(fs *flag.FlagSet) *logFlags {
	l := &logFlags{}
	fs.StringVar(&l.level, "log-level", "info",
		"debug, info, warn or error; above info the informational stream is "+
			"suppressed and errors still reach stderr")
	fs.StringVar(&l.format, "log-format", "text",
		"text (the customary timestamped lines) or json (one slog record per line)")
	return l
}

// logger builds the *log.Logger the rest of the command hands to protocol
// packages, writing to stdout.
func (l logFlags) logger() (*log.Logger, error) { return l.loggerTo(os.Stdout) }

// loggerTo is logger with the destination named. It exists because a logger
// built over a slog handler cannot be redirected afterwards -- SetOutput
// replaces the bridge rather than what the bridge writes to, so a test that
// redirected one would silently be testing the text path. The destination is a
// parameter so it is chosen once, where the handler is built.
//
// It returns a plain logger for the text format so that the default output is
// byte-for-byte what it was, and a slog-backed one for json.
func (l logFlags) loggerTo(w io.Writer) (*log.Logger, error) {
	lvl, err := parseLevel(l.level)
	if err != nil {
		return nil, err
	}
	// internal/debuglog is where the protocol packages read this, since they
	// cannot import package main. It replaces the per-protocol environment
	// variables (VEEPIN_SSTP_DEBUG) that had started to accumulate.
	debuglog.SetEnabled(lvl <= slog.LevelDebug)

	// Above info, the informational stream goes nowhere. See the header for why
	// this is the whole of what the level can mean while the tree logs through
	// *log.Logger.
	out := w
	if lvl > slog.LevelInfo {
		out = io.Discard
	}

	switch strings.ToLower(l.format) {
	case "", "text":
		// Unchanged, deliberately. A slog TextHandler would render every line
		// as `time=... level=INFO msg="..."`, which is strictly worse to read
		// at a terminal than the timestamped line this has always printed --
		// and being able to choose json is the feature, not being made to.
		return log.New(out, "", log.LstdFlags|log.Lmicroseconds), nil
	case "json":
		h := slog.NewJSONHandler(out, &slog.HandlerOptions{Level: lvl})
		// NewLogLogger is the bridge: it hands back a *log.Logger whose every
		// Printf becomes one slog record at the given level, so the seventeen
		// protocol packages need not know slog exists.
		return slog.NewLogLogger(h, slog.LevelInfo), nil
	default:
		return nil, fmt.Errorf("unknown -log-format %q (text or json)", l.format)
	}
}

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown -log-level %q (debug, info, warn or error)", s)
	}
}
