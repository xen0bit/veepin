package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/xen0bit/veepin/internal/debuglog"
	"github.com/xen0bit/veepin/internal/vlog"
)

// Logging: one level and one shape, on log/slog.
//
// Before this there was one *log.Logger at LstdFlags|Lmicroseconds everywhere,
// no level, no structure, and one ad-hoc per-protocol escape hatch
// (VEEPIN_SSTP_DEBUG) that existed because someone needed exactly this and
// there was nowhere to put it. The supervisor's log ring then served those
// lines to the panel as free text.
//
// # What the level does
//
// It filters *within* the stream. Every line the tree writes goes through
// internal/vlog, which chooses a level at the call site:
//
//	debug   everything, including the per-protocol detail that used to need
//	        VEEPIN_SSTP_DEBUG
//	info    the default, and exactly what the command printed before
//	warn    the informational stream is dropped; problems still print
//	error   only what actually failed
//
// This is the second version of this comment. The first said the level was "a
// gate on the stream rather than a filter within it" -- at warn, the logger was
// simply pointed at io.Discard -- because *log.Logger has no per-call level and
// reclassifying several hundred call sites was judged too large. It was: it is
// exactly one wrapper type and a rule about which direction lines may move
// (never downward). See internal/vlog.
//
// Errors reaching stderr does not depend on the level either way: a fatal error
// returns up to main and is printed by run(), never through the logger.
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
		"debug, info, warn or error; the level filters the stream per line, and "+
			"a fatal error reaches stderr whatever it is set to")
	fs.StringVar(&l.format, "log-format", "text",
		"text (the customary timestamped lines) or json (one slog record per line)")
	return l
}

// logger builds the logger the command writes its own lines through, on stdout.
//
// Protocol packages do not get this one: a facade builds its own from logDest(),
// which is why nothing here ever hands a logger to a Config.
func (l logFlags) logger() (*vlog.Logger, error) { return l.loggerTo(os.Stdout) }

// loggerTo is logger with the destination named. It exists because a logger
// built over a slog handler cannot be redirected afterwards -- the handler holds
// the writer -- so a test that redirected one would silently be testing
// somewhere else. The destination is a parameter so it is chosen once, where the
// handler is built.
//
// Both formats now go through slog. The text one uses legacyText (textlog.go),
// which prints the timestamped line this command has always printed: the format
// is what twenty-eight interop cells and the panel's log ring read.
func (l logFlags) loggerTo(w io.Writer) (*vlog.Logger, error) {
	h, err := l.handlerTo(w)
	if err != nil {
		return nil, err
	}
	return vlog.New(slog.New(h)), nil
}

// handlerTo is the handler behind loggerTo, exposed separately because the
// management plane needs the same one twice: once for the supervisor's logger
// and once for an http.Server's ErrorLog, which is a *log.Logger and can only be
// bridged from a handler.
func (l logFlags) handlerTo(w io.Writer) (slog.Handler, error) {
	lvl, err := parseLevel(l.level)
	if err != nil {
		return nil, err
	}
	// internal/debuglog is where the protocol packages read this, since they
	// cannot import package main. It replaces the per-protocol environment
	// variables (VEEPIN_SSTP_DEBUG) that had started to accumulate.
	debuglog.SetEnabled(lvl <= slog.LevelDebug)

	switch strings.ToLower(l.format) {
	case "", "text":
		return vlog.NewTextHandler(w, lvl), nil
	case "json":
		return slog.NewJSONHandler(w, &slog.HandlerOptions{Level: lvl}), nil
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
