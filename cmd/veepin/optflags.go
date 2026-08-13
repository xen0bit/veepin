package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/xen0bit/veepin/client"
)

// Generating the command-line flag set from the OptSpec tables.
//
// connectFlags and serveFlags used to be one `case` per protocol -- about
// twelve hundred lines between them -- each binding flags whose name, type,
// default and help text were already declared, in the OptSpec tables the same
// protocol registers through RegisterClientOpts/RegisterServerOpts. Those
// tables additionally carry Required and Secret, which the flags did not.
//
// The tell was in AGENTS.md's own guard table: four of the mechanical guards
// existed solely to hold those two hand-written copies against each other, and
// the fourth was written because the first two were blind to an option the
// parse read that no flag emitted. A guard that checks two hand-maintained
// copies agree is evidence of the duplication, not a remedy for it -- and this
// one had already leaked a bug through, which is why applyOverrides has a `-set`
// key check.
//
// # The two kinds of "default"
//
// OptSpec.Default is what the PROTOCOL does when the option is unset -- 443 for
// an HTTPS port, AES-256-GCM for an OpenVPN cipher. It is not the same claim as
// "the flag holds this value", and conflating them is the one way this could
// silently break things:
//
//	veepin connect openvpn -config work.ovpn
//
// where work.ovpn names a cipher. If an unset -cipher emitted "AES-256-GCM"
// into the option map, it would override the file, and the operator would get a
// cipher they never asked for with nothing anywhere saying so.
//
// So the flag's default is spec.Default (which is what makes -h finally tell
// the truth about what happens when you say nothing), and the collector omits
// any key still holding that default and not explicitly passed. An unset flag
// therefore contributes nothing to the option map -- exactly as the hand-written
// switch did -- and each protocol's own parse applies its own fallback. Passing
// the default value explicitly still emits it, which is how an operator
// overrides a config file with the stock value on purpose.

// bindSpecFlags declares one command-line flag per spec on fs, and returns the
// collector that reads them back into the option map the facade parses.
//
// The returned collector may be called before or after fs.Parse; flags_test.go
// calls fs.Set directly and then collects, which fs.Visit reports as explicitly
// set exactly as parsing would.
func bindSpecFlags(fs *flag.FlagSet, specs []client.OptSpec) func() map[string]string {
	// values holds one pointer per spec, in spec order, so the collector reads
	// them back without a second lookup.
	type binding struct {
		spec client.OptSpec
		name string
		str  *string
		num  *int
		flip *bool
	}
	bindings := make([]binding, 0, len(specs))

	for _, sp := range specs {
		b := binding{spec: sp, name: flagName(sp)}
		usage := flagUsage(sp)
		switch sp.Kind {
		case client.OptInt:
			n, _ := strconv.Atoi(sp.Default) // a non-numeric Default is a spec bug; 0 is the safe read
			b.num = fs.Int(b.name, n, usage)
		case client.OptBool:
			b.flip = fs.Bool(b.name, sp.Default == "true", usage)
		default:
			b.str = fs.String(b.name, sp.Default, usage)
		}
		// The -<flag>-file companion (item 7): every option a spec marks Secret
		// gets one, so a password or a PSK need never appear in the process
		// table, the shell history, or the systemd unit that carries the
		// command line.
		//
		// A spec whose Kind is already OptFilePath is skipped: its value IS a
		// path, and "-key-file-file" would be nonsense.
		if sp.Secret && sp.Kind != client.OptFilePath && b.str != nil {
			fs.Var(&secretFileFlag{dst: b.str, flag: b.name},
				b.name+"-file",
				"read -"+b.name+" from this file instead, so the secret is not in the process table")
		}
		bindings = append(bindings, b)
	}

	return func() map[string]string {
		explicit := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })

		out := make(map[string]string, len(bindings))
		for _, b := range bindings {
			var v string
			switch {
			case b.num != nil:
				v = strconv.Itoa(*b.num)
			case b.flip != nil:
				v = strconv.FormatBool(*b.flip)
			default:
				v = *b.str
			}
			// An unset flag still holding its documented default contributes
			// nothing, so the protocol's own parse decides -- see the header.
			// A secret filled in from its -file companion counts as explicit:
			// the companion is the flag the operator passed.
			if !explicit[b.name] && !explicit[b.name+"-file"] && v == defaultString(b.spec) {
				continue
			}
			out[b.spec.Key] = v
		}
		return out
	}
}

// flagName is the command-line spelling of a spec: its Flag when it has one,
// otherwise its Key.
func flagName(sp client.OptSpec) string {
	if sp.Flag != "" {
		return sp.Flag
	}
	return sp.Key
}

// flagUsage is the help line. Required is appended rather than being left to
// each Help string, because it was written into some of them and not others and
// the flag set is the wrong place to keep that inconsistent.
//
// A "(default N)" the Help spells out is removed, because the flag package
// appends its own from the value now carried on the flag -- so leaving it
// produced "server IKE port (default 500) (default 500)". The spec's Help keeps
// it for the management panel, which renders help text with no default of its
// own beside it.
func flagUsage(sp client.OptSpec) string {
	usage := sp.Help
	if sp.Default != "" {
		usage = defaultParenthetical.ReplaceAllString(usage, "")
		usage = strings.TrimSpace(usage)
	}
	if sp.Required && !strings.Contains(usage, "required") {
		usage += " (required)"
	}
	return usage
}

// defaultParenthetical matches the ways the Help strings spell a default out:
// "(default 500)", "(default: 500)", "(0 = default 3600)".
var defaultParenthetical = regexp.MustCompile(`\s*\((?:[^()]*=\s*)?default:?\s+[^()]*\)`)

// defaultString is a spec's Default normalised to the spelling the collector
// compares against, so an int spec with no Default matches "0" rather than "".
func defaultString(sp client.OptSpec) string {
	switch sp.Kind {
	case client.OptInt:
		n, _ := strconv.Atoi(sp.Default)
		return strconv.Itoa(n)
	case client.OptBool:
		return strconv.FormatBool(sp.Default == "true")
	default:
		return sp.Default
	}
}

// secretFileFlag is the -<flag>-file companion: it reads the secret out of a
// file at parse time and writes it into the same variable the primary flag
// holds.
//
// At parse time rather than at collection time, deliberately. A file that
// cannot be read is then reported by fs.Parse, alongside every other
// command-line error, instead of having to be threaded back through a collector
// whose whole signature exists to be simple.
type secretFileFlag struct {
	dst  *string
	flag string
	path string
}

func (s *secretFileFlag) String() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Get satisfies flag.Getter. It returns the PATH, never the secret: this is
// what -h and any flag walker reads back, and a Getter that hands out the
// contents of a key file is a Getter that will eventually print one.
func (s *secretFileFlag) Get() any { return s.path }

func (s *secretFileFlag) Set(path string) error {
	if *s.dst != "" {
		return fmt.Errorf("-%s and -%s-file both given; use one", s.flag, s.flag)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("-%s-file: %w", s.flag, err)
	}
	// Only the trailing newline comes off, and only one line's worth. A secret
	// with leading spaces is a secret; `echo hunter2 > pass` is the way every
	// operator will create one of these files, and the newline it adds is not
	// part of the password.
	*s.dst = strings.TrimRight(string(b), "\r\n")
	s.path = path
	if *s.dst == "" {
		return fmt.Errorf("-%s-file: %s is empty", s.flag, path)
	}
	return nil
}
