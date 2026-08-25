package main

// runProfile manages named client connection profiles under
// ~/.config/veepin/profiles/. It is the client-side mirror of the supervisor's
// listener directory: one JSON file per profile, the same protocol+options map
// shape. A profile can then be dialed by name with `veepin connect <name>`.
//
// Subcommands:
//
//	ls                       list saved profiles
//	add <name> <protocol>    create a profile from connect flags (or stdin JSON)
//	show <name>              print a profile (secrets redacted)
//	rm <name>                delete a profile [-y]
//
// VEEPIN_PROFILE_DIR overrides the directory, which is what the tests use and
// what lets a profile set live somewhere other than the user's config home.

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/internal/confstore"
	"github.com/xen0bit/veepin/internal/profile"
)

func runProfile(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: veepin profile <subcommand>\nsubcommands: ls, add, show, rm")
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "ls":
		return profileList(rest)
	case "add":
		return profileAdd(rest)
	case "show":
		return profileShow(rest)
	case "rm":
		return profileRm(rest)
	default:
		return fmt.Errorf("profile: unknown subcommand %q", sub)
	}
}

func profileDir() (string, error) {
	dir := os.Getenv("VEEPIN_PROFILE_DIR")
	if dir != "" {
		return dir, nil
	}
	return profile.DefaultDir()
}

func profileList(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: veepin profile ls (takes no arguments)")
	}
	dir, err := profileDir()
	if err != nil {
		return err
	}
	cfgs, err := profile.LoadDir(dir)
	if err != nil {
		return err
	}
	// Print one line per profile: name, protocol. No JSON envelope — the output
	// is meant for a human, not a pipeline (use the mgmt API for that).
	//
	// Sorted, because LoadDir returns a map and ranging one gave a different
	// order on every run. Every other listing in the tree sorts.
	for _, name := range slices.Sorted(maps.Keys(cfgs)) {
		fmt.Printf("%-24s %s\n", name, cfgs[name].Protocol)
	}
	return nil
}

func profileAdd(args []string) error {
	fs := flag.NewFlagSet("profile add", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Flag-driven form: `profile add <name> <protocol> [-flag ...]`. The
	// per-protocol flags are bound and parsed below, reusing connectFlags so the
	// profile takes exactly what `veepin connect <protocol>` takes.
	if fs.NArg() >= 2 {
		return profileAddFlags(fs.Arg(0), fs.Arg(1), fs.Args()[2:])
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: veepin profile add <name> <protocol> [flags]\n" +
			"       (or: veepin profile add < a-profile.json)")
	}
	body, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return fmt.Errorf("profile add: read a profile JSON on stdin (got EOF)")
	}
	// Parsed through the package rather than with a second decoder here, so the
	// CLI and the on-disk reader cannot disagree about what a profile is.
	cfg, err := profile.ParseBytes(body)
	if err != nil {
		return fmt.Errorf("profile add: %w", err)
	}
	// The stdin form gets the registry check the flag form already does, and
	// the same save-time validation, so a profile that cannot be dialed is
	// refused here rather than surfacing at `veepin connect` time with a
	// mystery parse error.
	if !slices.Contains(client.AllProtocols(), cfg.Protocol) {
		return fmt.Errorf("profile add: unknown protocol %q (available: %s)",
			cfg.Protocol, strings.Join(client.AllProtocols(), ", "))
	}
	if err := client.ValidateOptions(cfg.Protocol, cfg.Options); err != nil {
		return fmt.Errorf("profile add: %w", err)
	}
	dir, err := profileDir()
	if err != nil {
		return err
	}
	if err := profile.Write(dir, cfg); err != nil {
		return err
	}
	fmt.Printf("saved %q (protocol %s)\n", cfg.Name, cfg.Protocol)
	return nil
}

// profileAddFlags is the flag-driven create: the protocol's own connect flags
// become the profile's options, so `veepin profile add home ikev2 -gateway
// vpn.example.com -psk ...` reads exactly like `veepin connect ikev2 ...`.
func profileAddFlags(name, protocol string, args []string) error {
	if !confstore.ValidName(name) {
		return fmt.Errorf("profile add: name %q must match %s", name, confstore.NameGrammar())
	}
	if !slices.Contains(client.AllProtocols(), protocol) {
		return fmt.Errorf("profile add: unknown protocol %q (available: %s)",
			protocol, strings.Join(client.AllProtocols(), ", "))
	}
	fs := flag.NewFlagSet("profile add "+name, flag.ContinueOnError)
	options, err := connectFlags(protocol, fs)
	if err != nil {
		return err
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("profile add: unexpected argument %q", fs.Arg(0))
	}
	cfg := profile.Config{Name: name, Protocol: protocol, Options: options()}
	// The profile's options were typed as connect flags, but flags are a lossy
	// form: defaults get baked in, required options can be left out, and a typo
	// in a value the parse does not check is only caught here. ValidateOptions
	// runs the protocol's ParseFunc and discards the Dialer -- no I/O -- so a
	// profile that would fail at connect time is refused at save time, with the
	// parse's own "X is required" message.
	if err := client.ValidateOptions(protocol, cfg.Options); err != nil {
		return fmt.Errorf("profile add: %w", err)
	}
	dir, err := profileDir()
	if err != nil {
		return err
	}
	if err := profile.Write(dir, cfg); err != nil {
		return err
	}
	fmt.Printf("saved %q (protocol %s)\n", name, protocol)
	return nil
}

func profileShow(args []string) error {
	// The -secrets flag may precede or follow the name: Go's flag package stops
	// at the first positional, so pull it out first rather than document an
	// order requirement.
	showSecrets := false
	rest := make([]string, 0, len(args))
	for _, a := range args {
		if a == "-secrets" || a == "--secrets" {
			showSecrets = true
			continue
		}
		rest = append(rest, a)
	}
	if len(rest) != 1 {
		return fmt.Errorf("usage: veepin profile show <name> [-secrets]")
	}
	dir, err := profileDir()
	if err != nil {
		return err
	}
	cfg, err := profile.ParseFile(profile.Path(dir, rest[0]))
	if err != nil {
		return err
	}
	// Redact secrets unless asked not to: a PSK or password echoed to the
	// terminal (and shell history) is a leak vector with no upside, since the
	// config file itself is mode 0600 on the operator's own disk.
	if !showSecrets {
		specs, _ := client.ClientOptsFor(cfg.Protocol)
		cfg.Options = client.Redact(specs, cfg.Options)
	}
	// SetEscapeHTML(false) keeps the "<redacted>" sentinel readable, the same
	// choice the management API's writeJSON makes for the same reason.
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(cfg)
}

func profileRm(args []string) error {
	// -y is read positionally (see mgmtRm for why it cannot be a flag in the
	// set): a profile rm in a script is usually `profile rm name -y`, and Go's
	// flag package stops parsing at the first positional.
	yes := false
	filtered := make([]string, 0, len(args))
	for _, a := range args {
		// -yes too: it is what an operator types, and accepting only -y meant
		// the long form fell through to be read as a name.
		if a == "-y" || a == "--y" || a == "-yes" || a == "--yes" {
			yes = true
			continue
		}
		filtered = append(filtered, a)
	}
	fs := flag.NewFlagSet("profile rm", flag.ContinueOnError)
	if err := fs.Parse(filtered); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: veepin profile rm <name> [-y]")
	}
	name := fs.Arg(0)
	if !confirmDelete("delete profile "+name, yes) {
		return fmt.Errorf("profile rm %s: cancelled", name)
	}
	dir, err := profileDir()
	if err != nil {
		return err
	}
	if err := profile.Delete(dir, name); err != nil {
		return err
	}
	fmt.Printf("deleted %q\n", name)
	return nil
}
