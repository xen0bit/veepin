package main

// runProfile manages named client connection profiles under
// ~/.config/veepin/profiles/. It is the client-side mirror of the supervisor's
// listener directory: one JSON file per profile, the same protocol+options map
// shape. A profile can then be dialed by name with `veepin connect <name>`.
//
// Subcommands:
//
//	ls          list saved profiles
//	add         create a profile from stdin
//	rm <name>   delete a profile
//
// VEEPIN_PROFILE_DIR overrides the directory, which is what the tests use and
// what lets a profile set live somewhere other than the user's config home.

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/xen0bit/veepin/internal/profile"
)

func runProfile(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: veepin profile <subcommand>\nsubcommands: ls, add, rm")
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "ls":
		return profileList(rest)
	case "add":
		return profileAdd(rest)
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
	for _, c := range cfgs {
		fmt.Printf("%-24s %s\n", c.Name, c.Protocol)
	}
	return nil
}

func profileAdd(args []string) error {
	fs := flag.NewFlagSet("profile add", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
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

func profileRm(args []string) error {
	fs := flag.NewFlagSet("profile rm", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: veepin profile rm <name>")
	}
	dir, err := profileDir()
	if err != nil {
		return err
	}
	if err := profile.Delete(dir, fs.Arg(0)); err != nil {
		return err
	}
	fmt.Printf("deleted %q\n", fs.Arg(0))
	return nil
}
