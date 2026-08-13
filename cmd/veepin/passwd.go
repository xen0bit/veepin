package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/xen0bit/veepin/internal/userdb"
)

// runPasswd prints a bcrypt verifier for a password, in the form a users-file
// holds. It exists so the feature is self-contained: a credentials file that
// can hold a hash is no use to an operator with no way to produce one, and
// "install apache2-utils and run htpasswd -B" is a poor answer for a binary
// with no runtime dependencies.
//
// The output is the same $2a$ string htpasswd -B emits, deliberately: the
// format is not veepin's, and an operator who already has a hash from
// somewhere else should be able to paste it in.
//
// The password is read from the terminal rather than taken as an argument.
// Taking it as an argument would put it in the process table and the shell
// history, which is the whole of item 7 — and a tool whose purpose is to keep
// the password off disk should not be the thing that leaks it.
func runPasswd(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("usage: veepin passwd  (the password is read from stdin, not the command line, " +
			"so it does not land in the process table or the shell history)")
	}

	fmt.Fprint(os.Stderr, "password: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return fmt.Errorf("passwd: reading the password: %w", err)
	}
	// Only the line terminator comes off. A password with leading or trailing
	// spaces is a password, and trimming it here would hash something the user
	// will never type again.
	password := strings.TrimRight(line, "\r\n")
	fmt.Fprintln(os.Stderr)
	if password == "" {
		return fmt.Errorf("passwd: the password is empty")
	}

	hash, err := userdb.Hash(password)
	if err != nil {
		return err
	}
	fmt.Println(hash)
	return nil
}
