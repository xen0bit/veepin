package dbusplugin

// File options on a private connection are opened as if by its owner.
//
// The service runs as root, and a connection's file options -- a WireGuard
// config, an OpenVPN key, an SSH identity -- are paths it opens and uses as
// credentials. A user may create a connection private to themselves, so
// without a check they could name /etc/wireguard/wg0.conf or /root/.ssh/id_*
// and bring up a tunnel authenticated as the machine. NetworkManager's own
// plugins read such files as the connection's owner for the same reason.
//
// This is a check rather than a privilege drop: the file must be readable by
// the owner through its permission bits -- owned by them, or readable by a
// group they are in, or by everyone. A system connection (no user named in
// connection.permissions) can only be created by an administrator, and is not
// checked.
//
// What it does not cover: files that a config file itself names, such as the
// ca/cert/key an .ovpn references. Those are chosen by whoever wrote that file,
// which this check has just established is the owner, and they are opened as
// root. doc/networkmanager-plugin.md records the gap.

import (
	"fmt"
	"os"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/nm/internal/nmconfig"
)

// connectionOwner returns the user a private connection belongs to, or "" for
// a system connection. connection.permissions holds entries of the form
// "user:<name>:"; a connection visible to more than one user is checked
// against each.
func connectionOwners(settings nmconfig.Settings) []string {
	v, ok := settings["connection"]["permissions"]
	if !ok {
		return nil
	}
	perms, _ := v.Value().([]string)
	var users []string
	for _, p := range perms {
		if rest, ok := strings.CutPrefix(p, "user:"); ok {
			if name, _, _ := strings.Cut(rest, ":"); name != "" {
				users = append(users, name)
			}
		}
	}
	return users
}

// checkFileAccess refuses a file option on a private connection that its
// owners could not read themselves.
func checkFileAccess(settings nmconfig.Settings, conn nmconfig.Connection) error {
	owners := connectionOwners(settings)
	if len(owners) == 0 {
		return nil
	}
	specs, _ := client.ClientOptsFor(conn.Protocol)
	for _, sp := range specs {
		if sp.Kind != client.OptFilePath {
			continue
		}
		path := conn.Options[sp.Key]
		if path == "" {
			continue
		}
		for _, name := range owners {
			if err := userCanRead(name, path); err != nil {
				return fmt.Errorf("%s: %w", sp.Key, err)
			}
		}
	}
	return nil
}

// userCanRead reports whether name could read path by its permission bits,
// following symlinks the way open would.
func userCanRead(name, path string) error {
	u, err := user.Lookup(name)
	if err != nil {
		return fmt.Errorf("connection owner %q: %w", name, err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot read its ownership", path)
	}
	mode := fi.Mode().Perm()
	uid := strconv.FormatUint(uint64(st.Uid), 10)
	gid := strconv.FormatUint(uint64(st.Gid), 10)
	switch {
	case uid == u.Uid:
		if mode&0o400 != 0 {
			return nil
		}
	case mode&0o004 != 0:
		return nil
	case mode&0o040 != 0:
		groups, _ := u.GroupIds()
		if u.Gid == gid || slices.Contains(groups, gid) {
			return nil
		}
	}
	return fmt.Errorf("%s is not readable by the connection's owner %s", path, name)
}
