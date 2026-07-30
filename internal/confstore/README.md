# internal/confstore

One JSON file per entity in a directory, generic over the entity type.

```
<dir>/site-a.json
<dir>/branch.json
<dir>/mgmt/          subdirectories are skipped
```

Two callers: the supervisor's listener directory and the client's saved
profiles. They arrived at the same design independently — the same name grammar,
the same strict decode, the same duplicate check, the same atomic
write-and-rename — and carried it as two near-identical copies until this
package merged them.

A stored type supplies its name and its validation:

```go
func (c Config) ConfigName() string { return c.Name }
func (c Config) Validate() error    { ... }

store := confstore.New[Config](dir, "profile", newConfig)
```

`New`'s third argument is the value each decode starts from, which is how a
field gets a non-zero default: `encoding/json` only writes what the document
carries, so anything the document omits keeps what the constructor set.

## Why the name grammar lives here

An entity's name *is* its filename, so it is the one field that reaches the
filesystem. `ValidName` is the single definition of what may do that:
`[a-z0-9][a-z0-9-]{0,31}`. It is also safe as an iptables `--comment` value,
which the supervisor depends on — it tags every rule `veepin:<name>` and deletes
by that tag, so a name needing quotes would be a name the teardown could not
match.

## Durability

`Write` is temp file → write → **fsync** → close → rename. The fsync is what
makes the rename mean anything: without it a crash between the two can leave the
new name pointing at a file whose contents never reached the disk, which for a
listener config is a listener that will not parse on the next boot.

## Caveats

**The directory is not fsynced, only the file.** A crash immediately after
`rename` can lose the directory entry on some filesystems even though the data
is durable. Closing that would mean opening and syncing the directory fd on
every write; for config files an operator can rewrite, it has not been judged
worth it.

**No locking.** Two processes writing the same directory can interleave: each
individual file lands atomically, but a `LoadDir` racing a `Write` sees a
consistent old or new file with no guarantee about which. One supervisor per
directory is assumed and not enforced.

**`DisallowUnknownFields` makes config forward-incompatible.** A file written by
a newer veepin carrying a field this build does not know fails to parse rather
than ignoring it. That is deliberate — silently dropping an operator's setting is
worse — but it means a downgrade breaks on configs the upgrade wrote.

**`LoadDir` fails whole rather than partially.** One malformed file makes the
entire directory unreadable, so a typo in `branch.json` stops `site-a.json`
loading too. The alternative — skipping the bad file — starts a fleet that
silently differs from what is on disk.
