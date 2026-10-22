# Operating Kidobo

Kidobo runs one command at a time; it is not a resident daemon. `sync` is the
command that changes firewall and ipset enforcement. Run the commands below on
the intended Linux host as an operator with the required privileges. For
configuration keys and paths, see [Configuration](configuration.md).

## First setup and routine changes

1. Install Kidobo using the [README instructions](../README.md#install).
2. Run `sudo kidobo init`. It creates missing configuration, data, cache, and
   systemd unit files without replacing existing ones. At default paths it
   reloads systemd and enables and starts `kidobo-sync.timer`.
3. Edit `/etc/kidobo/config.toml` and, if needed,
   `/var/lib/kidobo/blocklist.txt`.
4. Run `sudo kidobo doctor` and inspect its JSON `overall` and `checks` values.
   `doctor` performs read-only probes. An `overall` value of `FAIL` exits with
   status `1`; a cache-access `SKIP` means it could not safely prove effective
   writability without writing a probe file.
5. Run `sudo kidobo sync` to load sources and apply the resulting IPv4 and IPv6
   sets and firewall rules. Run it again after any source or configuration
   change. A successful sync leaves one managed INPUT jump per enabled family at
   position 1.

At default paths, `init` requires an installed binary at
`/usr/local/bin/kidobo` or `/usr/bin/kidobo` for its generated service.
The generated `Type=oneshot` service runs `kidobo sync`; its timer starts two
minutes after boot and schedules another run one hour after the service was
last active. The timer is persistent. The generated service writes journal
format logs. To inspect scheduled runs and their diagnostics, use:

```bash
systemctl status kidobo-sync.timer
systemctl status kidobo-sync.service
journalctl -u kidobo-sync.service
```

Manual runs accept `--log-level` (for example, `sudo kidobo --log-level debug
sync`). `sync --timer` emits per-stage timing logs. Logs go to stderr; `doctor`
prints its JSON report to stdout.

## Check and change sources

`kidobo lookup 203.0.113.7` and `kidobo lookup --file targets.txt` inspect
local, active temporary, and compatible cached sources without network access,
ASN resolution, or firewall changes. Lookup reports raw source overlaps,
including safelist exemptions; it does not read the live ipset or calculate
the final enforced set. An invalid or missing configuration limits lookup to
the local blocklist, active temporary entries, and cached remote sources and
produces warnings for unavailable coverage.
Use `--format tsv` for scripts; see the [compatibility contract](compatibility.md)
for its record format.

Without `--for`, `sudo kidobo ban 203.0.113.7` and its `--file` form add
permanent entries to the local blocklist. A file supplies one strict IP or
CIDR target per line. Permanent `ban --asn 213412` updates `[asn].banned`;
ASN ban may resolve and cache prefixes, while ASN unban makes
a best-effort cache cleanup. `unban --yes` skips confirmation where removal
would require it. All ban and unban modes require valid configuration and none
changes enforcement until `sudo kidobo sync` succeeds.

Add an expiring local ban with `sudo kidobo ban 203.0.113.7 --for 12h`,
`sudo kidobo ban --file targets.txt --for 3d`, or
`sudo kidobo ban --asn AS64496 64497 --for 7d`. Durations are positive whole
numbers followed by `h` or `d` (case insensitive); whitespace around the
duration is ignored and one day is 24 hours. The expiry clock starts when the
validated change is saved, after ASN resolution when that is required. Banning
an already temporary entry replaces its deadline, even when the new deadline
is sooner. A permanent exact duplicate is kept permanent and cannot be
downgraded by a temporary request. Omitting `--for` keeps the existing
permanent-ban behavior. A later permanent ban of a temporary target adds it
to the permanent source and leaves its temporary record to expire naturally.

Temporary IP/CIDR and ASN entries are stored in
`/var/lib/kidobo/temporary-bans.toml`; they do not alter the blocklist or
`[asn].banned`. `sync` takes the active/expired snapshot after acquiring its
lock. An entry is active when its expiry is later than that cutoff, and a
source edit becomes eligible at the next sync. A ban that expires before its
first sync is never enforced. Expiration takes effect when a later sync
successfully replaces the relevant set; delayed or failed syncs can prolong
enforcement, and another source can continue to
block the same address. After a fully successful enforcement run, Kidobo
best-effort removes expired records. Failed enforcement can leave one address
family updated because IPv4 and IPv6 set replacements are separate.

With a nonzero `ipset.timeout`, the kernel timeout remains in force for every
set entry. Kidobo warns when adding or renewing a temporary ban and during a
sync with active temporary entries, because kernel expiry can remove it before
the recorded deadline.

`unban` removes matching entries from both the permanent and temporary local
stores. Partial CIDR overlaps are shown and require confirmation; `unban --yes`
approves their removal. `unban --asn` removes the ASN from both permanent and
temporary ASN state. Each two-file update writes temporary state first and
permanent state second, so a failure on the second write can leave a partial
change. `flush` and `flush --cache-only` preserve the temporary-ban file.

## When a command fails

- **Configuration or prerequisite failure:** Read the specific `doctor` check
  or command error. Correct the file or missing prerequisite, rerun `doctor`,
  then run `sync`. Unknown configuration keys and invalid non-header local
  blocklist lines fail rather than being silently ignored.
- **Remote feed or GitHub metadata warning:** A failed fetch, invalid nonempty
  response, or rejected redirect does not replace good cache data. Redirects
  are limited to ten hops and the configured URL's origin. Kidobo
  warns and uses a compatible validated cache when available. A whitespace-
  or comment-only remote response is an intentional empty feed. If cache
  staging fails and no validated fallback exists, sync stops before replacing
  either set. Remote HTTP bodies default to an 8 MiB limit; the
  `KIDOBO_MAX_HTTP_BODY_BYTES` override is capped at 32 MiB, while GitHub
  metadata remains capped at 8 MiB. Fix the source or cache problem and rerun
  `sync`.
- **ASN refresh warning:** A stale cached prefix list can be used when refresh
  fails. Check `bgpq4` and source connectivity, then rerun `sync` after fixing
  the cause.
- **Temporary-ban failure:** Check the temporary state with `kidobo doctor`.
  A missing file means no temporary bans; unreadable or malformed state stops
  sync before set replacement. If an unban reports a partially completed
  update, inspect its diagnostic and rerun the unban command.
- **Kernel-timeout warning:** A nonzero `ipset.timeout` can remove kernel
  entries before their saved expiry. Use `0` if entries should remain until
  a sync applies their removal.
- **Capacity or enforcement failure:** Sync checks every enabled family's
  `maxelem` before swapping either set. A later ipset or firewall error can
  leave an incomplete update; inspect the error and current managed state
  before retrying. The two family swaps are separate, and Kidobo establishes
  new firewall enforcement before removing old wiring.
- **Cleanup failure:** `sudo kidobo flush` attempts managed firewall/ipset and
  remote-cache cleanup and returns `1` if required cleanup remains incomplete.
  `sudo kidobo flush --cache-only` clears only the remote cache and leaves
  firewall/ipset state unchanged. Treat `flush` as a removal operation, not a
  diagnostic. If uninstall cannot confirm config-aware live cleanup, the
  installer retains the binary and runtime files; inspect the failure before
  attempting uninstall again.

Exit status is `0` for success, help, or version; `1` for runtime or `doctor`
failure; `2` for command-line usage errors; and `130` for SIGINT. After SIGINT,
an active sync enforcement or full-flush cleanup section finishes its scoped
work unless an operational error prevents it. Check the final diagnostic
before deciding whether to retry.
