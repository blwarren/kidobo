# Operating Kidobo

Kidobo runs one command at a time; it is not a resident daemon. `sync` is the
command that changes firewall and ipset enforcement. Run the commands below on
the intended Linux host as an operator with the required privileges. For
configuration keys and paths, see [Configuration](configuration.md).

## First setup and routine changes

1. Install Kidobo using the [README instructions](../README.md#install).
2. For an interactive guided setup, run `sudo kidobo setup` from a terminal.
   Setup reviews proposed values before saving, preserves an existing
   configuration, provisions required files and units, then runs `doctor`
   before offering an initial sync. A doctor failure stops setup before sync
   or timer activation. Declining the initial sync leaves the saved
   configuration pending; it does not apply firewall changes. At default
   paths, setup separately asks whether to enable the scheduled timer; that
   choice can apply even when the initial sync was declined. With
   `KIDOBO_ROOT`, units stay under that root and no host timer is activated.
   Setup does not stop an existing active timer; that timer may apply saved
   settings while setup is running.
   Noninteractive use prints guidance and exits with usage status without
   creating files. Use `sudo kidobo init` for the existing noninteractive
   provisioning workflow; it creates missing configuration, data, cache, and
   systemd unit files without replacing existing ones. At default paths `init`
   reloads systemd and enables and starts `kidobo-sync.timer`.
3. Edit `/etc/kidobo/config.toml` and, if needed,
   `/var/lib/kidobo/blocklist.txt`.
4. Run `sudo kidobo doctor` and inspect its report. In an interactive terminal
   it groups checks into human-readable sections; when stdout is redirected or
   under systemd it keeps the JSON report. Use `--format human` or `--format
   json` to choose explicitly. `doctor` performs read-only probes. A `FAIL`
   exits with status `1`; a cache-access `SKIP` means it could not safely prove
   effective writability without writing a probe file.
5. Run `sudo kidobo sync` to load sources and apply the resulting IPv4 and IPv6
   sets and firewall rules. Run it again after any source or configuration
   change. A successful sync leaves one managed INPUT jump per enabled family at
   position 1.

To calculate a proposed sync without changing enforcement, run
`kidobo sync --dry-run`. The default preview is offline: it uses the local
blocklist, active temporary bans, validated remote-feed and ASN caches, and
cached GitHub metadata when configured. It does not fetch or refresh sources,
write normalized cache data, promote or clean caches, prune temporary entries,
or invoke firewall tools.
The preview requires an existing sync lock file and reports a clear failure
when it cannot acquire the lock or read that file. It does not create a lock
file.

`kidobo sync --dry-run --allow-network` explicitly permits remote-feed and
GitHub metadata requests and ASN resolution for that preview. Fetched or
resolved data stays in memory: the command does not stage or promote cache
generations, change saved sources, prune expired records, or touch enforcement.
Both forms apply the
normal source bounds and admission checks. A missing or unusable required
offline source, including an unavailable required ASN cache, fails the preview
rather than reporting a partial successful result.

The preview reports separate IPv4/IPv6 proposed counts and capacity outcomes.
It does not enumerate live set members, so the exact live count delta is
unavailable; proposed counts do not establish added or removed CIDRs. Preview
success does not guarantee a later sync will succeed: configuration, source
data, caches, live firewall state, and available capacity can change. The
preview does not record last-sync or freshness receipts. `--allow-network` requires
`--dry-run`; ordinary `kidobo sync` retains its existing enforcement behavior.
`sync --timer` continues to profile a real sync.

Generate shell completion scripts to stdout with `kidobo completions bash`,
`kidobo completions zsh`, or `kidobo completions fish`. Redirect the selected
script to the appropriate shell's completion directory; completion generation
does not read configuration or call system tools.

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
sync`). `sync --timer` emits per-stage timing logs. Logs always go to stderr;
command output goes to stdout. `KIDOBO_LOG_FORMAT=auto|human|journal` controls
log formatting; `auto` uses human logs on an interactive terminal and journal
fields for redirected or systemd output. `KIDOBO_LOG_COLOR=auto|always|never`
controls log colors, and `NO_COLOR` disables automatic color.

## Human-readable output and pipes

`lookup` prints labeled, streaming records and a summary by default. Its human
layout wraps to the detected terminal width, with an 80-column fallback, and
disables color when stdout is redirected, `TERM=dumb`, or `NO_COLOR` is set.
Use `kidobo lookup ... --format tsv` for scripts; TSV records and file-mode
summary remain stable when piped.

`doctor` selects grouped human output when stdout is an interactive terminal
outside systemd, and the existing JSON report when stdout is redirected or the
command runs under systemd. `--format human` and `--format json` override that
choice. The JSON report remains on stdout; diagnostics and configured logs stay
on stderr. Explicit human output remains plain text when redirected.

## Inspect live state and saved bans

Running `kidobo` with no arguments opens the read-only status view. It compares
the configured managed sets with directly observed kernel set headers and
firewall rules. Entry counts come from the validated live `ipset` header;
configured feed counts come from configuration and do not mean that feeds were
fetched or enumerated. Status also counts saved local and temporary bans. It
does not create missing files, elevate privileges, or record sync history. If
permissions or inconsistent observations prevent verification, the affected
fields remain `unknown`. `last_successful_sync` is `null` because Kidobo does
not yet persist a successful-sync receipt. With `KIDOBO_ROOT`, host systemd
timer state is unknown because the alternate root does not identify a host
timer.

Use `kidobo status --format json` for the versioned machine-readable status
report. Its `schema_version` is `1`; nullable observations distinguish missing
state from state that could not be verified. Retry with appropriate privileges
when live fields are unknown.

`sudo kidobo check 203.0.113.7` verifies one address against the corresponding
managed set and the effective Kidobo jump from `INPUT`. A verified match prints
`BLOCKED BY KIDOBO`; verified nonmembership prints `NOT BLOCKED BY KIDOBO`.
These describe Kidobo's managed incoming blocking path, not every firewall,
routing, or application policy on the host. Insufficient, conflicting, or
disabled-family evidence reports `UNKNOWN`. Known verdicts exit `0`; unknown
exits `1`; malformed input, including a CIDR, exits `2`. Use `lookup` to inspect
CIDR or saved/cached source overlaps.

The check report lists offline saved/cache overlaps in a separate
`offline_matches` field. They may be stale and never change the live verdict.
This separation is useful when saved entries have not yet been applied by
`sync`, or when another source still blocks an address after a local unban.
Use `kidobo check IP --format json` for the versioned `schema_version: 1`
report.

`kidobo bans` lists only operator-managed local IP/CIDR and ASN entries. It
does not inspect imported feeds or the live firewall. Temporary records include
expired entries awaiting cleanup; expiry is shown in UTC and a saved expiry
does not prove that `sync` has removed the kernel entry. The default display is
limited to 50 records; use `--limit N` or `--all` to change that bound. Select
`--temporary` or `--permanent` to filter by lifetime, and `--asn` to show only
ASN records. These commands are read-only and do not refresh sources or modify
enforcement.

## Check and change sources

`kidobo lookup 203.0.113.7` and `kidobo lookup --file targets.txt` inspect
local, active temporary, and compatible cached sources without network access,
ASN resolution, or firewall changes. Lookup reports raw source overlaps,
including safelist exemptions; it does not read the live ipset or calculate
the final enforced set. An invalid or missing configuration limits lookup to
the local blocklist, active temporary entries, and cached remote sources and
produces warnings for unavailable coverage.
Use `--format tsv` for scripts; see the [compatibility contract](compatibility.md)
for its record format. Results stream as targets are processed, so a large
number of overlaps does not require retaining all matches. Targets, source
labels, and matched entries escape control characters in both output formats.

Without `--for`, `sudo kidobo ban 203.0.113.7` and its `--file` form add
permanent entries to the local blocklist. A file supplies one strict IP or
CIDR target per line. Permanent `ban --asn 213412` updates `[asn].banned`;
ASN ban may resolve and cache prefixes, while ASN unban makes a best-effort
cache cleanup. Ban and unban require valid configuration and save local sources
before any enforcement work. Their interactive application behavior is
described below.
ASN arguments accept bare numbers or an `AS` prefix in any ASCII letter case,
such as `AS64496`, `as64496`, `As64496`, and `aS64496`.

When both stdin and stdout are terminals outside systemd, a changed ban or
unban asks whether to run `sync` after saving. Accepting applies the saved
source change immediately; declining leaves enforcement pending and exits
successfully. With piped or redirected output, the default is save-only and no
prompt is shown. `--no-apply` explicitly saves without offering to run sync.
`--apply` requests sync after saving and also runs it when the requested source
already matches the saved state, so it can repair enforcement. If that sync
fails, the command exits nonzero with `Source change saved; live firewall
update failed`; the saved source remains in place. Inspect the failure and run
`sudo kidobo sync` again. A failed sync can leave one address family updated
because IPv4 and IPv6 set replacements are separate.

`unban --yes` only approves removal of partially overlapping entries. It does
not request sync or accept the later application prompt. Use `unban --apply`
to apply after saving, or `unban --no-apply` to save without prompting.

Configuration can also be inspected or edited with `kidobo config show`,
`kidobo config path`, `kidobo sources`, and `kidobo allow`. These commands do
not refresh remote data. Source and allow edits save configuration only; run
`sudo kidobo sync` to apply them. `sources list` is offline. Exact canonical
allow duplicates are no-ops. A distinct allow already covered by a broader
range may be saved without expanding coverage or prompting, so the narrower
entry remains if the broader one is later removed. An allow addition that
expands coverage asks for a default-no confirmation in an interactive
terminal; pass `--yes` to approve it noninteractively. Exact canonical removal
does not carve a smaller range out of a wider saved CIDR. Configuration
display redacts URL user information and query/fragment values.

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
stores. Repeated targets that identify the same canonical network count once
in an unban request. Partial CIDR overlaps are shown and require confirmation;
`unban --yes` approves their removal. `unban --asn` removes the ASN from both
permanent and temporary ASN state. Each two-file update writes temporary state
first and permanent state second, so a failure on the second write can leave a
partial change. `flush` and `flush --cache-only` preserve the temporary-ban
file.

Full `flush` prints what it will remove and asks for confirmation in an
interactive terminal. Declining exits successfully without starting cleanup.
Use `flush --yes` to skip the prompt; noninteractive full flush runs with a
warning unless `--yes` was supplied. `flush --cache-only` never asks for
confirmation and leaves firewall and ipset state unchanged.

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
  metadata remains capped at 8 MiB. Normalized remote lists must fit within
  16 MiB, even when the HTTP body limit is higher. An oversized normalized
  refresh uses a validated fallback with a warning; without one, sync stops
  before publishing that cache or replacing either set. Fix the source or cache
  problem and rerun `sync`.
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

Exit status is `0` for success, help, version, or a declined confirmation; `1`
for runtime, `doctor`, or requested-sync failure; `2` for command-line usage
errors; and `130` for SIGINT. After SIGINT,
an active sync enforcement or full-flush cleanup section finishes its scoped
work unless an operational error prevents it. Check the final diagnostic
before deciding whether to retry.

## Uninstall safely

Do not start manual Kidobo commands while uninstall is running. At default
paths, uninstall records whether the timer is active and stops scheduling
before checking that the service has no active run or pending job. It aborts
if work is active or that state cannot be established; it never stops an
active sync. Wait for existing work to finish and retry.

The installer must complete config-aware `flush` before disabling the timer
or removing artifacts. A missing binary, invalid configuration, held lock, or
cleanup failure preserves the installed files. If uninstall fails before
artifact removal, it restarts the timer only when it was previously active
and reports any restoration failure. With `KIDOBO_ROOT`, uninstall skips host
systemd operations and applies cleanup to the selected root.
