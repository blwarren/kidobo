# Operating Kidobo

Kidobo runs one-shot commands. `sync` applies saved sources to firewall and
ipset enforcement; `flush` removes managed enforcement. Run the commands below
on the intended Linux host with the required privileges. For configuration keys
and paths, see [Configuration](configuration.md).

File inputs, including `--file` target lists, configuration, local sources, and
caches, must resolve to regular files. Symlinks to regular files are supported;
named pipes, sockets, directories, and devices are rejected. Save streamed
input to a regular file before passing its path to Kidobo.

## First setup

Install Kidobo using the [README instructions](../README.md#install), then run
the guided setup in a terminal:

```bash
sudo kidobo setup
```

Setup starts from your existing configuration, reviews choices before saving,
provisions missing files and units, then runs `doctor`. A doctor failure stops
setup before it offers an initial sync or timer activation.

The initial sync and scheduled timer have separate confirmations. Declining
the initial sync skips that immediate application, but enabling the timer can
still apply saved settings later. Setup leaves an existing active timer
running, so it may apply settings while setup is in progress. Under
`KIDOBO_ROOT`, unit files stay in that root and no host timer is activated.

### Noninteractive provisioning

`setup` requires terminal input and output; otherwise it exits with usage
status without creating files. For automation, use:

```bash
sudo kidobo init
```

`init` creates missing configuration, data, cache, and systemd unit files
without replacing existing files. At default paths it immediately reloads
systemd and enables and starts `kidobo-sync.timer`. Prepare your intended
configuration before activating scheduling. See [scheduling](#scheduling) for
how to pause automatic runs while making changes.

## Apply routine changes

Edit `/etc/kidobo/config.toml` and, if needed,
`/var/lib/kidobo/blocklist.txt`, or use the [configuration commands](#manage-feeds-and-exemptions).
Check the configuration and prerequisites:

```bash
sudo kidobo doctor
```

`doctor` performs read-only probes: a `FAIL` exits with status `1`; a cache-access
`SKIP` means it could not
safely prove effective writability without writing a probe file. See
[output formats](#logs-and-output-formats) for human and JSON reports.

After reviewing the report and resolving failures, apply the changes:

```bash
sudo kidobo sync
```

Repeat sync after source or configuration changes. A successful sync replaces
the enabled families' sets and leaves one managed `INPUT` jump per enabled
family at position 1. Use [status and check](#inspect-live-state-and-saved-bans)
to verify the result.

## Preview a sync

To calculate proposed counts without changing enforcement, run:

```bash
sudo kidobo sync --dry-run
```

The default preview is offline: it uses the local blocklist, active temporary
bans, validated remote-feed and ASN caches, and
cached GitHub metadata when configured. It does not fetch or refresh sources,
write normalized cache data, promote or clean caches, prune temporary entries,
or invoke firewall tools.

The preview requires an existing sync lock file, created by setup or init, and
does not create one itself. A root-owned lock hardened by a mutating command
is readable only by root, so use `sudo` for a normal system installation. If
the lock is held by another command, wait for that command to finish and retry.

`sudo kidobo sync --dry-run --allow-network` explicitly permits remote-feed and
GitHub metadata requests and ASN resolution for that preview. Fetched or
resolved data stays in memory: the command does not stage or promote cache
generations, change saved sources, prune expired records, or touch enforcement.
Both forms apply the normal source bounds and admission checks. A missing or
unusable required offline source, including an unavailable required ASN cache,
fails the preview rather than reporting a partial successful result.

The preview reports separate IPv4/IPv6 proposed counts and capacity outcomes.
It does not enumerate live set members, so the exact live count delta is
unavailable; proposed counts do not establish added or removed CIDRs. Preview
success does not guarantee a later sync will succeed: configuration, source
data, caches, live firewall state, and available capacity can change. The
preview does not record last-sync or freshness receipts. `--allow-network`
requires `--dry-run`. The separate `sync --timer` option profiles a real sync
and cannot be combined with `--dry-run`.

## Scheduling

At default paths, `init` requires an installed binary at
`/usr/local/bin/kidobo` or `/usr/bin/kidobo` for its generated service.
The generated `Type=oneshot` service runs `kidobo sync`; its timer starts two
minutes after boot and schedules another run one hour after the service was
last active. The timer is persistent. The generated service writes journal
format logs. To inspect scheduling and the most recent service run, use:

```bash
systemctl status kidobo-sync.timer
systemctl status kidobo-sync.service
```

To pause automatic runs, including across a reboot:

```bash
sudo systemctl disable --now kidobo-sync.timer
```

This leaves existing enforcement in place and does not stop an active sync.
Wait for any active service or manually started sync to finish before making
changes that must remain unapplied. Re-enable scheduling when ready:

```bash
sudo systemctl enable --now kidobo-sync.timer
```

Enabling the timer authorizes subsequent syncs to apply saved settings. To
remove existing enforcement as well, follow [managed cleanup](#remove-managed-enforcement).

## Logs and output formats

Read diagnostics from scheduled runs with:

```bash
journalctl -u kidobo-sync.service
```

Manual runs accept `--log-level` (for example, `sudo kidobo --log-level debug
sync`). `sync --timer` emits per-stage timing logs. Logs always go to stderr;
command output goes to stdout. `KIDOBO_LOG_FORMAT=auto|human|journal` controls
log formatting; `auto` uses human logs on an interactive terminal and journal
fields for redirected or systemd output. `KIDOBO_LOG_COLOR=auto|always|never`
controls log colors, and `NO_COLOR` disables automatic color.

### Human-readable output and pipes

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

## Find offline source matches

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

## Add and remove bans

### Permanent bans and immediate application

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

### Temporary bans

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
enforcement, and another source can continue to block the same address.
After a fully successful enforcement run, Kidobo
best-effort removes expired records. Failed enforcement can leave one address
family updated because IPv4 and IPv6 set replacements are separate.

With a nonzero `ipset.timeout`, the kernel timeout remains in force for every
set entry. Kidobo warns when adding or renewing a temporary ban and during a
sync with active temporary entries, because kernel expiry can remove it before
the recorded deadline.

### Remove a ban

`unban` removes matching entries from both the permanent and temporary local
stores. Repeated targets that identify the same canonical network count once
in an unban request. Partial CIDR overlaps are shown and require confirmation;
`unban --yes` approves their removal. `unban --asn` removes the ASN from both
permanent and temporary ASN state. Each two-file update writes temporary state
first and permanent state second, so a failure on the second write can leave a
partial change. `flush` and `flush --cache-only` preserve the temporary-ban
file.

## Manage feeds and exemptions

Use `kidobo sources list`, `kidobo allow list`, and `kidobo config show` to
inspect saved configuration. `kidobo config path` locates the file, including
before initialization. To save a feed or exemption:

```bash
sudo kidobo sources add https://example.org/feed.txt
sudo kidobo allow add 203.0.113.7
```

Replace the example URL with your chosen feed. Additions that expand safelist
coverage require confirmation; use `--yes` when approving one in automation.
Source and allow edits do not fetch data or change enforcement. Run
`sudo kidobo sync` to apply them. See [configuration management](configuration.md#managing-configured-sources-and-exemptions)
for removal rules, overlapping exemptions, and redacted configuration display.

## Shell completions

Generate shell completion scripts with `kidobo completions bash`,
`kidobo completions zsh`, or `kidobo completions fish`. For a Bash session:

```bash
kidobo completions bash > kidobo.bash
source ./kidobo.bash
```

For persistent installation, put the generated script in your shell's completion
directory. Generation writes only to stdout and does not read configuration or
call system tools. Regenerate and reinstall the script after upgrading Kidobo to
pick up completion changes.

File arguments support path completion, including paths with spaces in Bash.
Zsh also supports URL completion. Filename suggestions are suppressed for
non-path arguments where supported. Fish's generated script omits positional
suggestions, including shell names after `kidobo completions`.

## Remove managed enforcement

`sudo kidobo flush` removes managed firewall rules, ipsets, and remote cache.
It preserves configuration and saved bans. It also leaves scheduling active:
the next timer-driven sync can recreate enforcement. To keep enforcement
removed, [disable scheduling](#scheduling), wait for active syncs to finish,
then flush. To restore enforcement, run `sudo kidobo sync` and re-enable the
timer if you want automatic runs.

Full `flush` prints what it will remove and asks for confirmation in an
interactive terminal. Declining exits successfully without starting cleanup.
Use `flush --yes` to skip the prompt; noninteractive full flush runs with a
warning unless `--yes` was supplied. `sudo kidobo flush --cache-only` never
asks for confirmation and leaves firewall and ipset state unchanged.

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
or removing artifacts. `--uninstall` authorizes this cleanup; the installer runs
its internal flush with noninteractive input and no additional confirmation,
including when uninstall is started from a terminal. Cleanup output and failures
remain visible. Standalone interactive `kidobo flush` still asks for confirmation.
A missing binary, invalid configuration, held lock, or
cleanup failure preserves the installed files. If uninstall fails before
artifact removal, it restarts the timer only when it was previously active
and reports any restoration failure. With `KIDOBO_ROOT`, uninstall skips host
systemd operations and applies cleanup to the selected root.
