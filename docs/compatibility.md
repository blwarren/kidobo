# Operator interfaces and compatibility

Kidobo is currently pre-1.0. The command, output, and path descriptions below
document the current implementation. The compatibility guarantee across
releases begins with 1.0; it does not apply to 0.x releases. Consult the
[release notes](../CHANGELOG.md) before upgrading.

## Compatibility policy for 1.x

Kidobo 1.x keeps the documented operator contract compatible until 2.0. Minor
releases may add commands, options, configuration keys, or output fields where
the existing format permits extension. Security tightening may reject inputs
that were previously accepted, but the change must be called out in release
notes.

The compatibility-sensitive surface includes:

- The documented root status view, `status`, `check`, `bans`, `init`, `doctor`,
  `sync`, `flush`, `lookup`, `ban`, `unban`, `setup`, `sources`, `allow`,
  `config`, and `completions` commands and their documented options.
- Exit status `0` for success, help, and version; `1` for runtime or check
  failure; `2` for usage errors; and `130` for SIGINT.
- Existing configuration keys, accepted value types, and defaults. Unknown
  keys remain errors; additions in minor releases receive documented defaults.
- Default paths under `/etc/kidobo`, `/var/lib/kidobo`, and
  `/var/cache/kidobo`, plus the documented `KIDOBO_ROOT` relocation.
- Existing permanent `ban` and `unban` forms remain available. `ban --for`
  adds temporary IP/CIDR or ASN bans in a separate versioned state file;
  `init` preserves existing temporary state and `doctor` validates it
  read-only. Temporary records use absolute Unix expiry times and become
  effective through the existing one-shot `sync` workflow.
- The `kidobo-sync.service` and `kidobo-sync.timer` names, paths, and one-shot
  timer model. A 1.x release will not turn Kidobo into a resident daemon.
- Installer checksum and version verification, in-place upgrades, and the rule
  that uninstall removes artifacts only after config-aware live cleanup
  succeeds.
- Readability of cache generations written by earlier 1.x releases. New 1.x
  writers may use newer compatible generations while retaining bounded legacy
  readers; rejected or corrupt cache data is never selected.

## Read-only inspection commands

Running `kidobo` without a subcommand is compatible with `kidobo status` and
opens the read-only status view. `status` and `check` use versioned JSON when
`--format json` is selected; their reports identify `schema_version: 1`. Status
separates configured feed count from validated live `ipset` header entry
counts. `last_successful_sync` remains `null` until Kidobo has a persisted
success receipt. Missing observations remain null or `unknown`; they are not
reported as zero or inferred from configuration.

`check IP` accepts one IPv4 or IPv6 address, not a CIDR. Its verdict is
`blocked`, `not_blocked`, or `unknown` for Kidobo's managed incoming `INPUT`
path only. Verified blocked and not-blocked results exit `0`, unknown exits
`1`, and invalid syntax exits `2`. The optional `offline_matches` list contains
separate saved/cache overlap evidence and cannot change the live verdict.

`bans` is a read-only inventory of locally saved operator-managed entries. Its
default display limit is 50; `--limit N` and `--all` adjust that bound.
`--temporary`, `--permanent`, and `--asn` filter the inventory. Temporary
records include expired entries until normal cleanup and show absolute expiry
times in UTC. Listing saved state does not imply it is currently enforced.

## Source changes and cleanup confirmation

`ban` and `unban` save local source state first. When both stdin and stdout are
terminals outside systemd, a changed request asks whether to run `sync` after
the save. Declining leaves enforcement pending. Piped or redirected runs save
without prompting or syncing by default. `--no-apply` explicitly selects that
save-only behavior; `--apply` explicitly requests sync, including when there is
no source change. If the requested sync fails, the command returns a runtime
failure while retaining the saved source. Operators can retry with `kidobo
sync`; the existing IPv4/IPv6 partial-update boundary still applies.

`unban --yes` approves only removal of partial overlaps and never approves
sync. In an interactive session, the later sync question remains independent.

`sources` and `allow` inspect or edit saved configuration only. They do not
fetch remote feeds, refresh caches, or update firewall enforcement. Exact
canonical allow duplicates are no-ops. A distinct allow target already
covered by a broader exemption can be saved without expanding coverage or
confirmation. Adding an allow range that expands exemption coverage requires
an interactive default-no confirmation or `--yes`; exact canonical removal
does not split a wider saved range. `config show` redacts URL user information
and query/fragment values. `config path` reports the selected path without
creating the file.

`setup` is an interactive terminal workflow. When stdin or stdout is not a
terminal, it prints guidance and exits with usage status without writing setup
files. Its final review precedes configuration writes, existing configuration
is preserved, and the initial sync is a separate confirmation after
provisioning and a successful `doctor` run. `init` remains available for the
existing provisioning interface. At default paths, setup asks separately
whether to enable the scheduled timer after the initial-sync choice; under
`KIDOBO_ROOT`, unit files are kept under that root and no host timer is
activated. Existing active timers remain active during setup and may apply
saved settings before the wizard completes.

`sync --dry-run` is a read-only preview that calculates proposed family counts
and capacity outcomes. It is offline by default and requires the existing sync
lock file. `sync --dry-run --allow-network` explicitly permits feed and GitHub
metadata requests and ASN resolution but still keeps results in memory and does
not promote or clean caches, prune temporary entries, or alter enforcement.
`--allow-network` without `--dry-run` is a usage error. Preview does not enumerate live set
members, so its exact live delta is unavailable; no last-sync or freshness
receipt is inferred. Preview output is human-oriented and has no JSON contract.

`completions bash|zsh|fish` writes the selected shell completion script to
stdout without loading configuration or invoking system tools.

Full `flush` asks for confirmation on an interactive terminal. Declining exits
successfully without cleanup. `flush --yes` skips that prompt; noninteractive
full flush remains available and warns about the removal unless `--yes` is
provided. `flush --cache-only` remains confirmation-free and does not change
firewall or ipset state.

## Machine-readable lookup output

`lookup --format tsv` keeps its current records:

- A match is `target<TAB>source<TAB>matched-entry`.
- File-mode misses are `target<TAB>NO_MATCH`.
- File mode ends with
  `summary: total_ips=N matched_ips=N matched_pct=N%`.
- Single-target misses retain the existing empty stdout behavior.

Target identity and source text remain raw inside core lookup. At the human
and TSV output boundaries, targets, source labels, and matched entries are
encoded exactly once so they cannot add terminal commands, fields, or records:

- backslash: `\\`
- tab, carriage return, and newline: `\t`, `\r`, and `\n`
- other ASCII controls: `\xNN` with two uppercase hexadecimal digits
- non-ASCII control code points: `\u{…}` with uppercase hexadecimal digits

Printable text, including printable Unicode, is unchanged.

## Published artifact

The supported archive remains named `kidobo-vX.Y.Z-linux-x86_64.tar.gz`. It
contains a static `x86_64-unknown-linux-musl` executable tested on Debian 11 and
Alpine 3.22. Static linking does not remove operational dependencies: the
installer requires Bash and its documented command-line tools, firewall
operations require `ipset` and `iptables`/`ip6tables`, ASN refresh requires
`bgpq4`, and generated periodic execution requires systemd.
