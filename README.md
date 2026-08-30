# kidobo

`kidobo` is a one-shot Linux firewall blocklist manager.
It builds IPv4/IPv6 blocklists from local and remote sources, subtracts
safelist entries, atomically replaces each managed `ipset`, and maintains
deterministic `iptables`/`ip6tables` wiring.

## Features

- Manages local and remote IPv4/IPv6 blocklists.
- Deduplicates, merges, and minimizes CIDR entries before enforcement.
- Carves operator-defined safe IP/CIDR ranges out of blocklists.
- Uses kernel `ipset` matching with normalized `iptables`/`ip6tables` rules.
- Supports local IP/CIDR and ASN bans through the CLI or configuration files.

## Install

Install latest release:

```bash
curl -fsSL https://raw.githubusercontent.com/blwarren/kidobo/main/scripts/install.sh | sudo bash
```

Install a specific release:

```bash
curl -fsSL https://raw.githubusercontent.com/blwarren/kidobo/main/scripts/install.sh | sudo bash -s -- --version v0.14.0
```

The command above pins the binary release while still using the installer from
the mutable `main` branch. To pin both, use the same release tag in the installer
URL and argument:

```bash
curl -fsSL https://raw.githubusercontent.com/blwarren/kidobo/vX.Y.Z/scripts/install.sh | sudo bash -s -- --version vX.Y.Z
```

Install and initialize in one step:

```bash
curl -fsSL https://raw.githubusercontent.com/blwarren/kidobo/main/scripts/install.sh | sudo bash -s -- --init
```

Uninstall:

```bash
curl -fsSL https://raw.githubusercontent.com/blwarren/kidobo/main/scripts/install.sh | sudo bash -s -- --uninstall
```

Security note: piping a script to `sudo bash` is convenient, but for a stricter
install policy, download and review a tag-pinned installer before running it.
The installer verifies the requested checksum and binary version in a staged
file before atomically replacing an existing installation.

## Requirements

- Linux x86_64 for published binaries. Other architectures must build from
  source and are not currently tested.
- `sudo`, `ipset`, and `iptables` for runtime checks and enforcement.
- `ip6tables` when IPv6 enforcement is enabled, which is the default.
- `bgpq4` for ASN resolution and for the complete `doctor` check.
- systemd only when using the generated periodic sync service and timer.

## Quick Start

Initialize the default files and generated systemd units:

```bash
sudo kidobo init
```

Configure your sources and safelist:

```bash
sudoedit /etc/kidobo/config.toml
```

Check prerequisites and system wiring before changing source state:

```bash
sudo kidobo doctor
```

Add local entries (optional):

Use commands:

```bash
sudo kidobo ban 203.0.113.7
sudo kidobo unban 203.0.113.7
sudo kidobo ban --file targets.txt
sudo kidobo unban --file targets.txt --yes
sudo kidobo ban --asn 213412
sudo kidobo unban --asn AS213412
```

`ban --asn` loads or resolves the ASN prefixes and caches them before updating
`[asn].banned`. A stale cache can be used when refresh fails. These commands
change source state only; they do not change live firewall enforcement.

Or edit the local blocklist file directly:

```bash
echo "203.0.113.0/24" | sudo tee -a /var/lib/kidobo/blocklist.txt
```

Apply blocklists to `ipset` and firewall rules after any source or configuration
change:

```bash
sudo kidobo sync
```

Check whether targets match (offline):

```bash
kidobo lookup 203.0.113.7
kidobo lookup --file targets.txt
kidobo lookup --file targets.txt --format tsv
```

Remove kidobo firewall/ipset artifacts (optional):

```bash
sudo kidobo flush
sudo kidobo flush --cache-only
```

`flush` attempts every cleanup step and exits with status `1` if any live
firewall, ipset, or cache artifact could not be removed. The installer preserves
runtime files when uninstall cleanup cannot be confirmed. An uninstall using
`KIDOBO_ROOT` requires GNU `realpath` so the installer can canonicalize and scope
every removal before cleanup begins.

## Minimal Config

`/etc/kidobo/config.toml`:

```toml
[ipset]
set_name = "kidobo"

[safe]
ips = []
include_github_meta = true
github_meta_url = "https://api.github.com/meta"

[remote]
timeout_secs = 30
urls = []

[asn]
banned = []
cache_stale_after_secs = 86400
```

Useful options:

- `ipset.set_name_v6`: optional, defaults to `<set_name>-v6`
- `ipset.enable_ipv6`: default `true`
- `ipset.chain_action`: `DROP` (default) or `REJECT`
- `ipset.maxelem`: range `[1, 500000]`
- `remote.timeout_secs`: range `[1, 3600]`
- `asn.banned`: ASN bans loaded from cache or resolved to prefixes during `sync`
- `asn.cache_stale_after_secs`: ASN prefix cache refresh threshold
  (default `86400`, range `[1, 604800]`)

Unknown configuration keys are rejected at every level so misspellings cannot
silently select defaults. IPv4 and IPv6 set names must always be distinct.

## Defaults

- Config file: `/etc/kidobo/config.toml`
- Local blocklist: `/var/lib/kidobo/blocklist.txt`
- Cache dir: `/var/cache/kidobo`
- Systemd units:
  - `/etc/systemd/system/kidobo-sync.service`
  - `/etc/systemd/system/kidobo-sync.timer`

`kidobo init` creates missing files and systemd units.
At default paths it also runs `systemctl daemon-reload` and enables
`kidobo-sync.timer`, and writes `KIDOBO_LOG_FORMAT=journal` into
`kidobo-sync.service`.
For default systemd units, `init` requires an installed `kidobo` binary at
`/usr/local/bin/kidobo` or `/usr/bin/kidobo`; it will not generate units from
an arbitrary build or `cargo run` path.

## Notes

- IP/CIDR `ban` and `unban` commands update the local blocklist. ASN bans load
  and cache prefixes before updating `[asn].banned`; ASN unbans remove the
  configuration entry and make a best-effort cache cleanup. `--file` accepts
  one strict IP/CIDR target per line. No ban or unban changes live enforcement
  before `sync`.
- `lookup` is offline-only and reports raw overlaps with the local blocklist,
  cached remote sources, configured `safe.ips`, compatible cached GitHub meta
  safelist data, and cached prefixes for currently configured ASN bans. It
  never fetches sources or invokes `bgpq4`.
- Safelist lookup rows identify exemptions; lookup does not inspect live ipset
  state or calculate the final post-safelist firewall set. Missing or invalid
  config still permits lookup against the local blocklist and cached remote
  sources. Lookup warns on stderr when config-backed coverage or a configured
  GitHub/ASN cache is unavailable.
- Lookup prints a readable results table by default, including explicit match
  status and summary counts for both single targets and files. Long source URLs
  wrap without being truncated. Use `--format tsv` for the legacy tab-separated
  output intended for scripts; color is limited to interactive terminals and
  disabled when `NO_COLOR` is set.
- `sync` canonicalizes a valid local blocklist, preserving only the leading
  comment/header section before canonical entries. Invalid non-header local
  lines now fail `sync`; they are not silently dropped or rewritten away.
- Remote responses containing only whitespace or comments are treated as an
  intentional empty feed. A non-empty response with no valid CIDRs, or GitHub
  metadata missing a selected category, is treated as a soft fetch failure and
  does not replace the last usable cache.
- Remote fetches follow at most ten redirects, and only when the destination
  keeps the configured URL's scheme, host, and effective port. A blocked
  redirect is a soft fetch failure and does not replace the last usable cache.
- Ipset replacement is atomic per set, not across both address families. IPv6
  and IPv4 are capacity-checked before either set is replaced, but their swaps
  are separate operations.
- `doctor` is read-only by default. It checks whether the remote cache path is
  structurally plausible without creating directories or writing probe files;
  plausible permissions are reported as `SKIP` because effective access is not
  mutated to prove writability.
- `KIDOBO_ROOT` relocates config, data, cache, and generated systemd paths under
  a custom root. `init` does not call `systemctl` when this override is present,
  which also makes an unprivileged isolated setup possible when the root is
  writable.

## Development

Development commands are defined in `Justfile`. See the
[development-command reference](scripts/README.md) for release and recovery
details, and the [architecture guide](docs/architecture.md) for extension
boundaries and recipes.

```bash
cargo install --locked just --version 1.55.1
just _install-cooldown _install-deny _install-audit
just check
just ci
just release-notes-check
```

`just check` is the fast development loop. Run `just ci` explicitly before every
push; GitHub does not run project CI for pushes or tags. The complete local gate
checks formatting, lints, dependency policy, audits, and tests. Coverage and the
isolated release-binary exercise run only during publication. The exercise uses
a temporary `KIDOBO_ROOT`, a loopback HTTP feed, and fake privileged commands;
it never touches the development host's firewall or systemd. Dependabot update
PRs are the only GitHub-hosted automation retained. Run
`just release-notes-check` after every repository change.

Authenticate with `gh auth login` before publishing, then run
`just publish-release X.Y.Z` from a clean branch. The publisher validates and
packages the release locally, pushes the release commit and tag atomically,
verifies the draft's downloaded assets, and only then publishes it. See the
[development-command reference](scripts/README.md) for the complete workflow
and failure recovery.

Use `just --list` to see all available local and CI recipes.

## License

MIT (see `LICENSE`).
