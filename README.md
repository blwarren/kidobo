# kidobo

`kidobo` is a one-shot Linux firewall blocklist manager.
It builds IPv4/IPv6 blocklists from local and remote sources, subtracts
safelist entries, and updates `ipset` atomically with deterministic
`iptables`/`ip6tables` wiring.

## Features

- Easily manage and update both local and remote IP/CIDR blocklists.
- Utilizes ipset to harness the efficiency of the Linux kernel in enforcing blocklists.
- Automatic dedupe and consolidation of blocklists before ipset creation.
- Sync happens **fast**: in testing on a Linode Nanode (Single core CPU VM with 1 GB RAM)
  updates involving multiple blocklists totalling 400,000 lines happen in less than
  five seconds.
- Stay in control: identify safe IP's that are carved out of blocklists.
- Local blocklist entries can be managed through manual editing of text
  file or through use of CLI ban/unban commands.

## Install

Release binaries are currently published for Linux x86_64.

No testing has been performed on other CPU architectures, but feel free to run the test suite and build from source when using this on other platforms.

Install latest release:

```bash
curl -fsSL https://raw.githubusercontent.com/blwarren/kidobo/main/scripts/install.sh | sudo bash
```

Install a specific release:

```bash
curl -fsSL https://raw.githubusercontent.com/blwarren/kidobo/main/scripts/install.sh | sudo bash -s -- --version v0.12.1
```

Install and initialize in one step:

```bash
curl -fsSL https://raw.githubusercontent.com/blwarren/kidobo/main/scripts/install.sh | sudo bash -s -- --init
```

Uninstall:

```bash
curl -fsSL https://raw.githubusercontent.com/blwarren/kidobo/main/scripts/install.sh | sudo bash -s -- --uninstall
```

Security note: piping a script to `sudo bash` is convenient, but you should
review the script (and pin a version) if you need a stricter install policy.
The installer verifies the requested checksum and binary version in a staged
file before atomically replacing an existing installation.

## Quick Start

Initialize default files and (optionally) systemd units:

```bash
sudo kidobo init
```

Configure your sources and safelist:

```bash
sudoedit /etc/kidobo/config.toml
```

Add local entries (optional):

Use commands:

```bash
kidobo ban 203.0.113.7
kidobo unban 203.0.113.7
kidobo ban --file targets.txt
kidobo unban --file targets.txt --yes
kidobo ban --asn 213412
kidobo unban --asn AS213412
```

Or edit the local blocklist file directly:

```bash
echo "203.0.113.0/24" | sudo tee -a /var/lib/kidobo/blocklist.txt
```

Check prerequisites and system wiring:

```bash
sudo kidobo doctor
```

Apply blocklists to `ipset` and firewall rules:

```bash
sudo kidobo sync
```

Re-apply after local blocklist changes:

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
runtime files when uninstall cleanup cannot be confirmed.

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
- `asn.banned`: ASN bans that are resolved to prefixes during `sync`
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

- `ban` and `unban` modify local source state only:
  blocklist entries for IP/CIDR targets and config `[asn].banned` for ASN targets.
  `--file` accepts one strict IP/CIDR target per line.
  Run `sync` to apply changes to firewall/ipset runtime state.
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
- `doctor` is read-only by default. It checks whether the remote cache path is
  structurally plausible without creating directories or writing probe files;
  plausible permissions are reported as `SKIP` because effective access is not
  mutated to prove writability.
- `KIDOBO_ROOT` relocates config/data/cache paths under a custom root.

## Development

Development commands are defined in `Justfile`.

```bash
cargo install --locked just --version 1.55.1
rustup component add llvm-tools-preview
cargo install --locked cargo-llvm-cov --version 0.8.4
just check
just ci
just coverage
just release-notes-check
just verify-release
```

Run `just verify-release` before initiating a release. The publisher enforces
the same gate before preparing release state. Publish from any clean branch;
the command switches to `main`
automatically and verifies that it is not behind or diverged from `origin/main`:

```bash
just publish-release 0.11.0
```

The command verifies release readiness, prepares the release in a temporary
worktree, validates the candidate, displays the complete release diff, and asks
for confirmation before atomically pushing the release commit and tag.
After publication, the working tree remains on the updated `main` branch.
If validation fails or publication is cancelled, the command restores the
branch from which it was started.

Use `just --list` to see all available local and CI recipes.

## License

MIT (see `LICENSE`).
