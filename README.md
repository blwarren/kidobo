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
curl -fsSL https://raw.githubusercontent.com/blwarren/kidobo/main/scripts/install.sh | sudo bash -s -- --version v0.14.1
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

- Linux x86_64 for the published static musl binary. The release artifact is
  exercised on Debian 11 and Alpine 3.22; other architectures must build from
  source and are not currently tested.
- Bash, `curl`, `tar`, `sha256sum`, and standard file-installation tools for the
  installer. GNU `realpath` is additionally required for custom-root uninstall.
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

See the [configuration guide](docs/configuration.md) for every key, default,
and limit.

Check prerequisites and system wiring before changing source state:

```bash
sudo kidobo doctor
```

Add a local entry (optional):

```bash
sudo kidobo ban 203.0.113.7
```

`ban` and `unban` change source state only. Run `sync` to change live
enforcement. See the [operations guide](docs/operations.md) for file and ASN
bans, offline lookup, the timer, and failure recovery.

Apply blocklists to `ipset` and firewall rules after any source or configuration
change:

```bash
sudo kidobo sync
```

Check whether targets match (offline):

```bash
kidobo lookup 203.0.113.7
```

Lookup is offline and reports source overlaps, not the live enforced set.
`sudo kidobo flush` removes managed firewall/ipset artifacts and remote cache;
read the [operations guide](docs/operations.md#when-a-command-fails) before
using it for recovery or uninstall.

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

Unknown configuration keys are rejected at every level so misspellings cannot
silently select defaults. IPv4 and IPv6 set names must always be distinct.
The [configuration guide](docs/configuration.md) covers all accepted keys.

## Defaults

- Config file: `/etc/kidobo/config.toml`
- Local blocklist: `/var/lib/kidobo/blocklist.txt`
- Cache dir: `/var/cache/kidobo`
- Systemd units:
  - `/etc/systemd/system/kidobo-sync.service`
  - `/etc/systemd/system/kidobo-sync.timer`

`kidobo init` creates missing files and systemd units. At default paths it
enables the one-shot sync timer. See the [operations guide](docs/operations.md)
for timer and logging details.

## More information

- [Configuration](docs/configuration.md): keys, defaults, limits, and paths.
- [Operations](docs/operations.md): routine commands, timer, logs, and recovery.
- [1.x compatibility contract](docs/compatibility.md): stable operator interfaces.

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
checks formatting, lints, dependency policy, audits, and tests. Coverage,
strict rustdoc, the isolated release-binary exercise, and static Debian/Alpine
compatibility run only during publication. The exercises use a temporary
`KIDOBO_ROOT`, a loopback HTTP feed, and fake privileged commands; they never
touch the development host's firewall or systemd. Dependabot update
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
