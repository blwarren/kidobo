# kidobo

Kidobo is a command-line tool for managing IP blocklists on Linux servers. It
combines a local blocklist with configured remote feeds and ASN prefixes,
removes safelisted addresses, and loads the result into a managed IPv4 `ipset`
and, when enabled, an IPv6 `ipset`. Managed `iptables` rules apply the IPv4 set
to incoming traffic; `ip6tables` does the same for IPv6 when enabled.

Kidobo runs once per command. It does not run a background process; the
optional systemd timer invokes `sync` periodically. Editing source files or
configuration alone does not change the firewall; `sync` applies those changes.

## How synchronization works

- Kidobo validates configuration, loads local entries, configured HTTP feeds,
  and ASN prefixes, then computes separate IPv4 and IPv6 blocklists.
- It merges overlapping entries, subtracts configured safelist ranges,
  and produces a minimal set of CIDRs for each family.
- It checks both enabled families against their configured capacity before
  replacing either set. Each `ipset` replacement is atomic; the IPv4 and IPv6
  replacements are separate operations.
- It establishes new firewall enforcement before removing old managed rules.
  A failed source refresh uses a compatible validated cache when available;
  errors that prevent a safe update stop `sync` with a nonzero exit status.

Kidobo creates a managed chain for each enabled family and a jump to it from
`INPUT`. `doctor` checks the host without changing firewall state, and `lookup`
examines local and cached sources without contacting the network or reading
live firewall state.

## Install

Install the latest release:

```bash
curl -fsSL https://raw.githubusercontent.com/blwarren/kidobo/main/scripts/install.sh | sudo bash
```

To install a specific binary release:

```bash
curl -fsSL https://raw.githubusercontent.com/blwarren/kidobo/main/scripts/install.sh | sudo bash -s -- --version v0.15.0
```

That command pins the binary but retrieves the installer from the mutable
`main` branch. To use the installer from the same release, substitute a release
tag in both places:

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

For a controlled server deployment, download and review a tag-pinned installer
before running it with elevated privileges. The installer checks the selected
archive's checksum and the staged binary's version before replacing an
existing installation.

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

## Quick start

For an interactive first-run guide, start setup in a terminal:

```bash
sudo kidobo setup
```

Setup reviews configuration before saving, provisions missing files, and runs
`doctor`. It asks separately whether to run an initial sync and enable the
scheduled timer. Enabling the timer can apply saved settings even if you decline
the initial sync. An already active timer keeps running during setup.

For noninteractive provisioning, `sudo kidobo init` creates missing files and
immediately enables scheduling at default paths. See [setup and
scheduling](docs/operations.md#first-setup) before using it in automation.

### Configure sources

Configure your sources and safelist either in the TOML file or with the
configuration commands:

```bash
sudoedit /etc/kidobo/config.toml
sudo kidobo sources list
sudo kidobo allow list
sudo kidobo config show
```

`kidobo sources add URL` and `kidobo sources remove URL` edit configured feed
URLs. `kidobo allow add IP_OR_CIDR` and `kidobo allow remove IP_OR_CIDR` edit
the safelist. These commands save configuration only; run `sudo kidobo sync`
to apply source changes. `config show` redacts URL credentials and query or
fragment values.

See the [configuration guide](docs/configuration.md) for every key, default,
and limit.

Check configuration and host prerequisites:

```bash
sudo kidobo doctor
```

Add a local entry without requesting immediate enforcement (optional):

```bash
sudo kidobo ban 203.0.113.7 --no-apply
```

`ban` and `unban` save source changes first. In an interactive terminal they
offer to run `sync`; `--apply` requests it explicitly, and `--no-apply` saves
without prompting. A scheduled sync can also apply saved changes. See
[ban management](docs/operations.md#add-and-remove-bans) for temporary, file,
and ASN bans.

### Preview and apply

Preview proposed counts and capacity without changing enforcement:

```bash
sudo kidobo sync --dry-run
```

The preview stays offline and uses validated caches. It requires the existing
lock file created by setup or init; `sudo` allows it to read a root-owned lock.
If required cached sources are unavailable, use
`sudo kidobo sync --dry-run --allow-network` to allow feed, GitHub metadata,
and ASN requests with results kept in memory. A successful preview does not
guarantee a later sync, because inputs and live state can change.

Apply the configured blocklists. Repeat this after changing sources or
configuration:

```bash
sudo kidobo sync
```

### Verify the result

Inspect live enforcement and check one address:

```bash
sudo kidobo status
sudo kidobo check 203.0.113.7
```

`check` reports whether Kidobo's managed incoming path blocks the address. It
reports `UNKNOWN` when it cannot verify that path. Running `kidobo` without a
subcommand also opens the status view.

Inspect saved bans and offline source overlaps:

```bash
kidobo bans
kidobo lookup 203.0.113.7
```

`bans` lists operator-managed entries; `lookup` reports local and cached source
overlaps. Neither establishes live enforcement. For cleanup, read
[removing managed enforcement](docs/operations.md#remove-managed-enforcement)
or [uninstalling safely](docs/operations.md#uninstall-safely).

Generate a completion script with `kidobo completions bash`,
`kidobo completions zsh`, or `kidobo completions fish`; the selected script is
written to stdout.

## Minimal configuration

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

The initial configuration has no remote blocklist URLs or ASN bans. Add the
sources you intend to enforce. Unknown keys are rejected, and IPv4 and IPv6
set names must be distinct.
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
- [Compatibility](docs/compatibility.md): current interfaces and the 1.x policy.
- [Release history](CHANGELOG.md): changes to released versions.
- [Security policy](SECURITY.md): supported versions and private vulnerability reporting.

## Development

Start with the [development workflow](docs/development.md) for toolchain setup
and required checks. Use `just --list` to discover commands. The
[architecture guide](docs/architecture.md) explains implementation boundaries;
the [command reference](scripts/README.md) covers performance checks,
publication, and recovery.

## License

MIT (see `LICENSE`).
