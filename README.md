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
curl -fsSL https://raw.githubusercontent.com/blwarren/kidobo/main/scripts/install.sh | sudo bash -s -- --version v0.14.3
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

## Quick Start

For an interactive first-run guide, start setup in a terminal:

```bash
sudo kidobo setup
```

Setup reviews the proposed configuration before saving it, provisions local
files and service units, and runs `doctor` before offering an initial sync. It
does not apply firewall changes unless you accept that sync. For automated or
noninteractive provisioning, use `sudo kidobo init`.

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

Add a local entry (optional):

```bash
sudo kidobo ban 203.0.113.7
```

`ban` and `unban` change source state only. Run `sync` to change live
enforcement. See the [operations guide](docs/operations.md) for file and ASN
bans, offline lookup, the timer, and failure recovery.

Preview proposed counts and capacity without changing enforcement:

```bash
kidobo sync --dry-run
```

The preview uses validated local caches and stays offline by default. To
explicitly allow feed, GitHub metadata, and ASN requests while keeping results
in memory, use
`kidobo sync --dry-run --allow-network`. A successful preview does not
guarantee a later sync, because inputs and live state can change.

Apply the configured blocklists. Repeat this after changing sources or
configuration:

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

Generate a completion script with `kidobo completions bash`,
`kidobo completions zsh`, or `kidobo completions fish`; the selected script is
written to stdout.

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
- [1.x compatibility contract](docs/compatibility.md): stable operator interfaces.

## Development

Development commands are defined in `Justfile`. See the
[development workflow](docs/development.md) for validation, testing, and release discipline,
the [command reference](scripts/README.md) for release and recovery details, and the
[architecture guide](docs/architecture.md) for extension boundaries and recipes.

Development uses Rust 1.99.1 through `rust-toolchain.toml`. The minimum supported
Rust version remains 1.97.1 in the Cargo manifests. Keep code compatible with that
minimum and verify it with `RUSTUP_TOOLCHAIN=1.97.1 just test`.

```bash
cargo install --locked just --version 1.55.1
just _install-cooldown _install-deny _install-audit
just check
just ci
just release-notes-check
```

`just test-fast` runs the core, application, and CLI unit tests. The pre-commit hook
uses `just commit-check` for whitespace checks and, when staged files affect Rust,
formatting verification and these fast tests. It does not modify source files.
`just check` remains the complete development format/test/lint loop. Run `just ci`
before every push; GitHub does not run project CI for pushes or tags. The local CI gate
checks formatting, lints, dependency policy, audits, and application correctness via `just test-app`.
`just test` runs all workspace tests, including installer, repository tooling, and E2E infrastructure
tests; run it when changing those areas. Publication additionally
requires coverage, strict rustdoc, the isolated release-binary exercise, static Debian/Alpine
compatibility, and by default required Debian/Ubuntu coverage in the [Incus distro lifecycle
matrix](docs/e2e.md). Separate `just e2e` runs cover all seven configured targets, including
advisory Fedora and AlmaLinux with enforcing SELinux. Each target gets fresh provisioning and
full application checks, with at most two VMs running concurrently. Read the
[E2E scope contract](docs/e2e.md#scope-and-non-goals) before changing that infrastructure.
The isolated exercises use a temporary `KIDOBO_ROOT`, a loopback HTTP feed, and fake privileged
commands; they never
touch the development host's firewall or systemd. The Incus matrix runs real privileged
operations only inside disposable VMs. Dependabot update
PRs are the only GitHub-hosted automation retained. Run
`just release-notes-check` after every repository change.

Authenticate with `gh auth login` before publishing, then run
`just publish-release X.Y.Z` from a clean branch. The publisher validates and
packages the release locally, pushes the release commit and tag atomically,
verifies the draft's downloaded assets, and only then publishes it. See the
[development-command reference](scripts/README.md) for the complete workflow
and failure recovery. Use `just publish-release X.Y.Z --skip-e2e` to omit the VM
matrix while retaining all other release checks and uploaded-asset verification.
Every publication attempt reruns validation and builds its candidate; prior E2E results are not
reused. E2E logs and frozen evidence survive a failed attempt. The command reference distinguishes
retrying before publication from recovery after Git refs have been pushed.

Use `just --list` to see all available local and CI recipes.

## License

MIT (see `LICENSE`).
