# kidobo

Kidobo manages IP blocklists on Linux servers. It combines local entries,
remote feeds, and ASN prefixes, subtracts safelisted addresses, and loads the
result into IPv4 and optional IPv6 sets for incoming firewall rules.
`kidobo sync` applies saved changes. You can run it manually or schedule it
with the systemd timer.

## Requirements

- The published binary runs on x86_64 Linux and is tested on Debian 11 and
  Alpine 3.22. Other architectures require a source build and are untested.
- The installer uses Bash, `curl`, `tar`, `sha256sum`, and standard file
  installation tools. Custom-root uninstall also requires GNU `realpath`.
- Host checks and enforcement use `sudo`, `ipset`, and `iptables`.
  IPv6 (enabled by default), full cleanup, and host uninstall also need
  `ip6tables`. ASN resolution and the full `doctor` check need `bgpq4`.
- Scheduled syncs with the supplied timer require systemd.

## Install

Install the latest release on the intended host.

```bash
curl -fsSL https://raw.githubusercontent.com/blwarren/kidobo/main/scripts/install.sh | sudo bash
```

For a controlled deployment, download and review a tag-pinned installer before
running it with elevated privileges. See [installation options](#installation-options).

## Quick start

Run guided setup in a terminal.

```bash
sudo kidobo setup
```

Add the feeds and safelist entries you want to use. Setup shows the proposed
configuration before saving and runs `doctor` to check the host. Choose the
initial sync to apply your settings now. Setup asks separately about enabling
the timer, which can apply saved settings later even if you decline the initial sync.
An already active timer keeps running during setup.

### Verify the result

After the first sync, inspect the managed firewall and check an address from
your blocklist. Replace `203.0.113.7` with the address you want to verify.

```bash
sudo kidobo status
sudo kidobo check 203.0.113.7
```

`check` reports whether Kidobo blocks incoming traffic from that address.
`UNKNOWN` means it could not verify the live result. To see which saved or
cached sources contain an address, use [offline lookup](docs/operations.md#find-offline-source-matches).
If sync reports a feed warning, it may have used a cached copy or skipped the
feed. See [sync warnings and recovery](docs/operations.md#when-a-command-fails).

## Installation options

This example installs a specific binary release with the installer from `main`.

```bash
curl -fsSL https://raw.githubusercontent.com/blwarren/kidobo/main/scripts/install.sh | sudo bash -s -- --version v0.15.4
```

To pin the installer as well, replace both occurrences of `vX.Y.Z` with the same
release tag. The installer checks the archive checksum and the staged binary's
version before replacing an existing installation.

```bash
curl -fsSL https://raw.githubusercontent.com/blwarren/kidobo/vX.Y.Z/scripts/install.sh | sudo bash -s -- --version vX.Y.Z
```

For noninteractive provisioning, `--init` installs the binary and creates
missing files. **At default host paths this immediately enables and starts the
sync timer.** Prepare the intended configuration before using this option.

```bash
curl -fsSL https://raw.githubusercontent.com/blwarren/kidobo/main/scripts/install.sh | sudo bash -s -- --init
```

Host `--init` supports `/usr/local/bin/kidobo`, or `/usr/bin/kidobo` when the
former does not take precedence. For a custom binary-only install, set
`KIDOBO_INSTALL_DIR` and omit `--init`. To remove Kidobo, follow
[Uninstall safely](docs/operations.md#uninstall-safely).

## More information

- [Operations](docs/operations.md) covers bans, feed and safelist edits, sync previews, scheduling, and recovery.
- [Configuration](docs/configuration.md) lists TOML keys, defaults, limits, and paths.
- [Compatibility](docs/compatibility.md) describes current interfaces and the 1.x policy.
- [Release history](CHANGELOG.md) lists changes by version.
- [Security policy](SECURITY.md) covers supported versions and private vulnerability reporting.

## Development

Start with the [development workflow](docs/development.md) for toolchain setup
and required checks. Use `just --list` to discover commands. See
[Architecture](docs/architecture.md) for implementation boundaries and the
[command reference](scripts/README.md) for performance checks, publication,
and recovery.

## License

MIT (see [LICENSE](LICENSE)).
