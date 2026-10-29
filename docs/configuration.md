# Configuration

Kidobo reads `/etc/kidobo/config.toml` by default. `kidobo init` creates a
starter file only when one does not already exist. Edit it, then run
`sudo kidobo doctor` to check the configuration and host prerequisites before
running `sudo kidobo sync` to apply it. Unknown tables and keys are errors.

```toml
[ipset]
set_name = "kidobo"

[safe]
ips = []
include_github_meta = true

[remote]
urls = []

[asn]
banned = []
```

Only `[ipset]` and its `set_name` are required. The other tables and their
keys are optional. The defaults below apply when a key is omitted.

## Managed sets and firewall action

| Key | Default | Accepted value |
| --- | --- | --- |
| `ipset.set_name` | Required | Nonempty IPv4 set name, at most 31 characters, using only letters, digits, `_`, `-`, or `.`; must not start with `-`. |
| `ipset.set_name_v6` | `<set_name>-v6` | Explicit names follow the IPv4 name rules and must be distinct. The derived name must fit the 31-character limit when IPv6 is enabled; supply an explicit name if needed. With IPv6 disabled, an overlong derived name is accepted. |
| `ipset.enable_ipv6` | `true` | Boolean. When false, sync does not enforce IPv6 and cleans up managed IPv6 artifacts. |
| `ipset.chain_action` | `DROP` | `DROP` or `REJECT` (case insensitive). |
| `ipset.set_type` | `hash:net` | Nonempty ipset type using only letters, digits, `:`, `,`, `_`, `-`, or `.`; `hash:net` is the supported managed type. |
| `ipset.hashsize` | `65536` | Positive power of two fitting in a 32-bit unsigned integer. |
| `ipset.maxelem` | `500000` | Integer from `1` through `500000`, per managed set. |
| `ipset.timeout` | `0` | Integer seconds from `0` through `2147483`; `0` means entries do not expire. |

With IPv6 disabled, sync and flush still remove managed IPv6 firewall wiring
and any valid configured IPv6 set. If the derived IPv6 name exceeds 31
characters, cleanup skips that impossible set name without reporting a failure.
Explicit IPv6 names must always satisfy the name rules, even with IPv6 disabled.

Invalid names and out-of-range timeouts are configuration errors. Correct the
value before running commands that require valid configuration; Kidobo does
not rename sets, clamp timeouts, or rewrite these settings automatically.

IPv4 and IPv6 lists are computed and capacity checked separately. Sync checks
both enabled families against `maxelem` before replacing either set. Each set
replacement is atomic, but the two replacements are not one transaction.

## Safelist and sources

| Key | Default | Accepted value |
| --- | --- | --- |
| `safe.ips` | `[]` | Array of individual IPv4/IPv6 addresses or CIDRs to subtract from the effective blocklist. |
| `safe.include_github_meta` | `true` | Boolean controlling the GitHub metadata safelist. |
| `safe.github_meta_url` | `https://api.github.com/meta` | HTTP or HTTPS URL with a host. |
| `safe.github_meta_categories` | Omitted | Omitted: `api`, `git`, `hooks`, and `packages`; `[]`: all categories; nonempty array: only the named categories. |
| `remote.urls` | `[]` | Array of HTTP or HTTPS blocklist URLs with hosts. |
| `remote.timeout_secs` | `30` | Integer from `1` through `3600`, per request. |
| `remote.cache_stale_after_secs` | No active default | Legacy integer from `1` through `604800`, accepted and validated for existing configurations but no longer used to decide refresh behavior. |
| `asn.banned` | `[]` | Array of integer ASN values from `1` through `4294967295`; duplicates are removed. |
| `asn.cache_stale_after_secs` | `86400` | Integer from `1` through `604800`; age after which a cached ASN prefix list is eligible for refresh. |

`safe.ips` is the operator-controlled exemption list. GitHub metadata is an
additional safelist source when enabled; its selected categories must be
present in the response. Kidobo bounds the admitted GitHub networks by entry
count, prefix width, and family coverage, and rejects a batch that would erase
a nonempty enabled-family baseline. See [Operations](operations.md) for cache
fallback behavior.

The GitHub metadata safelist accepts at most 4,096 distinct entries. It
rejects IPv4 prefixes broader than `/8`, IPv6 prefixes broader than `/16`, and
collapsed coverage above one-sixteenth of either family's address space.

The local blocklist lives at `/var/lib/kidobo/blocklist.txt` by default. It
accepts one IP address or CIDR per line. Permanent IP/CIDR bans are recorded
there; `asn.banned` is the configuration source for permanent ASN bans.
Temporary entries live separately in `/var/lib/kidobo/temporary-bans.toml`.
This versioned state file records canonical IP/CIDR or ASN entries with
absolute Unix expiry times. `init` creates a valid empty file when absent and
preserves an existing file. `doctor` validates it without changing it. None of
these source edits changes live firewall enforcement until the next `sync`.

Temporary state uses `version = 1`, `[[ips]]` records with `cidr` and
`expires_at`, and `[[asns]]` records with `asn` and `expires_at`. Expiry values
are positive Unix seconds. Reads and writes are limited to 16 MiB; unknown
fields, unsupported versions, invalid records, and duplicate canonical
identities are errors. A missing file is an empty source. `unban` updates both
permanent and temporary sources for the requested target type.

## Managing configured sources and exemptions

Use `kidobo sources` or `kidobo sources list` to inspect configured remote
blocklist URLs and `kidobo sources add URL` / `kidobo sources remove URL` to
edit them. Listing also reports validated cache availability; refresh time is
unknown when there is no trustworthy refresh receipt. These commands update
`remote.urls`; they do not fetch feeds, refresh caches, or change firewall
state. Run `sudo kidobo sync` to apply a saved change.

Use `kidobo allow` or `kidobo allow list` to inspect operator-managed
exemptions in `safe.ips`.
`kidobo allow add IP_OR_CIDR` and `kidobo allow remove IP_OR_CIDR` edit that
list. Adding an exact canonical duplicate is a no-op. A distinct address or
range already covered by a broader exemption can be saved without expanding
coverage or prompting; this can keep the narrower entry if the broader one is
removed later. An addition that expands coverage asks for confirmation in an
interactive terminal; use `--yes` to approve that change when running
noninteractively. Removal matches the exact canonical address or network and
does not split a wider CIDR into smaller ranges. These edits are saved source
changes; run `sudo kidobo sync` before expecting the live managed set to
reflect them.

`kidobo config show` requires an existing, valid configuration file. It displays
effective values, their origins, and defaults, redacting URL credentials and
query/fragment values. `kidobo config path` prints the selected configuration
path, including a path relocated by `KIDOBO_ROOT`, even before the file exists.
Both commands are read-only and never create a configuration file.

## Paths and validation

| Item | Default path |
| --- | --- |
| Configuration | `/etc/kidobo/config.toml` |
| Local blocklist | `/var/lib/kidobo/blocklist.txt` |
| Temporary bans | `/var/lib/kidobo/temporary-bans.toml` |
| Cache | `/var/cache/kidobo` |
| Generated systemd units | `/etc/systemd/system/kidobo-sync.service` and `/etc/systemd/system/kidobo-sync.timer` |

`KIDOBO_ROOT` relocates these files under a custom root: `config/config.toml`,
`data/blocklist.txt`, `data/temporary-bans.toml`, `cache/`, and
`systemd/system/`. With this override, `init` does not enable a live systemd
timer. Set names and configuration keys remain subject to the same validation.
See the [compatibility reference](compatibility.md) for current interfaces and
the 1.x compatibility policy.
