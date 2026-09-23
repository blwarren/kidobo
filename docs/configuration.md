# Configuration

Kidobo reads `/etc/kidobo/config.toml` by default. `kidobo init` creates a
starter file only when one does not already exist. Edit it, then run
`kidobo doctor` to check the configuration and host prerequisites before
running `kidobo sync` to apply it. Unknown tables and keys are errors.

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
| `ipset.set_name` | Required | Nonempty IPv4 set name, at most 31 characters, using only letters, digits, `_`, `-`, or `.`. |
| `ipset.set_name_v6` | `<set_name>-v6` | Distinct IPv6 set name with the same name rules. Supply an explicit name if the derived name would exceed 31 characters. |
| `ipset.enable_ipv6` | `true` | Boolean. When false, sync does not enforce IPv6 and cleans up managed IPv6 artifacts. |
| `ipset.chain_action` | `DROP` | `DROP` or `REJECT` (case insensitive). |
| `ipset.set_type` | `hash:net` | Nonempty ipset type using only letters, digits, `:`, `,`, `_`, `-`, or `.`; `hash:net` is the supported managed type. |
| `ipset.hashsize` | `65536` | Positive power of two fitting in a 32-bit unsigned integer. |
| `ipset.maxelem` | `500000` | Integer from `1` through `500000`, per managed set. |
| `ipset.timeout` | `0` | Integer from `0` through `4294967295`; `0` means entries do not expire. |

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
accepts one IP address or CIDR per line. `ban` and `unban` edit that source;
`asn.banned` is the configuration source for ASN bans. Neither edit changes
live firewall enforcement until the next `sync`.

## Paths and validation

| Item | Default path |
| --- | --- |
| Configuration | `/etc/kidobo/config.toml` |
| Local blocklist | `/var/lib/kidobo/blocklist.txt` |
| Cache | `/var/cache/kidobo` |
| Generated systemd units | `/etc/systemd/system/kidobo-sync.service` and `/etc/systemd/system/kidobo-sync.timer` |

`KIDOBO_ROOT` relocates these files under a custom root: `config/config.toml`,
`data/blocklist.txt`, `cache/`, and `systemd/system/`. With this override,
`init` does not enable a live systemd timer. Set names and configuration keys
remain subject to the same validation. See the [1.x compatibility
contract](compatibility.md) for the supported operator interface.
