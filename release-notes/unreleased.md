### Fixed

- Config validation now rejects malformed `http://`/`https://` remote and
  GitHub meta URLs, unknown configuration keys, and IPv4/IPv6 ipset name
  collisions. IPv4-only configs still permit an unused derived IPv6 set name
  longer than the kernel limit.
- `kidobo doctor` no longer requires or sudo-probes `iptables-save` and
  `iptables-restore`, which are not used by the one-shot runtime path.
- `kidobo init` no longer requires `bgpq4` before any ASN blocklist sources are
  configured, and its generated default config now includes the remote cache
  staleness setting.
- Custom GitHub meta URLs no longer reuse metadata-less raw cache files that
  may have been written for the default GitHub meta endpoint.
- The install script now selects checksum entries by exact archive filename
  instead of using a regex match.
- Sync now validates existing ipset type and family, checks both family limits
  before swapping either set, and activates firewall rules only after source
  loading and atomic set replacement succeed.
- Firewall rule updates now wait briefly for the xtables lock and insert new
  enforcement before removing superseded rules, avoiding fail-open gaps when a
  command fails partway through an update.
- Non-empty remote feeds with no valid CIDRs and malformed GitHub category data
  now retain the last usable cache instead of overwriting it with an empty list.
- `kidobo flush` now reports incomplete cleanup as a failure, and uninstall
  preserves runtime files when direct firewall cleanup cannot be confirmed.
- The read-only doctor cache check now rejects missing traversal permissions and
  reports plausible, but unproven, effective writability as `SKIP`.
- The unchecked integer `from_parts` CIDR constructors are no longer public;
  callers must use the prefix-validating `Ipv4Cidr::new` and `Ipv6Cidr::new` APIs.

### Changed

- Releases can now be prepared, validated, committed, tagged, and atomically
  pushed with `just publish-release X.Y.Z`; an optional leading `v` is accepted,
  local commits ahead of `origin/main` are included, and the command uses a
  temporary worktree with confirmation before publication. It switches to
  `main` automatically and leaves the completed checkout there.
- `kidobo lookup` now defaults to a readable, wrapped results table with
  explicit match statuses and summary counts. TTY output highlights statuses,
  `NO_COLOR` disables styling, and `--format tsv` preserves the previous
  tab-separated output for scripts.
- `kidobo lookup` now reports raw overlaps with configured safelist entries,
  compatible cached GitHub meta safelist data, and cached prefixes for
  configured ASN bans, in addition to the local blocklist and cached remote
  sources. Lookup remains offline-only and retains its local/remote fallback
  when config is missing or invalid, with warnings when config-backed cache
  coverage is unavailable.
