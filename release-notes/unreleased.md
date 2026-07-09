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
