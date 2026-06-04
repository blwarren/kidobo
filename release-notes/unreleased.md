### Fixed

- Config validation now rejects malformed `http://`/`https://` remote and
  GitHub meta URLs, prevents IPv4/IPv6 ipset name collisions when IPv6 is
  enabled, and no longer rejects IPv4-only configs only because the unused
  derived IPv6 set name would be too long.
- `kidobo doctor` no longer requires or sudo-probes `iptables-save` and
  `iptables-restore`, which are not used by the one-shot runtime path.
- `kidobo init` no longer requires `bgpq4` before any ASN blocklist sources are
  configured, and its generated default config now includes the remote cache
  staleness setting.
- Custom GitHub meta URLs no longer reuse metadata-less raw cache files that
  may have been written for the default GitHub meta endpoint.
- The install script now selects checksum entries by exact archive filename
  instead of using a regex match.
