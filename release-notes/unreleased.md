- Uninstall now canonicalizes `KIDOBO_ROOT` before cleanup and rejects empty,
  root-equivalent, symlink-to-root, or unresolvable override paths.
- Firewall activation now uses a transient Kidobo-owned staging chain to replace
  shared `INPUT` jumps by exact rule while remaining fail-closed during partial failures.
- Kidobo now handles non-Unicode process environment values without panicking and
  preserves non-Unicode runtime root paths.
- ASN updates now keep the process lock through cache cleanup and reject malformed,
  wrong-family, or empty `bgpq4` results before changing configuration.
- Lock files now reject symlinks on Unix and apply owner-only permissions through the
  opened file, closing pathname races.
- Remote-feed and GitHub metadata caches now publish checksum-addressed generations
  atomically and fall back through the previous generation and compatible legacy data.
