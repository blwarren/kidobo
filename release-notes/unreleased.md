### Changed

- Raise the default download limit for each remote blocklist from 8 MiB to 16 MiB.

### Security

- Update the URL parser to fix a stack overflow when computing the origin of nested `blob:` URLs (RUSTSEC-2026-0592).
