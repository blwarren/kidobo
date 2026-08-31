# Kidobo 1.x compatibility contract

Kidobo 1.x keeps the documented operator contract compatible until 2.0. Minor
releases may add commands, options, configuration keys, or output fields where
the existing format permits extension. Security tightening may reject inputs
that were previously accepted, but the change must be called out in release
notes.

The compatibility-sensitive surface includes:

- The documented `init`, `doctor`, `sync`, `flush`, `lookup`, `ban`, and
  `unban` commands and their documented options.
- Exit status `0` for success, help, and version; `1` for runtime or check
  failure; `2` for usage errors; and `130` for SIGINT.
- Existing configuration keys, accepted value types, and defaults. Unknown
  keys remain errors; additions in minor releases receive documented defaults.
- Default paths under `/etc/kidobo`, `/var/lib/kidobo`, and
  `/var/cache/kidobo`, plus the documented `KIDOBO_ROOT` relocation.
- The `kidobo-sync.service` and `kidobo-sync.timer` names, paths, and one-shot
  timer model. A 1.x release will not turn Kidobo into a resident daemon.
- Installer checksum and version verification, in-place upgrades, and the rule
  that uninstall removes artifacts only after config-aware live cleanup
  succeeds.
- Readability of cache generations written by earlier 1.x releases. New 1.x
  writers may use newer compatible generations while retaining bounded legacy
  readers; rejected or corrupt cache data is never selected.

## Machine-readable lookup output

`lookup --format tsv` keeps its current records:

- A match is `target<TAB>source<TAB>matched-entry`.
- File-mode misses are `target<TAB>NO_MATCH`.
- File mode ends with
  `summary: total_ips=N matched_ips=N matched_pct=N%`.
- Single-target misses retain the existing empty stdout behavior.

Target identity remains raw inside core lookup. At every output boundary it is
encoded so one target cannot add terminal commands, fields, or records:

- backslash: `\\`
- tab, carriage return, and newline: `\t`, `\r`, and `\n`
- other ASCII controls: `\xNN` with two uppercase hexadecimal digits
- non-ASCII control code points: `\u{…}` with uppercase hexadecimal digits

Printable text, including printable Unicode, is unchanged.

## Published artifact

The supported archive remains named `kidobo-vX.Y.Z-linux-x86_64.tar.gz`. It
contains a static `x86_64-unknown-linux-musl` executable tested on Debian 11 and
Alpine 3.22. Static linking does not remove operational dependencies: the
installer requires Bash and its documented command-line tools, firewall
operations require `ipset` and `iptables`/`ip6tables`, ASN refresh requires
`bgpq4`, and generated periodic execution requires systemd.
