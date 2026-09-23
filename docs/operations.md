# Operating Kidobo

Kidobo runs one command at a time; it is not a resident daemon. `sync` is the
command that changes firewall and ipset enforcement. Run the commands below on
the intended Linux host as an operator with the required privileges. For
configuration keys and paths, see [Configuration](configuration.md).

## First setup and routine changes

1. Install Kidobo using the [README instructions](../README.md#install).
2. Run `sudo kidobo init`. It creates missing configuration, data, cache, and
   systemd unit files without replacing existing ones. At default paths it
   reloads systemd and enables and starts `kidobo-sync.timer`.
3. Edit `/etc/kidobo/config.toml` and, if needed,
   `/var/lib/kidobo/blocklist.txt`.
4. Run `sudo kidobo doctor` and inspect its JSON `overall` and `checks` values.
   `doctor` performs read-only probes. An `overall` value of `FAIL` exits with
   status `1`; a cache-access `SKIP` means it could not safely prove effective
   writability without writing a probe file.
5. Run `sudo kidobo sync` to load sources and apply the resulting IPv4 and IPv6
   sets and firewall rules. Run it again after any source or configuration
   change. A successful sync leaves one managed INPUT jump per enabled family at
   position 1.

At default paths, `init` requires an installed binary at
`/usr/local/bin/kidobo` or `/usr/bin/kidobo` for its generated service.
The generated `Type=oneshot` service runs `kidobo sync`; its timer starts two
minutes after boot and schedules another run one hour after the service was
last active. The timer is persistent. The generated service writes journal
format logs. To inspect scheduled runs and their diagnostics, use:

```bash
systemctl status kidobo-sync.timer
systemctl status kidobo-sync.service
journalctl -u kidobo-sync.service
```

Manual runs accept `--log-level` (for example, `sudo kidobo --log-level debug
sync`). `sync --timer` emits per-stage timing logs. Logs go to stderr; `doctor`
prints its JSON report to stdout.

## Check and change sources

`kidobo lookup 203.0.113.7` and `kidobo lookup --file targets.txt` inspect
local and compatible cached sources without network access, ASN resolution, or
firewall changes. Lookup reports raw source overlaps, including safelist
exemptions; it does not read the live ipset or calculate the final enforced
set. An invalid or missing configuration limits lookup to the local blocklist
and cached remote sources and produces warnings for unavailable coverage.
Use `--format tsv` for scripts; see the [compatibility contract](compatibility.md)
for its record format.

`sudo kidobo ban 203.0.113.7`, `sudo kidobo unban 203.0.113.7`, and their
`--file` forms edit the local blocklist only. A file supplies one strict IP or
CIDR target per line. `ban --asn 213412` and `unban --asn AS213412` update
`[asn].banned`; ASN ban may resolve and cache prefixes, while ASN unban makes
a best-effort cache cleanup. `unban --yes` skips confirmation where removal
would require it. All ban and unban modes require valid configuration and none
changes enforcement until `sudo kidobo sync` succeeds.

## When a command fails

- **Configuration or prerequisite failure:** Read the specific `doctor` check
  or command error. Correct the file or missing prerequisite, rerun `doctor`,
  then run `sync`. Unknown configuration keys and invalid non-header local
  blocklist lines fail rather than being silently ignored.
- **Remote feed or GitHub metadata warning:** A failed fetch, invalid nonempty
  response, or rejected redirect does not replace good cache data. Redirects
  are limited to ten hops and the configured URL's origin. Kidobo
  warns and uses a compatible validated cache when available. A whitespace-
  or comment-only remote response is an intentional empty feed. If cache
  staging fails and no validated fallback exists, sync stops before replacing
  either set. Remote HTTP bodies default to an 8 MiB limit; the
  `KIDOBO_MAX_HTTP_BODY_BYTES` override is capped at 32 MiB, while GitHub
  metadata remains capped at 8 MiB. Fix the source or cache problem and rerun
  `sync`.
- **ASN refresh warning:** A stale cached prefix list can be used when refresh
  fails. Check `bgpq4` and source connectivity, then rerun `sync` after fixing
  the cause.
- **Capacity or enforcement failure:** Sync checks every enabled family's
  `maxelem` before swapping either set. A later ipset or firewall error can
  leave an incomplete update; inspect the error and current managed state
  before retrying. The two family swaps are separate, and Kidobo establishes
  new firewall enforcement before removing old wiring.
- **Cleanup failure:** `sudo kidobo flush` attempts managed firewall/ipset and
  remote-cache cleanup and returns `1` if required cleanup remains incomplete.
  `sudo kidobo flush --cache-only` clears only the remote cache and leaves
  firewall/ipset state unchanged. Treat `flush` as a removal operation, not a
  diagnostic. If uninstall cannot confirm config-aware live cleanup, the
  installer retains the binary and runtime files; inspect the failure before
  attempting uninstall again.

Exit status is `0` for success, help, or version; `1` for runtime or `doctor`
failure; `2` for command-line usage errors; and `130` for SIGINT. After SIGINT,
an active sync enforcement or full-flush cleanup section finishes its scoped
work unless an operational error prevents it. Check the final diagnostic
before deciding whether to retry.
