### Fixed

- Keep reply traffic flowing during firewall rule replacement, coordinate sync and full flush
  across storage roots, and preserve operator-authored references to Kidobo chains.
- Recover from corrupt legacy feeds, revalidate only the resource that supplied a cached body,
  and retain admissible GitHub safelist fallbacks and durable first-time cache publications.
- Recheck the reviewed configuration before setup proceeds and preserve comments on retained
  entries when removing configured sources or exemptions.
- Enforce local blocklist syntax during offline lookup and return complete status JSON for
  Unix paths containing invalid UTF-8.
- Preserve selected remote-feed and GitHub metadata cache generations when manifest replacement
  succeeds but directory synchronization fails. Confirm directory durability on retry before using
  the selection or pruning generations.
- Reject partial HTTP responses for remote feeds and GitHub metadata, and disregard legacy
  remote-feed caches whose metadata identifies a different URL.
- Honor explicit `ban --apply` and `unban --apply` after a saved-state reporting error, and report
  the synchronization outcome.
- Preserve configuration bytes for no-op ASN edits and retain comments on ASN entries kept by an edit.
- Skip nonmatching ranges during offline lookup and process cached remote feeds one at a time.
- Install the binary at the intended path, wait for the complete init log before attempting recovery,
  and choose an executable binary when provisioning scheduled sync.
- Preserve individual saved bans, comments, and formatting during sync. Read comment-heavy
  local blocklists without allocating a separate record for each blank or comment line.
- Confirm permanent ban and unban durability on retry before applying enforcement. Preserve
  file contents and permissions on unchanged source and exemption edits.
- Reject nonempty all-invalid feed caches during fallback selection.
- Check the IPv4 and IPv6 firewall tools before full cleanup, support unscheduled non-systemd
  uninstall, and verify the executable selected for installer initialization.

### Security

- Redact URL credentials and query/fragment values from doctor JSON configuration-error diagnostics
  and accepted alternative HTTP(S) URL spellings in CLI output and logs.
- Redact complete feed URLs in fetch diagnostics and offline lookup source labels, including TSV exports.
