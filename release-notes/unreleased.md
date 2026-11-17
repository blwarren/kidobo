### Fixed

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

### Security

- Redact URL credentials and query/fragment values from doctor JSON configuration-error diagnostics
  and accepted alternative HTTP(S) URL spellings in CLI output and logs.
