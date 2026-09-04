- Stage remote and GitHub cache generations until both address families pass
  semantic and capacity checks, preventing rejected refreshes from replacing a
  usable cache.
- Retain validated remote and GitHub cache data when staging fails, and abort
  sync before enforcement when no usable fallback exists. Repair corrupt
  generations from identical fresh data and retain previous generations across
  unchanged refreshes.
- Enforce subprocess deadlines through output collection, including pipes held
  open by descendants after the initial process exits.
- Cancel prompts and pending workflow work on Ctrl-C while completing started
  firewall enforcement and cleanup. Preserve operational failure diagnostics
  when interruption also occurs.
- Reject invalid configuration before IP/CIDR and ASN source-state changes,
  including configuration changed during interactive unban confirmation.
- Bound remote feed bodies, parsed entries, and aggregate retention, and reject
  overly broad or family-erasing GitHub metadata safelists.
- Preserve custom `KIDOBO_ROOT` values through installer elevation and preserve
  all uninstall artifacts whenever config-aware cleanup fails.
- Escape control characters in lookup targets across human, TSV, and error
  output.
- Publish a static Linux x86_64 artifact and verify it on Debian 11 and Alpine
  3.22 before release drafting.
