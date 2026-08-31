- Stage remote and GitHub cache generations until both address families pass
  semantic and capacity checks, preventing rejected refreshes from replacing a
  usable cache.
- Bound remote feed bodies, parsed entries, and aggregate retention, and reject
  overly broad or family-erasing GitHub metadata safelists.
- Preserve custom `KIDOBO_ROOT` values through installer elevation and preserve
  all uninstall artifacts whenever config-aware cleanup fails.
- Escape control characters in lookup targets across human, TSV, and error
  output.
- Publish a static Linux x86_64 artifact and verify it on Debian 11 and Alpine
  3.22 before release drafting.
