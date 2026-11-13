### Fixed

- Preserve selected remote-feed and GitHub metadata cache generations when manifest replacement
  succeeds but directory synchronization fails.

### Security

- Redact URL credentials and query/fragment values from doctor JSON configuration-error diagnostics
  and accepted alternative HTTP(S) URL spellings in CLI output and logs.
