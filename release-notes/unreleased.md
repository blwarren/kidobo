### Fixed

- Managed set names beginning with `-` are now rejected before firewall commands
  run, preventing ipset from treating a set name as a command option.
- IPv4-only sync cleanup, flush, and uninstall now accept long IPv4 set names
  without trying to destroy an impossible derived IPv6 set name.
- File inputs now require regular files, including symlinks to regular files.
  Named pipes and devices are rejected instead of potentially leaving commands
  waiting indefinitely while holding the sync lock.
- Configuration now rejects ipset timeouts above the supported limit of
  2,147,483 seconds, including during sync previews; zero still disables expiry.
- Terminal uninstalls now complete firewall cleanup before removing Kidobo's files,
  without a second confirmation that could previously skip cleanup.
- Sync now reloads configuration under its process lock, so configuration edits
  completed before lock acquisition are used for sources and firewall enforcement.
- Initialization now preserves files created concurrently, including saved settings,
  bans, and an acquired process lock.
- Status and live address checks now accept unrelated ipsets whose names contain
  characters outside Kidobo's managed-set naming rules.
- Network-enabled sync previews now enforce the same ASN source size limit as
  normal synchronization, including when the resulting firewall entries fit capacity.
- Shell completions now preserve Bash `--file` paths containing spaces, complete
  feed URLs in Zsh, and suppress inappropriate filename suggestions for non-path
  arguments where supported.
