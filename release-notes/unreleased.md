### Fixed

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
