### Fixed

- Terminal uninstalls now complete firewall cleanup before removing Kidobo's files,
  without a second confirmation that could previously skip cleanup.
- Sync now reloads configuration under its process lock, so configuration edits
  completed before lock acquisition are used for sources and firewall enforcement.
