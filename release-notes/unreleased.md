### Fixed

- Timed-out external commands now terminate their descendant process group, so
  inherited output pipes cannot leave a Kidobo operation hanging after its
  timeout.
- The installer now verifies a downloaded binary before atomically replacing
  the installed copy, preserving the previous binary when download,
  extraction, staging, or verification fails.
- Cancelling `just publish-release`, or encountering a validation failure,
  restores the branch from which the release command was started.

### Changed

- Removed the `kidobo analyze overlap` command and its now-empty top-level
  `analyze` command group. New default configs no longer include
  `remote.cache_stale_after_secs`; existing configs that contain the setting
  remain accepted for compatibility.
