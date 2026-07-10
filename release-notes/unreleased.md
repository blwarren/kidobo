### Changed

- The documented curl-pipe installer now runs correctly when Bash reads it from
  standard input.
- `just publish-release` now runs the local test suite once using the same
  quality gate as the GitHub release workflow, instead of repeating it under
  coverage before GitHub performs its independent post-push verification.
