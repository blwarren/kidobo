# Dependency release age

Only add or update third-party dependencies after their registry releases have
aged at least seven full days (168 hours). This applies to direct and transitive
dependencies, including development and build tools. Verify registry publication
timestamps; an unknown age does not satisfy the rule. The delay reduces exposure
to newly published packages but does not establish that a package is safe.

Preserve existing locked versions unless an update is requested or necessary for
the task. Security fixes follow the same rule unless a narrowly scoped exception
has a documented reason or an explicit user override.

## Repository workflow

Use the existing [development commands](../scripts/README.md):

```bash
just update
```

This installs the pinned `cargo-cooldown` tool, updates dependencies using
[cooldown.toml](../cooldown.toml), and then runs the non-E2E workspace tests. Run
`just test --include-e2e` as well when an update affects the E2E system. The
configuration sets a seven-day minimum registry publish age, denies incompatible
publish ages, and uses the existing lockfile as the version floor. Inspect the
resulting manifest and lockfile diff before accepting an update.

[Dependabot configuration](../.github/dependabot.yml) applies a seven-day cooldown
to version-update PRs. GitHub's [cooldown option](https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference#cooldown)
does not cover security-update PRs. Such a PR still needs publication-age review
or a documented exception before its dependency changes are adopted.

Raw Cargo commands and tool installations do not inherit `cooldown.toml` policy.
For additions, tool installations, and other dependency changes outside the
guarded update recipe, verify the publication timestamps of every newly selected
registry version, including transitive versions. Do not treat a passing
`just ci` as proof of release age: its dependency checks cover advisories,
licenses, sources, and bans, not registry publication timestamps.

## Verified additions for human terminal output

The following direct dependency versions were checked against crates.io on
2026-10-27 20:49 UTC. Each publication time is more than 168 hours before the
check time, and each crate's declared MSRV is below the workspace MSRV 1.97.1.

| Crate | Version | Published (UTC) | Declared MSRV |
| --- | --- | --- | --- |
| [`clap_complete`](https://crates.io/crates/clap_complete/4.6.11) | 4.6.11 | 2026-09-15 16:32:44 | 1.85 |
| [`terminal_size`](https://crates.io/crates/terminal_size/0.4.4) | 0.4.4 | 2026-03-23 16:39:14 | 1.71 |
| [`unicode-segmentation`](https://crates.io/crates/unicode-segmentation/1.13.3) | 1.13.3 | 2026-06-01 15:58:43 | 1.85.0 |
| [`unicode-width`](https://crates.io/crates/unicode-width/0.2.2) | 0.2.2 | 2025-10-06 14:33:47 | 1.66 |

The existing locked `jiff` 0.2.38 (published 2026-10-06 15:01:05 UTC,
declared MSRV 1.70) was promoted to a direct dependency; this does not add or
update a registry version. The selected `clap_complete` release accepts the
existing locked `clap` 4.6.7. `terminal_size` reuses the locked `rustix` 1.1.5
and `windows-sys` 0.61.2 versions; the Unicode crates add no required runtime
transitive versions.

## Other existing locked dependency promotions

`url` and `nix` were also promoted from the existing locked graph without
selecting new versions. Their registry metadata was checked on
2026-10-27 21:46 UTC; both publications predate that check by more than 168
hours, and their declared MSRVs are below the workspace minimum of Rust 1.97.1.

| Crate | Locked version | Published (UTC) | Declared MSRV | Use |
| --- | --- | --- | --- | --- |
| [`url`](https://crates.io/crates/url/2.5.8) | 2.5.8 | 2026-01-05 22:14:31 | 1.63 | Direct production dependency for URL parsing and redaction. |
| [`nix`](https://crates.io/crates/nix/0.31.3) | 0.31.3 | 2026-05-11 07:01:18 | 1.69 | Direct development dependency with the `term` feature for PTY tests. |

## Exceptions

Record the exact crate and version, the reason for bypassing the delay, and any
explicit user override in the change's review record. Keep the exception limited
to the versions needed for that reason; do not disable the global cooldown.

When the guarded updater needs an exception, add an exact entry with its reason
to `cooldown.toml`:

```toml
# Reason: record the specific justification or explicit user override here.
[[allow.exact]]
crate = "affected-crate"
version = "1.2.3"
```

Retain the justification with the dependency change. Once registry timestamps
confirm that the version has aged seven full days, remove the no-longer-needed
allowlist entry; preserve the reason in the review record or commit history.

After dependency changes, follow the [development validation requirements](development.md#toolchain-and-validation)
and [release-note workflow](development.md#release-notes-and-publication).
