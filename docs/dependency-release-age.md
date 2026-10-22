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
[cooldown.toml](../cooldown.toml), and then runs the workspace tests. The
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
