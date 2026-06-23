# Scripts Layout

`scripts/dev.sh` is the canonical entrypoint for local and CI tooling gates.
Top-level gate scripts are thin wrappers kept for backward compatibility.

## Structure

- `scripts/dev.sh`: central command dispatcher for validation and CI tasks.
- `scripts/install.sh`: public install/uninstall flow used by operators.
- `scripts/changelog/*`: release-notes normalization and changelog generation.
- `scripts/perf/*`: benchmark and lookup RSS regression tooling.
- `.cargo/mutants.toml`: cargo-mutants mutation-testing configuration.

## Common Commands

- `./scripts/dev.sh pre-commit-fast`
- `./scripts/dev.sh pre-push-tests`
- `./scripts/dev.sh post-coding-gates`
- `./scripts/dev.sh gates-minimum`
- `./scripts/dev.sh gates-extended`
- `./scripts/dev.sh mutants`
- `./scripts/dev.sh mutants --shard 1/4`
- `./scripts/dev.sh release-notes-check`

## Backward Compatibility

These wrapper paths remain valid and delegate to `scripts/dev.sh`:

- `scripts/pre-commit-fast.sh`
- `scripts/pre-push-tests.sh`
