# Development Commands

`Justfile` is the canonical entrypoint for local and CI tooling gates.
Install `just` before running development recipes:

```bash
cargo install --locked just --version 1.55.1
```

## Structure

- `Justfile`: validation, CI, release-note, udeps, and mutation-test recipes.
- `scripts/install.sh`: public install/uninstall flow used by operators.
- `scripts/publish-release.sh`: guarded, transactional release preparation and publication.
- `scripts/changelog/*`: release-notes normalization and changelog generation.
- `scripts/perf/*`: benchmark and lookup RSS regression tooling.
- `.cargo/mutants.toml`: cargo-mutants mutation-testing configuration.

## Common Commands

- `just pre-commit-fast`
- `just pre-push-tests`
- `just post-coding-gates`
- `just gates-minimum`
- `just gates-extended`
- `just release-notes-check`
- `just publish-release 0.11.0` (a leading `v` is also accepted; branch switching is automatic)
- `just mutants`
- `just mutants --shard 1/4`
