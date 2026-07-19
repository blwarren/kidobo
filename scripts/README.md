# Development Commands

`Justfile` is the canonical entrypoint for local and CI tooling gates.
Install `just` before running development recipes:

```bash
cargo install --locked just --version 1.55.1
rustup component add llvm-tools-preview
cargo install --locked cargo-llvm-cov --version 0.8.4
```

## Structure

- `Justfile`: validation, CI, release-note, udeps, and mutation-test recipes.
- `scripts/install.sh`: public install/uninstall flow used by operators.
- `scripts/publish-release.sh`: guarded, transactional release preparation and publication.
- `scripts/changelog/*`: release-notes normalization and changelog generation.
- `scripts/perf/*`: benchmark and lookup RSS regression tooling.
- `.cargo/mutants.toml`: cargo-mutants mutation-testing configuration.

## Common Commands

- `just check`
- `just ci`
- `just coverage` (90% minimum for stable region, function, and line metrics)
- `just exercise-release` (build and safely exercise the release binary with isolated runtime fixtures)
- `just verify-release` (release notes, full CI, and coverage in one required pre-release gate)
- `just update`
- `just udeps`
- `just release-notes-check`
- `just publish-release 0.11.0` (a leading `v` is also accepted; branch switching is automatic and is restored if publication does not complete)
- `just mutants`
- `just mutants --shard 1/4`
