# Kidobo agent guidance

Kidobo is a released, operational pre-1.0 firewall CLI. Prioritize fail-closed safety,
deterministic computation, operator compatibility, and reliable installation and release.

## Always apply

- Keep the process one-shot; do not add a daemon, watcher, or internal scheduler.
- Keep IPv4 and IPv6 separate. Validate every enabled family's capacity before swapping either set;
  atomicity is per set. Establish new firewall enforcement before removing old wiring, and never
  modify unrelated firewall chains.
- Keep `lookup` offline and `doctor` read-only. `ban` and `unban` change source/config state;
  enforcement waits for `sync`.
- Never validate against the development host's live firewall or systemd using `sync`, `flush`,
  `init`, the installer, `ipset`, `iptables`, `ip6tables`, `sudo`, or `systemctl`. Use injected runners,
  fake binaries, and a temporary `KIDOBO_ROOT`. Live validation requires explicit direction and a
  disposable environment.
- Agents must not run mutation tests; execution belongs to the user. Agents may inspect
  user-produced reports.
- New commands, configuration surface, or runtime modes require explicit scope. Changes to cache
  format, fallback, or staleness semantics require explicit approval.
- `CHANGELOG.md` is generated; never hand-edit it. After any repository change, run
  `just release-notes-check` and report whether it rewrote the changelog or release notes. Follow
  [the release-note workflow](docs/development.md#release-notes-and-publication).

## Read for the task

Read the relevant sections before the corresponding work; other guides need not be loaded.

| Work | Guidance |
| --- | --- |
| Crate boundaries, domain computation, command/source workflows, firewall or cache logic | [Architecture](docs/architecture.md), including its sync sequence and failure policy. |
| Rust, tests, executable scripts, or validation | [Toolchain and validation](docs/development.md#toolchain-and-validation). |
| Core or safety-critical behavior, including fixes and refactors | [Safety-critical regressions](docs/development.md#safety-critical-regressions). |
| CLI, output, paths, installation, or systemd compatibility | [Compatibility contract](docs/compatibility.md) and the relevant [operator workflow](docs/operations.md). |
| Configuration or source semantics | [Configuration](docs/configuration.md) and [Operations](docs/operations.md). |
| Dependency additions, updates, or tool installation | [Dependency release age](docs/dependency-release-age.md). |
| Mutation reports or exclusions | [Mutation result procedure](docs/development.md#mutation-results) and [historical triage evidence](docs/mutation-triage.md). |
| Release notes, versions, tags, or publication | [Release discipline](docs/development.md#release-notes-and-publication) and [commands and recovery](scripts/README.md). |

Use `Justfile` as the canonical command interface. The development guide defines change-specific
checks and the local CI requirement before pushes and merges. General workflow, language skills,
handoffs, and commit conventions follow user-level guidance.
