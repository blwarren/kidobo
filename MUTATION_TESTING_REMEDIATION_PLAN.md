# Mutation Testing Remediation Plan

This plan is based on the current `mutants.out` report in the repository root.

Report snapshot:

- `mutants.out/missed.txt`: 212 missed mutants
- `mutants.out/timeout.txt`: 22 timeout mutants
- `mutants.out/unviable.txt`: 314 unviable mutants
- Runner evidence: `cargo-mutants 27.1.0` against package `kidobo 0.10.1`
- Test command evidence: `cargo test --package=kidobo@0.10.1 --all-features --lib --bins --tests`

Do not rerun mutation testing from agent turns. Use user-provided mutation reports, and ask the user for a rerun after meaningful stages are complete. Provide targeted commands for the user to run to ensure rerun mutation testing targets only the relevant code for review of that stage.

## Priorities

Address missed and timeout mutants in this order:

1. Firewall safety and ipset atomicity
2. Deterministic core interval, safelist, lookup, and config behavior
3. Cache, source-loading, and path/lock correctness
4. Stable operator-visible CLI behavior
5. Low-risk diagnostics, cosmetic output, equivalent mutants, and unviable triage

Each stage is intended to be small enough for one focused implementation turn.

## Stage 0: Baseline Triage

- [ ] Confirm the unmutated `cargo test --lib --bins --tests --all-features` baseline passes before changing tests.
- [ ] Reconcile `mutants.out/missed.txt` and `mutants.out/timeout.txt` against current source line numbers before coding.
- [ ] Classify each targeted mutant as safety-critical, operator-visible, equivalent, low-value diagnostic, or timeout-only before adding tests.
- [ ] Track any intentionally ignored missed mutants in the stage completion notes with a brief rationale.

## Stage 1: Core Interval Conversion

- [ ] Add IPv4 tests for `/0`, `/32`, non-zero host-bit canonicalization, and max-address interval endpoints.
- [ ] Add IPv6 tests for `/0`, `/128`, high-bit networks, and max-address interval endpoints.
- [ ] Add interval-to-CIDR tests for single-host, two-host, unaligned, and max-boundary ranges in both families.
- [ ] Add a large unsorted IPv4 input test that forces radix sorting and proves output matches ordinary sorting.
- [ ] Review timeout mutants in `intervals_to_*`, `largest_prefix_*`, and `is_aligned_*` for explicit progress assertions or documented skip candidates.

## Stage 2: Safelist Subtraction

- [ ] Add IPv4 safelist subtraction tests for first-address, last-address, middle split, full removal, and no-overlap cases.
- [ ] Add IPv6 safelist subtraction tests for first-address, last-address, middle split, full removal, and high-bit tail boundaries.
- [ ] Add tests where multiple safelist entries carve one candidate so ignoring later safelist entries fails.
- [ ] Add order-independence tests with unsorted candidates and unsorted safelist entries.
- [ ] Add adjacency tests proving adjacent blocklist intervals merge while carved output remains minimal and non-overlapping.

## Stage 3: Overlap And Lookup

- [ ] Add blocklist overlap tests for unsorted remote intervals where partition advancement must skip only non-overlapping prefixes.
- [ ] Add coverage tests where one local interval is covered only by multiple adjacent remote intervals.
- [ ] Add IPv6 overlap and full-coverage tests mirroring the IPv4 boundary cases.
- [ ] Add lookup tests for IPv6 supernet, same-start nested IPv6 entries, and non-overlapping prefix sections.
- [ ] Add lookup tests that prove family separation when IPv4 and IPv6 source entries are interleaved.

## Stage 4: Config And Blocklist Parsing

- [ ] Add boundary tests for every bounded config newtype at min, max, max plus one, zero, and negative input where applicable.
- [ ] Add set-name validation tests for exactly 31 characters, 32 characters, allowed punctuation, and disallowed punctuation.
- [ ] Add set-type validation tests for every allowed separator and representative disallowed bytes.
- [ ] Add blocklist canonicalization tests for comments, blank lines, duplicate CIDRs, host addresses, and trailing tokens.
- [ ] Add config-edit ASN tests for empty lists, multiple values, invalid negatives, and value replacement without damaging unrelated TOML.

## Stage 5: Ipset Atomicity

- [ ] Strengthen temp-set-name tests to assert suffix separator position, truncation budget, fallback base, and UTF-8 boundary handling.
- [ ] Add restore-script tests that fail if create, add, or swap lines are omitted, reordered, duplicated, or written unsorted.
- [ ] Add atomic-replace tests proving stale temp destroy, restore, and final destroy use the same temp name and never issue incremental add commands.
- [ ] Add tests for ipset missing-set and unsupported-terse predicates that reject wrong exit codes and unrelated stderr text.
- [ ] Add a temp restore script cleanup test that verifies the restore file is removed after success and after restore failure if practical.

## Stage 6: Firewall Wiring And Sync

- [ ] Add firewall predicate tests that distinguish missing-chain, missing-rule, permission-denied, and success statuses exactly.
- [ ] Add ensure-wiring tests that verify the single chain name, INPUT position 1, action target, and no unrelated chain commands.
- [ ] Add cleanup tests for missing IPv6 artifacts to prove cleanup is best effort and does not fail sync.
- [ ] Add sync dependency tests that assert config, lock, artifact ensure, source load, safelist subtract, atomic restore, cleanup, log, and unlock order where observable.
- [ ] Add maxelem tests for exact limit, limit plus one, and IPv4/IPv6 error family fields.

## Stage 7: Command, I/O, Lock, And Paths

- [ ] Add `ProcessStatus` tests for exited zero, exited nonzero, and non-code statuses so success and code cannot be collapsed.
- [ ] Add command timeout tests for non-1 ms durations to pin timeout reporting and output-reader joining.
- [ ] Add bounded-read tests for zero, exact limit, over limit by one, and large limit conversion behavior.
- [ ] Add atomic-write collision tests that exercise retry on `AlreadyExists` and error on non-collision open failures.
- [ ] Add lock contention tests proving a held lock returns contention instead of success.
- [ ] Add path-resolution tests for root override precedence, sandbox disable presence, falsey sandbox values, and missing explicit config policy.

## Stage 8: HTTP And GitHub Metadata

- [ ] Add HTTP max-body tests for env values zero, one, default, invalid, and exact response-size limit.
- [ ] Add remote parsing tests for BOM, comments, empty lines, trailing text, invalid UTF-8 lossiness, and IPv4/IPv6 preservation.
- [ ] Add cache fallback tests for body too large with and without valid cache so fallback metadata and networks are pinned.
- [ ] Add header extraction tests through a local HTTP response to verify ETag and Last-Modified are preserved and absent headers stay absent.
- [ ] Add GitHub metadata tests for custom URL cache isolation, missing metadata with custom URL, and sidecar category mismatch.
- [ ] Add GitHub metadata extraction tests for nested arrays/objects, category normalization, all-category mode, and invalid JSON fallback.

## Stage 9: ASN And Source Loading

- [ ] Add bgpq4 resolver tests proving both `-4` and `-6` calls run, outputs are merged, sorted, and deduplicated.
- [ ] Add ASN cache tests for fresh cache, stale refresh success, stale fallback on resolver failure, invalid cache ignored, and write failure propagation.
- [ ] Add ASN output parsing tests for comments, blank lines, invalid lines, and mixed IPv4/IPv6 CIDRs.
- [ ] Add source-file tests for missing cache iplist hash, hash mismatch, oversized file, not-found behavior, and label resolution.
- [ ] Add cached-source stale-age boundary tests for exactly stale and just under stale.

## Stage 10: CLI Operator Behavior

- [ ] Add analyze-overlap CLI tests that pin summary totals, remote table column widths, singular/plural totals, and no-overlap output.
- [ ] Add lookup CLI tests for stdin/file target collection, invalid targets, duplicate targets, and deterministic output ordering.
- [ ] Add blocklist ASN CLI tests for ban, unban, duplicate removal, formatted ASN lists, partial-removal reporting, and no-op totals.
- [ ] Add confirmation-prompt tests for yes, no, EOF, mixed case, and partial entry rendering.
- [ ] Add doctor command tests for fail-fast status, warning status, IPv6 disabled mode, sudo probe failure details, and directory permission bits.
- [ ] Add init/systemd tests for command failure handling, no-op provisioning summaries, and escaping of backslash, quote, and newline values.

## Stage 11: Logging And Diagnostics

- [ ] Decide whether logging format/color missed mutants are operator-visible enough to test or should be documented as low-value diagnostics.
- [ ] Add logging tests for `human`, `journal`, `auto`, invalid env values, systemd detection, and color auto-detection when deemed operator-visible.
- [ ] Add tests for stderr-detail helpers only when their exact text is part of an asserted operator error path.
- [ ] Record any ignored logging, timer, or cosmetic presentation mutants with one-sentence rationale in the stage completion notes.

## Stage 12: Unviable And Timeout Cleanup

- [ ] Spot-check top unviable clusters in `src/core/network.rs`, `src/adapters/http_cache.rs`, `src/adapters/ipset.rs`, `src/adapters/github_meta.rs`, and `src/adapters/command_runner.rs` for dead or confusing code.
- [ ] Simplify production code instead of adding tests where an unviable or missed mutant exposes redundant branches or unreachable helpers.
- [ ] For timeout mutants that are predictable nontermination and not useful tests, propose the narrowest `.cargo/mutants.toml` exclude for user approval.
- [ ] Keep any mutation-test configuration change narrow and explain the suppressed mutant by file, function, and reason.

## Stage 13: Verification And Rerun Handoff

- [ ] After each implementation stage, run `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- [ ] Run `./scripts/dev.sh release-notes-check` after every repo change and include rewritten changelog or release-note files if it changes them.
- [ ] Ask the user to rerun mutation testing after safety-critical stages because agents should not run mutation testing directly.
- [ ] Compare the user's rerun report against this plan and check off completed tasks only when corresponding mutants are caught, justified, or suppressed.
