# Mutation Testing Remediation Plan

This plan preserves the original repo-wide mutation snapshot and tracks newer scoped reports as stage
follow-ups. The scoped `src/core/network.rs` follow-up is complete; `mutants.out.old` has empty missed and
timeout files and is non-actionable.

Original repo-wide report snapshot:

- `mutants.out/missed.txt`: 212 missed mutants
- `mutants.out/timeout.txt`: 22 timeout mutants
- `mutants.out/unviable.txt`: 314 unviable mutants
- Runner evidence: `cargo-mutants 27.1.0` against package `kidobo 0.10.1`
- Test command evidence: `cargo test --package=kidobo@0.10.1 --all-features --lib --bins --tests`

Current network-only report snapshot:

- `mutants.out/missed.txt`: 14 missed mutants before the run was interrupted
- `mutants.out/timeout.txt`: 6 timeout mutants before the run was interrupted
- `mutants.out/unviable.txt`: 33 unviable mutants before the run was interrupted
- Baseline evidence from the user-run report: clean unmutated baseline, 60 caught mutants before interruption
- Status: complete. All `src/core/network.rs` mutation follow-up items are resolved.

Do not rerun mutation testing from agent turns. Use user-provided mutation reports, and ask the user for a rerun after meaningful stages are complete. When asking for a rerun, provide a targeted command that scopes mutation testing to the code changed in that stage.

## Priorities

Address missed and timeout mutants in this order:

1. Firewall safety and ipset atomicity
2. Deterministic core interval, safelist, lookup, and config behavior
3. Cache, source-loading, and path/lock correctness
4. Stable operator-visible CLI behavior
5. Low-risk diagnostics, cosmetic output, equivalent mutants, and unviable triage

Each stage is intended to be small enough for one focused implementation turn.

## Stage 0: Baseline Triage

- [x] Confirm the unmutated `cargo test --lib --bins --tests --all-features` baseline passes before changing tests.
- [x] Reconcile `mutants.out/missed.txt` and `mutants.out/timeout.txt` against current source line numbers before coding.
- [x] Classify each targeted mutant as safety-critical, operator-visible, equivalent, low-value diagnostic, or timeout-only before adding tests.
- [x] Track any intentionally ignored missed mutants in the stage completion notes with a brief rationale.

Stage 0 completion notes from 2026-06-23:

- Baseline passed with `cargo test --lib --bins --tests --all-features`: 328 library tests, 0 binary tests, and 31 integration tests.
- Report reconciliation found 212 missed mutants and 22 timeout mutants, matching the snapshot above.
- Every referenced `file:line` entry in `mutants.out/missed.txt` and `mutants.out/timeout.txt` still points to an existing, nonblank source line in the current tree.
- No missed mutants were intentionally ignored during Stage 0. Equivalent and low-value diagnostic decisions remain stage-local until the exact mutant is addressed or explicitly deferred.
- Timeout entries were classified as timeout-only for triage. Do not suppress them without later review of whether the timeout exposes a termination, retry, or cleanup risk.

| Area | Missed | Timeout | Stage 0 classification | Planned follow-up |
| --- | ---: | ---: | --- | --- |
| `src/core/network.rs` | 29 | 16 | Safety-critical deterministic core | Completed in Stages 1 and 2 |
| `src/core/blocklist_analysis.rs` | 12 | 3 | Safety-critical deterministic core | Stage 3 |
| `src/core/lookup.rs` | 3 | 0 | Safety-critical deterministic core | Stage 3 |
| `src/core/config.rs` | 14 | 0 | Safety-critical config validation | Stage 4 |
| `src/core/blocklist.rs` | 2 | 0 | Safety-critical blocklist parsing | Stage 4 |
| `src/adapters/ipset.rs` | 26 | 1 | Safety-critical firewall atomicity | Stage 5 |
| `src/adapters/iptables.rs` | 3 | 1 | Safety-critical firewall wiring | Stage 6 |
| `src/app/sync.rs` | 4 | 0 | Safety-critical sync ordering and cleanup | Stage 6 |
| `src/cli/flush.rs` | 2 | 0 | Safety-critical cleanup command behavior | Stage 6 |
| `src/adapters/limited_io.rs` | 5 | 0 | Safety-critical bounded I/O and atomic writes | Stage 7 |
| `src/adapters/lock.rs` | 1 | 0 | Safety-critical lock contention | Stage 7 |
| `src/adapters/path.rs` | 2 | 0 | Safety-critical path resolution | Stage 7 |
| `src/adapters/command_runner.rs` | 2 | 1 | Operator-visible command execution and timeout behavior | Stage 7 |
| `src/adapters/http_cache.rs` | 13 | 0 | Source-loading and cache correctness | Stage 8 |
| `src/adapters/github_meta.rs` | 7 | 0 | Source-loading and metadata cache correctness | Stage 8 |
| `src/adapters/asn.rs` | 3 | 0 | Source-loading correctness | Stage 9 |
| `src/adapters/source_files.rs` | 4 | 0 | Source-loading correctness | Stage 9 |
| `src/cli/commands.rs` | 28 | 0 | Operator-visible CLI output and lookup behavior | Stage 10 |
| `src/cli/blocklist/asn.rs` | 9 | 0 | Operator-visible blocklist ASN behavior | Stage 10 |
| `src/cli/blocklist/confirm.rs` | 8 | 0 | Operator-visible confirmation behavior | Stage 10 |
| `src/cli/blocklist/plan.rs` | 1 | 0 | Operator-visible blocklist planning | Stage 10 |
| `src/cli/blocklist/targets.rs` | 3 | 0 | Operator-visible blocklist target handling | Stage 10 |
| `src/cli/doctor/checks.rs` | 5 | 0 | Operator-visible diagnostics | Stage 10 |
| `src/cli/doctor/mod.rs` | 3 | 0 | Operator-visible diagnostics | Stage 10 |
| `src/cli/doctor/probes.rs` | 5 | 0 | Operator-visible diagnostics | Stage 10 |
| `src/cli/init/provision.rs` | 1 | 0 | Operator-visible install behavior | Stage 10 |
| `src/cli/init/systemd.rs` | 2 | 0 | Operator-visible install behavior | Stage 10 |
| `src/cli/init/templates.rs` | 3 | 0 | Operator-visible install behavior | Stage 10 |
| `src/adapters/config_edit.rs` | 3 | 0 | Operator-visible config edit behavior | Stage 10 |
| `src/logging.rs` | 9 | 0 | Low-value diagnostic unless exact output is operator-visible | Stage 11 |

## Stage 1: Core Interval Conversion

- [x] Add IPv4 tests for `/0`, `/32`, non-zero host-bit canonicalization, and max-address interval endpoints.
- [x] Add IPv6 tests for `/0`, `/128`, high-bit networks, and max-address interval endpoints.
- [x] Add interval-to-CIDR tests for single-host, two-host, unaligned, and max-boundary ranges in both families.
- [x] Add a large unsorted IPv4 input test that forces radix sorting and proves output matches ordinary sorting.
- [x] Review timeout mutants in `intervals_to_*`, `largest_prefix_*`, and `is_aligned_*` for explicit progress assertions or documented skip candidates.

Stage 1 completion notes from 2026-06-23:

- Added boundary tests for IPv4 `/0`, `/32`, host-bit canonicalization, and intervals ending at `u32::MAX`.
- Added boundary tests for IPv6 `/0`, `/128`, high-bit network canonicalization, and intervals ending at `u128::MAX`.
- Added interval-to-CIDR tests for single-host, two-host, unaligned, and max-boundary ranges for both families.
- Added a large unsorted IPv4 merge test that exceeds the radix-sort threshold and verifies output against an independent ordinary-sort merge helper.
- Reworked CIDR regeneration increments to use checked shifts, largest-prefix search to use bounded descending prefix ranges, and alignment masks to use checked right shifts. This addresses timeout-only mutation risks without suppressions.
- Stage-local ignored missed mutants: `ipv4_to_interval` and `ipv6_to_interval` `|` to `^` is equivalent for valid `Ipv4Cidr` and `Ipv6Cidr` values because constructors and `from_parts` canonicalize host bits before interval conversion.
- Stage-local ignored missed mutants: radix-sort fallback mutations that still return ordinary sorted output are performance-path changes, not observable correctness changes. The large-input test pins output equivalence rather than over-specifying whether fallback sorting ran.

Stage 1 network-only follow-up notes from 2026-06-23:

- Re-reviewed the current scoped `mutants.out` report: 14 missed, 6 timeout, and 33 unviable results in
  `src/core/network.rs` before interruption. `mutants.out.old` is not actionable because its missed and
  timeout files are empty.
- Replaced branchy IPv4 and IPv6 host-mask logic with shared checked-shift helpers, then reused those
  helpers for CIDR interval conversion, block-end calculation, and network masks.
- Added direct radix-sort tests that assert successful sorting, preservation of every interval, mixed high
  and low 16-bit start handling, and two-item sorting. These target bucket extraction and shift mutants in
  both radix passes without testing whether the merge path chose radix sorting or ordinary sorting.
- Added full IPv4 and IPv6 address-space interval regeneration tests that require `/0` output. Existing
  max-tail regeneration tests still pin preservation of the final address near `u32::MAX` and `u128::MAX`.
- Intentional non-fix: `start | suffix` to `start ^ suffix` in interval conversion is equivalent for valid
  `Ipv4Cidr` and `Ipv6Cidr` values because constructors canonicalize host bits before conversion.
- Intentional non-fix: the `radix_sort_intervals_u32_by_start` length guard changed from `<` to `==` is
  equivalent for observable output because an empty slice still returns `true` unchanged after the two
  no-op passes.
- Intentional non-fix: radix threshold and fallback mutations that only swap between radix sort and
  ordinary sort are performance-path mutants when the sorted output is unchanged.
- Intentional non-fix: the `intervals_to_ipv*_cidrs_from_merged` overflow guard changed from `>` to `>=`
  is equivalent for observable output on valid merged intervals; equality occurs only after a CIDR has
  already covered the last address needed for that interval.
- Timeout triage: `ipv4_to_interval` `==` to `!=`, `ipv6_to_interval` `|` to `&`, and `+=` to `*=` in CIDR
  regeneration are artificial timeout risks under mutation, not supported-input nontermination in the
  original code after the checked-shift and bounded-progress cleanup.
- Unviable default-value mutants remain inconclusive unless a later review finds dead, redundant, or
  confusing production code.
- Agents did not run mutation execution. The scoped `src/core/network.rs` follow-up is now complete.

## Stage 2: Safelist Subtraction

- [x] Add IPv4 safelist subtraction tests for first-address, last-address, middle split, full removal, and no-overlap cases.
- [x] Add IPv6 safelist subtraction tests for first-address, last-address, middle split, full removal, and high-bit tail boundaries.
- [x] Add tests where multiple safelist entries carve one candidate so ignoring later safelist entries fails.
- [x] Add order-independence tests with unsorted candidates and unsorted safelist entries.
- [x] Add adjacency tests proving adjacent blocklist intervals merge while carved output remains minimal and non-overlapping.

Stage 2 completion notes from 2026-06-23:

- The remaining `src/core/network.rs` safelist subtraction mutants are resolved.
- This completes the network-only follow-up tracked by Stages 1 and 2. No open `src/core/network.rs`
  mutation remediation remains in this plan.

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

- [x] Spot-check top unviable clusters in `src/core/network.rs` for dead or confusing code.
- [ ] Spot-check top unviable clusters in `src/adapters/http_cache.rs`, `src/adapters/ipset.rs`, `src/adapters/github_meta.rs`, and `src/adapters/command_runner.rs` for dead or confusing code.
- [ ] Simplify production code instead of adding tests where an unviable or missed mutant exposes redundant branches or unreachable helpers.
- [ ] For timeout mutants that are predictable nontermination and not useful tests, propose the narrowest `.cargo/mutants.toml` exclude for user approval.
- [ ] Keep any mutation-test configuration change narrow and explain the suppressed mutant by file, function, and reason.

## Stage 13: Verification And Rerun Handoff

- [ ] After each implementation stage, run `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-targets --all-features`.
- [ ] Run `./scripts/dev.sh release-notes-check` after every repo change and include rewritten changelog or release-note files if it changes them.
- [ ] Ask the user to rerun mutation testing after safety-critical stages because agents should not run mutation testing directly.
- [ ] Compare the user's rerun report against this plan and check off completed tasks only when corresponding mutants are caught, justified, or suppressed.

Completed scoped network reruns for `src/core/network.rs`:

```bash
cargo mutants --no-config --file src/core/network.rs --re 'ipv[46]_to_interval|intervals_to_ipv[46]_cidrs|largest_prefix|is_aligned|block_end|ipv[46]_mask' --all-features --minimum-test-timeout 60 --timeout-multiplier 3 --build-timeout-multiplier 3 -- --lib --bins --tests
cargo mutants --no-config --file src/core/network.rs --re 'merge_intervals|sort_intervals|radix_sort' --all-features --minimum-test-timeout 60 --timeout-multiplier 3 --build-timeout-multiplier 3 -- --lib --bins --tests
cargo mutants --no-config --file src/core/network.rs --re 'subtract_intervals|subtract_safelist|intervals_overlap|cidr_overlaps' --all-features --minimum-test-timeout 60 --timeout-multiplier 3 --build-timeout-multiplier 3 -- --lib --bins --tests
```

No further scoped `src/core/network.rs` mutation rerun is pending from this plan.
