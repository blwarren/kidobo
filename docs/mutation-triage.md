# Mutation result triage

This note records the review of the user-produced `mutants.out` reports. Codex
does not run mutation testing for this repository.

The four missed `||` to `&&` mutations in the empty-input guards of
`count_overlapping_ipv4`, `count_overlapping_ipv6`, `fully_covered_ipv4`, and
`fully_covered_ipv6` are equivalent. If either input is empty, the downstream
loops still return the same empty or zero result, so tests should not encode
which early-return expression is used.

The three timeout mutations replace forward index increments with
multiplication in the IPv4 overlap scan and the IPv4/IPv6 coverage scans. They
create artificial non-progress loops rather than a plausible production
behavior. They should be handled with narrow cargo-mutants exclusions if they
continue to time out in a future user-run report, rather than with tests that
depend on internal loop mechanics.

The behavioral IPv6 overlap, coverage, endpoint, and nested lookup gaps from the
remaining missed mutations are covered by focused regression tests in the core
modules.

The incremental run covering production changes since `480d98f` found seven
missed mutations. Three exposed operator-visible human lookup gaps: removing
table borders, coloring continuation rows instead of the first status row, and
omitting the dim `NO MATCH` style. Exact border and color-placement regression
tests now cover those behaviors.

The other four mutations do not change the relevant production outcome. One
removes the best-effort join after the command process tree has already been
terminated and waited upon. Three change only whether a failed or already
missing temporary ipset destroy emits a warning; the destroy command and
best-effort return behavior are unchanged. Narrow `exclude_re` entries keep
future mutation runs focused without suppressing command sequencing or cleanup
attempt coverage.

The focused rerun confirmed the remediation: 74 mutants were evaluated, with
41 caught, 33 unviable, no missed mutants, and no timeouts. The three lookup
mutants are now caught, and the four documented non-behavioral mutations are
excluded. This incremental triage is complete; the unviable results remain
inconclusive and do not justify score-driven test changes.

The broader safety-critical run from 2026-07-18 evaluated 265 mutants across
configuration, sync orchestration, command execution, locking, ipset,
iptables, and flush behavior. The unmutated baseline passed. The report
contained 47 missed, 3 timeout, 76 unviable, and 139 caught mutants.

The meaningful gaps now have focused behavioral coverage. Tests pin exact
configuration time bounds and validated-newtype conversions, the 31-byte ipset
name boundary, explicit `hash:net` parsing, nontrivial timeout conversion,
lock and command-error classifiers, deterministic sorting and deduplication,
temporary restore-script deletion on success and failure, UTF-8-safe byte
truncation, temporary-set suffix sizing, and exact IPv4/IPv6 firewall binary
selection. Redundant postcondition branches in temporary-set naming and
disabled-IPv6 cleanup were simplified without changing production behavior.
Test-only restore-script read limits now use their literal byte value so
mutation testing does not spend time varying fixture arithmetic.

Eight reported mutations are intentionally filtered. Diagnostic-only changes
to `stderr_detail` and the disabled sync timer have no stable operator-visible
contract. Forcing `is_sorted_and_unique` to return false is equivalent because
the fallback still sorts and deduplicates. Allowing the UTF-8 truncation loop
to inspect byte index zero is equivalent because zero is always a character
boundary, while replacing its decrement with division creates artificial
non-progress. The two `FirewallFamily::binary` replacement mutants are covered
by exact unit assertions but cause unrelated integration tests to hang before
cargo-mutants can classify the failure, so they are excluded narrowly by
function name. The 76 unviable mutants remain inconclusive and are not a reason
for score-driven production changes.

The 2026-07-18 user-run confirmation rerun evaluated 246 selected mutants. The
unmutated baseline passed; 170 mutants were caught, 76 were unviable, and none
were missed or timed out. This confirms that all viable selected mutants are
either behaviorally covered or intentionally excluded. The safety-critical
triage is complete, and the unviable results require no score-driven follow-up.
