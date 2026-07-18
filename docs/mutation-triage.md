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
