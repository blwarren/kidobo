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
