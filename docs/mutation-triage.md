# Mutation exclusions

Use this guide when reviewing the `exclude_re` patterns in
[`.cargo/mutants.toml`](../.cargo/mutants.toml). The
[development workflow](development.md#mutation-results) describes how to assess user-produced
mutation reports. Mutation execution belongs to the user; agents must not run it.

An exclusion needs a specific reason tied to the observable contract. Keep command attempts,
failure ordering, family selection, bounded execution, and cleanup covered even when a mutation
that changes only a warning or a redundant computation is excluded. A filtered mutation is not
evidence that tests would catch it.

## Patterns that match current code

### Best-effort temporary-set destruction

The match-guard and `||` patterns for `best_effort_destroy_set` in
[`ipset.rs`](../crates/kidobo-adapters/src/ipset.rs) change which command results emit warnings.
They preserve the `ipset destroy` attempt and the best-effort return behavior. These filters do
not justify excluding removal of the command itself or changes to restore/swap ordering.
The adapter tests assert command sequencing and the final destroy attempt after restore failure.

### Diagnostic formatting

The `stderr_detail` replacement pattern changes the text used for empty or trimmed stderr.
It matches helpers in both [`ipset.rs`](../crates/kidobo-adapters/src/ipset.rs) and
[`doctor.rs`](../crates/kidobo-app/src/doctor.rs). Their command results and doctor check statuses
are decided separately. Reassess this pattern if exact diagnostic text becomes a supported
contract or another function with this name is added; the regex does not restrict its module.

### Equivalent sorting and UTF-8 boundary checks

In [`ipset.rs`](../crates/kidobo-adapters/src/ipset.rs):

- Replacing `is_sorted_and_unique` with `false` forces sorting and deduplication even when the input
  already has those properties. The output remains the same; the extra work is the difference.
- Replacing `>` with `>=` in `truncate_to_max_bytes` permits a boundary check at byte index zero.
  Zero is always a UTF-8 character boundary, so the resulting slice is unchanged.
- Replacing `-=` with `/=` in that loop leaves its index unchanged because the operand is one.
  This creates artificial nontermination when truncation lands inside a multibyte character.

Keep the exact prefix and UTF-8 boundary assertions. Revisit these exclusions if either the
fallback algorithm or the loop changes.

### Firewall binary selection

The `FirewallFamily::binary` replacement pattern excludes incorrect replacements of `iptables`
and `ip6tables`. This is a test-execution workaround for integration-test hangs described in the
mutation configuration, rather than equivalent behavior. The `firewall_family_selects_exact_binary`
unit test in [`iptables.rs`](../crates/kidobo-adapters/src/iptables.rs) asserts both mappings.
Reassess the filter when changing command fixtures or family dispatch; retain those exact assertions
and coverage that keeps IPv4 and IPv6 operations separate.

## Patterns without current targets

The configuration also contains patterns for `best_effort_join_output_reader` and
`SyncStageTimer::mark`. Neither symbol exists in the current source, so these patterns currently
exclude nothing. The command executor now polls nonblocking output pipes, and timing is handled by
`LoggingSyncObserver::stage_completed`. Remove obsolete patterns when maintaining the mutation
configuration; do not transfer their rationale to new functions based only on similar names.

## Maintaining the rationale

When changing an exclusion or the code it matches, check its full match scope, identify the
contract it could hide, and retain behavioral coverage for that contract. Record the current
reason here. Keep run-specific commands, counts, and results with the reviewed report or change
record rather than treating them as continuing qualification of later code.
