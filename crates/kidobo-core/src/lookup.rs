//! Offline lookup of operator targets against canonical source entries.

use std::sync::Arc;

use thiserror::Error;

use crate::network::{CanonicalCidr, ipv4_to_interval, ipv6_to_interval, parse_ip_cidr_strict};

/// One canonical CIDR retained with its operator-visible source context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupSourceEntry {
    /// Stable source label used in lookup output.
    pub source_label: Arc<str>,
    /// Original source line shown to the operator when matched.
    pub source_line: String,
    /// Canonical CIDR used for overlap matching.
    pub cidr: CanonicalCidr,
}

/// One target-to-source overlap reported by a lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupMatch {
    /// Original lookup target text.
    pub target: String,
    /// Label of the source containing the match.
    pub source_label: String,
    /// Original source entry containing the matched CIDR.
    pub matched_source_entry: String,
    /// Canonical source CIDR that overlaps the target.
    pub matched_cidr: CanonicalCidr,
}

/// Deterministically ordered matches and invalid lookup targets.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LookupReport {
    /// Valid target-to-source overlaps.
    pub matches: Vec<LookupMatch>,
    /// Sorted, unique target strings that could not be parsed.
    pub invalid_targets: Vec<String>,
}

/// Reason a strict lookup target could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LookupTargetParseError {
    /// The target is empty after trimming.
    #[error("lookup target is empty")]
    Empty,
    /// The target is not exactly one IP address or CIDR.
    #[error("lookup target is not exactly one valid IP address or CIDR")]
    Invalid,
}

/// Parses one lookup target using strict token rules.
///
/// # Errors
///
/// Returns [`LookupTargetParseError::Invalid`] when the input is not exactly one valid IP or
/// CIDR.
pub fn parse_target_strict(input: &str) -> Result<CanonicalCidr, LookupTargetParseError> {
    let normalized = input.trim();
    if normalized.is_empty() {
        return Err(LookupTargetParseError::Empty);
    }

    parse_ip_cidr_strict(normalized).ok_or(LookupTargetParseError::Invalid)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IndexedSource<T> {
    start: T,
    end: T,
    source_idx: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IntervalIndex<T> {
    entries: Vec<IndexedSource<T>>,
    subtree_max_ends: Vec<T>,
}

impl<T: Copy + Ord + Default> IntervalIndex<T> {
    fn new(entries: impl Iterator<Item = IndexedSource<T>>) -> Self {
        let mut entries = entries.collect::<Vec<_>>();
        entries.sort_unstable_by_key(|entry| (entry.start, entry.end));
        let mut subtree_max_ends = vec![T::default(); entries.len()];
        Self::set_subtree_max_ends(&entries, &mut subtree_max_ends);
        Self {
            entries,
            subtree_max_ends,
        }
    }

    // The median of each sorted slice is its subtree root. Parallel arrays keep the
    // maximum end per root without padding each IPv4 entry to the index's alignment.
    fn set_subtree_max_ends(entries: &[IndexedSource<T>], max_ends: &mut [T]) -> Option<T> {
        let median = entries.len() / 2;
        let (left, rest) = entries.split_at(median);
        let (root, right) = rest.split_first()?;
        let (left_max_ends, rest) = max_ends.split_at_mut(median);
        let (root_max, right_max_ends) = rest.split_first_mut()?;

        *root_max = root
            .end
            .max(Self::set_subtree_max_ends(left, left_max_ends).unwrap_or(root.end))
            .max(Self::set_subtree_max_ends(right, right_max_ends).unwrap_or(root.end));
        Some(*root_max)
    }

    fn visit_overlaps(&self, start: T, end: T, mut emit: impl FnMut(usize)) -> usize {
        Self::visit_subtree(&self.entries, &self.subtree_max_ends, start, end, &mut emit)
    }

    // Returns the number of nodes examined so tests can assert the pruning behavior.
    fn visit_subtree(
        entries: &[IndexedSource<T>],
        max_ends: &[T],
        start: T,
        end: T,
        emit: &mut impl FnMut(usize),
    ) -> usize {
        let median = entries.len() / 2;
        let (left_max_ends, rest) = max_ends.split_at(median);
        let Some((&root_max, right_max_ends)) = rest.split_first() else {
            return 0;
        };
        if root_max < start {
            return 1;
        }

        let (left, rest) = entries.split_at(median);
        let Some((root, right)) = rest.split_first() else {
            return 1;
        };
        let mut visited = 1 + Self::visit_subtree(left, left_max_ends, start, end, emit);
        if root.start <= end {
            if root.end >= start {
                emit(root.source_idx);
            }
            visited += Self::visit_subtree(right, right_max_ends, start, end, emit);
        }
        visited
    }
}

fn compare_source_entries(a: &LookupSourceEntry, b: &LookupSourceEntry) -> std::cmp::Ordering {
    (a.source_label.as_ref(), a.source_line.as_str(), a.cidr).cmp(&(
        b.source_label.as_ref(),
        b.source_line.as_str(),
        b.cidr,
    ))
}

fn same_source_entry(a: &LookupSourceEntry, b: &LookupSourceEntry) -> bool {
    a.source_label == b.source_label && a.source_line == b.source_line && a.cidr == b.cidr
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PreparedTarget<'a> {
    raw: &'a str,
    parsed: CanonicalCidr,
}

fn prepare_targets<S: AsRef<str>>(targets: &[S]) -> (Vec<PreparedTarget<'_>>, Vec<String>) {
    let mut prepared = Vec::with_capacity(targets.len());
    let mut invalid_targets = Vec::<&str>::new();

    for target in targets {
        let raw = target.as_ref();
        match parse_target_strict(raw) {
            Ok(parsed) => prepared.push(PreparedTarget { raw, parsed }),
            Err(_) => invalid_targets.push(raw),
        }
    }

    prepared.sort_unstable_by_key(|target| target.raw);
    prepared.dedup_by(|left, right| left.raw == right.raw);

    invalid_targets.sort_unstable();
    invalid_targets.dedup();

    (
        prepared,
        invalid_targets.into_iter().map(str::to_string).collect(),
    )
}

fn target_matches<'a>(
    target: PreparedTarget<'_>,
    sources: &'a [LookupSourceEntry],
    v4_index: &IntervalIndex<u32>,
    v6_index: &IntervalIndex<u128>,
) -> Vec<&'a LookupSourceEntry> {
    let mut matched_sources = Vec::new();
    let mut emit = |source_idx| {
        if let Some(source) = sources.get(source_idx) {
            matched_sources.push(source);
        }
    };

    match target.parsed {
        CanonicalCidr::V4(cidr) => {
            let interval = ipv4_to_interval(cidr);
            v4_index.visit_overlaps(interval.start, interval.end, &mut emit);
        }
        CanonicalCidr::V6(cidr) => {
            let interval = ipv6_to_interval(cidr);
            v6_index.visit_overlaps(interval.start, interval.end, emit);
        }
    }

    matched_sources.sort_unstable_by(|left, right| compare_source_entries(left, right));
    matched_sources.dedup_by(|left, right| same_source_entry(left, right));

    matched_sources
}

/// Runs indexed lookup once per valid target and emits each target's complete match slice.
///
/// Targets and matches are emitted deterministically. The returned strings are sorted, unique
/// invalid targets.
pub fn run_lookup_by_target<S, F>(
    targets: &[S],
    sources: &[LookupSourceEntry],
    mut emit: F,
) -> Vec<String>
where
    S: AsRef<str>,
    F: FnMut(&str, &[&LookupSourceEntry]),
{
    let Ok(invalid_targets) = try_run_lookup_by_target(targets, sources, |target, matches| {
        emit(target, matches);
        Ok::<(), std::convert::Infallible>(())
    });
    invalid_targets
}

/// Runs indexed lookup with a fallible callback for each valid target's borrowed matches.
///
/// Targets and matches are deterministic, including empty batches for unmatched targets.
/// Returns sorted, unique invalid targets after all valid batches have been emitted.
///
/// # Errors
///
/// Returns the callback's error immediately without processing further targets.
pub fn try_run_lookup_by_target<S, F, E>(
    targets: &[S],
    sources: &[LookupSourceEntry],
    mut emit: F,
) -> Result<Vec<String>, E>
where
    S: AsRef<str>,
    F: FnMut(&str, &[&LookupSourceEntry]) -> Result<(), E>,
{
    let v4_index = IntervalIndex::new(sources.iter().enumerate().filter_map(
        |(source_idx, source)| {
            let CanonicalCidr::V4(cidr) = source.cidr else {
                return None;
            };
            let interval = ipv4_to_interval(cidr);
            Some(IndexedSource {
                start: interval.start,
                end: interval.end,
                source_idx,
            })
        },
    ));
    let v6_index = IntervalIndex::new(sources.iter().enumerate().filter_map(
        |(source_idx, source)| {
            let CanonicalCidr::V6(cidr) = source.cidr else {
                return None;
            };
            let interval = ipv6_to_interval(cidr);
            Some(IndexedSource {
                start: interval.start,
                end: interval.end,
                source_idx,
            })
        },
    ));
    let (prepared_targets, invalid_targets) = prepare_targets(targets);

    for target in prepared_targets {
        let matched_sources = target_matches(target, sources, &v4_index, &v6_index);
        emit(target.raw, &matched_sources)?;
    }

    Ok(invalid_targets)
}

/// Runs indexed lookup and emits one callback per target-to-source match.
///
/// Returns sorted, unique invalid targets after all valid matches have been emitted.
pub fn run_lookup_streaming<S, F>(
    targets: &[S],
    sources: &[LookupSourceEntry],
    mut emit: F,
) -> Vec<String>
where
    S: AsRef<str>,
    F: FnMut(&str, &LookupSourceEntry),
{
    run_lookup_by_target(targets, sources, |target, matched_sources| {
        for source in matched_sources {
            emit(target, source);
        }
    })
}

/// Produces a complete deterministic lookup report for all targets.
#[must_use]
pub fn run_lookup<S: AsRef<str>>(targets: &[S], sources: &[LookupSourceEntry]) -> LookupReport {
    let mut matches = Vec::new();
    let invalid_targets = run_lookup_streaming(targets, sources, |target, source| {
        matches.push(LookupMatch {
            target: target.to_string(),
            source_label: source.source_label.to_string(),
            matched_source_entry: source.source_line.clone(),
            matched_cidr: source.cidr,
        });
    });

    LookupReport {
        matches,
        invalid_targets,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LookupSourceEntry, LookupTargetParseError, parse_target_strict, run_lookup,
        run_lookup_by_target, run_lookup_streaming,
    };
    use crate::network::{CanonicalCidr, Ipv4Cidr, Ipv6Cidr, cidr_overlaps};

    #[test]
    fn fallible_batches_stop_at_first_error_in_sorted_target_order() {
        let mut emitted = Vec::new();
        let result = super::try_run_lookup_by_target(
            &["203.0.113.9", "invalid", "198.51.100.8", "192.0.2.1"],
            &[],
            |target, matches| {
                assert_eq!(matches.len(), 0);
                emitted.push(target.to_string());
                if target == "198.51.100.8" {
                    Err(42_u8)
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(result, Err(42));
        assert_eq!(emitted, ["192.0.2.1", "198.51.100.8"]);
    }

    #[test]
    fn strict_target_parsing_accepts_ip_and_cidr() {
        let host = parse_target_strict("198.51.100.1").expect("host");
        assert_eq!(
            host,
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0xc633_6401, 32))
        );

        let cidr = parse_target_strict("2001:db8::/64").expect("cidr");
        assert_eq!(
            cidr,
            CanonicalCidr::V6(Ipv6Cidr::from_parts(
                0x2001_0db8_0000_0000_0000_0000_0000_0000,
                64
            ))
        );
    }

    #[test]
    fn strict_target_parsing_rejects_non_strict_forms() {
        assert_eq!(parse_target_strict(""), Err(LookupTargetParseError::Empty));
        assert_eq!(
            parse_target_strict("10.0.0.1 trailing"),
            Err(LookupTargetParseError::Invalid)
        );
        assert_eq!(
            parse_target_strict("not-an-ip"),
            Err(LookupTargetParseError::Invalid)
        );
    }

    #[test]
    fn overlap_matching_is_family_aware() {
        let v4_a = CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a00_0000, 24));
        let v4_b = CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a00_0080, 25));
        let v6 = CanonicalCidr::V6(Ipv6Cidr::from_parts(
            0x2001_0db8_0000_0000_0000_0000_0000_0000,
            64,
        ));

        assert!(cidr_overlaps(v4_a, v4_b));
        assert!(!cidr_overlaps(v4_a, v6));
    }

    #[test]
    fn lookup_reports_matches_and_invalid_targets() {
        let sources = vec![
            LookupSourceEntry {
                source_label: "internal:blocklist".into(),
                source_line: "10.0.0.0/24".to_string(),
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a00_0000, 24)),
            },
            LookupSourceEntry {
                source_label: "remote:abcd1234.iplist".into(),
                source_line: "2001:db8::/64".to_string(),
                cidr: CanonicalCidr::V6(Ipv6Cidr::from_parts(
                    0x2001_0db8_0000_0000_0000_0000_0000_0000,
                    64,
                )),
            },
        ];

        let report = run_lookup(
            &[
                "10.0.0.7".to_string(),
                "2001:db8::5".to_string(),
                "invalid".to_string(),
            ],
            &sources,
        );

        assert_eq!(report.invalid_targets, vec!["invalid".to_string()]);
        assert_eq!(report.matches.len(), 2);

        assert_eq!(report.matches[0].target, "10.0.0.7");
        assert_eq!(report.matches[0].source_label, "internal:blocklist");
        assert_eq!(report.matches[0].matched_source_entry, "10.0.0.0/24");

        assert_eq!(report.matches[1].target, "2001:db8::5");
        assert_eq!(report.matches[1].source_label, "remote:abcd1234.iplist");
        assert_eq!(report.matches[1].matched_source_entry, "2001:db8::/64");
    }

    #[test]
    fn lookup_index_v6_keeps_endpoint_boundary_matches() {
        let sources = vec![LookupSourceEntry {
            source_label: "source:v6-boundary".into(),
            source_line: "2001:db8::/124".to_string(),
            cidr: CanonicalCidr::V6(Ipv6Cidr::from_parts(
                0x2001_0db8_0000_0000_0000_0000_0000_0000,
                124,
            )),
        }];

        let report = run_lookup(&["2001:db8::f".to_string()], &sources);

        assert_eq!(report.invalid_targets.len(), 0);
        assert_eq!(report.matches.len(), 1);
        assert_eq!(report.matches[0].source_label, "source:v6-boundary");
        assert_eq!(report.matches[0].matched_source_entry, "2001:db8::/124");
    }

    #[test]
    fn lookup_index_handles_non_overlapping_prefix_sections() {
        let sources = vec![
            LookupSourceEntry {
                source_label: "source:a".into(),
                source_line: "10.0.0.0/24".to_string(),
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a00_0000, 24)),
            },
            LookupSourceEntry {
                source_label: "source:b".into(),
                source_line: "10.0.2.0/24".to_string(),
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a00_0200, 24)),
            },
            LookupSourceEntry {
                source_label: "source:c".into(),
                source_line: "10.0.4.0/24".to_string(),
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a00_0400, 24)),
            },
        ];

        let report = run_lookup(&["10.0.2.7".to_string()], &sources);
        assert_eq!(report.matches.len(), 1);
        assert_eq!(report.matches[0].source_label, "source:b");
    }

    #[test]
    fn streaming_lookup_dedups_duplicate_targets_and_sources() {
        let sources = vec![
            LookupSourceEntry {
                source_label: "source:a".into(),
                source_line: "10.0.0.0/24".to_string(),
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a00_0000, 24)),
            },
            LookupSourceEntry {
                source_label: "source:a".into(),
                source_line: "10.0.0.0/24".to_string(),
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a00_0000, 24)),
            },
        ];

        let targets = vec!["10.0.0.7".to_string(), "10.0.0.7".to_string()];
        let mut emitted = Vec::new();
        let invalid = run_lookup_streaming(&targets, &sources, |target, source| {
            emitted.push((
                target.to_string(),
                source.source_label.to_string(),
                source.source_line.clone(),
                source.cidr,
            ));
        });

        assert_eq!(invalid.len(), 0);
        assert_eq!(emitted.len(), 1);
        assert_eq!(emitted[0].0, "10.0.0.7");
        assert_eq!(emitted[0].1, "source:a");
        assert_eq!(emitted[0].2, "10.0.0.0/24");
    }

    #[test]
    fn lookup_by_target_emits_empty_matches_for_valid_target() {
        let mut emitted = Vec::new();
        let invalid = run_lookup_by_target(&["198.51.100.9"], &[], |target, matches| {
            emitted.push((target.to_string(), matches.len()));
        });

        assert_eq!(invalid.len(), 0);
        assert_eq!(emitted, vec![("198.51.100.9".to_string(), 0)]);
    }

    #[test]
    fn lookup_preserves_distinct_source_lines_for_same_label_and_cidr() {
        let sources = vec![
            LookupSourceEntry {
                source_label: "source:a".into(),
                source_line: "10.0.0.0/24".to_string(),
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a00_0000, 24)),
            },
            LookupSourceEntry {
                source_label: "source:a".into(),
                source_line: "10.0.0.42/24".to_string(),
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a00_0000, 24)),
            },
        ];

        let report = run_lookup(&["10.0.0.7".to_string()], &sources);
        let matched_source_entries = report
            .matches
            .iter()
            .map(|m| m.matched_source_entry.as_str())
            .collect::<Vec<_>>();

        assert_eq!(matched_source_entries, vec!["10.0.0.0/24", "10.0.0.42/24"]);
    }

    #[test]
    fn lookup_index_keeps_supernet_matches() {
        let sources = vec![
            LookupSourceEntry {
                source_label: "source:super".into(),
                source_line: "10.0.0.0/8".to_string(),
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a00_0000, 8)),
            },
            LookupSourceEntry {
                source_label: "source:narrow".into(),
                source_line: "10.2.0.0/16".to_string(),
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a02_0000, 16)),
            },
        ];

        let report = run_lookup(&["10.2.3.4".to_string()], &sources);
        let labels = report
            .matches
            .iter()
            .map(|m| m.source_label.as_str())
            .collect::<Vec<_>>();

        assert_eq!(labels, vec!["source:narrow", "source:super"]);
    }

    #[test]
    fn lookup_target_supernets_keep_nested_source_matches() {
        let sources = vec![
            LookupSourceEntry {
                source_label: "source:v6-nested".into(),
                source_line: "2001:db8:0:1::/64".to_string(),
                cidr: CanonicalCidr::V6(Ipv6Cidr::from_parts(
                    0x2001_0db8_0000_0001_0000_0000_0000_0000,
                    64,
                )),
            },
            LookupSourceEntry {
                source_label: "source:v4-outside".into(),
                source_line: "10.2.0.0/24".to_string(),
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a02_0000, 24)),
            },
            LookupSourceEntry {
                source_label: "source:v4-nested".into(),
                source_line: "10.1.2.0/24".to_string(),
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a01_0200, 24)),
            },
        ];

        let report = run_lookup(
            &["10.1.0.0/16".to_string(), "2001:db8::/48".to_string()],
            &sources,
        );
        let matches = report
            .matches
            .iter()
            .map(|entry| (entry.target.as_str(), entry.source_label.as_str()))
            .collect::<Vec<_>>();

        assert_eq!(
            matches,
            vec![
                ("10.1.0.0/16", "source:v4-nested"),
                ("2001:db8::/48", "source:v6-nested"),
            ]
        );
    }

    #[test]
    fn lookup_index_keeps_same_start_nested_matches() {
        let sources = vec![
            LookupSourceEntry {
                source_label: "source:super".into(),
                source_line: "10.0.0.0/8".to_string(),
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a00_0000, 8)),
            },
            LookupSourceEntry {
                source_label: "source:narrow".into(),
                source_line: "10.0.0.0/16".to_string(),
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a00_0000, 16)),
            },
        ];

        let report = run_lookup(&["10.0.2.7".to_string()], &sources);
        let labels = report
            .matches
            .iter()
            .map(|m| m.source_label.as_str())
            .collect::<Vec<_>>();

        assert_eq!(labels, vec!["source:narrow", "source:super"]);
    }

    #[test]
    fn lookup_ipv6_index_keeps_same_start_nested_matches() {
        let base = 0x2001_0db8_0000_0000_0000_0000_0000_0000_u128;
        let sources = vec![
            LookupSourceEntry {
                source_label: "source:super".into(),
                source_line: "2001:db8::/48".to_string(),
                cidr: CanonicalCidr::V6(Ipv6Cidr::from_parts(base, 48)),
            },
            LookupSourceEntry {
                source_label: "source:narrow".into(),
                source_line: "2001:db8::/64".to_string(),
                cidr: CanonicalCidr::V6(Ipv6Cidr::from_parts(base, 64)),
            },
        ];

        let report = run_lookup(&["2001:db8::7".to_string()], &sources);
        let labels = report
            .matches
            .iter()
            .map(|entry| entry.source_label.as_str())
            .collect::<Vec<_>>();

        assert_eq!(labels, vec!["source:narrow", "source:super"]);
    }

    #[test]
    fn lookup_preserves_distinct_source_labels_for_same_cidr() {
        let sources = vec![
            LookupSourceEntry {
                source_label: "feed:a".into(),
                source_line: "10.0.0.0/24".to_string(),
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a00_0000, 24)),
            },
            LookupSourceEntry {
                source_label: "feed:b".into(),
                source_line: "10.0.0.0/24".to_string(),
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a00_0000, 24)),
            },
        ];

        let report = run_lookup(&["10.0.0.7".to_string()], &sources);
        let labels = report
            .matches
            .iter()
            .map(|m| m.source_label.as_str())
            .collect::<Vec<_>>();

        assert_eq!(labels, vec!["feed:a", "feed:b"]);
    }

    #[test]
    fn lookup_keeps_distinct_raw_targets_that_parse_to_same_cidr() {
        let sources = vec![LookupSourceEntry {
            source_label: "source:a".into(),
            source_line: "203.0.113.7/32".to_string(),
            cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0xcb00_7107, 32)),
        }];

        let report = run_lookup(
            &["203.0.113.7".to_string(), "203.0.113.7/32".to_string()],
            &sources,
        );

        let targets = report
            .matches
            .iter()
            .map(|m| m.target.clone())
            .collect::<Vec<_>>();
        assert_eq!(targets, vec!["203.0.113.7", "203.0.113.7/32"]);
    }

    #[test]
    fn indexed_matches_agree_with_brute_force_for_both_families() {
        let source_text = [
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "0.0.0.0/0",
            "10.0.0.128/25",
            "2001:db8::80/121",
            "::/0",
            "10.0.0.64/26",
            "10.0.0.0/24",
            "2001:db8::40/122",
            "2001:db8::/120",
            "10.0.0.0/24",
            "255.255.255.255",
        ];
        let sources = source_text.map(|line| LookupSourceEntry {
            source_label: "fixture".into(),
            source_line: line.to_string(),
            cidr: parse_target_strict(line).expect("source"),
        });
        let valid_targets = [
            "255.255.255.255",
            "10.0.0.127",
            "10.0.0.128",
            "10.0.0.0/23",
            "10.0.1.0",
            "2001:db8::7f",
            "2001:db8::80",
            "2001:db8::/119",
            "2001:db8::100",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "0.0.0.0/0",
            "::/0",
        ];
        let expected = std::collections::BTreeSet::from(valid_targets)
            .into_iter()
            .map(|target| {
                let cidr = parse_target_strict(target).expect("target");
                let mut matches = sources
                    .iter()
                    .filter(|source| cidr_overlaps(source.cidr, cidr))
                    .collect::<Vec<_>>();
                matches.sort_unstable_by_key(|source| source.source_line.as_str());
                matches.dedup();
                (
                    target.to_string(),
                    matches.into_iter().cloned().collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();
        let targets = valid_targets
            .into_iter()
            .chain(["invalid-z", "invalid-a", "10.0.0.127", "invalid-z"])
            .collect::<Vec<_>>();
        let mut actual = Vec::new();
        let invalid = run_lookup_by_target(&targets, &sources, |target, matches| {
            actual.push((
                target.to_string(),
                matches
                    .iter()
                    .map(|&source| source.clone())
                    .collect::<Vec<_>>(),
            ));
        });
        assert_eq!(actual, expected);
        assert_eq!(invalid, ["invalid-a", "invalid-z"]);
    }

    #[test]
    fn broad_prefix_does_not_force_scanning_narrow_misses() {
        use super::{IndexedSource, IntervalIndex};

        const NARROW_COUNT: u32 = 65_536;
        let ipv4 = IntervalIndex::new(
            std::iter::once(IndexedSource {
                start: 0,
                end: u32::MAX,
                source_idx: 0,
            })
            .chain((1..=NARROW_COUNT).map(|host| IndexedSource {
                start: host,
                end: host,
                source_idx: usize::try_from(host).expect("host index"),
            })),
        );
        let ipv6 = IntervalIndex::new(ipv4.entries.iter().map(|entry| IndexedSource {
            start: u128::from(entry.start),
            end: if entry.source_idx == 0 {
                u128::MAX
            } else {
                u128::from(entry.end)
            },
            source_idx: entry.source_idx,
        }));
        let mut matches = Vec::new();
        let v4_visited = ipv4.visit_overlaps(u32::MAX, u32::MAX, |idx| matches.push(idx));
        assert_eq!(matches, [0]);
        matches.clear();
        let v6_visited = ipv6.visit_overlaps(u128::MAX, u128::MAX, |idx| matches.push(idx));
        assert_eq!(matches, [0]);
        assert!(v4_visited < 40, "visited {v4_visited} IPv4 entries");
        assert!(v6_visited < 40, "visited {v6_visited} IPv6 entries");
    }

    #[test]
    fn lookup_invalid_targets_are_sorted_and_deduped() {
        let report = run_lookup(
            &["zzz".to_string(), "aaa".to_string(), "zzz".to_string()],
            &[],
        );
        assert_eq!(
            report.invalid_targets,
            vec!["aaa".to_string(), "zzz".to_string()]
        );
    }
}
