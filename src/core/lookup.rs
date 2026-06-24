use std::sync::Arc;

use crate::core::network::{
    CanonicalCidr, IntervalU32, IntervalU128, cidr_overlaps as network_cidr_overlaps,
    ipv4_to_interval, ipv6_to_interval, parse_ip_cidr_strict,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupSourceEntry {
    pub source_label: Arc<str>,
    pub source_line: String,
    pub cidr: CanonicalCidr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupMatch {
    pub target: String,
    pub source_label: String,
    pub matched_source_entry: String,
    pub matched_cidr: CanonicalCidr,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LookupReport {
    pub matches: Vec<LookupMatch>,
    pub invalid_targets: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupTargetParseError {
    Empty,
    Invalid,
}

pub fn parse_target_strict(input: &str) -> Result<CanonicalCidr, LookupTargetParseError> {
    let normalized = input.trim();
    if normalized.is_empty() {
        return Err(LookupTargetParseError::Empty);
    }

    parse_ip_cidr_strict(normalized).ok_or(LookupTargetParseError::Invalid)
}

pub fn cidr_overlaps(a: CanonicalCidr, b: CanonicalCidr) -> bool {
    network_cidr_overlaps(a, b)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IndexedSourceV4 {
    interval: IntervalU32,
    source_idx: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IndexedSourceV6 {
    interval: IntervalU128,
    source_idx: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct IntervalIndexV4 {
    entries: Vec<IndexedSourceV4>,
    prefix_max_end: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct IntervalIndexV6 {
    entries: Vec<IndexedSourceV6>,
    prefix_max_end: Vec<u128>,
}

impl IntervalIndexV4 {
    fn from_sources(sources: &[LookupSourceEntry]) -> Self {
        let mut entries = sources
            .iter()
            .enumerate()
            .filter_map(|(idx, source)| match source.cidr {
                CanonicalCidr::V4(cidr) => Some(IndexedSourceV4 {
                    interval: ipv4_to_interval(cidr),
                    source_idx: idx,
                }),
                CanonicalCidr::V6(_) => None,
            })
            .collect::<Vec<_>>();
        entries.sort_unstable_by_key(|entry| (entry.interval.start, entry.interval.end));

        let mut prefix_max_end = Vec::with_capacity(entries.len());
        let mut running_max = 0_u32;
        for entry in &entries {
            running_max = running_max.max(entry.interval.end);
            prefix_max_end.push(running_max);
        }

        Self {
            entries,
            prefix_max_end,
        }
    }

    fn overlapping_source_indices(&self, target: IntervalU32) -> impl Iterator<Item = usize> + '_ {
        let upper = self
            .entries
            .partition_point(|entry| entry.interval.start <= target.end);
        let lower = self
            .prefix_max_end
            .partition_point(|max_end| *max_end < target.start);
        let start = lower.min(upper);

        self.entries
            .get(start..upper)
            .into_iter()
            .flatten()
            .filter(move |entry| entry.interval.end >= target.start)
            .map(|entry| entry.source_idx)
    }
}

impl IntervalIndexV6 {
    fn from_sources(sources: &[LookupSourceEntry]) -> Self {
        let mut entries = sources
            .iter()
            .enumerate()
            .filter_map(|(idx, source)| match source.cidr {
                CanonicalCidr::V4(_) => None,
                CanonicalCidr::V6(cidr) => Some(IndexedSourceV6 {
                    interval: ipv6_to_interval(cidr),
                    source_idx: idx,
                }),
            })
            .collect::<Vec<_>>();
        entries.sort_unstable_by_key(|entry| (entry.interval.start, entry.interval.end));

        let mut prefix_max_end = Vec::with_capacity(entries.len());
        let mut running_max = 0_u128;
        for entry in &entries {
            running_max = running_max.max(entry.interval.end);
            prefix_max_end.push(running_max);
        }

        Self {
            entries,
            prefix_max_end,
        }
    }

    fn overlapping_source_indices(&self, target: IntervalU128) -> impl Iterator<Item = usize> + '_ {
        let upper = self
            .entries
            .partition_point(|entry| entry.interval.start <= target.end);
        let lower = self
            .prefix_max_end
            .partition_point(|max_end| *max_end < target.start);
        let start = lower.min(upper);

        self.entries
            .get(start..upper)
            .into_iter()
            .flatten()
            .filter(move |entry| entry.interval.end >= target.start)
            .map(|entry| entry.source_idx)
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

fn emit_target_matches<F>(
    target: PreparedTarget<'_>,
    sources: &[LookupSourceEntry],
    v4_index: &IntervalIndexV4,
    v6_index: &IntervalIndexV6,
    mut emit: F,
) where
    F: FnMut(&str, &LookupSourceEntry),
{
    let mut matched_sources = Vec::<&LookupSourceEntry>::new();

    match target.parsed {
        CanonicalCidr::V4(cidr) => {
            for source_idx in v4_index.overlapping_source_indices(ipv4_to_interval(cidr)) {
                if let Some(source) = sources.get(source_idx) {
                    matched_sources.push(source);
                }
            }
        }
        CanonicalCidr::V6(cidr) => {
            for source_idx in v6_index.overlapping_source_indices(ipv6_to_interval(cidr)) {
                if let Some(source) = sources.get(source_idx) {
                    matched_sources.push(source);
                }
            }
        }
    }

    matched_sources.sort_unstable_by(|left, right| compare_source_entries(left, right));
    matched_sources.dedup_by(|left, right| same_source_entry(left, right));

    for source in matched_sources {
        emit(target.raw, source);
    }
}

pub fn run_lookup_streaming<S, F>(
    targets: &[S],
    sources: &[LookupSourceEntry],
    mut emit: F,
) -> Vec<String>
where
    S: AsRef<str>,
    F: FnMut(&str, &LookupSourceEntry),
{
    let v4_index = IntervalIndexV4::from_sources(sources);
    let v6_index = IntervalIndexV6::from_sources(sources);
    let (prepared_targets, invalid_targets) = prepare_targets(targets);

    for target in prepared_targets {
        emit_target_matches(target, sources, &v4_index, &v6_index, &mut emit);
    }

    invalid_targets
}

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
        LookupSourceEntry, LookupTargetParseError, cidr_overlaps, parse_target_strict, run_lookup,
        run_lookup_streaming,
    };
    use crate::core::network::{CanonicalCidr, Ipv4Cidr, Ipv6Cidr};

    #[test]
    fn strict_target_parsing_accepts_ip_and_cidr() {
        let host = parse_target_strict("198.51.100.1").expect("host");
        assert_eq!(
            host,
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0xc6336401, 32))
        );

        let cidr = parse_target_strict("2001:db8::/64").expect("cidr");
        assert_eq!(
            cidr,
            CanonicalCidr::V6(Ipv6Cidr::from_parts(0x20010db8000000000000000000000000, 64))
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
        let v4_a = CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 24));
        let v4_b = CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000080, 25));
        let v6 = CanonicalCidr::V6(Ipv6Cidr::from_parts(0x20010db8000000000000000000000000, 64));

        assert!(cidr_overlaps(v4_a, v4_b));
        assert!(!cidr_overlaps(v4_a, v6));
    }

    #[test]
    fn lookup_reports_matches_and_invalid_targets() {
        let sources = vec![
            LookupSourceEntry {
                source_label: "internal:blocklist".into(),
                source_line: "10.0.0.0/24".to_string(),
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 24)),
            },
            LookupSourceEntry {
                source_label: "remote:abcd1234.iplist".into(),
                source_line: "2001:db8::/64".to_string(),
                cidr: CanonicalCidr::V6(Ipv6Cidr::from_parts(
                    0x20010db8000000000000000000000000,
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
                0x20010db8000000000000000000000000,
                124,
            )),
        }];

        let report = run_lookup(&["2001:db8::f".to_string()], &sources);

        assert!(report.invalid_targets.is_empty());
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
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 24)),
            },
            LookupSourceEntry {
                source_label: "source:b".into(),
                source_line: "10.0.2.0/24".to_string(),
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000200, 24)),
            },
            LookupSourceEntry {
                source_label: "source:c".into(),
                source_line: "10.0.4.0/24".to_string(),
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000400, 24)),
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
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 24)),
            },
            LookupSourceEntry {
                source_label: "source:a".into(),
                source_line: "10.0.0.0/24".to_string(),
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 24)),
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

        assert!(invalid.is_empty());
        assert_eq!(emitted.len(), 1);
        assert_eq!(emitted[0].0, "10.0.0.7");
        assert_eq!(emitted[0].1, "source:a");
        assert_eq!(emitted[0].2, "10.0.0.0/24");
    }

    #[test]
    fn lookup_preserves_distinct_source_lines_for_same_label_and_cidr() {
        let sources = vec![
            LookupSourceEntry {
                source_label: "source:a".into(),
                source_line: "10.0.0.0/24".to_string(),
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 24)),
            },
            LookupSourceEntry {
                source_label: "source:a".into(),
                source_line: "10.0.0.42/24".to_string(),
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 24)),
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
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 8)),
            },
            LookupSourceEntry {
                source_label: "source:narrow".into(),
                source_line: "10.2.0.0/16".to_string(),
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a020000, 16)),
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
    fn lookup_index_keeps_same_start_nested_matches() {
        let sources = vec![
            LookupSourceEntry {
                source_label: "source:super".into(),
                source_line: "10.0.0.0/8".to_string(),
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 8)),
            },
            LookupSourceEntry {
                source_label: "source:narrow".into(),
                source_line: "10.0.0.0/16".to_string(),
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 16)),
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
    fn lookup_preserves_distinct_source_labels_for_same_cidr() {
        let sources = vec![
            LookupSourceEntry {
                source_label: "feed:a".into(),
                source_line: "10.0.0.0/24".to_string(),
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 24)),
            },
            LookupSourceEntry {
                source_label: "feed:b".into(),
                source_line: "10.0.0.0/24".to_string(),
                cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 24)),
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
            cidr: CanonicalCidr::V4(Ipv4Cidr::from_parts(0xcb007107, 32)),
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
