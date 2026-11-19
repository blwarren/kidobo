//! Deterministic parsing and mutation planning for the local blocklist.

use std::collections::HashSet;

use thiserror::Error;

use crate::network::{
    CanonicalCidr, IntervalU32, IntervalU128, ipv4_to_interval, ipv6_to_interval,
    merge_intervals_u32_owned, merge_intervals_u128_owned, parse_ip_cidr_strict, split_by_family,
};

/// Error returned when an operator-supplied ban or unban target is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BlocklistTargetParseError {
    /// The target is not exactly one valid IP address or CIDR.
    #[error("target is not exactly one valid IP address or CIDR")]
    Invalid,
}

/// A non-comment blocklist line that could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid blocklist entry at line {line_number}: {content}")]
pub struct InvalidBlocklistLine {
    /// One-based line number in the original document.
    pub line_number: usize,
    /// Original invalid line contents.
    pub content: String,
}

/// Original blocklist bytes and the locations of its data entries in source order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlocklistDocument {
    contents: String,
    entries: Vec<(std::ops::Range<usize>, CanonicalCidr)>,
}

impl BlocklistDocument {
    /// Parses the document and indexes only valid data entries.
    ///
    /// # Errors
    ///
    /// Returns the first invalid non-comment line.
    pub fn parse(contents: impl Into<String>) -> Result<Self, InvalidBlocklistLine> {
        let contents = contents.into();
        let mut entries = Vec::new();
        let mut start = 0;
        for (index, span) in contents.split_inclusive('\n').enumerate() {
            let end = start + span.len();
            let line = span
                .strip_suffix("\r\n")
                .or_else(|| span.strip_suffix('\n'))
                .unwrap_or(span);
            if let Some(network) = parse_blocklist_entry(line, index + 1)? {
                entries.push((start..end, network));
            }
            start = end;
        }
        Ok(Self { contents, entries })
    }

    /// Returns canonical identities in their original order, including duplicates.
    pub fn networks(&self) -> impl ExactSizeIterator<Item = CanonicalCidr> + '_ {
        self.entries.iter().map(|(_, network)| *network)
    }

    /// Returns the canonical identity for one indexed data entry.
    #[must_use]
    pub fn network(&self, index: usize) -> Option<CanonicalCidr> {
        self.entries.get(index).map(|(_, network)| *network)
    }

    /// Appends canonical entries, preserving the original document and separating an unterminated line.
    #[must_use]
    pub fn with_appended(mut self, entries: &[String]) -> String {
        if !entries.is_empty() && !self.contents.is_empty() && !self.contents.ends_with('\n') {
            self.contents.push('\n');
        }
        for entry in entries {
            self.contents.push_str(entry);
            self.contents.push('\n');
        }
        self.contents
    }

    /// Removes only the selected data entries, including each removed entry's own line ending.
    #[must_use]
    pub fn without_entries(&self, remove: &HashSet<usize>) -> String {
        let mut kept = String::with_capacity(self.contents.len());
        let mut start = 0;
        for (index, (span, _)) in self.entries.iter().enumerate() {
            if remove.contains(&index) {
                kept.push_str(&self.contents[start..span.start]);
                start = span.end;
            }
        }
        kept.push_str(&self.contents[start..]);
        kept
    }
}

/// Result of comparing a requested ban target with the current blocklist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanClassification {
    /// The target was not already present and should be added.
    Added(CanonicalCidr),
    /// The target is an exact duplicate of an existing or earlier requested entry.
    AlreadyPresent(CanonicalCidr),
}

/// Exact and overlapping line indexes affected by an unban request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UnbanIndexPlan {
    /// Zero-based indexes that exactly equal a requested target.
    pub exact_indexes: Vec<usize>,
    /// Zero-based indexes that overlap but do not exactly equal a target.
    pub partial_indexes: Vec<usize>,
}

/// Parses one operator-supplied blocklist target using strict token rules.
///
/// # Errors
///
/// Returns [`BlocklistTargetParseError::Invalid`] when the input is not exactly one valid IP or
/// CIDR.
pub fn parse_blocklist_target(input: &str) -> Result<CanonicalCidr, BlocklistTargetParseError> {
    let token = input.trim();
    parse_ip_cidr_strict(token).ok_or(BlocklistTargetParseError::Invalid)
}

#[must_use]
/// Classifies ban targets in input order, treating earlier new targets as present.
pub fn classify_ban_targets(
    existing: impl IntoIterator<Item = CanonicalCidr>,
    targets: &[CanonicalCidr],
) -> Vec<BanClassification> {
    let mut present = existing.into_iter().collect::<HashSet<_>>();
    let mut outcomes = Vec::with_capacity(targets.len());

    for target in targets {
        if present.insert(*target) {
            outcomes.push(BanClassification::Added(*target));
        } else {
            outcomes.push(BanClassification::AlreadyPresent(*target));
        }
    }

    outcomes
}

/// Reusable exact and family-separated overlap indexes for an unban request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnbanTargetIndex {
    targets: Vec<CanonicalCidr>,
    ipv4: Vec<IntervalU32>,
    ipv6: Vec<IntervalU128>,
}

impl UnbanTargetIndex {
    /// Sorts and deduplicates targets, then merges their family-specific coverage.
    #[must_use]
    pub fn new(mut targets: Vec<CanonicalCidr>) -> Self {
        targets.sort_unstable();
        targets.dedup();
        let families = split_by_family(&targets);
        Self {
            targets,
            ipv4: merge_intervals_u32_owned(
                families.ipv4.into_iter().map(ipv4_to_interval).collect(),
            ),
            ipv6: merge_intervals_u128_owned(
                families.ipv6.into_iter().map(ipv6_to_interval).collect(),
            ),
        }
    }

    /// Returns the sorted, unique canonical targets without collapsing their identities.
    #[must_use]
    pub fn targets(&self) -> &[CanonicalCidr] {
        &self.targets
    }

    /// Plans removal in source order, giving exact identities priority over partial overlaps.
    ///
    /// Returned indexes are sorted and unique, and include each matching source entry once.
    #[must_use]
    pub fn plan(&self, entries: impl IntoIterator<Item = Option<CanonicalCidr>>) -> UnbanIndexPlan {
        let mut plan = UnbanIndexPlan::default();
        for (index, entry) in entries.into_iter().enumerate() {
            let Some(entry) = entry else {
                continue;
            };
            if self.targets.binary_search(&entry).is_ok() {
                plan.exact_indexes.push(index);
            } else if self.overlaps(entry) {
                plan.partial_indexes.push(index);
            }
        }
        plan
    }

    fn overlaps(&self, entry: CanonicalCidr) -> bool {
        match entry {
            CanonicalCidr::V4(cidr) => {
                let entry = ipv4_to_interval(cidr);
                let index = self.ipv4.partition_point(|target| target.end < entry.start);
                self.ipv4
                    .get(index)
                    .is_some_and(|target| target.start <= entry.end)
            }
            CanonicalCidr::V6(cidr) => {
                let entry = ipv6_to_interval(cidr);
                let index = self.ipv6.partition_point(|target| target.end < entry.start);
                self.ipv6
                    .get(index)
                    .is_some_and(|target| target.start <= entry.end)
            }
        }
    }
}

#[must_use]
/// Returns sorted zero-based indexes exactly matching any requested target.
pub fn exact_match_indexes(
    entries: impl IntoIterator<Item = CanonicalCidr>,
    targets: &[CanonicalCidr],
) -> Vec<usize> {
    let target_set = targets.iter().copied().collect::<HashSet<_>>();
    let mut indexes = Vec::new();

    for (idx, entry) in entries.into_iter().enumerate() {
        if target_set.contains(&entry) {
            indexes.push(idx);
        }
    }

    indexes
}

/// Parses a saved blocklist line using its one-based position for diagnostics.
///
/// Blank lines and full-line comments return `Ok(None)`.
///
/// # Errors
///
/// Returns [`InvalidBlocklistLine`] when the line is not exactly one valid IP or CIDR.
pub fn parse_blocklist_entry(
    line: &str,
    line_number: usize,
) -> Result<Option<CanonicalCidr>, InvalidBlocklistLine> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(None);
    }

    parse_ip_cidr_strict(trimmed)
        .map(Some)
        .ok_or_else(|| InvalidBlocklistLine {
            line_number,
            content: line.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use crate::network::{CanonicalCidr, parse_ip_cidr_non_strict};

    use super::{
        BanClassification, BlocklistDocument, BlocklistTargetParseError, InvalidBlocklistLine,
        UnbanTargetIndex, classify_ban_targets, exact_match_indexes, parse_blocklist_target,
    };

    #[test]
    fn parsing_rejects_invalid_non_header_lines() {
        let err = BlocklistDocument::parse("# header\n203.0.113.7 trailing-junk\n")
            .expect_err("invalid line must fail");

        assert_eq!(
            err,
            InvalidBlocklistLine {
                line_number: 2,
                content: "203.0.113.7 trailing-junk".to_string(),
            }
        );
    }

    #[test]
    fn classify_ban_targets_preserves_order_and_dedups_against_existing_and_new_entries() {
        let existing = vec![parse_ip_cidr_non_strict("198.51.100.0/24").expect("existing")];
        let targets = vec![
            parse_ip_cidr_non_strict("203.0.113.7").expect("first"),
            parse_ip_cidr_non_strict("198.51.100.0/24").expect("second"),
            parse_ip_cidr_non_strict("203.0.113.7").expect("third"),
        ];

        assert_eq!(
            classify_ban_targets(existing, &targets),
            vec![
                BanClassification::Added(parse_ip_cidr_non_strict("203.0.113.7").expect("added")),
                BanClassification::AlreadyPresent(
                    parse_ip_cidr_non_strict("198.51.100.0/24").expect("present")
                ),
                BanClassification::AlreadyPresent(
                    parse_ip_cidr_non_strict("203.0.113.7").expect("dup")
                ),
            ]
        );
    }

    #[test]
    fn plan_unban_separates_exact_and_partial_matches_without_cross_family_leakage() {
        let entries = vec![
            Some(parse_ip_cidr_non_strict("203.0.113.0/24").expect("v4 supernet")),
            Some(parse_ip_cidr_non_strict("203.0.113.7").expect("v4 exact")),
            Some(parse_ip_cidr_non_strict("2001:db8::/64").expect("v6")),
        ];
        let target = parse_ip_cidr_non_strict("203.0.113.7").expect("target");

        let plan = UnbanTargetIndex::new(vec![target]).plan(entries);
        assert_eq!(plan.exact_indexes, vec![1]);
        assert_eq!(plan.partial_indexes, vec![0]);
    }

    #[test]
    fn plan_unban_many_excludes_exact_indexes_from_partial_results() {
        let entries = vec![
            Some(parse_ip_cidr_non_strict("203.0.113.0/24").expect("first")),
            Some(parse_ip_cidr_non_strict("198.51.100.0/24").expect("second")),
        ];
        let targets = vec![
            parse_ip_cidr_non_strict("203.0.113.0/24").expect("exact"),
            parse_ip_cidr_non_strict("198.51.100.7").expect("partial"),
            parse_ip_cidr_non_strict("203.0.113.7").expect("overlap exact bucket"),
        ];

        let plan = UnbanTargetIndex::new(targets).plan(entries);
        assert_eq!(plan.exact_indexes, vec![0]);
        assert_eq!(plan.partial_indexes, vec![1]);
    }

    #[test]
    fn unban_index_preserves_identities_across_adjacent_and_nested_targets() {
        let targets = ["10.0.0.128/25", "2001:db8::1", "10.0.0.0/25", "10.0.0.0/25"]
            .map(|value| parse_blocklist_target(value).expect("target"));
        let index = UnbanTargetIndex::new(targets.to_vec());
        assert_eq!(index.targets().len(), 3);
        let entries = [
            Some(parse_blocklist_target("10.0.0.0/24").expect("merged coverage")),
            Some(parse_blocklist_target("10.0.0.128/25").expect("exact")),
            None,
            Some(parse_blocklist_target("10.0.0.128/25").expect("duplicate source")),
            Some(parse_blocklist_target("2001:db8::/127").expect("v6 overlap")),
            Some(parse_blocklist_target("2001:db8::2").expect("v6 outside")),
        ];
        let plan = index.plan(entries);
        assert_eq!(plan.exact_indexes, [1, 3]);
        assert_eq!(plan.partial_indexes, [0, 4]);
    }

    #[test]
    fn unban_index_keeps_endpoint_overlaps_and_gaps_in_both_families() {
        let targets = [
            "255.255.255.255",
            "0.0.0.0",
            "::",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        ]
        .map(|value| parse_blocklist_target(value).expect("target"));
        let entries = [
            "0.0.0.0/0",
            "0.0.0.1",
            "255.255.255.254/31",
            "0.0.0.0",
            "::/0",
            "::1",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127",
            "::",
        ]
        .map(|value| Some(parse_blocklist_target(value).expect("entry")));
        let plan = UnbanTargetIndex::new(targets.to_vec()).plan(entries);
        assert_eq!(plan.exact_indexes, [3, 7]);
        assert_eq!(plan.partial_indexes, [0, 2, 4, 6]);
        assert_eq!(
            UnbanTargetIndex::new(Vec::new()).plan(entries),
            super::UnbanIndexPlan::default()
        );
    }

    #[test]
    fn unban_index_matches_pairwise_overlap_model_for_mixed_family_targets() {
        let networks = [
            "0.0.0.0/0",
            "10.0.0.0/24",
            "10.0.0.0/25",
            "10.0.0.128/25",
            "10.0.0.127",
            "10.0.0.128",
            "10.0.1.0/24",
            "255.255.255.255",
            "::/0",
            "2001:db8::/126",
            "2001:db8::/127",
            "2001:db8::2/127",
            "2001:db8::1",
            "2001:db8::2",
            "2001:db8::4",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        ]
        .map(|value| parse_blocklist_target(value).expect("network"));
        let entries = networks
            .into_iter()
            .map(Some)
            .chain([None])
            .collect::<Vec<_>>();
        for first in networks {
            for second in networks {
                let targets = [second, first, second];
                let mut expected = super::UnbanIndexPlan::default();
                for (index, entry) in entries.iter().enumerate() {
                    if let Some(entry) = entry {
                        if targets.contains(entry) {
                            expected.exact_indexes.push(index);
                        } else if targets
                            .iter()
                            .any(|target| crate::network::cidr_overlaps(*entry, *target))
                        {
                            expected.partial_indexes.push(index);
                        }
                    }
                }
                assert_eq!(
                    UnbanTargetIndex::new(targets.to_vec()).plan(entries.iter().copied()),
                    expected
                );
            }
        }
    }

    #[test]
    fn exact_match_indexes_only_match_exact_entries() {
        let entries = vec![
            Some(parse_ip_cidr_non_strict("203.0.113.0/24").expect("cidr")),
            Some(parse_ip_cidr_non_strict("203.0.113.7").expect("host")),
            None,
        ];
        let targets = vec![parse_ip_cidr_non_strict("203.0.113.0/24").expect("target")];

        assert_eq!(
            exact_match_indexes(entries.into_iter().flatten(), &targets),
            vec![0]
        );
    }

    #[test]
    fn parse_blocklist_target_trims_whitespace_and_canonicalizes_hosts() {
        let parsed = parse_blocklist_target(" 203.0.113.7 ").expect("parse");
        assert_eq!(
            parsed,
            CanonicalCidr::V4(crate::network::Ipv4Cidr::from_parts(0xcb00_7107, 32))
        );
    }

    #[test]
    fn parse_blocklist_target_rejects_trailing_tokens() {
        assert_eq!(
            parse_blocklist_target("203.0.113.7 trailing-junk"),
            Err(BlocklistTargetParseError::Invalid)
        );
    }

    #[test]
    fn removal_preserves_every_byte_outside_selected_data_entries() {
        let original =
            "# header  \r\n192.0.2.4\r\n\r\n 192.0.2.5 \r\n# between\n192.0.2.4\n2001:db8::7";
        let document = BlocklistDocument::parse(original).expect("parse");
        assert_eq!(document.networks().len(), 4);
        assert_eq!(
            document.without_entries(&[0, 2].into()),
            "# header  \r\n\r\n 192.0.2.5 \r\n# between\n2001:db8::7"
        );
        assert_eq!(
            document.without_entries(&[3].into()),
            original.strip_suffix("2001:db8::7").unwrap()
        );
        assert_eq!(
            document.without_entries(&std::collections::HashSet::new()),
            original
        );
    }
}
