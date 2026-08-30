//! Deterministic parsing and mutation planning for the local blocklist.

use std::collections::{BTreeSet, HashSet};

use crate::network::{
    CanonicalCidr, cidr_overlaps, collapse_ipv4, collapse_ipv6, parse_ip_cidr_strict,
    split_by_family,
};

/// Error returned when an operator-supplied ban or unban target is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlocklistTargetParseError {
    /// The target is not exactly one valid IP address or CIDR.
    Invalid,
}

/// A non-comment blocklist line that could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidBlocklistLine {
    /// One-based line number in the original document.
    pub line_number: usize,
    /// Original invalid line contents.
    pub content: String,
}

/// Parsed blocklist contents with enough structure to render canonical output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlocklistDocument {
    /// Original lines paired with any canonical CIDR they contain.
    pub lines: Vec<BlocklistLine>,
    /// Whether the source document contained any bytes.
    pub has_content: bool,
    /// Whether the source document ended in a newline.
    pub trailing_newline: bool,
}

impl BlocklistDocument {
    /// Parses a line-oriented blocklist while preserving its original structure.
    ///
    /// # Errors
    ///
    /// Returns the first [`InvalidBlocklistLine`] when a non-comment entry is not a valid IP or
    /// CIDR.
    pub fn parse(contents: &str) -> Result<Self, InvalidBlocklistLine> {
        let mut lines = Vec::new();
        let mut in_header = true;

        for (idx, line) in contents.lines().enumerate() {
            lines.push(BlocklistLine::parse(line, idx + 1, &mut in_header)?);
        }

        Ok(Self {
            lines,
            has_content: !contents.is_empty(),
            trailing_newline: contents.ends_with('\n'),
        })
    }

    /// Renders the preserved header followed by sorted, collapsed CIDRs.
    #[must_use]
    pub fn canonicalized_contents(&self) -> String {
        let mut header_lines = Vec::new();
        let mut entries = Vec::new();
        let mut in_header = true;

        for line in &self.lines {
            let trimmed = line.original.trim();

            if in_header {
                if line.canonical.is_none() && (trimmed.is_empty() || trimmed.starts_with('#')) {
                    header_lines.push(trimmed.to_string());
                    continue;
                }
                in_header = false;
            }

            if let Some(cidr) = line.canonical {
                entries.push(cidr);
            }
        }

        let canonical_entries = canonical_entry_lines(&entries);
        if !canonical_entries.is_empty() {
            if !header_lines.is_empty() && !header_lines.last().is_some_and(String::is_empty) {
                header_lines.push(String::new());
            }
            header_lines.extend(canonical_entries);
        } else if header_lines.last().is_some_and(String::is_empty) {
            header_lines.pop();
        }

        let mut normalized = header_lines.join("\n");
        if !normalized.is_empty() {
            normalized.push('\n');
        }
        normalized
    }
}

/// One original blocklist line and its optional canonical CIDR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlocklistLine {
    /// Unmodified line contents.
    pub original: String,
    /// Parsed CIDR, or `None` for a blank or comment line.
    pub canonical: Option<CanonicalCidr>,
}

impl BlocklistLine {
    fn parse(
        line: &str,
        line_number: usize,
        in_header: &mut bool,
    ) -> Result<Self, InvalidBlocklistLine> {
        let trimmed = line.trim();
        let canonical = if *in_header {
            if trimmed.is_empty() || trimmed.starts_with('#') {
                None
            } else {
                *in_header = false;
                parse_blocklist_entry(line, line_number)?
            }
        } else {
            parse_blocklist_entry(line, line_number)?
        };

        Ok(Self {
            original: line.to_string(),
            canonical,
        })
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
    existing: &[CanonicalCidr],
    targets: &[CanonicalCidr],
) -> Vec<BanClassification> {
    let mut present = existing.iter().copied().collect::<HashSet<_>>();
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

#[must_use]
/// Plans removal of one target without mutating the parsed document.
pub fn plan_unban(entries: &[Option<CanonicalCidr>], target: CanonicalCidr) -> UnbanIndexPlan {
    plan_unban_many(entries, &[target])
}

#[must_use]
/// Plans exact removals and partial-overlap warnings for multiple targets.
///
/// Returned indexes are sorted and unique; exact matches are excluded from the partial list.
pub fn plan_unban_many(
    entries: &[Option<CanonicalCidr>],
    targets: &[CanonicalCidr],
) -> UnbanIndexPlan {
    let mut exact_indexes = BTreeSet::new();
    let mut partial_indexes = BTreeSet::new();

    for target in targets {
        for (idx, entry) in entries.iter().enumerate() {
            let Some(entry) = entry else {
                continue;
            };

            if entry == target {
                exact_indexes.insert(idx);
            } else if cidr_overlaps(*entry, *target) {
                partial_indexes.insert(idx);
            }
        }
    }

    for idx in &exact_indexes {
        partial_indexes.remove(idx);
    }

    UnbanIndexPlan {
        exact_indexes: exact_indexes.into_iter().collect(),
        partial_indexes: partial_indexes.into_iter().collect(),
    }
}

#[must_use]
/// Returns sorted zero-based indexes exactly matching any requested target.
pub fn exact_match_indexes(
    entries: &[Option<CanonicalCidr>],
    targets: &[CanonicalCidr],
) -> Vec<usize> {
    let target_set = targets.iter().copied().collect::<HashSet<_>>();
    let mut indexes = Vec::new();

    for (idx, entry) in entries.iter().enumerate() {
        if entry.is_some_and(|entry| target_set.contains(&entry)) {
            indexes.push(idx);
        }
    }

    indexes
}

/// Parses, collapses, and renders blocklist contents in canonical order.
///
/// # Errors
///
/// Returns the first [`InvalidBlocklistLine`] when a non-comment entry is not a valid IP or CIDR.
pub fn canonicalize_blocklist(contents: &str) -> Result<String, InvalidBlocklistLine> {
    Ok(BlocklistDocument::parse(contents)?.canonicalized_contents())
}

fn canonical_entry_lines(entries: &[CanonicalCidr]) -> Vec<String> {
    let family_split = split_by_family(entries);
    let collapsed_v4 = collapse_ipv4(&family_split.ipv4);
    let collapsed_v6 = collapse_ipv6(&family_split.ipv6);

    let mut canonical = Vec::new();
    canonical.extend(collapsed_v4.into_iter().map(|cidr| cidr.to_string()));
    canonical.extend(collapsed_v6.into_iter().map(|cidr| cidr.to_string()));
    canonical
}

fn parse_blocklist_entry(
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
        canonicalize_blocklist, classify_ban_targets, exact_match_indexes, parse_blocklist_target,
        plan_unban, plan_unban_many,
    };

    #[test]
    fn canonicalize_blocklist_preserves_header_and_canonicalizes_entries() {
        let normalized = canonicalize_blocklist(
            "# top comment \n203.0.113.7\n# dropped later comment\n203.0.113.0/24\n2001:db8::/64\n2001:db8::/64\n",
        )
        .expect("canonicalize");

        assert_eq!(
            normalized,
            "# top comment\n\n203.0.113.0/24\n2001:db8::/64\n"
        );
    }

    #[test]
    fn canonicalize_blocklist_trims_header_trailing_blank_when_no_entries() {
        assert_eq!(
            canonicalize_blocklist("# header\n\n").expect("canonicalize"),
            "# header\n"
        );
    }

    #[test]
    fn canonicalize_blocklist_rejects_invalid_non_header_lines() {
        let err = canonicalize_blocklist("# header\n203.0.113.7 trailing-junk\n")
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
            classify_ban_targets(&existing, &targets),
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

        let plan = plan_unban(&entries, target);
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

        let plan = plan_unban_many(&entries, &targets);
        assert_eq!(plan.exact_indexes, vec![0]);
        assert_eq!(plan.partial_indexes, vec![1]);
    }

    #[test]
    fn exact_match_indexes_only_match_exact_entries() {
        let entries = vec![
            Some(parse_ip_cidr_non_strict("203.0.113.0/24").expect("cidr")),
            Some(parse_ip_cidr_non_strict("203.0.113.7").expect("host")),
            None,
        ];
        let targets = vec![parse_ip_cidr_non_strict("203.0.113.0/24").expect("target")];

        assert_eq!(exact_match_indexes(&entries, &targets), vec![0]);
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
    fn parse_document_preserves_original_lines_for_mutation_workflows() {
        let document =
            BlocklistDocument::parse("# header\n203.0.113.0/24\n# comment\n\n").expect("parse");

        assert_eq!(document.lines.len(), 4);
        assert_eq!(document.lines[0].original, "# header");
        assert_eq!(document.lines[1].original, "203.0.113.0/24");
        assert_eq!(document.lines[2].original, "# comment");
        assert_eq!(document.lines[3].original, "");
        assert!(document.trailing_newline);
        assert!(document.has_content);
    }
}
