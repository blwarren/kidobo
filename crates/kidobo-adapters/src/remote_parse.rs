//! Pure bounded parsing and rendering for remote feed cache payloads.

use std::collections::BTreeSet;

use kidobo_core::network::{CanonicalCidr, parse_ip_cidr_non_strict};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RemoteFeedLimits {
    pub(crate) data_lines: usize,
    pub(crate) unique_cidrs: usize,
}

impl RemoteFeedLimits {
    pub(crate) fn from_maxelem(maxelem: u32) -> Self {
        let maxelem = usize::try_from(maxelem).unwrap_or(usize::MAX);
        let doubled = maxelem.saturating_mul(2);
        Self {
            data_lines: 16_384.max(doubled.min(1_000_000)),
            unique_cidrs: 4_096.max(doubled.min(1_000_000)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteParseBudget {
    DataLines { observed: usize, limit: usize },
    UniqueCidrs { observed: usize, limit: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedRemoteCidrs {
    pub(crate) networks: Vec<CanonicalCidr>,
    pub(crate) data_lines: usize,
    pub(crate) invalid_lines: usize,
}

pub(crate) fn parse_remote_cidrs_bounded(
    raw: &[u8],
    limits: RemoteFeedLimits,
) -> Result<ParsedRemoteCidrs, RemoteParseBudget> {
    let text = String::from_utf8_lossy(raw);
    let mut parsed = BTreeSet::new();
    let mut data_lines = 0_usize;
    let mut invalid_lines = 0_usize;

    for line in text.lines() {
        let without_bom = line.trim_start_matches('\u{feff}').trim();
        if without_bom.is_empty() || without_bom.starts_with('#') {
            continue;
        }
        data_lines += 1;
        if data_lines > limits.data_lines {
            return Err(RemoteParseBudget::DataLines {
                observed: data_lines,
                limit: limits.data_lines,
            });
        }
        let Some(token) = without_bom
            .split_once(',')
            .map_or(without_bom, |(first_column, _)| first_column)
            .split_whitespace()
            .next()
        else {
            continue;
        };
        if let Some(cidr) = parse_ip_cidr_non_strict(token) {
            parsed.insert(cidr);
            if parsed.len() > limits.unique_cidrs {
                return Err(RemoteParseBudget::UniqueCidrs {
                    observed: parsed.len(),
                    limit: limits.unique_cidrs,
                });
            }
        } else {
            invalid_lines += 1;
        }
    }
    Ok(ParsedRemoteCidrs {
        networks: parsed.into_iter().collect(),
        data_lines,
        invalid_lines,
    })
}

pub(crate) fn parse_cached_iplist_bounded(
    iplist: &str,
    limits: RemoteFeedLimits,
) -> Result<Vec<CanonicalCidr>, RemoteParseBudget> {
    parse_remote_cidrs_bounded(iplist.as_bytes(), limits).map(|parsed| parsed.networks)
}

pub(crate) fn format_normalized_cidrs(cidrs: &[CanonicalCidr]) -> String {
    cidrs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}
