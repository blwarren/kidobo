//! Pure parsing and rendering for remote feed cache payloads.

use kidobo_core::network::{CanonicalCidr, parse_ip_cidr_non_strict, parse_lines_non_strict};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedRemoteCidrs {
    pub(crate) networks: Vec<CanonicalCidr>,
    pub(crate) data_lines: usize,
    pub(crate) invalid_lines: usize,
}

pub(crate) fn parse_remote_cidrs(raw: &[u8]) -> ParsedRemoteCidrs {
    let text = String::from_utf8_lossy(raw);
    let mut parsed = Vec::new();
    let mut data_lines = 0_usize;
    let mut invalid_lines = 0_usize;

    for line in text.lines() {
        let without_bom = line.trim_start_matches('\u{feff}').trim();
        if without_bom.is_empty() || without_bom.starts_with('#') {
            continue;
        }
        data_lines += 1;
        let Some(token) = without_bom
            .split_once(',')
            .map_or(without_bom, |(first_column, _)| first_column)
            .split_whitespace()
            .next()
        else {
            continue;
        };
        if let Some(cidr) = parse_ip_cidr_non_strict(token) {
            parsed.push(cidr);
        } else {
            invalid_lines += 1;
        }
    }
    ParsedRemoteCidrs {
        networks: parsed,
        data_lines,
        invalid_lines,
    }
}

pub(crate) fn parse_cached_iplist(iplist: &str) -> Vec<CanonicalCidr> {
    parse_lines_non_strict(iplist.lines())
}

pub(crate) fn format_normalized_cidrs(cidrs: &[CanonicalCidr]) -> String {
    cidrs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}
