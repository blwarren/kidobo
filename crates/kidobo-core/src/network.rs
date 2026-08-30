//! Family-separated parsing, interval arithmetic, collapse, and safelist subtraction.

use std::net::IpAddr;

pub use crate::network_types::{CanonicalCidr, FamilyCidrs, Ipv4Cidr, Ipv6Cidr};
use crate::network_types::{ipv4_host_mask, ipv6_host_mask};
#[cfg(test)]
use crate::network_types::{ipv4_mask, ipv6_mask};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct IntervalU32 {
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct IntervalU128 {
    pub start: u128,
    pub end: u128,
}

impl From<Ipv4Cidr> for IntervalU32 {
    fn from(value: Ipv4Cidr) -> Self {
        ipv4_to_interval(value)
    }
}

impl From<Ipv6Cidr> for IntervalU128 {
    fn from(value: Ipv6Cidr) -> Self {
        ipv6_to_interval(value)
    }
}

#[must_use]
/// Parses the first whitespace-delimited token as an IP address or CIDR.
///
/// Host addresses become `/32` or `/128`; invalid input returns `None`.
pub fn parse_ip_cidr_non_strict(input: &str) -> Option<CanonicalCidr> {
    let token = input.split_whitespace().next()?.trim();
    if token.is_empty() {
        return None;
    }

    parse_ip_cidr_token(token)
}

#[must_use]
/// Parses exactly one IP address or CIDR after trimming surrounding whitespace.
///
/// Embedded whitespace or invalid input returns `None`.
pub fn parse_ip_cidr_strict(input: &str) -> Option<CanonicalCidr> {
    let normalized = input.trim();
    if normalized.is_empty() {
        return None;
    }

    if normalized.split_whitespace().count() != 1 {
        return None;
    }

    parse_ip_cidr_token(normalized)
}

/// Parses an already isolated IP-address or CIDR token into canonical network form.
#[must_use]
pub fn parse_ip_cidr_token(token: &str) -> Option<CanonicalCidr> {
    if let Ok(ip) = token.parse::<IpAddr>() {
        return Some(match ip {
            IpAddr::V4(v4) => CanonicalCidr::V4(Ipv4Cidr::new(v4, 32)?),
            IpAddr::V6(v6) => CanonicalCidr::V6(Ipv6Cidr::new(v6, 128)?),
        });
    }

    let (addr_part, prefix_part) = token.split_once('/')?;
    let prefix = prefix_part.parse::<u8>().ok()?;
    let ip = addr_part.parse::<IpAddr>().ok()?;

    match ip {
        IpAddr::V4(v4) => Ipv4Cidr::new(v4, prefix).map(CanonicalCidr::V4),
        IpAddr::V6(v6) => Ipv6Cidr::new(v6, prefix).map(CanonicalCidr::V6),
    }
}

/// Parses the first token from each input and discards invalid inputs.
pub fn parse_lines_non_strict<I, S>(inputs: I) -> Vec<CanonicalCidr>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    inputs
        .into_iter()
        .filter_map(|value| parse_ip_cidr_non_strict(value.as_ref()))
        .collect()
}

#[must_use]
/// Separates canonical CIDRs into independent IPv4 and IPv6 vectors.
///
/// Relative order within each family is preserved.
pub fn split_by_family(cidrs: &[CanonicalCidr]) -> FamilyCidrs {
    let mut separated = FamilyCidrs::default();

    for cidr in cidrs {
        match cidr {
            CanonicalCidr::V4(v4) => separated.ipv4.push(*v4),
            CanonicalCidr::V6(v6) => separated.ipv6.push(*v6),
        }
    }

    separated
}

/// Merges overlapping or adjacent IPv4 ranges and emits minimal canonical CIDRs.
#[must_use]
pub fn collapse_ipv4(cidrs: &[Ipv4Cidr]) -> Vec<Ipv4Cidr> {
    let intervals = cidrs.iter().copied().map(IntervalU32::from).collect();
    let merged = merge_intervals_u32_owned(intervals);
    intervals_to_ipv4_cidrs_from_merged(&merged)
}

/// Merges overlapping or adjacent IPv6 ranges and emits minimal canonical CIDRs.
#[must_use]
pub fn collapse_ipv6(cidrs: &[Ipv6Cidr]) -> Vec<Ipv6Cidr> {
    let intervals = cidrs.iter().copied().map(IntervalU128::from).collect();
    let merged = merge_intervals_u128_owned(intervals);
    intervals_to_ipv6_cidrs_from_merged(&merged)
}

pub(crate) fn ipv4_to_interval(cidr: Ipv4Cidr) -> IntervalU32 {
    let start = cidr.network;
    IntervalU32 {
        start,
        end: start.saturating_add(ipv4_host_mask(cidr.prefix)),
    }
}

pub(crate) fn ipv6_to_interval(cidr: Ipv6Cidr) -> IntervalU128 {
    let start = cidr.network;
    IntervalU128 {
        start,
        end: start.saturating_add(ipv6_host_mask(cidr.prefix)),
    }
}

#[cfg(test)]
pub(crate) fn merge_intervals_u32(intervals: &[IntervalU32]) -> Vec<IntervalU32> {
    merge_intervals_u32_owned(intervals.to_vec())
}

#[cfg(test)]
pub(crate) fn merge_intervals_u128(intervals: &[IntervalU128]) -> Vec<IntervalU128> {
    merge_intervals_u128_owned(intervals.to_vec())
}

/// Removes all safelisted IPv4 addresses and returns minimal canonical CIDRs.
#[must_use]
pub fn subtract_safelist_ipv4(candidates: &[Ipv4Cidr], safelist: &[Ipv4Cidr]) -> Vec<Ipv4Cidr> {
    let candidate_intervals = merge_intervals_u32_owned(
        candidates
            .iter()
            .copied()
            .map(IntervalU32::from)
            .collect::<Vec<_>>(),
    );
    let safe_intervals = merge_intervals_u32_owned(
        safelist
            .iter()
            .copied()
            .map(IntervalU32::from)
            .collect::<Vec<_>>(),
    );

    let carved = subtract_intervals_u32_merged(&candidate_intervals, &safe_intervals);
    intervals_to_ipv4_cidrs_from_merged(&carved)
}

/// Removes all safelisted IPv6 addresses and returns minimal canonical CIDRs.
#[must_use]
pub fn subtract_safelist_ipv6(candidates: &[Ipv6Cidr], safelist: &[Ipv6Cidr]) -> Vec<Ipv6Cidr> {
    let candidate_intervals = merge_intervals_u128_owned(
        candidates
            .iter()
            .copied()
            .map(IntervalU128::from)
            .collect::<Vec<_>>(),
    );
    let safe_intervals = merge_intervals_u128_owned(
        safelist
            .iter()
            .copied()
            .map(IntervalU128::from)
            .collect::<Vec<_>>(),
    );

    let carved = subtract_intervals_u128_merged(&candidate_intervals, &safe_intervals);
    intervals_to_ipv6_cidrs_from_merged(&carved)
}

#[cfg(test)]
pub(crate) fn intervals_to_ipv4_cidrs(intervals: &[IntervalU32]) -> Vec<Ipv4Cidr> {
    let merged = merge_intervals_u32_owned(intervals.to_vec());
    intervals_to_ipv4_cidrs_from_merged(&merged)
}

#[cfg(test)]
pub(crate) fn intervals_to_ipv6_cidrs(intervals: &[IntervalU128]) -> Vec<Ipv6Cidr> {
    let merged = merge_intervals_u128_owned(intervals.to_vec());
    intervals_to_ipv6_cidrs_from_merged(&merged)
}

#[must_use]
/// Returns whether two same-family CIDRs share at least one address.
///
/// CIDRs from different address families never overlap.
pub fn cidr_overlaps(a: CanonicalCidr, b: CanonicalCidr) -> bool {
    match (a, b) {
        (CanonicalCidr::V4(left), CanonicalCidr::V4(right)) => {
            intervals_overlap_u32(ipv4_to_interval(left), ipv4_to_interval(right))
        }
        (CanonicalCidr::V6(left), CanonicalCidr::V6(right)) => {
            intervals_overlap_u128(ipv6_to_interval(left), ipv6_to_interval(right))
        }
        _ => false,
    }
}

const RADIX_SORT_MIN_LEN: usize = 16_384;
const RADIX_BUCKETS_U16: usize = 1 << 16;

fn intervals_to_ipv4_cidrs_from_merged(intervals: &[IntervalU32]) -> Vec<Ipv4Cidr> {
    let mut out = Vec::new();

    for interval in intervals {
        let mut start = interval.start;

        while start <= interval.end {
            let prefix = largest_prefix_u32(start, interval.end);
            out.push(Ipv4Cidr::from_parts(start, prefix));

            if prefix == 0 {
                break;
            }

            let host_bits = 32_u32 - u32::from(prefix);
            let Some(increment) = 1_u32.checked_shl(host_bits) else {
                break;
            };
            if start > u32::MAX - increment {
                break;
            }
            start += increment;
        }
    }

    out
}

fn intervals_to_ipv6_cidrs_from_merged(intervals: &[IntervalU128]) -> Vec<Ipv6Cidr> {
    let mut out = Vec::new();

    for interval in intervals {
        let mut start = interval.start;

        while start <= interval.end {
            let prefix = largest_prefix_u128(start, interval.end);
            out.push(Ipv6Cidr::from_parts(start, prefix));

            if prefix == 0 {
                break;
            }

            let host_bits = 128_u32 - u32::from(prefix);
            let Some(size) = 1_u128.checked_shl(host_bits) else {
                break;
            };
            if start > u128::MAX - size {
                break;
            }
            start += size;
        }
    }

    out
}

fn merge_intervals_u32_owned(mut intervals: Vec<IntervalU32>) -> Vec<IntervalU32> {
    if intervals.is_empty() {
        return Vec::new();
    }

    sort_intervals_u32_for_merge(&mut intervals);
    let mut iter = intervals.into_iter();
    let Some(mut current) = iter.next() else {
        return Vec::new();
    };
    let mut merged = Vec::new();

    for interval in iter {
        if interval.start <= current.end.saturating_add(1) {
            current.end = current.end.max(interval.end);
        } else {
            merged.push(current);
            current = interval;
        }
    }

    merged.push(current);
    merged
}

fn sort_intervals_u32_for_merge(intervals: &mut [IntervalU32]) {
    if intervals.is_sorted() {
        return;
    }

    if intervals.len() < RADIX_SORT_MIN_LEN {
        intervals.sort_unstable();
        return;
    }

    // Two-pass LSD radix sort over 32-bit starts (16 bits per pass).
    if !radix_sort_intervals_u32_by_start(intervals) {
        intervals.sort_unstable();
    }
}

fn radix_sort_intervals_u32_by_start(intervals: &mut [IntervalU32]) -> bool {
    if intervals.len() < 2 {
        return true;
    }

    let mut src = intervals.to_vec();
    let mut dst = vec![IntervalU32 { start: 0, end: 0 }; intervals.len()];
    let mut counts = vec![0_usize; RADIX_BUCKETS_U16];

    for shift in [0_u32, 16_u32] {
        counts.fill(0);

        for interval in &src {
            let Ok(bucket) = usize::try_from((interval.start >> shift) & 0xFFFF) else {
                return false;
            };
            let Some(count) = counts.get_mut(bucket) else {
                return false;
            };
            *count += 1;
        }

        let mut running = 0_usize;
        for count in &mut counts {
            let current = *count;
            *count = running;
            running += current;
        }

        for interval in &src {
            let Ok(bucket) = usize::try_from((interval.start >> shift) & 0xFFFF) else {
                return false;
            };
            let Some(out_idx) = counts.get(bucket).copied() else {
                return false;
            };
            let Some(slot) = dst.get_mut(out_idx) else {
                return false;
            };
            *slot = *interval;
            let Some(count) = counts.get_mut(bucket) else {
                return false;
            };
            *count += 1;
        }

        std::mem::swap(&mut src, &mut dst);
    }

    intervals.copy_from_slice(&src);
    true
}

fn merge_intervals_u128_owned(mut intervals: Vec<IntervalU128>) -> Vec<IntervalU128> {
    if intervals.is_empty() {
        return Vec::new();
    }

    intervals.sort_unstable();
    let mut iter = intervals.into_iter();
    let Some(mut current) = iter.next() else {
        return Vec::new();
    };
    let mut merged = Vec::new();

    for interval in iter {
        if interval.start <= current.end.saturating_add(1) {
            current.end = current.end.max(interval.end);
        } else {
            merged.push(current);
            current = interval;
        }
    }

    merged.push(current);
    merged
}

fn subtract_intervals_u32_merged(base: &[IntervalU32], carve: &[IntervalU32]) -> Vec<IntervalU32> {
    if base.is_empty() {
        return Vec::new();
    }
    if carve.is_empty() {
        return base.to_vec();
    }

    let mut result = Vec::with_capacity(base.len());
    let mut carve_idx = 0_usize;

    for base_interval in base.iter().copied() {
        while carve
            .get(carve_idx)
            .is_some_and(|interval| interval.end < base_interval.start)
        {
            carve_idx += 1;
        }

        let mut next_start = base_interval.start;
        let mut idx = carve_idx;
        let mut fully_carved = false;

        while let Some(&carve_interval) = carve.get(idx) {
            if carve_interval.start > base_interval.end {
                break;
            }

            if carve_interval.end < next_start {
                idx += 1;
                continue;
            }

            if carve_interval.start > next_start {
                result.push(IntervalU32 {
                    start: next_start,
                    end: carve_interval.start - 1,
                });
            }

            if carve_interval.end >= base_interval.end {
                fully_carved = true;
                break;
            }

            next_start = carve_interval.end + 1;
            idx += 1;
        }

        if !fully_carved && next_start <= base_interval.end {
            result.push(IntervalU32 {
                start: next_start,
                end: base_interval.end,
            });
        }

        carve_idx = idx;
    }

    result
}

fn subtract_intervals_u128_merged(
    base: &[IntervalU128],
    carve: &[IntervalU128],
) -> Vec<IntervalU128> {
    if base.is_empty() {
        return Vec::new();
    }
    if carve.is_empty() {
        return base.to_vec();
    }

    let mut result = Vec::with_capacity(base.len());
    let mut carve_idx = 0_usize;

    for base_interval in base.iter().copied() {
        while carve
            .get(carve_idx)
            .is_some_and(|interval| interval.end < base_interval.start)
        {
            carve_idx += 1;
        }

        let mut next_start = base_interval.start;
        let mut idx = carve_idx;
        let mut fully_carved = false;

        while let Some(&carve_interval) = carve.get(idx) {
            if carve_interval.start > base_interval.end {
                break;
            }

            if carve_interval.end < next_start {
                idx += 1;
                continue;
            }

            if carve_interval.start > next_start {
                result.push(IntervalU128 {
                    start: next_start,
                    end: carve_interval.start - 1,
                });
            }

            if carve_interval.end >= base_interval.end {
                fully_carved = true;
                break;
            }

            next_start = carve_interval.end + 1;
            idx += 1;
        }

        if !fully_carved && next_start <= base_interval.end {
            result.push(IntervalU128 {
                start: next_start,
                end: base_interval.end,
            });
        }

        carve_idx = idx;
    }

    result
}

fn largest_prefix_u32(start: u32, end: u32) -> u8 {
    let mut prefix = 32_u8;

    for next_prefix in (0_u8..32_u8).rev() {
        if !is_aligned_u32(start, next_prefix) {
            break;
        }
        if block_end_u32(start, next_prefix) > end {
            break;
        }
        prefix = next_prefix;
    }

    prefix
}

fn largest_prefix_u128(start: u128, end: u128) -> u8 {
    let mut prefix = 128_u8;

    for next_prefix in (0_u8..128_u8).rev() {
        if !is_aligned_u128(start, next_prefix) {
            break;
        }
        if block_end_u128(start, next_prefix) > end {
            break;
        }
        prefix = next_prefix;
    }

    prefix
}

fn is_aligned_u32(start: u32, prefix: u8) -> bool {
    (start & ipv4_host_mask(prefix)) == 0
}

fn is_aligned_u128(start: u128, prefix: u8) -> bool {
    (start & ipv6_host_mask(prefix)) == 0
}

fn block_end_u32(start: u32, prefix: u8) -> u32 {
    start.saturating_add(ipv4_host_mask(prefix))
}

fn block_end_u128(start: u128, prefix: u8) -> u128 {
    start.saturating_add(ipv6_host_mask(prefix))
}

fn intervals_overlap_u32(a: IntervalU32, b: IntervalU32) -> bool {
    !(a.end < b.start || b.end < a.start)
}

fn intervals_overlap_u128(a: IntervalU128, b: IntervalU128) -> bool {
    !(a.end < b.start || b.end < a.start)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::{
        CanonicalCidr, IntervalU32, IntervalU128, Ipv4Cidr, Ipv6Cidr, block_end_u32,
        block_end_u128, cidr_overlaps, collapse_ipv4, collapse_ipv6, intervals_to_ipv4_cidrs,
        intervals_to_ipv6_cidrs, ipv4_mask, ipv4_to_interval, ipv6_mask, ipv6_to_interval,
        is_aligned_u32, is_aligned_u128, largest_prefix_u32, largest_prefix_u128,
        merge_intervals_u32, merge_intervals_u128, parse_ip_cidr_non_strict,
        parse_lines_non_strict, radix_sort_intervals_u32_by_start, split_by_family,
        subtract_safelist_ipv4, subtract_safelist_ipv6,
    };

    fn all_intervals_u32(base: u32, width: u32) -> Vec<IntervalU32> {
        let mut intervals = Vec::new();
        for start in 0..width {
            for end in start..width {
                intervals.push(IntervalU32 {
                    start: base + start,
                    end: base + end,
                });
            }
        }
        intervals
    }

    #[test]
    fn checked_constructors_reject_invalid_prefixes() {
        assert!(Ipv4Cidr::new(Ipv4Addr::UNSPECIFIED, 33).is_none());
        assert!(Ipv6Cidr::new(Ipv6Addr::UNSPECIFIED, 129).is_none());
    }

    #[test]
    fn checked_constructors_canonicalize_boundary_prefixes() {
        let v4 = Ipv4Cidr::new(Ipv4Addr::new(203, 0, 113, 7), 0).expect("valid prefix");
        let v6 = Ipv6Cidr::new(Ipv6Addr::LOCALHOST, 0).expect("valid prefix");

        assert_eq!(v4.network(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(v6.network(), Ipv6Addr::UNSPECIFIED);
        assert!(Ipv4Cidr::new(Ipv4Addr::BROADCAST, 32).is_some());
        assert!(Ipv6Cidr::new(Ipv6Addr::from(u128::MAX), 128).is_some());
    }

    fn all_intervals_u128(base: u128, width: u32) -> Vec<IntervalU128> {
        let mut intervals = Vec::new();
        for start in 0..width {
            for end in start..width {
                intervals.push(IntervalU128 {
                    start: base + u128::from(start),
                    end: base + u128::from(end),
                });
            }
        }
        intervals
    }

    fn interval_bits_u32(interval: IntervalU32, base: u32, width: u32) -> u16 {
        let mut bits = 0_u16;
        let upper = base + width;
        let start = interval.start.max(base);
        let end = interval.end.min(upper - 1);
        if start > end {
            return bits;
        }

        for ip in start..=end {
            bits |= 1_u16 << (ip - base);
        }
        bits
    }

    fn interval_bits_u128(interval: IntervalU128, base: u128, width: u32) -> u16 {
        let mut bits = 0_u16;
        let upper = base + u128::from(width);
        let start = interval.start.max(base);
        let end = interval.end.min(upper - 1);
        if start > end {
            return bits;
        }

        let mut ip = start;
        loop {
            let offset = u32::try_from(ip - base).expect("offset must fit u32");
            bits |= 1_u16 << offset;
            if ip == end {
                break;
            }
            ip += 1;
        }

        bits
    }

    fn cidrs_to_bits_u32(cidrs: &[Ipv4Cidr], base: u32, width: u32) -> u16 {
        let mut bits = 0_u16;
        let upper = base + width;

        for cidr in cidrs {
            let interval = ipv4_to_interval(*cidr);
            assert!(
                interval.start >= base && interval.end < upper,
                "interval escaped small test space: {interval:?} base={base} width={width}"
            );
            for ip in interval.start..=interval.end {
                bits |= 1_u16 << (ip - base);
            }
        }

        bits
    }

    fn cidrs_to_bits_u128(cidrs: &[Ipv6Cidr], base: u128, width: u32) -> u16 {
        let mut bits = 0_u16;
        let upper = base + u128::from(width);

        for cidr in cidrs {
            let interval = ipv6_to_interval(*cidr);
            assert!(
                interval.start >= base && interval.end < upper,
                "interval escaped small test space: {interval:?} base={base} width={width}"
            );

            let mut ip = interval.start;
            loop {
                let offset = u32::try_from(ip - base).expect("offset must fit u32");
                bits |= 1_u16 << offset;
                if ip == interval.end {
                    break;
                }
                ip += 1;
            }
        }

        bits
    }

    fn build_ipv4_forms(base: u32, width: u32) -> Vec<(Vec<Ipv4Cidr>, u16)> {
        let intervals = all_intervals_u32(base, width);
        let mut choices = Vec::with_capacity(intervals.len() + 1);
        choices.push(None);
        choices.extend(intervals.iter().copied().map(Some));

        let mut forms = Vec::new();
        for first in &choices {
            for second in &choices {
                let mut cidrs = Vec::new();
                let mut bits = 0_u16;

                if let Some(interval) = first {
                    cidrs.extend(intervals_to_ipv4_cidrs(&[*interval]));
                    bits |= interval_bits_u32(*interval, base, width);
                }
                if let Some(interval) = second {
                    cidrs.extend(intervals_to_ipv4_cidrs(&[*interval]));
                    bits |= interval_bits_u32(*interval, base, width);
                }

                if let Some(first_cidr) = cidrs.first().copied() {
                    cidrs.push(first_cidr);
                }
                cidrs.reverse();

                forms.push((cidrs, bits));
            }
        }

        forms
    }

    fn build_ipv6_forms(base: u128, width: u32) -> Vec<(Vec<Ipv6Cidr>, u16)> {
        let intervals = all_intervals_u128(base, width);
        let mut choices = Vec::with_capacity(intervals.len() + 1);
        choices.push(None);
        choices.extend(intervals.iter().copied().map(Some));

        let mut forms = Vec::new();
        for first in &choices {
            for second in &choices {
                let mut cidrs = Vec::new();
                let mut bits = 0_u16;

                if let Some(interval) = first {
                    cidrs.extend(intervals_to_ipv6_cidrs(&[*interval]));
                    bits |= interval_bits_u128(*interval, base, width);
                }
                if let Some(interval) = second {
                    cidrs.extend(intervals_to_ipv6_cidrs(&[*interval]));
                    bits |= interval_bits_u128(*interval, base, width);
                }

                if let Some(first_cidr) = cidrs.first().copied() {
                    cidrs.push(first_cidr);
                }
                cidrs.reverse();

                forms.push((cidrs, bits));
            }
        }

        forms
    }

    fn merge_intervals_u32_with_standard_sort(mut intervals: Vec<IntervalU32>) -> Vec<IntervalU32> {
        if intervals.is_empty() {
            return Vec::new();
        }

        intervals.sort_unstable();
        let mut iter = intervals.into_iter();
        let mut current = iter
            .next()
            .expect("non-empty intervals must have a first item");
        let mut merged = Vec::new();

        for interval in iter {
            if interval.start <= current.end.saturating_add(1) {
                current.end = current.end.max(interval.end);
            } else {
                merged.push(current);
                current = interval;
            }
        }

        merged.push(current);
        merged
    }

    #[test]
    fn parse_non_strict_accepts_hosts_and_canonicalizes_networks() {
        let host = parse_ip_cidr_non_strict("10.0.0.1").expect("parse host");
        assert_eq!(
            host,
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a00_0001, 32))
        );

        let cidr = parse_ip_cidr_non_strict("10.0.0.42/24").expect("parse cidr");
        assert_eq!(
            cidr,
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a00_0000, 24))
        );

        assert!(parse_ip_cidr_non_strict("not-an-ip").is_none());
        assert!(parse_ip_cidr_non_strict(" ").is_none());
    }

    #[test]
    fn split_by_family_is_strict() {
        let parsed = parse_lines_non_strict([
            "10.0.0.1",
            "2001:db8::1",
            "invalid",
            "198.51.100.0/24 trailing",
        ]);

        let separated = split_by_family(&parsed);
        assert_eq!(separated.ipv4.len(), 2);
        assert_eq!(separated.ipv6.len(), 1);
    }

    #[test]
    fn collapse_ipv4_merges_overlap_and_adjacency() {
        let collapsed = collapse_ipv4(&[
            Ipv4Cidr::from_parts(0x0a00_0000, 25),
            Ipv4Cidr::from_parts(0x0a00_0080, 25),
            Ipv4Cidr::from_parts(0x0a00_0000, 24),
        ]);

        assert_eq!(collapsed, vec![Ipv4Cidr::from_parts(0x0a00_0000, 24)]);
    }

    #[test]
    fn collapse_ipv6_merges_adjacent_networks() {
        let collapsed = collapse_ipv6(&[
            Ipv6Cidr::from_parts(0x2001_0db8_0000_0000_0000_0000_0000_0000, 65),
            Ipv6Cidr::from_parts(0x2001_0db8_0000_0000_8000_0000_0000_0000, 65),
        ]);

        assert_eq!(
            collapsed,
            vec![Ipv6Cidr::from_parts(
                0x2001_0db8_0000_0000_0000_0000_0000_0000,
                64
            )]
        );
    }

    #[test]
    fn interval_conversion_is_correct_for_ipv4_and_ipv6() {
        let v4_interval = ipv4_to_interval(Ipv4Cidr::from_parts(0xc000_0200, 24));
        assert_eq!(
            v4_interval,
            IntervalU32 {
                start: 0xc000_0200,
                end: 0xc000_02ff,
            }
        );

        let v6_interval = ipv6_to_interval(Ipv6Cidr::from_parts(
            0x2001_0db8_0000_0000_0000_0000_0000_0000,
            126,
        ));
        assert_eq!(
            v6_interval,
            IntervalU128 {
                start: 0x2001_0db8_0000_0000_0000_0000_0000_0000,
                end: 0x2001_0db8_0000_0000_0000_0000_0000_0003,
            }
        );
    }

    #[test]
    fn cidr_overlap_includes_shared_endpoint_for_each_family() {
        let v4_block = CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a00_0000, 24));
        let v4_last_host = CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a00_00ff, 32));

        assert!(cidr_overlaps(v4_block, v4_last_host));
        assert!(cidr_overlaps(v4_last_host, v4_block));

        let v6_base = 0x2001_0db8_0000_0000_0000_0000_0000_0000_u128;
        let v6_block = CanonicalCidr::V6(Ipv6Cidr::from_parts(v6_base, 127));
        let v6_last_host = CanonicalCidr::V6(Ipv6Cidr::from_parts(v6_base + 1, 128));

        assert!(cidr_overlaps(v6_block, v6_last_host));
        assert!(cidr_overlaps(v6_last_host, v6_block));
    }

    #[test]
    fn ipv4_interval_conversion_covers_boundary_prefixes() {
        let full_space = Ipv4Cidr::new(Ipv4Addr::new(203, 0, 113, 99), 0).expect("valid /0");
        assert_eq!(full_space.network(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(full_space.prefix(), 0);
        assert_eq!(
            ipv4_to_interval(full_space),
            IntervalU32 {
                start: 0,
                end: u32::MAX,
            }
        );

        let canonicalized = Ipv4Cidr::new(Ipv4Addr::new(192, 0, 2, 129), 25).expect("valid /25");
        assert_eq!(canonicalized.network(), Ipv4Addr::new(192, 0, 2, 128));
        assert_eq!(canonicalized.prefix(), 25);
        assert_eq!(
            ipv4_to_interval(canonicalized),
            IntervalU32 {
                start: 0xc000_0280,
                end: 0xc000_02ff,
            }
        );

        let max_host = Ipv4Cidr::new(Ipv4Addr::BROADCAST, 32).expect("valid /32");
        assert_eq!(max_host.prefix(), 32);
        assert_eq!(
            ipv4_to_interval(max_host),
            IntervalU32 {
                start: u32::MAX,
                end: u32::MAX,
            }
        );

        let max_pair = Ipv4Cidr::new(Ipv4Addr::new(255, 255, 255, 254), 31).expect("valid /31");
        assert_eq!(
            ipv4_to_interval(max_pair),
            IntervalU32 {
                start: u32::MAX - 1,
                end: u32::MAX,
            }
        );
    }

    #[test]
    fn ipv6_interval_conversion_covers_boundary_prefixes() {
        let full_space =
            Ipv6Cidr::new(Ipv6Addr::from(0x2001_0db8_0000_0000_u128), 0).expect("valid /0");
        assert_eq!(full_space.network(), Ipv6Addr::from(0));
        assert_eq!(full_space.prefix(), 0);
        assert_eq!(
            ipv6_to_interval(full_space),
            IntervalU128 {
                start: 0,
                end: u128::MAX,
            }
        );

        let high_bit_network = Ipv6Cidr::new(
            Ipv6Addr::from(0xffff_0000_0000_0000_0000_0000_0000_0001_u128),
            16,
        )
        .expect("valid /16");
        assert_eq!(
            high_bit_network.network(),
            Ipv6Addr::from(0xffff_0000_0000_0000_0000_0000_0000_0000_u128)
        );
        assert_eq!(high_bit_network.prefix(), 16);
        assert_eq!(
            ipv6_to_interval(high_bit_network),
            IntervalU128 {
                start: 0xffff_0000_0000_0000_0000_0000_0000_0000_u128,
                end: 0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_u128,
            }
        );

        let max_host = Ipv6Cidr::new(Ipv6Addr::from(u128::MAX), 128).expect("valid /128");
        assert_eq!(max_host.prefix(), 128);
        assert_eq!(
            ipv6_to_interval(max_host),
            IntervalU128 {
                start: u128::MAX,
                end: u128::MAX,
            }
        );

        let max_pair = Ipv6Cidr::new(Ipv6Addr::from(u128::MAX - 1), 127).expect("valid /127");
        assert_eq!(
            ipv6_to_interval(max_pair),
            IntervalU128 {
                start: u128::MAX - 1,
                end: u128::MAX,
            }
        );
    }

    #[test]
    fn largest_prefix_helpers_cover_progress_boundaries() {
        assert_eq!(largest_prefix_u32(0, u32::MAX), 0);
        assert_eq!(largest_prefix_u32(u32::MAX - 1, u32::MAX), 31);
        assert_eq!(largest_prefix_u32(u32::MAX, u32::MAX), 32);
        assert_eq!(largest_prefix_u32(0x0a00_0003, 0x0a00_0006), 32);
        assert!(is_aligned_u32(0, 0));
        assert!(!is_aligned_u32(1, 0));
        assert!(is_aligned_u32(u32::MAX, 32));
        assert!(!is_aligned_u32(u32::MAX, 31));

        assert_eq!(largest_prefix_u128(0, u128::MAX), 0);
        assert_eq!(largest_prefix_u128(u128::MAX - 1, u128::MAX), 127);
        assert_eq!(largest_prefix_u128(u128::MAX, u128::MAX), 128);
        assert_eq!(
            largest_prefix_u128(
                0x2001_0db8_0000_0000_0000_0000_0000_0003,
                0x2001_0db8_0000_0000_0000_0000_0000_0006,
            ),
            128
        );
        assert!(is_aligned_u128(0, 0));
        assert!(!is_aligned_u128(1, 0));
        assert!(is_aligned_u128(u128::MAX, 128));
        assert!(!is_aligned_u128(u128::MAX, 127));
    }

    #[test]
    fn mask_and_block_end_helpers_cover_prefix_boundaries() {
        assert_eq!(ipv4_mask(0), 0);
        assert_eq!(ipv4_mask(24), 0xffff_ff00);
        assert_eq!(ipv4_mask(32), u32::MAX);
        assert_eq!(block_end_u32(0, 0), u32::MAX);
        assert_eq!(block_end_u32(0xc000_0200, 24), 0xc000_02ff);
        assert_eq!(block_end_u32(u32::MAX, 32), u32::MAX);

        assert_eq!(ipv6_mask(0), 0);
        assert_eq!(
            ipv6_mask(16),
            0xffff_0000_0000_0000_0000_0000_0000_0000_u128
        );
        assert_eq!(ipv6_mask(128), u128::MAX);
        assert_eq!(block_end_u128(0, 0), u128::MAX);
        assert_eq!(
            block_end_u128(0x2001_0db8_0000_0000_0000_0000_0000_0000_u128, 64),
            0x2001_0db8_0000_0000_ffff_ffff_ffff_ffff_u128
        );
        assert_eq!(block_end_u128(u128::MAX, 128), u128::MAX);
    }

    #[test]
    fn merge_intervals_handles_adjacency() {
        let merged_v4 = merge_intervals_u32(&[
            IntervalU32 { start: 10, end: 20 },
            IntervalU32 { start: 21, end: 30 },
        ]);
        assert_eq!(merged_v4, vec![IntervalU32 { start: 10, end: 30 }]);

        let merged_v6 = merge_intervals_u128(&[
            IntervalU128 {
                start: 100,
                end: 120,
            },
            IntervalU128 {
                start: 121,
                end: 130,
            },
        ]);
        assert_eq!(
            merged_v6,
            vec![IntervalU128 {
                start: 100,
                end: 130
            }]
        );
    }

    #[test]
    fn merge_intervals_matches_for_sorted_and_unsorted_inputs() {
        let sorted_v4 = vec![
            IntervalU32 { start: 1, end: 2 },
            IntervalU32 { start: 3, end: 5 },
            IntervalU32 { start: 10, end: 12 },
        ];
        let unsorted_v4 = vec![
            IntervalU32 { start: 10, end: 12 },
            IntervalU32 { start: 1, end: 2 },
            IntervalU32 { start: 3, end: 5 },
        ];
        assert_eq!(
            merge_intervals_u32(&sorted_v4),
            merge_intervals_u32(&unsorted_v4)
        );

        let sorted_v6 = vec![
            IntervalU128 { start: 40, end: 50 },
            IntervalU128 { start: 51, end: 53 },
            IntervalU128 {
                start: 100,
                end: 110,
            },
        ];
        let unsorted_v6 = vec![
            IntervalU128 {
                start: 100,
                end: 110,
            },
            IntervalU128 { start: 40, end: 50 },
            IntervalU128 { start: 51, end: 53 },
        ];
        assert_eq!(
            merge_intervals_u128(&sorted_v6),
            merge_intervals_u128(&unsorted_v6)
        );
    }

    #[test]
    fn merge_intervals_handles_equal_starts_with_mixed_ends() {
        let intervals = vec![
            IntervalU32 {
                start: 100,
                end: 100,
            },
            IntervalU32 {
                start: 100,
                end: 140,
            },
            IntervalU32 {
                start: 101,
                end: 110,
            },
            IntervalU32 {
                start: 141,
                end: 141,
            },
        ];

        let merged = merge_intervals_u32(&intervals);
        assert_eq!(
            merged,
            vec![IntervalU32 {
                start: 100,
                end: 141
            }]
        );
    }

    #[test]
    fn merge_intervals_merges_unsorted_adjacency() {
        let merged_v4 = merge_intervals_u32(&[
            IntervalU32 { start: 21, end: 30 },
            IntervalU32 { start: 10, end: 20 },
        ]);
        assert_eq!(merged_v4, vec![IntervalU32 { start: 10, end: 30 }]);

        let merged_v6 = merge_intervals_u128(&[
            IntervalU128 {
                start: 121,
                end: 130,
            },
            IntervalU128 {
                start: 100,
                end: 120,
            },
        ]);
        assert_eq!(
            merged_v6,
            vec![IntervalU128 {
                start: 100,
                end: 130
            }]
        );
    }

    #[test]
    fn merge_intervals_preserves_single_interval() {
        assert_eq!(
            merge_intervals_u32(&[IntervalU32 { start: 10, end: 12 }]),
            vec![IntervalU32 { start: 10, end: 12 }]
        );
        assert_eq!(
            merge_intervals_u128(&[IntervalU128 { start: 10, end: 12 }]),
            vec![IntervalU128 { start: 10, end: 12 }]
        );
    }

    #[test]
    fn merge_intervals_handles_equal_starts_for_ipv6() {
        let merged = merge_intervals_u128(&[
            IntervalU128 {
                start: 100,
                end: 100,
            },
            IntervalU128 {
                start: 100,
                end: 140,
            },
        ]);
        assert_eq!(
            merged,
            vec![IntervalU128 {
                start: 100,
                end: 140
            }]
        );
    }

    #[test]
    fn merge_intervals_does_not_merge_across_single_address_gap() {
        let merged_v4 = merge_intervals_u32(&[
            IntervalU32 { start: 1, end: 2 },
            IntervalU32 { start: 4, end: 5 },
        ]);
        assert_eq!(
            merged_v4,
            vec![
                IntervalU32 { start: 1, end: 2 },
                IntervalU32 { start: 4, end: 5 },
            ]
        );

        let merged_v6 = merge_intervals_u128(&[
            IntervalU128 { start: 1, end: 2 },
            IntervalU128 { start: 4, end: 5 },
        ]);
        assert_eq!(
            merged_v6,
            vec![
                IntervalU128 { start: 1, end: 2 },
                IntervalU128 { start: 4, end: 5 },
            ]
        );
    }

    #[test]
    fn merge_intervals_handles_max_endpoint_without_overflow() {
        assert_eq!(
            merge_intervals_u32(&[
                IntervalU32 {
                    start: u32::MAX,
                    end: u32::MAX,
                },
                IntervalU32 {
                    start: u32::MAX,
                    end: u32::MAX,
                },
            ]),
            vec![IntervalU32 {
                start: u32::MAX,
                end: u32::MAX,
            }]
        );

        assert_eq!(
            merge_intervals_u128(&[
                IntervalU128 {
                    start: u128::MAX,
                    end: u128::MAX,
                },
                IntervalU128 {
                    start: u128::MAX,
                    end: u128::MAX,
                },
            ]),
            vec![IntervalU128 {
                start: u128::MAX,
                end: u128::MAX,
            }]
        );
    }

    #[test]
    fn merge_intervals_returns_empty_for_empty_input() {
        assert!(merge_intervals_u32(&[]).is_empty());
    }

    #[test]
    fn merge_intervals_handles_zero_start_without_underflow() {
        let merged = merge_intervals_u32(&[
            IntervalU32 { start: 0, end: 0 },
            IntervalU32 { start: 1, end: 1 },
        ]);
        assert_eq!(merged, vec![IntervalU32 { start: 0, end: 1 }]);
    }

    #[test]
    fn merge_intervals_preserves_three_disjoint_components() {
        let merged = merge_intervals_u32(&[
            IntervalU32 { start: 1, end: 1 },
            IntervalU32 { start: 3, end: 3 },
            IntervalU32 { start: 5, end: 5 },
        ]);
        assert_eq!(
            merged,
            vec![
                IntervalU32 { start: 1, end: 1 },
                IntervalU32 { start: 3, end: 3 },
                IntervalU32 { start: 5, end: 5 },
            ]
        );
    }

    #[test]
    fn merge_intervals_large_unsorted_input_uses_correct_ordering() {
        let mut intervals = Vec::with_capacity(16_384);
        for i in 0..8_192_u32 {
            intervals.push(IntervalU32 {
                start: 0x0001_0000 + i * 2,
                end: 0x0001_0000 + i * 2,
            });
            intervals.push(IntervalU32 {
                start: i * 2,
                end: i * 2,
            });
        }

        let merged = merge_intervals_u32(&intervals);

        assert_eq!(merged.len(), 16_384);
        assert_eq!(merged[0], IntervalU32 { start: 0, end: 0 });
        assert_eq!(
            merged[8_191],
            IntervalU32 {
                start: 16_382,
                end: 16_382
            }
        );
        assert_eq!(
            merged[8_192],
            IntervalU32 {
                start: 65_536,
                end: 65_536
            }
        );
    }

    #[test]
    fn large_unsorted_ipv4_merge_matches_standard_sorting() {
        let mut intervals = Vec::with_capacity(20_000);

        for i in 0..20_000_u32 {
            let start = ((i * 65_537) % 1_000_003) * 4 + 1;
            intervals.push(IntervalU32 { start, end: start });
        }

        let expected = merge_intervals_u32_with_standard_sort(intervals.clone());
        let actual = merge_intervals_u32(&intervals);

        assert_eq!(actual, expected);
        assert_eq!(actual.len(), intervals.len());
        assert_ne!(intervals, expected);
    }

    #[test]
    fn radix_sort_directly_sorts_mixed_high_and_low_start_bits() {
        let mut intervals = vec![
            IntervalU32 {
                start: 0x0002_0001,
                end: 0x0002_0001,
            },
            IntervalU32 {
                start: 0x0001_ffff,
                end: 0x0001_ffff,
            },
            IntervalU32 {
                start: 0xffff_0000,
                end: 0xffff_0000,
            },
            IntervalU32 {
                start: 0x0000_8000,
                end: 0x0000_8000,
            },
            IntervalU32 {
                start: 0x0001_0000,
                end: 0x0001_0000,
            },
            IntervalU32 {
                start: 0x0000_0002,
                end: 0x0000_0002,
            },
            IntervalU32 {
                start: 0x8000_0001,
                end: 0x8000_0001,
            },
            IntervalU32 {
                start: 0x0002_0000,
                end: 0x0002_0000,
            },
        ];
        let mut expected = intervals.clone();
        expected.sort_by_key(|interval| interval.start);

        assert!(radix_sort_intervals_u32_by_start(&mut intervals));
        assert_eq!(intervals, expected);

        let mut two_intervals = vec![
            IntervalU32 { start: 2, end: 2 },
            IntervalU32 { start: 1, end: 1 },
        ];
        assert!(radix_sort_intervals_u32_by_start(&mut two_intervals));
        assert_eq!(
            two_intervals,
            vec![
                IntervalU32 { start: 1, end: 1 },
                IntervalU32 { start: 2, end: 2 },
            ]
        );
    }

    #[test]
    fn safelist_subtraction_carves_ipv4_ranges() {
        let carved = subtract_safelist_ipv4(
            &[Ipv4Cidr::from_parts(0x0a00_0000, 24)],
            &[Ipv4Cidr::from_parts(0x0a00_0000, 25)],
        );

        assert_eq!(carved, vec![Ipv4Cidr::from_parts(0x0a00_0080, 25)]);
    }

    #[test]
    fn safelist_subtraction_carves_ipv6_ranges() {
        let carved = subtract_safelist_ipv6(
            &[Ipv6Cidr::from_parts(
                0x2001_0db8_0000_0000_0000_0000_0000_0000,
                127,
            )],
            &[Ipv6Cidr::from_parts(
                0x2001_0db8_0000_0000_0000_0000_0000_0000,
                128,
            )],
        );

        assert_eq!(
            carved,
            vec![Ipv6Cidr::from_parts(
                0x2001_0db8_0000_0000_0000_0000_0000_0001,
                128
            )]
        );
    }

    #[test]
    fn exhaustive_ipv4_subtraction_matches_bruteforce_on_small_space() {
        let base = 0xcb00_7100_u32;
        let width = 6_u32;
        let forms = build_ipv4_forms(base, width);

        for (candidates, candidate_bits) in &forms {
            for (safelist, safelist_bits) in &forms {
                let actual = subtract_safelist_ipv4(candidates, safelist);
                let actual_bits = cidrs_to_bits_u32(&actual, base, width);
                let expected_bits = *candidate_bits & !*safelist_bits;

                assert_eq!(
                    actual_bits, expected_bits,
                    "IPv4 carved set mismatch candidates={candidates:?} safelist={safelist:?}"
                );
            }
        }
    }

    #[test]
    fn exhaustive_ipv6_subtraction_matches_bruteforce_on_small_space() {
        let base = 0x2001_0db8_0000_0000_0000_0000_0000_0000_u128;
        let width = 6_u32;
        let forms = build_ipv6_forms(base, width);

        for (candidates, candidate_bits) in &forms {
            for (safelist, safelist_bits) in &forms {
                let actual = subtract_safelist_ipv6(candidates, safelist);
                let actual_bits = cidrs_to_bits_u128(&actual, base, width);
                let expected_bits = *candidate_bits & !*safelist_bits;

                assert_eq!(
                    actual_bits, expected_bits,
                    "IPv6 carved set mismatch candidates={candidates:?} safelist={safelist:?}"
                );
            }
        }
    }

    #[test]
    fn minimal_cidr_regeneration_from_intervals() {
        let cidrs = intervals_to_ipv4_cidrs(&[IntervalU32 {
            start: 0x0a00_0002,
            end: 0x0a00_0005,
        }]);

        assert_eq!(
            cidrs,
            vec![
                Ipv4Cidr::from_parts(0x0a00_0002, 31),
                Ipv4Cidr::from_parts(0x0a00_0004, 31),
            ]
        );

        let cidrs_v6 = intervals_to_ipv6_cidrs(&[IntervalU128 {
            start: 0x2001_0db8_0000_0000_0000_0000_0000_0002,
            end: 0x2001_0db8_0000_0000_0000_0000_0000_0003,
        }]);
        assert_eq!(
            cidrs_v6,
            vec![Ipv6Cidr::from_parts(
                0x2001_0db8_0000_0000_0000_0000_0000_0002,
                127
            )]
        );
    }

    #[test]
    fn interval_regeneration_covers_ipv4_boundary_shapes() {
        assert_eq!(
            intervals_to_ipv4_cidrs(&[IntervalU32 {
                start: 0x0a00_0001,
                end: 0x0a00_0001,
            }]),
            vec![Ipv4Cidr::from_parts(0x0a00_0001, 32)]
        );

        assert_eq!(
            intervals_to_ipv4_cidrs(&[IntervalU32 {
                start: 0x0a00_0002,
                end: 0x0a00_0003,
            }]),
            vec![Ipv4Cidr::from_parts(0x0a00_0002, 31)]
        );

        assert_eq!(
            intervals_to_ipv4_cidrs(&[IntervalU32 {
                start: 0x0a00_0003,
                end: 0x0a00_0006,
            }]),
            vec![
                Ipv4Cidr::from_parts(0x0a00_0003, 32),
                Ipv4Cidr::from_parts(0x0a00_0004, 31),
                Ipv4Cidr::from_parts(0x0a00_0006, 32),
            ]
        );

        assert_eq!(
            intervals_to_ipv4_cidrs(&[IntervalU32 {
                start: u32::MAX - 2,
                end: u32::MAX,
            }]),
            vec![
                Ipv4Cidr::from_parts(u32::MAX - 2, 32),
                Ipv4Cidr::from_parts(u32::MAX - 1, 31),
            ]
        );
    }

    #[test]
    fn interval_regeneration_covers_ipv6_boundary_shapes() {
        let base = 0x2001_0db8_0000_0000_0000_0000_0000_0000_u128;

        assert_eq!(
            intervals_to_ipv6_cidrs(&[IntervalU128 {
                start: base + 1,
                end: base + 1,
            }]),
            vec![Ipv6Cidr::from_parts(base + 1, 128)]
        );

        assert_eq!(
            intervals_to_ipv6_cidrs(&[IntervalU128 {
                start: base + 2,
                end: base + 3,
            }]),
            vec![Ipv6Cidr::from_parts(base + 2, 127)]
        );

        assert_eq!(
            intervals_to_ipv6_cidrs(&[IntervalU128 {
                start: base + 3,
                end: base + 6,
            }]),
            vec![
                Ipv6Cidr::from_parts(base + 3, 128),
                Ipv6Cidr::from_parts(base + 4, 127),
                Ipv6Cidr::from_parts(base + 6, 128),
            ]
        );

        assert_eq!(
            intervals_to_ipv6_cidrs(&[IntervalU128 {
                start: u128::MAX - 2,
                end: u128::MAX,
            }]),
            vec![
                Ipv6Cidr::from_parts(u128::MAX - 2, 128),
                Ipv6Cidr::from_parts(u128::MAX - 1, 127),
            ]
        );
    }

    #[test]
    fn interval_regeneration_covers_full_address_spaces() {
        assert_eq!(
            intervals_to_ipv4_cidrs(&[IntervalU32 {
                start: 0,
                end: u32::MAX,
            }]),
            vec![Ipv4Cidr::from_parts(0, 0)]
        );

        assert_eq!(
            intervals_to_ipv6_cidrs(&[IntervalU128 {
                start: 0,
                end: u128::MAX,
            }]),
            vec![Ipv6Cidr::from_parts(0, 0)]
        );
    }

    #[test]
    fn interval_regeneration_merges_adjacent_input_intervals() {
        let cidrs = intervals_to_ipv4_cidrs(&[
            IntervalU32 {
                start: 0x0a00_0000,
                end: 0x0a00_0000,
            },
            IntervalU32 {
                start: 0x0a00_0001,
                end: 0x0a00_0001,
            },
        ]);

        assert_eq!(cidrs, vec![Ipv4Cidr::from_parts(0x0a00_0000, 31)]);
    }

    #[test]
    fn interval_regeneration_sorts_unsorted_ipv6_input_intervals() {
        let base = 0x2001_0db8_0000_0000_0000_0000_0000_0000_u128;
        let cidrs = intervals_to_ipv6_cidrs(&[
            IntervalU128 {
                start: base + 4,
                end: base + 5,
            },
            IntervalU128 {
                start: base,
                end: base + 1,
            },
        ]);

        assert_eq!(
            cidrs,
            vec![
                Ipv6Cidr::from_parts(base, 127),
                Ipv6Cidr::from_parts(base + 4, 127),
            ]
        );
    }

    #[test]
    fn parse_lines_non_strict_ignores_invalid_lines() {
        let parsed = parse_lines_non_strict(["10.0.0.1", "not-valid", "2001:db8::/32"]);
        assert_eq!(parsed.len(), 2);
    }
}
