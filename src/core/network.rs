use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::core::AddressFamily;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CanonicalCidr {
    V4(Ipv4Cidr),
    V6(Ipv6Cidr),
}

impl CanonicalCidr {
    pub fn family(self) -> AddressFamily {
        match self {
            Self::V4(_) => AddressFamily::Ipv4,
            Self::V6(_) => AddressFamily::Ipv6,
        }
    }
}

impl std::fmt::Display for CanonicalCidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CanonicalCidr::V4(cidr) => write!(f, "{cidr}"),
            CanonicalCidr::V6(cidr) => write!(f, "{cidr}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ipv4Cidr {
    network: u32,
    prefix: u8,
}

impl Ipv4Cidr {
    pub fn new(address: Ipv4Addr, prefix: u8) -> Option<Self> {
        if prefix > 32 {
            return None;
        }

        let raw = u32::from(address);
        Some(Self::from_parts(raw, prefix))
    }

    pub fn from_parts(network: u32, prefix: u8) -> Self {
        debug_assert!(prefix <= 32);
        let mask = ipv4_mask(prefix);
        Self {
            network: network & mask,
            prefix,
        }
    }

    pub fn network(self) -> Ipv4Addr {
        Ipv4Addr::from(self.network)
    }

    pub fn prefix(self) -> u8 {
        self.prefix
    }
}

impl std::fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network(), self.prefix)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ipv6Cidr {
    network: u128,
    prefix: u8,
}

impl Ipv6Cidr {
    pub fn new(address: Ipv6Addr, prefix: u8) -> Option<Self> {
        if prefix > 128 {
            return None;
        }

        let raw = u128::from(address);
        Some(Self::from_parts(raw, prefix))
    }

    pub fn from_parts(network: u128, prefix: u8) -> Self {
        debug_assert!(prefix <= 128);
        let mask = ipv6_mask(prefix);
        Self {
            network: network & mask,
            prefix,
        }
    }

    pub fn network(self) -> Ipv6Addr {
        Ipv6Addr::from(self.network)
    }

    pub fn prefix(self) -> u8 {
        self.prefix
    }
}

impl std::fmt::Display for Ipv6Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network(), self.prefix)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FamilyCidrs {
    pub ipv4: Vec<Ipv4Cidr>,
    pub ipv6: Vec<Ipv6Cidr>,
}

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

pub(crate) fn parse_ip_cidr_non_strict(input: &str) -> Option<CanonicalCidr> {
    let token = input.split_whitespace().next()?.trim();
    if token.is_empty() {
        return None;
    }

    parse_ip_cidr_token(token)
}

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

pub(crate) fn parse_ip_cidr_token(token: &str) -> Option<CanonicalCidr> {
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

pub(crate) fn parse_lines_non_strict<I, S>(inputs: I) -> Vec<CanonicalCidr>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    inputs
        .into_iter()
        .filter_map(|value| parse_ip_cidr_non_strict(value.as_ref()))
        .collect()
}

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

pub fn collapse_ipv4(cidrs: &[Ipv4Cidr]) -> Vec<Ipv4Cidr> {
    let intervals = cidrs.iter().copied().map(IntervalU32::from).collect();
    let merged = merge_intervals_u32_owned(intervals);
    intervals_to_ipv4_cidrs_from_merged(&merged)
}

pub fn collapse_ipv6(cidrs: &[Ipv6Cidr]) -> Vec<Ipv6Cidr> {
    let intervals = cidrs.iter().copied().map(IntervalU128::from).collect();
    let merged = merge_intervals_u128_owned(intervals);
    intervals_to_ipv6_cidrs_from_merged(&merged)
}

pub(crate) fn ipv4_to_interval(cidr: Ipv4Cidr) -> IntervalU32 {
    let start = cidr.network;
    let end = if cidr.prefix == 0 {
        u32::MAX
    } else {
        let host_bits = 32_u32 - u32::from(cidr.prefix);
        let suffix = (1_u32 << host_bits) - 1;
        start | suffix
    };

    IntervalU32 { start, end }
}

pub(crate) fn ipv6_to_interval(cidr: Ipv6Cidr) -> IntervalU128 {
    let start = cidr.network;
    let end = if cidr.prefix == 0 {
        u128::MAX
    } else {
        let host_bits = 128_u32 - u32::from(cidr.prefix);
        let suffix = if host_bits == 0 {
            0
        } else {
            (1_u128 << host_bits) - 1
        };
        start | suffix
    };

    IntervalU128 { start, end }
}

#[cfg(test)]
pub(crate) fn merge_intervals_u32(intervals: &[IntervalU32]) -> Vec<IntervalU32> {
    merge_intervals_u32_owned(intervals.to_vec())
}

#[cfg(test)]
pub(crate) fn merge_intervals_u128(intervals: &[IntervalU128]) -> Vec<IntervalU128> {
    merge_intervals_u128_owned(intervals.to_vec())
}

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
            let increment = 1_u32 << host_bits;
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

            let size = 1_u128 << (128_u32 - u32::from(prefix));
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
            let bucket = ((interval.start >> shift) & 0xFFFF) as usize;
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
            let bucket = ((interval.start >> shift) & 0xFFFF) as usize;
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

    while prefix > 0 {
        let next_prefix = prefix - 1;
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

    while prefix > 0 {
        let next_prefix = prefix - 1;
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
    if prefix == 0 {
        return start == 0;
    }

    let host_bits = 32_u32 - u32::from(prefix);
    let host_mask = (1_u32 << host_bits) - 1;
    (start & host_mask) == 0
}

fn is_aligned_u128(start: u128, prefix: u8) -> bool {
    if prefix == 0 {
        return start == 0;
    }

    let host_bits = 128_u32 - u32::from(prefix);
    let host_mask = (1_u128 << host_bits) - 1;
    (start & host_mask) == 0
}

fn block_end_u32(start: u32, prefix: u8) -> u32 {
    if prefix == 0 {
        u32::MAX
    } else {
        let host_bits = 32_u32 - u32::from(prefix);
        let increment = (1_u32 << host_bits) - 1;
        start.saturating_add(increment)
    }
}

fn block_end_u128(start: u128, prefix: u8) -> u128 {
    if prefix == 0 {
        u128::MAX
    } else {
        let host_bits = 128_u32 - u32::from(prefix);
        start.saturating_add((1_u128 << host_bits) - 1)
    }
}

fn intervals_overlap_u32(a: IntervalU32, b: IntervalU32) -> bool {
    !(a.end < b.start || b.end < a.start)
}

fn intervals_overlap_u128(a: IntervalU128, b: IntervalU128) -> bool {
    !(a.end < b.start || b.end < a.start)
}

fn ipv4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32_u32 - u32::from(prefix))
    }
}

fn ipv6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128_u32 - u32::from(prefix))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CanonicalCidr, IntervalU32, IntervalU128, Ipv4Cidr, Ipv6Cidr, collapse_ipv4, collapse_ipv6,
        intervals_to_ipv4_cidrs, intervals_to_ipv6_cidrs, ipv4_to_interval, ipv6_to_interval,
        merge_intervals_u32, merge_intervals_u128, parse_ip_cidr_non_strict,
        parse_lines_non_strict, split_by_family, subtract_safelist_ipv4, subtract_safelist_ipv6,
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

    #[test]
    fn parse_non_strict_accepts_hosts_and_canonicalizes_networks() {
        let host = parse_ip_cidr_non_strict("10.0.0.1").expect("parse host");
        assert_eq!(
            host,
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000001, 32))
        );

        let cidr = parse_ip_cidr_non_strict("10.0.0.42/24").expect("parse cidr");
        assert_eq!(
            cidr,
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 24))
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
            Ipv4Cidr::from_parts(0x0a000000, 25),
            Ipv4Cidr::from_parts(0x0a000080, 25),
            Ipv4Cidr::from_parts(0x0a000000, 24),
        ]);

        assert_eq!(collapsed, vec![Ipv4Cidr::from_parts(0x0a000000, 24)]);
    }

    #[test]
    fn collapse_ipv6_merges_adjacent_networks() {
        let collapsed = collapse_ipv6(&[
            Ipv6Cidr::from_parts(0x20010db8000000000000000000000000, 65),
            Ipv6Cidr::from_parts(0x20010db8000000008000000000000000, 65),
        ]);

        assert_eq!(
            collapsed,
            vec![Ipv6Cidr::from_parts(0x20010db8000000000000000000000000, 64)]
        );
    }

    #[test]
    fn interval_conversion_is_correct_for_ipv4_and_ipv6() {
        let v4_interval = ipv4_to_interval(Ipv4Cidr::from_parts(0xc0000200, 24));
        assert_eq!(
            v4_interval,
            IntervalU32 {
                start: 0xc0000200,
                end: 0xc00002ff,
            }
        );

        let v6_interval = ipv6_to_interval(Ipv6Cidr::from_parts(
            0x20010db8000000000000000000000000,
            126,
        ));
        assert_eq!(
            v6_interval,
            IntervalU128 {
                start: 0x20010db8000000000000000000000000,
                end: 0x20010db8000000000000000000000003,
            }
        );
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
    fn safelist_subtraction_carves_ipv4_ranges() {
        let carved = subtract_safelist_ipv4(
            &[Ipv4Cidr::from_parts(0x0a000000, 24)],
            &[Ipv4Cidr::from_parts(0x0a000000, 25)],
        );

        assert_eq!(carved, vec![Ipv4Cidr::from_parts(0x0a000080, 25)]);
    }

    #[test]
    fn safelist_subtraction_carves_ipv6_ranges() {
        let carved = subtract_safelist_ipv6(
            &[Ipv6Cidr::from_parts(
                0x20010db8000000000000000000000000,
                127,
            )],
            &[Ipv6Cidr::from_parts(
                0x20010db8000000000000000000000000,
                128,
            )],
        );

        assert_eq!(
            carved,
            vec![Ipv6Cidr::from_parts(
                0x20010db8000000000000000000000001,
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
        let base = 0x20010db8000000000000000000000000_u128;
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
            start: 0x0a000002,
            end: 0x0a000005,
        }]);

        assert_eq!(
            cidrs,
            vec![
                Ipv4Cidr::from_parts(0x0a000002, 31),
                Ipv4Cidr::from_parts(0x0a000004, 31),
            ]
        );

        let cidrs_v6 = intervals_to_ipv6_cidrs(&[IntervalU128 {
            start: 0x20010db8000000000000000000000002,
            end: 0x20010db8000000000000000000000003,
        }]);
        assert_eq!(
            cidrs_v6,
            vec![Ipv6Cidr::from_parts(
                0x20010db8000000000000000000000002,
                127
            )]
        );
    }

    #[test]
    fn interval_regeneration_merges_adjacent_input_intervals() {
        let cidrs = intervals_to_ipv4_cidrs(&[
            IntervalU32 {
                start: 0x0a000000,
                end: 0x0a000000,
            },
            IntervalU32 {
                start: 0x0a000001,
                end: 0x0a000001,
            },
        ]);

        assert_eq!(cidrs, vec![Ipv4Cidr::from_parts(0x0a000000, 31)]);
    }

    #[test]
    fn interval_regeneration_sorts_unsorted_ipv6_input_intervals() {
        let base = 0x20010db8000000000000000000000000_u128;
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
