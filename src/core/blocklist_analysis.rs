use crate::core::network::{
    FamilyCidrs, IntervalU32, IntervalU128, Ipv4Cidr, Ipv6Cidr, collapse_ipv4, collapse_ipv6,
    ipv4_to_interval, ipv6_to_interval, split_by_family, subtract_safelist_ipv4,
    subtract_safelist_ipv6,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FamilyOverlapCount {
    pub overlapping: usize,
    pub fully_covered: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OverlapCount {
    pub ipv4: FamilyOverlapCount,
    pub ipv6: FamilyOverlapCount,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FamilyReduction {
    pub ipv4: Vec<Ipv4Cidr>,
    pub ipv6: Vec<Ipv6Cidr>,
}

pub fn collapse_by_family(cidrs: &[crate::core::network::CanonicalCidr]) -> FamilyCidrs {
    let separated = split_by_family(cidrs);
    FamilyCidrs {
        ipv4: collapse_ipv4(&separated.ipv4),
        ipv6: collapse_ipv6(&separated.ipv6),
    }
}

pub fn overlap_counts(local: &FamilyCidrs, remote: &FamilyCidrs) -> OverlapCount {
    OverlapCount {
        ipv4: overlap_count_ipv4(&local.ipv4, &remote.ipv4),
        ipv6: overlap_count_ipv6(&local.ipv6, &remote.ipv6),
    }
}

pub fn subtract_remote_from_local(local: &FamilyCidrs, remote: &FamilyCidrs) -> FamilyReduction {
    FamilyReduction {
        ipv4: subtract_safelist_ipv4(&local.ipv4, &remote.ipv4),
        ipv6: subtract_safelist_ipv6(&local.ipv6, &remote.ipv6),
    }
}

pub fn fully_covered_local(local: &FamilyCidrs, remote: &FamilyCidrs) -> FamilyReduction {
    FamilyReduction {
        ipv4: fully_covered_ipv4(&local.ipv4, &remote.ipv4),
        ipv6: fully_covered_ipv6(&local.ipv6, &remote.ipv6),
    }
}

fn overlap_count_ipv4(local: &[Ipv4Cidr], remote: &[Ipv4Cidr]) -> FamilyOverlapCount {
    let overlapping = count_overlapping_ipv4(local, remote);
    let fully_covered = fully_covered_ipv4(local, remote).len();
    FamilyOverlapCount {
        overlapping,
        fully_covered,
    }
}

fn overlap_count_ipv6(local: &[Ipv6Cidr], remote: &[Ipv6Cidr]) -> FamilyOverlapCount {
    let overlapping = count_overlapping_ipv6(local, remote);
    let fully_covered = fully_covered_ipv6(local, remote).len();
    FamilyOverlapCount {
        overlapping,
        fully_covered,
    }
}

fn count_overlapping_ipv4(local: &[Ipv4Cidr], remote: &[Ipv4Cidr]) -> usize {
    if local.is_empty() || remote.is_empty() {
        return 0;
    }

    let mut local_intervals = local
        .iter()
        .copied()
        .map(ipv4_to_interval)
        .collect::<Vec<_>>();
    let mut remote_intervals = remote
        .iter()
        .copied()
        .map(ipv4_to_interval)
        .collect::<Vec<_>>();
    local_intervals.sort_unstable();
    remote_intervals.sort_unstable();
    count_overlapping_intervals_u32(&local_intervals, &remote_intervals)
}

fn count_overlapping_ipv6(local: &[Ipv6Cidr], remote: &[Ipv6Cidr]) -> usize {
    if local.is_empty() || remote.is_empty() {
        return 0;
    }

    let mut local_intervals = local
        .iter()
        .copied()
        .map(ipv6_to_interval)
        .collect::<Vec<_>>();
    let mut remote_intervals = remote
        .iter()
        .copied()
        .map(ipv6_to_interval)
        .collect::<Vec<_>>();
    local_intervals.sort_unstable();
    remote_intervals.sort_unstable();
    count_overlapping_intervals_u128(&local_intervals, &remote_intervals)
}

fn count_overlapping_intervals_u32(local: &[IntervalU32], remote: &[IntervalU32]) -> usize {
    let mut overlap_count = 0_usize;
    let mut remote_idx = 0_usize;

    for local_interval in local {
        while remote
            .get(remote_idx)
            .is_some_and(|interval| interval.end < local_interval.start)
        {
            remote_idx += 1;
        }

        if remote
            .get(remote_idx)
            .is_some_and(|interval| interval.start <= local_interval.end)
        {
            overlap_count += 1;
        }
    }

    overlap_count
}

fn count_overlapping_intervals_u128(local: &[IntervalU128], remote: &[IntervalU128]) -> usize {
    let mut overlap_count = 0_usize;
    let mut remote_idx = 0_usize;

    for local_interval in local {
        while remote
            .get(remote_idx)
            .is_some_and(|interval| interval.end < local_interval.start)
        {
            remote_idx += 1;
        }

        if remote
            .get(remote_idx)
            .is_some_and(|interval| interval.start <= local_interval.end)
        {
            overlap_count += 1;
        }
    }

    overlap_count
}

fn fully_covered_ipv4(local: &[Ipv4Cidr], remote: &[Ipv4Cidr]) -> Vec<Ipv4Cidr> {
    if local.is_empty() || remote.is_empty() {
        return Vec::new();
    }

    let mut remote_intervals = remote
        .iter()
        .copied()
        .map(ipv4_to_interval)
        .collect::<Vec<_>>();
    remote_intervals.sort_unstable();
    local
        .iter()
        .copied()
        .filter(|cidr| is_interval_covered_u32(ipv4_to_interval(*cidr), &remote_intervals))
        .collect()
}

fn fully_covered_ipv6(local: &[Ipv6Cidr], remote: &[Ipv6Cidr]) -> Vec<Ipv6Cidr> {
    if local.is_empty() || remote.is_empty() {
        return Vec::new();
    }

    let mut remote_intervals = remote
        .iter()
        .copied()
        .map(ipv6_to_interval)
        .collect::<Vec<_>>();
    remote_intervals.sort_unstable();
    local
        .iter()
        .copied()
        .filter(|cidr| is_interval_covered_u128(ipv6_to_interval(*cidr), &remote_intervals))
        .collect()
}

fn is_interval_covered_u32(target: IntervalU32, remote: &[IntervalU32]) -> bool {
    let mut idx = remote.partition_point(|entry| entry.end < target.start);
    let mut covered_until = target.start;

    while let Some(entry) = remote.get(idx) {
        if entry.start > covered_until {
            return false;
        }

        if entry.end >= target.end {
            return true;
        }

        covered_until = entry.end.saturating_add(1);
        idx += 1;
    }

    false
}

fn is_interval_covered_u128(target: IntervalU128, remote: &[IntervalU128]) -> bool {
    let mut idx = remote.partition_point(|entry| entry.end < target.start);
    let mut covered_until = target.start;

    while let Some(entry) = remote.get(idx) {
        if entry.start > covered_until {
            return false;
        }

        if entry.end >= target.end {
            return true;
        }

        covered_until = entry.end.saturating_add(1);
        idx += 1;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::{
        collapse_by_family, fully_covered_local, overlap_counts, subtract_remote_from_local,
    };
    use crate::core::network::{CanonicalCidr, Ipv4Cidr, Ipv6Cidr};

    #[test]
    fn overlap_counts_reports_overlapping_and_fully_covered() {
        let local = collapse_by_family(&[
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 24)),
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0b000000, 24)),
            CanonicalCidr::V6(Ipv6Cidr::from_parts(0x20010db8000000000000000000000000, 64)),
        ]);
        let remote = collapse_by_family(&[
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 25)),
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000080, 25)),
            CanonicalCidr::V6(Ipv6Cidr::from_parts(0x20010db8000000000000000000000000, 65)),
        ]);

        let overlap = overlap_counts(&local, &remote);
        assert_eq!(overlap.ipv4.overlapping, 1);
        assert_eq!(overlap.ipv4.fully_covered, 1);
        assert_eq!(overlap.ipv6.overlapping, 1);
        assert_eq!(overlap.ipv6.fully_covered, 0);
    }

    #[test]
    fn fully_covered_and_reduced_local_are_deterministic() {
        let local = collapse_by_family(&[
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 24)),
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0b000000, 24)),
            CanonicalCidr::V6(Ipv6Cidr::from_parts(0x20010db8000000000000000000000000, 64)),
        ]);
        let remote = collapse_by_family(&[
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 24)),
            CanonicalCidr::V6(Ipv6Cidr::from_parts(0x20010db8000000000000000000000000, 65)),
        ]);

        let covered = fully_covered_local(&local, &remote);
        assert_eq!(covered.ipv4, vec![Ipv4Cidr::from_parts(0x0a000000, 24)]);
        assert!(covered.ipv6.is_empty());

        let reduced = subtract_remote_from_local(&local, &remote);
        assert_eq!(reduced.ipv4, vec![Ipv4Cidr::from_parts(0x0b000000, 24)]);
        assert_eq!(
            reduced.ipv6,
            vec![Ipv6Cidr::from_parts(0x20010db8000000008000000000000000, 65)]
        );
    }

    #[test]
    fn fully_covered_local_reports_ipv6_when_fully_covered() {
        let local = collapse_by_family(&[CanonicalCidr::V6(Ipv6Cidr::from_parts(
            0x20010db8000000000000000000000000,
            64,
        ))]);
        let remote = collapse_by_family(&[CanonicalCidr::V6(Ipv6Cidr::from_parts(
            0x20010db8000000000000000000000000,
            64,
        ))]);

        let covered = fully_covered_local(&local, &remote);
        assert_eq!(
            covered.ipv6,
            vec![Ipv6Cidr::from_parts(0x20010db8000000000000000000000000, 64)]
        );
    }

    #[test]
    fn overlap_counts_counts_each_overlapping_local_entry() {
        let local = collapse_by_family(&[
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 26)),
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000080, 26)),
        ]);
        let remote = collapse_by_family(&[CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 24))]);

        let overlap = overlap_counts(&local, &remote);
        assert_eq!(overlap.ipv4.overlapping, 2);
        assert_eq!(overlap.ipv4.fully_covered, 2);
    }

    #[test]
    fn overlap_counts_treats_exact_host_match_as_overlap() {
        let local = collapse_by_family(&[CanonicalCidr::V4(Ipv4Cidr::from_parts(0xcb007107, 32))]);
        let remote = collapse_by_family(&[CanonicalCidr::V4(Ipv4Cidr::from_parts(0xcb007107, 32))]);

        let overlap = overlap_counts(&local, &remote);
        assert_eq!(overlap.ipv4.overlapping, 1);
        assert_eq!(overlap.ipv4.fully_covered, 1);
    }

    #[test]
    fn overlap_counts_each_ipv6_local_covered_by_one_supernet() {
        let base = 0x20010db8000000000000000000000000_u128;
        let local = collapse_by_family(&[
            CanonicalCidr::V6(Ipv6Cidr::from_parts(base, 66)),
            CanonicalCidr::V6(Ipv6Cidr::from_parts(base + (1_u128 << 63), 66)),
        ]);
        let remote = collapse_by_family(&[CanonicalCidr::V6(Ipv6Cidr::from_parts(base, 64))]);

        let overlap = overlap_counts(&local, &remote);
        assert_eq!(overlap.ipv6.overlapping, 2);
        assert_eq!(overlap.ipv6.fully_covered, 2);
    }

    #[test]
    fn ipv6_coverage_skips_disjoint_remote_before_covering_entry() {
        let target = 0x20010db8000000000000000000000000_u128;
        let local = collapse_by_family(&[CanonicalCidr::V6(Ipv6Cidr::from_parts(target, 64))]);
        let remote = collapse_by_family(&[
            CanonicalCidr::V6(Ipv6Cidr::from_parts(0x20010db7000000000000000000000000, 64)),
            CanonicalCidr::V6(Ipv6Cidr::from_parts(target, 64)),
        ]);

        let overlap = overlap_counts(&local, &remote);
        assert_eq!(overlap.ipv6.overlapping, 1);
        assert_eq!(overlap.ipv6.fully_covered, 1);
    }
}
