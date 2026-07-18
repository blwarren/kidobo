use crate::network::{
    CanonicalCidr, Ipv4Cidr, Ipv6Cidr, split_by_family, subtract_safelist_ipv4,
    subtract_safelist_ipv6,
};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EffectiveBlocklists {
    pub ipv4: Vec<Ipv4Cidr>,
    pub ipv6: Vec<Ipv6Cidr>,
}

pub fn compute_effective_blocklists(
    candidates: &[CanonicalCidr],
    safelist: &[CanonicalCidr],
    enable_ipv6: bool,
) -> EffectiveBlocklists {
    let candidate_family = split_by_family(candidates);
    let safelist_family = split_by_family(safelist);

    let effective_v4 = subtract_safelist_ipv4(&candidate_family.ipv4, &safelist_family.ipv4);

    let effective_v6 = if enable_ipv6 {
        subtract_safelist_ipv6(&candidate_family.ipv6, &safelist_family.ipv6)
    } else {
        Vec::new()
    };

    EffectiveBlocklists {
        ipv4: effective_v4,
        ipv6: effective_v6,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::Ipv6Addr;

    use crate::network::{
        CanonicalCidr, Ipv4Cidr, Ipv6Cidr, cidr_overlaps, ipv4_to_interval, ipv6_to_interval,
    };

    use super::{EffectiveBlocklists, compute_effective_blocklists};

    #[derive(Clone, Copy)]
    struct XorShift64 {
        state: u64,
    }

    impl XorShift64 {
        fn new(seed: u64) -> Self {
            assert_ne!(seed, 0, "seed must be non-zero");
            Self { state: seed }
        }

        fn next_u64(&mut self) -> u64 {
            let mut next = self.state;
            next ^= next << 13;
            next ^= next >> 7;
            next ^= next << 17;
            self.state = next;
            next
        }

        fn next_u32(&mut self) -> u32 {
            let bytes = self.next_u64().to_ne_bytes();
            u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        }

        fn next_u128(&mut self) -> u128 {
            (u128::from(self.next_u64()) << 64) | u128::from(self.next_u64())
        }

        fn next_usize(&mut self, upper_exclusive: usize) -> usize {
            if upper_exclusive == 0 {
                return 0;
            }

            let upper = u64::try_from(upper_exclusive).expect("usize must fit into u64");
            let reduced = self.next_u64() % upper;
            usize::try_from(reduced).expect("reduced random value must fit into usize")
        }
    }

    fn random_ipv4_cidr(rng: &mut XorShift64, min_prefix: u8) -> Ipv4Cidr {
        let span = u64::from(32_u8.saturating_sub(min_prefix)) + 1;
        let delta = u8::try_from(rng.next_u64() % span).expect("prefix delta must fit u8");
        let prefix = min_prefix + delta;
        Ipv4Cidr::from_parts(rng.next_u32(), prefix)
    }

    fn random_ipv6_cidr(rng: &mut XorShift64, min_prefix: u8) -> Ipv6Cidr {
        let span = u64::from(128_u8.saturating_sub(min_prefix)) + 1;
        let delta = u8::try_from(rng.next_u64() % span).expect("prefix delta must fit u8");
        let prefix = min_prefix + delta;
        Ipv6Cidr::from_parts(rng.next_u128(), prefix)
    }

    fn random_canonical_cidrs(
        rng: &mut XorShift64,
        count: usize,
        min_v4_prefix: u8,
        min_v6_prefix: u8,
    ) -> Vec<CanonicalCidr> {
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            if !out.is_empty() && rng.next_u64().is_multiple_of(4) {
                let idx = rng.next_usize(out.len());
                out.push(out[idx]);
                continue;
            }

            if (rng.next_u64() & 1) == 0 {
                out.push(CanonicalCidr::V4(random_ipv4_cidr(rng, min_v4_prefix)));
            } else {
                out.push(CanonicalCidr::V6(random_ipv6_cidr(rng, min_v6_prefix)));
            }
        }

        out
    }

    fn assert_disjoint_from_safelist(
        effective: &EffectiveBlocklists,
        safelist: &[CanonicalCidr],
        enable_ipv6: bool,
    ) {
        for safe in safelist {
            match safe {
                CanonicalCidr::V4(safe_v4) => {
                    for cidr in &effective.ipv4 {
                        assert!(
                            !cidr_overlaps(CanonicalCidr::V4(*cidr), CanonicalCidr::V4(*safe_v4)),
                            "effective IPv4 entry {cidr} overlaps safelist IPv4 entry {safe_v4}"
                        );
                    }
                }
                CanonicalCidr::V6(safe_v6) => {
                    if !enable_ipv6 {
                        continue;
                    }

                    for cidr in &effective.ipv6 {
                        assert!(
                            !cidr_overlaps(CanonicalCidr::V6(*cidr), CanonicalCidr::V6(*safe_v6)),
                            "effective IPv6 entry {cidr} overlaps safelist IPv6 entry {safe_v6}"
                        );
                    }
                }
            }
        }
    }

    fn expand_ipv4(cidrs: &[Ipv4Cidr]) -> BTreeSet<u32> {
        let mut expanded = BTreeSet::new();
        for cidr in cidrs {
            let interval = ipv4_to_interval(*cidr);
            for ip in interval.start..=interval.end {
                expanded.insert(ip);
            }
        }
        expanded
    }

    fn expand_ipv6(cidrs: &[Ipv6Cidr]) -> BTreeSet<u128> {
        let mut expanded = BTreeSet::new();
        for cidr in cidrs {
            let interval = ipv6_to_interval(*cidr);
            let mut ip = interval.start;
            loop {
                expanded.insert(ip);
                if ip == interval.end {
                    break;
                }
                ip += 1;
            }
        }
        expanded
    }

    fn assert_ipv4_coverage_exact(cidrs: &[Ipv4Cidr], expected_start: u32, expected_end: u32) {
        let mut intervals = cidrs
            .iter()
            .copied()
            .map(ipv4_to_interval)
            .collect::<Vec<_>>();
        intervals.sort_unstable();

        let mut next_start = expected_start;
        for (idx, interval) in intervals.iter().enumerate() {
            assert_eq!(
                interval.start, next_start,
                "IPv4 coverage has a gap or overlap before interval {interval:?}"
            );
            assert!(
                interval.end <= expected_end,
                "IPv4 coverage extends beyond expected end: {interval:?}"
            );

            if interval.end == expected_end {
                assert_eq!(
                    idx + 1,
                    intervals.len(),
                    "IPv4 coverage has extra intervals after expected end"
                );
                return;
            }

            next_start = interval
                .end
                .checked_add(1)
                .expect("IPv4 interval end should not overflow before expected end");
        }

        panic!("IPv4 coverage ended before expected range {expected_start}..={expected_end}");
    }

    fn assert_ipv6_coverage_exact(cidrs: &[Ipv6Cidr], expected_start: u128, expected_end: u128) {
        let mut intervals = cidrs
            .iter()
            .copied()
            .map(ipv6_to_interval)
            .collect::<Vec<_>>();
        intervals.sort_unstable();

        let mut next_start = expected_start;
        for (idx, interval) in intervals.iter().enumerate() {
            assert_eq!(
                interval.start, next_start,
                "IPv6 coverage has a gap or overlap before interval {interval:?}"
            );
            assert!(
                interval.end <= expected_end,
                "IPv6 coverage extends beyond expected end: {interval:?}"
            );

            if interval.end == expected_end {
                assert_eq!(
                    idx + 1,
                    intervals.len(),
                    "IPv6 coverage has extra intervals after expected end"
                );
                return;
            }

            next_start = interval
                .end
                .checked_add(1)
                .expect("IPv6 interval end should not overflow before expected end");
        }

        panic!("IPv6 coverage ended before expected range {expected_start}..={expected_end}");
    }

    #[test]
    fn pipeline_collapses_and_carves_per_family() {
        let candidates = vec![
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 25)),
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000080, 25)),
            CanonicalCidr::V6(Ipv6Cidr::from_parts(0x20010db8000000000000000000000000, 64)),
        ];
        let safelist = vec![
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 25)),
            CanonicalCidr::V6(Ipv6Cidr::from_parts(0x20010db8000000000000000000000000, 65)),
        ];

        let effective = compute_effective_blocklists(&candidates, &safelist, true);

        assert_eq!(
            effective.ipv4,
            vec![Ipv4Cidr::from_parts(0x0a000080, 25)],
            "collapsed /24 should be carved by /25 safelist"
        );
        assert_eq!(
            effective.ipv6,
            vec![
                Ipv6Cidr::new(
                    "2001:db8:0:0:8000::"
                        .parse::<Ipv6Addr>()
                        .expect("valid ipv6"),
                    65
                )
                .expect("valid cidr")
            ],
            "v6 /64 should be carved by /65 safelist"
        );
    }

    #[test]
    fn ipv6_disable_drops_ipv6_output() {
        let candidates = vec![CanonicalCidr::V6(Ipv6Cidr::from_parts(
            0x20010db8000000000000000000000000,
            64,
        ))];

        let effective = compute_effective_blocklists(&candidates, &[], false);
        assert!(effective.ipv6.is_empty());
    }

    #[test]
    fn full_address_space_inputs_still_exclude_safelist_endpoints() {
        let candidates = vec![
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0, 0)),
            CanonicalCidr::V6(Ipv6Cidr::from_parts(0, 0)),
        ];
        let safelist = vec![
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0, 32)),
            CanonicalCidr::V4(Ipv4Cidr::from_parts(u32::MAX, 32)),
            CanonicalCidr::V6(Ipv6Cidr::from_parts(0, 128)),
            CanonicalCidr::V6(Ipv6Cidr::from_parts(u128::MAX, 128)),
        ];

        let effective = compute_effective_blocklists(&candidates, &safelist, true);

        assert_ipv4_coverage_exact(&effective.ipv4, 1, u32::MAX - 1);
        assert_ipv6_coverage_exact(&effective.ipv6, 1, u128::MAX - 1);
        assert_disjoint_from_safelist(&effective, &safelist, true);
    }

    #[test]
    fn safelist_covering_disjoint_candidate_slices_removes_all_overlaps() {
        let candidates = vec![
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 26)),
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000080, 26)),
            CanonicalCidr::V6(Ipv6Cidr::from_parts(
                0x20010db8000000000000000000000000,
                124,
            )),
            CanonicalCidr::V6(Ipv6Cidr::from_parts(
                0x20010db8000000000000000000000010,
                124,
            )),
        ];
        let safelist = vec![
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 24)),
            CanonicalCidr::V6(Ipv6Cidr::from_parts(
                0x20010db8000000000000000000000000,
                120,
            )),
        ];

        let effective = compute_effective_blocklists(&candidates, &safelist, true);
        assert!(effective.ipv4.is_empty());
        assert!(effective.ipv6.is_empty());
    }

    #[test]
    fn subtraction_applies_all_safelist_entries_per_family() {
        let v6_base = 0x20010db8000000000000000000000000_u128;
        let candidates = vec![
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 24)),
            CanonicalCidr::V6(Ipv6Cidr::from_parts(v6_base, 120)),
        ];
        let safelist = vec![
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 25)),
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000080, 26)),
            CanonicalCidr::V6(Ipv6Cidr::from_parts(v6_base, 121)),
            CanonicalCidr::V6(Ipv6Cidr::from_parts(v6_base + 0x80, 122)),
        ];

        let effective = compute_effective_blocklists(&candidates, &safelist, true);

        assert_eq!(effective.ipv4, vec![Ipv4Cidr::from_parts(0x0a0000c0, 26)]);
        assert_eq!(
            effective.ipv6,
            vec![Ipv6Cidr::from_parts(v6_base + 0xc0, 122)]
        );
    }

    #[test]
    fn subtraction_carves_each_candidate_interval_not_just_first_overlap() {
        let v6_base = 0x20010db8000000000000000000000000_u128;
        let candidates = vec![
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 25)),
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000100, 24)),
            CanonicalCidr::V6(Ipv6Cidr::from_parts(v6_base, 127)),
            CanonicalCidr::V6(Ipv6Cidr::from_parts(v6_base + 4, 126)),
        ];
        let safelist = vec![
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000100, 25)),
            CanonicalCidr::V6(Ipv6Cidr::from_parts(v6_base + 4, 127)),
        ];

        let effective = compute_effective_blocklists(&candidates, &safelist, true);

        assert_eq!(
            effective.ipv4,
            vec![
                Ipv4Cidr::from_parts(0x0a000000, 25),
                Ipv4Cidr::from_parts(0x0a000180, 25),
            ]
        );
        assert_eq!(
            effective.ipv6,
            vec![
                Ipv6Cidr::from_parts(v6_base, 127),
                Ipv6Cidr::from_parts(v6_base + 6, 127),
            ]
        );
    }

    #[test]
    fn subtraction_respects_safelist_supernets() {
        let v6_base = 0x20010db8000000000000000000000000_u128;
        let candidates = vec![
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000080, 25)),
            CanonicalCidr::V6(Ipv6Cidr::from_parts(v6_base + 0x80, 121)),
        ];
        let safelist = vec![
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 24)),
            CanonicalCidr::V6(Ipv6Cidr::from_parts(v6_base, 120)),
        ];

        let effective = compute_effective_blocklists(&candidates, &safelist, true);
        assert!(effective.ipv4.is_empty());
        assert!(effective.ipv6.is_empty());
    }

    #[test]
    fn subtraction_preserves_no_safelisted_endpoint_addresses() {
        let v6_base = 0x20010db8000000000000000000000000_u128;
        let candidates = vec![
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 31)),
            CanonicalCidr::V6(Ipv6Cidr::from_parts(v6_base, 127)),
        ];
        let safelist = vec![
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000001, 32)),
            CanonicalCidr::V6(Ipv6Cidr::from_parts(v6_base + 1, 128)),
        ];

        let effective = compute_effective_blocklists(&candidates, &safelist, true);

        assert_eq!(effective.ipv4, vec![Ipv4Cidr::from_parts(0x0a000000, 32)]);
        assert_eq!(effective.ipv6, vec![Ipv6Cidr::from_parts(v6_base, 128)]);
    }

    #[test]
    fn subtraction_handles_unsorted_safelist_ranges() {
        let v6_base = 0x20010db8000000000000000000000000_u128;
        let candidates = vec![
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 24)),
            CanonicalCidr::V6(Ipv6Cidr::from_parts(v6_base, 120)),
        ];
        let safelist = vec![
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000080, 25)),
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 25)),
            CanonicalCidr::V6(Ipv6Cidr::from_parts(v6_base + 0x80, 121)),
            CanonicalCidr::V6(Ipv6Cidr::from_parts(v6_base, 121)),
        ];

        let effective = compute_effective_blocklists(&candidates, &safelist, true);
        assert!(effective.ipv4.is_empty());
        assert!(effective.ipv6.is_empty());
    }

    #[test]
    fn randomized_mixed_family_inputs_never_overlap_safelist() {
        let mut rng = XorShift64::new(0x5f37_59df_5eed_c0de);

        for _ in 0..600 {
            let candidate_count = 1 + rng.next_usize(24);
            let safelist_count = rng.next_usize(24);
            let candidates = random_canonical_cidrs(&mut rng, candidate_count, 0, 0);
            let safelist = random_canonical_cidrs(&mut rng, safelist_count, 0, 0);

            let effective = compute_effective_blocklists(&candidates, &safelist, true);
            assert_disjoint_from_safelist(&effective, &safelist, true);

            let effective_ipv4_only = compute_effective_blocklists(&candidates, &safelist, false);
            assert!(effective_ipv4_only.ipv6.is_empty());
            assert_disjoint_from_safelist(&effective_ipv4_only, &safelist, false);
        }
    }

    #[test]
    fn randomized_ipv4_narrow_prefix_matches_bruteforce_model() {
        let mut rng = XorShift64::new(0x1234_5678_9abc_def0);

        for _ in 0..400 {
            let candidate_count = 1 + rng.next_usize(12);
            let safelist_count = rng.next_usize(12);
            let mut candidates = Vec::with_capacity(candidate_count);
            let mut safelist = Vec::with_capacity(safelist_count);

            for _ in 0..candidate_count {
                candidates.push(random_ipv4_cidr(&mut rng, 29));
            }
            for _ in 0..safelist_count {
                safelist.push(random_ipv4_cidr(&mut rng, 29));
            }

            let candidate_canonical = candidates
                .iter()
                .copied()
                .map(CanonicalCidr::V4)
                .collect::<Vec<_>>();
            let safelist_canonical = safelist
                .iter()
                .copied()
                .map(CanonicalCidr::V4)
                .collect::<Vec<_>>();

            let effective =
                compute_effective_blocklists(&candidate_canonical, &safelist_canonical, true);
            assert_disjoint_from_safelist(&effective, &safelist_canonical, true);

            let mut expected = expand_ipv4(&candidates);
            for safe_ip in expand_ipv4(&safelist) {
                expected.remove(&safe_ip);
            }
            let actual = expand_ipv4(&effective.ipv4);

            assert_eq!(
                actual, expected,
                "effective IPv4 set must equal candidate-safelist"
            );
        }
    }

    #[test]
    fn randomized_ipv6_narrow_prefix_matches_bruteforce_model() {
        let mut rng = XorShift64::new(0x0fed_cba9_8765_4321);

        for _ in 0..250 {
            let candidate_count = 1 + rng.next_usize(8);
            let safelist_count = rng.next_usize(8);
            let mut candidates = Vec::with_capacity(candidate_count);
            let mut safelist = Vec::with_capacity(safelist_count);

            for _ in 0..candidate_count {
                candidates.push(random_ipv6_cidr(&mut rng, 126));
            }
            for _ in 0..safelist_count {
                safelist.push(random_ipv6_cidr(&mut rng, 126));
            }

            let candidate_canonical = candidates
                .iter()
                .copied()
                .map(CanonicalCidr::V6)
                .collect::<Vec<_>>();
            let safelist_canonical = safelist
                .iter()
                .copied()
                .map(CanonicalCidr::V6)
                .collect::<Vec<_>>();

            let effective =
                compute_effective_blocklists(&candidate_canonical, &safelist_canonical, true);
            assert_disjoint_from_safelist(&effective, &safelist_canonical, true);

            let mut expected = expand_ipv6(&candidates);
            for safe_ip in expand_ipv6(&safelist) {
                expected.remove(&safe_ip);
            }
            let actual = expand_ipv6(&effective.ipv6);

            assert_eq!(
                actual, expected,
                "effective IPv6 set must equal candidate-safelist"
            );
        }
    }
}
