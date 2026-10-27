//! Temporary ban identities, deadlines, and versioned operator-managed state.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::Deserialize;
use thiserror::Error;
use toml_edit::{ArrayOfTables, DocumentMut, Item, Table, value};

use crate::network::{CanonicalCidr, parse_ip_cidr_strict};

/// Empty version-one temporary-ban state, suitable for initialization.
pub const DEFAULT_TEMPORARY_BANS_TEMPLATE: &str = "version = 1\n";

/// A validated positive duration expressed in whole hours or days.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BanDuration {
    seconds: u64,
}

impl BanDuration {
    /// Returns the duration in elapsed seconds.
    #[must_use]
    pub fn seconds(self) -> u64 {
        self.seconds
    }

    /// Computes an absolute expiry representable in the persistent state format.
    ///
    /// # Errors
    ///
    /// Returns an error if the deadline exceeds the positive signed 64-bit range.
    pub fn expires_at(self, now: u64) -> Result<u64, TemporaryBanError> {
        let deadline = now
            .checked_add(self.seconds)
            .ok_or(TemporaryBanError::InvalidExpiry)?;
        validate_expiry(deadline)?;
        Ok(deadline)
    }
}

impl FromStr for BanDuration {
    type Err = TemporaryBanError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let input = input.trim();
        let (digits, multiplier) = if let Some(digits) = input.strip_suffix(['h', 'H']) {
            (digits, 3600)
        } else if let Some(digits) = input.strip_suffix(['d', 'D']) {
            (digits, 86400)
        } else {
            return Err(TemporaryBanError::InvalidDuration);
        };
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(TemporaryBanError::InvalidDuration);
        }
        let seconds = digits
            .parse::<u64>()
            .ok()
            .and_then(|amount| amount.checked_mul(multiplier))
            .filter(|seconds| *seconds > 0 && i64::try_from(*seconds).is_ok())
            .ok_or(TemporaryBanError::InvalidDuration)?;
        Ok(Self { seconds })
    }
}

impl fmt::Display for BanDuration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.seconds.is_multiple_of(86400) {
            write!(formatter, "{}d", self.seconds / 86400)
        } else {
            write!(formatter, "{}h", self.seconds / 3600)
        }
    }
}

/// Persistent identities and absolute Unix deadlines, without network collapse.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TemporaryBans {
    /// Canonical IP/CIDR identities and their expiry timestamps.
    pub ips: BTreeMap<CanonicalCidr, u64>,
    /// Normalized positive ASN identities and their expiry timestamps.
    pub asns: BTreeMap<u32, u64>,
}

impl TemporaryBans {
    /// Returns IP/CIDR entries whose deadlines are strictly later than the cutoff.
    #[must_use]
    pub fn active_ips(&self, cutoff: u64) -> Vec<CanonicalCidr> {
        self.ips
            .iter()
            .filter_map(|(target, expiry)| (*expiry > cutoff).then_some(*target))
            .collect()
    }

    /// Returns ASN entries whose deadlines are strictly later than the cutoff.
    #[must_use]
    pub fn active_asns(&self, cutoff: u64) -> Vec<u32> {
        self.asns
            .iter()
            .filter_map(|(target, expiry)| (*expiry > cutoff).then_some(*target))
            .collect()
    }

    /// Removes expired entries, returning whether any record was removed.
    pub fn prune_expired(&mut self, cutoff: u64) -> bool {
        let previous = (self.ips.len(), self.asns.len());
        self.ips.retain(|_, expiry| *expiry > cutoff);
        self.asns.retain(|_, expiry| *expiry > cutoff);
        previous != (self.ips.len(), self.asns.len())
    }
}

/// Invalid duration, deadline, or persistent temporary-ban state.
#[derive(Debug, Error)]
pub enum TemporaryBanError {
    /// Duration syntax or arithmetic is invalid.
    #[error("duration must be a positive whole number of hours or days (for example, 12h or 7d)")]
    InvalidDuration,
    /// A deadline is zero or outside the format's signed 64-bit range.
    #[error(
        "temporary ban expiry must be a positive Unix timestamp within the signed 64-bit range"
    )]
    InvalidExpiry,
    /// Persistent state violates its schema or identity constraints.
    #[error("invalid temporary ban state: {reason}")]
    InvalidState {
        /// Actionable validation diagnostic.
        reason: String,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredBans {
    version: u32,
    #[serde(default)]
    ips: Vec<StoredIp>,
    #[serde(default)]
    asns: Vec<StoredAsn>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredIp {
    cidr: String,
    expires_at: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredAsn {
    asn: u32,
    expires_at: u64,
}

/// Parses versioned state and rejects malformed or duplicate canonical identities.
///
/// # Errors
///
/// Returns an error for unsupported versions, invalid records, or unknown fields.
pub fn parse_temporary_bans(contents: &str) -> Result<TemporaryBans, TemporaryBanError> {
    let stored: StoredBans =
        toml_edit::de::from_str(contents).map_err(|error| TemporaryBanError::InvalidState {
            reason: error.to_string(),
        })?;
    if stored.version != 1 {
        return Err(TemporaryBanError::InvalidState {
            reason: format!("unsupported version {}", stored.version),
        });
    }
    let mut state = TemporaryBans::default();
    for record in stored.ips {
        validate_expiry(record.expires_at)?;
        let target =
            parse_ip_cidr_strict(&record.cidr).ok_or_else(|| TemporaryBanError::InvalidState {
                reason: format!("invalid IP/CIDR identity {:?}", record.cidr),
            })?;
        if state.ips.insert(target, record.expires_at).is_some() {
            return Err(TemporaryBanError::InvalidState {
                reason: format!("duplicate IP/CIDR identity {target}"),
            });
        }
    }
    for record in stored.asns {
        validate_expiry(record.expires_at)?;
        validate_asn(record.asn)?;
        if state.asns.insert(record.asn, record.expires_at).is_some() {
            return Err(TemporaryBanError::InvalidState {
                reason: format!("duplicate ASN identity AS{}", record.asn),
            });
        }
    }
    Ok(state)
}

/// Renders deterministic version-one TOML while validating all stored values.
///
/// # Errors
///
/// Returns an error for invalid deadlines or zero ASN identities.
pub fn serialize_temporary_bans(state: &TemporaryBans) -> Result<String, TemporaryBanError> {
    let mut document = DocumentMut::new();
    document.insert("version", value(1));
    if !state.ips.is_empty() {
        let mut records = ArrayOfTables::new();
        for (cidr, expiry) in &state.ips {
            let mut record = Table::new();
            record.insert("cidr", value(cidr.to_string()));
            record.insert("expires_at", value(validate_expiry(*expiry)?));
            records.push(record);
        }
        document.insert("ips", Item::ArrayOfTables(records));
    }
    if !state.asns.is_empty() {
        let mut records = ArrayOfTables::new();
        for (asn, expiry) in &state.asns {
            validate_asn(*asn)?;
            let mut record = Table::new();
            record.insert("asn", value(i64::from(*asn)));
            record.insert("expires_at", value(validate_expiry(*expiry)?));
            records.push(record);
        }
        document.insert("asns", Item::ArrayOfTables(records));
    }
    Ok(document.to_string())
}

fn validate_expiry(expiry: u64) -> Result<i64, TemporaryBanError> {
    i64::try_from(expiry)
        .ok()
        .filter(|expiry| *expiry > 0)
        .ok_or(TemporaryBanError::InvalidExpiry)
}

fn validate_asn(asn: u32) -> Result<(), TemporaryBanError> {
    if asn == 0 {
        return Err(TemporaryBanError::InvalidState {
            reason: "ASN identity must be positive".to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_accepts_only_positive_whole_hours_and_days() {
        for (input, seconds, displayed) in [
            ("1h", 3600, "1h"),
            (" 12H ", 43200, "12h"),
            ("3D", 259_200, "3d"),
            ("024h", 86400, "1d"),
        ] {
            let duration = input.parse::<BanDuration>().expect(input);
            assert_eq!(duration.seconds(), seconds);
            assert_eq!(duration.to_string(), displayed);
            assert_eq!(duration.expires_at(100).expect("deadline"), 100 + seconds);
        }
        for input in [
            "",
            "1",
            "h",
            "0h",
            "0d",
            "-1h",
            "+1h",
            "1.5h",
            "1d2h",
            "1 h",
            "1h trailing",
            "１h",
            "18446744073709551616h",
            "2562047788015216h",
        ] {
            assert!(input.parse::<BanDuration>().is_err(), "accepted {input:?}");
        }
    }

    #[test]
    fn duration_deadlines_check_both_integer_and_format_overflow() {
        let duration = "1h".parse::<BanDuration>().expect("duration");
        let maximum = u64::try_from(i64::MAX).expect("maximum");
        assert_eq!(
            duration.expires_at(maximum - 3600).expect("boundary"),
            maximum
        );
        assert!(matches!(
            duration.expires_at(maximum - 3599),
            Err(TemporaryBanError::InvalidExpiry)
        ));
        assert!(matches!(
            duration.expires_at(u64::MAX),
            Err(TemporaryBanError::InvalidExpiry)
        ));
    }

    #[test]
    fn state_normalizes_and_preserves_independent_networks_and_deadlines() {
        let state = parse_temporary_bans(
            "version = 1\n\
             [[ips]]\ncidr = '203.0.113.7/24'\nexpires_at = 100\n\
             [[ips]]\ncidr = '203.0.113.7'\nexpires_at = 101\n\
             [[ips]]\ncidr = '2001:DB8::7/48'\nexpires_at = 102\n\
             [[asns]]\nasn = 64496\nexpires_at = 100\n\
             [[asns]]\nasn = 64497\nexpires_at = 102\n",
        )
        .expect("state");
        let subnet = parse_ip_cidr_strict("203.0.113.0/24").expect("subnet");
        let host = parse_ip_cidr_strict("203.0.113.7").expect("host");
        let v6 = parse_ip_cidr_strict("2001:db8::/48").expect("IPv6 subnet");
        assert_eq!(
            state,
            TemporaryBans {
                ips: [(subnet, 100), (host, 101), (v6, 102)].into(),
                asns: [(64496, 100), (64497, 102)].into(),
            }
        );
        assert_eq!(state.active_ips(99), [subnet, host, v6]);
        assert_eq!(state.active_ips(100), [host, v6]);
        assert_eq!(state.active_ips(102), []);
        assert_eq!(state.active_asns(99), [64496, 64497]);
        assert_eq!(state.active_asns(100), [64497]);
        let rendered = serialize_temporary_bans(&state).expect("serialize");
        assert!(rendered.contains("203.0.113.0/24"));
        assert!(rendered.contains("2001:db8::/48"));
        assert_eq!(parse_temporary_bans(&rendered).expect("roundtrip"), state);
        let mut pruned = state.clone();
        assert!(!pruned.prune_expired(99));
        assert_eq!(pruned, state);
        assert!(pruned.prune_expired(100));
        assert_eq!(
            pruned,
            TemporaryBans {
                ips: [(host, 101), (v6, 102)].into(),
                asns: [(64497, 102)].into(),
            }
        );
        assert!(!pruned.prune_expired(100));
        assert!(pruned.prune_expired(102));
        assert_eq!(pruned, TemporaryBans::default());
    }

    #[test]
    fn state_rejects_malformed_unknown_and_duplicate_records() {
        for contents in [
            "",
            "version = 2",
            "version = 1\nunknown = 0",
            "version = 1\nips = 0",
            "version = 1\n[[ips]]\ncidr = 'invalid'\nexpires_at = 1",
            "version = 1\n[[ips]]\ncidr = '203.0.113.7 extra'\nexpires_at = 1",
            "version = 1\n[[ips]]\ncidr = '203.0.113.7'\nexpires_at = 1\nunknown = 0",
            "version = 1\n[[ips]]\ncidr = '203.0.113.7'",
            "version = 1\n[[ips]]\ncidr = '203.0.113.7'\nexpires_at = 0",
            "version = 1\n[[asns]]\nasn = 0\nexpires_at = 1",
            "version = 1\n[[asns]]\nasn = 4294967296\nexpires_at = 1",
            "version = 1\n[[asns]]\nasn = 1\nexpires_at = -1",
            "version = 1\n[[asns]]\nasn = 1\nexpires_at = 9223372036854775808",
            "version = 1\n[[ips]]\ncidr = '203.0.113.7'\nexpires_at = 1\n[[ips]]\ncidr = '203.0.113.7/32'\nexpires_at = 2",
            "version = 1\n[[ips]]\ncidr = '203.0.113.7/24'\nexpires_at = 1\n[[ips]]\ncidr = '203.0.113.0/24'\nexpires_at = 2",
            "version = 1\n[[asns]]\nasn = 64496\nexpires_at = 1\n[[asns]]\nasn = 64496\nexpires_at = 2",
        ] {
            assert!(
                parse_temporary_bans(contents).is_err(),
                "accepted {contents:?}"
            );
        }
    }

    #[test]
    fn serialization_validates_values_and_has_a_stable_empty_template() {
        let mut state = TemporaryBans::default();
        assert_eq!(
            serialize_temporary_bans(&state).expect("empty"),
            DEFAULT_TEMPORARY_BANS_TEMPLATE
        );
        assert_eq!(
            parse_temporary_bans(DEFAULT_TEMPORARY_BANS_TEMPLATE).expect("empty"),
            state
        );
        state.asns.insert(0, 1);
        assert!(matches!(
            serialize_temporary_bans(&state),
            Err(TemporaryBanError::InvalidState { .. })
        ));
        state.asns.clear();
        for expiry in [0, u64::MAX] {
            state.asns.insert(64496, expiry);
            assert!(matches!(
                serialize_temporary_bans(&state),
                Err(TemporaryBanError::InvalidExpiry)
            ));
        }
        state.asns.clear();
        state
            .ips
            .insert(parse_ip_cidr_strict("203.0.113.1").expect("ip"), 0);
        assert!(matches!(
            serialize_temporary_bans(&state),
            Err(TemporaryBanError::InvalidExpiry)
        ));
    }
}
