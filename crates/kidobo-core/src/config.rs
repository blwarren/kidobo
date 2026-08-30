//! In-memory TOML configuration parsing, defaults, and validation.

use std::num::NonZeroU32;

use serde::Deserialize;
use thiserror::Error;
use toml_edit::de::from_str as parse_toml_str;

use crate::config_validation::{
    bounded_newtype, bounded_u32, non_empty, parse_chain_action, parse_cidr_field_strict,
    required_non_empty, validate_http_url, validate_ipset_set_name, validate_ipset_set_type,
};
use crate::network::CanonicalCidr;

/// Default kernel ipset type used for managed sets.
pub const DEFAULT_IPSET_TYPE: &str = "hash:net";
/// Default firewall action for matched addresses.
pub const DEFAULT_CHAIN_ACTION: FirewallAction = FirewallAction::Drop;
/// Default ipset hash table size.
pub const DEFAULT_HASHSIZE: u32 = 65_536;
/// Default and maximum supported number of entries per managed ipset.
pub const DEFAULT_MAXELEM: u32 = 500_000;
/// Default ipset entry timeout; zero means entries do not expire.
pub const DEFAULT_TIMEOUT: u32 = 0;
/// Default timeout for a remote source request.
pub const DEFAULT_REMOTE_TIMEOUT_SECS: u32 = 30;
/// Default age after which an ASN cache is eligible for refresh.
pub const DEFAULT_ASN_CACHE_STALE_AFTER_SECS: u32 = 24 * 60 * 60;
/// Whether GitHub metadata networks are included by default.
pub const DEFAULT_INCLUDE_GITHUB_META: bool = true;
/// GitHub metadata categories included when no explicit category list is configured.
pub const DEFAULT_GITHUB_META_CATEGORIES: [&str; 4] = ["api", "git", "hooks", "packages"];
/// Default GitHub metadata API endpoint.
pub const DEFAULT_GITHUB_META_URL: &str = "https://api.github.com/meta";
/// Maximum accepted remote request timeout.
pub const REMOTE_TIMEOUT_SECS_MAX: u32 = 3600;
/// Maximum accepted ASN cache refresh interval.
pub const ASN_CACHE_STALE_AFTER_SECS_MAX: u32 = 7 * 24 * 60 * 60;
const LEGACY_REMOTE_CACHE_STALE_AFTER_SECS_MAX: u32 = 7 * 24 * 60 * 60;

/// Validated, non-zero, power-of-two ipset hash table size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HashsizePow2(NonZeroU32);

impl HashsizePow2 {
    #[must_use]
    /// Validates a raw hash size.
    ///
    /// Returns `None` for zero or a value that is not a power of two.
    pub fn new(value: u32) -> Option<Self> {
        let non_zero = NonZeroU32::new(value)?;
        if value.is_power_of_two() {
            Some(Self(non_zero))
        } else {
            None
        }
    }

    #[must_use]
    /// Returns the validated raw value.
    pub fn get(self) -> u32 {
        self.0.get()
    }
}

impl From<HashsizePow2> for u32 {
    fn from(value: HashsizePow2) -> Self {
        value.get()
    }
}

/// Validated, non-zero ipset capacity within Kidobo's supported limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MaxElem(NonZeroU32);

impl MaxElem {
    #[must_use]
    /// Validates a raw capacity.
    ///
    /// Returns `None` for zero or a value above [`DEFAULT_MAXELEM`].
    pub fn new(value: u32) -> Option<Self> {
        let non_zero = NonZeroU32::new(value)?;
        if value <= DEFAULT_MAXELEM {
            Some(Self(non_zero))
        } else {
            None
        }
    }

    #[must_use]
    /// Returns the validated raw value.
    pub fn get(self) -> u32 {
        self.0.get()
    }
}

impl From<MaxElem> for u32 {
    fn from(value: MaxElem) -> Self {
        value.get()
    }
}

/// Validated, non-zero remote request timeout in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RemoteTimeoutSecs(NonZeroU32);

impl RemoteTimeoutSecs {
    #[must_use]
    /// Validates a raw timeout.
    ///
    /// Returns `None` for zero or a value above [`REMOTE_TIMEOUT_SECS_MAX`].
    pub fn new(value: u32) -> Option<Self> {
        let non_zero = NonZeroU32::new(value)?;
        if value <= REMOTE_TIMEOUT_SECS_MAX {
            Some(Self(non_zero))
        } else {
            None
        }
    }

    #[must_use]
    /// Returns the validated timeout in seconds.
    pub fn get(self) -> u32 {
        self.0.get()
    }
}

impl From<RemoteTimeoutSecs> for u32 {
    fn from(value: RemoteTimeoutSecs) -> Self {
        value.get()
    }
}

/// Validated, non-zero ASN cache refresh interval in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AsnCacheStaleAfterSecs(NonZeroU32);

impl AsnCacheStaleAfterSecs {
    #[must_use]
    /// Validates a raw refresh interval.
    ///
    /// Returns `None` for zero or a value above [`ASN_CACHE_STALE_AFTER_SECS_MAX`].
    pub fn new(value: u32) -> Option<Self> {
        let non_zero = NonZeroU32::new(value)?;
        if value <= ASN_CACHE_STALE_AFTER_SECS_MAX {
            Some(Self(non_zero))
        } else {
            None
        }
    }

    #[must_use]
    /// Returns the validated refresh interval in seconds.
    pub fn get(self) -> u32 {
        self.0.get()
    }
}

impl From<AsnCacheStaleAfterSecs> for u32 {
    fn from(value: AsnCacheStaleAfterSecs) -> Self {
        value.get()
    }
}

/// Complete validated Kidobo configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Managed ipset and firewall settings.
    pub ipset: IpsetConfig,
    /// Networks carved out of the effective blocklist.
    pub safe: SafeConfig,
    /// Remote blocklist source settings.
    pub remote: RemoteConfig,
    /// ASN source and cache settings.
    pub asn: AsnConfig,
}

/// Managed ipset and firewall settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpsetConfig {
    /// IPv4 ipset name.
    pub set_name: String,
    /// IPv6 ipset name.
    pub set_name_v6: String,
    /// Whether IPv6 enforcement is enabled.
    pub enable_ipv6: bool,
    /// Firewall action applied to set matches.
    pub chain_action: FirewallAction,
    /// Kernel ipset type, currently constrained to the supported network type.
    pub set_type: String,
    /// Initial ipset hash table size.
    pub hashsize: HashsizePow2,
    /// Maximum number of entries in each managed set.
    pub maxelem: MaxElem,
    /// Kernel timeout assigned to entries; zero disables expiry.
    pub timeout: u32,
}

/// Firewall verdict applied to a matching address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallAction {
    /// Silently discard the packet.
    Drop,
    /// Reject the packet with the firewall's standard response.
    Reject,
}

/// Safelist and GitHub metadata configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeConfig {
    /// Explicit CIDRs that must be removed from effective blocklists.
    pub ips: Vec<CanonicalCidr>,
    /// Whether GitHub metadata CIDRs participate in safelisting.
    pub include_github_meta: bool,
    /// Configured GitHub metadata endpoint.
    pub github_meta_url: String,
    /// Category selection; `None` uses defaults and an empty list selects all categories.
    pub github_meta_categories: Option<Vec<String>>,
}

/// Remote blocklist configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteConfig {
    /// Canonical HTTP or HTTPS source URLs in configured order.
    pub urls: Vec<String>,
    /// Per-request timeout.
    pub timeout_secs: RemoteTimeoutSecs,
}

/// Autonomous-system blocklist configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsnConfig {
    /// Sorted, unique autonomous-system numbers to block.
    pub banned: Vec<u32>,
    /// Age after which cached ASN prefixes should be refreshed.
    pub cache_stale_after_secs: AsnCacheStaleAfterSecs,
}

/// Interpreted GitHub metadata category selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GithubMetaCategoryMode {
    /// Use Kidobo's documented default category set.
    Default,
    /// Accept every network category returned by the endpoint.
    All,
    /// Accept only the listed category names.
    Explicit(Vec<String>),
}

impl SafeConfig {
    #[must_use]
    /// Resolves the compatibility-sensitive optional category representation.
    pub fn github_meta_category_mode(&self) -> GithubMetaCategoryMode {
        match &self.github_meta_categories {
            None => GithubMetaCategoryMode::Default,
            Some(values) if values.is_empty() => GithubMetaCategoryMode::All,
            Some(values) => GithubMetaCategoryMode::Explicit(values.clone()),
        }
    }
}

/// Error produced while parsing or validating configuration text.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// The input is not valid TOML or does not match the expected schema.
    #[error("failed to parse TOML config: {reason}")]
    Parse {
        /// Parser diagnostic suitable for operator-facing error context.
        reason: String,
    },

    /// The required `[ipset]` table is absent.
    #[error("missing required config section `[ipset]`")]
    MissingIpsetSection,

    /// A known field violates its semantic constraints.
    #[error("invalid config value for `{field}`: {reason}")]
    InvalidField {
        /// Stable configuration field path.
        field: &'static str,
        /// Human-readable validation failure.
        reason: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    ipset: Option<RawIpsetConfig>,
    safe: Option<RawSafeConfig>,
    remote: Option<RawRemoteConfig>,
    asn: Option<RawAsnConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIpsetConfig {
    set_name: Option<String>,
    set_name_v6: Option<String>,
    enable_ipv6: Option<bool>,
    chain_action: Option<String>,
    set_type: Option<String>,
    hashsize: Option<i64>,
    maxelem: Option<i64>,
    timeout: Option<i64>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawSafeConfig {
    ips: Option<Vec<String>>,
    include_github_meta: Option<bool>,
    github_meta_url: Option<String>,
    github_meta_categories: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawRemoteConfig {
    urls: Option<Vec<String>>,
    timeout_secs: Option<i64>,
    cache_stale_after_secs: Option<i64>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawAsnConfig {
    banned: Option<Vec<i64>>,
    cache_stale_after_secs: Option<i64>,
}

impl Config {
    /// Parses and validates configuration from in-memory TOML.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when the TOML is malformed, a required section or field is
    /// missing, or any configured value violates its domain constraints.
    pub fn from_toml_str(contents: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = parse_toml_str(contents).map_err(|err| ConfigError::Parse {
            reason: err.to_string(),
        })?;

        Self::from_raw(raw)
    }

    fn from_raw(raw: RawConfig) -> Result<Self, ConfigError> {
        let raw_ipset = raw.ipset.ok_or(ConfigError::MissingIpsetSection)?;
        let ipset = parse_ipset(raw_ipset)?;
        let safe = parse_safe(raw.safe.unwrap_or_default())?;
        let remote = parse_remote(raw.remote.unwrap_or_default())?;
        let asn = parse_asn(raw.asn.unwrap_or_default())?;

        Ok(Self {
            ipset,
            safe,
            remote,
            asn,
        })
    }
}

fn parse_ipset(raw: RawIpsetConfig) -> Result<IpsetConfig, ConfigError> {
    let set_name = required_non_empty(raw.set_name, "ipset.set_name")?;
    validate_ipset_set_name(&set_name, "ipset.set_name")?;

    let enable_ipv6 = raw.enable_ipv6.unwrap_or(true);
    let set_name_v6 = if let Some(value) = raw.set_name_v6 {
        let parsed = non_empty(&value, "ipset.set_name_v6")?;
        validate_ipset_set_name(&parsed, "ipset.set_name_v6")?;
        parsed
    } else {
        let derived = format!("{set_name}-v6");
        if enable_ipv6 {
            validate_ipset_set_name(&derived, "ipset.set_name_v6")?;
        }
        derived
    };
    if set_name_v6 == set_name {
        return Err(ConfigError::InvalidField {
            field: "ipset.set_name_v6",
            reason: "must differ from ipset.set_name".to_string(),
        });
    }

    let chain_action = parse_chain_action(raw.chain_action)?;
    let set_type = match raw.set_type {
        Some(value) => {
            let parsed = non_empty(&value, "ipset.set_type")?;
            validate_ipset_set_type(&parsed)?;
            parsed
        }
        None => DEFAULT_IPSET_TYPE.to_string(),
    };

    let hashsize = bounded_newtype(
        raw.hashsize.unwrap_or(i64::from(DEFAULT_HASHSIZE)),
        "ipset.hashsize",
        1,
        u32::MAX,
        "must be a power-of-two positive integer".to_string(),
        HashsizePow2::new,
    )?;

    let maxelem = bounded_newtype(
        raw.maxelem.unwrap_or(i64::from(DEFAULT_MAXELEM)),
        "ipset.maxelem",
        1,
        DEFAULT_MAXELEM,
        format!("must be between 1 and {DEFAULT_MAXELEM}"),
        MaxElem::new,
    )?;

    let timeout = bounded_u32(
        raw.timeout.unwrap_or(i64::from(DEFAULT_TIMEOUT)),
        "ipset.timeout",
        0,
        u32::MAX,
    )?;

    Ok(IpsetConfig {
        set_name,
        set_name_v6,
        enable_ipv6,
        chain_action,
        set_type,
        hashsize,
        maxelem,
        timeout,
    })
}

fn parse_safe(raw: RawSafeConfig) -> Result<SafeConfig, ConfigError> {
    let mut ips = Vec::new();
    if let Some(values) = raw.ips {
        for value in values {
            let parsed = parse_cidr_field_strict(&non_empty(&value, "safe.ips")?, "safe.ips")?;
            ips.push(parsed);
        }
    }

    let include_github_meta = raw
        .include_github_meta
        .unwrap_or(DEFAULT_INCLUDE_GITHUB_META);

    let github_meta_url = match raw.github_meta_url {
        Some(value) => {
            let parsed = non_empty(&value, "safe.github_meta_url")?;
            validate_http_url(&parsed, "safe.github_meta_url")?;
            parsed
        }
        None => DEFAULT_GITHUB_META_URL.to_string(),
    };

    let github_meta_categories = match raw.github_meta_categories {
        None => None,
        Some(values) => {
            let mut normalized = Vec::with_capacity(values.len());
            for value in values {
                normalized.push(non_empty(&value, "safe.github_meta_categories")?);
            }
            Some(normalized)
        }
    };

    Ok(SafeConfig {
        ips,
        include_github_meta,
        github_meta_url,
        github_meta_categories,
    })
}

fn parse_remote(raw: RawRemoteConfig) -> Result<RemoteConfig, ConfigError> {
    let mut urls = Vec::new();
    if let Some(values) = raw.urls {
        for value in values {
            let parsed = non_empty(&value, "remote.urls")?;
            validate_http_url(&parsed, "remote.urls")?;
            urls.push(parsed);
        }
    }

    let timeout_secs = bounded_newtype(
        raw.timeout_secs
            .unwrap_or(i64::from(DEFAULT_REMOTE_TIMEOUT_SECS)),
        "remote.timeout_secs",
        1,
        REMOTE_TIMEOUT_SECS_MAX,
        format!("must be between 1 and {REMOTE_TIMEOUT_SECS_MAX}"),
        RemoteTimeoutSecs::new,
    )?;

    // This overlap-analysis setting was removed from the runtime model, but is
    // still validated when present so existing operator configs remain valid.
    if let Some(value) = raw.cache_stale_after_secs {
        bounded_u32(
            value,
            "remote.cache_stale_after_secs",
            1,
            LEGACY_REMOTE_CACHE_STALE_AFTER_SECS_MAX,
        )?;
    }

    Ok(RemoteConfig { urls, timeout_secs })
}

fn parse_asn(raw: RawAsnConfig) -> Result<AsnConfig, ConfigError> {
    let mut banned = Vec::new();
    if let Some(values) = raw.banned {
        for value in values {
            let parsed = bounded_u32(value, "asn.banned", 1, u32::MAX)?;
            banned.push(parsed);
        }
    }
    banned.sort_unstable();
    banned.dedup();

    let cache_stale_after_secs = bounded_newtype(
        raw.cache_stale_after_secs
            .unwrap_or(i64::from(DEFAULT_ASN_CACHE_STALE_AFTER_SECS)),
        "asn.cache_stale_after_secs",
        1,
        ASN_CACHE_STALE_AFTER_SECS_MAX,
        format!("must be between 1 and {ASN_CACHE_STALE_AFTER_SECS_MAX}"),
        AsnCacheStaleAfterSecs::new,
    )?;

    Ok(AsnConfig {
        banned,
        cache_stale_after_secs,
    })
}

#[cfg(test)]
mod tests {
    use crate::network::{CanonicalCidr, Ipv4Cidr};

    use super::{
        ASN_CACHE_STALE_AFTER_SECS_MAX, AsnCacheStaleAfterSecs, Config, ConfigError,
        DEFAULT_ASN_CACHE_STALE_AFTER_SECS, DEFAULT_CHAIN_ACTION, DEFAULT_GITHUB_META_CATEGORIES,
        DEFAULT_GITHUB_META_URL, DEFAULT_HASHSIZE, DEFAULT_IPSET_TYPE, DEFAULT_MAXELEM,
        DEFAULT_REMOTE_TIMEOUT_SECS, DEFAULT_TIMEOUT, FirewallAction, GithubMetaCategoryMode,
        HashsizePow2, MaxElem, REMOTE_TIMEOUT_SECS_MAX, RemoteTimeoutSecs,
    };
    use crate::config_validation::validate_ipset_set_name;

    #[test]
    fn time_defaults_and_limits_have_exact_values() {
        assert_eq!(DEFAULT_REMOTE_TIMEOUT_SECS, 30);
        assert_eq!(DEFAULT_ASN_CACHE_STALE_AFTER_SECS, 86_400);
        assert_eq!(REMOTE_TIMEOUT_SECS_MAX, 3_600);
        assert_eq!(ASN_CACHE_STALE_AFTER_SECS_MAX, 604_800);
    }

    #[test]
    fn validated_numeric_types_convert_without_losing_values() {
        assert_eq!(
            u32::from(HashsizePow2::new(8_192).expect("valid hashsize")),
            8_192
        );
        assert_eq!(
            u32::from(MaxElem::new(123_456).expect("valid maxelem")),
            123_456
        );
        assert_eq!(
            u32::from(RemoteTimeoutSecs::new(45).expect("valid timeout")),
            45
        );
        assert_eq!(
            u32::from(AsnCacheStaleAfterSecs::new(9_000).expect("valid ASN cache age")),
            9_000
        );
    }

    #[test]
    fn parses_minimal_config_and_applies_defaults() {
        let config = Config::from_toml_str("[ipset]\nset_name = 'kidobo'\n").expect("parse");

        assert_eq!(config.ipset.set_name, "kidobo");
        assert_eq!(config.ipset.set_name_v6, "kidobo-v6");
        assert!(config.ipset.enable_ipv6);
        assert_eq!(config.ipset.chain_action, DEFAULT_CHAIN_ACTION);
        assert_eq!(config.ipset.set_type, DEFAULT_IPSET_TYPE);
        assert_eq!(config.ipset.hashsize.get(), DEFAULT_HASHSIZE);
        assert_eq!(config.ipset.maxelem.get(), DEFAULT_MAXELEM);
        assert_eq!(config.ipset.timeout, DEFAULT_TIMEOUT);
        assert!(config.safe.ips.is_empty());
        assert!(config.safe.include_github_meta);
        assert_eq!(config.safe.github_meta_url, DEFAULT_GITHUB_META_URL);
        assert_eq!(
            config.safe.github_meta_category_mode(),
            GithubMetaCategoryMode::Default
        );
        assert_eq!(
            DEFAULT_GITHUB_META_CATEGORIES,
            ["api", "git", "hooks", "packages"]
        );
        assert_eq!(config.remote.urls, Vec::<String>::new());
        assert_eq!(
            config.remote.timeout_secs.get(),
            DEFAULT_REMOTE_TIMEOUT_SECS
        );
        assert!(config.asn.banned.is_empty());
        assert_eq!(
            config.asn.cache_stale_after_secs.get(),
            DEFAULT_ASN_CACHE_STALE_AFTER_SECS
        );
    }

    #[test]
    fn set_name_v6_can_be_overridden() {
        let config =
            Config::from_toml_str("[ipset]\nset_name = 'kidobo'\nset_name_v6 = 'custom-v6'\n")
                .expect("parse");

        assert_eq!(config.ipset.set_name_v6, "custom-v6");
    }

    #[test]
    fn set_name_v6_must_not_match_set_name() {
        let err = Config::from_toml_str("[ipset]\nset_name = 'kidobo'\nset_name_v6 = 'kidobo'\n")
            .expect_err("must fail");

        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "ipset.set_name_v6",
                reason: "must differ from ipset.set_name".to_string(),
            }
        );
    }

    #[test]
    fn set_name_v6_must_not_match_set_name_when_ipv6_disabled() {
        let err = Config::from_toml_str(
            "[ipset]\nset_name = 'kidobo'\nset_name_v6 = 'kidobo'\nenable_ipv6 = false\n",
        )
        .expect_err("must fail");

        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "ipset.set_name_v6",
                reason: "must differ from ipset.set_name".to_string(),
            }
        );
    }

    #[test]
    fn enable_ipv6_false_is_respected() {
        let config = Config::from_toml_str("[ipset]\nset_name='kidobo'\nenable_ipv6=false\n")
            .expect("parse");

        assert!(!config.ipset.enable_ipv6);
    }

    #[test]
    fn enable_ipv6_false_does_not_require_valid_derived_v6_set_name() {
        let config = Config::from_toml_str(
            "[ipset]\nset_name='kidobo-name-that-is-thirty-one'\nenable_ipv6=false\n",
        )
        .expect("parse");

        assert_eq!(config.ipset.set_name, "kidobo-name-that-is-thirty-one");
        assert!(!config.ipset.enable_ipv6);
    }

    #[test]
    fn enabled_ipv6_requires_valid_derived_v6_set_name() {
        let err = Config::from_toml_str("[ipset]\nset_name='kidobo-name-that-is-thirty-one'\n")
            .expect_err("must fail");

        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "ipset.set_name_v6",
                reason: "must be 31 characters or fewer".to_string(),
            }
        );
    }

    #[test]
    fn chain_action_defaults_to_drop() {
        let config = Config::from_toml_str("[ipset]\nset_name='kidobo'\n").expect("parse");
        assert_eq!(config.ipset.chain_action, FirewallAction::Drop);
    }

    #[test]
    fn chain_action_accepts_drop_or_reject_case_insensitively() {
        let drop_config =
            Config::from_toml_str("[ipset]\nset_name='kidobo'\nchain_action='drop'\n")
                .expect("parse");
        assert_eq!(drop_config.ipset.chain_action, FirewallAction::Drop);

        let reject_config =
            Config::from_toml_str("[ipset]\nset_name='kidobo'\nchain_action='REJECT'\n")
                .expect("parse");
        assert_eq!(reject_config.ipset.chain_action, FirewallAction::Reject);
    }

    #[test]
    fn chain_action_rejects_invalid_values() {
        let err = Config::from_toml_str("[ipset]\nset_name='kidobo'\nchain_action='ACCEPT'\n")
            .expect_err("must fail");
        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "ipset.chain_action",
                reason: "must be DROP or REJECT".to_string(),
            }
        );
    }

    #[test]
    fn safe_empty_categories_means_all() {
        let config = Config::from_toml_str(
            "[ipset]\nset_name='kidobo'\n[safe]\ngithub_meta_categories=[]\n",
        )
        .expect("parse");

        assert_eq!(
            config.safe.github_meta_category_mode(),
            GithubMetaCategoryMode::All
        );
    }

    #[test]
    fn safe_ips_are_strictly_parsed_as_cidrs() {
        let config =
            Config::from_toml_str("[ipset]\nset_name='kidobo'\n[safe]\nips=['10.0.0.1']\n")
                .expect("parse");
        assert_eq!(
            config.safe.ips,
            vec![CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a00_0001, 32))]
        );
    }

    #[test]
    fn safe_ips_reject_invalid_cidr_tokens() {
        let err = Config::from_toml_str("[ipset]\nset_name='kidobo'\n[safe]\nips=['not-an-ip']\n")
            .expect_err("must fail");
        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "safe.ips",
                reason: "invalid IP/CIDR token `not-an-ip`".to_string(),
            }
        );
    }

    #[test]
    fn safe_explicit_categories_are_preserved() {
        let config = Config::from_toml_str(
            "[ipset]\nset_name='kidobo'\n[safe]\ngithub_meta_categories=['api','hooks']\n",
        )
        .expect("parse");

        assert_eq!(
            config.safe.github_meta_category_mode(),
            GithubMetaCategoryMode::Explicit(vec!["api".to_string(), "hooks".to_string()])
        );
    }

    #[test]
    fn safe_github_meta_url_can_be_overridden() {
        let config = Config::from_toml_str(
            "[ipset]\nset_name='kidobo'\n[safe]\ngithub_meta_url='https://example.com/meta'\n",
        )
        .expect("parse");
        assert_eq!(config.safe.github_meta_url, "https://example.com/meta");
    }

    #[test]
    fn safe_github_meta_url_must_be_http_or_https() {
        let err = Config::from_toml_str(
            "[ipset]\nset_name='kidobo'\n[safe]\ngithub_meta_url='ftp://example.com/meta'\n",
        )
        .expect_err("must fail");
        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "safe.github_meta_url",
                reason: "must be a valid http:// or https:// URL with a host".to_string(),
            }
        );
    }

    #[test]
    fn safe_github_meta_url_must_be_structurally_valid() {
        let err = Config::from_toml_str(
            "[ipset]\nset_name='kidobo'\n[safe]\ngithub_meta_url='https://'\n",
        )
        .expect_err("must fail");
        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "safe.github_meta_url",
                reason: "must be a valid http:// or https:// URL with a host".to_string(),
            }
        );
    }

    #[test]
    fn asn_banned_values_are_deduped_and_sorted() {
        let config = Config::from_toml_str(
            "[ipset]\nset_name='kidobo'\n[asn]\nbanned=[64513,64512,64513]\n",
        )
        .expect("parse");
        assert_eq!(config.asn.banned, vec![64512, 64513]);
    }

    #[test]
    fn asn_cache_stale_after_secs_can_be_overridden() {
        let config = Config::from_toml_str(
            "[ipset]\nset_name='kidobo'\n[asn]\ncache_stale_after_secs=7200\n",
        )
        .expect("parse");
        assert_eq!(config.asn.cache_stale_after_secs.get(), 7200);
    }

    #[test]
    fn asn_rejects_invalid_values() {
        let err = Config::from_toml_str("[ipset]\nset_name='kidobo'\n[asn]\nbanned=[0]\n")
            .expect_err("must fail");
        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "asn.banned",
                reason: format!("must be between {} and {}", 1, u32::MAX),
            }
        );

        let err = Config::from_toml_str(
            "[ipset]\nset_name='kidobo'\n[asn]\ncache_stale_after_secs=999999999\n",
        )
        .expect_err("must fail");
        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "asn.cache_stale_after_secs",
                reason: format!("must be between 1 and {ASN_CACHE_STALE_AFTER_SECS_MAX}"),
            }
        );
    }

    #[test]
    fn missing_ipset_section_fails() {
        let err = Config::from_toml_str("[safe]\nips=[]\n").expect_err("must fail");
        assert_eq!(err, ConfigError::MissingIpsetSection);
    }

    #[test]
    fn missing_set_name_fails() {
        let err = Config::from_toml_str("[ipset]\n").expect_err("must fail");
        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "ipset.set_name",
                reason: "value is required".to_string(),
            }
        );
    }

    #[test]
    fn hashsize_must_be_power_of_two() {
        let err = Config::from_toml_str("[ipset]\nset_name='kidobo'\nhashsize=100\n")
            .expect_err("must fail");
        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "ipset.hashsize",
                reason: "must be a power-of-two positive integer".to_string(),
            }
        );
    }

    #[test]
    fn maxelem_must_be_in_allowed_range() {
        let err = Config::from_toml_str("[ipset]\nset_name='kidobo'\nmaxelem=500001\n")
            .expect_err("must fail");
        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "ipset.maxelem",
                reason: "must be between 1 and 500000".to_string(),
            }
        );
    }

    #[test]
    fn timeout_must_be_non_negative() {
        let err = Config::from_toml_str("[ipset]\nset_name='kidobo'\ntimeout=-1\n")
            .expect_err("must fail");
        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "ipset.timeout",
                reason: format!("must be between {} and {}", 0, u32::MAX),
            }
        );
    }

    #[test]
    fn set_name_rejects_whitespace_and_overlength_values() {
        let err = Config::from_toml_str("[ipset]\nset_name='kidobo bad'\n").expect_err("must fail");
        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "ipset.set_name",
                reason: "must contain only [A-Za-z0-9_.-]".to_string(),
            }
        );

        let err =
            Config::from_toml_str("[ipset]\nset_name='kidobo-name-that-is-way-too-long-12345'\n")
                .expect_err("must fail");
        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "ipset.set_name",
                reason: "must be 31 characters or fewer".to_string(),
            }
        );
    }

    #[test]
    fn set_name_accepts_exactly_31_characters() {
        validate_ipset_set_name(&"a".repeat(31), "ipset.set_name").expect("31-character set name");
        assert!(validate_ipset_set_name(&"a".repeat(32), "ipset.set_name").is_err());
    }

    #[test]
    fn set_type_accepts_explicit_supported_punctuation() {
        let config = Config::from_toml_str("[ipset]\nset_name='kidobo'\nset_type='hash:net'\n")
            .expect("valid set type");

        assert_eq!(config.ipset.set_type, "hash:net");
    }

    #[test]
    fn set_type_rejects_whitespace_and_control_characters() {
        let err = Config::from_toml_str("[ipset]\nset_name='kidobo'\nset_type='hash: net'\n")
            .expect_err("must fail");
        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "ipset.set_type",
                reason: "must contain only [A-Za-z0-9:,_-.]".to_string(),
            }
        );

        let err = Config::from_toml_str("[ipset]\nset_name='kidobo'\nset_type='hash:net\\nadd'\n")
            .expect_err("must fail");
        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "ipset.set_type",
                reason: "must contain only [A-Za-z0-9:,_-.]".to_string(),
            }
        );
    }

    #[test]
    fn empty_remote_url_fails() {
        let err = Config::from_toml_str("[ipset]\nset_name='kidobo'\n[remote]\nurls=['']\n")
            .expect_err("must fail");
        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "remote.urls",
                reason: "value must not be empty".to_string(),
            }
        );
    }

    #[test]
    fn remote_urls_must_be_http_or_https() {
        let err = Config::from_toml_str(
            "[ipset]\nset_name='kidobo'\n[remote]\nurls=['file:///tmp/list.txt']\n",
        )
        .expect_err("must fail");
        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "remote.urls",
                reason: "must be a valid http:// or https:// URL with a host".to_string(),
            }
        );
    }

    #[test]
    fn remote_urls_must_be_structurally_valid() {
        let err = Config::from_toml_str(
            "[ipset]\nset_name='kidobo'\n[remote]\nurls=['https:// example.com/list.txt']\n",
        )
        .expect_err("must fail");
        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "remote.urls",
                reason: "must be a valid http:// or https:// URL with a host".to_string(),
            }
        );
    }

    #[test]
    fn remote_timeout_secs_can_be_overridden() {
        let config =
            Config::from_toml_str("[ipset]\nset_name='kidobo'\n[remote]\ntimeout_secs=45\n")
                .expect("parse");
        assert_eq!(config.remote.timeout_secs.get(), 45);
    }

    #[test]
    fn remote_timeout_secs_must_be_within_allowed_range() {
        let err = Config::from_toml_str("[ipset]\nset_name='kidobo'\n[remote]\ntimeout_secs=0\n")
            .expect_err("must fail");
        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "remote.timeout_secs",
                reason: "must be between 1 and 3600".to_string(),
            }
        );

        let err =
            Config::from_toml_str("[ipset]\nset_name='kidobo'\n[remote]\ntimeout_secs=3601\n")
                .expect_err("must fail");
        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "remote.timeout_secs",
                reason: "must be between 1 and 3600".to_string(),
            }
        );
    }

    #[test]
    fn legacy_remote_cache_stale_after_secs_is_accepted() {
        Config::from_toml_str(
            "[ipset]\nset_name='kidobo'\n[remote]\ncache_stale_after_secs=7200\n",
        )
        .expect("parse");
    }

    #[test]
    fn remote_cache_stale_after_secs_must_be_within_allowed_range() {
        let err = Config::from_toml_str(
            "[ipset]\nset_name='kidobo'\n[remote]\ncache_stale_after_secs=0\n",
        )
        .expect_err("must fail");
        assert_eq!(
            err,
            ConfigError::InvalidField {
                field: "remote.cache_stale_after_secs",
                reason: "must be between 1 and 604800".to_string(),
            }
        );
    }

    #[test]
    fn parse_errors_are_mapped() {
        let err = Config::from_toml_str("not toml").expect_err("must fail");
        match err {
            ConfigError::Parse { .. } => {}
            _ => panic!("expected parse error"),
        }
    }

    #[test]
    fn parser_rejects_unknown_root_and_nested_keys() {
        for contents in [
            "[ipset]\nset_name='kidobo'\nunknown=true\n",
            "[ipset]\nset_name='kidobo'\n[remote]\ntimeout_second=30\n",
            "[ipset]\nset_name='kidobo'\n[safe]\ninclude_github=true\n",
            "[ipset]\nset_name='kidobo'\n[extra]\nvalue=true\n",
            "ipset = { set_name = 'kidobo', typo = true }\n",
            "ipset.set_name='kidobo'\nasn.stale_seconds=30\n",
        ] {
            assert!(
                matches!(
                    Config::from_toml_str(contents),
                    Err(ConfigError::Parse { .. })
                ),
                "unexpectedly accepted {contents:?}"
            );
        }
    }

    #[test]
    fn parser_accepts_comments_blank_lines_and_trailing_commas() {
        let config = Config::from_toml_str(
            "# leading comment\n\
             [ipset]\n\
             set_name = 'kidobo'\n\
             \n\
             [safe]\n\
             # comment inside table\n\
             ips = [\n\
               '10.0.0.1',\n\
             ]\n\
             \n\
             [remote]\n\
             urls = [\n\
               'https://example.com/list.txt',\n\
             ]\n\
             \n\
             [asn]\n\
             banned = [\n\
               64512,\n\
             ]\n",
        )
        .expect("parse");

        assert_eq!(config.ipset.set_name, "kidobo");
        assert_eq!(
            config.safe.ips,
            vec![CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a00_0001, 32))]
        );
        assert_eq!(
            config.remote.urls,
            vec!["https://example.com/list.txt".to_string()]
        );
        assert_eq!(config.asn.banned, vec![64512]);
    }

    #[test]
    fn parser_accepts_dotted_keys_for_nested_sections() {
        let config = Config::from_toml_str(
            "ipset.set_name = 'kidobo'\n\
             ipset.enable_ipv6 = false\n\
             safe.ips = ['10.0.0.1']\n\
             safe.github_meta_url = 'https://example.com/meta'\n\
             remote.urls = ['https://example.com/list.txt']\n\
             remote.timeout_secs = 45\n\
             asn.banned = [64512]\n\
             asn.cache_stale_after_secs = 7200\n",
        )
        .expect("parse");

        assert_eq!(config.ipset.set_name, "kidobo");
        assert!(!config.ipset.enable_ipv6);
        assert_eq!(
            config.safe.ips,
            vec![CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a00_0001, 32))]
        );
        assert_eq!(config.safe.github_meta_url, "https://example.com/meta");
        assert_eq!(
            config.remote.urls,
            vec!["https://example.com/list.txt".to_string()]
        );
        assert_eq!(config.remote.timeout_secs.get(), 45);
        assert_eq!(config.asn.banned, vec![64512]);
        assert_eq!(config.asn.cache_stale_after_secs.get(), 7200);
    }

    #[test]
    fn parser_accepts_inline_tables_for_sections() {
        let config = Config::from_toml_str(
            "ipset = { set_name = 'kidobo', enable_ipv6 = false }\n\
             safe = { include_github_meta = false, github_meta_url = 'https://example.com/meta' }\n\
             remote = { urls = ['https://example.com/list.txt'], timeout_secs = 45 }\n\
             asn = { banned = [64513, 64512], cache_stale_after_secs = 7200 }\n",
        )
        .expect("parse");

        assert_eq!(config.ipset.set_name, "kidobo");
        assert!(!config.ipset.enable_ipv6);
        assert!(!config.safe.include_github_meta);
        assert_eq!(config.safe.github_meta_url, "https://example.com/meta");
        assert_eq!(
            config.remote.urls,
            vec!["https://example.com/list.txt".to_string()]
        );
        assert_eq!(config.remote.timeout_secs.get(), 45);
        assert_eq!(config.asn.banned, vec![64512, 64513]);
        assert_eq!(config.asn.cache_stale_after_secs.get(), 7200);
    }

    #[test]
    fn parser_rejects_duplicate_keys() {
        let err = Config::from_toml_str(
            "[ipset]\n\
             set_name = 'kidobo'\n\
             set_name = 'kidobo-duplicate'\n",
        )
        .expect_err("must fail");

        match err {
            ConfigError::Parse { .. } => {}
            _ => panic!("expected parse error for duplicate key"),
        }
    }

    #[test]
    fn parser_rejects_duplicate_tables() {
        let err = Config::from_toml_str(
            "[ipset]\n\
             set_name = 'kidobo'\n\
             [ipset]\n\
             enable_ipv6 = false\n",
        )
        .expect_err("must fail");

        match err {
            ConfigError::Parse { .. } => {}
            _ => panic!("expected parse error for duplicate table"),
        }
    }
}
