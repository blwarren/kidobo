use std::num::NonZeroU32;

use serde::Deserialize;
use thiserror::Error;
use toml_edit::de::from_str as parse_toml_str;

use crate::core::network::{CanonicalCidr, parse_ip_cidr_token};

pub const DEFAULT_IPSET_TYPE: &str = "hash:net";
pub const DEFAULT_CHAIN_ACTION: FirewallAction = FirewallAction::Drop;
pub const DEFAULT_HASHSIZE: u32 = 65_536;
pub const DEFAULT_MAXELEM: u32 = 500_000;
pub const DEFAULT_TIMEOUT: u32 = 0;
pub const DEFAULT_REMOTE_TIMEOUT_SECS: u32 = 30;
pub const DEFAULT_REMOTE_CACHE_STALE_AFTER_SECS: u32 = 24 * 60 * 60;
pub const DEFAULT_ASN_CACHE_STALE_AFTER_SECS: u32 = 24 * 60 * 60;
pub const DEFAULT_INCLUDE_GITHUB_META: bool = true;
pub const DEFAULT_GITHUB_META_CATEGORIES: [&str; 4] = ["api", "git", "hooks", "packages"];
pub const DEFAULT_GITHUB_META_URL: &str = "https://api.github.com/meta";
pub const REMOTE_TIMEOUT_SECS_MAX: u32 = 3600;
pub const REMOTE_CACHE_STALE_AFTER_SECS_MAX: u32 = 7 * 24 * 60 * 60;
pub const ASN_CACHE_STALE_AFTER_SECS_MAX: u32 = 7 * 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HashsizePow2(NonZeroU32);

impl HashsizePow2 {
    pub fn new(value: u32) -> Option<Self> {
        let non_zero = NonZeroU32::new(value)?;
        if value.is_power_of_two() {
            Some(Self(non_zero))
        } else {
            None
        }
    }

    pub fn get(self) -> u32 {
        self.0.get()
    }
}

impl From<HashsizePow2> for u32 {
    fn from(value: HashsizePow2) -> Self {
        value.get()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MaxElem(NonZeroU32);

impl MaxElem {
    pub fn new(value: u32) -> Option<Self> {
        let non_zero = NonZeroU32::new(value)?;
        if value <= DEFAULT_MAXELEM {
            Some(Self(non_zero))
        } else {
            None
        }
    }

    pub fn get(self) -> u32 {
        self.0.get()
    }
}

impl From<MaxElem> for u32 {
    fn from(value: MaxElem) -> Self {
        value.get()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RemoteTimeoutSecs(NonZeroU32);

impl RemoteTimeoutSecs {
    pub fn new(value: u32) -> Option<Self> {
        let non_zero = NonZeroU32::new(value)?;
        if value <= REMOTE_TIMEOUT_SECS_MAX {
            Some(Self(non_zero))
        } else {
            None
        }
    }

    pub fn get(self) -> u32 {
        self.0.get()
    }
}

impl From<RemoteTimeoutSecs> for u32 {
    fn from(value: RemoteTimeoutSecs) -> Self {
        value.get()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RemoteCacheStaleAfterSecs(NonZeroU32);

impl RemoteCacheStaleAfterSecs {
    pub fn new(value: u32) -> Option<Self> {
        let non_zero = NonZeroU32::new(value)?;
        if value <= REMOTE_CACHE_STALE_AFTER_SECS_MAX {
            Some(Self(non_zero))
        } else {
            None
        }
    }

    pub fn get(self) -> u32 {
        self.0.get()
    }
}

impl From<RemoteCacheStaleAfterSecs> for u32 {
    fn from(value: RemoteCacheStaleAfterSecs) -> Self {
        value.get()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AsnCacheStaleAfterSecs(NonZeroU32);

impl AsnCacheStaleAfterSecs {
    pub fn new(value: u32) -> Option<Self> {
        let non_zero = NonZeroU32::new(value)?;
        if value <= ASN_CACHE_STALE_AFTER_SECS_MAX {
            Some(Self(non_zero))
        } else {
            None
        }
    }

    pub fn get(self) -> u32 {
        self.0.get()
    }
}

impl From<AsnCacheStaleAfterSecs> for u32 {
    fn from(value: AsnCacheStaleAfterSecs) -> Self {
        value.get()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub ipset: IpsetConfig,
    pub safe: SafeConfig,
    pub remote: RemoteConfig,
    pub asn: AsnConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpsetConfig {
    pub set_name: String,
    pub set_name_v6: String,
    pub enable_ipv6: bool,
    pub chain_action: FirewallAction,
    pub set_type: String,
    pub hashsize: HashsizePow2,
    pub maxelem: MaxElem,
    pub timeout: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallAction {
    Drop,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeConfig {
    pub ips: Vec<CanonicalCidr>,
    pub include_github_meta: bool,
    pub github_meta_url: String,
    pub github_meta_categories: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteConfig {
    pub urls: Vec<String>,
    pub timeout_secs: RemoteTimeoutSecs,
    pub cache_stale_after_secs: RemoteCacheStaleAfterSecs,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsnConfig {
    pub banned: Vec<u32>,
    pub cache_stale_after_secs: AsnCacheStaleAfterSecs,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GithubMetaCategoryMode {
    Default,
    All,
    Explicit(Vec<String>),
}

impl SafeConfig {
    pub fn github_meta_category_mode(&self) -> GithubMetaCategoryMode {
        match &self.github_meta_categories {
            None => GithubMetaCategoryMode::Default,
            Some(values) if values.is_empty() => GithubMetaCategoryMode::All,
            Some(values) => GithubMetaCategoryMode::Explicit(values.clone()),
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConfigError {
    #[error("failed to parse TOML config: {reason}")]
    Parse { reason: String },

    #[error("missing required config section `[ipset]`")]
    MissingIpsetSection,

    #[error("invalid config value for `{field}`: {reason}")]
    InvalidField { field: &'static str, reason: String },
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
    let set_name_v6 = match raw.set_name_v6 {
        Some(value) => {
            let parsed = non_empty(&value, "ipset.set_name_v6")?;
            validate_ipset_set_name(&parsed, "ipset.set_name_v6")?;
            parsed
        }
        None => {
            let derived = format!("{set_name}-v6");
            if enable_ipv6 {
                validate_ipset_set_name(&derived, "ipset.set_name_v6")?;
            }
            derived
        }
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

    let cache_stale_after_secs = bounded_newtype(
        raw.cache_stale_after_secs
            .unwrap_or(i64::from(DEFAULT_REMOTE_CACHE_STALE_AFTER_SECS)),
        "remote.cache_stale_after_secs",
        1,
        REMOTE_CACHE_STALE_AFTER_SECS_MAX,
        format!("must be between 1 and {REMOTE_CACHE_STALE_AFTER_SECS_MAX}"),
        RemoteCacheStaleAfterSecs::new,
    )?;

    Ok(RemoteConfig {
        urls,
        timeout_secs,
        cache_stale_after_secs,
    })
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

fn required_non_empty(value: Option<String>, field: &'static str) -> Result<String, ConfigError> {
    match value {
        Some(value) => non_empty(&value, field),
        None => Err(ConfigError::InvalidField {
            field,
            reason: "value is required".to_string(),
        }),
    }
}

fn non_empty(value: &str, field: &'static str) -> Result<String, ConfigError> {
    let normalized = value.trim().to_string();
    if normalized.is_empty() {
        return Err(ConfigError::InvalidField {
            field,
            reason: "value must not be empty".to_string(),
        });
    }

    Ok(normalized)
}

fn parse_cidr_field_strict(value: &str, field: &'static str) -> Result<CanonicalCidr, ConfigError> {
    let normalized = value.trim();
    if normalized.split_whitespace().count() != 1 {
        return Err(ConfigError::InvalidField {
            field,
            reason: "must be a single IP or CIDR token".to_string(),
        });
    }

    parse_ip_cidr_token(normalized).ok_or_else(|| ConfigError::InvalidField {
        field,
        reason: format!("invalid IP/CIDR token `{normalized}`"),
    })
}

fn bounded_u32(value: i64, field: &'static str, min: u32, max: u32) -> Result<u32, ConfigError> {
    if value < i64::from(min) || value > i64::from(max) {
        return Err(ConfigError::InvalidField {
            field,
            reason: format!("must be between {min} and {max}"),
        });
    }

    u32::try_from(value).map_err(|err| ConfigError::InvalidField {
        field,
        reason: err.to_string(),
    })
}

fn bounded_newtype<T>(
    value: i64,
    field: &'static str,
    min: u32,
    max: u32,
    invalid_reason: String,
    parse: impl FnOnce(u32) -> Option<T>,
) -> Result<T, ConfigError> {
    let value = bounded_u32(value, field, min, max)?;
    parse(value).ok_or(ConfigError::InvalidField {
        field,
        reason: invalid_reason,
    })
}

fn validate_ipset_set_name(value: &str, field: &'static str) -> Result<(), ConfigError> {
    if value.len() > 31 {
        return Err(ConfigError::InvalidField {
            field,
            reason: "must be 31 characters or fewer".to_string(),
        });
    }

    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(ConfigError::InvalidField {
            field,
            reason: "must contain only [A-Za-z0-9_.-]".to_string(),
        });
    }

    Ok(())
}

fn validate_ipset_set_type(value: &str) -> Result<(), ConfigError> {
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b':' | b',' | b'_' | b'-' | b'.')
    }) {
        return Err(ConfigError::InvalidField {
            field: "ipset.set_type",
            reason: "must contain only [A-Za-z0-9:,_-.]".to_string(),
        });
    }

    Ok(())
}

fn validate_http_url(value: &str, field: &'static str) -> Result<(), ConfigError> {
    let parsed = reqwest::Url::parse(value).map_err(|_| ConfigError::InvalidField {
        field,
        reason: "must be a valid http:// or https:// URL with a host".to_string(),
    })?;
    if matches!(parsed.scheme(), "http" | "https") && parsed.host_str().is_some() {
        return Ok(());
    }

    Err(ConfigError::InvalidField {
        field,
        reason: "must be a valid http:// or https:// URL with a host".to_string(),
    })
}

fn parse_chain_action(value: Option<String>) -> Result<FirewallAction, ConfigError> {
    let Some(value) = value else {
        return Ok(DEFAULT_CHAIN_ACTION);
    };

    let normalized = non_empty(&value, "ipset.chain_action")?;
    match normalized.to_ascii_uppercase().as_str() {
        "DROP" => Ok(FirewallAction::Drop),
        "REJECT" => Ok(FirewallAction::Reject),
        _ => Err(ConfigError::InvalidField {
            field: "ipset.chain_action",
            reason: "must be DROP or REJECT".to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use crate::core::network::{CanonicalCidr, Ipv4Cidr};

    use super::{
        ASN_CACHE_STALE_AFTER_SECS_MAX, Config, ConfigError, DEFAULT_ASN_CACHE_STALE_AFTER_SECS,
        DEFAULT_CHAIN_ACTION, DEFAULT_GITHUB_META_CATEGORIES, DEFAULT_GITHUB_META_URL,
        DEFAULT_HASHSIZE, DEFAULT_IPSET_TYPE, DEFAULT_MAXELEM,
        DEFAULT_REMOTE_CACHE_STALE_AFTER_SECS, DEFAULT_REMOTE_TIMEOUT_SECS, DEFAULT_TIMEOUT,
        FirewallAction, GithubMetaCategoryMode,
    };

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
        assert_eq!(
            config.remote.cache_stale_after_secs.get(),
            DEFAULT_REMOTE_CACHE_STALE_AFTER_SECS
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
            vec![CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000001, 32))]
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
    fn remote_cache_stale_after_secs_can_be_overridden() {
        let config = Config::from_toml_str(
            "[ipset]\nset_name='kidobo'\n[remote]\ncache_stale_after_secs=7200\n",
        )
        .expect("parse");
        assert_eq!(config.remote.cache_stale_after_secs.get(), 7200);
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
            vec![CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000001, 32))]
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
            vec![CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000001, 32))]
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
