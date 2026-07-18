use crate::network::{CanonicalCidr, parse_ip_cidr_token};

use crate::config::{ConfigError, DEFAULT_CHAIN_ACTION, FirewallAction};

pub(super) fn required_non_empty(
    value: Option<String>,
    field: &'static str,
) -> Result<String, ConfigError> {
    match value {
        Some(value) => non_empty(&value, field),
        None => Err(ConfigError::InvalidField {
            field,
            reason: "value is required".to_string(),
        }),
    }
}

pub(super) fn non_empty(value: &str, field: &'static str) -> Result<String, ConfigError> {
    let normalized = value.trim().to_string();
    if normalized.is_empty() {
        return Err(ConfigError::InvalidField {
            field,
            reason: "value must not be empty".to_string(),
        });
    }
    Ok(normalized)
}

pub(super) fn parse_cidr_field_strict(
    value: &str,
    field: &'static str,
) -> Result<CanonicalCidr, ConfigError> {
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

pub(super) fn bounded_u32(
    value: i64,
    field: &'static str,
    min: u32,
    max: u32,
) -> Result<u32, ConfigError> {
    if value < i64::from(min) || value > i64::from(max) {
        return Err(ConfigError::InvalidField {
            field,
            reason: format!("must be between {min} and {max}"),
        });
    }
    u32::try_from(value).map_err(|error| ConfigError::InvalidField {
        field,
        reason: error.to_string(),
    })
}

pub(super) fn bounded_newtype<T>(
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

pub(super) fn validate_ipset_set_name(value: &str, field: &'static str) -> Result<(), ConfigError> {
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

pub(super) fn validate_ipset_set_type(value: &str) -> Result<(), ConfigError> {
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

pub(super) fn validate_http_url(value: &str, field: &'static str) -> Result<(), ConfigError> {
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

pub(super) fn parse_chain_action(value: Option<String>) -> Result<FirewallAction, ConfigError> {
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
