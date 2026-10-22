//! Deterministic parsing and normalization of autonomous-system identities.

use thiserror::Error;

/// An operator token is not a positive `u32` autonomous-system number.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid ASN token `{input}`")]
pub struct AsnTokenError {
    /// Original operator input retained for diagnostics.
    pub input: String,
}

/// Parses a positive ASN with an optional ASCII case-insensitive `AS` prefix.
///
/// # Errors
///
/// Returns [`AsnTokenError`] when the input is empty, malformed, zero, or outside `u32`.
pub fn parse_asn_token(input: &str) -> Result<u32, AsnTokenError> {
    let trimmed = input.trim();
    let normalized = trimmed
        .strip_prefix(['A', 'a'])
        .and_then(|remainder| remainder.strip_prefix(['S', 's']))
        .unwrap_or(trimmed);
    normalized
        .parse::<u32>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| AsnTokenError {
            input: input.to_owned(),
        })
}

/// Parses, sorts, and deduplicates operator-supplied ASN tokens.
///
/// # Errors
///
/// Returns [`AsnTokenError`] for the first invalid token, preserving its original text.
pub fn normalize_asn_tokens<I, S>(tokens: I) -> Result<Vec<u32>, AsnTokenError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut normalized = tokens
        .into_iter()
        .map(|token| parse_asn_token(token.as_ref()))
        .collect::<Result<Vec<_>, _>>()?;
    normalized.sort_unstable();
    normalized.dedup();
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::{AsnTokenError, normalize_asn_tokens, parse_asn_token};

    #[test]
    fn parse_asn_token_accepts_bare_and_every_case_of_as_prefix() {
        for token in [
            "213412",
            "AS213412",
            "as213412",
            "As213412",
            "aS213412",
            "  As213412  ",
        ] {
            assert_eq!(parse_asn_token(token).expect("valid ASN"), 213_412);
        }
        assert_eq!(parse_asn_token("AS1").expect("minimum"), 1);
        assert_eq!(parse_asn_token("4294967295").expect("maximum"), u32::MAX);
        assert_eq!(
            parse_asn_token("+42").expect("existing accepted syntax"),
            42
        );
    }

    #[test]
    fn normalize_asn_tokens_deduplicates_and_sorts() {
        assert_eq!(
            normalize_asn_tokens(["AS64513", "64512", "aS64513", "As64512"]).expect("valid tokens"),
            [64512, 64513]
        );
        assert_eq!(
            normalize_asn_tokens::<[&str; 0], &str>([]).expect("empty"),
            []
        );
    }

    #[test]
    fn invalid_tokens_retain_the_original_input_and_diagnostic() {
        for token in [
            "",
            "   ",
            "AS0",
            "0",
            "AS",
            "A",
            "S1",
            "AS-1",
            "4294967296",
            "AS1 trailing",
            "ＡＳ1",
        ] {
            let error = parse_asn_token(token).expect_err("invalid token");
            assert_eq!(
                error,
                AsnTokenError {
                    input: token.to_owned()
                }
            );
            assert_eq!(error.to_string(), format!("invalid ASN token `{token}`"));
        }
        assert_eq!(
            normalize_asn_tokens(["AS42", "bad", "also bad"]),
            Err(AsnTokenError {
                input: "bad".to_owned()
            })
        );
    }
}
