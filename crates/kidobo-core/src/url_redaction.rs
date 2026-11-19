//! URL privacy at diagnostic and output boundaries.

use url::Url;

/// Redacts HTTP(S) credentials and complete query/fragment values in embedded URL text.
///
/// Ordinary URLs retain their original spelling, including printable Unicode. Malformed URL
/// tokens are concealed rather than risking disclosure of credentials from invalid user input.
/// Terminal controls are deliberately left to the output encoder so fields are escaped once.
#[must_use]
pub fn redact_urls(value: &str) -> String {
    if Url::parse(value).is_ok_and(|url| matches!(url.scheme(), "http" | "https")) {
        return redact_http_url(value);
    }
    let mut rendered = String::with_capacity(value.len());
    let mut remaining = value;
    while let Some(start) = next_url_start(remaining) {
        let prefix = remaining.get(..start).unwrap_or_default();
        rendered.push_str(prefix);
        let candidate = remaining.get(start..).unwrap_or_default();
        let end = url_token_end(candidate, prefix.chars().next_back());
        let token = candidate.get(..end).unwrap_or_default();
        rendered.push_str(&redact_http_url(token));
        remaining = candidate.get(end..).unwrap_or_default();
    }
    rendered.push_str(remaining);
    rendered
}

fn next_url_start(value: &str) -> Option<usize> {
    value.char_indices().find_map(|(index, character)| {
        if !character.eq_ignore_ascii_case(&'h') {
            return None;
        }
        // URL parsing removes ASCII tabs and newlines even within the scheme.
        let mut bytes = value
            .get(index..)?
            .bytes()
            .filter(|byte| !matches!(byte, b'\t' | b'\r' | b'\n'));
        if !b"http".iter().all(|expected| {
            bytes
                .next()
                .is_some_and(|byte| byte.eq_ignore_ascii_case(expected))
        }) {
            return None;
        }
        match bytes.next()? {
            b':' => Some(index),
            b's' | b'S' if bytes.next() == Some(b':') => Some(index),
            _ => None,
        }
    })
}

fn url_token_end(value: &str, preceding: Option<char>) -> usize {
    let closing = match preceding {
        Some('(') => Some(')'),
        Some('[') => Some(']'),
        Some('{') => Some('}'),
        Some('<') => Some('>'),
        Some(quote @ ('\'' | '"' | '`')) => Some(quote),
        _ => None,
    };
    let mut brackets = 0_usize;
    let mut parentheses = 0_usize;
    for (index, character) in value.char_indices() {
        if closing == Some(character)
            && (character != ']' || brackets == 0)
            && (character != ')' || parentheses == 0)
        {
            return index;
        }
        if closing.is_none()
            && ((character.is_whitespace() && !matches!(character, '\t' | '\r' | '\n'))
                || matches!(character, '\'' | '"' | '`' | '<' | '>'))
        {
            return index;
        }
        match character {
            '[' => brackets += 1,
            ']' => brackets = brackets.saturating_sub(1),
            '(' => parentheses += 1,
            ')' => parentheses = parentheses.saturating_sub(1),
            _ => {}
        }
    }
    value.len()
}

/// Formats one complete configured HTTP(S) URL for display before it enters a diagnostic.
#[must_use]
pub fn redact_http_url(token: &str) -> String {
    let Ok(mut url) = Url::parse(token) else {
        return "[redacted URL]".to_string();
    };
    if nested_url_has_sensitive_parts(token) {
        return "[redacted URL]".to_string();
    }
    let has_credentials = !url.username().is_empty() || url.password().is_some();
    if !has_credentials && url.query().is_none() && url.fragment().is_none() {
        return token.to_string();
    }
    if has_credentials && (url.set_username("REDACTED").is_err() || url.set_password(None).is_err())
    {
        return "[redacted URL]".to_string();
    }
    if url.query().is_some() {
        url.set_query(Some("REDACTED"));
    }
    if url.fragment().is_some() {
        url.set_fragment(Some("REDACTED"));
    }
    url.into()
}

fn nested_url_has_sensitive_parts(token: &str) -> bool {
    let after_scheme = |text: &str| text.find(':').map_or(text.len(), |index| index + 1);
    let mut remaining = token.get(after_scheme(token)..).unwrap_or_default();
    while let Some(start) = next_url_start(remaining) {
        let nested = remaining.get(start..).unwrap_or_default();
        match Url::parse(nested) {
            Ok(url)
                if url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none() => {}
            _ => return true,
        }
        remaining = nested.get(after_scheme(nested)..).unwrap_or_default();
    }
    false
}
