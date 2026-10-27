//! Shared, terminal-safe human presentation primitives.

use std::io::{self, Write};

use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;
use url::Url;

/// Semantic status whose meaning remains visible without color.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    Warn,
    Fail,
    Skip,
    Unknown,
}

impl Status {
    fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
            Self::Skip => "SKIP",
            Self::Unknown => "UNKNOWN",
        }
    }

    fn color(self) -> &'static str {
        match self {
            Self::Pass => "32",
            Self::Warn => "33",
            Self::Fail => "31",
            Self::Skip | Self::Unknown => "36",
        }
    }
}

/// Destination capabilities supplied by the CLI rather than detected while rendering.
#[derive(Debug, Clone, Copy)]
pub struct Presentation {
    width: usize,
    color: bool,
}

impl Presentation {
    /// Creates a renderer, with an 80-column fallback for an unavailable width.
    pub fn new(width: usize, color: bool) -> Self {
        Self {
            width: if width == 0 { 80 } else { width },
            color,
        }
    }

    /// Writes a restrained heading, escaping any supplied terminal controls.
    pub fn heading(self, output: &mut dyn Write, title: &str) -> io::Result<()> {
        for line in wrap(title, self.width) {
            if self.color {
                writeln!(output, "\x1b[1m{line}\x1b[0m")?;
            } else {
                writeln!(output, "{line}")?;
            }
        }
        Ok(())
    }

    /// Writes text within the destination width without interpreting embedded controls.
    pub fn paragraph(self, output: &mut dyn Write, text: &str) -> io::Result<()> {
        for line in wrap(text, self.width) {
            writeln!(output, "{line}")?;
        }
        Ok(())
    }

    /// Writes aligned key/value rows, stacking labels when space is insufficient.
    pub fn key_values(self, output: &mut dyn Write, fields: &[(&str, &str)]) -> io::Result<()> {
        let label_width = fields
            .iter()
            .map(|(label, _)| UnicodeWidthStr::width(encode_human(label).as_str()))
            .max()
            .unwrap_or(0);
        for (label, value) in fields {
            let label = encode_human(label);
            if label_width + 6 >= self.width || label_width > 24 {
                for line in wrap_encoded(&format!("{label}:"), self.width) {
                    writeln!(output, "{line}")?;
                }
                for line in wrap(value, self.width.saturating_sub(2)) {
                    writeln!(output, "  {line}")?;
                }
            } else {
                let indent = label_width + 4;
                for (index, line) in wrap(value, self.width.saturating_sub(indent))
                    .into_iter()
                    .enumerate()
                {
                    if index == 0 {
                        let padding = " ".repeat(
                            label_width.saturating_sub(UnicodeWidthStr::width(label.as_str())),
                        );
                        writeln!(output, "  {label}:{padding} {line}")?;
                    } else {
                        writeln!(output, "{}{line}", " ".repeat(indent))?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Writes one streaming record without collecting other records.
    pub fn record(self, output: &mut dyn Write, fields: &[(&str, &str)]) -> io::Result<()> {
        self.key_values(output, fields)
    }

    /// Writes a named check and its evidence, with a plain-text status in every mode.
    pub fn status(
        self,
        output: &mut dyn Write,
        status: Status,
        label: &str,
        detail: &str,
    ) -> io::Result<()> {
        let prefix = format!("[{}]", status.label());
        let indent = prefix.len() + 1;
        for (index, label) in wrap(label, self.width.saturating_sub(indent))
            .into_iter()
            .enumerate()
        {
            if index > 0 {
                writeln!(output, "{}{label}", " ".repeat(indent))?;
            } else if self.color {
                writeln!(output, "\x1b[{}m{prefix}\x1b[0m {label}", status.color())?;
            } else {
                writeln!(output, "{prefix} {label}")?;
            }
        }
        for line in wrap(detail, self.width.saturating_sub(2)) {
            writeln!(output, "  {line}")?;
        }
        Ok(())
    }

    /// Writes a compact table, or labeled records when its full columns cannot fit.
    pub fn table(
        self,
        output: &mut dyn Write,
        headers: &[&str],
        rows: &[Vec<String>],
    ) -> io::Result<()> {
        if rows.iter().any(|row| row.len() != headers.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "table rows must have one value per header",
            ));
        }
        let headers = headers
            .iter()
            .map(|header| encode_human(header))
            .collect::<Vec<_>>();
        let rows = rows
            .iter()
            .map(|row| {
                row.iter()
                    .map(|cell| encode_human(cell))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let widths = headers
            .iter()
            .enumerate()
            .map(|(index, header)| {
                rows.iter()
                    .filter_map(|row| row.get(index))
                    .map(|cell| UnicodeWidthStr::width(cell.as_str()))
                    .chain(std::iter::once(UnicodeWidthStr::width(header.as_str())))
                    .max()
                    .unwrap_or(0)
            })
            .collect::<Vec<_>>();
        let total_width =
            widths.iter().sum::<usize>() + headers.len().saturating_sub(1).saturating_mul(2);
        if total_width <= self.width {
            write_table_line(output, &headers, &widths)?;
            for row in rows {
                write_table_line(output, &row, &widths)?;
            }
        } else {
            for (index, row) in rows.iter().enumerate() {
                if index > 0 {
                    writeln!(output)?;
                }
                for (header, cell) in headers.iter().zip(row) {
                    write_encoded_field(output, header, cell, self.width)?;
                }
            }
        }
        Ok(())
    }

    /// Writes an actionable command hint.
    pub fn next(self, output: &mut dyn Write, command: &str) -> io::Result<()> {
        self.paragraph(output, &format!("Next: {command}"))
    }
}

fn write_table_line(output: &mut dyn Write, cells: &[String], widths: &[usize]) -> io::Result<()> {
    for (index, (cell, width)) in cells.iter().zip(widths).enumerate() {
        if index > 0 {
            write!(output, "  ")?;
        }
        write!(output, "{cell}")?;
        if index + 1 < cells.len() {
            write!(
                output,
                "{}",
                " ".repeat(width.saturating_sub(UnicodeWidthStr::width(cell.as_str())))
            )?;
        }
    }
    writeln!(output)
}

fn write_encoded_field(
    output: &mut dyn Write,
    label: &str,
    value: &str,
    width: usize,
) -> io::Result<()> {
    for line in wrap_encoded(&format!("{label}: {value}"), width.saturating_sub(2)) {
        writeln!(output, "  {line}")?;
    }
    Ok(())
}

/// Encodes control characters exactly as the compatibility-sensitive lookup TSV boundary does.
pub fn escape(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => encoded.push_str("\\\\"),
            '\t' => encoded.push_str("\\t"),
            '\r' => encoded.push_str("\\r"),
            '\n' => encoded.push_str("\\n"),
            character if character.is_ascii_control() => {
                use std::fmt::Write as _;
                let _write_result = write!(encoded, "\\x{:02X}", u32::from(character));
            }
            character if character.is_control() => {
                use std::fmt::Write as _;
                let _write_result = write!(encoded, "\\u{{{:X}}}", u32::from(character));
            }
            character => encoded.push(character),
        }
    }
    encoded
}

/// Escapes text once and wraps it without splitting Unicode grapheme clusters.
pub fn wrap(value: &str, width: usize) -> Vec<String> {
    wrap_encoded(&encode_human(value), width)
}

fn encode_human(value: &str) -> String {
    escape(&redact_urls(value))
}

/// Redacts HTTP(S) credentials and complete query/fragment values in embedded URL text.
///
/// Ordinary URLs retain their original spelling, including printable Unicode. Malformed URL
/// tokens are concealed rather than risking disclosure of credentials from invalid user input.
/// Terminal controls are deliberately left to the output encoder so fields are escaped once.
pub fn redact_urls(value: &str) -> String {
    if next_url_start(value) == Some(0) && Url::parse(value).is_ok() {
        return redact_url_token(value);
    }
    let mut rendered = String::with_capacity(value.len());
    let mut remaining = value;
    while let Some(start) = next_url_start(remaining) {
        let prefix = remaining.get(..start).unwrap_or_default();
        rendered.push_str(prefix);
        let candidate = remaining.get(start..).unwrap_or_default();
        let end = url_token_end(candidate, prefix.chars().next_back());
        let token = candidate.get(..end).unwrap_or_default();
        rendered.push_str(&redact_url_token(token));
        remaining = candidate.get(end..).unwrap_or_default();
    }
    rendered.push_str(remaining);
    rendered
}

fn next_url_start(value: &str) -> Option<usize> {
    value.char_indices().find_map(|(index, _)| {
        let suffix = value.get(index..)?;
        (suffix
            .get(..7)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
            || suffix
                .get(..8)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://")))
        .then_some(index)
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
            && (character.is_whitespace() || matches!(character, '\'' | '"' | '`' | '<' | '>'))
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

fn redact_url_token(token: &str) -> String {
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
    let scheme_length = |text: &str| {
        if text
            .get(..7)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
        {
            7
        } else {
            8
        }
    };
    let mut remaining = token.get(scheme_length(token)..).unwrap_or_default();
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
        remaining = nested.get(scheme_length(nested)..).unwrap_or_default();
    }
    false
}

fn wrap_encoded(value: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in value.split_whitespace() {
        let word_width = UnicodeWidthStr::width(word);
        let line_width = UnicodeWidthStr::width(line.as_str());
        if !line.is_empty() && line_width + 1 + word_width <= width {
            line.push(' ');
            line.push_str(word);
            continue;
        }
        if !line.is_empty() {
            lines.push(std::mem::take(&mut line));
        }
        if word_width <= width {
            line.push_str(word);
            continue;
        }
        for grapheme in word.graphemes(true) {
            if !line.is_empty()
                && UnicodeWidthStr::width(line.as_str()) + UnicodeWidthStr::width(grapheme) > width
            {
                lines.push(std::mem::take(&mut line));
            }
            line.push_str(grapheme);
        }
    }
    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    lines
}

/// Automatic human-output color policy. Explicit legacy logging overrides remain separate.
pub const fn color_enabled(terminal: bool, no_color: bool, term_dumb: bool) -> bool {
    terminal && !no_color && !term_dumb
}

/// Formats a canonical Unix timestamp as an explicitly labeled UTC date and time.
pub fn format_utc(unix_seconds: u64) -> String {
    i64::try_from(unix_seconds)
        .ok()
        .and_then(|seconds| jiff::Timestamp::from_second(seconds).ok())
        .map_or_else(
            || format!("Unix {unix_seconds} (outside display range)"),
            |timestamp| timestamp.strftime("%Y-%m-%d %H:%M:%S UTC").to_string(),
        )
}

/// Formats remaining saved lifetime without implying that kernel enforcement has changed.
pub fn remaining_duration(expires_at: u64, now: u64) -> String {
    let seconds = expires_at.saturating_sub(now);
    match seconds {
        0 => "expired".to_string(),
        1..60 => format!("{seconds}s remaining"),
        60..3600 => format!("{}m remaining", seconds / 60),
        3600..86400 => format!("{}h {}m remaining", seconds / 3600, seconds % 3600 / 60),
        _ => format!("{}d {}h remaining", seconds / 86400, seconds % 86400 / 3600),
    }
}

#[cfg(test)]
mod tests {
    use unicode_width::UnicodeWidthStr;

    use super::{
        Presentation, Status, color_enabled, escape, format_utc, redact_urls, remaining_duration,
        wrap,
    };

    #[test]
    fn lookup_encoding_is_preserved_and_controls_cannot_add_records() {
        assert_eq!(
            escape("é\\\t\r\n\u{1b}[31m\u{7f}\u{85}"),
            "é\\\\\\t\\r\\n\\x1B[31m\\x7F\\u{85}"
        );
    }

    #[test]
    fn wrapping_retains_graphemes_and_measures_display_columns() {
        assert_eq!(wrap("界界界", 4), vec!["界界", "界"]);
        assert_eq!(
            wrap("e\u{301}e\u{301}e\u{301}", 2),
            vec!["e\u{301}e\u{301}", "e\u{301}"]
        );
        assert_eq!(wrap("👨‍👩‍👧‍👦👨‍👩‍👧‍👦", 2), vec!["👨‍👩‍👧‍👦", "👨‍👩‍👧‍👦"]);
        assert_eq!(wrap("one two three", 7), vec!["one two", "three"]);
        assert_eq!(wrap("", 0), vec![""]);
    }

    #[test]
    fn table_layouts_have_stable_narrow_and_wide_golden_output() {
        let headers = ["Target", "Source", "State"];
        let rows = vec![vec![
            "2001:db8:1234:5678:9abc:def0:1234:5678".to_string(),
            "operator blocklist".to_string(),
            "saved".to_string(),
        ]];
        for width in [60, 80, 120] {
            let mut output = Vec::new();
            Presentation::new(width, false)
                .table(&mut output, &headers, &rows)
                .expect("table");
            let output = String::from_utf8(output).expect("UTF-8");
            let expected = if width == 60 {
                "  Target: 2001:db8:1234:5678:9abc:def0:1234:5678\n  Source: operator blocklist\n  State: saved\n".to_string()
            } else {
                format!(
                    "Target{}Source{}State\n2001:db8:1234:5678:9abc:def0:1234:5678  operator blocklist  saved\n",
                    " ".repeat(34),
                    " ".repeat(14)
                )
            };
            assert_eq!(output, expected, "width {width}");
            assert!(
                output
                    .lines()
                    .all(|line| UnicodeWidthStr::width(line) <= width)
            );
        }
    }

    #[test]
    fn key_values_wrap_and_align_unicode_labels_without_losing_evidence() {
        let mut output = Vec::new();
        Presentation::new(24, false)
            .record(
                &mut output,
                &[
                    ("状態", "a long value with detail"),
                    ("Path", "/etc/kidobo"),
                ],
            )
            .expect("record");
        assert_eq!(
            String::from_utf8(output).expect("UTF-8"),
            "  状態: a long value\n        with detail\n  Path: /etc/kidobo\n"
        );
    }

    #[test]
    fn colored_status_never_interprets_untrusted_control_sequences() {
        let mut output = Vec::new();
        let presentation = Presentation::new(60, true);
        presentation
            .heading(&mut output, "Checks")
            .expect("heading");
        for status in [
            Status::Pass,
            Status::Warn,
            Status::Fail,
            Status::Skip,
            Status::Unknown,
        ] {
            presentation
                .status(&mut output, status, "feed\nFAKE", "\u{1b}]0;bad\u{7}")
                .expect("status");
        }
        presentation
            .next(&mut output, "sudo kidobo sync")
            .expect("next");
        let output = String::from_utf8(output).expect("UTF-8");
        assert!(output.starts_with("\u{1b}[1mChecks\u{1b}[0m\n"));
        assert!(output.contains("[PASS]\u{1b}[0m feed\\nFAKE\n  \\x1B]0;bad\\x07"));
        assert!(!output.contains("\u{1b}]"));
        assert!(output.ends_with("Next: sudo kidobo sync\n"));
    }

    #[test]
    fn empty_or_inconsistent_tables_are_handled_without_losing_cells() {
        let mut output = Vec::new();
        Presentation::new(0, false)
            .table(&mut output, &[], &[])
            .expect("empty table");
        assert_eq!(output, b"\n");
        let error = Presentation::new(80, false)
            .table(&mut output, &["Name"], &[vec![]])
            .expect_err("missing cell");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn table_cells_are_encoded_exactly_once_in_both_layouts() {
        for width in [12, 80] {
            let mut output = Vec::new();
            Presentation::new(width, false)
                .table(
                    &mut output,
                    &["Source", "State"],
                    &[vec!["\u{1b}[31m".to_string(), "saved".to_string()]],
                )
                .expect("table");
            let output = String::from_utf8(output).expect("UTF-8");
            assert!(output.contains("\\x1B[31m"));
            assert!(!output.contains("\\\\x1B[31m"));
            assert!(!output.contains('\u{1b}'));
        }
    }

    #[test]
    fn automatic_color_obeys_destination_and_accessibility_controls() {
        assert!(color_enabled(true, false, false));
        assert!(!color_enabled(false, false, false));
        assert!(!color_enabled(true, true, false));
        assert!(!color_enabled(true, false, true));
    }

    #[test]
    fn expiry_is_readable_utc_with_safe_out_of_range_fallback() {
        assert_eq!(format_utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(
            format_utc(u64::MAX),
            format!("Unix {} (outside display range)", u64::MAX)
        );
        assert_eq!(remaining_duration(10, 10), "expired");
        assert_eq!(remaining_duration(11, 10), "1s remaining");
        assert_eq!(remaining_duration(125, 5), "2m remaining");
        assert_eq!(remaining_duration(3660, 0), "1h 1m remaining");
        assert_eq!(remaining_duration(90000, 0), "1d 1h remaining");
    }

    #[test]
    fn ordinary_urls_and_printable_unicode_keep_their_original_spelling() {
        for value in [
            "feed https://EXAMPLE.org/界/fe\u{301}ed.txt failed",
            "HTTP://EXAMPLE.org/a%2Fb",
            "https://example.org/path/https://other.example/plain",
            "https://example.org/界\u{1b}[31m",
        ] {
            assert_eq!(redact_urls(value), value);
        }
        assert_eq!(
            wrap("https://example.org/界\u{1b}[31m", 80),
            vec!["https://example.org/界\\x1B[31m"]
        );
    }

    #[test]
    fn url_credentials_and_all_query_and_fragment_contents_are_redacted() {
        let input = "https://alice:secret%20password@example.org/feed?token=first value&other=second#fragment-secret";
        assert_eq!(
            redact_urls(input),
            "https://REDACTED@example.org/feed?REDACTED#REDACTED"
        );
        assert_eq!(
            redact_urls("HTTPS://alice:password@example.org/?bare-secret#section-secret"),
            "https://REDACTED@example.org/?REDACTED#REDACTED"
        );
        assert_eq!(
            escape(input),
            input,
            "the exact TSV encoder must not redact fields"
        );
    }

    #[test]
    fn embedded_urls_preserve_error_context_without_exposing_nested_credentials() {
        let input = "request (`https://alice:password@example.org/feed?token=secret#fragment`): failed; source 'http://bob:secret@[2001:db8::1]/feed' returned 403";
        assert_eq!(
            redact_urls(input),
            "request (`https://REDACTED@example.org/feed?REDACTED#REDACTED`): failed; source 'http://REDACTED@[2001:db8::1]/feed' returned 403"
        );
        let nested = "https://public.example/proxy/https://alice:password@private.example/feed";
        assert_eq!(redact_urls(nested), "[redacted URL]");
        let query = "source 'https://outer.example/?next=https://alice:password@inner.example/?key=secret': failed";
        let rendered = redact_urls(query);
        assert_eq!(rendered, "source '[redacted URL]': failed");
        assert_eq!(redact_urls(&rendered), rendered);
    }

    #[test]
    fn malformed_url_tokens_cannot_disclose_potential_credentials() {
        for input in [
            "https://alice:password@",
            "https://alice:password@example.org:invalid/feed?token=secret#fragment",
        ] {
            assert_eq!(redact_urls(input), "[redacted URL]");
        }
        assert_eq!(
            redact_urls(
                "invalid 'https://us er:secret pass@example .org/feed?token=secret value#fragment value': invalid host"
            ),
            "invalid '[redacted URL]': invalid host"
        );
    }

    #[test]
    fn human_rows_redact_urls_before_the_single_control_encoding_boundary() {
        let input = "https://alice:password@example.org/feed?token=secret#fragment";
        let mut output = Vec::new();
        let view = Presentation::new(60, false);
        view.key_values(&mut output, &[("Source", input)])
            .expect("key/value rows");
        view.table(&mut output, &["URL"], &[vec![input.to_string()]])
            .expect("table");
        let output = String::from_utf8(output).expect("UTF-8");
        for secret in ["alice", "password", "token=secret", "fragment"] {
            assert!(!output.contains(secret), "leaked {secret}: {output}");
        }
        assert!(output.contains("https://REDACTED@example.org/feed?REDACTED#REDACTED"));
    }
}
