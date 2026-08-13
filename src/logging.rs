use std::env;
use std::io::{IsTerminal, Write};

use env_logger::WriteStyle;
use log::LevelFilter;

use crate::error::KidoboError;

/// Initializes process-wide logging at the requested level.
///
/// # Errors
///
/// Returns [`KidoboError::LoggerInit`] if a logger has already been initialized or the logger
/// otherwise cannot be installed.
pub fn init(level: LevelFilter) -> Result<(), KidoboError> {
    let stderr_is_terminal = std::io::stderr().is_terminal();
    let no_color_set = env::var_os("NO_COLOR").is_some();
    let mut builder = env_logger::Builder::new();
    builder.filter_level(level);
    let format = select_log_format(
        env::var_os("KIDOBO_LOG_FORMAT").as_deref(),
        stderr_is_terminal,
        running_under_systemd(),
    );
    let color_mode = select_log_color_mode(env::var_os("KIDOBO_LOG_COLOR").as_deref());
    builder.write_style(match format {
        LogFormat::Human => write_style_for_color_mode(color_mode),
        LogFormat::Journal => WriteStyle::Never,
    });
    let color_enabled = format == LogFormat::Human
        && should_use_human_color(color_mode, stderr_is_terminal, no_color_set);
    builder.format(move |buf, record| match format {
        LogFormat::Human => {
            let level = format_human_level(record.level(), color_enabled);
            writeln!(buf, "{level}: {}", record.args())
        }
        LogFormat::Journal => writeln!(buf, "level={} msg={}", record.level(), record.args()),
    });
    builder.try_init().map_err(|err| KidoboError::LoggerInit {
        reason: err.to_string(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogFormat {
    Human,
    Journal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogColorMode {
    Auto,
    Always,
    Never,
}

fn running_under_systemd() -> bool {
    env::var_os("INVOCATION_ID").is_some() || env::var_os("JOURNAL_STREAM").is_some()
}

fn select_log_format(
    configured: Option<&std::ffi::OsStr>,
    stderr_is_terminal: bool,
    under_systemd: bool,
) -> LogFormat {
    match configured
        .and_then(|value| value.to_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(value) if value.eq_ignore_ascii_case("human") => LogFormat::Human,
        Some(value) if value.eq_ignore_ascii_case("journal") => LogFormat::Journal,
        Some(value) if value.eq_ignore_ascii_case("auto") => {
            auto_log_format(stderr_is_terminal, under_systemd)
        }
        Some(_) | None => auto_log_format(stderr_is_terminal, under_systemd),
    }
}

fn auto_log_format(stderr_is_terminal: bool, under_systemd: bool) -> LogFormat {
    if under_systemd || !stderr_is_terminal {
        LogFormat::Journal
    } else {
        LogFormat::Human
    }
}

fn select_log_color_mode(configured: Option<&std::ffi::OsStr>) -> LogColorMode {
    match configured
        .and_then(|value| value.to_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(value) if value.eq_ignore_ascii_case("always") => LogColorMode::Always,
        Some(value) if value.eq_ignore_ascii_case("never") => LogColorMode::Never,
        Some(value) if value.eq_ignore_ascii_case("auto") => LogColorMode::Auto,
        Some(_) | None => LogColorMode::Auto,
    }
}

fn should_use_human_color(
    mode: LogColorMode,
    stderr_is_terminal: bool,
    no_color_set: bool,
) -> bool {
    match mode {
        LogColorMode::Always => true,
        LogColorMode::Never => false,
        LogColorMode::Auto => stderr_is_terminal && !no_color_set,
    }
}

fn write_style_for_color_mode(mode: LogColorMode) -> WriteStyle {
    match mode {
        LogColorMode::Always => WriteStyle::Always,
        LogColorMode::Never => WriteStyle::Never,
        LogColorMode::Auto => WriteStyle::Auto,
    }
}

fn format_human_level(level: log::Level, color_enabled: bool) -> String {
    if !color_enabled {
        return level.to_string();
    }

    let color_code = match level {
        log::Level::Error => "31",
        log::Level::Warn => "33",
        log::Level::Info => "32",
        log::Level::Debug => "36",
        log::Level::Trace => "90",
    };

    format!("\x1b[{color_code}m{level}\x1b[0m")
}

#[cfg(test)]
mod tests {
    use env_logger::WriteStyle;
    use log::LevelFilter;

    use super::{
        LogColorMode, LogFormat, auto_log_format, format_human_level, init, select_log_color_mode,
        select_log_format, should_use_human_color, write_style_for_color_mode,
    };
    use crate::error::KidoboError;

    #[test]
    fn repeated_init_reports_logger_init_error() {
        let _ = init(LevelFilter::Off);

        let err = init(LevelFilter::Off).expect_err("second init must fail");
        match err {
            KidoboError::LoggerInit { reason } => assert!(!reason.is_empty()),
            _ => panic!("expected logger init error"),
        }
    }

    #[test]
    fn auto_format_prefers_journal_for_non_tty_or_systemd() {
        assert_eq!(auto_log_format(false, false), LogFormat::Journal);
        assert_eq!(auto_log_format(true, true), LogFormat::Journal);
    }

    #[test]
    fn auto_format_uses_human_for_interactive_non_systemd() {
        assert_eq!(auto_log_format(true, false), LogFormat::Human);
    }

    #[test]
    fn explicit_format_overrides_auto_detection() {
        assert_eq!(
            select_log_format(Some("human".as_ref()), false, true),
            LogFormat::Human
        );
        assert_eq!(
            select_log_format(Some("journal".as_ref()), true, false),
            LogFormat::Journal
        );
    }

    #[test]
    fn invalid_or_missing_config_falls_back_to_auto() {
        assert_eq!(select_log_format(None, true, false), LogFormat::Human);
        assert_eq!(
            select_log_format(Some("unknown".as_ref()), true, true),
            LogFormat::Journal
        );
    }

    #[test]
    fn color_is_disabled_when_not_terminal() {
        assert!(!should_use_human_color(LogColorMode::Auto, false, false));
    }

    #[test]
    fn color_mode_parsing_accepts_auto_always_never() {
        assert_eq!(
            select_log_color_mode(Some("auto".as_ref())),
            LogColorMode::Auto
        );
        assert_eq!(
            select_log_color_mode(Some("always".as_ref())),
            LogColorMode::Always
        );
        assert_eq!(
            select_log_color_mode(Some("never".as_ref())),
            LogColorMode::Never
        );
        assert_eq!(
            select_log_color_mode(Some("invalid".as_ref())),
            LogColorMode::Auto
        );
    }

    #[test]
    fn always_mode_forces_color_even_without_tty() {
        assert!(should_use_human_color(LogColorMode::Always, false, true));
    }

    #[test]
    fn never_mode_disables_color_even_with_tty() {
        assert!(!should_use_human_color(LogColorMode::Never, true, false));
    }

    #[test]
    fn auto_mode_respects_no_color() {
        assert!(!should_use_human_color(LogColorMode::Auto, true, true));
        assert!(should_use_human_color(LogColorMode::Auto, true, false));
    }

    #[test]
    fn human_level_format_supports_plain_and_ansi_color_modes() {
        assert_eq!(format_human_level(log::Level::Info, false), "INFO");
        assert_eq!(
            format_human_level(log::Level::Info, true),
            "\u{1b}[32mINFO\u{1b}[0m"
        );
    }

    #[test]
    fn write_style_tracks_color_mode() {
        assert!(matches!(
            write_style_for_color_mode(LogColorMode::Auto),
            WriteStyle::Auto
        ));
        assert!(matches!(
            write_style_for_color_mode(LogColorMode::Always),
            WriteStyle::Always
        ));
        assert!(matches!(
            write_style_for_color_mode(LogColorMode::Never),
            WriteStyle::Never
        ));
    }
}
