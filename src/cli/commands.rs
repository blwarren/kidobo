use std::collections::BTreeSet;
use std::env;
use std::io::IsTerminal;
use std::path::PathBuf;

use log::warn;

use crate::adapters::config::load_config_from_file;
use crate::adapters::limited_io::read_to_string_with_limit;
use crate::adapters::lookup_sources::load_lookup_sources;
use crate::adapters::path::{PathResolutionInput, resolve_paths_without_config};
use crate::cli::args::{Command, LookupFormat};
use crate::cli::blocklist::{run_ban_command, run_unban_command};
use crate::cli::doctor::run_doctor_command;
use crate::cli::flush::run_flush_command;
use crate::cli::init::run_init_command;
use crate::cli::sync::run_sync_command;
use crate::core::lookup::{parse_target_strict, run_lookup_by_target, run_lookup_streaming};
use crate::error::KidoboError;

const LOOKUP_TARGET_READ_LIMIT: usize = 2 * 1024 * 1024;

pub fn dispatch(command: Command) -> Result<(), KidoboError> {
    match command {
        Command::Init => run_init_command(),
        Command::Doctor => run_doctor_command(),
        Command::Sync { timer } => run_sync_command(timer),
        Command::Flush { cache_only } => run_flush_command(cache_only),
        Command::Lookup { ip, file, format } => run_lookup_command(ip, file, format),
        Command::Ban { target, file, asn } => {
            run_ban_command(target.as_deref(), file.as_deref(), asn.as_deref())
        }
        Command::Unban {
            target,
            file,
            asn,
            yes,
        } => run_unban_command(target.as_deref(), file.as_deref(), asn.as_deref(), yes),
    }
}

#[allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "CLI command writes results and diagnostics to the terminal"
)]
fn run_lookup_command(
    ip: Option<String>,
    file: Option<PathBuf>,
    format: LookupFormat,
) -> Result<(), KidoboError> {
    let file_mode = file.is_some();
    let targets = collect_lookup_targets(ip, file)?;

    let path_input = PathResolutionInput::from_process(None);
    let paths = resolve_paths_without_config(&path_input)?;
    // Config-backed lookup sources are additive. Preserve lookup's compatibility
    // path when config is missing or invalid so local and remote cache inspection
    // remains available during config recovery.
    let config = match load_config_from_file(&paths.config_file) {
        Ok(config) => Some(config),
        Err(err) => {
            warn!(
                "lookup config-backed sources unavailable; checking only local and cached remote sources: {err}"
            );
            None
        }
    };
    let sources = load_lookup_sources(&paths, config.as_ref())?;

    let invalid_targets = match format {
        LookupFormat::Human => print_human_lookup(&targets, &sources),
        LookupFormat::Tsv => print_tsv_lookup(&targets, &sources, file_mode),
    };

    for invalid in &invalid_targets {
        eprintln!("invalid target: {invalid}");
    }

    if !invalid_targets.is_empty() {
        return Err(KidoboError::LookupInvalidTargets {
            count: invalid_targets.len(),
        });
    }

    Ok(())
}

const LOOKUP_TARGET_WIDTH: usize = 30;
const LOOKUP_STATUS_WIDTH: usize = 8;
const LOOKUP_SOURCE_WIDTH: usize = 44;
const LOOKUP_ENTRY_WIDTH: usize = 30;

#[allow(
    clippy::print_stdout,
    reason = "CLI command writes its report to standard output"
)]
fn print_human_lookup(
    targets: &[String],
    sources: &[crate::core::lookup::LookupSourceEntry],
) -> Vec<String> {
    let color = should_color_lookup(
        std::io::stdout().is_terminal(),
        env::var_os("NO_COLOR").is_some(),
    );
    print_lookup_table_border('┌', '┬', '┐');
    print_lookup_table_row(["Target", "Status", "Source", "Matched Entry"], false);
    print_lookup_table_border('├', '┼', '┤');

    let mut total_count = 0_usize;
    let mut matched_count = 0_usize;
    let invalid_targets = run_lookup_by_target(targets, sources, |target, matches| {
        total_count += 1;
        if matches.is_empty() {
            print_lookup_table_row([target, "NO MATCH", "—", "—"], color);
        } else {
            matched_count += 1;
            for source in matches {
                print_lookup_table_row(
                    [
                        target,
                        "MATCH",
                        source.source_label.as_ref(),
                        &source.source_line,
                    ],
                    color,
                );
            }
        }
    });

    print_lookup_table_border('└', '┴', '┘');
    let unmatched_count = total_count.saturating_sub(matched_count);
    println!();
    println!("Summary");
    println!("  Targets:    {total_count}");
    println!("  Matched:    {matched_count}");
    println!("  Unmatched:  {unmatched_count}");
    println!("  Match rate: {}", percent_str(matched_count, total_count));

    invalid_targets
}

#[allow(
    clippy::print_stdout,
    reason = "CLI command writes its report to standard output"
)]
fn print_tsv_lookup(
    targets: &[String],
    sources: &[crate::core::lookup::LookupSourceEntry],
    file_mode: bool,
) -> Vec<String> {
    let mut matched_targets = BTreeSet::new();
    let invalid_targets = run_lookup_streaming(targets, sources, |target, source| {
        matched_targets.insert(target.to_string());
        println!("{target}\t{}\t{}", source.source_label, source.source_line);
    });

    if file_mode {
        let valid_targets = collect_unique_valid_lookup_targets(targets);
        for target in &valid_targets {
            if !matched_targets.contains(target) {
                println!("{target}\tNO_MATCH");
            }
        }
        let matched_count = matched_targets
            .iter()
            .filter(|target| valid_targets.contains(*target))
            .count();
        println!(
            "summary: total_ips={} matched_ips={matched_count} matched_pct={}",
            valid_targets.len(),
            percent_str(matched_count, valid_targets.len())
        );
    }

    invalid_targets
}

fn should_color_lookup(stdout_is_terminal: bool, no_color_set: bool) -> bool {
    stdout_is_terminal && !no_color_set
}

#[allow(
    clippy::print_stdout,
    reason = "CLI table renderer writes directly to standard output"
)]
fn print_lookup_table_border(left: char, junction: char, right: char) {
    println!(
        "{left}{}{junction}{}{junction}{}{junction}{}{right}",
        "─".repeat(LOOKUP_TARGET_WIDTH + 2),
        "─".repeat(LOOKUP_STATUS_WIDTH + 2),
        "─".repeat(LOOKUP_SOURCE_WIDTH + 2),
        "─".repeat(LOOKUP_ENTRY_WIDTH + 2),
    );
}

#[allow(
    clippy::print_stdout,
    reason = "CLI table renderer writes directly to standard output"
)]
fn print_lookup_table_row(cells: [&str; 4], color_status: bool) {
    for line in format_lookup_table_row(cells, color_status) {
        println!("{line}");
    }
}

fn format_lookup_table_row(cells: [&str; 4], color_status: bool) -> Vec<String> {
    let [target, status, source, entry] = cells;
    let wrapped_target = wrap_lookup_cell(target, LOOKUP_TARGET_WIDTH);
    let wrapped_status = wrap_lookup_cell(status, LOOKUP_STATUS_WIDTH);
    let wrapped_source = wrap_lookup_cell(source, LOOKUP_SOURCE_WIDTH);
    let wrapped_entry = wrap_lookup_cell(entry, LOOKUP_ENTRY_WIDTH);
    let height = [
        wrapped_target.len(),
        wrapped_status.len(),
        wrapped_source.len(),
        wrapped_entry.len(),
    ]
    .into_iter()
    .max()
    .unwrap_or(1);
    let mut rows = Vec::with_capacity(height);

    for line_idx in 0..height {
        let displayed_target =
            format_lookup_cell_line(&wrapped_target, line_idx, LOOKUP_TARGET_WIDTH);
        let mut displayed_status =
            format_lookup_cell_line(&wrapped_status, line_idx, LOOKUP_STATUS_WIDTH);
        let displayed_source =
            format_lookup_cell_line(&wrapped_source, line_idx, LOOKUP_SOURCE_WIDTH);
        let displayed_entry = format_lookup_cell_line(&wrapped_entry, line_idx, LOOKUP_ENTRY_WIDTH);
        if color_status && line_idx == 0 {
            displayed_status = color_lookup_status(status, &displayed_status);
        }
        rows.push(format!(
            "│ {displayed_target} │ {displayed_status} │ {displayed_source} │ {displayed_entry} │"
        ));
    }

    rows
}

fn format_lookup_cell_line(lines: &[String], line_idx: usize, width: usize) -> String {
    let value = lines.get(line_idx).map_or("", String::as_str);
    format!("{value:<width$}")
}

fn wrap_lookup_cell(value: &str, width: usize) -> Vec<String> {
    let chars = value.chars().collect::<Vec<_>>();
    if chars.is_empty() {
        return vec![String::new()];
    }
    chars
        .chunks(width)
        .map(|chunk| chunk.iter().collect())
        .collect()
}

fn color_lookup_status(status: &str, padded: &str) -> String {
    match status {
        "MATCH" => format!("\x1b[1;36m{padded}\x1b[0m"),
        "NO MATCH" => format!("\x1b[2m{padded}\x1b[0m"),
        _ => padded.to_string(),
    }
}

fn collect_unique_valid_lookup_targets<S: AsRef<str>>(targets: &[S]) -> BTreeSet<String> {
    targets
        .iter()
        .filter_map(|target| {
            let raw = target.as_ref();
            parse_target_strict(raw).ok().map(|_| raw.to_string())
        })
        .collect()
}

fn percent(numerator: usize, denominator: usize) -> usize {
    if denominator == 0 {
        return 0;
    }
    numerator.saturating_mul(100) / denominator
}

fn percent_str(numerator: usize, denominator: usize) -> String {
    format!("{}%", percent(numerator, denominator))
}

fn collect_lookup_targets(
    ip: Option<String>,
    file: Option<PathBuf>,
) -> Result<Vec<String>, KidoboError> {
    match (ip, file) {
        (Some(target), None) => Ok(vec![target]),
        (None, Some(path)) => read_target_lines(&path),
        _ => Ok(Vec::new()),
    }
}

fn read_target_lines(path: &std::path::Path) -> Result<Vec<String>, KidoboError> {
    let contents = read_to_string_with_limit(path, LOOKUP_TARGET_READ_LIMIT).map_err(|err| {
        KidoboError::LookupTargetFileRead {
            path: path.to_path_buf(),
            reason: err.to_string(),
        }
    })?;

    Ok(contents.lines().map(ToString::to_string).collect())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use tempfile::TempDir;

    use super::{
        collect_lookup_targets, collect_unique_valid_lookup_targets, color_lookup_status,
        format_lookup_table_row, read_target_lines, should_color_lookup, wrap_lookup_cell,
    };
    use crate::error::KidoboError;

    #[test]
    fn lookup_target_collection_single_mode() {
        let targets =
            collect_lookup_targets(Some("203.0.113.7".to_string()), None).expect("collect");
        assert_eq!(targets, vec!["203.0.113.7"]);
    }

    #[test]
    fn lookup_target_collection_file_mode() {
        let temp = TempDir::new().expect("tempdir");
        let file = temp.path().join("targets.txt");
        fs::write(&file, "10.0.0.1\n2001:db8::1\n").expect("write");

        let targets = collect_lookup_targets(None, Some(file)).expect("collect");
        assert_eq!(targets, vec!["10.0.0.1", "2001:db8::1"]);
    }

    #[test]
    fn read_target_lines_reports_file_read_error() {
        let missing = PathBuf::from("/definitely/missing/targets.txt");
        let err = read_target_lines(&missing).expect_err("must fail");
        match err {
            KidoboError::LookupTargetFileRead { path, .. } => assert_eq!(path, missing),
            _ => panic!("unexpected error variant"),
        }
    }

    #[test]
    fn oversized_target_file_is_rejected() {
        let temp = TempDir::new().expect("tempdir");
        let file = temp.path().join("targets.txt");
        fs::write(&file, "1".repeat(super::LOOKUP_TARGET_READ_LIMIT + 1)).expect("write");

        let err = read_target_lines(&file).expect_err("must fail");
        match err {
            KidoboError::LookupTargetFileRead { reason, .. } => {
                assert!(reason.contains("file exceeds 2097152 byte limit"));
            }
            _ => panic!("unexpected error variant"),
        }
    }

    #[test]
    fn collect_unique_valid_lookup_targets_skips_invalid_and_dedups() {
        let targets = vec![
            "203.0.113.7".to_string(),
            "not-an-ip".to_string(),
            "203.0.113.7".to_string(),
            "2001:db8::1".to_string(),
        ];
        let unique = collect_unique_valid_lookup_targets(&targets);
        assert_eq!(
            unique.into_iter().collect::<Vec<_>>(),
            vec!["2001:db8::1", "203.0.113.7"]
        );
    }

    #[test]
    fn lookup_color_requires_terminal_without_no_color() {
        assert!(should_color_lookup(true, false));
        assert!(!should_color_lookup(false, false));
        assert!(!should_color_lookup(true, true));
    }

    #[test]
    fn lookup_status_color_wraps_already_padded_cell() {
        let colored = color_lookup_status("MATCH", "MATCH   ");
        assert_eq!(colored, "\x1b[1;36mMATCH   \x1b[0m");
        assert_eq!(
            colored.replace("\x1b[1;36m", "").replace("\x1b[0m", ""),
            "MATCH   "
        );
    }

    #[test]
    fn lookup_no_match_color_is_dimmed() {
        assert_eq!(
            color_lookup_status("NO MATCH", "NO MATCH"),
            "\x1b[2mNO MATCH\x1b[0m"
        );
    }

    #[test]
    fn lookup_table_colors_only_the_first_status_line() {
        let long_source = "s".repeat(super::LOOKUP_SOURCE_WIDTH + 1);
        let rows = format_lookup_table_row(["198.51.100.9", "NO MATCH", &long_source, "—"], true);

        assert_eq!(rows.len(), 2);
        assert!(rows[0].contains("\x1b[2mNO MATCH\x1b[0m"));
        assert!(!rows[1].contains("\x1b["));
    }

    #[test]
    fn lookup_cell_wrapping_preserves_content_and_width() {
        let wrapped = wrap_lookup_cell("abcdefghij", 4);
        assert_eq!(wrapped, vec!["abcd", "efgh", "ij"]);
        assert_eq!(wrapped.concat(), "abcdefghij");
        assert!(wrapped.iter().all(|line| line.chars().count() <= 4));
    }
}
