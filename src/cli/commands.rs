use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::PathBuf;

use log::warn;

use crate::cli::CliIo;
use crate::cli::args::{Command, LookupFormat};
use crate::cli::blocklist::{run_ban_command, run_unban_command};
use crate::cli::doctor::run_doctor_command;
use crate::cli::flush::run_flush_command;
use crate::cli::init::run_init_command;
use crate::cli::sync::run_sync_command;
use crate::error::KidoboError;
use kidobo_adapters::config::FileConfigRepository;
use kidobo_adapters::lookup_sources::build_offline_lookup_registry;
use kidobo_adapters::path::{SystemPathResolver, path_resolution_input_from_process};
use kidobo_adapters::target_file::LookupTargetFileReader;
use kidobo_app::lookup::{self, LookupDependencies, LookupInput, LookupOutcome, LookupRequest};

pub fn dispatch_with(command: Command, io: &mut CliIo<'_>) -> Result<(), KidoboError> {
    match command {
        Command::Init => run_init_command(io),
        Command::Doctor => run_doctor_command(io),
        Command::Sync { timer } => run_sync_command(timer),
        Command::Flush { cache_only } => run_flush_command(cache_only),
        Command::Lookup { ip, file, format } => run_lookup_command(ip, file, format, io),
        Command::Ban { target, file, asn } => {
            run_ban_command(target.as_deref(), file.as_deref(), asn.as_deref(), io)
        }
        Command::Unban {
            target,
            file,
            asn,
            yes,
        } => run_unban_command(target.as_deref(), file.as_deref(), asn.as_deref(), yes, io),
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
    io: &mut CliIo<'_>,
) -> Result<(), KidoboError> {
    let input = match (ip, file) {
        (Some(target), None) => LookupInput::Single(target),
        (None, Some(path)) => LookupInput::File(path),
        _ => return Ok(()),
    };
    let request = LookupRequest {
        paths: path_resolution_input_from_process(None),
        input,
    };
    let paths = SystemPathResolver;
    let configs = FileConfigRepository;
    let target_files = LookupTargetFileReader;
    let sources = build_offline_lookup_registry()?;
    let outcome = lookup::execute(
        &request,
        &LookupDependencies {
            paths: &paths,
            configs: &configs,
            target_files: &target_files,
            sources: &sources,
        },
    )?;

    for notice in &outcome.notices {
        warn!("{}", notice.message);
    }

    let rendered = match format {
        LookupFormat::Human => render_human_lookup(
            &outcome,
            should_color_lookup(io.stdout_is_terminal, io.no_color),
        ),
        LookupFormat::Tsv => render_tsv_lookup(&outcome),
    };
    io.stdout
        .write_all(rendered.as_bytes())
        .map_err(cli_io_error)?;

    for invalid in &outcome.invalid_targets {
        writeln!(io.stderr, "invalid target: {invalid}").map_err(cli_io_error)?;
    }

    if !outcome.invalid_targets.is_empty() {
        return Err(kidobo_app::AppError::LookupInvalidTargets {
            count: outcome.invalid_targets.len(),
        }
        .into());
    }

    Ok(())
}

const LOOKUP_TARGET_WIDTH: usize = 30;
const LOOKUP_STATUS_WIDTH: usize = 8;
const LOOKUP_SOURCE_WIDTH: usize = 44;
const LOOKUP_ENTRY_WIDTH: usize = 30;

fn render_human_lookup(outcome: &LookupOutcome, color: bool) -> String {
    let mut output = String::new();
    let _top = writeln!(&mut output, "{}", lookup_table_border('┌', '┬', '┐'));
    for row in format_lookup_table_row(["Target", "Status", "Source", "Matched Entry"], false) {
        let _row = writeln!(&mut output, "{row}");
    }
    let _separator = writeln!(&mut output, "{}", lookup_table_border('├', '┼', '┤'));

    let mut total_count = 0_usize;
    let mut matched_count = 0_usize;
    for target in &outcome.valid_targets {
        total_count += 1;
        let matches = outcome
            .matches
            .iter()
            .filter(|source| source.target == *target)
            .collect::<Vec<_>>();
        if matches.is_empty() {
            for row in format_lookup_table_row([target, "NO MATCH", "—", "—"], color) {
                let _row = writeln!(&mut output, "{row}");
            }
        } else {
            matched_count += 1;
            for source in matches {
                for row in format_lookup_table_row(
                    [
                        target,
                        "MATCH",
                        &source.source_label,
                        &source.matched_source_entry,
                    ],
                    color,
                ) {
                    let _row = writeln!(&mut output, "{row}");
                }
            }
        }
    }

    let _bottom = writeln!(&mut output, "{}", lookup_table_border('└', '┴', '┘'));
    let unmatched_count = total_count.saturating_sub(matched_count);
    let _summary = writeln!(
        &mut output,
        "\nSummary\n  Targets:    {total_count}\n  Matched:    {matched_count}\n  Unmatched:  {unmatched_count}\n  Match rate: {}",
        percent_str(matched_count, total_count)
    );
    output
}

fn render_tsv_lookup(outcome: &LookupOutcome) -> String {
    let mut output = String::new();
    let mut matched_targets = BTreeSet::new();
    for source in &outcome.matches {
        matched_targets.insert(source.target.clone());
        let _match = writeln!(
            &mut output,
            "{}\t{}\t{}",
            source.target, source.source_label, source.matched_source_entry
        );
    }

    if outcome.file_mode {
        for target in &outcome.valid_targets {
            if !matched_targets.contains(target) {
                let _no_match = writeln!(&mut output, "{target}\tNO_MATCH");
            }
        }
        let matched_count = matched_targets
            .iter()
            .filter(|target| outcome.valid_targets.contains(*target))
            .count();
        let _summary = writeln!(
            &mut output,
            "summary: total_ips={} matched_ips={matched_count} matched_pct={}",
            outcome.valid_targets.len(),
            percent_str(matched_count, outcome.valid_targets.len())
        );
    }
    output
}

fn should_color_lookup(stdout_is_terminal: bool, no_color_set: bool) -> bool {
    stdout_is_terminal && !no_color_set
}

fn lookup_table_border(left: char, junction: char, right: char) -> String {
    format!(
        "{left}{}{junction}{}{junction}{}{junction}{}{right}",
        "─".repeat(LOOKUP_TARGET_WIDTH + 2),
        "─".repeat(LOOKUP_STATUS_WIDTH + 2),
        "─".repeat(LOOKUP_SOURCE_WIDTH + 2),
        "─".repeat(LOOKUP_ENTRY_WIDTH + 2),
    )
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

fn percent(numerator: usize, denominator: usize) -> usize {
    if denominator == 0 {
        return 0;
    }
    numerator.saturating_mul(100) / denominator
}

fn percent_str(numerator: usize, denominator: usize) -> String {
    format!("{}%", percent(numerator, denominator))
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "Result::map_err supplies the owned I/O error"
)]
fn cli_io_error(error: std::io::Error) -> KidoboError {
    KidoboError::CliIo {
        reason: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        color_lookup_status, format_lookup_table_row, should_color_lookup, wrap_lookup_cell,
    };

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
