use std::path::PathBuf;

use clap::CommandFactory;
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
use kidobo_app::lookup::{
    self, LookupDependencies, LookupInput, LookupRequest, LookupSourceEntry, LookupSummary,
};

pub fn dispatch_with(command: Command, io: &mut CliIo<'_>) -> Result<(), KidoboError> {
    match command {
        Command::Completions { shell } => write_completions(shell, io.stdout),
        Command::Setup => super::setup::run(io),
        Command::Sources { action } => {
            super::configuration::sources(action.unwrap_or(super::args::SourceAction::List), io)
        }
        Command::Allow { action } => {
            super::configuration::allow(action.unwrap_or(super::args::AllowAction::List), io)
        }
        Command::Config { action } => {
            super::configuration::config(action.unwrap_or(super::args::ConfigAction::Show), io)
        }
        Command::Status { format } => super::inspection::status(format, io),
        Command::Check { ip, format } => super::inspection::check(ip, format, io),
        Command::Bans {
            temporary,
            permanent,
            asn,
            limit,
            all,
        } => super::bans::run(
            if temporary {
                kidobo_app::bans::BanLifetimeFilter::Temporary
            } else if permanent {
                kidobo_app::bans::BanLifetimeFilter::Permanent
            } else {
                kidobo_app::bans::BanLifetimeFilter::All
            },
            asn,
            if all { None } else { Some(limit.get()) },
            io,
        ),
        Command::Init => run_init_command(io),
        Command::Doctor { format } => run_doctor_command(format, io),
        Command::Sync {
            timer,
            dry_run,
            allow_network,
        } => {
            if dry_run {
                super::preview::run(allow_network, io)
            } else {
                run_sync_command(timer, io)
            }
        }
        Command::Flush { cache_only, yes } => run_flush_command(cache_only, yes, io),
        Command::Lookup { ip, file, format } => run_lookup_command(ip, file, format, io),
        Command::Ban {
            target,
            file,
            asn,
            duration,
            application,
        } => {
            let changed = run_ban_command(
                target.as_deref(),
                file.as_deref(),
                asn.as_deref(),
                duration,
                io,
            )?;
            super::mutation::finish_change(application.mode(), changed, io, &mut |io| {
                run_sync_command(false, io)
            })
        }
        Command::Unban {
            target,
            file,
            asn,
            yes,
            application,
        } => {
            let changed =
                run_unban_command(target.as_deref(), file.as_deref(), asn.as_deref(), yes, io)?;
            super::mutation::finish_change(application.mode(), changed, io, &mut |io| {
                run_sync_command(false, io)
            })
        }
    }
}

fn write_completions(
    shell: super::args::CompletionShell,
    output: &mut dyn std::io::Write,
) -> Result<(), KidoboError> {
    // The generator panics on writer errors. Static command metadata bounds this intermediate
    // script; only the final write reaches fallible terminal or pipe output.
    let mut script = Vec::new();
    clap_complete::generate(
        shell.generator(),
        &mut super::args::Cli::command(),
        "kidobo",
        &mut script,
    );
    output.write_all(&script)?;
    Ok(())
}

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
    let mut renderer = LookupRenderer {
        format,
        view: io.presentation(),
        header_written: false,
        unmatched_targets: Vec::new(),
        output: io.stdout,
    };
    let outcome = lookup::execute(
        &request,
        &LookupDependencies {
            cancellation: &crate::cli::interrupt::SigintCancellation,
            paths: &paths,
            configs: &configs,
            target_files: &target_files,
            sources: &sources,
            clock: &kidobo_adapters::temporary_bans::SystemClock,
            temporary_bans: &kidobo_adapters::temporary_bans::FileTemporaryBanRepository,
        },
        |target, matches| renderer.emit(target, matches),
    )?;

    for notice in &outcome.notices {
        warn!("{}", notice.message);
    }

    renderer.finish(&outcome)?;

    for invalid in &outcome.invalid_targets {
        writeln!(
            io.stderr,
            "invalid target: {}",
            encode_lookup_field(invalid)
        )?;
    }

    if !outcome.invalid_targets.is_empty() {
        return Err(kidobo_app::AppError::LookupInvalidTargets {
            count: outcome.invalid_targets.len(),
        }
        .into());
    }

    Ok(())
}

struct LookupRenderer<'a> {
    format: LookupFormat,
    view: crate::cli::presentation::Presentation,
    header_written: bool,
    unmatched_targets: Vec<String>,
    output: &'a mut dyn std::io::Write,
}

impl LookupRenderer<'_> {
    fn human_header(&mut self) -> Result<(), KidoboError> {
        if !self.header_written {
            self.view.heading(self.output, "Offline source overlaps")?;
            self.view.paragraph(
                self.output,
                "Saved and cached source evidence; this does not establish live enforcement.",
            )?;
            self.header_written = true;
        }
        Ok(())
    }

    fn emit(&mut self, target: &str, matches: &[&LookupSourceEntry]) -> Result<(), KidoboError> {
        match self.format {
            LookupFormat::Human => {
                self.human_header()?;
                if matches.is_empty() {
                    self.view
                        .record(self.output, &[("Target", target), ("Status", "NO MATCH")])?;
                }
                for source in matches {
                    self.view.record(
                        self.output,
                        &[
                            ("Target", target),
                            ("Status", "MATCH"),
                            ("Source", &source.source_label),
                            ("Matched Entry", &source.source_line),
                        ],
                    )?;
                }
                writeln!(self.output)?;
            }
            LookupFormat::Tsv => {
                let target = encode_lookup_field(target);
                for source in matches {
                    writeln!(
                        self.output,
                        "{}\t{}\t{}",
                        target,
                        encode_lookup_field(&source.source_label),
                        encode_lookup_field(&source.source_line)
                    )?;
                }
                if matches.is_empty() {
                    self.unmatched_targets.push(target);
                }
            }
        }
        Ok(())
    }

    fn finish(&mut self, summary: &LookupSummary) -> Result<(), KidoboError> {
        let total_count = summary.total_count;
        let matched_count = summary.matched_count;
        match self.format {
            LookupFormat::Human => {
                self.human_header()?;
                let unmatched_count = total_count.saturating_sub(matched_count);
                self.view.heading(self.output, "Summary")?;
                self.view.key_values(
                    self.output,
                    &[
                        ("Targets", &total_count.to_string()),
                        ("Matched", &matched_count.to_string()),
                        ("Unmatched", &unmatched_count.to_string()),
                        ("Match rate", &percent_str(matched_count, total_count)),
                    ],
                )?;
            }
            LookupFormat::Tsv if summary.file_mode => {
                for target in &self.unmatched_targets {
                    writeln!(self.output, "{target}\tNO_MATCH")?;
                }
                writeln!(
                    self.output,
                    "summary: total_ips={total_count} matched_ips={matched_count} matched_pct={}",
                    percent_str(matched_count, total_count)
                )?;
            }
            LookupFormat::Tsv => {}
        }
        Ok(())
    }
}

fn encode_lookup_field(value: &str) -> String {
    crate::cli::presentation::escape(value)
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

#[cfg(test)]
mod tests {
    use super::encode_lookup_field;

    #[test]
    fn completion_write_errors_keep_the_cli_exit_and_os_cause() {
        struct FailingWriter;
        impl std::io::Write for FailingWriter {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from_raw_os_error(28))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        for shell in [
            crate::cli::args::CompletionShell::Bash,
            crate::cli::args::CompletionShell::Zsh,
            crate::cli::args::CompletionShell::Fish,
        ] {
            let error = super::write_completions(shell, &mut FailingWriter)
                .expect_err("failed output is not a panic");
            assert_eq!(error.exit_code(), 1);
            match error {
                crate::error::KidoboError::CliIo { source } => {
                    assert_eq!(source.raw_os_error(), Some(28));
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }
    }

    #[test]
    fn renderers_encode_each_field_once_and_preserve_writer_errors() {
        use kidobo_app::lookup::LookupSourceEntry;
        struct BrokenWriter;
        impl std::io::Write for BrokenWriter {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let source = LookupSourceEntry {
            source_label: std::sync::Arc::from("label\t\u{1b}\\"),
            source_line: "203.0.113.7\r\u{85}\\".to_string(),
            cidr: kidobo_core::network::parse_ip_cidr_token("203.0.113.7").expect("cidr"),
        };
        for format in [super::LookupFormat::Human, super::LookupFormat::Tsv] {
            let mut output = Vec::new();
            let mut renderer = super::LookupRenderer {
                format,
                view: crate::cli::presentation::Presentation::new(120, false),
                header_written: false,
                unmatched_targets: Vec::new(),
                output: &mut output,
            };
            renderer
                .emit("\t203.0.113.7\n", &[&source])
                .expect("render");
            let stdout = String::from_utf8(output).expect("UTF-8");
            assert!(stdout.contains(r"\t203.0.113.7\n"));
            assert!(stdout.contains(r"label\t\x1B\\"));
            assert!(stdout.contains(r"203.0.113.7\r\u{85}\\"));
            assert!(!stdout.contains('\u{1b}'));

            let mut broken = BrokenWriter;
            let mut renderer = super::LookupRenderer {
                format,
                view: crate::cli::presentation::Presentation::new(120, false),
                header_written: false,
                unmatched_targets: Vec::new(),
                output: &mut broken,
            };
            match renderer
                .emit("203.0.113.7", &[&source])
                .expect_err("writer fails")
            {
                crate::error::KidoboError::CliIo { source } => {
                    assert_eq!(source.kind(), std::io::ErrorKind::BrokenPipe);
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }
    }

    #[test]
    fn lookup_field_encoding_is_deterministic_and_printable() {
        assert_eq!(
            encode_lookup_field("plain\\\t\r\n\x1b\x7f\u{85}"),
            "plain\\\\\\t\\r\\n\\x1B\\x7F\\u{85}"
        );
        assert_eq!(encode_lookup_field("café 東京"), "café 東京");
    }
}
