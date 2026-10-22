use std::fmt;
use std::path::Path;

use log::warn;

use crate::cli::CliIo;
use crate::error::KidoboError;
use kidobo_adapters::blocklist_file::FileBlocklistRepository;
use kidobo_adapters::blocklist_operations::SystemAsnOperations;
use kidobo_adapters::config::FileConfigRepository;
use kidobo_adapters::lock::FileLockManager;
use kidobo_adapters::path::{SystemPathResolver, path_resolution_input_from_process};
use kidobo_adapters::temporary_bans::{FileTemporaryBanRepository, SystemClock};
use kidobo_app::AppError;
use kidobo_app::blocklist::BanDuration;
use kidobo_app::blocklist::{
    self, AsnBanRequest, BanChange, BanOutcome, BanRequest, BlocklistDependencies, BlocklistInput,
    UnbanDecision, UnbanRequest,
};

pub fn run_ban_command(
    target: Option<&str>,
    file: Option<&Path>,
    asn: Option<&[String]>,
    duration: Option<BanDuration>,
    io: &mut CliIo<'_>,
) -> Result<(), KidoboError> {
    let dependencies = production_dependencies();
    let paths = path_resolution_input_from_process(None);
    if let Some(tokens) = asn {
        let outcome = blocklist::execute_ban_asn(
            &AsnBanRequest {
                paths,
                tokens: tokens.to_vec(),
                duration,
            },
            &dependencies,
        )?;
        for notice in &outcome.notices {
            warn!("{}", notice.message);
        }
        if let Some(duration) = duration {
            render_ban_changes(&outcome.temporary_changes, Some(duration), io)?;
            sync_notice(io)?;
            return Ok(());
        }
        output(
            io,
            format_args!(
                "added {} ASN ban(s): {}",
                outcome.added.len(),
                format_asn_list(&outcome.added)
            ),
        )?;
        if outcome.removed_duplicate_entries > 0 {
            output(
                io,
                format_args!(
                    "removed {} duplicate IP/CIDR entry(ies) from local blocklist",
                    outcome.removed_duplicate_entries
                ),
            )?;
        }
        sync_notice(io)?;
        return Ok(());
    }

    let input = command_input(target, file)?;
    let file_mode = matches!(input, BlocklistInput::File(_));
    let outcome = blocklist::execute_ban(
        &BanRequest {
            paths,
            input,
            duration,
        },
        &dependencies,
    )?;
    let (changes, notices) = match outcome {
        BanOutcome::Applied(changes) => (changes, Vec::new()),
        BanOutcome::TemporaryApplied { changes, notices } => (changes, notices),
        BanOutcome::InvalidTargets(targets) => return report_invalid_targets(&targets, io),
        BanOutcome::EmptyFile => {
            output(io, format_args!("no blocklist targets loaded from file"))?;
            return Ok(());
        }
    };
    for notice in notices {
        warn!("{}", notice.message);
    }
    render_ban_changes(&changes, duration, io)?;
    if !file_mode || !changes.is_empty() {
        sync_notice(io)?;
    }
    Ok(())
}

pub fn run_unban_command(
    target: Option<&str>,
    file: Option<&Path>,
    asn: Option<&[String]>,
    yes: bool,
    io: &mut CliIo<'_>,
) -> Result<(), KidoboError> {
    let dependencies = production_dependencies();
    let paths = path_resolution_input_from_process(None);
    if let Some(tokens) = asn {
        let outcome = blocklist::execute_unban_asn(
            &AsnBanRequest {
                paths,
                tokens: tokens.to_vec(),
                duration: None,
            },
            &dependencies,
        )?;
        for notice in &outcome.notices {
            warn!("{}", notice.message);
        }
        output(
            io,
            format_args!(
                "removed {} ASN ban(s): {}",
                outcome.removed.len(),
                format_asn_list(&outcome.removed)
            ),
        )?;
        output(
            io,
            format_args!("deleted {} ASN cache file(s)", outcome.deleted_cache_files),
        )?;
        sync_notice(io)?;
        return Ok(());
    }

    let input = command_input(target, file)?;
    let file_mode = matches!(input, BlocklistInput::File(_));
    let request = UnbanRequest { paths, input };
    let preparation = blocklist::prepare_unban(&request, &dependencies)?;
    let preview = match preparation {
        blocklist::UnbanPreparation::Ready(preview) => preview,
        blocklist::UnbanPreparation::InvalidTargets(targets) => {
            report_invalid_targets(&targets, io)?;
            return Ok(());
        }
        blocklist::UnbanPreparation::EmptyFile => {
            output(io, format_args!("no blocklist targets loaded from file"))?;
            return Ok(());
        }
    };
    let remove_partial = confirm_partial_matches(&preview, file_mode, yes, io)?;
    let outcome = blocklist::apply_unban(
        &request,
        &preview,
        &UnbanDecision { remove_partial },
        &dependencies,
    )?;
    if outcome.total_removed() == 0 {
        if file_mode && outcome.had_partial_matches {
            output(
                io,
                format_args!(
                    "no blocklist entries were removed for {} file target(s)",
                    outcome.requested_target_count
                ),
            )?;
        } else if file_mode {
            output(
                io,
                format_args!(
                    "no blocklist entries matched {} file target(s)",
                    outcome.requested_target_count
                ),
            )?;
        } else {
            output(
                io,
                format_args!("no blocklist entries match {}", outcome.target_label),
            )?;
        }
        return Ok(());
    }
    if file_mode {
        output(
            io,
            format_args!(
                "removed {} blocklist entries for {} file target(s)",
                outcome.total_removed(),
                outcome.requested_target_count
            ),
        )?;
    } else {
        output(
            io,
            format_args!(
                "removed {} blocklist entries for {}",
                outcome.total_removed(),
                outcome.target_label
            ),
        )?;
    }
    sync_notice(io)?;
    Ok(())
}

fn production_dependencies() -> BlocklistDependencies<'static> {
    static PATHS: SystemPathResolver = SystemPathResolver;
    static CONFIGS: FileConfigRepository = FileConfigRepository;
    static LOCKS: FileLockManager = FileLockManager;
    static REPOSITORY: FileBlocklistRepository = FileBlocklistRepository;
    static ASN: SystemAsnOperations = SystemAsnOperations;
    BlocklistDependencies {
        cancellation: &crate::cli::interrupt::SigintCancellation,
        paths: &PATHS,
        configs: &CONFIGS,
        locks: &LOCKS,
        repository: &REPOSITORY,
        asn: &ASN,
        temporary_bans: &FileTemporaryBanRepository,
        clock: &SystemClock,
    }
}

fn command_input(target: Option<&str>, file: Option<&Path>) -> Result<BlocklistInput, AppError> {
    match (target, file) {
        (Some(target), None) => Ok(BlocklistInput::Single(target.to_string())),
        (None, Some(path)) => Ok(BlocklistInput::File(path.to_path_buf())),
        _ => Err(AppError::BlocklistTargetParse {
            input: String::new(),
        }),
    }
}

fn render_ban_changes(
    changes: &[BanChange],
    duration: Option<BanDuration>,
    io: &mut CliIo<'_>,
) -> Result<(), KidoboError> {
    let duration_text = duration
        .map(|duration| format!(" for {duration}"))
        .unwrap_or_default();
    for change in changes {
        match change {
            BanChange::TemporaryAdded { target, expires_at } => output(
                io,
                format_args!(
                    "added temporary ban {target}{duration_text} (expires at Unix {expires_at})"
                ),
            )?,
            BanChange::TemporaryRescheduled { target, expires_at } => output(
                io,
                format_args!(
                    "rescheduled temporary ban {target}{duration_text} (expires at Unix {expires_at})"
                ),
            )?,
            BanChange::AlreadyPermanent(target) => {
                output(io, format_args!("already permanently banned: {target}"))?;
            }
            BanChange::AlreadyPresent(target) => {
                if duration.is_some() {
                    output(io, format_args!("duplicate temporary ban target: {target}"))?;
                } else {
                    output(io, format_args!("blocklist already contains {target}"))?;
                }
            }
            BanChange::Added(target) => output(io, format_args!("added blocklist entry {target}"))?,
        }
    }
    Ok(())
}

fn report_invalid_targets(targets: &[String], io: &mut CliIo<'_>) -> Result<(), KidoboError> {
    for target in targets {
        writeln!(io.stderr, "invalid target: {target}")?;
    }
    if targets.is_empty() {
        Ok(())
    } else {
        Err(AppError::BlocklistInvalidTargets {
            count: targets.len(),
        }
        .into())
    }
}

fn confirm_partial_matches(
    preview: &blocklist::UnbanPreview,
    file_mode: bool,
    yes: bool,
    io: &mut CliIo<'_>,
) -> Result<bool, KidoboError> {
    if preview.partial_entries.is_empty() {
        return Ok(false);
    }
    if file_mode {
        output(
            io,
            format_args!("file targets also match the following blocklist entries:"),
        )?;
    } else {
        output(
            io,
            format_args!(
                "{} also matches the following blocklist entries:",
                preview.target_label
            ),
        )?;
    }
    for entry in &preview.partial_entries {
        output(io, format_args!("  - {entry}"))?;
    }
    if yes {
        output(
            io,
            format_args!("auto-approving removal of partial matches"),
        )?;
        return Ok(true);
    }
    write!(io.stdout, "Remove these entries as well? [y/N]: ")?;
    io.stdout
        .flush()
        .map_err(|error| KidoboError::BlocklistPrompt { source: error })?;
    let response = io.input.read_response()?;
    Ok(matches!(
        response.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn output(io: &mut CliIo<'_>, arguments: fmt::Arguments<'_>) -> Result<(), KidoboError> {
    writeln!(io.stdout, "{arguments}")?;
    Ok(())
}

fn sync_notice(io: &mut CliIo<'_>) -> Result<(), KidoboError> {
    output(
        io,
        format_args!("changes take effect after running `sudo kidobo sync`"),
    )
}

fn format_asn_list(asns: &[u32]) -> String {
    asns.iter()
        .map(|asn| format!("AS{asn}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::io::{self, Write};

    use super::output;
    use crate::cli::{CliIo, PromptInput};
    use crate::error::KidoboError;

    struct UnusedInput;

    impl PromptInput for UnusedInput {
        fn read_response(&mut self) -> Result<String, KidoboError> {
            panic!("rendering must not read input");
        }
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from_raw_os_error(32))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[cfg(unix)]
    #[test]
    fn output_retains_the_writers_os_error() {
        let error = output(
            &mut CliIo {
                input: &mut UnusedInput,
                stdout: &mut FailingWriter,
                stderr: &mut Vec::new(),
                stdout_is_terminal: false,
                no_color: true,
            },
            format_args!("added blocklist entry 203.0.113.7/32"),
        )
        .expect_err("write failure");
        let source = error
            .source()
            .expect("write cause")
            .downcast_ref::<io::Error>()
            .expect("typed write cause");
        assert_eq!(source.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(source.raw_os_error(), Some(32));
        assert_eq!(error.exit_code(), 1);
        assert_eq!(error.to_string(), format!("CLI I/O failed: {source}"));
    }
}
