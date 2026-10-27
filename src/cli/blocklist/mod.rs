use std::fmt;
use std::path::Path;

use log::warn;

use crate::cli::CliIo;
use crate::cli::presentation::{format_utc, remaining_duration};
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
    self, AsnBanDependencies, AsnBanRequest, AsnUnbanDependencies, AsnUnbanRequest, BanChange,
    BanDependencies, BanOutcome, BanRequest, BlocklistInput, UnbanApplyDependencies, UnbanDecision,
    UnbanPreparationDependencies, UnbanRequest,
};
use kidobo_app::temporary_bans::Clock;

pub fn run_ban_command(
    target: Option<&str>,
    file: Option<&Path>,
    asn: Option<&[String]>,
    duration: Option<BanDuration>,
    io: &mut CliIo<'_>,
) -> Result<bool, KidoboError> {
    let paths = path_resolution_input_from_process(None);
    if let Some(tokens) = asn {
        let outcome = blocklist::execute_ban_asn(
            &AsnBanRequest {
                paths,
                tokens: tokens.to_vec(),
                duration,
            },
            &asn_ban_dependencies(),
        )?;
        for notice in &outcome.notices {
            warn!("{}", notice.message);
        }
        if let Some(duration) = duration {
            render_ban_changes(&outcome.temporary_changes, Some(duration), io)?;
            return Ok(changes_saved(&outcome.temporary_changes));
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
        return Ok(!outcome.added.is_empty());
    }

    let input = command_input(target, file)?;
    let outcome = blocklist::execute_ban(
        &BanRequest {
            paths,
            input,
            duration,
        },
        &ban_dependencies(),
    )?;
    let (changes, notices) = match outcome {
        BanOutcome::Applied(changes) => (changes, Vec::new()),
        BanOutcome::TemporaryApplied { changes, notices } => (changes, notices),
        BanOutcome::InvalidTargets(targets) => {
            return report_invalid_targets(&targets, io).map(|()| false);
        }
        BanOutcome::EmptyFile => {
            output(io, format_args!("no blocklist targets loaded from file"))?;
            return Ok(false);
        }
    };
    for notice in notices {
        warn!("{}", notice.message);
    }
    render_ban_changes(&changes, duration, io)?;

    Ok(changes_saved(&changes))
}

pub fn run_unban_command(
    target: Option<&str>,
    file: Option<&Path>,
    asn: Option<&[String]>,
    yes: bool,
    io: &mut CliIo<'_>,
) -> Result<bool, KidoboError> {
    let paths = path_resolution_input_from_process(None);
    if let Some(tokens) = asn {
        let outcome = blocklist::execute_unban_asn(
            &AsnUnbanRequest {
                paths,
                tokens: tokens.to_vec(),
            },
            &asn_unban_dependencies(),
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
        return Ok(!outcome.removed.is_empty());
    }

    let input = command_input(target, file)?;
    let file_mode = matches!(input, BlocklistInput::File(_));
    let request = UnbanRequest { paths, input };
    let preparation = blocklist::prepare_unban(&request, &unban_preparation_dependencies())?;
    let preview = match preparation {
        blocklist::UnbanPreparation::Ready(preview) => preview,
        blocklist::UnbanPreparation::InvalidTargets(targets) => {
            report_invalid_targets(&targets, io)?;
            return Ok(false);
        }
        blocklist::UnbanPreparation::EmptyFile => {
            output(io, format_args!("no blocklist targets loaded from file"))?;
            return Ok(false);
        }
    };
    let remove_partial = confirm_partial_matches(&preview, file_mode, yes, io)?;
    let outcome = blocklist::apply_unban(
        &request,
        &preview,
        &UnbanDecision { remove_partial },
        &unban_apply_dependencies(),
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
        return Ok(false);
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
    Ok(true)
}

fn ban_dependencies() -> BanDependencies<'static> {
    BanDependencies {
        cancellation: &crate::cli::interrupt::SigintCancellation,
        paths: &SystemPathResolver,
        configs: &FileConfigRepository,
        locks: &FileLockManager,
        repository: &FileBlocklistRepository,
        temporary_bans: &FileTemporaryBanRepository,
        clock: &SystemClock,
    }
}

fn unban_preparation_dependencies() -> UnbanPreparationDependencies<'static> {
    UnbanPreparationDependencies {
        cancellation: &crate::cli::interrupt::SigintCancellation,
        paths: &SystemPathResolver,
        configs: &FileConfigRepository,
        repository: &FileBlocklistRepository,
        temporary_bans: &FileTemporaryBanRepository,
    }
}

fn unban_apply_dependencies() -> UnbanApplyDependencies<'static> {
    UnbanApplyDependencies {
        cancellation: &crate::cli::interrupt::SigintCancellation,
        paths: &SystemPathResolver,
        configs: &FileConfigRepository,
        locks: &FileLockManager,
        repository: &FileBlocklistRepository,
        temporary_bans: &FileTemporaryBanRepository,
    }
}

fn asn_ban_dependencies() -> AsnBanDependencies<'static> {
    AsnBanDependencies {
        cancellation: &crate::cli::interrupt::SigintCancellation,
        paths: &SystemPathResolver,
        configs: &FileConfigRepository,
        locks: &FileLockManager,
        repository: &FileBlocklistRepository,
        temporary_bans: &FileTemporaryBanRepository,
        clock: &SystemClock,
        prefix_loader: &SystemAsnOperations,
        config_editor: &SystemAsnOperations,
    }
}

fn asn_unban_dependencies() -> AsnUnbanDependencies<'static> {
    AsnUnbanDependencies {
        cancellation: &crate::cli::interrupt::SigintCancellation,
        paths: &SystemPathResolver,
        configs: &FileConfigRepository,
        locks: &FileLockManager,
        temporary_bans: &FileTemporaryBanRepository,
        config_editor: &SystemAsnOperations,
        cache_remover: &SystemAsnOperations,
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
                    "added temporary ban {target}{duration_text} (expires {}; {}; Unix {expires_at})",
                    format_utc(*expires_at),
                    remaining_duration(*expires_at, SystemClock.now_unix_secs()?)
                ),
            )?,
            BanChange::TemporaryRescheduled { target, expires_at } => output(
                io,
                format_args!(
                    "rescheduled temporary ban {target}{duration_text} (expires {}; {}; Unix {expires_at})",
                    format_utc(*expires_at),
                    remaining_duration(*expires_at, SystemClock.now_unix_secs()?)
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
    if duration.is_some() && changes_saved(changes) {
        io.presentation().paragraph(io.stdout, "The duration started when saved. Delayed or failed sync/timer runs can delay activation or removal; another source may continue blocking the address.")?;
    }
    Ok(())
}

fn report_invalid_targets(targets: &[String], io: &mut CliIo<'_>) -> Result<(), KidoboError> {
    for target in targets {
        writeln!(
            io.stderr,
            "invalid target: {}",
            crate::cli::presentation::escape(target)
        )?;
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
    io.presentation()
        .paragraph(io.stdout, &arguments.to_string())?;
    Ok(())
}

fn changes_saved(changes: &[BanChange]) -> bool {
    changes.iter().any(|change| {
        matches!(
            change,
            BanChange::Added(_)
                | BanChange::TemporaryAdded { .. }
                | BanChange::TemporaryRescheduled { .. }
        )
    })
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
                stdin_is_terminal: false,
                stderr_is_terminal: false,
                terminal_width: 80,
                term_dumb: false,
                under_systemd: false,
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
