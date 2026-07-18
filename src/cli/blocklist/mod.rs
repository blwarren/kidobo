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
use kidobo_app::AppError;
use kidobo_app::blocklist::{
    self, AsnBanRequest, BanChange, BanRequest, BlocklistDependencies, BlocklistInput,
    UnbanDecision, UnbanRequest,
};

pub fn run_ban_command(
    target: Option<&str>,
    file: Option<&Path>,
    asn: Option<&[String]>,
    io: &mut CliIo<'_>,
) -> Result<(), KidoboError> {
    let dependencies = production_dependencies();
    let paths = path_resolution_input_from_process(None);
    if let Some(tokens) = asn {
        let outcome = blocklist::execute_ban_asn(
            &AsnBanRequest {
                paths,
                tokens: tokens.to_vec(),
            },
            &dependencies,
        )?;
        for notice in &outcome.notices {
            warn!("{}", notice.message);
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
    let outcome = blocklist::execute_ban(&BanRequest { paths, input }, &dependencies)?;
    report_invalid_targets(&outcome.invalid_targets, io)?;
    if outcome.empty_file {
        output(io, format_args!("no blocklist targets loaded from file"))?;
        return Ok(());
    }
    for change in &outcome.changes {
        match change {
            BanChange::Added(value) => {
                output(io, format_args!("added blocklist entry {value}"))?;
            }
            BanChange::AlreadyPresent(value) => {
                output(io, format_args!("blocklist already contains {value}"))?;
            }
        }
    }
    if !file_mode || !outcome.changes.is_empty() {
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
    report_invalid_targets(&preparation.invalid_targets, io)?;
    if preparation.empty_file {
        output(io, format_args!("no blocklist targets loaded from file"))?;
        return Ok(());
    }
    let preview = preparation
        .preview
        .ok_or_else(|| AppError::BlocklistTargetParse {
            input: String::new(),
        })?;
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
        paths: &PATHS,
        configs: &CONFIGS,
        locks: &LOCKS,
        repository: &REPOSITORY,
        asn: &ASN,
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

fn report_invalid_targets(targets: &[String], io: &mut CliIo<'_>) -> Result<(), KidoboError> {
    for target in targets {
        writeln!(io.stderr, "invalid target: {target}").map_err(cli_io_error)?;
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
    write!(io.stdout, "Remove these entries as well? [y/N]: ").map_err(cli_io_error)?;
    io.stdout
        .flush()
        .map_err(|error| KidoboError::BlocklistPrompt {
            reason: error.to_string(),
        })?;
    let mut response = String::new();
    io.input
        .read_line(&mut response)
        .map_err(|error| KidoboError::BlocklistPrompt {
            reason: error.to_string(),
        })?;
    Ok(matches!(
        response.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn output(io: &mut CliIo<'_>, arguments: fmt::Arguments<'_>) -> Result<(), KidoboError> {
    writeln!(io.stdout, "{arguments}").map_err(cli_io_error)
}

fn sync_notice(io: &mut CliIo<'_>) -> Result<(), KidoboError> {
    output(
        io,
        format_args!("changes take effect after running `sudo kidobo sync`"),
    )
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

fn format_asn_list(asns: &[u32]) -> String {
    asns.iter()
        .map(|asn| format!("AS{asn}"))
        .collect::<Vec<_>>()
        .join(", ")
}
