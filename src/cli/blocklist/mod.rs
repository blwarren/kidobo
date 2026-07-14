mod asn;
mod confirm;
mod plan;
mod targets;

#[cfg(test)]
mod tests;

use std::path::Path;

use crate::adapters::lock::acquire_non_blocking;
use crate::adapters::path::{PathResolutionInput, resolve_paths};
use crate::error::KidoboError;

#[allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "CLI command writes results and diagnostics to the terminal"
)]
pub fn run_ban_command(
    target: Option<&str>,
    file: Option<&Path>,
    asn: Option<&[String]>,
) -> Result<(), KidoboError> {
    let path_input = PathResolutionInput::from_process(None);
    let paths = resolve_paths(&path_input)?;
    if let Some(asn_tokens) = asn {
        return asn::run_ban_asn_command(
            &paths.config_file,
            &paths.blocklist_file,
            &paths.cache_dir,
            &paths.lock_file,
            asn_tokens,
        );
    }

    let _lock = acquire_non_blocking(&paths.lock_file)?;
    if let Some(file) = file {
        return targets::run_ban_file_command(&paths.blocklist_file, file);
    }

    let Some(target) = target else {
        return Err(KidoboError::BlocklistTargetParse {
            input: String::new(),
        });
    };
    targets::run_ban_target_command(&paths.blocklist_file, target)
}

#[allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "CLI command writes results and diagnostics to the terminal"
)]
pub fn run_unban_command(
    target: Option<&str>,
    file: Option<&Path>,
    asn: Option<&[String]>,
    yes: bool,
) -> Result<(), KidoboError> {
    let path_input = PathResolutionInput::from_process(None);
    let paths = resolve_paths(&path_input)?;
    if let Some(asn_tokens) = asn {
        return asn::run_unban_asn_command(
            &paths.config_file,
            &paths.cache_dir,
            &paths.lock_file,
            asn_tokens,
        );
    }

    if let Some(file) = file {
        return targets::run_unban_file_command(&paths.blocklist_file, &paths.lock_file, file, yes);
    }

    let Some(target) = target else {
        return Err(KidoboError::BlocklistTargetParse {
            input: String::new(),
        });
    };
    targets::run_unban_target_command(&paths.blocklist_file, &paths.lock_file, target, yes)
}
