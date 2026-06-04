mod provision;
mod systemd;
mod templates;

#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};

use crate::adapters::command_runner::SudoCommandRunner;
use crate::adapters::path::{
    ENV_KIDOBO_ROOT, PathResolutionInput, ResolvedPaths, resolve_paths_without_config,
};
use crate::error::KidoboError;

use self::provision::{InitSummary, ensure_dir, ensure_file_if_missing};
use self::systemd::{
    DEFAULT_KIDOBO_BINARY_PATH, FALLBACK_KIDOBO_BINARY_PATH, InitCommandRunner,
    ensure_systemd_timer_enabled, resolve_installed_executable_path,
};
use self::templates::{
    DEFAULT_BLOCKLIST_TEMPLATE, DEFAULT_CONFIG_TEMPLATE, DEFAULT_SYSTEMD_TIMER_TEMPLATE,
    KIDOBO_SYNC_SERVICE_FILE, KIDOBO_SYNC_TIMER_FILE, build_systemd_service_template,
    resolve_systemd_dir,
};

#[allow(clippy::print_stdout)]
pub fn run_init_command() -> Result<(), KidoboError> {
    let path_input = PathResolutionInput::from_process(None);
    let paths = resolve_paths_without_config(&path_input)?;
    let executable_path = resolve_installed_executable_path(&[
        PathBuf::from(DEFAULT_KIDOBO_BINARY_PATH),
        PathBuf::from(FALLBACK_KIDOBO_BINARY_PATH),
    ])?;
    let kido_root_override = path_input.env.get(ENV_KIDOBO_ROOT).map(PathBuf::from);
    let sudo_runner = SudoCommandRunner::default();
    let summary = run_init_with_context(
        &paths,
        &executable_path,
        kido_root_override.as_deref(),
        &sudo_runner,
    )?;
    print_init_summary(&summary);
    Ok(())
}

#[cfg(test)]
pub(crate) fn run_init_with_paths(paths: &ResolvedPaths) -> Result<(), KidoboError> {
    let _ = run_init_with_paths_with_summary(paths)?;
    Ok(())
}

#[cfg(test)]
fn run_init_with_paths_with_summary(paths: &ResolvedPaths) -> Result<InitSummary, KidoboError> {
    let kido_root_override = infer_kido_root_override(paths);
    run_init_with_paths_and_runner(
        paths,
        &systemd::NoopInitCommandRunner,
        kido_root_override.as_deref(),
    )
}

#[cfg(test)]
fn run_init_with_paths_and_runner(
    paths: &ResolvedPaths,
    runner: &dyn InitCommandRunner,
    kido_root_override: Option<&Path>,
) -> Result<InitSummary, KidoboError> {
    let executable_path = PathBuf::from(DEFAULT_KIDOBO_BINARY_PATH);
    run_init_with_context(paths, &executable_path, kido_root_override, runner)
}

fn run_init_with_context(
    paths: &ResolvedPaths,
    executable_path: &Path,
    kido_root_override: Option<&Path>,
    runner: &dyn InitCommandRunner,
) -> Result<InitSummary, KidoboError> {
    let mut summary = InitSummary::default();
    let systemd_dir = resolve_systemd_dir(kido_root_override);
    let systemd_service = systemd_dir.join(KIDOBO_SYNC_SERVICE_FILE);
    let systemd_timer = systemd_dir.join(KIDOBO_SYNC_TIMER_FILE);

    for dir in [
        &paths.config_dir,
        &paths.data_dir,
        &paths.remote_cache_dir,
        &systemd_dir,
    ] {
        summary.record(dir, ensure_dir(dir)?);
    }

    let service_template = build_systemd_service_template(executable_path, kido_root_override);
    for (file_path, contents) in [
        (&paths.config_file, DEFAULT_CONFIG_TEMPLATE),
        (&paths.blocklist_file, DEFAULT_BLOCKLIST_TEMPLATE),
        (&paths.lock_file, ""),
        (&systemd_service, service_template.as_str()),
        (&systemd_timer, DEFAULT_SYSTEMD_TIMER_TEMPLATE),
    ] {
        summary.record(file_path, ensure_file_if_missing(file_path, contents)?);
    }

    if kido_root_override.is_none() {
        ensure_systemd_timer_enabled(runner)?;
    }

    Ok(summary)
}

#[cfg(test)]
fn infer_kido_root_override(paths: &ResolvedPaths) -> Option<PathBuf> {
    let root = paths.config_dir.parent()?.to_path_buf();
    if paths.config_dir != root.join("config") {
        return None;
    }

    if paths.data_dir != root.join("data")
        || paths.blocklist_file != root.join("data/blocklist.txt")
        || paths.cache_dir != root.join("cache")
        || paths.remote_cache_dir != root.join("cache/remote")
        || paths.lock_file != root.join("cache/sync.lock")
    {
        return None;
    }

    Some(root)
}

#[allow(clippy::print_stdout)]
fn print_init_summary(summary: &InitSummary) {
    print!("{}", provision::render_init_summary(summary));
}
