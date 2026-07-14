use std::fmt::Write;
use std::fs;
use std::path::{Path, PathBuf};

use crate::adapters::limited_io::write_string_atomic;
use crate::error::KidoboError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProvisionState {
    Created,
    Unchanged,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct InitSummary {
    created: Vec<PathBuf>,
    unchanged: Vec<PathBuf>,
}

impl InitSummary {
    pub(super) fn record(&mut self, path: &Path, state: ProvisionState) {
        match state {
            ProvisionState::Created => self.created.push(path.to_path_buf()),
            ProvisionState::Unchanged => self.unchanged.push(path.to_path_buf()),
        }
    }
}

pub(super) fn render_init_summary(summary: &InitSummary) -> String {
    let mut output = String::new();
    let _header_write = writeln!(
        &mut output,
        "init completed: created={} unchanged={}",
        summary.created.len(),
        summary.unchanged.len()
    );
    for path in &summary.created {
        let _created_write = writeln!(&mut output, "created: {}", path.display());
    }
    for path in &summary.unchanged {
        let _unchanged_write = writeln!(&mut output, "unchanged: {}", path.display());
    }
    output
}

pub(super) fn ensure_dir(path: &Path) -> Result<ProvisionState, KidoboError> {
    let existed = path.exists();
    fs::create_dir_all(path).map_err(|err| KidoboError::InitIo {
        path: path.to_path_buf(),
        reason: err.to_string(),
    })?;

    if existed {
        Ok(ProvisionState::Unchanged)
    } else {
        Ok(ProvisionState::Created)
    }
}

pub(super) fn ensure_file_if_missing(
    path: &Path,
    contents: &str,
) -> Result<ProvisionState, KidoboError> {
    if path.exists() {
        if !path.is_file() {
            return Err(KidoboError::InitIo {
                path: path.to_path_buf(),
                reason: "path exists but is not a file".to_string(),
            });
        }
        return Ok(ProvisionState::Unchanged);
    }

    if let Some(parent) = path.parent() {
        ensure_dir(parent)?;
    }

    write_string_atomic(path, contents).map_err(|err| KidoboError::InitIo {
        path: path.to_path_buf(),
        reason: err.to_string(),
    })?;

    Ok(ProvisionState::Created)
}
