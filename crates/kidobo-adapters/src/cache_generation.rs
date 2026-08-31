//! Private generation-atomic cache storage shared by remote-source adapters.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

use log::warn;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash::hex_lower;
use crate::limited_io::{read_bytes_with_limit, write_bytes_atomic};

const CACHE_SCHEMA_VERSION: u8 = 2;
const MANIFEST_FILE_NAME: &str = "current.json";
const MANIFEST_READ_LIMIT: usize = 16 * 1024;
const GENERATIONS_DIRECTORY: &str = "generations";
static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerationManifest {
    version: u8,
    current: String,
    previous: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GenerationCandidate {
    pub(crate) id: String,
    pub(crate) directory: PathBuf,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GenerationFile<'a> {
    pub(crate) name: &'static str,
    pub(crate) contents: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GenerationFileLimit {
    pub(crate) name: &'static str,
    pub(crate) read_limit: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommitStage {
    Staged,
    Published,
    ManifestCommitted,
}

/// Fully written generation whose manifest has not yet selected it.
///
/// Dropping an unpromoted generation removes a newly published directory when possible. A
/// content-addressed directory that already existed is left untouched because another selected
/// manifest may still reference it.
#[derive(Debug)]
pub(crate) struct StagedGeneration {
    store_root: PathBuf,
    generation_id: String,
    previous: Option<String>,
    remove_on_drop: bool,
    promoted: bool,
}

impl StagedGeneration {
    pub(crate) fn promote(mut self) -> io::Result<String> {
        self.promote_with_hook(|_| Ok(()))?;
        Ok(self.generation_id.clone())
    }

    fn promote_with_hook<F>(&mut self, mut hook: F) -> io::Result<()>
    where
        F: FnMut(CommitStage) -> io::Result<()>,
    {
        let manifest = GenerationManifest {
            version: CACHE_SCHEMA_VERSION,
            current: self.generation_id.clone(),
            previous: self.previous.clone(),
        };
        let manifest_bytes = serde_json::to_vec_pretty(&manifest)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        write_bytes_atomic(&self.store_root.join(MANIFEST_FILE_NAME), &manifest_bytes)?;
        self.promoted = true;
        self.remove_on_drop = false;
        hook(CommitStage::ManifestCommitted)?;
        prune_generations(&self.store_root, &manifest);
        Ok(())
    }
}

impl Drop for StagedGeneration {
    fn drop(&mut self) {
        if !self.promoted && self.remove_on_drop {
            let directory = self
                .store_root
                .join(GENERATIONS_DIRECTORY)
                .join(&self.generation_id);
            let _remove_result = fs::remove_dir_all(directory);
        }
    }
}

pub(crate) fn generation_candidates(store_root: &Path) -> Vec<GenerationCandidate> {
    let manifest_path = store_root.join(MANIFEST_FILE_NAME);
    let bytes = match read_bytes_with_limit(&manifest_path, MANIFEST_READ_LIMIT) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Vec::new(),
        Err(error) => {
            warn!(
                "failed to read cache generation manifest {}: {error}",
                manifest_path.display()
            );
            return Vec::new();
        }
    };
    let manifest = match serde_json::from_slice::<GenerationManifest>(&bytes) {
        Ok(manifest) if manifest.version == CACHE_SCHEMA_VERSION => manifest,
        Ok(manifest) => {
            warn!(
                "unsupported cache generation manifest version {} at {}",
                manifest.version,
                manifest_path.display()
            );
            return Vec::new();
        }
        Err(error) => {
            warn!(
                "failed to parse cache generation manifest {}: {error}",
                manifest_path.display()
            );
            return Vec::new();
        }
    };

    if !is_generation_id(&manifest.current)
        || manifest
            .previous
            .as_deref()
            .is_some_and(|previous| !is_generation_id(previous) || previous == manifest.current)
    {
        warn!(
            "cache generation manifest contains invalid generation IDs at {}",
            manifest_path.display()
        );
        return Vec::new();
    }

    [Some(manifest.current), manifest.previous]
        .into_iter()
        .flatten()
        .map(|id| GenerationCandidate {
            directory: store_root.join(GENERATIONS_DIRECTORY).join(&id),
            id,
        })
        .collect()
}

pub(crate) fn cleanup_unselected_generations(store_root: &Path) {
    let manifest_path = store_root.join(MANIFEST_FILE_NAME);
    let candidates = generation_candidates(store_root);
    if candidates.is_empty() {
        if manifest_path.exists() {
            return;
        }
        let generations_root = store_root.join(GENERATIONS_DIRECTORY);
        let Ok(entries) = fs::read_dir(&generations_root) else {
            return;
        };
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                let _remove_result = fs::remove_dir_all(entry.path());
            }
        }
        let _sync_result = sync_directory(&generations_root);
        return;
    }

    let Some(current) = candidates.first() else {
        return;
    };
    let manifest = GenerationManifest {
        version: CACHE_SCHEMA_VERSION,
        current: current.id.clone(),
        previous: candidates.get(1).map(|candidate| candidate.id.clone()),
    };
    prune_generations(store_root, &manifest);
}

pub(crate) fn generation_contents_match(
    candidate: &GenerationCandidate,
    files: &[GenerationFileLimit],
) -> bool {
    let mut contents = Vec::with_capacity(files.len());
    for generation_file in files {
        let path = candidate.directory.join(generation_file.name);
        let bytes = match read_bytes_with_limit(&path, generation_file.read_limit) {
            Ok(bytes) => bytes,
            Err(error) => {
                warn!(
                    "failed to read cache generation member {}: {error}",
                    path.display()
                );
                return false;
            }
        };
        contents.push((generation_file.name, bytes));
    }
    contents.sort_unstable_by_key(|(name, _)| *name);

    let actual_id = generation_id_from_parts(
        contents
            .iter()
            .map(|(name, contents)| (*name, contents.as_slice())),
    );
    if actual_id != candidate.id {
        warn!(
            "cache generation content ID mismatch for {}: ignoring generation",
            candidate.directory.display()
        );
        return false;
    }
    true
}

#[cfg(test)]
pub(crate) fn commit_generation(
    store_root: &Path,
    files: &[GenerationFile<'_>],
    previous: Option<&str>,
) -> io::Result<String> {
    commit_generation_with_hook(store_root, files, previous, |_| Ok(()))
}

pub(crate) fn stage_generation(
    store_root: &Path,
    files: &[GenerationFile<'_>],
    previous: Option<&str>,
) -> io::Result<StagedGeneration> {
    stage_generation_with_hook(store_root, files, previous, |_| Ok(()))
}

#[cfg(test)]
fn commit_generation_with_hook<F>(
    store_root: &Path,
    files: &[GenerationFile<'_>],
    previous: Option<&str>,
    mut hook: F,
) -> io::Result<String>
where
    F: FnMut(CommitStage) -> io::Result<()>,
{
    let mut staged = stage_generation_with_hook(store_root, files, previous, &mut hook)?;
    staged.promote_with_hook(&mut hook)?;
    Ok(staged.generation_id.clone())
}

fn stage_generation_with_hook<F>(
    store_root: &Path,
    files: &[GenerationFile<'_>],
    previous: Option<&str>,
    mut hook: F,
) -> io::Result<StagedGeneration>
where
    F: FnMut(CommitStage) -> io::Result<()>,
{
    if files.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cache generation contains no files",
        ));
    }
    let mut ordered_files = files.to_vec();
    ordered_files.sort_unstable_by_key(|file| file.name);
    if ordered_files.windows(2).any(|pair| {
        pair.first()
            .zip(pair.get(1))
            .is_some_and(|(left, right)| left.name == right.name)
    }) || ordered_files
        .iter()
        .any(|file| !is_safe_file_name(file.name))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cache generation file names must be unique safe basenames",
        ));
    }

    let generation_id = generation_id(&ordered_files);
    let generations_root = store_root.join(GENERATIONS_DIRECTORY);
    fs::create_dir_all(&generations_root)?;
    let staging_directory = create_staging_directory(&generations_root)?;
    let write_result = (|| {
        for generation_file in &ordered_files {
            let path = staging_directory.join(generation_file.name);
            let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
            file.write_all(generation_file.contents)?;
            file.sync_all()?;
        }
        sync_directory(&staging_directory)?;
        hook(CommitStage::Staged)?;

        let generation_directory = generations_root.join(&generation_id);
        let remove_on_drop = if generation_directory.exists() {
            fs::remove_dir_all(&staging_directory)?;
            false
        } else {
            fs::rename(&staging_directory, &generation_directory)?;
            sync_directory(&generations_root)?;
            true
        };
        let previous = previous
            .filter(|candidate| is_generation_id(candidate) && *candidate != generation_id)
            .map(str::to_owned);
        let staged = StagedGeneration {
            store_root: store_root.to_path_buf(),
            generation_id: generation_id.clone(),
            previous,
            remove_on_drop,
            promoted: false,
        };
        hook(CommitStage::Published)?;
        Ok(staged)
    })();

    if write_result.is_err() {
        let _cleanup_result = fs::remove_dir_all(&staging_directory);
    }
    write_result
}

fn create_staging_directory(generations_root: &Path) -> io::Result<PathBuf> {
    for _ in 0..32 {
        let counter = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = generations_root.join(format!(".staging-{}-{counter}", process::id()));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "failed to create a unique cache generation staging directory",
    ))
}

fn generation_id(files: &[GenerationFile<'_>]) -> String {
    generation_id_from_parts(files.iter().map(|file| (file.name, file.contents)))
}

fn generation_id_from_parts<'a>(files: impl IntoIterator<Item = (&'a str, &'a [u8])>) -> String {
    let mut hasher = Sha256::new();
    for (name, contents) in files {
        hasher.update(name.len().to_le_bytes());
        hasher.update(name.as_bytes());
        hasher.update(contents.len().to_le_bytes());
        hasher.update(contents);
    }
    hex_lower(&hasher.finalize())
}

fn prune_generations(store_root: &Path, manifest: &GenerationManifest) {
    let generations_root = store_root.join(GENERATIONS_DIRECTORY);
    let Ok(entries) = fs::read_dir(&generations_root) else {
        return;
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        let keep = name == manifest.current || manifest.previous.as_deref() == Some(name.as_ref());
        if !keep && entry.path().is_dir() {
            let _remove_result = fs::remove_dir_all(entry.path());
        }
    }
    let _sync_result = sync_directory(&generations_root);
}

fn is_generation_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_safe_file_name(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io;

    use tempfile::TempDir;

    use crate::limited_io::read_bytes_with_limit;

    use super::{
        CommitStage, GENERATIONS_DIRECTORY, GenerationFile, GenerationFileLimit,
        cleanup_unselected_generations, commit_generation, commit_generation_with_hook,
        generation_candidates, generation_contents_match, stage_generation,
    };

    fn commit(store: &std::path::Path, value: &[u8], previous: Option<&str>) -> String {
        commit_generation(
            store,
            &[GenerationFile {
                name: "payload",
                contents: value,
            }],
            previous,
        )
        .expect("commit")
    }

    #[test]
    fn failures_before_manifest_commit_keep_the_previous_generation_selected() {
        // A published directory is still intentionally invisible until the manifest commit, so
        // both pre-publish and post-publish failures must select the preceding generation.
        for failure_stage in [CommitStage::Staged, CommitStage::Published] {
            let temp = TempDir::new().expect("tempdir");
            let old = commit(temp.path(), b"old", None);
            let result = commit_generation_with_hook(
                temp.path(),
                &[GenerationFile {
                    name: "payload",
                    contents: b"new",
                }],
                Some(&old),
                |stage| {
                    if stage == failure_stage {
                        Err(io::Error::other("injected commit failure"))
                    } else {
                        Ok(())
                    }
                },
            );

            assert!(result.is_err());
            let candidates = generation_candidates(temp.path());
            assert_eq!(candidates[0].id, old);
            assert_eq!(
                read_bytes_with_limit(&candidates[0].directory.join("payload"), 16)
                    .expect("read payload"),
                b"old"
            );
        }
    }

    #[test]
    fn manifest_commit_retains_new_current_and_old_previous() {
        let temp = TempDir::new().expect("tempdir");
        let old = commit(temp.path(), b"old", None);
        let result = commit_generation_with_hook(
            temp.path(),
            &[GenerationFile {
                name: "payload",
                contents: b"new",
            }],
            Some(&old),
            |stage| {
                if stage == CommitStage::ManifestCommitted {
                    Err(io::Error::other("injected post-manifest failure"))
                } else {
                    Ok(())
                }
            },
        );

        assert!(result.is_err());
        let candidates = generation_candidates(temp.path());
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[1].id, old);
        assert_eq!(
            read_bytes_with_limit(&candidates[1].directory.join("payload"), 16)
                .expect("read previous"),
            b"old"
        );
    }

    #[test]
    fn generation_contents_must_match_the_manifest_id() {
        let temp = TempDir::new().expect("tempdir");
        commit(temp.path(), b"original", None);
        let candidate = generation_candidates(temp.path())
            .into_iter()
            .next()
            .expect("candidate");
        let files = [GenerationFileLimit {
            name: "payload",
            read_limit: 16,
        }];
        assert!(generation_contents_match(&candidate, &files));

        std::fs::write(candidate.directory.join("payload"), b"modified").expect("corrupt");

        assert!(!generation_contents_match(&candidate, &files));
    }

    #[test]
    fn malformed_previous_id_invalidates_the_manifest() {
        let temp = TempDir::new().expect("tempdir");
        let current = commit(temp.path(), b"original", None);
        std::fs::write(
            temp.path().join("current.json"),
            format!("{{\"version\":2,\"current\":\"{current}\",\"previous\":\"../legacy\"}}"),
        )
        .expect("write malformed manifest");

        assert!(generation_candidates(temp.path()).is_empty());
    }

    #[test]
    fn online_cleanup_removes_unselected_crash_generation() {
        let temp = TempDir::new().expect("tempdir");
        let selected = commit(temp.path(), b"selected", None);
        let staged = stage_generation(
            temp.path(),
            &[GenerationFile {
                name: "payload",
                contents: b"unselected",
            }],
            Some(&selected),
        )
        .expect("stage generation");
        std::mem::forget(staged);

        cleanup_unselected_generations(temp.path());

        let directories = std::fs::read_dir(temp.path().join(GENERATIONS_DIRECTORY))
            .expect("read generations")
            .map(|entry| entry.expect("entry").file_name())
            .collect::<Vec<_>>();
        assert_eq!(directories, [std::ffi::OsString::from(selected)]);
    }
}
