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

pub(crate) fn commit_generation(
    store_root: &Path,
    files: &[GenerationFile<'_>],
    previous: Option<&str>,
) -> io::Result<String> {
    commit_generation_with_hook(store_root, files, previous, |_| Ok(()))
}

fn commit_generation_with_hook<F>(
    store_root: &Path,
    files: &[GenerationFile<'_>],
    previous: Option<&str>,
    mut hook: F,
) -> io::Result<String>
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
        if generation_directory.exists() {
            fs::remove_dir_all(&staging_directory)?;
        } else {
            fs::rename(&staging_directory, &generation_directory)?;
            sync_directory(&generations_root)?;
        }
        hook(CommitStage::Published)?;

        let previous = previous
            .filter(|candidate| is_generation_id(candidate) && *candidate != generation_id)
            .map(str::to_owned);
        let manifest = GenerationManifest {
            version: CACHE_SCHEMA_VERSION,
            current: generation_id.clone(),
            previous,
        };
        let manifest_bytes = serde_json::to_vec_pretty(&manifest)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        write_bytes_atomic(&store_root.join(MANIFEST_FILE_NAME), &manifest_bytes)?;
        hook(CommitStage::ManifestCommitted)?;
        prune_generations(store_root, &manifest);
        Ok(())
    })();

    if write_result.is_err() {
        let _cleanup_result = fs::remove_dir_all(&staging_directory);
    }
    write_result.map(|()| generation_id)
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
        CommitStage, GenerationFile, GenerationFileLimit, commit_generation,
        commit_generation_with_hook, generation_candidates, generation_contents_match,
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
}
