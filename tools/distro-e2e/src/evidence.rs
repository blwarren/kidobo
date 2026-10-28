//! Frozen inputs and verified evidence archives for one run.
use crate::{Result, Runner, hash, strings, vendor_images};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

struct GuestInput {
    name: &'static str,
    lifecycle: bool,
}

// Relative to scripts/e2e in the checkout and inputs/ in the frozen evidence.
const GUEST_INPUTS: &[GuestInput] = &[
    GuestInput {
        name: "provision.sh",
        lifecycle: true,
    },
    GuestInput {
        name: "bootstrap.sh",
        lifecycle: false,
    },
    GuestInput {
        name: "lifecycle.sh",
        lifecycle: true,
    },
    GuestInput {
        name: "traffic.py",
        lifecycle: true,
    },
    GuestInput {
        name: "checks.json",
        lifecycle: true,
    },
    GuestInput {
        name: "lib/reporting.sh",
        lifecycle: true,
    },
    GuestInput {
        name: "lib/fixtures.sh",
        lifecycle: true,
    },
    GuestInput {
        name: "lib/network.sh",
        lifecycle: true,
    },
    GuestInput {
        name: "lib/runtime.sh",
        lifecycle: true,
    },
    GuestInput {
        name: "lib/upgrade.sh",
        lifecycle: true,
    },
];

pub(super) fn lifecycle_inputs() -> impl Iterator<Item = &'static str> {
    GUEST_INPUTS
        .iter()
        .filter(|input| input.lifecycle)
        .map(|input| input.name)
}

fn snapshot_guest_inputs(
    source: &Path,
    inputs: &Path,
    hashes: &mut serde_json::Map<String, serde_json::Value>,
) -> Result<()> {
    for input in GUEST_INPUTS {
        let destination = inputs.join(input.name);
        fs::create_dir_all(destination.parent().ok_or("guest input has no parent")?)?;
        fs::copy(source.join(input.name), &destination)?;
        hashes.insert(input.name.into(), hash(&destination)?.into());
    }
    Ok(())
}

fn rust_sources(directory: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            rust_sources(&entry.path(), files)?;
        } else if kind.is_file()
            && entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "rs")
        {
            files.push(entry.path());
        }
    }
    Ok(())
}

fn harness_identity(root: &Path) -> Result<String> {
    let mut files = Vec::new();
    rust_sources(&root.join("tools/distro-e2e/src"), &mut files)?;
    files.sort();
    files.extend([root.join("Cargo.lock"), root.join("rust-toolchain.toml")]);
    let mut harness = Sha256::new();
    for path in files {
        harness.update(
            path.strip_prefix(root)?
                .to_str()
                .ok_or("non-UTF-8 harness source path")?
                .as_bytes(),
        );
        harness.update([0]);
        harness.update(hash(&path)?.as_bytes());
    }
    let mut identity = String::with_capacity(64);
    for byte in harness.finalize() {
        write!(&mut identity, "{byte:02x}")?;
    }
    Ok(identity)
}

pub(super) fn archive_evidence(runner: &mut Runner) -> Result<()> {
    archive_evidence_using(runner, "tar")
}
pub(super) fn archive_evidence_using(runner: &mut Runner, program: &str) -> Result<()> {
    runner.stage("finalizing evidence archive")?;
    fs::create_dir_all(runner.evidence())?;
    fs::write(
        runner.evidence().join("README.txt"),
        "Frozen inputs and SHA256 manifest: inputs/\nGuest diagnostics and snapshots: <distro>/\nCommand output and check references: ../targets/<distro>/transcript.log and results.json\n",
    )?;
    let temporary = runner.dir.join(".evidence.tar.gz.tmp");
    let archive = runner.dir.join("evidence.tar.gz");
    let temporary_text = temporary
        .to_str()
        .ok_or("non-UTF-8 evidence archive path")?;
    let evidence = runner.evidence();
    runner.command(
        program,
        &strings(&[
            "-czf",
            temporary_text,
            "-C",
            evidence.to_str().ok_or("non-UTF-8 evidence directory")?,
            ".",
        ]),
        300,
    )?;
    runner.command(program, &strings(&["-tzf", temporary_text]), 300)?;
    let sha256 = hash(&temporary)?;
    fs::rename(&temporary, &archive)?;
    runner.report.document["evidence"] = json!({"path": "evidence.tar.gz", "sha256": sha256});
    runner.report.emit(&format!(
        "Evidence archive: {} SHA-256={sha256}",
        archive.display()
    ))?;
    fs::remove_dir_all(evidence)?;
    Ok(())
}
pub(super) fn freeze_archive(source: &Path, dir: &Path) -> Result<PathBuf> {
    let release = dir.join("inputs/release");
    fs::create_dir(&release)?;
    let destination = release.join(source.file_name().ok_or("archive has no filename")?);
    fs::copy(source, &destination)?;
    fs::copy(
        source.with_file_name("SHA256SUMS"),
        release.join("SHA256SUMS"),
    )?;
    Ok(destination)
}
pub(super) fn snapshot_inputs(dir: &Path, config: &Path) -> Result<()> {
    let inputs = dir.join("inputs");
    fs::create_dir(&inputs)?;
    let mut hashes = serde_json::Map::new();
    hashes.insert("harness".into(), json!(harness_identity(Path::new("."))?));
    snapshot_guest_inputs(Path::new("scripts/e2e"), &inputs, &mut hashes)?;
    for (source, name) in [
        (Path::new("scripts/install.sh"), "installer.sh"),
        (config, "e2e.toml"),
    ] {
        let destination = inputs.join(name);
        fs::copy(source, &destination)?;
        hashes.insert(name.into(), hash(&destination)?.into());
    }
    vendor_images::snapshot(&inputs, config)?;
    hashes.insert(
        "e2e-images.toml".into(),
        hash(&inputs.join("e2e-images.toml"))?.into(),
    );
    for key in fs::read_dir(inputs.join("image-keys"))? {
        let path = key?.path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("invalid image key filename")?;
        hashes.insert(format!("image-keys/{name}"), hash(&path)?.into());
    }
    fs::write(
        inputs.join("SHA256.json"),
        serde_json::to_vec_pretty(&hashes)?,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::TestDir;
    use std::collections::BTreeSet;

    #[test]
    fn helper_inventory_covers_checked_in_files_and_frozen_copies_survive_source_changes() {
        let temp = TestDir::new();
        let checkout = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/e2e");
        let helpers = fs::read_dir(checkout.join("lib"))
            .expect("guest helper directory")
            .map(|entry| {
                format!(
                    "lib/{}",
                    entry
                        .expect("helper entry")
                        .file_name()
                        .to_str()
                        .expect("helper name")
                )
            })
            .collect::<BTreeSet<_>>();
        let uploaded = lifecycle_inputs()
            .filter(|name| name.starts_with("lib/"))
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        assert_eq!(uploaded, helpers);
        let source = temp.path().join("source");
        let frozen = temp.path().join("frozen");
        for input in GUEST_INPUTS {
            let path = source.join(input.name);
            fs::create_dir_all(path.parent().expect("source parent")).expect("source directory");
            fs::copy(checkout.join(input.name), path).expect("copy real guest input");
        }
        let mut hashes = serde_json::Map::new();
        snapshot_guest_inputs(&source, &frozen, &mut hashes).expect("freeze guest inputs");
        for input in GUEST_INPUTS {
            fs::write(source.join(input.name), "changed after snapshot\n")
                .expect("change source input");
            assert_eq!(
                hash(&frozen.join(input.name)).expect("frozen hash"),
                hashes[input.name].as_str().expect("recorded hash")
            );
            assert_ne!(
                hash(&source.join(input.name)).expect("source hash"),
                hashes[input.name].as_str().expect("recorded hash")
            );
        }
        assert_eq!(hashes.len(), GUEST_INPUTS.len());
    }

    #[test]
    fn harness_identity_tracks_nested_sources_tests_lockfile_and_toolchain() {
        let temp = TestDir::new();
        let source = temp.path().join("tools/distro-e2e/src");
        fs::create_dir_all(source.join("nested")).expect("source tree");
        for (path, contents) in [
            ("tools/distro-e2e/src/main.rs", "fn main() {}"),
            ("tools/distro-e2e/src/nested/tests.rs", "// test contract"),
            ("Cargo.lock", "lock"),
            ("rust-toolchain.toml", "toolchain"),
        ] {
            fs::write(temp.path().join(path), contents).expect("identity input");
        }
        let baseline = harness_identity(temp.path()).expect("identity");
        assert_eq!(
            harness_identity(temp.path()).expect("repeat identity"),
            baseline
        );
        let reordered = temp.path().join("reordered");
        for path in [
            "rust-toolchain.toml",
            "Cargo.lock",
            "tools/distro-e2e/src/main.rs",
            "tools/distro-e2e/src/nested/tests.rs",
        ] {
            let destination = reordered.join(path);
            fs::create_dir_all(destination.parent().expect("input parent"))
                .expect("reordered tree");
            fs::copy(temp.path().join(path), destination).expect("reordered input");
        }
        assert_eq!(
            harness_identity(&reordered).expect("reordered identity"),
            baseline
        );
        fs::write(source.join("notes.txt"), "not Rust").expect("unrelated file");
        assert_eq!(
            harness_identity(temp.path()).expect("unrelated file ignored"),
            baseline
        );
        for path in [
            "tools/distro-e2e/src/nested/tests.rs",
            "Cargo.lock",
            "rust-toolchain.toml",
        ] {
            let path = temp.path().join(path);
            let original = crate::read_text(&path).expect("original input");
            fs::write(&path, "changed").expect("change input");
            assert_ne!(
                harness_identity(temp.path()).expect("changed identity"),
                baseline
            );
            fs::write(path, original).expect("restore input");
        }
        fs::write(source.join("nested/new.rs"), "// new module").expect("new module");
        assert_ne!(
            harness_identity(temp.path()).expect("new module identity"),
            baseline
        );
        fs::remove_file(source.join("nested/new.rs")).expect("remove new module");
        fs::rename(
            source.join("nested/tests.rs"),
            source.join("nested/renamed.rs"),
        )
        .expect("rename module");
        assert_ne!(
            harness_identity(temp.path()).expect("renamed module identity"),
            baseline
        );
    }
}
