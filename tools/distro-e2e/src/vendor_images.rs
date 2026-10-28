//! Reviewed upstream disks, ordinary Incus storage, and advisory release discovery.
use super::{Config, Distro, OWNER, Result, Runner, coordination, hash, read_text, strings};
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

mod discovery;
#[cfg(test)]
mod tests;

static NEXT_IMPORT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

const MANIFEST: &str = "e2e-images.toml";
const MINIMUM_AGE: u64 = 7 * 24 * 60 * 60;
const METADATA_LIMIT: u64 = 4 * 1024 * 1024;

#[derive(Subcommand)]
pub(super) enum ImageAction {
    Check,
    Refresh { distro: Option<String> },
}

/// Keep the coordinator lock until evidence has finalized and adoption can be last.
pub(super) struct Refresh {
    destination: PathBuf,
    original: Vec<u8>,
    manifest: Manifest,
    _lock: File,
}

impl Refresh {
    pub(super) fn commit(self) -> Result<()> {
        commit_refresh(&self.destination, &self.original, &self.manifest)
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    images: BTreeMap<String, Pin>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Pin {
    url: String,
    sha256: String,
    architecture: String,
    published_at: u64,
    signing_fingerprint: String,
    incus_fingerprint: String,
    signed_checksum: String,
    checksum_signature: Option<String>,
}

struct Trust {
    fingerprint: &'static str,
    key: &'static str,
    prefix: String,
}

fn trust(id: &str) -> Result<Trust> {
    let (fingerprint, key, prefix) = match id {
        "fedora-44" => (
            "36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6",
            "fedora-44.asc",
            "https://dl.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/".into(),
        ),
        "almalinux-9" => (
            "BF18AC2876178908D6E71267D36CB86CB86B3716",
            "almalinux-9.asc",
            "https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/".into(),
        ),
        "almalinux-10" => (
            "EE6DB7B98F5BF5EDD9DA0DE5DEE5C11CC2A1E572",
            "almalinux-10.asc",
            "https://repo.almalinux.org/almalinux/10/cloud/x86_64/images/".into(),
        ),
        _ => {
            return Err(format!(
                "unsupported vendor source {id}; new releases and signing keys require review"
            )
            .into());
        }
    };
    Ok(Trust {
        fingerprint,
        key,
        prefix,
    })
}

fn digest_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Manifest {
    fn load(path: &Path) -> Result<Self> {
        let manifest: Self = toml_edit::de::from_str(&read_text(path)?)?;
        if manifest.version != 1 {
            return Err("unsupported vendor image manifest version".into());
        }
        for (id, pin) in &manifest.images {
            let source = trust(id)?;
            let filename = pin
                .url
                .strip_prefix(&source.prefix)
                .ok_or("unexpected vendor image origin")?;
            if filename.is_empty()
                || filename.contains('/')
                || filename.contains("..")
                || !filename
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                || !filename.ends_with(".x86_64.qcow2")
                || filename.contains("latest")
                || discovery::image_version(id, filename).is_none()
                || pin.architecture != "x86_64"
                || pin.signing_fingerprint != source.fingerprint
                || !digest_valid(&pin.sha256)
                || !digest_valid(&pin.incus_fingerprint)
                || pin.published_at == 0
                || pin.signed_checksum.is_empty()
            {
                return Err(format!("invalid reviewed vendor image pin {id}").into());
            }
        }
        Ok(manifest)
    }
}

pub(super) fn validate_sources(config: &Config) -> Result<()> {
    for target in &config.distros {
        if target.image.is_empty() == target.vendor_image.is_none() {
            return Err(format!(
                "{} requires exactly one of image or vendor_image",
                target.id
            )
            .into());
        }
        if let Some(id) = &target.vendor_image {
            trust(id)?;
            if id != &target.id || target.selinux != "enforcing" {
                return Err(
                    "vendor image must match its target and require enforcing SELinux".into(),
                );
            }
        }
    }
    Ok(())
}

fn manifest_path(config: &Path) -> PathBuf {
    config.with_file_name(MANIFEST)
}

pub(super) fn snapshot(inputs: &Path, config: &Path) -> Result<()> {
    let source = manifest_path(config);
    // Fixtures with no vendor sources can use an empty manifest, without consulting production pins.
    if source.exists() {
        Manifest::load(&source)?;
        fs::copy(&source, inputs.join(MANIFEST))?;
    } else {
        let config: Config = toml_edit::de::from_str(&read_text(config)?)?;
        if config.distros.iter().any(|d| d.vendor_image.is_some()) {
            return Err("vendor image manifest missing".into());
        }
        fs::write(inputs.join(MANIFEST), "version = 1\n[images]\n")?;
    }
    let manifest = Manifest::load(&inputs.join(MANIFEST))?;
    let key_dir = inputs.join("image-keys");
    fs::create_dir_all(&key_dir)?;
    for id in manifest.images.keys() {
        let source = trust(id)?;
        fs::copy(
            config.with_file_name("e2e-image-keys").join(source.key),
            key_dir.join(source.key),
        )?;
    }
    Ok(())
}

fn discovery_pins(manifest: &Manifest) -> Vec<discovery::DiscoveryPin> {
    manifest
        .images
        .iter()
        .map(|(id, pin)| discovery::DiscoveryPin {
            id: id.clone(),
            url: pin.url.clone(),
            sha256: pin.sha256.clone(),
        })
        .collect()
}

fn report_discovery(
    runner: &mut Runner,
    config: &Config,
    manifest: &Manifest,
) -> Result<discovery::Discovery> {
    let result = discovery::discover(runner, &discovery_pins(manifest), config)?;
    for notice in &result.notices {
        runner.report.progress(&format!("[images] {notice}"))?;
    }
    for warning in &result.warnings {
        runner
            .report
            .progress(&format!("[images] update status unknown: {warning}"))?;
    }
    runner.report.document["image_discovery"] = serde_json::to_value(&result)?;
    runner.report.save()?;
    fs::write(
        runner.evidence().join("image-discovery.json"),
        serde_json::to_vec_pretty(&result)?,
    )?;
    Ok(result)
}

pub(super) fn startup_check(runner: &mut Runner, config: &Config) -> Result<()> {
    let manifest = Manifest::load(&runner.evidence().join("inputs").join(MANIFEST))?;
    report_discovery(runner, config, &manifest)?;
    Ok(())
}

pub(super) fn execute(
    runner: &mut Runner,
    config: &Config,
    config_path: &Path,
    action: &ImageAction,
) -> Result<Option<Refresh>> {
    let inputs = runner.evidence().join("inputs");
    fs::create_dir_all(&inputs)?;
    snapshot(&inputs, config_path)?;
    let mut manifest = Manifest::load(&inputs.join(MANIFEST))?;
    let discovery = report_discovery(runner, config, &manifest)?;
    if matches!(action, ImageAction::Check) {
        return if discovery.warnings.is_empty() {
            Ok(None)
        } else {
            Err("image discovery incomplete; see retained warnings".into())
        };
    }
    let ImageAction::Refresh { distro } = action else {
        unreachable!()
    };
    let selected: Vec<_> = config
        .distros
        .iter()
        .filter_map(|d| d.vendor_image.as_ref())
        .filter(|id| distro.as_ref().is_none_or(|selected| selected == *id))
        .cloned()
        .collect();
    if selected.is_empty() {
        return Err("refresh requires a configured vendor-image target".into());
    }
    let lock = coordination::lock(runner)?;
    // Refresh never creates projects or changes profiles; setup is an explicit separate command.
    let project: Value = serde_json::from_str(&runner.incus(
        &strings(&["query", &format!("/1.0/projects/{}", config.project)]),
        30,
    )?)?;
    let project = project.get("metadata").unwrap_or(&project);
    if project["config"]["user.kidobo-e2e"] != OWNER
        || project["config"]["features.images"] == "false"
    {
        return Err("refresh requires the suite-owned project with isolated image storage".into());
    }
    for id in selected {
        let candidate = discovery
            .candidates
            .iter()
            .find(|candidate| candidate.id == id)
            .ok_or_else(|| format!("no complete discovery candidate for {id}"))?;
        let pin = refresh_candidate(runner, &id, candidate)?;
        manifest.images.insert(id, pin);
    }
    let destination = manifest_path(config_path);
    if read_text(&destination)? != read_text(&inputs.join(MANIFEST))? {
        return Err(
            "image pins changed during refresh; refusing to overwrite concurrent edits".into(),
        );
    }
    if runner.cancelled.load(std::sync::atomic::Ordering::Relaxed) {
        return Err("image refresh interrupted before pin adoption".into());
    }
    fs::write(
        runner.evidence().join("proposed-e2e-images.toml"),
        toml_edit::ser::to_string_pretty(&manifest)?,
    )?;
    runner.report.progress("[images] Verified source images ready. Pins will be adopted after evidence finalization; review the resulting diff before VM acceptance.")?;
    Ok(Some(Refresh {
        destination,
        original: read_text(&inputs.join(MANIFEST))?.into_bytes(),
        manifest,
        _lock: lock,
    }))
}

fn commit_refresh(destination: &Path, original: &[u8], manifest: &Manifest) -> Result<()> {
    if read_text(destination)?.as_bytes() != original {
        return Err(
            "image pins changed during refresh; refusing to overwrite concurrent edits".into(),
        );
    }
    let temporary = destination.with_extension(format!("toml.{}.tmp", std::process::id()));
    let mut file = File::options()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let result = (|| -> Result<()> {
        file.write_all(toml_edit::ser::to_string_pretty(manifest)?.as_bytes())?;
        file.sync_all()?;
        Manifest::load(&temporary)?;
        if read_text(destination)?.as_bytes() != original {
            return Err(
                "image pins changed during refresh; refusing to overwrite concurrent edits".into(),
            );
        }
        fs::rename(&temporary, destination)?;
        Ok(())
    })();
    if temporary.exists() {
        fs::remove_file(&temporary)?;
    }
    result
}

fn download(runner: &mut Runner, url: &str, path: &Path, limit: u64, seconds: u64) -> Result<()> {
    let outcome = runner.command(
        "curl",
        &strings(&[
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--connect-timeout",
            "10",
            "--max-time",
            &seconds.to_string(),
            "--max-filesize",
            &limit.to_string(),
            "--output",
            path.to_str().ok_or("non-UTF-8 download path")?,
            url,
        ]),
        seconds + 2,
    );
    if outcome.is_err() {
        if path.exists() {
            fs::remove_file(path)?;
        }
        outcome?;
    }
    if fs::metadata(path)?.len() > limit {
        fs::remove_file(path)?;
        return Err("vendor download exceeds its size bound".into());
    }
    Ok(())
}

fn verify_signature(runner: &mut Runner, id: &str, pin: &Pin, dir: &Path) -> Result<u64> {
    let source = trust(id)?;
    if pin.signing_fingerprint != source.fingerprint {
        return Err("unreviewed signing identity".into());
    }
    let home = dir.join("gnupg");
    fs::create_dir_all(&home)?;
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700))?;
    let base = strings(&[
        "--batch",
        "--no-options",
        "--homedir",
        home.to_str().ok_or("keyring path")?,
    ]);
    let key = runner.evidence().join("inputs/image-keys").join(source.key);
    let mut args = base.clone();
    args.extend(strings(&["--import", key.to_str().ok_or("key path")?]));
    runner.command("gpg", &args, 30)?;
    let checksum = dir.join("CHECKSUM");
    fs::write(&checksum, &pin.signed_checksum)?;
    let mut args = base;
    args.extend(strings(&["--status-fd", "1"]));
    let plaintext = dir.join("verified-checksums.txt");
    if let Some(signature) = &pin.checksum_signature {
        args.push("--verify".into());
        let path = dir.join("CHECKSUM.asc");
        fs::write(&path, signature)?;
        args.push(path.to_str().ok_or("signature path")?.into());
    } else {
        // Only GPG's authenticated plaintext counts; unsigned text surrounding a
        // valid clearsigned block must never supply an adopted artifact digest.
        args.extend(strings(&[
            "--yes",
            "--output",
            plaintext.to_str().ok_or("plaintext path")?,
            "--decrypt",
        ]));
    }
    args.push(checksum.to_str().ok_or("checksum path")?.into());
    let status = runner.command("gpg", &args, 30)?;
    let signature_time = status
        .lines()
        .find_map(|line| {
            let words: Vec<_> = line.split_whitespace().collect();
            if words.get(1) == Some(&"VALIDSIG")
                && (words.get(2) == Some(&source.fingerprint)
                    || words.last() == Some(&source.fingerprint))
            {
                words
                    .get(4)
                    .and_then(|timestamp| timestamp.parse::<u64>().ok())
            } else {
                None
            }
        })
        .ok_or("checksum was not signed by the reviewed vendor key")?;
    let filename = pin.url.rsplit('/').next().ok_or("missing image filename")?;
    let authenticated = if pin.checksum_signature.is_some() {
        pin.signed_checksum.clone()
    } else {
        read_text(&plaintext)?
    };
    verify_checksum_entry(&authenticated, filename, &pin.sha256)?;
    fs::write(
        dir.join("verification.json"),
        serde_json::to_vec_pretty(
            &json!({"sha256":pin.sha256,"signing_fingerprint":source.fingerprint,"signature_verified":true}),
        )?,
    )?;
    // No persistent keyring or trust database: the checked-in public key and fingerprint are the trust boundary.
    fs::remove_dir_all(home)?;
    Ok(signature_time)
}

fn verify_checksum_entry(text: &str, filename: &str, expected: &str) -> Result<()> {
    let mut values = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("SHA256 (") {
            if let Some((name, digest)) = rest.split_once(") = ")
                && name == filename
            {
                values.push(digest.trim());
            }
        } else {
            let mut words = line.split_whitespace();
            if let (Some(digest), Some(name), None) = (words.next(), words.next(), words.next())
                && name.trim_start_matches('*') == filename
            {
                values.push(digest);
            }
        }
    }
    if values.as_slice() != [expected] {
        return Err("signed checksum must contain exactly one matching artifact digest".into());
    }
    Ok(())
}

fn metadata(id: &str, pin: &Pin) -> String {
    format!(
        "architecture: x86_64\ncreation_date: {}\nproperties:\n  user.kidobo-e2e-source: {OWNER}\n  description: Kidobo upstream {id}\n",
        pin.published_at
    )
}

fn package(runner: &mut Runner, id: &str, pin: &Pin, dir: &Path) -> Result<PathBuf> {
    fs::write(dir.join("metadata.yaml"), metadata(id, pin))?;
    let archive = dir.join("metadata.tar");
    runner.command(
        "tar",
        &strings(&[
            "--format=ustar",
            "--mtime=@0",
            "--owner=0",
            "--group=0",
            "--numeric-owner",
            "--mode=0644",
            "-cf",
            archive.to_str().ok_or("metadata archive path")?,
            "-C",
            dir.to_str().ok_or("metadata path")?,
            "metadata.yaml",
        ]),
        30,
    )?;
    Ok(archive)
}

fn split_fingerprint(metadata: &Path, disk: &Path) -> Result<String> {
    let mut digest = Sha256::new();
    let mut buffer = [0; 8192];
    for path in [metadata, disk] {
        let mut file = File::open(path)?;
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
        }
    }
    let mut fingerprint = String::with_capacity(64);
    for byte in digest.finalize() {
        write!(&mut fingerprint, "{byte:02x}")?;
    }
    Ok(fingerprint)
}

fn check_disk(runner: &mut Runner, disk: &Path, expected: &str) -> Result<()> {
    if hash(disk)? != expected {
        return Err("vendor artifact SHA-256 mismatch".into());
    }
    let info: Value = serde_json::from_str(&runner.command(
        "qemu-img",
        &strings(&["info", "--output=json", disk.to_str().ok_or("disk path")?]),
        60,
    )?)?;
    check_disk_info(&info)?;
    runner.command(
        "qemu-img",
        &strings(&["check", "-f", "qcow2", disk.to_str().ok_or("disk path")?]),
        120,
    )?;
    Ok(())
}

fn check_disk_info(info: &Value) -> Result<()> {
    if info["format"] != "qcow2"
        || info.get("backing-filename").is_some()
        || info.get("data-file").is_some()
        || info.pointer("/format-specific/data/data-file").is_some()
    {
        return Err("vendor disk must be a standalone qcow2 without external files".into());
    }
    Ok(())
}

fn local_image(runner: &mut Runner, fingerprint: &str) -> Result<bool> {
    let images: Vec<Value> =
        serde_json::from_str(&runner.incus(&strings(&["image", "list", "--format=json"]), 30)?)?;
    if let Some(image) = images
        .iter()
        .find(|image| image["fingerprint"] == fingerprint)
    {
        if image["type"] != "virtual-machine" || image["architecture"] != "x86_64" {
            return Err("pinned Incus fingerprint has an incompatible type or architecture".into());
        }
        return Ok(true);
    }
    Ok(false)
}

fn import(runner: &mut Runner, metadata: &Path, disk: &Path, fingerprint: &str) -> Result<()> {
    if local_image(runner, fingerprint)? {
        return Ok(());
    }
    let before: Vec<Value> =
        serde_json::from_str(&runner.incus(&strings(&["image", "list", "--format=json"]), 30)?)?;
    let token = format!(
        "{}-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
        NEXT_IMPORT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let result = runner
        .incus(
            &strings(&[
                "image",
                "import",
                metadata.to_str().ok_or("metadata path")?,
                disk.to_str().ok_or("disk path")?,
                &format!("user.kidobo-e2e-import={token}"),
            ]),
            900,
        )
        .and_then(|_| {
            if local_image(runner, fingerprint)? {
                Ok(())
            } else {
                Err("Incus import did not produce the expected fingerprint".into())
            }
        });
    if let Err(error) = result {
        // A per-import property attributes even an unexpected fingerprint without
        // sweeping another worker's images or touching pre-existing storage.
        let saved = runner.ignore_cancellation;
        runner.ignore_cancellation = true;
        let failed_report = if runner.report.failed() {
            let silent = runner.report.silent()?;
            Some(std::mem::replace(&mut runner.report, silent))
        } else {
            None
        };
        let cleanup = (|| -> Result<()> {
            let images: Vec<Value> = serde_json::from_str(
                &runner.incus(&strings(&["image", "list", "--format=json"]), 30)?,
            )?;
            for image in images.iter().filter(|image| {
                image["properties"]["user.kidobo-e2e-import"] == token
                    && image["properties"]["user.kidobo-e2e-source"] == OWNER
                    && !before
                        .iter()
                        .any(|existing| existing["fingerprint"] == image["fingerprint"])
            }) {
                let created = image["fingerprint"]
                    .as_str()
                    .filter(|value| digest_valid(value))
                    .ok_or("invalid newly imported image fingerprint")?;
                runner.incus(&strings(&["image", "delete", created]), 120)?;
            }
            Ok(())
        })();
        if let Some(report) = failed_report {
            runner.report = report;
        }
        runner.ignore_cancellation = saved;
        if let Err(cleanup_error) = cleanup {
            runner
                .cancelled
                .store(true, std::sync::atomic::Ordering::Relaxed);
            return Err(
                format!("image import failed: {error}; cleanup failed: {cleanup_error}").into(),
            );
        }
        return Err(error);
    }
    Ok(())
}

fn with_disk<T>(
    runner: &mut Runner,
    pin: &Pin,
    dir: &Path,
    operation: impl FnOnce(&mut Runner, &Path) -> Result<T>,
) -> Result<T> {
    let disk = dir.join("upstream.qcow2");
    let outcome = (|| {
        download(runner, &pin.url, &disk, 10 * 1024 * 1024 * 1024, 1800)?;
        check_disk(runner, &disk, &pin.sha256)?;
        operation(runner, &disk)
    })();
    if disk.exists() {
        fs::remove_file(disk)?;
    }
    outcome
}

pub(super) fn resolve(runner: &mut Runner, target: &Distro) -> Result<(String, String)> {
    let Some(id) = &target.vendor_image else {
        let output = runner.incus(
            &strings(&["image", "info", &format!("images:{}", target.image), "--vm"]),
            60,
        )?;
        let fingerprint = output
            .lines()
            .find_map(|line| line.strip_prefix("Fingerprint: "))
            .map(str::trim)
            .filter(|value| digest_valid(value))
            .ok_or("upstream VM image fingerprint missing")?
            .to_owned();
        return Ok((fingerprint.clone(), format!("images:{fingerprint}")));
    };
    let manifest = Manifest::load(&runner.evidence().join("inputs").join(MANIFEST))?;
    let pin = manifest.images.get(id).ok_or("vendor image pin missing")?;
    let dir = runner.evidence().join(&target.id).join("vendor-image");
    fs::create_dir_all(&dir)?;
    verify_signature(runner, id, pin, &dir)?;
    let archive = package(runner, id, pin, &dir)?;
    if !local_image(runner, &pin.incus_fingerprint)? {
        with_disk(runner, pin, &dir, |runner, disk| {
            if split_fingerprint(&archive, disk)? != pin.incus_fingerprint {
                return Err("vendor import fingerprint mismatch".into());
            }
            import(runner, &archive, disk, &pin.incus_fingerprint)
        })?;
    }
    fs::write(
        dir.join("source.json"),
        serde_json::to_vec_pretty(
            &json!({"url":pin.url,"sha256":pin.sha256,"incus_fingerprint":pin.incus_fingerprint,"published_at":pin.published_at,"signing_fingerprint":pin.signing_fingerprint}),
        )?,
    )?;
    Ok((pin.incus_fingerprint.clone(), pin.incus_fingerprint.clone()))
}

fn eligible(published: u64, now: u64) -> Result<()> {
    if published == 0
        || now
            .checked_sub(published)
            .is_none_or(|age| age < MINIMUM_AGE)
    {
        return Err(
            "vendor image publication must be known and at least seven full days old".into(),
        );
    }
    Ok(())
}

fn publication(runner: &mut Runner, url: &str) -> Result<u64> {
    let headers = runner.command(
        "curl",
        &strings(&[
            "--fail",
            "--silent",
            "--show-error",
            "--head",
            "--max-time",
            "20",
            "--max-filesize",
            "65536",
            url,
        ]),
        22,
    )?;
    let modified = headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("last-modified"))
        .map(|(_, value)| value.trim())
        .ok_or("vendor publication timestamp unavailable")?;
    let timestamp = runner.command("date", &strings(&["--utc", "--date", modified, "+%s"]), 5)?;
    Ok(timestamp.trim().parse()?)
}

fn refresh_candidate(
    runner: &mut Runner,
    id: &str,
    candidate: &discovery::Candidate,
) -> Result<Pin> {
    let source = trust(id)?;
    if !candidate.url.starts_with(&source.prefix)
        || !candidate.checksum_url.starts_with(&source.prefix)
        || candidate
            .signature_url
            .as_ref()
            .is_some_and(|url| !url.starts_with(&source.prefix))
    {
        return Err("discovery candidate is outside the reviewed vendor source".into());
    }
    let dir = runner.evidence().join("image-refresh").join(id);
    fs::create_dir_all(&dir)?;
    let published_at = publication(runner, &candidate.url)?;
    eligible(
        published_at,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?;
    download(
        runner,
        &candidate.checksum_url,
        &dir.join("CHECKSUM"),
        METADATA_LIMIT,
        30,
    )?;
    let signature = if let Some(url) = &candidate.signature_url {
        download(runner, url, &dir.join("CHECKSUM.asc"), METADATA_LIMIT, 30)?;
        Some(read_text(&dir.join("CHECKSUM.asc"))?)
    } else {
        None
    };
    let mut pin = Pin {
        url: candidate.url.clone(),
        sha256: candidate.sha256.clone(),
        architecture: "x86_64".into(),
        published_at,
        signing_fingerprint: source.fingerprint.into(),
        incus_fingerprint: String::new(),
        signed_checksum: read_text(&dir.join("CHECKSUM"))?,
        checksum_signature: signature,
    };
    let signature_time = verify_signature(runner, id, &pin, &dir)?;
    pin.published_at = pin.published_at.max(signature_time);
    eligible(
        pin.published_at,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?;
    let archive = package(runner, id, &pin, &dir)?;
    pin.incus_fingerprint = with_disk(runner, &pin, &dir, |runner, disk| {
        let fingerprint = split_fingerprint(&archive, disk)?;
        import(runner, &archive, disk, &fingerprint)?;
        Ok(fingerprint)
    })?;
    Ok(pin)
}
