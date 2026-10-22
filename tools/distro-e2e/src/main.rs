//! Host orchestrator: privileged application commands can only cross a verified Incus VM boundary.
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const OWNER: &str = "kidobo-e2e-v1";

#[derive(Parser)]
struct Cli {
    #[arg(long, default_value = "config/e2e.toml")]
    config: PathBuf,
    #[command(subcommand)]
    action: Action,
}
#[derive(Subcommand)]
enum Action {
    Setup,
    Run {
        #[arg(long)]
        archive: Option<PathBuf>,
        #[arg(long, default_value = "latest")]
        tag: String,
        #[arg(long)]
        published: bool,
        #[arg(long)]
        distro: Option<String>,
        #[arg(long)]
        keep_failed: bool,
    },
    Clean {
        run_id: String,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    project: String,
    profile: String,
    network: String,
    pool: String,
    cpus: u32,
    memory: String,
    disk: String,
    distros: Vec<Distro>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Distro {
    id: String,
    image: String,
    family: String,
    packages: Vec<String>,
}
#[derive(Serialize, Deserialize)]
struct Owned {
    owner: String,
    project: String,
    instances: Vec<String>,
}
struct Runner {
    project: String,
    dir: PathBuf,
    incus_program: PathBuf,
    cancelled: Arc<AtomicBool>,
    sequence: usize,
}
fn safe_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() < 64
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}
impl Runner {
    fn command(&mut self, program: &str, args: &[String], seconds: u64) -> Result<String> {
        const OUTPUT_LIMIT: u64 = 16 * 1024 * 1024;

        self.sequence += 1;
        let stem = self.dir.join(format!("{:04}", self.sequence));
        let out = File::create(stem.with_extension("stdout"))?;
        let err = File::create(stem.with_extension("stderr"))?;
        let started = Instant::now();
        let mut child = match Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(out)
            .stderr(err)
            .process_group(0)
            .spawn()
        {
            Ok(child) => child,
            Err(error) => {
                fs::write(
                    stem.with_extension("json"),
                    serde_json::to_vec_pretty(&json!({
                        "program": program,
                        "args": args,
                        "code": null,
                        "seconds": started.elapsed().as_secs_f64(),
                        "error": format!("spawn failed: {error}"),
                    }))?,
                )?;
                return Err(format!(
                    "failed to start {program}: {error}; logs: {}",
                    stem.display()
                )
                .into());
            }
        };
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            let interrupted = self.cancelled.load(Ordering::Relaxed);
            let timed_out = started.elapsed() > Duration::from_secs(seconds);
            if interrupted || timed_out {
                let pid = i32::try_from(child.id())?;
                let _ = nix::sys::signal::killpg(
                    nix::unistd::Pid::from_raw(pid),
                    nix::sys::signal::Signal::SIGKILL,
                );
                let _ = child.wait();
                let reason = if interrupted {
                    "interrupted"
                } else {
                    "timed out"
                };
                fs::write(
                    stem.with_extension("json"),
                    serde_json::to_vec_pretty(&json!({
                        "program": program,
                        "args": args,
                        "code": null,
                        "seconds": started.elapsed().as_secs_f64(),
                        "error": reason,
                    }))?,
                )?;
                return Err(format!("{program} {reason}; logs: {}", stem.display()).into());
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        fs::write(
            stem.with_extension("json"),
            serde_json::to_vec_pretty(
                &json!({"program":program,"args":args,"code":status.code(),"seconds":started.elapsed().as_secs_f64()}),
            )?,
        )?;
        if !status.success() {
            return Err(format!("{program} exited {status}; logs: {}", stem.display()).into());
        }
        let stdout_path = stem.with_extension("stdout");
        if fs::metadata(&stdout_path)?.len() > OUTPUT_LIMIT {
            return Err(format!(
                "{program} stdout exceeds the {OUTPUT_LIMIT}-byte capture limit; logs: {}",
                stem.display()
            )
            .into());
        }
        let mut output = String::new();
        File::open(stdout_path)?
            .take(OUTPUT_LIMIT)
            .read_to_string(&mut output)?;
        Ok(output)
    }
    fn incus(&mut self, args: &[String], seconds: u64) -> Result<String> {
        let mut full = vec!["--project".into(), self.project.clone()];
        full.extend_from_slice(args);
        let program = self.incus_program.to_string_lossy().into_owned();
        self.command(&program, &full, seconds)
    }
    fn verify(&mut self, vm: &str) -> Result<()> {
        let output = self.incus(&strings(&["list", vm, "--format=json"]), 30)?;
        let values: Vec<serde_json::Value> = serde_json::from_str(&output)?;
        let value = values
            .iter()
            .find(|value| value["name"] == vm)
            .ok_or("VM missing")?;
        validate_vm_config(value)?;
        Ok(())
    }
    fn create_vm(&mut self, image: &str, vm: &str, profile: &str) -> Result<()> {
        self.incus(
            &strings(&[
                "init",
                &format!("images:{image}"),
                vm,
                "--vm",
                "--profile",
                profile,
                "-c",
                &format!("user.kidobo-e2e={OWNER}"),
            ]),
            900,
        )?;
        self.verify(vm)?;
        self.incus(
            &strings(&[
                "config",
                "device",
                "add",
                vm,
                "agent",
                "disk",
                "source=agent:config",
            ]),
            30,
        )?;
        self.incus(&strings(&["start", vm]), 900)?;
        Ok(())
    }
    fn guest(&mut self, vm: &str, args: &[String], seconds: u64) -> Result<String> {
        self.verify(vm)?;
        let mut full = strings(&["exec", vm, "--mode=non-interactive", "--"]);
        full.extend_from_slice(args);
        self.incus(&full, seconds)
    }
    fn ready(&mut self, vm: &str) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(300);
        loop {
            if self.guest(vm, &strings(&["true"]), 15).is_ok() {
                return Ok(());
            }
            if self.cancelled.load(Ordering::Relaxed) || Instant::now() > deadline {
                return Err("VM agent did not become ready".into());
            }
            std::thread::sleep(Duration::from_secs(3));
        }
    }
    fn reboot(&mut self, vm: &str) -> Result<()> {
        let before = self.guest(
            vm,
            &strings(&["cat", "/proc/sys/kernel/random/boot_id"]),
            30,
        )?;
        self.incus(&strings(&["restart", vm, "--timeout=60"]), 120)?;
        self.ready(vm)?;
        let after = self.guest(
            vm,
            &strings(&["cat", "/proc/sys/kernel/random/boot_id"]),
            30,
        )?;
        if before == after {
            return Err("VM reboot did not change boot ID".into());
        }
        Ok(())
    }
    fn push(&mut self, vm: &str, source: &Path, dest: &str, recursive: bool) -> Result<()> {
        self.verify(vm)?;
        let mut args = strings(&["file", "push"]);
        if recursive {
            args.push("-r".into());
        }
        args.extend([source.to_string_lossy().into_owned(), format!("{vm}{dest}")]);
        self.incus(&args, 120)?;
        Ok(())
    }
    fn delete(&mut self, vm: &str) -> Result<()> {
        self.verify(vm)?;
        self.incus(&strings(&["delete", vm, "--force"]), 120)?;
        Ok(())
    }
}
fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|v| (*v).to_owned()).collect()
}
fn hash(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    let mut output = String::with_capacity(64);
    for byte in digest.finalize() {
        write!(&mut output, "{byte:02x}")?;
    }
    Ok(output)
}
fn tag_valid(tag: &str) -> bool {
    tag.starts_with('v')
        && tag.len() > 1
        && tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
}
#[expect(
    clippy::too_many_lines,
    reason = "Infrastructure creation is one ordered ownership transaction"
)]
fn setup(runner: &mut Runner, config: &Config) -> Result<()> {
    let incus_program = runner.incus_program.to_string_lossy().into_owned();
    // Show existing resources first; never overwrite an administrator's configuration.
    for (kind, name, create) in [
        (
            "project",
            &config.project,
            strings(&[
                "project",
                "create",
                &config.project,
                "-c",
                "features.profiles=true",
                "-c",
                &format!("user.kidobo-e2e={OWNER}"),
            ]),
        ),
        (
            "storage",
            &config.pool,
            strings(&[
                "storage",
                "create",
                &config.pool,
                "dir",
                &format!("user.kidobo-e2e={OWNER}"),
            ]),
        ),
        (
            "network",
            &config.network,
            strings(&[
                "network",
                "create",
                &config.network,
                "ipv4.address=auto",
                "ipv4.nat=true",
                "ipv6.address=none",
                &format!("user.kidobo-e2e={OWNER}"),
            ]),
        ),
    ] {
        let show = runner.command(
            &incus_program,
            &strings(&["--project", "default", kind, "show", name]),
            30,
        );
        if show.is_ok() {
            let owner = runner.command(
                &incus_program,
                &strings(&["--project", "default", kind, "get", name, "user.kidobo-e2e"]),
                30,
            )?;
            if owner.trim() != OWNER {
                return Err(format!("existing {kind} {name} is not owned by this suite").into());
            }
        } else {
            let mut args = strings(&["--project", "default"]);
            args.extend(create);
            runner.command(&incus_program, &args, 60)?;
        }
    }
    if runner
        .incus(&strings(&["profile", "show", &config.profile]), 30)
        .is_ok()
    {
        let owner = runner.incus(
            &strings(&["profile", "get", &config.profile, "user.kidobo-e2e"]),
            30,
        )?;
        if owner.trim() != OWNER {
            return Err("existing profile is not suite-owned".into());
        }
    } else {
        runner.incus(&strings(&["profile", "create", &config.profile]), 30)?;
        runner.incus(
            &strings(&[
                "profile",
                "set",
                &config.profile,
                &format!("user.kidobo-e2e={OWNER}"),
            ]),
            30,
        )?;
    }
    for (device, kind, properties) in [
        (
            "root",
            "disk",
            strings(&[
                "path=/",
                &format!("pool={}", config.pool),
                &format!("size={}", config.disk),
            ]),
        ),
        (
            "eth0",
            "nic",
            strings(&[&format!("network={}", config.network), "name=eth0"]),
        ),
    ] {
        let existing_type = runner.incus(
            &strings(&["profile", "device", "get", &config.profile, device, "type"]),
            30,
        );
        if let Ok(existing_type) = existing_type {
            if existing_type.trim() != kind {
                return Err(format!(
                    "suite profile device {device} has type {:?}; expected {kind}",
                    existing_type.trim()
                )
                .into());
            }
            let mut args = strings(&["profile", "device", "set", &config.profile, device]);
            for property in properties {
                let (key, desired) = property.split_once('=').ok_or("invalid device property")?;
                let current = runner.incus(
                    &strings(&["profile", "device", "get", &config.profile, device, key]),
                    30,
                )?;
                if current.trim() != desired {
                    args.push(property);
                }
            }
            if args.len() > 5 {
                runner.incus(&args, 30)?;
            }
        } else {
            let mut args = strings(&["profile", "device", "add", &config.profile, device, kind]);
            args.extend(properties);
            runner.incus(&args, 30)?;
        }
    }
    let mut limits = strings(&["profile", "set", &config.profile]);
    for (key, desired) in [
        ("limits.cpu", config.cpus.to_string()),
        ("limits.memory", config.memory.clone()),
    ] {
        let current = runner.incus(&strings(&["profile", "get", &config.profile, key]), 30)?;
        if current.trim() != desired {
            limits.push(format!("{key}={desired}"));
        }
    }
    if limits.len() > 3 {
        runner.incus(&limits, 30)?;
    }
    Ok(())
}
fn prepare_baseline(runner: &mut Runner, vm: &str) -> Result<()> {
    let baseline = read_text(&runner.dir.join("baseline-tag"))?;
    runner.guest(
        vm,
        &strings(&["mkdir", "-p", "/opt/kidobo-e2e/baseline"]),
        30,
    )?;
    runner.push(
        vm,
        &runner.dir.join("baseline-installer.sh"),
        "/opt/kidobo-e2e/baseline/installer.sh",
        false,
    )?;
    runner.push(
        vm,
        &runner.dir.join("baseline-SHA256SUMS"),
        "/opt/kidobo-e2e/baseline/SHA256SUMS",
        false,
    )?;
    runner.guest(
        vm,
        &strings(&["chmod", "+x", "/opt/kidobo-e2e/baseline/installer.sh"]),
        30,
    )?;
    runner.guest(
        vm,
        &strings(&[
            "bash",
            "-c",
            &format!(
                "printf '%s' '{}' > /opt/kidobo-e2e/baseline-tag",
                baseline.trim()
            ),
        ]),
        30,
    )?;
    Ok(())
}
fn scenario(
    runner: &mut Runner,
    vm: &str,
    distro: &Distro,
    tag: &str,
    published: bool,
    archive: Option<&Path>,
    phase: &mut &str,
) -> Result<()> {
    *phase = "provisioning";
    runner.ready(vm)?;
    runner.guest(vm, &strings(&["sh", "-c", "printf '%s\\n' kidobo-e2e-v1 > /etc/kidobo-e2e-owned; mkdir -p /opt/kidobo-e2e/release"]), 30)?;
    for script in ["provision.sh", "lifecycle.sh", "traffic.py"] {
        runner.push(
            vm,
            &runner.dir.join("inputs").join(script),
            &format!("/opt/kidobo-e2e/{script}"),
            false,
        )?;
    }
    let mut args = strings(&["bash", "/opt/kidobo-e2e/provision.sh", &distro.family]);
    args.extend(distro.packages.clone());
    runner.guest(vm, &args, 2400)?;
    runner.push(
        vm,
        &runner.dir.join("inputs/installer.sh"),
        "/opt/kidobo-e2e/release/installer.sh",
        false,
    )?;
    runner.guest(
        vm,
        &strings(&["chmod", "+x", "/opt/kidobo-e2e/release/installer.sh"]),
        30,
    )?;
    if let Some(archive) = archive {
        runner.push(
            vm,
            archive,
            &format!(
                "/opt/kidobo-e2e/release/{}",
                archive
                    .file_name()
                    .ok_or("archive has no filename")?
                    .to_string_lossy()
            ),
            false,
        )?;
        runner.push(
            vm,
            &archive.with_file_name("SHA256SUMS"),
            "/opt/kidobo-e2e/release/SHA256SUMS",
            false,
        )?;
    }
    if !published {
        prepare_baseline(runner, vm)?;
    }
    runner.guest(
        vm,
        &strings(&[
            "bash",
            "/opt/kidobo-e2e/lifecycle.sh",
            "os-upgrade",
            tag,
            if published { "published" } else { "candidate" },
        ]),
        2400,
    )?;
    runner.reboot(vm)?;
    runner.guest(
        vm,
        &strings(&["bash", "/opt/kidobo-e2e/provision.sh", "--check-kernel"]),
        60,
    )?;
    *phase = "application";
    let mode = if published { "published" } else { "candidate" };
    runner.guest(
        vm,
        &strings(&["bash", "/opt/kidobo-e2e/lifecycle.sh", "start", tag, mode]),
        600,
    )?;
    if !published {
        runner.reboot(vm)?;
        runner.guest(
            vm,
            &strings(&[
                "bash",
                "/opt/kidobo-e2e/lifecycle.sh",
                "after-reboot",
                tag,
                mode,
            ]),
            600,
        )?;
        runner.guest(
            vm,
            &strings(&["bash", "/opt/kidobo-e2e/lifecycle.sh", "upgrade", tag, mode]),
            600,
        )?;
    }
    runner.guest(
        vm,
        &strings(&["bash", "/opt/kidobo-e2e/lifecycle.sh", "finish", tag, mode]),
        600,
    )?;
    Ok(())
}
fn clean(runner: &mut Runner, config: &Config) -> Result<()> {
    let owned: Owned = serde_json::from_str(&read_text(&runner.dir.join("ownership.json"))?)?;
    let run_id = runner
        .dir
        .file_name()
        .ok_or("ownership directory has no run ID")?
        .to_string_lossy();
    validate_owned_manifest(&owned, &config.project, &run_id)?;
    for vm in owned.instances {
        // A previous cleanup may already have removed this VM.
        let output = runner.incus(&strings(&["list", "--format=json"]), 30)?;
        let list: Vec<serde_json::Value> = serde_json::from_str(&output)?;
        if list.iter().any(|v| v["name"] == vm) {
            runner.delete(&vm)?;
        }
    }
    Ok(())
}
fn validate_owned_manifest(owned: &Owned, project: &str, run_id: &str) -> Result<()> {
    if owned.owner != OWNER
        || owned.project != project
        || !safe_name(run_id)
        || owned
            .instances
            .iter()
            .any(|instance| !safe_name(instance) || !instance.starts_with(&format!("{run_id}-")))
    {
        return Err("invalid ownership manifest".into());
    }
    Ok(())
}
fn render_summary(tag: &str, artifact_hash: Option<&str>, results: &[serde_json::Value]) -> String {
    let mut summary = format!("Kidobo distro E2E run for {tag}\n");
    if let Some(hash) = artifact_hash {
        writeln!(summary, "Archive SHA-256: {hash}").expect("write to String");
    }
    summary.push('\n');
    for result in results {
        let distro = result["distro"].as_str().unwrap_or("unknown");
        let phase = result["phase"].as_str().unwrap_or("unknown");
        let status = if result["error"].is_null() {
            "PASS"
        } else {
            "FAIL"
        };
        let seconds = result["seconds"].as_f64().unwrap_or_default();
        let image = result["image"].as_str().unwrap_or("unknown");
        let fingerprint = result["image_fingerprint"]
            .as_str()
            .unwrap_or("unavailable");
        let diagnostic_count = result["diagnostic_errors"].as_array().map_or(0, Vec::len);
        writeln!(
            summary,
            "{distro}: {status} ({phase}, {seconds:.1}s) image={image} base_image={fingerprint} diagnostics={diagnostic_count}"
        )
        .expect("write to String");
        if let Some(error) = result["error"].as_str() {
            writeln!(summary, "  error: {error}").expect("write to String");
        }
        if let Some(errors) = result["diagnostic_errors"].as_array() {
            for error in errors.iter().filter_map(serde_json::Value::as_str) {
                writeln!(summary, "  diagnostic: {error}").expect("write to String");
            }
        }
    }
    summary
}
#[expect(
    clippy::too_many_lines,
    reason = "Matrix execution keeps diagnostics and cleanup adjacent to lifecycle execution"
)]
fn run(cli: Cli) -> Result<()> {
    let config: Config = toml_edit::de::from_str(&read_text(&cli.config)?)?;
    if [
        &config.project,
        &config.profile,
        &config.pool,
        &config.network,
    ]
    .iter()
    .any(|v| !safe_name(v))
        || config.distros.iter().any(|d| !safe_name(&d.id))
    {
        return Err("unsafe resource identifier".into());
    }
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal = cancelled.clone();
    ctrlc::set_handler(move || signal.store(true, Ordering::Relaxed))?;
    let run_id = match &cli.action {
        Action::Clean { run_id } => run_id.clone(),
        _ => format!(
            "run-{}-{}",
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            std::process::id()
        ),
    };
    if !safe_name(&run_id) {
        return Err("invalid run ID".into());
    }
    let dir = std::env::var_os("KIDOBO_E2E_RESULTS_DIR")
        .map_or_else(|| PathBuf::from("target/e2e"), PathBuf::from)
        .join(&run_id);
    fs::create_dir_all(&dir)?;
    let sequence = fs::read_dir(&dir)?.count();
    let mut runner = Runner {
        project: config.project.clone(),
        dir,
        incus_program: PathBuf::from("incus"),
        cancelled,
        sequence,
    };
    if !matches!(&cli.action, Action::Clean { .. }) {
        if std::env::consts::OS != "linux" || std::env::consts::ARCH != "x86_64" {
            return Err("distro E2E requires a Linux x86_64 host".into());
        }
        runner
            .command(
                "sh",
                &strings(&[
                    "-c",
                    "command -v genisoimage >/dev/null || command -v mkisofs >/dev/null",
                ]),
                10,
            )
            .map_err(|error| {
                format!("Incus agent CD-ROM requires host genisoimage or mkisofs: {error}")
            })?;
    }
    match cli.action {
        Action::Setup => setup(&mut runner, &config),
        Action::Clean { .. } => clean(&mut runner, &config),
        Action::Run {
            archive,
            mut tag,
            published,
            distro,
            keep_failed,
        } => {
            if published && archive.is_some() || !published && archive.is_none() {
                return Err("choose --published or --archive".into());
            }
            if published && tag == "latest" {
                let url = runner.command(
                    "curl",
                    &strings(&[
                        "-fsSL",
                        "--max-time",
                        "60",
                        "-o",
                        "/dev/null",
                        "-w",
                        "%{url_effective}",
                        "https://github.com/blwarren/kidobo/releases/latest",
                    ]),
                    90,
                )?;
                url.rsplit('/')
                    .next()
                    .ok_or("missing release tag")?
                    .trim()
                    .clone_into(&mut tag);
            }
            if !tag_valid(&tag) {
                return Err("invalid version tag".into());
            }
            snapshot_inputs(&runner.dir, &cli.config)?;
            let archive = archive.map(fs::canonicalize).transpose()?;
            let artifact_hash = archive.as_deref().map(hash).transpose()?;
            let test_archive = archive
                .as_deref()
                .map(|source| freeze_archive(source, &runner.dir))
                .transpose()?;
            if test_archive.as_deref().map(hash).transpose()? != artifact_hash {
                return Err("candidate changed while taking its input snapshot".into());
            }
            if !published {
                let release_list = runner.command(
                    "curl",
                    &strings(&[
                        "-fsSL",
                        "--max-time",
                        "60",
                        "https://api.github.com/repos/blwarren/kidobo/releases?per_page=100",
                    ]),
                    90,
                )?;
                let releases: Vec<serde_json::Value> = serde_json::from_str(&release_list)?;
                let target_version =
                    version_numbers(&tag).ok_or("invalid numeric candidate version")?;
                let baseline = releases
                    .iter()
                    .filter(|v| v["draft"] == false && v["prerelease"] == false)
                    .filter_map(|v| v["tag_name"].as_str())
                    .filter(|v| tag_valid(v))
                    .filter_map(|v| version_numbers(v).map(|n| (n, v)))
                    .filter(|(n, _)| *n < target_version)
                    .max_by_key(|(n, _)| *n)
                    .ok_or("no earlier published upgrade baseline found")?
                    .1;
                fs::write(runner.dir.join("baseline-tag"), baseline)?;
                for (url, name) in [
                    (
                        format!(
                            "https://raw.githubusercontent.com/blwarren/kidobo/{baseline}/scripts/install.sh"
                        ),
                        "baseline-installer.sh",
                    ),
                    (
                        format!(
                            "https://github.com/blwarren/kidobo/releases/download/{baseline}/SHA256SUMS"
                        ),
                        "baseline-SHA256SUMS",
                    ),
                ] {
                    runner.command(
                        "curl",
                        &strings(&[
                            "-fsSL",
                            "--retry",
                            "2",
                            "--max-time",
                            "60",
                            "-o",
                            &runner.dir.join(name).to_string_lossy(),
                            &url,
                        ]),
                        200,
                    )?;
                }
            }

            let targets: Vec<_> = config
                .distros
                .iter()
                .filter(|d| distro.as_ref().is_none_or(|id| *id == d.id))
                .collect();
            if targets.is_empty() {
                return Err("no matching distros".into());
            }
            let mut owned = Owned {
                owner: OWNER.into(),
                project: config.project.clone(),
                instances: vec![],
            };
            let mut results = vec![];
            for target in targets {
                if runner.cancelled.load(Ordering::Relaxed) {
                    break;
                }
                let vm = format!("{}-{}", run_id, target.id);
                let target_dir = runner.dir.join(&target.id);
                fs::create_dir_all(&target_dir)?;
                owned.instances.push(vm.clone());
                fs::write(
                    runner.dir.join("ownership.json"),
                    serde_json::to_vec_pretty(&owned)?,
                )?;
                println!("[e2e] {}: fresh VM {vm}", target.id);
                let started = Instant::now();
                let launch = runner.create_vm(&target.image, &vm, &config.profile);
                let mut phase = "provisioning";
                let outcome = launch.and_then(|()| {
                    scenario(
                        &mut runner,
                        &vm,
                        target,
                        &tag,
                        published,
                        test_archive.as_deref(),
                        &mut phase,
                    )
                });
                // Diagnostics and cleanup remain possible after SIGINT.
                let interrupted = runner.cancelled.swap(false, Ordering::Relaxed);
                let mut diagnostic_errors = vec![];
                let mut image_fingerprint: Option<String> = None;
                let vm_snapshot = runner
                    .incus(&strings(&["list", &vm, "--format=json"]), 30)
                    .and_then(|output| -> Result<()> {
                        let instances: Vec<serde_json::Value> = serde_json::from_str(&output)?;
                        let instance = instances
                            .iter()
                            .find(|instance| instance["name"] == vm)
                            .ok_or("VM missing from Incus diagnostics")?;
                        validate_vm_config(instance)?;
                        image_fingerprint = instance["config"]["volatile.base_image"]
                            .as_str()
                            .map(str::to_owned);
                        fs::write(
                            target_dir.join("vm.json"),
                            serde_json::to_vec_pretty(instance)?,
                        )?;
                        Ok(())
                    });
                if let Err(error) = vm_snapshot {
                    diagnostic_errors.push(format!("VM metadata: {error}"));
                } else {
                    let diagnostic_script = r"
printf '%s\n' '=== uname ==='; uname -a || true
printf '%s\n' '=== os-release ==='; cat /etc/os-release || true
printf '%s\n' '=== packages ==='
if command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f='${binary:Package}\t${Version}\n' || true; elif command -v rpm >/dev/null 2>&1; then rpm -qa || true; fi
printf '%s\n' '=== netfilter ==='; iptables --version || true; ip6tables --version || true; ipset save || true; iptables-save || true; ip6tables-save || true
printf '%s\n' '=== missing-chain comparison ==='; iptables -S E2E-ABSENT-CHAIN 2>&1 || true; ip6tables -S E2E-ABSENT-CHAIN 2>&1 || true
printf '%s\n' '=== native nft rules ==='; if command -v nft >/dev/null 2>&1; then nft list ruleset || true; fi
printf '%s\n' '=== kidobo service journal ==='; journalctl -u kidobo-sync.service --no-pager || true
";
                    match runner.guest(&vm, &strings(&["bash", "-c", diagnostic_script]), 120) {
                        Ok(output) => {
                            if let Err(error) =
                                fs::write(target_dir.join("guest-diagnostics.txt"), output)
                            {
                                diagnostic_errors.push(format!("write guest diagnostics: {error}"));
                            }
                        }
                        Err(error) => diagnostic_errors.push(format!("guest diagnostics: {error}")),
                    }
                    match runner.guest(&vm, &strings(&["test", "-d", "/opt/kidobo-e2e/state"]), 30)
                    {
                        Ok(_) => {
                            let pull = runner.verify(&vm).and_then(|()| {
                                let source = format!("{vm}/opt/kidobo-e2e/state");
                                let destination =
                                    target_dir.join("state").to_string_lossy().into_owned();
                                let mut args = strings(&["file", "pull", "-r"]);
                                args.extend([source, destination]);
                                runner.incus(&args, 120).map(|_| ())
                            });
                            if let Err(error) = pull {
                                diagnostic_errors.push(format!("pull guest state: {error}"));
                            }
                        }
                        Err(error) => {
                            diagnostic_errors.push(format!("guest state unavailable: {error}"));
                        }
                    }
                }
                let mut error = outcome.err().map(|e| e.to_string());
                if !(keep_failed && error.is_some())
                    && let Err(e) = runner.delete(&vm)
                {
                    error = Some(format!("{}; cleanup: {e}", error.unwrap_or_default()));
                }
                println!(
                    "[e2e] {}: {}",
                    target.id,
                    error.as_deref().unwrap_or("PASS")
                );
                results.push(json!({
                    "distro": target.id,
                    "phase": phase,
                    "error": error,
                    "seconds": started.elapsed().as_secs_f64(),
                    "image": target.image,
                    "image_fingerprint": image_fingerprint,
                    "diagnostic_errors": diagnostic_errors,
                }));
                fs::write(
                    runner.dir.join("results.json"),
                    serde_json::to_vec_pretty(
                        &json!({"tag":tag,"archive_sha256":artifact_hash,"results":results}),
                    )?,
                )?;
                fs::write(
                    runner.dir.join("summary.txt"),
                    render_summary(&tag, artifact_hash.as_deref(), &results),
                )?;
                if interrupted {
                    runner.cancelled.store(true, Ordering::Relaxed);
                    break;
                }
            }
            if archive.as_deref().map(hash).transpose()? != artifact_hash {
                return Err("candidate archive changed during testing".into());
            }
            if runner.cancelled.load(Ordering::Relaxed)
                || results.iter().any(|r| !r["error"].is_null())
            {
                return Err(format!("matrix failed; results: {}", runner.dir.display()).into());
            }
            Ok(())
        }
    }
}
fn read_text(path: &Path) -> Result<String> {
    let mut text = String::new();
    File::open(path)?
        .take(1024 * 1024 + 1)
        .read_to_string(&mut text)?;
    if text.len() > 1024 * 1024 {
        return Err("file exceeds 1 MiB".into());
    }
    Ok(text)
}
fn freeze_archive(source: &Path, dir: &Path) -> Result<PathBuf> {
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
fn snapshot_inputs(dir: &Path, config: &Path) -> Result<()> {
    let inputs = dir.join("inputs");
    fs::create_dir(&inputs)?;
    let mut hashes = serde_json::Map::new();
    for (source, name) in [
        (Path::new("scripts/install.sh"), "installer.sh"),
        (Path::new("scripts/e2e/provision.sh"), "provision.sh"),
        (Path::new("scripts/e2e/lifecycle.sh"), "lifecycle.sh"),
        (Path::new("scripts/e2e/traffic.py"), "traffic.py"),
        (config, "e2e.toml"),
    ] {
        let destination = inputs.join(name);
        fs::copy(source, &destination)?;
        hashes.insert(name.into(), hash(&destination)?.into());
    }
    fs::write(
        inputs.join("SHA256.json"),
        serde_json::to_vec_pretty(&hashes)?,
    )?;
    Ok(())
}
fn version_numbers(tag: &str) -> Option<(u64, u64, u64)> {
    let mut parts = tag.strip_prefix('v')?.split('-').next()?.split('.');
    let value = (
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    );
    if parts.next().is_some() {
        return None;
    }
    Some(value)
}
fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("[e2e] {error}");
        std::process::exit(1);
    }
}
fn validate_vm_config(value: &serde_json::Value) -> Result<()> {
    if value["type"] != "virtual-machine" || value["config"]["user.kidobo-e2e"] != OWNER {
        return Err("refusing operations on an unowned or non-VM instance".into());
    }
    Ok(())
}
#[cfg(test)]
mod tests;
