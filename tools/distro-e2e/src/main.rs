//! Host orchestrator: privileged application commands can only cross a verified Incus VM boundary.
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const OWNER: &str = "kidobo-e2e-v1";

mod contract;
mod coordination;
mod matrix;
mod prepared;
mod report;
mod resume;
use report::Report;

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
        /// Run the configured release requirements, omitting advisory compatibility targets.
        #[arg(long, conflicts_with = "distro")]
        required_only: bool,
        #[arg(long)]
        keep_failed: bool,
        /// Reuse completed target results for the same candidate and test inputs.
        #[arg(long, conflicts_with_all = ["published", "distro"])]
        resume: Option<String>,
        /// Rebuild selected preparation images and rerun selected lifecycle results.
        #[arg(long)]
        refresh_images: bool,
    },
    Clean {
        run_id: String,
    },
}
#[derive(Clone, Deserialize, Serialize)]
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
    #[serde(default = "default_parallelism")]
    max_parallel_vms: usize,
    #[serde(default)]
    prepared_images: prepared::Settings,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Distro {
    id: String,
    image: String,
    family: String,
    packages: Vec<String>,
    #[serde(default = "required_by_default")]
    required: bool,
    #[serde(default = "default_selinux")]
    selinux: String,
}
fn default_parallelism() -> usize {
    2
}
fn default_selinux() -> String {
    "image-default".into()
}
fn required_by_default() -> bool {
    true
}
fn selected_targets<'a>(
    config: &'a Config,
    distro: Option<&str>,
    required_only: bool,
) -> Vec<&'a Distro> {
    config
        .distros
        .iter()
        .filter(|d| distro.is_none_or(|id| id == d.id) && (!required_only || d.required))
        .collect()
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
    report: Report,
    command_poll_interval: Duration,
    ignore_cancellation: bool,
}
/// Each command owns only one pair of temporary files, removed even on failure.
struct Capture {
    dir: PathBuf,
    stdout: File,
    stderr: File,
}
struct ManagedChild {
    child: Child,
    completed: bool,
}
impl std::ops::Deref for ManagedChild {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.child
    }
}
impl std::ops::DerefMut for ManagedChild {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.child
    }
}
impl Drop for ManagedChild {
    fn drop(&mut self) {
        if !self.completed {
            if let Ok(pid) = i32::try_from(self.child.id()) {
                let _ = nix::sys::signal::killpg(
                    nix::unistd::Pid::from_raw(pid),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
            let _ = self.child.wait();
        }
    }
}
impl Capture {
    fn new(root: &Path) -> Result<Self> {
        static NEXT_CAPTURE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = root.join(format!(
            ".capture-{}-{}",
            std::process::id(),
            NEXT_CAPTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir)?;
        let result = (|| -> Result<Self> {
            Ok(Self {
                stdout: File::create(dir.join("stdout"))?,
                stderr: File::create(dir.join("stderr"))?,
                dir: dir.clone(),
            })
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&dir);
        }
        result
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}
#[derive(Default)]
struct Heartbeat {
    last_activity: Duration,
    last_notice: Duration,
}
impl Heartbeat {
    fn due(&mut self, elapsed: Duration, activity: bool) -> bool {
        if activity {
            self.last_activity = elapsed;
        }
        if elapsed.saturating_sub(self.last_activity.max(self.last_notice))
            >= Duration::from_secs(15)
        {
            self.last_notice = elapsed;
            true
        } else {
            false
        }
    }
}
fn archive_evidence(runner: &mut Runner) -> Result<()> {
    archive_evidence_using(runner, "tar")
}
fn archive_evidence_using(runner: &mut Runner, program: &str) -> Result<()> {
    runner.stage("finalizing evidence archive")?;
    fs::create_dir_all(runner.evidence())?;
    fs::write(
        runner.evidence().join("README.txt"),
        "Frozen inputs and SHA256 manifest: inputs/\nGuest diagnostics and snapshots: <distro>/\nCommand output and check references: ../transcript.log and ../results.json\n",
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
fn safe_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() < 64
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}
impl Runner {
    fn worker(&self, sink: std::sync::mpsc::SyncSender<report::Event>) -> Result<Self> {
        Ok(Self {
            project: self.project.clone(),
            dir: self.dir.clone(),
            incus_program: self.incus_program.clone(),
            cancelled: Arc::clone(&self.cancelled),
            report: self.report.worker(sink)?,
            command_poll_interval: self.command_poll_interval,
            ignore_cancellation: false,
        })
    }
    fn stage(&mut self, name: &str) -> Result<()> {
        self.report.finish_stage("passed")?;
        self.report.stage(name)
    }
    fn evidence(&self) -> PathBuf {
        self.dir.join(".evidence")
    }
    fn command(&mut self, program: &str, args: &[String], seconds: u64) -> Result<String> {
        let id = self.report.next_command_id();
        let line = self.report.emit(&format!(
            "[{} | command {id}] START {} {} (timeout {seconds}s)",
            self.report.context,
            program,
            serde_json::to_string(args)?
        ))?;
        let started = Instant::now();
        self.report.document["commands"]
            .as_array_mut()
            .ok_or("missing command records")?
            .push(json!({
                "id": id, "context": self.report.context, "program": program, "args": args,
                "code": null, "status": "running", "line": line,
            }));
        self.report.save()?;
        let result = if !self.ignore_cancellation && self.cancelled.load(Ordering::Relaxed) {
            Ok((None, String::new(), Some("interrupted".into())))
        } else {
            self.capture_command(id, program, args, seconds)
        };
        let (code, output, mut error) = match result {
            Ok((code, output, reason)) => (code, output, reason),
            Err(error) => (None, String::new(), Some(error.to_string())),
        };
        let record = self.report.command_mut(id)?;
        record["code"] = json!(code);
        record["seconds"] = json!(started.elapsed().as_secs_f64());
        record["error"] = json!(error);
        record["status"] = json!(if error.is_some() {
            "error"
        } else {
            "completed"
        });
        self.report.finish_checks(
            id,
            if error.as_deref().is_some_and(|e| e.contains("interrupted")) {
                "interrupted"
            } else if error.is_some() {
                "failed"
            } else {
                "incomplete"
            },
        )?;
        if error.is_none()
            && let Err(failure) = contract::validate(
                &self.report.document,
                id,
                args,
                &self.evidence().join("inputs/checks.json"),
            )
        {
            error = Some(failure.to_string());
            self.report.command_mut(id)?["error"] = json!(error);
            self.report.command_mut(id)?["status"] = json!("error");
        }
        if error.is_none()
            && self.report.document["checks"]
                .as_array()
                .is_some_and(|checks| {
                    checks
                        .iter()
                        .any(|check| check["command"] == id && check["status"] != "passed")
                })
        {
            error =
                Some("failed or unfinished guest checks despite successful command exit".into());
            self.report.command_mut(id)?["error"] = json!(error);
            self.report.command_mut(id)?["status"] = json!("error");
        }
        self.report.emit(&format!(
            "[{} | command {id}] END exit={} elapsed={:.1}s{}",
            self.report.context,
            code.map_or_else(|| "none".into(), |v| v.to_string()),
            started.elapsed().as_secs_f64(),
            error
                .as_ref()
                .map_or_else(String::new, |e| format!("; {e}"))
        ))?;
        self.report.save()?;
        if let Some(error) = error {
            let error = if error.starts_with("spawn failed:") {
                format!("failed to start {program}: {error}")
            } else {
                error
            };
            return Err(format!(
                "{error}; transcript: {} (command {id}, line {line})",
                self.dir.join("transcript.log").display()
            )
            .into());
        }
        Ok(output)
    }
    fn capture_command(
        &mut self,
        id: usize,
        program: &str,
        args: &[String],
        seconds: u64,
    ) -> Result<(Option<i32>, String, Option<String>)> {
        const OUTPUT_LIMIT: u64 = 16 * 1024 * 1024;
        let capture = Capture::new(&self.dir)?;
        let mut out = File::open(capture.dir.join("stdout"))?;
        let mut err = File::open(capture.dir.join("stderr"))?;
        let child = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(capture.stdout.try_clone()?)
            .stderr(capture.stderr.try_clone()?)
            .process_group(0)
            .spawn()
            .map_err(|e| format!("spawn failed: {e}"))?;
        let mut child = ManagedChild {
            child,
            completed: false,
        };
        let started = Instant::now();
        let mut heartbeat = Heartbeat::default();
        // Regular-file readers cannot block on inherited pipes. Bound each drain so
        // continuous output never prevents cancellation or timeout checks.
        let result = (|| -> Result<(Option<i32>, Option<String>)> {
            loop {
                let activity =
                    self.drain(id, "stdout", &mut out)? | self.drain(id, "stderr", &mut err)?;
                let elapsed = started.elapsed();
                if heartbeat.due(elapsed, activity) {
                    self.report.emit(&format!(
                        "[{} | command {id}] still running; elapsed={:.0}s",
                        self.report.context,
                        elapsed.as_secs_f64()
                    ))?;
                }
                if let Some(status) = child.try_wait()? {
                    child.completed = true;
                    // The direct child is done; drain the bytes already captured without
                    // waiting for EOF from background descendants.
                    let out_len = out.metadata()?.len();
                    let err_len = err.metadata()?.len();
                    while out.stream_position()? < out_len {
                        self.drain(id, "stdout", &mut out)?;
                    }
                    while err.stream_position()? < err_len {
                        self.drain(id, "stderr", &mut err)?;
                    }
                    return Ok((
                        status.code(),
                        (!status.success()).then(|| format!("{program} exited {status}")),
                    ));
                }
                if !self.ignore_cancellation && self.cancelled.load(Ordering::Relaxed) {
                    return Ok((None, Some("interrupted".into())));
                }
                if elapsed > Duration::from_secs(seconds) {
                    return Ok((None, Some("timed out".into())));
                }
                if !activity {
                    std::thread::sleep(self.command_poll_interval);
                }
            }
        })();
        if !child.completed {
            if let Ok(pid) = i32::try_from(child.id()) {
                let _ = nix::sys::signal::killpg(
                    nix::unistd::Pid::from_raw(pid),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
            let _ = child.wait();
            child.completed = true;
            // Best effort on failure; preserve the original reporting/command error.
            for (stream, source) in [("stdout", &mut out), ("stderr", &mut err)] {
                let end = source.metadata()?.len();
                while source.stream_position()? < end {
                    if self.drain(id, stream, source).is_err() {
                        break;
                    }
                }
            }
        }
        self.report.command_mut(id)?["stdout_bytes"] = json!(out.metadata()?.len());
        self.report.command_mut(id)?["stderr_bytes"] = json!(err.metadata()?.len());
        let (code, reason) = result?;
        if let Some(reason) = reason {
            return Ok((code, String::new(), Some(reason)));
        }
        if out.metadata()?.len() > OUTPUT_LIMIT {
            return Ok((
                code,
                String::new(),
                Some(format!(
                    "{program} stdout exceeds the {OUTPUT_LIMIT}-byte capture limit"
                )),
            ));
        }
        out.seek(SeekFrom::Start(0))?;
        let mut output = String::new();
        out.take(OUTPUT_LIMIT).read_to_string(&mut output)?;
        Ok((code, output, None))
    }
    fn drain(&mut self, id: usize, stream: &str, source: &mut File) -> Result<bool> {
        let mut buffer = [0; 8192];
        let mut activity = false;
        for _ in 0..32 {
            let count = source.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            activity = true;
            self.report.output(id, stream, &buffer[..count])?;
        }
        Ok(activity)
    }
    fn incus(&mut self, args: &[String], seconds: u64) -> Result<String> {
        // Raw API queries carry project scope in their URL and reject --project.
        let mut full = if args.first().is_some_and(|arg| arg == "query") {
            Vec::new()
        } else {
            vec!["--project".into(), self.project.clone()]
        };
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
                &if image.contains(':')
                    || (image.len() == 64 && image.bytes().all(|byte| byte.is_ascii_hexdigit()))
                {
                    image.to_owned()
                } else {
                    format!("images:{image}")
                },
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
        self.ready_with_timeout(vm, 300)
    }
    fn ready_with_timeout(&mut self, vm: &str, seconds: u64) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            if self.guest(vm, &strings(&["true"]), 15).is_ok() {
                return Ok(());
            }
            if (!self.ignore_cancellation && self.cancelled.load(Ordering::Relaxed))
                || Instant::now() > deadline
            {
                return Err("VM agent did not become ready".into());
            }
            self.report.emit(&format!(
                "[{}] VM agent not ready; retrying (expected readiness probe failure)",
                self.report.context
            ))?;
            std::thread::sleep(Duration::from_secs(3));
        }
    }
    fn reboot(&mut self, vm: &str) -> Result<()> {
        self.reboot_with_timeout(vm, 300)
    }
    fn reboot_with_timeout(&mut self, vm: &str, seconds: u64) -> Result<()> {
        let before = self.guest(
            vm,
            &strings(&["cat", "/proc/sys/kernel/random/boot_id"]),
            30,
        )?;
        self.incus(&strings(&["restart", vm, "--timeout=60"]), 120)?;
        self.ready_with_timeout(vm, seconds)?;
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
    fn retain(&mut self, vm: &str) -> Result<()> {
        let instances: Vec<serde_json::Value> =
            serde_json::from_str(&self.incus(&strings(&["list", vm, "--format=json"]), 30)?)?;
        let instance = instances
            .iter()
            .find(|instance| instance["name"] == vm)
            .ok_or("VM missing")?;
        validate_vm_config(instance)?;
        self.incus(
            &strings(&["config", "set", vm, "user.kidobo-e2e-retained=true"]),
            30,
        )?;
        if instance["status"] != "Stopped" {
            self.incus(&strings(&["stop", vm, "--timeout=60"]), 90)?;
        }
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
    let baseline = read_text(&runner.evidence().join("baseline-tag"))?;
    runner.guest(
        vm,
        &strings(&["mkdir", "-p", "/opt/kidobo-e2e/baseline"]),
        30,
    )?;
    runner.push(
        vm,
        &runner.evidence().join("baseline-installer.sh"),
        "/opt/kidobo-e2e/baseline/installer.sh",
        false,
    )?;
    runner.push(
        vm,
        &runner.evidence().join("baseline-SHA256SUMS"),
        "/opt/kidobo-e2e/baseline/SHA256SUMS",
        false,
    )?;
    runner.push(
        vm,
        &runner.evidence().join("baseline-archive.tar.gz"),
        &format!(
            "/opt/kidobo-e2e/baseline/kidobo-{}-linux-x86_64.tar.gz",
            baseline.trim()
        ),
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
fn prerequisites(
    runner: &mut Runner,
    vm: &str,
    distro: &Distro,
    _tag: &str,
    published: bool,
    archive: Option<&Path>,
) -> Result<()> {
    runner.guest(
        vm,
        &strings(&["mkdir", "-p", "/opt/kidobo-e2e/release"]),
        30,
    )?;
    for script in ["provision.sh", "lifecycle.sh", "traffic.py", "checks.json"] {
        runner.push(
            vm,
            &runner.evidence().join("inputs").join(script),
            &format!("/opt/kidobo-e2e/{script}"),
            false,
        )?;
    }
    runner.push(
        vm,
        &runner.evidence().join("inputs/installer.sh"),
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
        runner.stage(&format!("{} | upgrade baseline preparation", distro.id))?;
        prepare_baseline(runner, vm)?;
    }
    Ok(())
}

fn application(
    runner: &mut Runner,
    vm: &str,
    distro: &Distro,
    tag: &str,
    published: bool,
) -> Result<()> {
    runner.stage(&format!(
        "{} | installation and application checks",
        distro.id
    ))?;
    let mode = if published { "published" } else { "candidate" };
    runner.guest(
        vm,
        &strings(&["bash", "/opt/kidobo-e2e/lifecycle.sh", "start", tag, mode]),
        600,
    )?;
    if !published {
        runner.stage(&format!(
            "{} | application reboot and timer recovery",
            distro.id
        ))?;
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
        runner.stage(&format!("{} | upgrade and preservation", distro.id))?;
        runner.guest(
            vm,
            &strings(&["bash", "/opt/kidobo-e2e/lifecycle.sh", "upgrade", tag, mode]),
            600,
        )?;
    }
    runner.stage(&format!("{} | flush and uninstall", distro.id))?;
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
    let mut failures = Vec::new();
    for vm in owned.instances {
        let result = (|| -> Result<()> {
            // A previous cleanup may already have removed this VM.
            let output = runner.incus(&strings(&["list", "--format=json"]), 30)?;
            let list: Vec<serde_json::Value> = serde_json::from_str(&output)?;
            if list.iter().any(|v| v["name"] == vm) {
                runner.delete(&vm)?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            failures.push(format!("{vm}: {error}"));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!("VM cleanup failed: {}", failures.join("; ")).into())
    }
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
    prepared::validate_settings(&config)?;
    let mut ids = std::collections::BTreeSet::new();
    if config.distros.iter().any(|d| !ids.insert(&d.id))
        || !config.distros.iter().any(|d| d.required)
    {
        return Err("matrix needs unique targets and at least one required target".into());
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
    let report = Report::open(&dir)?;
    let mut runner = Runner {
        project: config.project.clone(),
        dir,
        incus_program: PathBuf::from("incus"),
        cancelled,
        report,
        command_poll_interval: Duration::from_millis(100),
        ignore_cancellation: false,
    };
    let is_clean = matches!(&cli.action, Action::Clean { .. });
    if is_clean {
        runner.stage("cleanup requested after run")?;
    } else {
        let (tag, archive, targets) = match &cli.action {
            Action::Run {
                tag,
                archive,
                distro,
                required_only,
                ..
            } => (
                tag.as_str(),
                archive.as_ref(),
                selected_targets(&config, distro.as_deref(), *required_only)
                    .into_iter()
                    .map(|d| d.id.clone())
                    .collect::<Vec<_>>(),
            ),
            _ => ("setup", None, Vec::new()),
        };
        runner.report.document["validation_contract"] = json!(contract::VERSION);
        runner.report.document["run_id"] = json!(run_id);
        runner.report.document["tag"] = json!(tag);
        runner.report.document["archive"] = json!(archive);
        runner.report.document["targets"] = json!(targets);
        let published = matches!(
            &cli.action,
            Action::Run {
                published: true,
                ..
            }
        );
        let mut stages = vec![];
        for target in &targets {
            for &name in resume::LIFECYCLE_STAGES {
                if published
                    && matches!(
                        name,
                        "upgrade baseline preparation"
                            | "application reboot and timer recovery"
                            | "upgrade and preservation"
                    )
                {
                    continue;
                }
                stages.push(json!({"name": format!("{target} | {name}"), "status": "not-run"}));
            }
        }
        runner.report.document["stages"] = json!(stages);
        runner.report.document["status"] = json!("running");
        runner.report.save()?;
        runner.report.emit(&format!(
            "E2E run {run_id}: release={tag} archive={archive:?} targets={targets:?}; results: {}",
            runner.dir.display()
        ))?;
    }
    let started = Instant::now();
    let outcome = execute(cli, &config, &run_id, &mut runner);
    runner.report.document["run_wall_seconds"] = json!(started.elapsed().as_secs_f64());
    let restored = runner.dir.join(".resume-candidate");
    if restored.exists() {
        fs::remove_dir_all(restored)?;
    }
    if is_clean {
        runner
            .report
            .finish_stage(if outcome.is_err() { "failed" } else { "passed" })?;
        return outcome;
    }
    let interrupted = runner.cancelled.load(Ordering::Relaxed);
    runner.ignore_cancellation = true;
    runner.report.document["status"] = json!(if interrupted {
        "interrupted"
    } else if outcome.is_err() {
        "failed"
    } else {
        "passed"
    });
    runner.report.document["error"] = json!(outcome.as_ref().err().map(ToString::to_string));
    runner.report.finish_stage(if interrupted {
        "interrupted"
    } else if outcome.is_err() {
        "failed"
    } else {
        "passed"
    })?;
    let archive = archive_evidence(&mut runner);
    runner
        .report
        .finish_stage(if archive.is_err() { "failed" } else { "passed" })?;
    if let Err(error) = &archive {
        runner.report.document["evidence_error"] = json!(error.to_string());
        runner.report.document["status"] = json!("failed");
        runner.report.emit(&format!(
            "Evidence incomplete: {error}; working evidence retained at {}",
            runner.evidence().display()
        ))?;
    }
    runner.report.save()?;
    runner.report.document["run_wall_seconds"] = json!(started.elapsed().as_secs_f64());
    if interrupted || outcome.is_err() || archive.is_err() {
        runner.report.document["release_gate_passed"] = json!(false);
    }
    runner.report.save()?;
    outcome?;
    archive?;
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "Matrix execution keeps diagnostics and cleanup adjacent to lifecycle execution"
)]
fn execute(cli: Cli, config: &Config, run_id: &str, runner: &mut Runner) -> Result<()> {
    if !matches!(&cli.action, Action::Clean { .. }) {
        fs::create_dir_all(runner.evidence())?;
        runner.command("tar", &strings(&["--version"]), 10)?;
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
        Action::Setup => {
            let _operation_lock = coordination::lock(runner)?;
            setup(runner, config)
        }
        Action::Clean { .. } => {
            let _operation_lock = coordination::lock(runner)?;
            runner.ignore_cancellation = true;
            clean(runner, config)
        }
        Action::Run {
            archive,
            mut tag,
            published,
            distro,
            required_only,
            keep_failed,
            resume,
            refresh_images,
        } => {
            runner.report.document["refresh_images"] = json!(refresh_images);
            let previous = resume
                .as_deref()
                .map(|id| resume::Resume::load(runner, id))
                .transpose()?;
            let archive = if let Some(previous) = &previous {
                if tag == "latest" {
                    tag = previous.document["tag"]
                        .as_str()
                        .ok_or("missing resume tag")?
                        .into();
                }
                Some(match archive {
                    Some(archive) => archive,
                    None => previous.restore_candidate(runner)?,
                })
            } else {
                archive
            };
            runner.report.document["coverage"] = json!(if published {
                "Published smoke lane; candidate post-install reboot, upgrade, and candidate-only checks are not run"
            } else {
                "Candidate lifecycle lane including reboot, upgrade, and failure preservation"
            });
            runner
                .report
                .emit(&format!("Coverage: {}", runner.report.document["coverage"]))?;
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
            snapshot_inputs(&runner.evidence(), &cli.config)?;
            let archive = archive.map(fs::canonicalize).transpose()?;
            let artifact_hash = archive.as_deref().map(hash).transpose()?;
            let test_archive = archive
                .as_deref()
                .map(|source| freeze_archive(source, &runner.evidence()))
                .transpose()?;
            if test_archive.as_deref().map(hash).transpose()? != artifact_hash {
                return Err("candidate changed while taking its input snapshot".into());
            }
            if let Some(previous) = &previous {
                previous.verify_inputs(
                    runner,
                    &tag,
                    archive.as_deref().ok_or("resume needs candidate")?,
                )?;
                previous.restore_baseline(runner)?;
            } else if !published {
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
                fs::write(runner.evidence().join("baseline-tag"), baseline)?;
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
                            &runner.evidence().join(name).to_string_lossy(),
                            &url,
                        ]),
                        200,
                    )?;
                }
            }

            if !published {
                let baseline = read_text(&runner.evidence().join("baseline-tag"))?;
                let baseline_archive = runner.evidence().join("baseline-archive.tar.gz");
                if !baseline_archive.exists() {
                    runner.command("curl",&strings(&["-fsSL","--retry","2","--max-time","120","-o",&baseline_archive.to_string_lossy(),
                        &format!("https://github.com/blwarren/kidobo/releases/download/{baseline}/kidobo-{baseline}-linux-x86_64.tar.gz")]),400)?;
                }
                verify_baseline(runner, &baseline)?;
            }
            let _operation_lock = coordination::lock(runner)?;
            let parallelism = coordination::preflight(runner, config)?;
            runner.report.document["effective_parallelism"] = json!(parallelism);
            if config.prepared_images.enabled {
                prepared::prune(runner, config)?;
            }
            let targets = selected_targets(config, distro.as_deref(), required_only);
            if targets.is_empty() {
                return Err("no matching distros".into());
            }
            runner.report.document["tag"] = json!(tag);
            runner.report.document["archive_sha256"] = json!(artifact_hash);
            runner.report.document["published"] = json!(published);
            runner.report.save()?;
            matrix::execute(
                runner,
                config,
                run_id,
                &targets,
                &tag,
                published,
                test_archive.as_deref(),
                keep_failed,
                previous.as_ref(),
            )?;
            if config.prepared_images.enabled {
                prepared::prune(runner, config)?;
            }
            if archive.as_deref().map(hash).transpose()? != artifact_hash {
                return Err("candidate archive changed during testing".into());
            }
            Ok(())
        }
    }
}
fn verify_baseline(runner: &mut Runner, tag: &str) -> Result<()> {
    let filename = format!("kidobo-{tag}-linux-x86_64.tar.gz");
    let manifest = read_text(&runner.evidence().join("baseline-SHA256SUMS"))?;
    let entries = manifest
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            Some((parts.next()?, parts.next()?))
        })
        .filter(|(_, name)| *name == filename)
        .collect::<Vec<_>>();
    if entries.len() != 1
        || entries[0].0 != hash(&runner.evidence().join("baseline-archive.tar.gz"))?
    {
        return Err("captured baseline archive checksum mismatch".into());
    }
    runner.report.document["baseline_archive_sha256"] = json!(entries[0].0);
    Ok(())
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
    let mut harness = Sha256::new();
    for module in [
        "main.rs",
        "matrix.rs",
        "report.rs",
        "resume.rs",
        "prepared.rs",
        "coordination.rs",
        "contract.rs",
    ] {
        harness.update(hash(&Path::new("tools/distro-e2e/src").join(module))?.as_bytes());
    }
    for input in ["Cargo.lock", "rust-toolchain.toml"] {
        harness.update(hash(Path::new(input))?.as_bytes());
    }
    let mut identity = String::with_capacity(64);
    for byte in harness.finalize() {
        write!(&mut identity, "{byte:02x}")?;
    }
    hashes.insert("harness".into(), json!(identity));
    for (source, name) in [
        (Path::new("scripts/install.sh"), "installer.sh"),
        (Path::new("scripts/e2e/provision.sh"), "provision.sh"),
        (Path::new("scripts/e2e/lifecycle.sh"), "lifecycle.sh"),
        (Path::new("scripts/e2e/traffic.py"), "traffic.py"),
        (Path::new("scripts/e2e/checks.json"), "checks.json"),
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
mod guest_http_tests;
#[cfg(test)]
mod guest_preservation_tests;
#[cfg(test)]
mod guest_reporting_tests;
#[cfg(test)]
mod guest_upgrade_tests;
#[cfg(test)]
mod preparation_tests;
#[cfg(test)]
mod tests;
