//! Host admission and a process-owned lock for one local Incus project.
use super::{Config, Result, Runner, read_text, strings};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub(super) fn lock(runner: &mut Runner) -> Result<File> {
    let info: Value = serde_json::from_str(&runner.incus(&strings(&["query", "/1.0"]), 30)?)?;
    let info = info.get("metadata").unwrap_or(&info);
    let server = info["environment"]["server_name"]
        .as_str()
        .ok_or("Incus server identity missing")?;
    let mut key = String::with_capacity(64);
    for byte in Sha256::digest(format!("{server}\n{}", runner.project)) {
        write!(&mut key, "{byte:02x}")?;
    }
    acquire(Path::new("/tmp"), &key)
}

fn acquire(directory: &Path, key: &str) -> Result<File> {
    let path = directory.join(format!("kidobo-e2e-{key}.lock"));
    let options = || {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits());
        options
    };
    let lock = match options()
        .write(true)
        .create_new(true)
        .mode(0o666)
        .open(&path)
    {
        Ok(lock) => lock,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => options().open(&path)?,
        Err(error) => return Err(error.into()),
    };
    if !lock.metadata()?.is_file() {
        return Err("E2E coordinator lock is not a regular file".into());
    }
    lock.try_lock().map_err(|error| {
        format!("another E2E operation owns this Incus server/project: {error}")
    })?;
    Ok(lock)
}

pub(super) fn preflight(runner: &mut Runner, config: &Config) -> Result<usize> {
    let project: Value = serde_json::from_str(&runner.incus(
        &strings(&["query", &format!("/1.0/projects/{}", config.project)]),
        30,
    )?)?;
    let project = project.get("metadata").unwrap_or(&project);
    if project["config"]["user.kidobo-e2e"] != super::OWNER
        || project["config"]["features.images"] == "false"
    {
        return Err("E2E requires a suite-owned project with its own image store".into());
    }
    let instances: Vec<Value> =
        serde_json::from_str(&runner.incus(&strings(&["list", "--format=json"]), 30)?)?;
    recover_abandoned(runner, &instances)?;
    let available = memory_available(&read_text(Path::new("/proc/meminfo"))?)?;
    let effective = memory_slots(
        available,
        memory_bytes(&config.memory)?,
        config.max_parallel_vms,
    )?;
    runner.report.document["requested_parallelism"] = json!(config.max_parallel_vms);
    runner.report.document["effective_parallelism"] = json!(effective);
    runner.report.emit(&format!(
        "VM concurrency: requested {}, admitted {effective}; 1 GiB host memory headroom",
        config.max_parallel_vms
    ))?;
    runner.report.save()?;
    Ok(effective)
}

// Called only while holding the server/project coordinator lock. The PID check
// also protects legacy runs which predate that lock and conservatively rejects reuse.
fn recover_abandoned(runner: &mut Runner, instances: &[Value]) -> Result<()> {
    let mut failures = Vec::new();
    for instance in instances {
        let name = instance["name"].as_str().unwrap_or("<unnamed>");
        let result = (|| -> Result<()> {
            super::validate_vm_config(instance)?;
            let mut parts = name.splitn(4, '-');
            if parts.next() != Some("run")
                || parts
                    .next()
                    .and_then(|value| value.parse::<u64>().ok())
                    .is_none()
            {
                return Err("unrecognized E2E run name; left untouched".into());
            }
            let pid = parts
                .next()
                .and_then(|value| value.parse::<u32>().ok())
                .filter(|pid| *pid > 0)
                .ok_or("invalid E2E owner PID; left untouched")?;
            if parts.next().is_none_or(str::is_empty) || !super::safe_name(name) {
                return Err("invalid E2E guest name; left untouched".into());
            }
            if Path::new("/proc").join(pid.to_string()).try_exists()? {
                return Err(format!("owner PID {pid} still exists; left untouched").into());
            }
            if instance["config"]["user.kidobo-e2e-retained"] == "true" {
                if instance["status"] != "Stopped" {
                    runner.retain(name)?;
                }
                runner
                    .report
                    .emit(&format!("Preserved explicitly retained E2E guest {name}"))?;
            } else {
                runner.delete(name)?;
                runner
                    .report
                    .emit(&format!("Removed abandoned E2E guest {name}"))?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            failures.push(format!("{name}: {error}"));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!("E2E guest recovery incomplete: {}", failures.join("; ")).into())
    }
}

fn memory_available(text: &str) -> Result<u64> {
    text.lines()
        .find_map(|line| line.strip_prefix("MemAvailable:"))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse::<u64>().ok())
        .and_then(|value| value.checked_mul(1024))
        .ok_or_else(|| "MemAvailable unavailable".into())
}

pub(super) fn memory_bytes(value: &str) -> Result<u64> {
    let (digits, suffix) = value.split_at(
        value
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(value.len()),
    );
    let multiplier = match suffix {
        "GiB" => 1024_u64.pow(3),
        "MiB" => 1024_u64.pow(2),
        "GB" => 1000_u64.pow(3),
        "MB" => 1000_u64.pow(2),
        "" => 1,
        _ => return Err("unsupported VM memory unit".into()),
    };
    digits
        .parse::<u64>()?
        .checked_mul(multiplier)
        .filter(|bytes| *bytes > 0)
        .ok_or_else(|| "invalid VM memory size".into())
}

fn memory_slots(available: u64, per_vm: u64, requested: usize) -> Result<usize> {
    let slots = available.saturating_sub(1024_u64.pow(3)) / per_vm;
    let effective = requested.min(usize::try_from(slots)?);
    if effective == 0 {
        return Err("insufficient memory for one VM plus 1 GiB headroom".into());
    }
    Ok(effective)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guest(name: &str, retained: bool) -> Value {
        json!({"name":name,"type":"virtual-machine","status":"Running",
            "config":{"user.kidobo-e2e":super::super::OWNER,
                "user.kidobo-e2e-retained":if retained { "true" } else { "false" }}})
    }

    fn recovery_runner(temp: &crate::tests::TestDir, instances: &[Value]) -> Runner {
        let program = temp.path().join("incus");
        std::fs::write(
            temp.path().join("instances.json"),
            serde_json::to_vec(instances).expect("JSON"),
        )
        .expect("instances");
        crate::tests::executable(
            &program,
            r#"#!/bin/bash
set -eu
cd "$(dirname "$0")"
[[ "$1" == --project && "$2" == test-project ]]
shift 2
if [[ "$1" == list ]]; then
    cat instances.json
else
    printf '%s\n' "$*" >> calls
    if [[ "$1" == delete && "$2" == *-fail ]]; then exit 1; fi
fi
"#,
        );
        crate::tests::runner_with_incus(temp.path(), &program)
    }

    #[test]
    fn recovery_cleans_orphans_without_manifests_and_preserves_retained_guests() {
        let temp = crate::tests::TestDir::new();
        let mut stopped = guest("run-1-4294967295-stopped", false);
        stopped["status"] = json!("Stopped");
        let mut retained_stopped = guest("run-1-4294967295-retained-stopped", true);
        retained_stopped["status"] = json!("Stopped");
        let instances = vec![
            guest("run-1-4294967295-running", false),
            stopped,
            guest("run-1-4294967295-retained", true),
            retained_stopped,
        ];
        let mut runner = recovery_runner(&temp, &instances);
        recover_abandoned(&mut runner, &instances).expect("recovered all abandoned guests");
        assert_eq!(
            read_text(&temp.path().join("calls")).expect("calls"),
            "delete run-1-4294967295-running --force\ndelete run-1-4294967295-stopped --force\nconfig set run-1-4294967295-retained user.kidobo-e2e-retained=true\nstop run-1-4294967295-retained --timeout=60\n"
        );
    }

    #[test]
    fn recovery_skips_active_foreign_and_malformed_guests_but_finishes_other_cleanup() {
        let temp = crate::tests::TestDir::new();
        let mut foreign = guest("run-1-4294967295-foreign", false);
        foreign["config"]["user.kidobo-e2e"] = json!("other");
        let instances = vec![
            foreign,
            guest("not-a-run", false),
            guest(&format!("run-1-{}-active", std::process::id()), false),
            guest("run-1-4294967295-fail", false),
            guest("run-1-4294967295-clean", false),
        ];
        let mut runner = recovery_runner(&temp, &instances);
        let error = recover_abandoned(&mut runner, &instances)
            .expect_err("blocked recovery")
            .to_string();
        assert!(error.contains("unowned"));
        assert!(error.contains("unrecognized"));
        assert!(error.contains("still exists"));
        assert!(error.contains("run-1-4294967295-fail"));
        assert_eq!(
            read_text(&temp.path().join("calls")).expect("calls"),
            "delete run-1-4294967295-fail --force\ndelete run-1-4294967295-clean --force\n"
        );
    }

    #[test]
    fn recovery_rechecks_ownership_before_deletion() {
        let temp = crate::tests::TestDir::new();
        let mut foreign = guest("run-1-4294967295-changed", false);
        foreign["config"]["user.kidobo-e2e"] = json!("other");
        let mut runner = recovery_runner(&temp, &[foreign]);
        let error = recover_abandoned(&mut runner, &[guest("run-1-4294967295-changed", false)])
            .expect_err("owner changed")
            .to_string();
        assert!(error.contains("unowned"));
        assert!(!temp.path().join("calls").exists());
    }

    #[test]
    fn explicit_cleanup_attempts_remaining_guests_after_a_delete_failure() {
        let temp = crate::tests::TestDir::new();
        let run = temp
            .path()
            .file_name()
            .expect("run name")
            .to_str()
            .expect("UTF-8");
        let failed = format!("{run}-fail");
        let cleaned = format!("{run}-clean");
        let mut runner = recovery_runner(&temp, &[guest(&failed, false), guest(&cleaned, false)]);
        let owned = super::super::Owned {
            owner: super::super::OWNER.into(),
            project: "test-project".into(),
            instances: vec![failed.clone(), cleaned.clone()],
        };
        std::fs::write(
            temp.path().join("ownership.json"),
            serde_json::to_vec(&owned).expect("JSON"),
        )
        .expect("manifest");
        let mut config: Config =
            toml_edit::de::from_str(include_str!("../../../config/e2e.toml")).expect("config");
        config.project = "test-project".into();
        let error = super::super::clean(&mut runner, &config)
            .expect_err("cleanup failure")
            .to_string();
        assert!(error.contains(&failed));
        assert_eq!(
            read_text(&temp.path().join("calls")).expect("calls"),
            format!("delete {failed} --force\ndelete {cleaned} --force\n")
        );
    }
    #[test]
    fn coordinator_lock_is_exclusive_releases_on_drop_and_rejects_symlinks() {
        let temp = crate::tests::TestDir::new();
        let first = acquire(temp.path(), "same").expect("first lock");
        assert!(
            acquire(temp.path(), "same")
                .expect_err("competing run")
                .to_string()
                .contains("owns")
        );
        drop(first);
        acquire(temp.path(), "same").expect("released lock");
        std::os::unix::fs::symlink("/dev/null", temp.path().join("kidobo-e2e-link.lock"))
            .expect("symlink");
        assert!(
            acquire(temp.path(), "link")
                .expect_err("nofollow")
                .to_string()
                .contains("Too many levels")
        );
    }

    #[test]
    fn coordinator_rejects_a_fifo_without_waiting_for_a_writer() {
        let temp = crate::tests::TestDir::new();
        let fifo = temp.path().join("kidobo-e2e-fifo.lock");
        nix::unistd::mkfifo(
            &fifo,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .expect("fifo");
        let directory = temp.path().to_owned();
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _ = sender.send(acquire(&directory, "fifo").map_err(|error| error.to_string()));
        });
        let result = receiver.recv_timeout(std::time::Duration::from_secs(5));
        if result.is_err() {
            let _release = OpenOptions::new()
                .write(true)
                .custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits())
                .open(&fifo)
                .expect("release blocked reader");
            worker.join().expect("reader released");
            panic!("coordinator blocked while opening a non-regular lock file");
        }
        worker.join().expect("lock admission finished");
        assert!(
            result
                .expect("immediate reply")
                .expect_err("non-regular file")
                .contains("regular file")
        );
    }
    #[test]
    fn memory_preflight_preserves_headroom_and_falls_back_to_one() {
        let gib = 1024_u64.pow(3);
        assert_eq!(memory_slots(9 * gib, 4 * gib, 2).expect("two"), 2);
        assert_eq!(memory_slots(8 * gib, 4 * gib, 2).expect("one"), 1);
        assert!(
            memory_slots(4 * gib, 4 * gib, 2)
                .expect_err("headroom")
                .to_string()
                .contains("insufficient")
        );
        assert_eq!(
            memory_available("MemAvailable: 123 kB").expect("available"),
            125_952
        );
    }
}
