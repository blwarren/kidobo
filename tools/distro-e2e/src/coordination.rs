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
    if instances.iter().any(|vm| vm["status"] == "Running") {
        return Err("E2E project already has running guests; stop or clean retained guests before starting a matrix".into());
    }
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
