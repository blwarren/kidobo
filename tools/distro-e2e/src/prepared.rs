//! Fresh guest preparation through ordinary distro tools and bounded readiness checks.
use super::{Config, Distro, OWNER, Result, Runner, strings};
use serde_json::{Value, json};
use std::fs;
use std::time::Instant;

pub(super) fn validate_settings(config: &Config) -> Result<()> {
    if !(1..=2).contains(&config.max_parallel_vms)
        || config
            .distros
            .iter()
            .any(|target| !matches!(target.selinux.as_str(), "enforcing" | "image-default"))
    {
        return Err("invalid E2E concurrency or SELinux settings".into());
    }
    Ok(())
}

fn readiness_seconds(runner: &Runner, deadline: Instant) -> Result<u64> {
    if runner.cancelled.load(std::sync::atomic::Ordering::Relaxed) {
        return Err("preparation readiness interrupted".into());
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err("preparation boot/enforcement readiness deadline expired".into());
    }
    Ok(remaining.as_secs().clamp(1, 15))
}

fn readiness_probe(
    runner: &mut Runner,
    vm: &str,
    mode: &str,
    deadline: Instant,
) -> Result<Option<String>> {
    let seconds = readiness_seconds(runner, deadline)?;
    match runner.guest(
        vm,
        &strings(&["bash", "/opt/kidobo-e2e/provision.sh", mode]),
        seconds,
    ) {
        Ok(value) => {
            readiness_seconds(runner, deadline)?;
            Ok(Some(value))
        }
        Err(error) => {
            // A zero-exit command rejected by the host assertion contract is a
            // harness failure, not an unavailable agent or pending guest probe.
            if runner.report.failed()
                || runner.report.document["commands"]
                    .as_array()
                    .and_then(|commands| commands.last())
                    .is_some_and(|command| command["code"] == 0)
            {
                return Err(error);
            }
            readiness_seconds(runner, deadline)?;
            Ok(None)
        }
    }
}

fn reboot_prepared(
    runner: &mut Runner,
    vm: &str,
    enforcing: bool,
    timeout: std::time::Duration,
    poll: std::time::Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let before = runner.guest(
        vm,
        &strings(&["cat", "/proc/sys/kernel/random/boot_id"]),
        readiness_seconds(runner, deadline)?,
    )?;
    readiness_seconds(runner, deadline)?;
    runner.incus(
        &strings(&["restart", vm, "--timeout=60"]),
        deadline
            .saturating_duration_since(Instant::now())
            .as_secs()
            .clamp(1, 120),
    )?;
    let mut observed = None;
    let boot = loop {
        match readiness_probe(runner, vm, "--boot-status", deadline)? {
            Some(boot) if !boot.trim().is_empty() && boot != before => {
                readiness_seconds(runner, deadline)?;
                if observed.as_ref() == Some(&boot) {
                    break boot;
                }
                runner
                    .report
                    .emit(&format!("Preparation observed boot {}", boot.trim()))?;
                observed = Some(boot);
            }
            _ => observed = None,
        }
        std::thread::sleep(poll.min(deadline.saturating_duration_since(Instant::now())));
    };
    if !enforcing {
        return Ok(());
    }
    if readiness_probe(runner, vm, "--start-enforcement", deadline)?.is_none() {
        // The detached job may have restarted the transport before its launcher
        // replied. Only its durable status plus a fresh enforcing probe can admit it.
        runner
            .report
            .emit("Enforcement launch transport interrupted; checking durable job result")?;
    }
    loop {
        if let Some(status) = readiness_probe(runner, vm, "--enforcement-status", deadline)? {
            match status.trim() {
                "pending" => {}
                "0 Enforcing" => {
                    if let Some(current) = readiness_probe(runner, vm, "--boot-status", deadline)? {
                        if current != boot {
                            return Err("guest rebooted during SELinux enforcement".into());
                        }
                        readiness_seconds(runner, deadline)?;
                        return Ok(());
                    }
                }
                other => {
                    return Err(format!(
                        "detached SELinux enforcement failed: {other}; see prepared/enforcement.log"
                    )
                    .into());
                }
            }
        }
        std::thread::sleep(poll.min(deadline.saturating_duration_since(Instant::now())));
    }
}

pub(super) fn prepare(
    runner: &mut Runner,
    config: &Config,
    target: &Distro,
    vm: &str,
) -> Result<Value> {
    if let Err(error) = validate_profile(runner, config) {
        runner
            .cancelled
            .store(true, std::sync::atomic::Ordering::Relaxed);
        return Err(error);
    }
    prepare_guest(runner, config, target, vm)
}

fn validate_profile(runner: &mut Runner, config: &Config) -> Result<()> {
    let profile: Value = serde_json::from_str(&runner.incus(
        &strings(&[
            "query",
            &format!(
                "/1.0/profiles/{}?project={}",
                config.profile, config.project
            ),
        ]),
        30,
    )?)?;
    let profile = profile.get("metadata").unwrap_or(&profile).clone();
    if profile["config"]["user.kidobo-e2e"] != OWNER {
        return Err("preparation profile is not suite-owned".into());
    }
    if profile["config"]["limits.cpu"]
        .as_str()
        .and_then(|value| value.parse::<u32>().ok())
        != Some(config.cpus)
        || profile["config"]["limits.memory"] != config.memory
        || profile["devices"]["root"]["pool"] != config.pool
        || profile["devices"]["root"]["size"] != config.disk
        || profile["devices"]["eth0"]["network"] != config.network
    {
        return Err(
            "suite profile resources differ from configuration; run e2e-setup before testing"
                .into(),
        );
    }
    Ok(())
}

fn prepare_guest(runner: &mut Runner, config: &Config, target: &Distro, vm: &str) -> Result<Value> {
    runner.stage(&format!("{} | VM creation", target.id))?;
    // Resolve the upstream alias once for this fresh guest.
    let source = runner.incus(
        &strings(&["image", "info", &format!("images:{}", target.image), "--vm"]),
        60,
    )?;
    let source_fp = source
        .lines()
        .find_map(|line| line.strip_prefix("Fingerprint: "))
        .map(str::trim)
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or("upstream VM image fingerprint missing")?;
    runner.create_vm(&format!("images:{source_fp}"), vm, &config.profile)?;
    runner.ready(vm)?;
    runner.guest(
        vm,
        &strings(&[
            "sh",
            "-c",
            "printf '%s\\n' kidobo-e2e-v1 > /etc/kidobo-e2e-owned; mkdir -p /opt/kidobo-e2e",
        ]),
        30,
    )?;
    for script in ["provision.sh", "checks.json"] {
        runner.push(
            vm,
            &runner.evidence().join("inputs").join(script),
            &format!("/opt/kidobo-e2e/{script}"),
            false,
        )?;
    }
    runner.stage(&format!("{} | provisioning", target.id))?;
    let mut args = strings(&[
        "bash",
        "/opt/kidobo-e2e/provision.sh",
        "--prepare",
        &target.family,
        &target.selinux,
    ]);
    args.extend(target.packages.clone());
    runner.guest(vm, &args, 4800)?;
    runner.stage(&format!("{} | pre-reboot evidence", target.id))?;
    let mut warnings = Vec::new();
    if let Some(warning) =
        crate::diagnostics::pre_reboot(runner, vm, &runner.evidence().join(&target.id))?
    {
        runner.report.emit(&format!("WARNING: {warning}"))?;
        warnings.push(warning);
    }
    let relabel = runner.guest(
        vm,
        &strings(&["cat", "/opt/kidobo-e2e/prepared/relabel-scheduled"]),
        30,
    )?;
    runner.stage(&format!(
        "{} | OS reboot and kernel verification",
        target.id
    ))?;
    reboot_prepared(
        runner,
        vm,
        target.selinux == "enforcing",
        std::time::Duration::from_secs(if relabel.trim() == "1" { 900 } else { 300 }),
        std::time::Duration::from_secs(2),
    )?;
    runner.guest(
        vm,
        &strings(&["bash", "/opt/kidobo-e2e/provision.sh", "--check-kernel"]),
        60,
    )?;
    runner.stage(&format!("{} | environment validation", target.id))?;
    runner.guest(
        vm,
        &strings(&["bash", "/opt/kidobo-e2e/provision.sh", "--validate"]),
        60,
    )?;
    let preparation: Value = serde_json::from_str(&runner.guest(
        vm,
        &strings(&["cat", "/opt/kidobo-e2e/prepared/environment.json"]),
        30,
    )?)?;
    let metadata = json!({"image_fingerprint":source_fp,"preparation":preparation,"diagnostic_warnings":warnings});
    let directory = runner.evidence().join(&target.id);
    fs::create_dir_all(&directory)?;
    fs::write(
        directory.join("preparation.json"),
        serde_json::to_vec_pretty(&metadata)?,
    )?;
    Ok(metadata)
}

#[cfg(test)]
#[path = "prepared/integration_tests.rs"]
mod integration_tests;
