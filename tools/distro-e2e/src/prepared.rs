//! Fresh guest preparation through ordinary distro tools and bounded readiness checks.
use super::{Config, Distro, OWNER, Result, Runner, read_text, strings};
use serde_json::{Value, json};
use std::fs;
use std::time::Instant;

pub(super) fn cloud_init_user_data(bootstrap: &str) -> Result<String> {
    Ok(format!(
        "#cloud-config\n{}\n",
        serde_json::to_string(&json!({"runcmd": [["bash", "-c", bootstrap]]}))?
    ))
}

fn cloud_init_warnings(output: &str, fedora: bool, vm: &str) -> Result<(Value, Vec<String>)> {
    let (document, exit) = output
        .rsplit_once("\nKIDOBO_CLOUD_INIT_EXIT=")
        .ok_or("cloud-init completion exit status missing")?;
    let status: Value = serde_json::from_str(document.trim())?;
    if status["status"] != "done"
        || !status["errors"]
            .as_array()
            .is_some_and(std::vec::Vec::is_empty)
    {
        return Err("cloud-init did not complete successfully".into());
    }
    let expected = format!("Failed to set the hostname to {vm} ({vm})");
    validate_cloud_errors(&status, fedora, &expected)?;
    let warnings = status["recoverable_errors"]
        .as_object()
        .ok_or("cloud-init recoverable error inventory missing")?
        .values()
        .flat_map(|messages| messages.as_array().into_iter().flatten())
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if !matches!(
        (exit.trim(), warnings.is_empty()),
        ("0,0", true) | ("2,2", false)
    ) {
        return Err("cloud-init exit status does not match accepted completion state".into());
    }
    Ok((status, warnings))
}

fn validate_cloud_errors(value: &Value, fedora: bool, expected: &str) -> Result<()> {
    let Some(object) = value.as_object() else {
        return Ok(());
    };
    for (key, value) in object {
        match key.as_str() {
            "errors" => {
                if !value.as_array().is_some_and(std::vec::Vec::is_empty) {
                    return Err("cloud-init reported critical errors".into());
                }
            }
            "recoverable_errors" => {
                let errors = value
                    .as_object()
                    .ok_or("unrecognized cloud-init recoverable errors")?;
                for messages in errors.values() {
                    let messages = messages
                        .as_array()
                        .ok_or("unrecognized cloud-init warning inventory")?;
                    for message in messages {
                        if !fedora || message.as_str() != Some(expected) {
                            return Err(format!("unexpected cloud-init warning: {message}").into());
                        }
                    }
                }
            }
            _ => validate_cloud_errors(value, fedora, expected)?,
        }
    }
    Ok(())
}

fn wait_for_cloud_init(runner: &mut Runner, target: &Distro, vm: &str) -> Result<Vec<String>> {
    runner.stage(&format!("{} | vendor image bootstrap", target.id))?;
    let output = runner.guest(
        vm,
        &strings(&[
            "bash",
            "-c",
            "set +e; cloud-init status --wait >/dev/null; waited=$?; cloud-init status --format=json; reported=$?; printf '\\nKIDOBO_CLOUD_INIT_EXIT=%s,%s\\n' \"$waited\" \"$reported\"",
        ]),
        300,
    )?;
    let directory = runner.evidence().join(&target.id);
    fs::create_dir_all(&directory)?;
    fs::write(directory.join("cloud-init-status.txt"), &output)?;
    let (status, warnings) = cloud_init_warnings(&output, target.id.starts_with("fedora-"), vm)?;
    fs::write(
        directory.join("cloud-init.json"),
        serde_json::to_vec_pretty(&status)?,
    )?;
    for warning in &warnings {
        runner
            .report
            .emit(&format!("WARNING: cloud-init: {warning}"))?;
    }
    Ok(warnings)
}

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
                        "detached SELinux enforcement failed: {other}; see kidobo-e2e-enforce.service journal"
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

fn create_fresh_vm(
    runner: &mut Runner,
    config: &Config,
    target: &Distro,
    vm: &str,
) -> Result<(String, Vec<String>)> {
    runner.stage(&format!("{} | VM creation", target.id))?;
    let (source_fp, image) = crate::vendor_images::resolve(runner, target)?;
    let user_data = if target.vendor_image.is_some() {
        let bootstrap = read_text(&runner.evidence().join("inputs/bootstrap.sh"))?;
        let user_data = cloud_init_user_data(&bootstrap)?;
        let directory = runner.evidence().join(&target.id);
        fs::create_dir_all(&directory)?;
        fs::write(directory.join("cloud-init-user-data.txt"), &user_data)?;
        Some(user_data)
    } else {
        None
    };
    runner.create_vm(&image, vm, &config.profile, user_data.as_deref())?;
    runner.ready(vm)?;
    let warnings = if target.vendor_image.is_some() {
        wait_for_cloud_init(runner, target, vm)?
    } else {
        Vec::new()
    };
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
    if target.vendor_image.is_some() {
        runner.guest(
            vm,
            &strings(&["bash", "/opt/kidobo-e2e/provision.sh", "--check-bootstrap"]),
            30,
        )?;
    }
    Ok((source_fp, warnings))
}

fn prepare_guest(runner: &mut Runner, config: &Config, target: &Distro, vm: &str) -> Result<Value> {
    let (source_fp, mut warnings) = create_fresh_vm(runner, config, target, vm)?;
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
        "{} | OS reboot and capability verification",
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
    let source = if target.vendor_image.is_some() {
        serde_json::from_str::<Value>(&read_text(
            &runner
                .evidence()
                .join(&target.id)
                .join("vendor-image/source.json"),
        )?)?
    } else {
        Value::Null
    };
    let metadata = json!({"image_fingerprint":source_fp,"source":source,"preparation":preparation,"diagnostic_warnings":warnings});
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
