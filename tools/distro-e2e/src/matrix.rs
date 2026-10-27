//! Two-pass matrix scheduling and per-target evidence finalization.
use super::{
    Config, Distro, OWNER, Owned, Result, Runner, application, clean, prerequisites, resume,
    strings, validate_vm_config,
};
use serde_json::Value;
use serde_json::json;
use std::fs;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::Instant;

struct Trial<'a> {
    target: &'a Distro,
    vm: String,
    transcript_line: usize,
    started: Instant,
    phase: &'static str,
    error: Option<String>,
}

#[expect(
    clippy::too_many_arguments,
    reason = "Explicit matrix inputs keep publication mode and artifact identity visible"
)]
pub(super) fn execute(
    runner: &mut Runner,
    config: &Config,
    run_id: &str,
    targets: &[&Distro],
    tag: &str,
    published: bool,
    archive: Option<&Path>,
    keep_failed: bool,
    previous: Option<&resume::Resume>,
) -> Result<()> {
    let outcome = execute_inner(
        runner,
        config,
        run_id,
        targets,
        tag,
        published,
        archive,
        keep_failed,
        previous,
    );
    if outcome.is_err() && !keep_failed && runner.dir.join("ownership.json").exists() {
        // A reporting or resume-validation error can occur while earlier guests are parked.
        // Sweep the recorded ownership list even if normal per-target finalization was bypassed.
        let interrupted = runner.cancelled.swap(false, Ordering::Relaxed);
        if let Err(error) = clean(runner, config) {
            runner.report.document["cleanup_error"] = json!(error.to_string());
            runner.report.save()?;
        }
        if interrupted {
            runner.cancelled.store(true, Ordering::Relaxed);
        }
    }
    outcome
}

#[expect(
    clippy::too_many_arguments,
    reason = "Explicit matrix inputs keep publication mode and artifact identity visible"
)]
#[expect(
    clippy::too_many_lines,
    reason = "Both scheduling passes keep target outcomes adjacent to cleanup decisions"
)]
fn execute_inner(
    runner: &mut Runner,
    config: &Config,
    run_id: &str,
    targets: &[&Distro],
    tag: &str,
    published: bool,
    archive: Option<&Path>,
    keep_failed: bool,
    previous: Option<&resume::Resume>,
) -> Result<()> {
    runner.report.document["required_targets"] = json!(
        targets
            .iter()
            .filter(|t| t.required)
            .map(|t| &t.id)
            .collect::<Vec<_>>()
    );
    runner.report.document["advisory_targets"] = json!(
        targets
            .iter()
            .filter(|t| !t.required)
            .map(|t| &t.id)
            .collect::<Vec<_>>()
    );
    let mut owned = Owned {
        owner: OWNER.into(),
        project: config.project.clone(),
        instances: vec![],
    };
    fs::write(
        runner.dir.join("ownership.json"),
        serde_json::to_vec_pretty(&owned)?,
    )?;
    let mut results = Vec::new();
    let mut prepared = Vec::new();
    let mut required_failed = false;
    for &target in targets {
        if runner.cancelled.load(Ordering::Relaxed) {
            break;
        }
        if let Some(previous) = previous
            && previous.reusable(runner, config, target)?
        {
            let mut result = previous.result(&target.id, target.required)?;
            let line = runner.report.emit(&format!(
                "[{}] REUSED completed lifecycle from {} (evidence SHA-256 verified)",
                target.id, previous.id
            ))?;
            if result["source_transcript_line"].is_null() {
                result["source_transcript_line"] = result["transcript_line"].clone();
            }
            result["transcript_line"] = json!(line);
            if let Some(stages) = runner.report.document["stages"].as_array_mut() {
                for stage in stages.iter_mut().filter(|s| {
                    s["name"]
                        .as_str()
                        .is_some_and(|n| n.starts_with(&format!("{} | ", target.id)))
                }) {
                    stage["status"] = json!("reused");
                    stage["source_run"] = json!(previous.id);
                }
            }
            results.push(result);
            runner.report.document["results"] = json!(results);
            runner.report.save()?;
            continue;
        }
        let vm = format!("{run_id}-{}", target.id);
        fs::create_dir_all(runner.evidence().join(&target.id))?;
        owned.instances.push(vm.clone());
        fs::write(
            runner.dir.join("ownership.json"),
            serde_json::to_vec_pretty(&owned)?,
        )?;
        runner.stage(&format!("{} | VM creation", target.id))?;
        runner.report.document["active_target"] = json!(target.id);
        let mut trial = Trial {
            target,
            vm,
            transcript_line: runner.report.line,
            started: Instant::now(),
            phase: "provisioning",
            error: None,
        };
        let outcome = runner
            .create_vm(&target.image, &trial.vm, &config.profile)
            .and_then(|()| prerequisites(runner, &trial.vm, target, tag, published, archive))
            .and_then(|()| {
                runner.verify(&trial.vm)?;
                runner.incus(&strings(&["stop", &trial.vm, "--timeout=60"]), 90)?;
                Ok(())
            });
        runner
            .report
            .finish_stage(if outcome.is_err() { "failed" } else { "passed" })?;
        if let Err(error) = outcome {
            required_failed |= target.required;
            trial.error = Some(error.to_string());
            finish(runner, &trial, keep_failed, &mut results)?;
        } else {
            prepared.push(trial);
        }
    }
    runner
        .report
        .emit("[e2e] Prerequisite pass complete; starting application pass for prepared targets")?;
    for mut trial in prepared {
        if required_failed || runner.cancelled.load(Ordering::Relaxed) {
            trial.error = Some(
                "application checks not run: required prerequisites failed or run interrupted"
                    .into(),
            );
        } else {
            runner.report.document["active_target"] = json!(trial.target.id);
            let outcome = (|| -> Result<()> {
                runner.verify(&trial.vm)?;
                runner.incus(&strings(&["start", &trial.vm]), 120)?;
                runner.ready(&trial.vm)?;
                runner.stage(&format!(
                    "{} | OS reboot and kernel verification",
                    trial.target.id
                ))?;
                runner.guest(
                    &trial.vm,
                    &strings(&["bash", "/opt/kidobo-e2e/provision.sh", "--check-kernel"]),
                    60,
                )?;
                trial.phase = "application";
                application(runner, &trial.vm, trial.target, tag, published)
            })();
            runner
                .report
                .finish_stage(if outcome.is_err() { "failed" } else { "passed" })?;
            trial.error = outcome.err().map(|e| e.to_string());
        }
        finish(runner, &trial, keep_failed, &mut results)?;
    }
    let warnings: Vec<_> = results
        .iter()
        .filter(|r| r["required"] == false && result_failed(r))
        .map(|r| {
            format!(
                "advisory target {} failed; see retained evidence",
                r["distro"]
            )
        })
        .collect();
    runner.report.document["warnings"] = json!(warnings);
    runner.report.document["active_target"] = json!(null);
    runner.report.save()?;
    if runner.cancelled.load(Ordering::Relaxed)
        || results.len() != targets.len()
        || results
            .iter()
            .any(|r| !r["cleanup_error"].is_null() || (r["required"] == true && result_failed(r)))
    {
        return Err(format!("matrix failed; results: {}", runner.dir.display()).into());
    }
    Ok(())
}

fn result_failed(result: &Value) -> bool {
    !result["error"].is_null()
        || !result["cleanup_error"].is_null()
        || result["diagnostic_errors"] != json!([])
}

#[expect(
    clippy::too_many_lines,
    reason = "Per-target diagnostics and cleanup remain one finalization boundary"
)]
fn finish(
    runner: &mut Runner,
    trial: &Trial<'_>,
    keep_failed: bool,
    results: &mut Vec<Value>,
) -> Result<()> {
    let interrupted = runner.cancelled.swap(false, Ordering::Relaxed);
    let target = trial.target;
    let vm = trial.vm.as_str();
    let target_dir = runner.evidence().join(&target.id);
    runner.stage(&format!("{} | diagnostics", target.id))?;
    let mut diagnostic_errors = vec![];
    let mut image_fingerprint: Option<String> = None;
    let mut vm_exists = None;
    let vm_snapshot = runner
        .incus(&strings(&["list", vm, "--format=json"]), 30)
        .and_then(|output| -> Result<()> {
            let instances: Vec<serde_json::Value> = serde_json::from_str(&output)?;
            let instance = instances.iter().find(|instance| instance["name"] == vm);
            vm_exists = Some(instance.is_some());
            let instance = instance.ok_or("VM missing from Incus diagnostics")?;
            validate_vm_config(instance)?;
            image_fingerprint = instance["config"]["volatile.base_image"]
                .as_str()
                .map(str::to_owned);
            fs::write(
                target_dir.join("vm.json"),
                serde_json::to_vec_pretty(instance)?,
            )?;
            if instance["status"] == "Stopped" {
                runner.incus(&strings(&["start", vm]), 120)?;
                runner.ready(vm)?;
            }
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
        match runner.guest(vm, &strings(&["bash", "-c", diagnostic_script]), 120) {
            Ok(output) => {
                if let Err(error) = fs::write(target_dir.join("guest-diagnostics.txt"), output) {
                    diagnostic_errors.push(format!("write guest diagnostics: {error}"));
                }
            }
            Err(error) => diagnostic_errors.push(format!("guest diagnostics: {error}")),
        }
        match runner.guest(vm, &strings(&["test", "-d", "/opt/kidobo-e2e/state"]), 30) {
            Ok(_) => {
                let pull = runner.verify(vm).and_then(|()| {
                    let source = format!("{vm}/opt/kidobo-e2e/state");
                    let destination = target_dir.join("state").to_string_lossy().into_owned();
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
    runner
        .report
        .finish_stage(if diagnostic_errors.is_empty() {
            "passed"
        } else {
            "incomplete"
        })?;
    runner.stage(&format!("{} | cleanup", target.id))?;
    let mut cleanup_error = None;
    if vm_exists != Some(false)
        && !(keep_failed && trial.error.is_some())
        && let Err(error) = runner.delete(vm)
    {
        cleanup_error = Some(error.to_string());
    }
    runner.report.emit(&format!(
        "[e2e] {} ({}): {}",
        target.id,
        if target.required {
            "required"
        } else {
            "advisory"
        },
        trial
            .error
            .as_deref()
            .or(cleanup_error.as_deref())
            .unwrap_or("PASS")
    ))?;
    results.push(json!({
        "distro": target.id, "required": target.required, "transcript_line": trial.transcript_line,
        "phase": trial.phase, "error": trial.error, "cleanup_error": cleanup_error,
        "seconds": trial.started.elapsed().as_secs_f64(), "image": target.image,
        "image_fingerprint": image_fingerprint, "diagnostic_errors": diagnostic_errors,
    }));
    runner.report.document["results"] = json!(results);
    runner.report.finish_stage(if cleanup_error.is_some() {
        "failed"
    } else if keep_failed && trial.error.is_some() {
        "retained"
    } else {
        "passed"
    })?;
    runner.report.save()?;
    if interrupted {
        runner.cancelled.store(true, Ordering::Relaxed);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
