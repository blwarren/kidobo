//! Independent bounded target lifecycles with worker-owned evidence.
use super::{
    Config, Distro, OWNER, Owned, Result, Runner, application, clean, diagnostics, prepared,
    prerequisites, strings, validate_vm_config,
};
use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::Instant;

mod outcome;

struct Trial<'a> {
    target: &'a Distro,
    vm: String,
    started: Instant,
    phase: &'static str,
    error: Option<String>,
    preparation: Value,
}

#[expect(
    clippy::too_many_arguments,
    reason = "Explicit candidate identity and coverage policy"
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
    );
    if outcome.is_err() && runner.dir.join("ownership.json").exists() {
        runner.ignore_cancellation = true;
        // A report failure cannot prevent independent ownership-checked cleanup.
        let failed_report = runner.report.silent()?;
        let saved = std::mem::replace(&mut runner.report, failed_report);
        let cleanup = if keep_failed {
            retain_owned(runner, config, run_id)
        } else {
            clean(runner, config)
        };
        runner.report = saved;
        runner.report.document["emergency_cleanup"] = json!({"retained":keep_failed,"completed":cleanup.is_ok(),"error":cleanup.as_ref().err().map(ToString::to_string)});
        let _ = runner.report.save();
        if let Err(error) = cleanup {
            runner.report.document["cleanup_error"] = json!(error.to_string());
            let _ = runner.report.save();
        }
    }
    outcome
}

fn retain_owned(runner: &mut Runner, config: &Config, run_id: &str) -> Result<()> {
    let owned: Owned =
        serde_json::from_str(&super::read_text(&runner.dir.join("ownership.json"))?)?;
    super::validate_owned_manifest(&owned, &config.project, run_id)?;
    let instances: Vec<Value> =
        serde_json::from_str(&runner.incus(&strings(&["list", "--format=json"]), 30)?)?;
    let mut failures = Vec::new();
    for vm in owned.instances {
        if instances.iter().any(|instance| instance["name"] == vm)
            && let Err(error) = runner.retain(&vm)
        {
            failures.push(format!("{vm}: {error}"));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!("VM retention failed: {}", failures.join("; ")).into())
    }
}

#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "Complete target lifecycles and aggregate outcomes stay adjacent"
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
    runner.report.document["configured_required_targets"] = json!(
        config
            .distros
            .iter()
            .filter(|t| t.required)
            .map(|t| &t.id)
            .collect::<Vec<_>>()
    );
    let parallelism = runner.report.document["effective_parallelism"]
        .as_u64()
        .and_then(|v| usize::try_from(v).ok())
        .unwrap_or(config.max_parallel_vms)
        .clamp(1, 2);
    let mut owned = Owned {
        owner: OWNER.into(),
        project: config.project.clone(),
        instances: vec![],
    };
    save_owned(runner, &owned)?;
    for chunk in targets.chunks(parallelism) {
        if runner.cancelled.load(Ordering::Relaxed) {
            break;
        }
        let (sender, receiver) = std::sync::mpsc::sync_channel(128);
        let mut jobs = Vec::new();
        for &target in chunk {
            let vm = format!("{run_id}-{}", target.id);
            fs::create_dir_all(runner.evidence().join(&target.id))?;
            owned.instances.push(vm.clone());
            save_owned(runner, &owned)?;
            let worker = runner.worker(&target.id, sender.clone())?;
            jobs.push((
                worker,
                Trial {
                    target,
                    vm,
                    started: Instant::now(),
                    phase: "provisioning",
                    error: None,
                    preparation: Value::Null,
                },
            ));
        }
        runner.report.document["active_targets"] =
            json!(chunk.iter().map(|t| &t.id).collect::<Vec<_>>());
        runner.report.save()?;
        std::thread::scope(|scope| -> Result<()> {
            let mut handles = Vec::new();
            for (mut worker, mut trial) in jobs {
                let sender = sender.clone();
                handles.push(scope.spawn(move || -> Result<()> {
                    let result = (|| -> Result<Value> {
                        let lifecycle = (|| -> Result<()> {
                            trial.preparation =
                                prepared::prepare(&mut worker, config, trial.target, &trial.vm)?;
                            prerequisites(
                                &mut worker,
                                &trial.vm,
                                trial.target,
                                tag,
                                published,
                                archive,
                            )?;
                            trial.phase = "application";
                            application(&mut worker, &trial.vm, trial.target, tag, published)
                        })();
                        worker.report.ensure_healthy()?;
                        worker.report.finish_stage(if lifecycle.is_err() {
                            "failed"
                        } else {
                            "passed"
                        })?;
                        trial.error = lifecycle.err().map(|error| error.to_string());
                        finish(&mut worker, &trial, keep_failed)
                    })();
                    if result.is_err() {
                        worker.cancelled.store(true, Ordering::Relaxed);
                    }
                    sender.send(super::report::Event::Completed(result?))?;
                    Ok(())
                }));
            }
            drop(sender);
            let mut failure = None;
            for event in receiver {
                if failure.is_none()
                    && let Err(error) = runner.report.accept(event)
                {
                    runner.cancelled.store(true, Ordering::Relaxed);
                    failure = Some(error.to_string());
                }
            }
            for handle in handles {
                let result = handle
                    .join()
                    .unwrap_or_else(|_| Err("E2E worker panicked".into()));
                if let Err(error) = result {
                    runner.cancelled.store(true, Ordering::Relaxed);
                    failure.get_or_insert_with(|| error.to_string());
                }
            }
            if let Some(error) = failure {
                return Err(error.into());
            }
            Ok(())
        })?;
    }
    let results = runner.report.document["results"]
        .as_array()
        .ok_or("missing results")?
        .clone();
    let summary = outcome::summarize(
        config,
        targets,
        &results,
        runner.cancelled.load(Ordering::Relaxed),
    );
    runner.report.document["warnings"] = json!(summary.warnings);
    runner.report.document["all_selected_targets_passed"] =
        json!(summary.all_selected_targets_passed);
    runner.report.document["release_gate_passed"] = json!(summary.release_gate_passed);
    runner.report.document["platforms"] = json!(summary.platforms);
    runner.report.document["active_targets"] = json!([]);
    runner.report.save()?;
    if runner.cancelled.load(Ordering::Relaxed) || !summary.matrix_succeeded {
        return Err(format!("matrix failed; results: {}", runner.dir.display()).into());
    }
    Ok(())
}

fn save_owned(runner: &Runner, owned: &Owned) -> Result<()> {
    let temporary = runner.dir.join(".ownership.json.tmp");
    fs::write(&temporary, serde_json::to_vec_pretty(owned)?)?;
    fs::rename(temporary, runner.dir.join("ownership.json"))?;
    Ok(())
}
#[expect(
    clippy::too_many_lines,
    reason = "Per-target diagnostics and cleanup remain one finalization boundary"
)]
fn finish(runner: &mut Runner, trial: &Trial<'_>, keep_failed: bool) -> Result<Value> {
    runner.ignore_cancellation = true;
    let target = trial.target;
    let vm = trial.vm.as_str();
    let target_dir = runner.evidence().join(&target.id);
    runner.stage(&format!("{} | diagnostics", target.id))?;
    let mut diagnostic_errors = vec![];
    let mut diagnostic_warnings: Vec<String> = trial.preparation["diagnostic_warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    let mut image_fingerprint: Option<String> = None;
    let mut vm_exists = None;
    let mut vm_running = false;
    let vm_snapshot = runner
        .incus(&strings(&["list", vm, "--format=json"]), 30)
        .and_then(|output| -> Result<()> {
            let instances: Vec<serde_json::Value> = serde_json::from_str(&output)?;
            let instance = instances.iter().find(|instance| instance["name"] == vm);
            vm_exists = Some(instance.is_some());
            let instance = instance.ok_or("VM missing from Incus diagnostics")?;
            runner.verify(vm)?;
            validate_vm_config(instance)?;
            vm_running = instance["status"] == "Running";
            image_fingerprint = instance["config"]["volatile.base_image"]
                .as_str()
                .map(str::to_owned);
            fs::write(
                target_dir.join("vm.json"),
                serde_json::to_vec_pretty(instance)?,
            )?;
            let host = diagnostics::collect(runner, vm, &target_dir);
            diagnostic_errors.extend(host.errors);
            diagnostic_warnings.extend(host.warnings);
            Ok(())
        });
    if let Err(error) = vm_snapshot {
        diagnostic_warnings.push(format!("VM metadata: {error}"));
    } else if vm_running {
        if target.vendor_image.is_some()
            && let Some(warning) = diagnostics::vendor_guest(runner, vm, &target_dir)?
        {
            diagnostic_warnings.push(warning);
        }
        let diagnostic_script = r"
printf '%s\n' '=== uname ==='; uname -a || true
printf '%s\n' '=== boot selection ==='; cat /proc/cmdline || true; find /boot -maxdepth 3 -type f -printf '%p %s bytes\n' || true
if command -v grubby >/dev/null 2>&1; then grubby --default-kernel || true; grubby --info=ALL || true; fi
printf '%s\n' '=== SELinux ==='; getenforce || true; journalctl -b --no-pager -g 'avc:|SELinux|autorelabel' || true
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
                    diagnostic_warnings.push(format!("write guest diagnostics: {error}"));
                }
            }
            Err(error) => diagnostic_warnings.push(format!("guest diagnostics: {error}")),
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
                    diagnostic_warnings.push(format!("pull guest state: {error}"));
                }
            }
            Err(error) => {
                diagnostic_warnings.push(format!("guest state unavailable: {error}"));
            }
        }
        if runner
            .guest(
                vm,
                &strings(&["test", "-d", "/opt/kidobo-e2e/prepared"]),
                30,
            )
            .is_ok()
        {
            let prepared = target_dir.join("prepared-diagnostics");
            let pull = runner.verify(vm).and_then(|()| {
                runner.incus(
                    &strings(&[
                        "file",
                        "pull",
                        "-r",
                        &format!("{vm}/opt/kidobo-e2e/prepared"),
                        &prepared.to_string_lossy(),
                    ]),
                    120,
                )
            });
            if let Err(error) = pull {
                diagnostic_warnings.push(format!("pull preparation diagnostics: {error}"));
            }
        }
    }
    runner.report.ensure_healthy()?;
    if !diagnostic_errors.is_empty() {
        runner.cancelled.store(true, Ordering::Relaxed);
    }
    runner.report.finish_stage(
        if diagnostic_errors.is_empty() && diagnostic_warnings.is_empty() {
            "passed"
        } else {
            "incomplete"
        },
    )?;
    runner.stage(&format!("{} | cleanup", target.id))?;
    let mut cleanup_error = None;
    if vm_exists != Some(false) {
        let cleanup = if keep_failed && trial.error.is_some() {
            runner.retain(vm)
        } else {
            runner.delete(vm)
        };
        if let Err(error) = cleanup {
            cleanup_error = Some(error.to_string());
            let stopped = runner.verify(vm).and_then(|()| {
                runner
                    .incus(&strings(&["stop", vm, "--timeout=60"]), 90)
                    .map(|_| ())
            });
            if let Err(stop_error) = stopped {
                runner.cancelled.store(true, Ordering::Relaxed);
                cleanup_error = Some(format!(
                    "{error}; could not stop retained guest: {stop_error}"
                ));
            }
        }
    }
    runner.report.progress(&format!(
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
            .or_else(|| diagnostic_errors.first().map(String::as_str))
            .unwrap_or("PASS")
    ))?;
    let result = json!({
        "distro": target.id, "required": target.required,
        "transcript": format!("targets/{}/transcript.log", target.id),
        "report": format!("targets/{}/results.json", target.id),
        "phase": trial.phase, "error": trial.error, "cleanup_error": cleanup_error,
        "seconds": trial.started.elapsed().as_secs_f64(), "image": target.image,
        "vendor_image": target.vendor_image,
        "preparation":trial.preparation, "validation_contract":crate::contract::VERSION,
        "image_fingerprint": image_fingerprint, "diagnostic_errors": diagnostic_errors,
        "diagnostic_warnings": diagnostic_warnings,
    });
    runner.report.finish_stage(if cleanup_error.is_some() {
        "failed"
    } else if keep_failed && trial.error.is_some() {
        "retained"
    } else {
        "passed"
    })?;
    runner.report.document["results"] = json!([result]);
    runner.report.document["status"] = json!(if outcome::result_failed(&result) {
        "failed"
    } else {
        "passed"
    });
    runner.report.save()?;
    Ok(result)
}

#[cfg(test)]
mod tests;
