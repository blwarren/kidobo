//! Bounded prerequisite/application scheduling with one coordinator-owned report.
use super::{
    Config, Distro, OWNER, Owned, Result, Runner, application, clean, diagnostics, prepared,
    prerequisites, resume, strings, validate_vm_config,
};
use serde_json::{Value, json};
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
    active_seconds: f64,
    parked_seconds: f64,
    parked_at: Option<Instant>,
    preparation: Value,
    result: Option<Value>,
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
    if outcome.is_err() && runner.dir.join("ownership.json").exists() {
        runner.ignore_cancellation = true;
        // A report failure cannot prevent independent ownership-checked cleanup.
        let failed_report = runner.report.silent()?;
        let saved = std::mem::replace(&mut runner.report, failed_report);
        let cleanup = if keep_failed {
            park_owned(runner, config, run_id)
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

fn park_owned(runner: &mut Runner, config: &Config, run_id: &str) -> Result<()> {
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

fn batch<'a, F>(runner: &mut Runner, jobs: Vec<Trial<'a>>, action: F) -> Result<Vec<Trial<'a>>>
where
    F: Fn(&mut Runner, Trial<'a>) -> Result<Trial<'a>> + Sync,
{
    let (sender, receiver) = std::sync::mpsc::sync_channel(128);
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for job in jobs {
            let mut worker = runner.worker(sender.clone())?;
            let action = &action;
            handles.push(scope.spawn(move || action(&mut worker, job)));
        }
        drop(sender);
        let mut failure = None;
        for event in receiver {
            if let Err(error) = runner.report.accept(event, failure.as_deref()) {
                runner.cancelled.store(true, Ordering::Relaxed);
                if failure.is_none() {
                    failure = Some(error.to_string());
                }
            }
        }
        let mut completed = Vec::new();
        for handle in handles {
            match handle.join() {
                Ok(Ok(trial)) => completed.push(trial),
                Ok(Err(error)) => {
                    runner.cancelled.store(true, Ordering::Relaxed);
                    if failure.is_none() {
                        failure = Some(error.to_string());
                    }
                }
                Err(_) => {
                    runner.cancelled.store(true, Ordering::Relaxed);
                    if failure.is_none() {
                        failure = Some("E2E worker panicked".into());
                    }
                }
            }
        }
        if let Some(error) = failure {
            return Err(error.into());
        }
        Ok(completed)
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "Explicit candidate identity and coverage policy"
)]
#[expect(
    clippy::too_many_lines,
    reason = "Two passes keep prerequisite barrier and resource ownership explicit"
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
            .filter(|target| target.required)
            .map(|target| &target.id)
            .collect::<Vec<_>>()
    );
    runner.report.document["advisory_targets"] = json!(
        targets
            .iter()
            .filter(|target| !target.required)
            .map(|target| &target.id)
            .collect::<Vec<_>>()
    );
    runner.report.document["configured_required_targets"] = json!(
        config
            .distros
            .iter()
            .filter(|target| target.required)
            .map(|target| &target.id)
            .collect::<Vec<_>>()
    );
    let parallelism = runner.report.document["effective_parallelism"]
        .as_u64()
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(config.max_parallel_vms)
        .clamp(1, 2);
    let refresh = runner.report.document["refresh_images"] == true;
    let mut owned = Owned {
        owner: OWNER.into(),
        project: config.project.clone(),
        instances: vec![],
    };
    save_owned(runner, &owned)?;
    let mut results = Vec::new();
    let mut pending = Vec::new();
    for &target in targets {
        if let Some(previous) = previous
            && !refresh
            && previous.reusable(runner, config, target)?
        {
            let mut result = previous.result(&target.id, target.required)?;
            let line = runner.report.emit(&format!(
                "[{}] REUSED completed lifecycle from {}",
                target.id, previous.id
            ))?;
            if result["source_transcript_line"].is_null() {
                result["source_transcript_line"] = result["transcript_line"].clone();
            }
            result["transcript_line"] = json!(line);
            if result["source_seconds"].is_null() {
                result["source_seconds"] = result["seconds"].clone();
            }
            result["seconds"] = json!(0.0);
            result["active_seconds"] = json!(0.0);
            result["parked_seconds"] = json!(0.0);
            if let Some(stages) = runner.report.document["stages"].as_array_mut() {
                for stage in stages.iter_mut().filter(|stage| {
                    stage["name"]
                        .as_str()
                        .is_some_and(|name| name.starts_with(&format!("{} | ", target.id)))
                }) {
                    stage["status"] = json!("reused");
                    stage["source_run"] = json!(previous.id);
                }
            }
            results.push(result);
        } else {
            pending.push(target);
        }
    }
    let mut prepared = Vec::new();
    let mut machine_ids = std::collections::BTreeSet::new();
    let mut required_failed = false;
    let count = pending.len();
    for (index, chunk) in pending.chunks(parallelism).enumerate() {
        if runner.cancelled.load(Ordering::Relaxed) {
            break;
        }
        let keep_running = (index + 1) * parallelism >= count;
        let mut jobs = Vec::new();
        for &target in chunk {
            let vm = format!("{run_id}-{}", target.id);
            fs::create_dir_all(runner.evidence().join(&target.id))?;
            owned.instances.push(vm.clone());
            save_owned(runner, &owned)?;
            jobs.push(Trial {
                target,
                vm,
                transcript_line: runner.report.line,
                started: Instant::now(),
                phase: "provisioning",
                error: None,
                active_seconds: 0.0,
                parked_seconds: 0.0,
                parked_at: None,
                preparation: Value::Null,
                result: None,
            });
        }
        runner.report.document["active_targets"] =
            json!(chunk.iter().map(|target| &target.id).collect::<Vec<_>>());
        let completed = batch(runner, jobs, |worker, mut trial| {
            let started = Instant::now();
            let outcome = (|| -> Result<()> {
                trial.preparation =
                    prepared::prepare(worker, config, trial.target, &trial.vm, refresh)?;
                prerequisites(worker, &trial.vm, trial.target, tag, published, archive)?;
                if !keep_running {
                    worker.verify(&trial.vm)?;
                    worker.incus(&strings(&["stop", &trial.vm, "--timeout=60"]), 90)?;
                    trial.parked_at = Some(Instant::now());
                }
                Ok(())
            })();
            worker
                .report
                .finish_stage(if outcome.is_err() { "failed" } else { "passed" })?;
            trial.active_seconds += started.elapsed().as_secs_f64();
            trial.error = outcome.err().map(|error| error.to_string());
            if trial.error.is_some() {
                trial.result = Some(finish(worker, &trial, keep_failed, ())?);
            }
            Ok(trial)
        })?;
        for trial in completed {
            if let Some(result) = trial.result {
                required_failed |= trial.target.required;
                results.push(result);
            } else {
                let machine = trial.preparation["admission"]["machine_id"]
                    .as_str()
                    .ok_or("clone admission lacks machine identity")?;
                if !machine_ids.insert(machine.to_owned()) {
                    return Err("different VM clones share a machine identity".into());
                }
                if trial.preparation["cache_hit"] == true
                    && let Some(stages) = runner.report.document["stages"].as_array_mut()
                {
                    for name in ["provisioning", "OS reboot and kernel verification"] {
                        if let Some(stage) = stages
                            .iter_mut()
                            .find(|stage| stage["name"] == format!("{} | {name}", trial.target.id))
                        {
                            stage["status"] = json!("cached");
                            stage["source_image"] = trial.preparation["image_fingerprint"].clone();
                        }
                    }
                }
                prepared.push(trial);
            }
        }
        runner.report.document["results"] = json!(results);
        runner.report.save()?;
    }
    // The last batch is already running: consume it before starting parked guests.
    prepared.sort_by_key(|trial| trial.parked_at.is_some());
    runner
        .report
        .emit("[e2e] Prerequisite pass complete; starting application pass")?;
    while !prepared.is_empty() {
        let width = parallelism.min(prepared.len());
        let jobs = prepared.drain(..width).collect::<Vec<_>>();
        let cancelled = runner.cancelled.load(Ordering::Relaxed);
        let completed = batch(runner, jobs, |worker, mut trial| {
            let started = Instant::now();
            if let Some(parked) = trial.parked_at.take() {
                trial.parked_seconds += parked.elapsed().as_secs_f64();
            }
            if required_failed || cancelled {
                trial.error = Some(
                    "application checks not run: required prerequisites failed or run interrupted"
                        .into(),
                );
            } else {
                let outcome = (|| -> Result<()> {
                    worker.verify(&trial.vm)?;
                    let state: Vec<Value> = serde_json::from_str(
                        &worker.incus(&strings(&["list", &trial.vm, "--format=json"]), 30)?,
                    )?;
                    if state
                        .iter()
                        .find(|value| value["name"] == trial.vm)
                        .is_some_and(|value| value["status"] == "Stopped")
                    {
                        worker.incus(&strings(&["start", &trial.vm]), 120)?;
                        worker.ready(&trial.vm)?;
                    }
                    trial.phase = "application";
                    application(worker, &trial.vm, trial.target, tag, published)
                })();
                worker
                    .report
                    .finish_stage(if outcome.is_err() { "failed" } else { "passed" })?;
                trial.error = outcome.err().map(|error| error.to_string());
            }
            trial.active_seconds += started.elapsed().as_secs_f64();
            let finalize = Instant::now();
            let mut result = finish(worker, &trial, keep_failed, ())?;
            result["active_seconds"] =
                json!(trial.active_seconds + finalize.elapsed().as_secs_f64());
            trial.result = Some(result);
            Ok(trial)
        })?;
        for trial in completed {
            if let Some(result) = trial.result {
                results.push(result);
            }
        }
        runner.report.document["results"] = json!(results);
        runner.report.save()?;
    }
    let warnings = results
        .iter()
        .filter(|result| result["required"] == false && result_failed(result))
        .map(|result| {
            format!(
                "advisory target {} failed; see retained evidence",
                result["distro"]
            )
        })
        .collect::<Vec<_>>();
    let all_passed =
        results.len() == targets.len() && results.iter().all(|result| !result_failed(result));
    let required_passed = results
        .iter()
        .filter(|result| result["required"] == true)
        .count()
        == targets.iter().filter(|target| target.required).count()
        && results
            .iter()
            .filter(|result| result["required"] == true)
            .all(|result| !result_failed(result));
    runner.report.document["warnings"] = json!(warnings);
    runner.report.document["results"] = json!(results);
    runner.report.document["all_selected_targets_passed"] = json!(all_passed);
    runner.report.document["release_gate_passed"] = json!(
        configured_release_passed(config, &results)
            && !runner.cancelled.load(Ordering::Relaxed)
            && results
                .iter()
                .all(|result| result["cleanup_error"].is_null())
    );
    runner.report.document["platforms"] = json!(
        results
            .iter()
            .map(|result| json!({"target":result["distro"],
        "iptables_backend":result["preparation"]["admission"]["iptables_backend"],
        "ip6tables_backend":result["preparation"]["admission"]["ip6tables_backend"],
        "selinux":result["preparation"]["admission"]["selinux"]}))
            .collect::<Vec<_>>()
    );
    runner.report.document["active_target"] = Value::Null;
    runner.report.document["active_targets"] = json!([]);
    runner.report.save()?;
    if runner.cancelled.load(Ordering::Relaxed)
        || results.len() != targets.len()
        || !required_passed
        || results
            .iter()
            .any(|result| !result["cleanup_error"].is_null())
    {
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
fn result_failed(result: &Value) -> bool {
    !result["error"].is_null()
        || !result["cleanup_error"].is_null()
        || result["diagnostic_errors"] != json!([])
}

fn configured_release_passed(config: &Config, results: &[Value]) -> bool {
    config
        .distros
        .iter()
        .filter(|target| target.required)
        .all(|target| {
            results
                .iter()
                .any(|result| result["distro"] == target.id && !result_failed(result))
        })
}

#[expect(
    clippy::too_many_lines,
    reason = "Per-target diagnostics and cleanup remain one finalization boundary"
)]
fn finish(runner: &mut Runner, trial: &Trial<'_>, keep_failed: bool, _unused: ()) -> Result<Value> {
    let finalized = Instant::now();
    runner.ignore_cancellation = true;
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
            diagnostic_errors.extend(diagnostics::collect(runner, vm, &target_dir));
            if instance["status"] == "Stopped" {
                if runner.cancelled.load(Ordering::Relaxed) {
                    return Err("stopped guest was not restarted during interrupted cleanup".into());
                }
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
                diagnostic_errors.push(format!("pull preparation diagnostics: {error}"));
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
            .or_else(|| diagnostic_errors.first().map(String::as_str))
            .unwrap_or("PASS")
    ))?;
    let result = json!({
        "distro": target.id, "required": target.required, "transcript_line": trial.transcript_line,
        "phase": trial.phase, "error": trial.error, "cleanup_error": cleanup_error,
        "seconds": trial.started.elapsed().as_secs_f64(), "image": target.image,
        "active_seconds":trial.active_seconds+finalized.elapsed().as_secs_f64(), "parked_seconds":trial.parked_seconds,
        "preparation":trial.preparation, "validation_contract":crate::contract::VERSION,
        "image_fingerprint": image_fingerprint, "diagnostic_errors": diagnostic_errors,
    });
    runner.report.finish_stage(if cleanup_error.is_some() {
        "failed"
    } else if keep_failed && trial.error.is_some() {
        "retained"
    } else {
        "passed"
    })?;
    runner.report.save()?;
    Ok(result)
}

#[cfg(test)]
mod tests;
