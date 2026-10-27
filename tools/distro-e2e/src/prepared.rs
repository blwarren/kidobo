//! Immutable, suite-owned preparation images with bounded freshness and retention.
use super::{Config, Distro, OWNER, Result, Runner, contract, hash, strings};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct Settings {
    pub(super) enabled: bool,
    pub(super) max_age_hours: u64,
    pub(super) max_generations: usize,
    pub(super) prune_after_hours: u64,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: true,
            max_age_hours: 168,
            max_generations: 2,
            prune_after_hours: 336,
        }
    }
}

pub(super) fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

pub(super) fn validate_settings(config: &Config) -> Result<()> {
    if !(1..=2).contains(&config.max_parallel_vms)
        || config.prepared_images.max_age_hours == 0
        || config.prepared_images.max_age_hours > u64::MAX / 3600
        || config.prepared_images.prune_after_hours < config.prepared_images.max_age_hours
        || config.prepared_images.prune_after_hours > u64::MAX / 3600
        || config.prepared_images.max_generations == 0
        || config
            .distros
            .iter()
            .any(|target| !matches!(target.selinux.as_str(), "enforcing" | "image-default"))
    {
        return Err("invalid E2E concurrency, image retention, or SELinux settings".into());
    }
    Ok(())
}

fn key(runner: &Runner, config: &Config, target: &Distro, profile: &Value) -> Result<String> {
    let frozen: Value = serde_json::from_str(&super::read_text(
        &runner.evidence().join("inputs/SHA256.json"),
    )?)?;
    if frozen["harness"].as_str().is_none_or(str::is_empty) {
        return Err("frozen host harness identity missing".into());
    }
    let identity = json!({"version":contract::VERSION,"preparation":hash(&runner.evidence().join("inputs/provision.sh"))?,
        "host_harness":frozen["harness"],
        "target":target,"project":config.project,"profile":{"name":config.profile,"config":profile["config"],"devices":profile["devices"]},"pool":config.pool,"network":config.network,
        "cpus":config.cpus,"memory":config.memory,"disk":config.disk,"architecture":std::env::consts::ARCH});
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(serde_json::to_vec(&identity)?) {
        write!(&mut output, "{byte:02x}")?;
    }
    Ok(output)
}

fn images(runner: &mut Runner) -> Result<Vec<Value>> {
    Ok(serde_json::from_str(&runner.incus(
        &strings(&["image", "list", "--format=json"]),
        30,
    )?)?)
}
fn property<'a>(image: &'a Value, name: &str) -> Option<&'a str> {
    image["properties"][name].as_str()
}
fn fingerprint(image: &Value) -> Result<&str> {
    image["fingerprint"]
        .as_str()
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| "invalid preparation image fingerprint".into())
}
fn owned(image: &Value) -> bool {
    property(image, "user.kidobo-e2e") == Some(OWNER)
        && image["public"] == false
        && image["type"] == "virtual-machine"
}

fn fresh(image: &Value, identity: &str, settings: &Settings, time: u64) -> bool {
    let Some(manifest) = property(image, "kidobo_e2e_manifest")
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
    else {
        return false;
    };
    owned(image)
        && property(image, "kidobo_e2e_ready") == Some("true")
        && property(image, "kidobo_e2e_key") == Some(identity)
        && manifest["format"] == 1
        && manifest["architecture"] == std::env::consts::ARCH
        && manifest["expected_kernel"]
            .as_str()
            .is_some_and(|kernel| !kernel.is_empty())
        && property(image, "kidobo_e2e_prepared_at")
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|created| {
                manifest["prepared_at_unix"] == created
                    && time
                        .checked_sub(created)
                        .is_some_and(|age| age < settings.max_age_hours * 3600)
            })
}

fn image_property(runner: &mut Runner, image: &str, name: &str, value: &str) -> Result<()> {
    runner
        .incus(&strings(&["image", "set-property", image, name, value]), 30)
        .map(|_| ())
}

pub(super) fn prune(runner: &mut Runner, config: &Config) -> Result<()> {
    let instances: Vec<Value> =
        serde_json::from_str(&runner.incus(&strings(&["list", "--format=json"]), 30)?)?;
    let time = now()?;
    let mut candidates = images(runner)?;
    candidates.retain(owned);
    candidates.sort_by_key(|image| {
        std::cmp::Reverse(
            property(image, "kidobo_e2e_prepared_at")
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(0),
        )
    });
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for image in candidates {
        let fp = fingerprint(&image)?;
        if instances.iter().any(|instance| {
            instance["config"]["volatile.base_image"] == fp
                || instance["expanded_config"]["volatile.base_image"] == fp
        }) {
            continue;
        }
        let Some(target) = property(&image, "kidobo_e2e_target") else {
            continue;
        };
        let count = counts.entry(target.to_owned()).or_default();
        if property(&image, "kidobo_e2e_ready") == Some("true") {
            *count += 1;
        }
        let last =
            property(&image, "kidobo_e2e_last_used").and_then(|value| value.parse::<u64>().ok());
        let expired = last.is_some_and(|last| {
            time.checked_sub(last)
                .is_some_and(|age| age >= config.prepared_images.prune_after_hours * 3600)
        });
        if property(&image, "kidobo_e2e_ready") != Some("true")
            || *count > config.prepared_images.max_generations
            || expired
        {
            runner.incus(&strings(&["image", "delete", fp]), 60)?;
        }
    }
    Ok(())
}

pub(super) fn prepare(
    runner: &mut Runner,
    config: &Config,
    target: &Distro,
    vm: &str,
    refresh: bool,
) -> Result<Value> {
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
    let identity = key(runner, config, target, &profile)?;
    if config.prepared_images.enabled && !refresh {
        let mut available = images(runner)?;
        available.sort_by_key(|image| {
            std::cmp::Reverse(
                property(image, "kidobo_e2e_prepared_at")
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or(0),
            )
        });
        let time = now()?;
        if let Some(image) = available
            .into_iter()
            .find(|image| fresh(image, &identity, &config.prepared_images, time))
        {
            let fp = fingerprint(&image)?.to_owned();
            let admission = clone_and_admit(runner, target, vm, &fp, &config.profile, &image);
            match admission {
                Ok(mut metadata) => {
                    image_property(runner, &fp, "kidobo_e2e_last_used", &now()?.to_string())?;
                    metadata["cache_hit"] = json!(true);
                    metadata["cache_key"] = json!(identity);
                    save_metadata(runner, target, &metadata)?;
                    return Ok(metadata);
                }
                Err(error) => {
                    runner.report.emit(&format!(
                        "[{}] Cached image {fp} rejected; rebuilding once: {error}",
                        target.id
                    ))?;
                    runner.report.document["cache_rejection"] =
                        json!({"fingerprint":fp,"error":error.to_string()});
                    let context = format!("{} | clone admission", target.id);
                    for key in ["commands", "checks"] {
                        for record in worker_records(&mut runner.report.document, key)? {
                            if record["context"] == context {
                                record["original_context"] = record["context"].clone();
                                record["context"] =
                                    json!(format!("cache diagnostics | {}", target.id));
                            }
                        }
                    }
                    runner.report.save()?;
                    image_property(runner, &fp, "kidobo_e2e_ready", "false")?;
                    remove_if_present(runner, vm)?;
                }
            }
        }
    }
    build(runner, config, target, vm, &identity)
}

fn remove_if_present(runner: &mut Runner, vm: &str) -> Result<()> {
    let values: Vec<Value> =
        serde_json::from_str(&runner.incus(&strings(&["list", vm, "--format=json"]), 30)?)?;
    if values.iter().any(|value| value["name"] == vm) {
        runner.delete(vm)?;
    }
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "Preparation, publication and clone admission form one cache admission transaction"
)]
fn build(
    runner: &mut Runner,
    config: &Config,
    target: &Distro,
    vm: &str,
    identity: &str,
) -> Result<Value> {
    let started = Instant::now();
    runner.stage(&format!("{} | VM creation", target.id))?;
    // Resolve the alias at refresh time, then create from its immutable fingerprint.
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
    let relabel = runner.guest(
        vm,
        &strings(&["cat", "/opt/kidobo-e2e/prepared/relabel-scheduled"]),
        30,
    )?;
    runner.stage(&format!(
        "{} | OS reboot and kernel verification",
        target.id
    ))?;
    runner.reboot_with_timeout(vm, if relabel.trim() == "1" { 900 } else { 300 })?;
    if relabel.trim() == "1" {
        let deadline = Instant::now() + std::time::Duration::from_mins(15);
        loop {
            if runner.guest(vm,&strings(&["bash","-c","test ! -e /.autorelabel && ! systemctl is-active --quiet selinux-autorelabel.service"]),15).is_ok() {break;}
            if runner.cancelled.load(std::sync::atomic::Ordering::Relaxed)
                || Instant::now() >= deadline
            {
                return Err("SELinux relabeling did not complete within 900 seconds".into());
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    }
    runner.guest(
        vm,
        &strings(&["bash", "/opt/kidobo-e2e/provision.sh", "--check-kernel"]),
        if relabel.trim() == "1" { 900 } else { 60 },
    )?;
    let manifest = runner.guest(
        vm,
        &strings(&["cat", "/opt/kidobo-e2e/prepared/manifest.json"]),
        30,
    )?;
    let preparation: Value = serde_json::from_str(&manifest)?;
    let created = preparation["prepared_at_unix"]
        .as_u64()
        .ok_or("preparation timestamp missing")?;
    if !config.prepared_images.enabled {
        runner.stage(&format!("{} | clone admission", target.id))?;
        runner.guest(
            vm,
            &strings(&["bash", "/opt/kidobo-e2e/provision.sh", "--admit", "--fresh"]),
            60,
        )?;
        return finish_admission(
            runner,
            target,
            vm,
            json!({"cache_hit":false,"cache_key":identity,"source_image_fingerprint":source_fp,"preparation":preparation,"cache_build_seconds":started.elapsed().as_secs_f64()}),
        );
    }
    runner.guest(
        vm,
        &strings(&["bash", "/opt/kidobo-e2e/provision.sh", "--sanitize"]),
        60,
    )?;
    runner.incus(&strings(&["stop", vm, "--timeout=60"]), 90)?;
    let generation = format!(
        "{}-{}",
        runner
            .dir
            .file_name()
            .ok_or("missing run")?
            .to_string_lossy(),
        target.id
    );
    runner.incus(
        &strings(&[
            "publish",
            vm,
            "--compression=none",
            &format!("user.kidobo-e2e={OWNER}"),
            &format!("kidobo_e2e_target={}", target.id),
            &format!("kidobo_e2e_key={identity}"),
            &format!("kidobo_e2e_generation={generation}"),
            "kidobo_e2e_ready=false",
            &format!("kidobo_e2e_prepared_at={created}"),
            &format!("kidobo_e2e_last_used={created}"),
            &format!("kidobo_e2e_source={source_fp}"),
            &format!("kidobo_e2e_manifest={}", manifest.trim()),
        ]),
        900,
    )?;
    let image = images(runner)?
        .into_iter()
        .find(|image| owned(image) && property(image, "kidobo_e2e_generation") == Some(&generation))
        .ok_or("published preparation image missing")?;
    let fp = fingerprint(&image)?.to_owned();
    runner.delete(vm)?;
    let mut metadata = clone_and_admit(runner, target, vm, &fp, &config.profile, &image)?;
    image_property(runner, &fp, "kidobo_e2e_ready", "true")?;
    metadata["cache_hit"] = json!(false);
    metadata["cache_key"] = json!(identity);
    metadata["cache_build_seconds"] = json!(started.elapsed().as_secs_f64());
    save_metadata(runner, target, &metadata)?;
    Ok(metadata)
}

fn clone_and_admit(
    runner: &mut Runner,
    target: &Distro,
    vm: &str,
    image: &str,
    profile: &str,
    description: &Value,
) -> Result<Value> {
    runner.stage(&format!("{} | VM creation", target.id))?;
    runner.create_vm(image, vm, profile)?;
    runner.ready(vm)?;
    runner.stage(&format!("{} | clone admission", target.id))?;
    runner.guest(
        vm,
        &strings(&["bash", "/opt/kidobo-e2e/provision.sh", "--admit"]),
        60,
    )?;
    let manifest = runner.guest(
        vm,
        &strings(&["cat", "/opt/kidobo-e2e/prepared/manifest.json"]),
        30,
    )?;
    let original =
        property(description, "kidobo_e2e_manifest").ok_or("cached manifest property missing")?;
    let manifest_value: Value = serde_json::from_str(&manifest)?;
    if manifest_value != serde_json::from_str::<Value>(original)?
        || manifest_value["selinux_requested"] != target.selinux
        || (target.selinux == "enforcing" && manifest_value["selinux_actual"] != "Enforcing")
    {
        return Err("cached preparation manifest or security requirement mismatch".into());
    }
    finish_admission(
        runner,
        target,
        vm,
        json!({"image_fingerprint":image,"source_image_fingerprint":property(description,"kidobo_e2e_source"),"preparation":serde_json::from_str::<Value>(&manifest)?}),
    )
}

fn finish_admission(
    runner: &mut Runner,
    target: &Distro,
    vm: &str,
    mut metadata: Value,
) -> Result<Value> {
    let admission = runner.guest(
        vm,
        &strings(&["cat", "/opt/kidobo-e2e/prepared/admission.json"]),
        30,
    )?;
    metadata["admission"] = serde_json::from_str(&admission)?;
    if let Some(rejection) = runner.report.document.get("cache_rejection") {
        metadata["rejected_cache"] = rejection.clone();
    }
    let directory = runner.evidence().join(&target.id);
    fs::create_dir_all(&directory)?;
    save_metadata(runner, target, &metadata)?;
    runner.verify(vm)?;
    runner.incus(
        &strings(&[
            "file",
            "pull",
            "-r",
            &format!("{vm}/opt/kidobo-e2e/prepared"),
            &directory.join("prepared").to_string_lossy(),
        ]),
        120,
    )?;
    Ok(metadata)
}

fn save_metadata(runner: &Runner, target: &Distro, metadata: &Value) -> Result<()> {
    fs::write(
        runner.evidence().join(&target.id).join("preparation.json"),
        serde_json::to_vec_pretty(metadata)?,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn freshness_has_a_fixed_boundary_and_never_uses_future_or_unready_images() {
        let settings = Settings::default();
        let mut image = json!({"public":false,"type":"virtual-machine","properties":{"user.kidobo-e2e":OWNER,"kidobo_e2e_ready":"true","kidobo_e2e_key":"key","kidobo_e2e_prepared_at":"100"}});
        image["properties"]["kidobo_e2e_manifest"]=json!(json!({"format":1,"architecture":std::env::consts::ARCH,"expected_kernel":"kernel","prepared_at_unix":100}).to_string());
        assert!(fresh(&image, "key", &settings, 100 + 168 * 3600 - 1));
        assert!(!fresh(&image, "key", &settings, 100 + 168 * 3600));
        assert!(!fresh(&image, "key", &settings, 99));
        assert!(!fresh(&image, "changed", &settings, 101));
        image["properties"]["kidobo_e2e_ready"] = json!("false");
        assert!(!fresh(&image, "key", &settings, 101));
    }
}

fn worker_records<'a>(document: &'a mut Value, key: &str) -> Result<&'a mut Vec<Value>> {
    document[key]
        .as_array_mut()
        .ok_or_else(|| "missing worker records".into())
}

#[cfg(test)]
#[path = "prepared/integration_tests.rs"]
mod integration_tests;
