use super::*;
use crate::tests::TestDir;
use crate::{Cli, Owned, Report, archive_evidence};
use clap::Parser;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

const CONFIG: &str = r#"
project = "kidobo-e2e"
profile = "kidobo-e2e"
network = "kidoboe2e0"
pool = "kidobo-e2e"
cpus = 2
memory = "4GiB"
disk = "30GiB"
[[distros]]
id = "debian-12"
image = "debian/bookworm"
family = "apt"
packages = ["bash"]
"#;

fn runner_at(dir: &Path) -> Runner {
    Runner {
        project: "kidobo-e2e".into(),
        dir: dir.into(),
        incus_program: "/unused-incus".into(),
        cancelled: Arc::new(AtomicBool::new(false)),
        report: Report::open(dir).expect("report"),
    }
}

fn successful_document() -> Value {
    json!({
        "run_id":"run-1-1", "tag":"v1.2.3", "status":"failed", "commands": [],
        "coverage":"Candidate lifecycle lane including reboot, upgrade, and failure preservation",
        "results":[{"distro":"debian-12", "phase":"application", "error":null,
            "cleanup_error":null, "diagnostic_errors":[], "image_fingerprint":"known-image", "transcript_line":4}],
        "stages":LIFECYCLE_STAGES.iter().map(|name| json!({"name":format!("debian-12 | {name}"),"status":"passed"})).collect::<Vec<_>>(),
        "checks":LIFECYCLE_STAGES.iter().map(|name| json!({"context":format!("debian-12 | {name}"),"status":"passed"})).collect::<Vec<_>>(),
    })
}

fn write_inputs(runner: &Runner) {
    let dir = runner.evidence().join("inputs");
    fs::create_dir_all(dir.join("release")).expect("inputs");
    let mut hashes = serde_json::Map::new();
    for name in ["installer.sh", "provision.sh", "lifecycle.sh", "traffic.py"] {
        let path = dir.join(name);
        fs::write(&path, format!("fixture {name}\n")).expect("script");
        hashes.insert(name.into(), json!(hash(&path).expect("hash")));
    }
    fs::write(dir.join("e2e.toml"), CONFIG).expect("config");
    fs::write(
        dir.join("SHA256.json"),
        serde_json::to_vec(&hashes).expect("json"),
    )
    .expect("manifest");
    fs::write(
        dir.join("release/kidobo-v1.2.3-linux-x86_64.tar.gz"),
        "candidate bytes",
    )
    .expect("candidate");
    fs::write(dir.join("release/SHA256SUMS"), "exact checksum manifest\n").expect("checksums");
    for (name, value) in [
        ("baseline-tag", "v1.2.2"),
        ("baseline-installer.sh", "baseline installer"),
        ("baseline-SHA256SUMS", "baseline checksums"),
    ] {
        fs::write(runner.evidence().join(name), value).expect("baseline");
    }
}

fn source(root: &Path) {
    let mut runner = runner_at(&root.join("run-1-1"));
    write_inputs(&runner);
    runner.report.document = successful_document();
    runner.report.document["archive_sha256"] = json!(
        hash(
            &runner
                .evidence()
                .join("inputs/release/kidobo-v1.2.3-linux-x86_64.tar.gz")
        )
        .expect("candidate digest")
    );
    archive_evidence(&mut runner).expect("archive fixtures");
    runner
        .report
        .finish_stage("passed")
        .expect("finish archive");
    runner.report.save().expect("save source");
}

#[test]
fn legacy_completed_targets_reuse_only_when_definitions_and_resources_match() {
    let temp = TestDir::new();
    source(temp.path());
    let mut runner = runner_at(&temp.path().join("run-2-2"));
    write_inputs(&runner);
    let original_bytes =
        read_text(&temp.path().join("run-1-1/results.json")).expect("source bytes");
    let previous = Resume::load(&mut runner, "run-1-1").expect("legacy source");
    let mut config: Config = toml_edit::de::from_str(CONFIG).expect("config");
    assert!(
        previous
            .reusable(&mut runner, &config, &config.distros[0])
            .expect("eligible")
    );
    config.distros[0].required = false;
    assert!(
        previous
            .reusable(&mut runner, &config, &config.distros[0])
            .expect("policy independent")
    );
    config.distros[0].packages.push("new-package".into());
    assert!(
        !previous
            .reusable(&mut runner, &config, &config.distros[0])
            .expect("changed target")
    );
    config.distros[0].packages.pop();
    config.memory = "8GiB".into();
    assert!(
        !previous
            .reusable(&mut runner, &config, &config.distros[0])
            .expect("changed resources")
    );
    assert_eq!(
        read_text(&temp.path().join("run-1-1/results.json")).expect("source unchanged"),
        original_bytes
    );
}

#[test]
fn resume_restores_exact_candidate_and_baseline_and_rejects_identity_changes() {
    let temp = TestDir::new();
    source(temp.path());
    let mut runner = runner_at(&temp.path().join("run-2-2"));
    write_inputs(&runner);
    let previous = Resume::load(&mut runner, "run-1-1").expect("source");
    let archive = previous.restore_candidate(&mut runner).expect("restore");
    assert_eq!(read_text(&archive).expect("candidate"), "candidate bytes");
    previous
        .verify_inputs(&mut runner, "v1.2.3", &archive)
        .expect("identity");
    previous.restore_baseline(&mut runner).expect("baseline");
    assert_eq!(
        read_text(&runner.evidence().join("baseline-tag")).expect("baseline"),
        "v1.2.2"
    );
    assert_eq!(runner.report.document["resume_from"]["run_id"], "run-1-1");
    assert!(
        previous
            .verify_inputs(&mut runner, "v1.2.4", &archive)
            .expect_err("tag changed")
            .to_string()
            .contains("tag or archive")
    );
    fs::write(&archive, "different candidate").expect("change candidate");
    assert!(
        previous
            .verify_inputs(&mut runner, "v1.2.3", &archive)
            .expect_err("archive changed")
            .to_string()
            .contains("SHA-256")
    );
}

#[test]
fn resume_rejects_changed_scripts_checksums_and_damaged_archives() {
    let temp = TestDir::new();
    source(temp.path());
    let mut runner = runner_at(&temp.path().join("run-2-2"));
    write_inputs(&runner);
    let previous = Resume::load(&mut runner, "run-1-1").expect("source");
    let archive = runner
        .evidence()
        .join("inputs/release/kidobo-v1.2.3-linux-x86_64.tar.gz");
    fs::write(
        runner.evidence().join("inputs/release/SHA256SUMS"),
        "changed",
    )
    .expect("checksum");
    assert!(
        previous
            .verify_inputs(&mut runner, "v1.2.3", &archive)
            .expect_err("manifest changed")
            .to_string()
            .contains("checksum manifest")
    );
    fs::write(
        runner.evidence().join("inputs/SHA256.json"),
        r#"{"installer.sh":"changed"}"#,
    )
    .expect("script hash");
    assert!(
        previous
            .verify_inputs(&mut runner, "v1.2.3", &archive)
            .expect_err("script changed")
            .to_string()
            .contains("installer.sh")
    );
    fs::write(temp.path().join("run-1-1/evidence.tar.gz"), "damaged").expect("damage");
    assert!(
        Resume::load(&mut runner, "run-1-1")
            .err()
            .expect("archive changed")
            .to_string()
            .contains("SHA-256 mismatch")
    );
    assert!(
        Resume::load(&mut runner, "../run-1-1")
            .err()
            .expect("path traversal")
            .to_string()
            .contains("invalid resume run")
    );
}

#[test]
fn unfinished_failed_or_incompletely_collected_targets_are_never_reused() {
    let good = successful_document();
    assert!(completed_target(&good, "debian-12"));
    for (field, value) in [
        ("error", json!("application failure")),
        ("cleanup_error", json!("cleanup failed")),
        ("diagnostic_errors", json!(["missing diagnostics"])),
        ("phase", json!("provisioning")),
    ] {
        let mut document = good.clone();
        document["results"][0][field] = value;
        assert!(!completed_target(&document, "debian-12"), "{field}");
    }
    for status in [
        "not-run",
        "running",
        "failed",
        "incomplete",
        "interrupted",
        "retained",
    ] {
        let mut document = good.clone();
        document["stages"][5]["status"] = json!(status);
        assert!(!completed_target(&document, "debian-12"), "stage {status}");
        let mut document = good.clone();
        document["checks"][5]["status"] = json!(status);
        assert!(!completed_target(&document, "debian-12"), "check {status}");
    }
    let mut document = good.clone();
    document["checks"]
        .as_array_mut()
        .expect("checks")
        .retain(|c| c["context"] != "debian-12 | installation and application checks");
    assert!(!completed_target(&document, "debian-12"));
    let mut document = good.clone();
    document["checks"] = json!([]);
    assert!(!completed_target(&document, "debian-12"));
    let mut document = good.clone();
    document["results"]
        .as_array_mut()
        .expect("results")
        .push(good["results"][0].clone());
    assert!(!completed_target(&document, "debian-12"));
}

#[test]
fn chained_reuse_verifies_original_evidence_instead_of_trusting_reuse_labels() {
    let temp = TestDir::new();
    source(temp.path());
    let mut second = runner_at(&temp.path().join("run-2-2"));
    write_inputs(&second);
    let original = Resume::load(&mut second, "run-1-1").expect("source");
    second.report.document = successful_document();
    second.report.document["run_id"] = json!("run-2-2");
    second.report.document["archive_sha256"] = original.document["archive_sha256"].clone();
    second.report.document["results"] =
        json!([original.result("debian-12", true).expect("reuse result")]);
    second.report.document["checks"] = json!([]);
    for stage in second.report.document["stages"]
        .as_array_mut()
        .expect("stages")
    {
        stage["status"] = json!("reused");
    }
    original.restore_baseline(&mut second).expect("baseline");
    archive_evidence(&mut second).expect("second archive");
    second
        .report
        .finish_stage("passed")
        .expect("finish archive");
    second.report.save().expect("save second");
    let mut third = runner_at(&temp.path().join("run-3-3"));
    write_inputs(&third);
    let previous = Resume::load(&mut third, "run-2-2").expect("second source");
    let config: Config = toml_edit::de::from_str(CONFIG).expect("config");
    assert!(
        previous
            .reusable(&mut third, &config, &config.distros[0])
            .expect("verified chain")
    );
    assert_eq!(
        previous.result("debian-12", true).expect("linked result")["reused_from"]["run_id"],
        "run-1-1"
    );
    fs::write(
        temp.path().join("run-1-1/evidence.tar.gz"),
        "damaged original",
    )
    .expect("damage");
    assert!(
        previous
            .reusable(&mut third, &config, &config.distros[0])
            .expect_err("original damaged")
            .to_string()
            .contains("SHA-256 mismatch")
    );
}

#[test]
fn resume_cli_rejects_published_or_filtered_reuse() {
    Cli::try_parse_from(["e2e", "run", "--resume", "run-1-1"]).expect("resume arguments");
    for option in [vec!["--published"], vec!["--distro", "debian-12"]] {
        let mut args = vec!["e2e", "run", "--resume", "run-1-1"];
        args.extend(option);
        assert!(Cli::try_parse_from(args).is_err());
    }
}

#[test]
fn verified_success_skips_vm_creation_and_links_the_original_evidence() {
    let temp = TestDir::new();
    source(temp.path());
    let mut runner = runner_at(&temp.path().join("run-2-2"));
    write_inputs(&runner);
    runner.report.document["stages"] = successful_document()["stages"].clone();
    let previous = Resume::load(&mut runner, "run-1-1").expect("source");
    let archive = runner
        .evidence()
        .join("inputs/release/kidobo-v1.2.3-linux-x86_64.tar.gz");
    previous
        .verify_inputs(&mut runner, "v1.2.3", &archive)
        .expect("matching inputs");
    previous.restore_baseline(&mut runner).expect("baseline");
    let config: Config = toml_edit::de::from_str(CONFIG).expect("config");
    crate::matrix::execute(
        &mut runner,
        &config,
        "run-2-2",
        &[&config.distros[0]],
        "v1.2.3",
        false,
        Some(&archive),
        false,
        Some(&previous),
    )
    .expect("reuse without invoking nonexistent Incus");
    assert_eq!(
        runner.report.document["results"][0]["reused_from"]["run_id"],
        "run-1-1"
    );
    let ownership: Owned =
        serde_json::from_str(&read_text(&runner.dir.join("ownership.json")).expect("ownership"))
            .expect("json");
    assert_eq!(ownership.instances, Vec::<String>::new());
    assert!(
        runner.report.document["stages"]
            .as_array()
            .expect("stages")
            .iter()
            .all(|s| s["status"] == "reused")
    );
    assert!(
        runner.report.document["commands"]
            .as_array()
            .expect("commands")
            .iter()
            .all(|c| c["program"] != "/unused-incus")
    );
}

#[test]
fn required_selection_includes_current_requirements_and_omits_advisory_targets() {
    let mut config: Config = toml_edit::de::from_str(CONFIG).expect("config");
    config.distros.extend([
        Distro {
            id: "new-required".into(),
            image: "new/image".into(),
            family: "apt".into(),
            packages: vec![],
            required: true,
        },
        Distro {
            id: "advisory".into(),
            image: "other/image".into(),
            family: "dnf".into(),
            packages: vec![],
            required: false,
        },
    ]);
    let ids = |only_required| {
        crate::selected_targets(&config, None, only_required)
            .iter()
            .map(|d| d.id.as_str())
            .collect::<Vec<_>>()
    };
    assert_eq!(ids(true), ["debian-12", "new-required"]);
    assert_eq!(ids(false), ["debian-12", "new-required", "advisory"]);
    Cli::try_parse_from(["e2e", "run", "--resume", "run-1-1", "--required-only"])
        .expect("required resume");
    assert!(
        Cli::try_parse_from(["e2e", "run", "--required-only", "--distro", "advisory"]).is_err()
    );
}
