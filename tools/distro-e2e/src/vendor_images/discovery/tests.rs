use super::*;
use crate::tests::{TestDir, executable, runner_with_incus};

fn config() -> Config {
    toml_edit::de::from_str(include_str!("../../../../../config/e2e.toml")).expect("matrix config")
}

fn pin(id: &str, name: &str) -> DiscoveryPin {
    DiscoveryPin {
        id: id.into(),
        url: format!("https://example.invalid/{name}"),
        sha256: "a".repeat(64),
    }
}

#[test]
fn stable_catalogues_exclude_prereleases_and_compare_numbers() {
    let fedora = r#"[
      {"version":"99 Beta", "arch":"x86_64", "variant":"Cloud"},
      {"version":"100", "arch":"aarch64", "variant":"Cloud"},
      {"version":"45", "arch":"x86_64", "variant":"Cloud"},
      {"version":"9", "arch":"x86_64", "variant":"Cloud"}
    ]"#;
    assert_eq!(fedora_release(fedora).expect("Fedora release"), [45]);
    let alma = r#"<a href="9/">9</a><a href="10/">10</a><a href="11-beta/">beta</a><a href="11.0-beta/">beta</a>"#;
    assert_eq!(alma_release(alma).expect("Alma release"), [10]);
    assert_eq!(
        debian_release("Origin: Debian\nSuite: stable\nVersion: 14.1\nCodename: forky\n")
            .expect("Debian release"),
        [14]
    );
    let ubuntu = "Dist: next\nSupported: 1\nVersion: 28.04.1 LTS\n\nDist: interim\nSupported: 1\nVersion: 28.10\n\nDist: beta\nSupported: 1\nVersion: 30.04 Beta LTS\n\nDist: old\nSupported: 0\nVersion: 12.04 LTS\n";
    assert_eq!(ubuntu_release(ubuntu).expect("Ubuntu release"), [28, 4]);
}

#[test]
fn unknown_catalogue_shapes_cannot_report_current() {
    for result in [
        fedora_release("[]"),
        fedora_release("{}"),
        alma_release("<h1>maintenance</h1>"),
        debian_release("Origin: Debian\nSuite: testing\nVersion: 14\nCodename: forky"),
        ubuntu_release("Dist: next\nVersion: 28.04 LTS"),
    ] {
        assert!(
            result.err().is_some(),
            "unknown catalogue must fail parsing"
        );
    }
    assert!(
        debian_release("Origin: Debian\nSuite: stable\nVersion: 14\nVersion: 13\nCodename: forky")
            .err()
            .is_some()
    );
}

#[test]
fn fedora_checksums_use_numeric_build_order_and_generic_architecture() {
    let listing = r#"<a href="Fedora-Cloud-44-1.9-x86_64-CHECKSUM">old</a>
      <a href="Fedora-Cloud-44-1.10-x86_64-CHECKSUM">new</a>
      <a href="Fedora-Cloud-44-2.0-aarch64-CHECKSUM">wrong arch</a>
      <a href="Fedora-Cloud-45_Beta-3.0-x86_64-CHECKSUM">beta</a>"#;
    assert_eq!(
        fedora_checksum_name(listing, "44").expect("checksum name"),
        "Fedora-Cloud-44-1.10-x86_64-CHECKSUM"
    );
    let current = pin("fedora-44", "Fedora-Cloud-Base-Generic-44-1.9.x86_64.qcow2");
    let checksum = format!(
        "SHA256 (Fedora-Cloud-Base-Generic-44-1.10.x86_64.qcow2) = {}\nSHA256 (Fedora-Cloud-Base-UEFI-UKI-44-8.0.x86_64.qcow2) = {}",
        "b".repeat(64),
        "c".repeat(64)
    );
    let candidate = latest_candidate(
        &current,
        "https://vendor/",
        "https://vendor/CHECKSUM",
        None,
        &checksum,
    )
    .expect("candidate");
    assert!(candidate.url.ends_with("Generic-44-1.10.x86_64.qcow2"));
    assert_eq!(candidate.sha256, "b".repeat(64));
}

#[test]
fn alma_candidates_are_versioned_default_disks_not_floating_or_alternate_images() {
    let current = pin(
        "almalinux-10",
        "AlmaLinux-10-GenericCloud-10.2-20261012.0.x86_64.qcow2",
    );
    let entries = [
        "AlmaLinux-10-GenericCloud-10.2-20261012.0.x86_64.qcow2",
        "AlmaLinux-10-GenericCloud-10.3-20261101.0.x86_64.qcow2",
        "AlmaLinux-10-GenericCloud-ext4-10.4-20261201.0.x86_64.qcow2",
        "AlmaLinux-10-GenericCloud-latest.x86_64.qcow2",
        "AlmaLinux-10-GenericCloud-10.4-beta-20261201.0.x86_64.qcow2",
        "AlmaLinux-10-GenericCloud-10.4-20261201.0.aarch64.qcow2",
        "AlmaLinux-10-GenericCloud-11.0-20270101.0.x86_64.qcow2",
    ]
    .map(|name| format!("{}  {name}", "a".repeat(64)))
    .join("\n");
    let candidate = latest_candidate(
        &current,
        "https://vendor/",
        "https://vendor/CHECKSUM",
        Some("https://vendor/CHECKSUM.asc".into()),
        &entries,
    )
    .expect("candidate");
    assert!(candidate.url.ends_with("10.3-20261101.0.x86_64.qcow2"));
    let older = format!(
        "{}  AlmaLinux-10-GenericCloud-10.1-20260101.0.x86_64.qcow2",
        "a".repeat(64)
    );
    assert!(
        latest_candidate(
            &current,
            "https://vendor/",
            "https://vendor/CHECKSUM",
            None,
            &older
        )
        .expect_err("downgrade error")
        .to_string()
        .contains("downgrade")
    );
}

#[test]
fn checksum_parser_rejects_duplicate_hashes_and_path_traversal() {
    for text in [
        format!(
            "{}  image.qcow2\n{}  image.qcow2",
            "a".repeat(64),
            "b".repeat(64)
        ),
        format!("{}  ../image.qcow2", "a".repeat(64)),
        "SHA256 (image.qcow2) = invalid".into(),
        "<h1>not found</h1>".into(),
    ] {
        assert!(checksum_entries(&text).err().is_some());
    }
}

#[test]
fn discovery_budget_and_cancellation_do_not_start_network_commands() {
    let temp = TestDir::new();
    let mut runner = runner_with_incus(temp.path(), std::path::Path::new("never-incus"));
    let discovery = discover_using(&mut runner, &[], &config(), "never-curl", Duration::ZERO)
        .expect("advisory expired budget");
    assert_eq!(discovery.warnings.len(), 4);
    assert_eq!(discovery.notices, Vec::<String>::new());
    assert_eq!(runner.report.document["commands"], serde_json::json!([]));
    runner.cancelled.store(true, Ordering::Relaxed);
    assert!(
        discover_using(
            &mut runner,
            &[],
            &config(),
            "never-curl",
            Duration::from_secs(30)
        )
        .err()
        .expect("cancelled")
        .to_string()
        .contains("interrupted")
    );
}

#[test]
fn source_failure_is_advisory_and_other_families_still_run() {
    let temp = TestDir::new();
    let program = temp.path().join("curl-fixture");
    executable(
        &program,
        r#"#!/bin/bash
set -eu
output=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output=$2; shift 2 ;;
    https:*) url=$1; shift ;;
    *) shift ;;
  esac
done
case "$url" in
  *fedoraproject.org*) exit 22 ;;
  *repo.almalinux.org*) printf '<a href="10/">10</a>\n' > "$output" ;;
  *deb.debian.org*) printf 'Origin: Debian\nSuite: stable\nVersion: 14.1\nCodename: forky\n' > "$output" ;;
  *changelogs.ubuntu.com*) printf 'Dist: newer\nSupported: 1\nVersion: 28.04 LTS\n' > "$output" ;;
  *) exit 99 ;;
esac
"#,
    );
    let mut runner = runner_with_incus(temp.path(), std::path::Path::new("never-incus"));
    let discovery = discover_using(
        &mut runner,
        &[],
        &config(),
        program.to_str().expect("UTF-8 fixture"),
        Duration::from_secs(30),
    )
    .expect("advisory discovery");
    assert_eq!(discovery.warnings.len(), 1);
    assert!(discovery.warnings[0].contains("fedora: update status unknown"));
    assert_eq!(discovery.notices.len(), 3);
    assert!(
        discovery
            .notices
            .iter()
            .any(|notice| notice.contains("debian: stable release 14"))
    );
    assert!(
        discovery
            .notices
            .iter()
            .any(|notice| notice.contains("ubuntu: stable release 28.4"))
    );
    assert_eq!(
        runner.report.document["commands"]
            .as_array()
            .expect("commands")
            .len(),
        4
    );
    assert_eq!(runner.report.document["results"], serde_json::json!([]));
}

#[test]
fn mandatory_report_failure_is_not_downgraded_to_discovery_warning() {
    let temp = TestDir::new();
    let mut runner = runner_with_incus(temp.path(), std::path::Path::new("never-incus"));
    fs::create_dir(temp.path().join("results.json")).expect("block authoritative results path");
    let error = discover_using(
        &mut runner,
        &[],
        &config(),
        "never-curl",
        Duration::from_secs(30),
    )
    .err()
    .expect("authoritative report failure");
    assert!(
        error
            .to_string()
            .contains("mandatory E2E report write failed")
    );
    assert!(runner.report.failed());
}
