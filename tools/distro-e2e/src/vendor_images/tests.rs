use super::*;
use crate::Report;
use crate::tests::{TestDir, executable};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

fn pin() -> Pin {
    Pin {
        url: "https://repo.almalinux.org/almalinux/10/cloud/x86_64/images/AlmaLinux-10-GenericCloud-10.2-20261012.0.x86_64.qcow2".into(),
        sha256: "a".repeat(64),
        architecture: "x86_64".into(),
        published_at: 1_791_780_872,
        signing_fingerprint: "EE6DB7B98F5BF5EDD9DA0DE5DEE5C11CC2A1E572".into(),
        incus_fingerprint: "b".repeat(64),
        signed_checksum: "fixture signed checksum".into(),
        checksum_signature: Some("fixture detached signature".into()),
    }
}

fn config() -> Config {
    Config {
        project: "test-project".into(),
        profile: "test-profile".into(),
        network: "test-network".into(),
        pool: "test-pool".into(),
        cpus: 2,
        memory: "4GiB".into(),
        disk: "30GiB".into(),
        max_parallel_vms: 2,
        distros: vec![Distro {
            id: "almalinux-10".into(),
            image: String::new(),
            vendor_image: Some("almalinux-10".into()),
            family: "dnf-epel".into(),
            packages: vec!["ipset".into()],
            required: false,
            selinux: "enforcing".into(),
        }],
    }
}

fn write_manifest(path: &Path, pin: Pin) {
    let manifest = Manifest {
        version: 1,
        images: BTreeMap::from([("almalinux-10".into(), pin)]),
    };
    fs::write(path, toml_edit::ser::to_string_pretty(&manifest).unwrap()).unwrap();
}

fn runner(root: &Path) -> Runner {
    let dir = root.join("run");
    let report = Report::open(&dir).unwrap();
    fs::create_dir_all(dir.join(".evidence/inputs")).unwrap();
    Runner {
        project: "test-project".into(),
        dir,
        incus_program: root.join("fake-incus"),
        cancelled: Arc::new(AtomicBool::new(false)),
        report,
        command_poll_interval: Duration::from_millis(1),
        ignore_cancellation: false,
    }
}

#[test]
fn target_source_is_exclusive_and_cannot_change_security_or_target_identity() {
    let mut config = config();
    validate_sources(&config).unwrap();
    config.distros[0].image = "almalinux/10".into();
    assert!(
        validate_sources(&config)
            .unwrap_err()
            .to_string()
            .contains("exactly one")
    );
    config.distros[0].vendor_image = None;
    validate_sources(&config).unwrap();
    config.distros[0].image.clear();
    assert!(
        validate_sources(&config)
            .unwrap_err()
            .to_string()
            .contains("exactly one")
    );
    config.distros[0].vendor_image = Some("almalinux-9".into());
    assert!(
        validate_sources(&config)
            .unwrap_err()
            .to_string()
            .contains("match its target")
    );
    config.distros[0].vendor_image = Some("almalinux-10".into());
    config.distros[0].selinux = "image-default".into();
    assert!(
        validate_sources(&config)
            .unwrap_err()
            .to_string()
            .contains("enforcing")
    );
}

#[test]
fn manifest_rejects_unreviewed_identity_floating_urls_and_incompatible_artifacts() {
    let temporary = TestDir::new();
    let path = temporary.path().join("pins.toml");
    write_manifest(&path, pin());
    Manifest::load(&path).unwrap();
    let invalid = [
        Pin {
            url: pin().url.replace("20261012.0", "latest"),
            ..pin()
        },
        Pin {
            url: pin().url.replace("repo.almalinux.org", "untrusted.example"),
            ..pin()
        },
        Pin {
            url: pin().url.replace("images/", "images/../"),
            ..pin()
        },
        Pin {
            architecture: "aarch64".into(),
            ..pin()
        },
        Pin {
            signing_fingerprint: "F".repeat(40),
            ..pin()
        },
        Pin {
            sha256: "not-a-digest".into(),
            ..pin()
        },
        Pin {
            incus_fingerprint: "A".repeat(64),
            ..pin()
        },
        Pin {
            published_at: 0,
            ..pin()
        },
    ];
    for candidate in invalid {
        write_manifest(&path, candidate);
        assert_ne!(
            Manifest::load(&path).map(|_| ()).unwrap_err().to_string(),
            ""
        );
    }
}

#[test]
fn checksum_requires_one_exact_filename_and_digest_in_either_vendor_format() {
    let digest = "a".repeat(64);
    for entry in [
        format!("SHA256 (disk.qcow2) = {digest}\n"),
        format!("{digest} *disk.qcow2\n"),
    ] {
        verify_checksum_entry(&entry, "disk.qcow2", &digest).unwrap();
        for invalid in [
            entry.repeat(2),
            entry.replace("disk.qcow2", "other.qcow2"),
            entry.replace(&digest, &"b".repeat(64)),
            format!("{entry}SHA256 (disk.qcow2) = {}\n", "c".repeat(64)),
        ] {
            assert!(
                verify_checksum_entry(&invalid, "disk.qcow2", &digest)
                    .unwrap_err()
                    .to_string()
                    .contains("exactly one")
            );
        }
    }
}

#[test]
fn release_age_rejects_unknown_future_and_even_one_second_inside_cooldown() {
    let published = 1_791_780_872;
    eligible(published, published + MINIMUM_AGE).unwrap();
    eligible(published, published + MINIMUM_AGE + 1).unwrap();
    for (publication, now) in [
        (0, published),
        (published + 1, published),
        (published, published + MINIMUM_AGE - 1),
    ] {
        assert!(
            eligible(publication, now)
                .unwrap_err()
                .to_string()
                .contains("seven full days")
        );
    }
}

#[test]
fn disk_hash_mismatch_fails_before_any_external_processing() {
    let temporary = TestDir::new();
    let disk = temporary.path().join("corrupt.qcow2");
    fs::write(&disk, "corrupt upstream disk").unwrap();
    let mut runner = runner(temporary.path());
    let failure = check_disk(&mut runner, &disk, &pin().sha256).unwrap_err();
    assert!(failure.to_string().contains("SHA-256 mismatch"));
    assert_eq!(runner.report.document["commands"], json!([]));
}

#[test]
fn disk_description_rejects_external_files_even_with_valid_qcow2_format() {
    check_disk_info(&json!({"format":"qcow2"})).unwrap();
    for info in [
        json!({"format":"raw"}),
        json!({"format":"qcow2", "backing-filename":"base.qcow2"}),
        json!({"format":"qcow2", "data-file":"external.raw"}),
        json!({"format":"qcow2", "format-specific":{"data":{"data-file":"external.raw"}}}),
    ] {
        assert!(
            check_disk_info(&info)
                .unwrap_err()
                .to_string()
                .contains("standalone qcow2")
        );
    }
}

#[test]
fn metadata_package_is_reproducible_and_split_fingerprint_preserves_file_order() {
    let temporary = TestDir::new();
    let first = temporary.path().join("first");
    let second = temporary.path().join("second");
    fs::create_dir(&first).unwrap();
    fs::create_dir(&second).unwrap();
    let mut runner = runner(temporary.path());
    let one = package(&mut runner, "almalinux-10", &pin(), &first).unwrap();
    let two = package(&mut runner, "almalinux-10", &pin(), &second).unwrap();
    assert_eq!(hash(&one).unwrap(), hash(&two).unwrap());
    let metadata = temporary.path().join("metadata");
    let disk = temporary.path().join("disk");
    fs::write(&metadata, b"abc").unwrap();
    fs::write(&disk, b"def").unwrap();
    assert_eq!(
        split_fingerprint(&metadata, &disk).unwrap(),
        "bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721"
    );
    assert_ne!(
        split_fingerprint(&metadata, &disk).unwrap(),
        split_fingerprint(&disk, &metadata).unwrap()
    );
}

fn fake_images(root: &Path, images: &Value, scenario: &str) {
    fs::write(
        root.join("state.json"),
        serde_json::to_vec(&json!({"images":images,"scenario":scenario,"commands":[]})).unwrap(),
    )
    .unwrap();
    executable(
        &root.join("fake-incus"),
        r"#!/usr/bin/env python3
import json
import sys
from pathlib import Path

root = Path(__file__).parent
path = root / 'state.json'
state = json.loads(path.read_text())
assert sys.argv[1:3] == ['--project', 'test-project'], sys.argv
args = sys.argv[3:]
state['commands'].append(args)
status = 0
if args == ['image', 'list', '--format=json']:
    print(json.dumps(state['images']))
elif args[:2] == ['image', 'import']:
    marker = 'foreign-owner' if state['scenario'] == 'foreign' else 'kidobo-e2e-v1'
    fingerprint = ('d' if state['scenario'] == 'mismatch' else 'b') * 64
    token = args[-1].split('=', 1)[1]
    state['images'].append({'fingerprint':fingerprint, 'type':'virtual-machine',
        'architecture':'x86_64', 'properties':{'user.kidobo-e2e-source':marker, 'user.kidobo-e2e-import':token}})
    if state['scenario'] not in ('success', 'mismatch'):
        print('injected import failure', file=sys.stderr)
        status = 1
elif args[:2] == ['image', 'delete']:
    state['images'] = [image for image in state['images'] if image['fingerprint'] != args[2]]
else:
    raise AssertionError(args)
path.write_text(json.dumps(state))
raise SystemExit(status)
",
    );
}

fn state(root: &Path) -> Value {
    serde_json::from_str(&read_text(&root.join("state.json")).unwrap()).unwrap()
}

#[test]
fn cached_fingerprint_skips_import_and_preserves_preexisting_storage() {
    let temporary = TestDir::new();
    let image = json!({"fingerprint":pin().incus_fingerprint,"type":"virtual-machine","architecture":"x86_64"});
    fake_images(temporary.path(), &json!([image]), "failure");
    let mut runner = runner(temporary.path());
    import(
        &mut runner,
        Path::new("nonexistent metadata"),
        Path::new("nonexistent disk"),
        &pin().incus_fingerprint,
    )
    .unwrap();
    let saved = state(temporary.path());
    assert_eq!(saved["images"], json!([image]));
    assert_eq!(
        saved["commands"],
        json!([["image", "list", "--format=json"]])
    );
}

#[test]
fn cached_fingerprint_with_wrong_architecture_cannot_be_used() {
    let temporary = TestDir::new();
    fake_images(
        temporary.path(),
        &json!([{"fingerprint":pin().incus_fingerprint,"type":"virtual-machine","architecture":"aarch64"}]),
        "success",
    );
    let mut runner = runner(temporary.path());
    assert!(
        local_image(&mut runner, &pin().incus_fingerprint)
            .unwrap_err()
            .to_string()
            .contains("incompatible")
    );
    assert_eq!(
        state(temporary.path())["commands"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn failed_import_cleans_only_new_owned_fingerprint_and_restores_cancellation_mode() {
    let temporary = TestDir::new();
    let existing =
        json!({"fingerprint":"c".repeat(64), "properties":{"user.kidobo-e2e-source":OWNER}});
    for scenario in ["failure", "foreign"] {
        fake_images(temporary.path(), &json!([existing]), scenario);
        let run_root = temporary.path().join(scenario);
        fs::create_dir(&run_root).unwrap();
        let mut runner = runner(&run_root);
        runner.incus_program = temporary.path().join("fake-incus");
        let failure = import(
            &mut runner,
            Path::new("metadata.tar"),
            Path::new("disk.qcow2"),
            &pin().incus_fingerprint,
        )
        .unwrap_err();
        assert!(failure.to_string().contains("exit"));
        assert!(
            read_text(&runner.dir.join("transcript.log"))
                .unwrap()
                .contains("injected import failure")
        );
        assert!(!runner.ignore_cancellation);
        let saved = state(temporary.path());
        assert_eq!(saved["images"][0], existing);
        assert_eq!(
            saved["images"].as_array().unwrap().len(),
            if scenario == "foreign" { 2 } else { 1 }
        );
    }
}

#[test]
fn successful_import_is_reused_without_new_import_or_cleanup() {
    let temporary = TestDir::new();
    fake_images(temporary.path(), &json!([]), "success");
    let mut runner = runner(temporary.path());
    for _ in 0..2 {
        import(
            &mut runner,
            Path::new("metadata.tar"),
            Path::new("disk.qcow2"),
            &pin().incus_fingerprint,
        )
        .unwrap();
    }
    let saved = state(temporary.path());
    let commands = saved["commands"].as_array().unwrap();
    assert_eq!(
        commands.iter().filter(|args| args[1] == "import").count(),
        1
    );
    assert_eq!(
        commands.iter().filter(|args| args[1] == "delete").count(),
        0
    );
    assert_eq!(saved["images"].as_array().unwrap().len(), 1);
}

#[test]
fn unexpected_import_fingerprint_is_cleaned_without_sweeping_existing_images() {
    let temporary = TestDir::new();
    let existing =
        json!({"fingerprint":"c".repeat(64), "properties":{"user.kidobo-e2e-source":OWNER}});
    fake_images(temporary.path(), &json!([existing]), "mismatch");
    let mut runner = runner(temporary.path());
    let error = import(
        &mut runner,
        Path::new("metadata.tar"),
        Path::new("disk.qcow2"),
        &pin().incus_fingerprint,
    )
    .unwrap_err();
    assert!(error.to_string().contains("expected fingerprint"));
    let saved = state(temporary.path());
    assert_eq!(saved["images"], json!([existing]));
    assert!(saved["commands"].as_array().unwrap().contains(&json!([
        "image",
        "delete",
        "d".repeat(64)
    ])));
}

#[test]
fn unfinished_refresh_drops_proposal_without_changing_pins() {
    let temporary = TestDir::new();
    let path = temporary.path().join("pins.toml");
    write_manifest(&path, pin());
    let original = read_text(&path).unwrap().into_bytes();
    let mut manifest = Manifest::load(&path).unwrap();
    manifest.images.get_mut("almalinux-10").unwrap().sha256 = "f".repeat(64);
    let pending = Refresh {
        destination: path.clone(),
        original: original.clone(),
        manifest,
        _lock: File::create(temporary.path().join("lock")).unwrap(),
    };
    // Any report/archive error returns before the caller reaches the commit.
    drop(pending);
    assert_eq!(read_text(&path).unwrap().into_bytes(), original);
}

#[test]
fn refresh_commit_rejects_invalid_pins_and_concurrent_edits_without_replacing_manifest() {
    let temporary = TestDir::new();
    let path = temporary.path().join("pins.toml");
    write_manifest(&path, pin());
    let original = read_text(&path).unwrap().into_bytes();
    let mut manifest = Manifest::load(&path).unwrap();
    manifest.images.get_mut("almalinux-10").unwrap().sha256 = "invalid".into();
    assert_ne!(
        commit_refresh(&path, &original, &manifest)
            .unwrap_err()
            .to_string(),
        ""
    );
    assert_eq!(read_text(&path).unwrap().into_bytes(), original);
    assert_eq!(fs::read_dir(temporary.path()).unwrap().count(), 1);

    let mut manifest = Manifest::load(&path).unwrap();
    manifest
        .images
        .get_mut("almalinux-10")
        .unwrap()
        .published_at += 1;
    let changed = format!(
        "{}\n# concurrent human edit\n",
        String::from_utf8(original.clone()).unwrap()
    );
    fs::write(&path, &changed).unwrap();
    assert!(
        commit_refresh(&path, &original, &manifest)
            .unwrap_err()
            .to_string()
            .contains("changed")
    );
    assert_eq!(read_text(&path).unwrap(), changed);
    assert_eq!(fs::read_dir(temporary.path()).unwrap().count(), 1);
}

#[test]
fn refresh_commit_replaces_all_verified_proposals_together() {
    let temporary = TestDir::new();
    let path = temporary.path().join("pins.toml");
    let production = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/e2e-images.toml");
    fs::copy(&production, &path).unwrap();
    let original = read_text(&path).unwrap().into_bytes();
    let mut manifest = Manifest::load(&path).unwrap();
    assert_eq!(manifest.images.len(), 3);
    for pin in manifest.images.values_mut() {
        pin.published_at += 1;
    }
    commit_refresh(&path, &original, &manifest).unwrap();
    let saved = Manifest::load(&path).unwrap();
    for (id, pin) in &manifest.images {
        assert_eq!(saved.images[id].published_at, pin.published_at);
    }
    assert_eq!(fs::read_dir(temporary.path()).unwrap().count(), 1);
}

#[test]
fn vendor_signature_verification_rejects_tampering_and_an_unreviewed_identity() {
    let temporary = TestDir::new();
    let production = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/e2e-images.toml");
    let manifest = Manifest::load(&production).unwrap();
    let mut runner = runner(temporary.path());
    snapshot(
        &runner.evidence().join("inputs"),
        &production.with_file_name("e2e.toml"),
    )
    .unwrap();
    let pin = &manifest.images["almalinux-10"];
    let dir = temporary.path().join("valid");
    fs::create_dir(&dir).unwrap();
    let signed_at = verify_signature(&mut runner, "almalinux-10", pin, &dir).unwrap();
    assert!(signed_at > 0);
    assert!(signed_at <= pin.published_at);
    assert!(!dir.join("gnupg").exists());
    let evidence: Value =
        serde_json::from_str(&read_text(&dir.join("verification.json")).unwrap()).unwrap();
    assert_eq!(evidence["signature_verified"], true);

    let mut changed = pin.clone();
    changed.signed_checksum = changed
        .signed_checksum
        .replace(&pin.sha256, &"f".repeat(64));
    let dir = temporary.path().join("tampered");
    fs::create_dir(&dir).unwrap();
    assert!(
        verify_signature(&mut runner, "almalinux-10", &changed, &dir)
            .unwrap_err()
            .to_string()
            .contains("exit")
    );
    assert!(!dir.join("verification.json").exists());

    let mut changed = pin.clone();
    changed.signing_fingerprint = "F".repeat(40);
    let dir = temporary.path().join("unreviewed");
    fs::create_dir(&dir).unwrap();
    assert!(
        verify_signature(&mut runner, "almalinux-10", &changed, &dir)
            .unwrap_err()
            .to_string()
            .contains("unreviewed signing identity")
    );
    assert!(!dir.join("verification.json").exists());
}

#[test]
fn valid_fedora_signature_cannot_authenticate_an_unsigned_artifact_digest() {
    let temporary = TestDir::new();
    let production = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/e2e-images.toml");
    let manifest = Manifest::load(&production).unwrap();
    let mut runner = runner(temporary.path());
    snapshot(
        &runner.evidence().join("inputs"),
        &production.with_file_name("e2e.toml"),
    )
    .unwrap();
    let pin = &manifest.images["fedora-44"];
    let valid = temporary.path().join("valid-fedora");
    fs::create_dir(&valid).unwrap();
    let signed_at = verify_signature(&mut runner, "fedora-44", pin, &valid).unwrap();
    assert!(signed_at > 0);
    assert!(signed_at <= pin.published_at);
    assert!(valid.join("verification.json").exists());

    let filename = "Fedora-Cloud-Base-Generic-44-99.1.x86_64.qcow2";
    let mut changed = pin.clone();
    changed.url = format!("{}{filename}", trust("fedora-44").unwrap().prefix);
    changed.sha256 = "f".repeat(64);
    write!(
        &mut changed.signed_checksum,
        "\nSHA256 ({filename}) = {}\n",
        changed.sha256
    )
    .unwrap();
    let unsigned = temporary.path().join("unsigned-tail");
    fs::create_dir(&unsigned).unwrap();
    let failure = verify_signature(&mut runner, "fedora-44", &changed, &unsigned).unwrap_err();
    assert!(
        failure
            .to_string()
            .contains("exactly one matching artifact digest")
    );
    assert!(!unsigned.join("verification.json").exists());
}
