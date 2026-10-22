use super::*;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Mutex, MutexGuard};

// Parallel fixture writes and process creation intermittently cause ETXTBSY on Linux.
static TEST_FIXTURE_LOCK: Mutex<()> = Mutex::new(());
static NEXT_TEST_DIR: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

struct TestDir {
    path: PathBuf,
    _guard: MutexGuard<'static, ()>,
}

impl TestDir {
    fn new() -> Self {
        let guard = TEST_FIXTURE_LOCK
            .lock()
            .expect("lock test fixture directory");
        let id = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "kidobo-distro-e2e-tests-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create test directory");
        Self {
            path,
            _guard: guard,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).expect("remove test directory");
    }
}

fn executable(path: &Path, body: &str) {
    fs::write(path, body).expect("write test executable");
    let mut permissions = fs::metadata(path)
        .expect("read executable metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("make test executable");
}

fn runner(dir: &Path) -> Runner {
    Runner {
        project: "test-project".into(),
        dir: dir.to_path_buf(),
        incus_program: PathBuf::from("incus"),
        cancelled: Arc::new(AtomicBool::new(false)),
        sequence: 0,
    }
}

fn runner_with_incus(dir: &Path, program: &Path) -> Runner {
    let mut runner = runner(dir);
    runner.incus_program = program.to_path_buf();
    runner
}

fn fake_incus(temp: &TestDir) -> (PathBuf, PathBuf) {
    let program = temp.path().join("fake-incus");
    let log = temp.path().join("incus-args.log");
    executable(
        &program,
        &format!(
            "#!/bin/bash\nset -eu\nprintf '<%s>' \"$@\" >> '{}'\nprintf '\\n' >> '{}'\nif [[ \"${{3:-}}\" == list ]]; then\n  case \"${{4:-}}\" in\n    vm-owned) printf '%s\\n' '[{{\"name\":\"vm-owned\",\"type\":\"virtual-machine\",\"config\":{{\"user.kidobo-e2e\":\"{OWNER}\"}}}}]' ;;\n    vm-container) printf '%s\\n' '[{{\"name\":\"vm-container\",\"type\":\"container\",\"config\":{{\"user.kidobo-e2e\":\"{OWNER}\"}}}}]' ;;\n    vm-unowned) printf '%s\\n' '[{{\"name\":\"vm-unowned\",\"type\":\"virtual-machine\",\"config\":{{\"user.kidobo-e2e\":\"someone-else\"}}}}]' ;;\n    *) printf '[]\\n' ;;\n  esac\nelse\n  printf 'fake-incus-output\\n'\nfi\n",
            log.display(),
            log.display()
        ),
    );
    (program, log)
}

fn fake_setup_incus(temp: &TestDir, profile_owner: &str, mode: &str) -> (PathBuf, PathBuf) {
    let program = temp.path().join("fake-setup-incus");
    let log = temp.path().join("setup-incus-args.log");
    let script = r#"#!/bin/bash
set -eu
printf '<%s>' "$@" >> '__LOG__'
printf '\n' >> '__LOG__'
if [[ "$1" != --project ]]; then exit 90; fi
if [[ "$2" == default ]]; then
  case "${4:-}" in
    show) printf 'description: kidobo-e2e-v1\n'; exit 0 ;;
    get) printf '%s\n' 'kidobo-e2e-v1'; exit 0 ;;
  esac
fi
if [[ "${3:-}" == profile ]]; then
  case "${4:-}" in
    show) printf 'description: kidobo-e2e-v1\n'; exit 0 ;;
    get)
      case "${6:-}" in
        user.kidobo-e2e) printf '%s\n' '__PROFILE_OWNER__' ;;
        limits.cpu) if [[ '__MODE__' == drift ]]; then printf '2\n'; else printf '4\n'; fi ;;
        limits.memory) printf '4GiB\n' ;;
        *) exit 91 ;;
      esac
      exit 0
      ;;
    device)
      case "${5:-}" in
        get)
          device="${7:-}"
          property="${8:-}"
          if [[ "$property" == type ]]; then
            case "__MODE__:$device" in
              missing-root:root|missing-eth0:eth0) exit 1 ;;
              wrong-root:root) printf 'nic\n' ;;
              wrong-eth0:eth0) printf 'disk\n' ;;
              *) if [[ "$device" == root ]]; then printf 'disk\n'; else printf 'nic\n'; fi ;;
            esac
          else
            case "$device:$property" in
              root:path) printf '/\n' ;;
              root:pool) printf 'test-pool\n' ;;
              root:size) if [[ '__MODE__' == drift ]]; then printf '8GiB\n'; else printf '20GiB\n'; fi ;;
              eth0:network) if [[ '__MODE__' == drift ]]; then printf 'other-network\n'; else printf 'test-network\n'; fi ;;
              eth0:name) printf 'eth0\n' ;;
              *) exit 92 ;;
            esac
          fi
          exit 0
          ;;
        add|set) exit 0 ;;
      esac
      ;;
    set|create) exit 0 ;;
  esac
fi
exit 93
"#
    .replace("__LOG__", &log.display().to_string())
    .replace("__PROFILE_OWNER__", profile_owner)
    .replace("__MODE__", mode);
    executable(&program, &script);
    (program, log)
}

fn setup_config() -> Config {
    Config {
        project: "test-project".into(),
        profile: "test-profile".into(),
        network: "test-network".into(),
        pool: "test-pool".into(),
        cpus: 4,
        memory: "4GiB".into(),
        disk: "20GiB".into(),
        distros: vec![],
    }
}

fn setup_calls(log: &Path) -> Vec<String> {
    read_text(log)
        .expect("read setup fake Incus log")
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn setup_rejects_profile_owner_suffix_and_description_only_marker() {
    for owner in [format!("{OWNER}-suffix"), String::new()] {
        let temp = TestDir::new();
        let (program, log) = fake_setup_incus(&temp, &owner, "unchanged");
        let mut runner = runner_with_incus(temp.path(), &program);

        let error =
            setup(&mut runner, &setup_config()).expect_err("spoofed profile must be rejected");

        assert!(
            error
                .to_string()
                .contains("existing profile is not suite-owned")
        );
        let calls = setup_calls(&log);
        assert!(
            calls
                .iter()
                .any(|call| call.contains("<profile><show><test-profile>"))
        );
        assert!(
            calls
                .iter()
                .any(|call| call.contains("<profile><get><test-profile><user.kidobo-e2e>"))
        );
        assert!(!calls.iter().any(|call| call.contains("<device><add>")));
        assert!(!calls.iter().any(|call| call.contains("<device><set>")));
    }
}

#[test]
fn setup_recovers_each_missing_owned_profile_device() {
    for (mode, device, kind) in [
        ("missing-root", "root", "disk"),
        ("missing-eth0", "eth0", "nic"),
    ] {
        let temp = TestDir::new();
        let (program, log) = fake_setup_incus(&temp, OWNER, mode);
        let mut runner = runner_with_incus(temp.path(), &program);

        setup(&mut runner, &setup_config()).expect("partial profile should be repaired");

        let calls = setup_calls(&log);
        let add = if device == "root" {
            "<profile><device><add><test-profile><root><disk><path=/><pool=test-pool><size=20GiB>"
        } else {
            "<profile><device><add><test-profile><eth0><nic><network=test-network><name=eth0>"
        };
        assert!(
            calls.iter().any(|call| call.contains(add)),
            "missing {device} add"
        );
        assert!(calls.iter().any(|call| call.contains(&format!(
            "<profile><device><get><test-profile><{device}><type>"
        ))));
        assert!(!calls.iter().any(|call| {
            call.contains(&format!("<profile><device><set><test-profile><{device}>"))
                || (kind == "disk" && call.contains("<profile><device><add><test-profile><eth0>"))
                || (kind == "nic" && call.contains("<profile><device><add><test-profile><root>"))
        }));
    }
}

#[test]
fn setup_rejects_wrong_type_for_existing_owned_profile_devices() {
    for (mode, device) in [("wrong-root", "root"), ("wrong-eth0", "eth0")] {
        let temp = TestDir::new();
        let (program, log) = fake_setup_incus(&temp, OWNER, mode);
        let mut runner = runner_with_incus(temp.path(), &program);

        let error = setup(&mut runner, &setup_config()).expect_err("wrong device type must fail");

        let error = error.to_string();
        assert!(
            error.contains(&format!("device {device} has type")),
            "wrong-device-type setup failed for an unexpected reason: {error}"
        );
        let calls = setup_calls(&log);
        assert!(!calls.iter().any(|call| {
            call.contains(&format!("<profile><device><add><test-profile><{device}>"))
                || call.contains(&format!("<profile><device><set><test-profile><{device}>"))
        }));
    }
}

#[test]
fn setup_updates_only_drifted_properties_and_leaves_current_profile_unchanged() {
    let temp = TestDir::new();
    let (program, log) = fake_setup_incus(&temp, OWNER, "drift");
    let mut runner = runner_with_incus(temp.path(), &program);

    setup(&mut runner, &setup_config()).expect("owned profile drift should be reconciled");

    let calls = setup_calls(&log);
    assert!(calls.iter().any(|call| {
        call == "<--project><test-project><profile><device><set><test-profile><root><size=20GiB>"
    }));
    assert!(calls.iter().any(|call| {
        call == "<--project><test-project><profile><device><set><test-profile><eth0><network=test-network>"
    }));
    assert!(calls.iter().any(|call| {
        call == "<--project><test-project><profile><set><test-profile><limits.cpu=4>"
    }));
    assert!(!calls.iter().any(|call| call.contains("<device><add>")));
    drop(temp);

    let temp = TestDir::new();
    let (program, log) = fake_setup_incus(&temp, OWNER, "unchanged");
    let mut runner = runner_with_incus(temp.path(), &program);

    setup(&mut runner, &setup_config()).expect("owned current profile should remain unchanged");

    let calls = setup_calls(&log);
    assert!(!calls.iter().any(|call| {
        call.contains("<create>") || call.contains("<add>") || call.contains("<set>")
    }));
}

#[test]
fn freeze_archive_preserves_private_archive_and_checksum_snapshot() {
    let temp = TestDir::new();
    fs::create_dir(temp.path().join("inputs")).expect("create input snapshot directory");
    let source = temp.path().join("candidate.tar.gz");
    let manifest = temp.path().join("SHA256SUMS");
    let archive_bytes = b"candidate archive bytes";
    let manifest_bytes = b"original digest  candidate.tar.gz\n";
    fs::write(&source, archive_bytes).expect("write source archive");
    fs::write(&manifest, manifest_bytes).expect("write source checksum manifest");

    let frozen = freeze_archive(&source, temp.path()).expect("freeze candidate archive");
    let frozen_manifest = temp.path().join("inputs/release/SHA256SUMS");

    fs::write(&source, b"mutated caller archive").expect("mutate caller archive");
    fs::write(&manifest, b"mutated caller manifest").expect("mutate caller manifest");

    assert_eq!(
        read_text(&frozen).expect("read frozen archive").as_bytes(),
        archive_bytes
    );
    assert_eq!(
        read_text(&frozen_manifest)
            .expect("read frozen checksum manifest")
            .as_bytes(),
        manifest_bytes
    );
    assert_ne!(
        hash(&frozen).expect("hash frozen archive"),
        hash(&source).expect("hash mutated caller archive")
    );
    assert_ne!(
        hash(&frozen_manifest).expect("hash frozen manifest"),
        hash(&manifest).expect("hash mutated caller manifest")
    );
}

#[test]
fn identifiers_cannot_escape_resource_namespace() {
    for name in ["../default", "", "other:vm", "/", "a b"] {
        assert!(!safe_name(name));
    }
    assert!(safe_name("run-123-debian-13"));
}

#[test]
fn rejects_version_injection() {
    assert!(tag_valid("v0.14.3"));
    assert!(!tag_valid("v1/../../"));
    assert!(!tag_valid("latest"));
}

#[test]
fn runner_records_nonzero_exit_and_keeps_both_output_streams() {
    let temp = TestDir::new();
    let program = temp.path().join("fail-command");
    executable(
        &program,
        "#!/bin/sh\nprintf 'stdout evidence\\n'\nprintf 'stderr evidence\\n' >&2\nexit 17\n",
    );
    let mut runner = runner(temp.path());

    let error = runner
        .command(program.to_str().expect("program path is UTF-8"), &[], 5)
        .expect_err("nonzero command must fail");

    assert!(error.to_string().contains("exited exit status: 17"));
    let stem = temp.path().join("0001");
    assert_eq!(
        read_text(&stem.with_extension("stdout")).expect("read stdout log"),
        "stdout evidence\n"
    );
    assert_eq!(
        read_text(&stem.with_extension("stderr")).expect("read stderr log"),
        "stderr evidence\n"
    );
    let metadata: serde_json::Value = serde_json::from_str(
        &read_text(&stem.with_extension("json")).expect("read command metadata"),
    )
    .expect("parse command metadata");
    assert_eq!(metadata["code"], 17);
    assert_eq!(
        metadata["program"],
        program.to_str().expect("program path is UTF-8")
    );
}

#[test]
fn runner_records_spawn_failure_metadata() {
    let temp = TestDir::new();
    let program = temp.path().join("missing-command");
    let mut runner = runner(temp.path());

    let error = runner
        .command(program.to_str().expect("program path is UTF-8"), &[], 5)
        .expect_err("missing program must fail");

    assert!(error.to_string().contains("failed to start"));
    let metadata: serde_json::Value = serde_json::from_str(
        &read_text(&temp.path().join("0001.json")).expect("read spawn metadata"),
    )
    .expect("parse spawn metadata");
    assert_eq!(metadata["code"], serde_json::Value::Null);
    assert!(
        metadata["error"]
            .as_str()
            .expect("spawn error is a string")
            .contains("spawn failed")
    );
    assert_eq!(metadata["program"], program.to_str().expect("UTF-8 path"));
}

#[test]
fn runner_timeout_kills_descendants_in_its_process_group() {
    let temp = TestDir::new();
    let program = temp.path().join("spawn-descendant");
    let marker = temp.path().join("descendant-finished");
    let spawned = temp.path().join("descendant-started");
    executable(
        &program,
        &format!(
            "#!/bin/sh\n(sleep 2; printf alive > '{}') &\nprintf started > '{}'\nwait\n",
            marker.display(),
            spawned.display()
        ),
    );
    let mut runner = runner(temp.path());

    let args = vec!["--probe".to_owned()];
    let error = runner
        .command(program.to_str().expect("program path is UTF-8"), &args, 1)
        .expect_err("command must time out");

    assert!(error.to_string().contains("timed out"));
    let metadata: serde_json::Value = serde_json::from_str(
        &read_text(&temp.path().join("0001.json")).expect("read timeout metadata"),
    )
    .expect("parse timeout metadata");
    assert_eq!(metadata["args"], json!(["--probe"]));
    assert_eq!(metadata["code"], serde_json::Value::Null);
    assert_eq!(metadata["error"], "timed out");
    assert!(metadata["seconds"].as_f64().is_some());
    assert!(spawned.exists(), "the test descendant should have started");
    std::thread::sleep(Duration::from_millis(2200));
    assert!(
        !marker.exists(),
        "timed-out descendant must not keep running"
    );
}

#[test]
fn runner_records_interruption_metadata() {
    let temp = TestDir::new();
    let program = temp.path().join("wait");
    executable(&program, "#!/bin/sh\nsleep 30\n");
    let mut runner = runner(temp.path());
    runner.cancelled.store(true, Ordering::Relaxed);

    let error = runner
        .command(program.to_str().expect("program path is UTF-8"), &[], 30)
        .expect_err("cancelled command must fail");

    assert!(error.to_string().contains("interrupted"));
    let metadata: serde_json::Value = serde_json::from_str(
        &read_text(&temp.path().join("0001.json")).expect("read interruption metadata"),
    )
    .expect("parse interruption metadata");
    assert_eq!(metadata["code"], serde_json::Value::Null);
    assert_eq!(metadata["error"], "interrupted");
    assert!(metadata["seconds"].as_f64().is_some());
}

#[test]
fn runner_reports_stdout_larger_than_capture_limit() {
    let temp = TestDir::new();
    let program = temp.path().join("large-output");
    executable(
        &program,
        "#!/bin/sh\ndd if=/dev/zero bs=16777217 count=1 status=none\n",
    );
    let mut runner = runner(temp.path());

    let error = runner
        .command(program.to_str().expect("program path is UTF-8"), &[], 5)
        .expect_err("oversized output must not be silently truncated");

    assert!(
        error
            .to_string()
            .contains("stdout exceeds the 16777216-byte capture limit")
    );
    assert_eq!(
        fs::metadata(temp.path().join("0001.stdout"))
            .expect("inspect full stdout log")
            .len(),
        16 * 1024 * 1024 + 1
    );
}

#[test]
fn vm_validation_accepts_only_suite_owned_virtual_machines() {
    let owned_vm = json!({
        "type": "virtual-machine",
        "config": {"user.kidobo-e2e": OWNER}
    });
    validate_vm_config(&owned_vm).expect("owned VM accepted");

    for unowned in [
        json!({"type": "container", "config": {"user.kidobo-e2e": OWNER}}),
        json!({"type": "virtual-machine", "config": {"user.kidobo-e2e": "someone-else"}}),
        json!({"type": "virtual-machine", "config": {}}),
        json!({"type": "virtual-machine"}),
        json!(null),
    ] {
        assert!(
            validate_vm_config(&unowned).is_err(),
            "unexpectedly accepted {unowned}"
        );
    }
}

#[test]
fn ownership_manifest_must_match_project_owner_and_run_id() {
    let owned = Owned {
        owner: OWNER.into(),
        project: "test-project".into(),
        instances: vec!["run-123-debian".into(), "run-123-alpine".into()],
    };
    validate_owned_manifest(&owned, "test-project", "run-123").expect("valid owned manifest");

    assert!(validate_owned_manifest(&owned, "other-project", "run-123").is_err());
    assert!(validate_owned_manifest(&owned, "test-project", "other-run").is_err());
    assert!(validate_owned_manifest(&owned, "test-project", "../run-123").is_err());

    let mut wrong_owner = Owned {
        owner: "someone-else".into(),
        project: owned.project.clone(),
        instances: owned.instances.clone(),
    };
    assert!(validate_owned_manifest(&wrong_owner, "test-project", "run-123").is_err());

    wrong_owner.owner = OWNER.into();
    wrong_owner.instances.push("run-999-unrelated".into());
    assert!(validate_owned_manifest(&wrong_owner, "test-project", "run-123").is_err());
}

#[test]
fn rendered_summary_includes_target_state_and_image_fingerprint() {
    let results = vec![json!({
        "distro": "debian-13",
        "phase": "application",
        "error": null,
        "seconds": 12.5,
        "image": "debian/13",
        "image_fingerprint": "sha256:abc123",
        "diagnostic_errors": [],
    })];

    let summary = render_summary("v1.2.3", Some("sha256:archive"), &results);

    assert!(summary.contains("Kidobo distro E2E run for v1.2.3"));
    assert!(summary.contains("Archive SHA-256: sha256:archive"));
    assert!(summary.contains("debian-13: PASS (application, 12.5s)"));
    assert!(summary.contains("image=debian/13 base_image=sha256:abc123"));
}

#[test]
fn guest_push_and_delete_route_only_through_verified_incus_vm() {
    let temp = TestDir::new();
    let (program, log) = fake_incus(&temp);
    let mut runner = runner_with_incus(temp.path(), &program);
    let host_marker = temp.path().join("host-payload-ran");
    let payload = format!("touch {}", host_marker.display());
    let guest_output = runner
        .guest("vm-owned", &strings(&["sh", "-c", &payload]), 5)
        .expect("guest command is routed through Incus");
    assert_eq!(guest_output, "fake-incus-output\n");

    let source = temp.path().join("artifact with spaces.txt");
    fs::write(&source, "fixture").expect("write push fixture");
    runner
        .push("vm-owned", &source, "/tmp/artifact.txt", false)
        .expect("file push is routed through Incus");
    runner
        .delete("vm-owned")
        .expect("delete is routed through Incus");

    let calls = read_text(&log).expect("read fake Incus log");
    let calls: Vec<_> = calls.lines().collect();
    assert_eq!(calls.len(), 6, "each operation verifies before acting");
    assert_eq!(
        calls[0],
        "<--project><test-project><list><vm-owned><--format=json>"
    );
    assert!(calls[1].contains("<exec><vm-owned><--mode=non-interactive><-->"));
    assert_eq!(
        calls[2],
        "<--project><test-project><list><vm-owned><--format=json>"
    );
    assert!(calls[3].contains("<file><push>"));
    assert!(calls[3].contains("<vm-owned/tmp/artifact.txt>"));
    assert_eq!(
        calls[4],
        "<--project><test-project><list><vm-owned><--format=json>"
    );
    assert_eq!(
        calls[5],
        "<--project><test-project><delete><vm-owned><--force>"
    );
    assert!(
        !host_marker.exists(),
        "guest payload must never run on the host"
    );
}

#[test]
fn guest_push_and_delete_reject_unowned_or_non_vm_targets_before_action() {
    for (vm, operation) in [
        ("vm-container", "guest"),
        ("vm-unowned", "push"),
        ("vm-container", "delete"),
    ] {
        let temp = TestDir::new();
        let (program, log) = fake_incus(&temp);
        let mut runner = runner_with_incus(temp.path(), &program);
        let source = temp.path().join("source");
        fs::write(&source, "fixture").expect("write push fixture");

        let result = match operation {
            "guest" => runner.guest(vm, &strings(&["true"]), 5).map(|_| ()),
            "push" => runner.push(vm, &source, "/tmp/source", false),
            "delete" => runner.delete(vm),
            _ => unreachable!(),
        };

        assert!(result.is_err(), "{operation} unexpectedly accepted {vm}");
        let error = result.expect_err("invalid target must be rejected");
        assert!(
            error.to_string().contains("unowned or non-VM"),
            "{operation} on {vm} failed for an unexpected reason: {error}"
        );
        let calls = read_text(&log).expect("read fake Incus log");
        let calls: Vec<_> = calls.lines().collect();
        assert_eq!(
            calls.len(),
            1,
            "rejected {operation} must not issue an action"
        );
        assert!(calls[0].contains(&format!("<list><{vm}><--format=json>")));
    }
}

#[test]
fn create_vm_verifies_ownership_before_agent_disk_and_start() {
    let temp = TestDir::new();
    let (program, log) = fake_incus(&temp);
    let mut runner = runner_with_incus(temp.path(), &program);

    runner
        .create_vm("debian/13", "vm-owned", "test-profile")
        .expect("owned VM receives agent disk and starts");

    let calls = read_text(&log).expect("read fake Incus log");
    let calls: Vec<_> = calls.lines().collect();
    assert_eq!(calls.len(), 4);
    assert_eq!(
        calls[0],
        "<--project><test-project><init><images:debian/13><vm-owned><--vm><--profile><test-profile><-c><user.kidobo-e2e=kidobo-e2e-v1>"
    );
    assert_eq!(
        calls[1],
        "<--project><test-project><list><vm-owned><--format=json>"
    );
    assert_eq!(
        calls[2],
        "<--project><test-project><config><device><add><vm-owned><agent><disk><source=agent:config>"
    );
    assert_eq!(calls[3], "<--project><test-project><start><vm-owned>");
}

#[test]
fn create_vm_refuses_agent_disk_and_start_when_ownership_check_fails() {
    let temp = TestDir::new();
    let (program, log) = fake_incus(&temp);
    let mut runner = runner_with_incus(temp.path(), &program);

    let error = runner
        .create_vm("alma/10", "vm-unowned", "test-profile")
        .expect_err("unowned VM must not be mutated");

    assert!(
        error.to_string().contains("unowned or non-VM"),
        "create_vm failed for an unexpected reason: {error}"
    );
    let calls = read_text(&log).expect("read fake Incus log");
    let calls: Vec<_> = calls.lines().collect();
    assert_eq!(calls.len(), 2, "only init and verification may run");
    assert!(calls[0].contains("<init><images:alma/10><vm-unowned>"));
    assert!(calls[1].contains("<list><vm-unowned><--format=json>"));
}
