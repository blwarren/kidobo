//! Fresh preparation tests execute a stateful fake Incus boundary, never a VM.
use super::*;
use crate::tests::{TestDir, executable};
use crate::{Report, read_text};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

struct Fixture {
    temporary: TestDir,
    config: Config,
}

impl Fixture {
    #[expect(
        clippy::too_many_lines,
        reason = "The stateful fake daemon and its preparation configuration form one isolated fixture"
    )]
    fn new() -> Self {
        let temporary = TestDir::new();
        let root = temporary.path();
        fs::write(
            root.join("state.json"),
            serde_json::to_vec(&json!({
                "instances":{}, "events":[], "scenario":"", "serial":0,
                "profile":{"config":{"user.kidobo-e2e":OWNER,"limits.cpu":"2","limits.memory":"4GiB"},
                    "devices":{"root":{"type":"disk","path":"/","pool":"test-pool","size":"30GiB"},
                        "eth0":{"type":"nic","name":"eth0","network":"test-network"}}}
            }))
            .expect("fake daemon state"),
        )
        .expect("write daemon state");
        fs::write(
            root.join("checks.json"),
            include_str!("../../../../scripts/e2e/checks.json"),
        )
        .expect("fake guest check inventory");
        executable(
            &root.join("fake-incus"),
            r#"#!/usr/bin/env python3
import json
import sys
from pathlib import Path

root = Path(__file__).parent
state_path = root / 'state.json'
state = json.loads(state_path.read_text())
args = sys.argv[1:]
if args[0] == 'query':
    assert '--project' not in args, args
    assert args[-1].endswith('?project=test-project'), args
    assert args == ['query', '/1.0/profiles/test-profile?project=test-project'] or args[-1].startswith('/1.0/instances/'), args
else:
    assert args[:2] == ['--project', 'test-project'], args
    args = args[2:]
    assert args[0] != 'query', '--project cannot be used with the query command'
state['events'].append(args)
scenario = state['scenario']


def save():
    state_path.write_text(json.dumps(state))


def fail(status):
    save()
    raise SystemExit(status)


def describe(name):
    vm = state['instances'][name]
    return {'name':name, 'type':'virtual-machine', 'status':vm['status'],
            'config':{'user.kidobo-e2e':'kidobo-e2e-v1', 'volatile.base_image':vm['base']}}


def markers(phase):
    checks = json.loads((root / 'checks.json').read_text())['profiles']['preparation'][phase]
    for name, count in checks.items():
        for _ in range(count):
            print(f'E2E_CHECK\t{name}\tSTART\tfixture expectation', file=sys.stderr)
            print(f'E2E_CHECK\t{name}\tPASS\tfixture observation', file=sys.stderr)


operation = args[0]
if operation == 'query':
    if '/instances/' in args[-1]:
        path = args[-1].split('?')[0]
        if path.endswith('/logs'):
            assert args[1] == args[-1], args
            print(json.dumps({'metadata':[path + '/qemu.log']}))
        else:
            assert args[1] == '--raw' and path.endswith('/logs/qemu.log'), args
            print('fixture QEMU log')
    else:
        print(json.dumps({'metadata':state['profile']}))
elif operation == 'console':
    print('fixture serial console')
elif operation == 'image':
    if args[1] == 'list':
        print(json.dumps([{'fingerprint':state['cached_fp'], 'type':'virtual-machine', 'architecture':'x86_64'}]))
    else:
        assert args[1] == 'info', args
        print('Fingerprint: ' + 'a' * 64)
elif operation == 'init':
    source, name = args[1:3]
    assert name not in state['instances'], name
    state['serial'] += 1
    assert source.startswith('images:') or source == state.get('cached_fp'), source
    state['instances'][name] = {'base':source.removeprefix('images:'), 'status':'Stopped', 'environment':None, 'boot':0}
elif operation == 'list':
    names = list(state['instances']) if args[1] == '--format=json' else [args[1]]
    print(json.dumps([describe(name) for name in names if name in state['instances']]))
elif operation == 'config':
    pass
elif operation in {'start','stop','restart'}:
    vm = state['instances'][args[1]]
    if operation == 'stop':
        vm['status'] = 'Stopped'
    else:
        vm['status'] = 'Running'
        vm['boot'] += 1
        if operation == 'restart' and scenario == 'post-reboot-agent-loss':
            vm['agent_down'] = True
elif operation == 'delete':
    del state['instances'][args[1]]
elif operation == 'file':
    if args[1] == 'push':
        assert Path(args[-2]).is_file(), args
    elif args[1] == 'pull':
        Path(args[-1]).mkdir(parents=True, exist_ok=True)
    else:
        raise AssertionError(args)
elif operation == 'exec':
    name = args[1]
    vm = state['instances'][name]
    assert vm['status'] == 'Running', name
    command = args[4:]
    if vm.get('agent_down'):
        print('VM agent is unavailable after restart', file=sys.stderr)
        fail(255)
    if command[0] == 'cat':
        path = command[1]
        if path == '/proc/sys/kernel/random/boot_id':
            print(f"{name}-boot-{vm['boot']}")
        elif path.endswith('/relabel-scheduled'):
            print('0')
        elif path.endswith('/environment.json'):
            print(json.dumps(vm['environment']))
        else:
            raise AssertionError(command)
    elif command[:2] == ['bash', '-c'] and '=== pre-reboot snapshot ===' in command[2]:
        print(f"pre-reboot kernel=fixture-kernel boot={vm['boot']}")
        if scenario == 'snapshot-failure':
            print('cat: /etc/grub2.cfg: No such file or directory', file=sys.stderr)
            fail(1)
    elif command[:2] == ['bash', '-c'] and 'cloud-init status --wait' in command[2]:
        status = {'status':'done', 'errors':[], 'recoverable_errors':{}}
        code = '0,0'
        if scenario == 'hostname-warning':
            status['recoverable_errors'] = {'WARNING':[f'Failed to set the hostname to {name} ({name})']}
            code = '2,2'
        elif scenario == 'bootstrap-failure':
            status['errors'] = ['agent installation failed']
            code = '1,1'
        print(json.dumps(status))
        print('KIDOBO_CLOUD_INIT_EXIT=' + code)
    elif command[0] in {'true','sh','test'}:
        pass
    elif command[:2] == ['bash','/opt/kidobo-e2e/provision.sh']:
        phase = command[2]
        if phase == '--boot-status':
            vm['probes'] = vm.get('probes', 0) + 1
            if scenario == 'boot-timeout':
                fail(255)
            if scenario == 'relabel-reboot' and vm['probes'] in {1, 3, 6}:
                if vm['probes'] == 3:
                    vm['boot'] += 1
                fail(255)
            print(f"{name}-boot-{vm['boot']}")
            if scenario != 'missing-probe-marker':
                markers(phase)
            save()
            raise SystemExit(0)
        if phase == '--start-enforcement':
            vm['enforcement_started'] = True
            if scenario == 'relabel-reboot':
                fail(255)
            markers(phase)
            save()
            raise SystemExit(0)
        if phase == '--enforcement-status':
            assert vm['enforcement_started']
            vm['enforcement_probes'] = vm.get('enforcement_probes', 0) + 1
            if scenario == 'relabel-reboot' and vm['enforcement_probes'] == 1:
                fail(255)
            print('17 Permissive' if scenario == 'enforcement-failure' else '0 Enforcing')
            markers(phase)
            save()
            raise SystemExit(0)
        if phase == '--prepare' and scenario == 'prepare-failure':
            fail(70)
        if phase == '--prepare':
            vm['family'] = command[3]
            vm['selinux_requested'] = command[4]
        if phase == '--validate':
            requested = vm.get('selinux_requested', 'image-default')
            vm['environment'] = {'family':vm.get('family', 'apt'), 'architecture':'x86_64', 'kernel':'fixture-kernel',
                              'selinux':'Enforcing' if requested == 'enforcing' else 'Disabled',
                              'iptables_backend':'iptables v1.8.11 (nf_tables)',
                              'ip6tables_backend':'ip6tables v1.8.11 (nf_tables)'}
        markers(phase)
    else:
        raise AssertionError(command)
else:
    raise AssertionError(args)
save()
"#,
        );
        let config = Config {
            project: "test-project".into(),
            profile: "test-profile".into(),
            network: "test-network".into(),
            pool: "test-pool".into(),
            cpus: 2,
            memory: "4GiB".into(),
            disk: "30GiB".into(),
            max_parallel_vms: 2,
            distros: vec![Distro {
                id: "primary".into(),
                image: "fixture/image".into(),
                vendor_image: None,
                family: "apt".into(),
                packages: vec!["bash".into()],
                required: true,
                selinux: "image-default".into(),
            }],
        };
        Self { temporary, config }
    }

    fn state(&self) -> Value {
        serde_json::from_str(
            &read_text(&self.temporary.path().join("state.json")).expect("daemon state"),
        )
        .expect("valid daemon state")
    }

    fn change(&self, update: impl FnOnce(&mut Value)) {
        let mut state = self.state();
        update(&mut state);
        fs::write(
            self.temporary.path().join("state.json"),
            serde_json::to_vec(&state).expect("updated state"),
        )
        .expect("save updated state");
    }

    fn runner(&self, run: u32) -> Runner {
        let dir = self.temporary.path().join(format!("run-100-{run}"));
        let report = Report::open(&dir).expect("preparation report");
        fs::create_dir_all(dir.join(".evidence/inputs")).expect("frozen inputs");
        if self.config.distros[0].vendor_image.is_some() {
            crate::vendor_images::snapshot(
                &dir.join(".evidence/inputs"),
                &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/e2e.toml"),
            )
            .unwrap();
            fs::write(
                dir.join(".evidence/inputs/bootstrap.sh"),
                include_str!("../../../../scripts/e2e/bootstrap.sh"),
            )
            .unwrap();
        }
        for (name, contents) in [
            (
                "provision.sh",
                include_str!("../../../../scripts/e2e/provision.sh"),
            ),
            (
                "checks.json",
                include_str!("../../../../scripts/e2e/checks.json"),
            ),
        ] {
            fs::write(dir.join(".evidence/inputs").join(name), contents)
                .expect("freeze preparation input");
        }
        fs::write(
            dir.join(".evidence/inputs/SHA256.json"),
            r#"{"harness":"stable-fixture"}"#,
        )
        .expect("freeze host preparation identity");
        Runner {
            project: self.config.project.clone(),
            dir,
            incus_program: self.temporary.path().join("fake-incus"),
            cancelled: Arc::new(AtomicBool::new(false)),
            report,
            command_poll_interval: Duration::from_millis(1),
            ignore_cancellation: false,
        }
    }

    fn prepare(&self, run: u32) -> (Runner, Result<Value>) {
        let mut runner = self.runner(run);
        let result = super::prepare(
            &mut runner,
            &self.config,
            &self.config.distros[0],
            &format!("run-100-{run}-primary"),
        );
        (runner, result)
    }

    fn count(&self, first: &str, second: Option<&str>) -> usize {
        self.state()["events"]
            .as_array()
            .expect("events")
            .iter()
            .filter(|event| event[0] == first && second.is_none_or(|value| event[1] == value))
            .count()
    }

    fn guest_count(&self, phase: &str) -> usize {
        self.state()["events"]
            .as_array()
            .expect("events")
            .iter()
            .filter(|event| {
                event
                    .as_array()
                    .is_some_and(|arguments| arguments.iter().any(|value| value == phase))
            })
            .count()
    }
}

#[test]
fn vendor_source_bootstraps_before_provisioning_and_keeps_fresh_guest_lifecycles() {
    let mut fixture = Fixture::new();
    let production: Config =
        toml_edit::de::from_str(include_str!("../../../../config/e2e.toml")).unwrap();
    fixture.config.distros[0] = production
        .distros
        .into_iter()
        .find(|d| d.id == "fedora-44")
        .unwrap();
    let pins: Value =
        toml_edit::de::from_str(include_str!("../../../../config/e2e-images.toml")).unwrap();
    let fingerprint = pins["images"]["fedora-44"]["incus_fingerprint"].clone();
    fixture.change(|state| state["cached_fp"] = fingerprint.clone());
    let (_, result) = fixture.prepare(1);
    let prepared = result.unwrap();
    assert_eq!(prepared["source"]["incus_fingerprint"], fingerprint);
    assert_eq!(
        prepared["source"]["sha256"],
        pins["images"]["fedora-44"]["sha256"]
    );
    let state = fixture.state();
    let events = state["events"].as_array().unwrap();
    let started = events.iter().position(|event| event[0] == "start").unwrap();
    for device in ["agent", "cloud-init"] {
        assert!(
            events[..started]
                .iter()
                .any(|event| event[0] == "config" && event[1] == "device" && event[4] == device)
        );
    }
    assert!(events[..started].iter().any(|event| {
        event[0] == "config"
            && event[1] == "set"
            && event[3]
                .as_str()
                .unwrap_or("")
                .starts_with("cloud-init.user-data=#cloud-config")
    }));
    let bootstrap = events
        .iter()
        .position(|event| {
            event
                .as_array()
                .unwrap()
                .contains(&json!("--check-bootstrap"))
        })
        .unwrap();
    let provision = events
        .iter()
        .position(|event| event.as_array().unwrap().contains(&json!("--prepare")))
        .unwrap();
    assert!(bootstrap < provision);
    fixture.change(|state| state["scenario"] = json!("bootstrap-failure"));
    let (_, failed) = fixture.prepare(2);
    assert!(
        failed
            .unwrap_err()
            .to_string()
            .contains("cloud-init did not complete")
    );
    assert_eq!(fixture.count("init", None), 2);
    assert_eq!(fixture.count("image", Some("import")), 0);
    assert_eq!(fixture.guest_count("--prepare"), 1);
}

#[test]
fn preparation_waits_through_relabel_reboot_and_enforcement_transport_loss() {
    let fixture = Fixture::new();
    fixture.change(|state| state["scenario"] = json!("relabel-reboot"));
    let mut runner = fixture.runner(1);
    let vm = "run-100-1-primary";
    runner
        .create_vm("images:fixture-image", vm, "test-profile", None)
        .expect("fixture VM");
    reboot_prepared(
        &mut runner,
        vm,
        true,
        Duration::from_secs(5),
        Duration::from_millis(1),
    )
    .unwrap_or_else(|error| {
        panic!(
            "{error}\n{}",
            read_text(&runner.dir.join("transcript.log")).expect("transcript")
        )
    });
    let state = fixture.state();
    assert_eq!(state["instances"][vm]["boot"], 3);
    assert_eq!(state["instances"][vm]["probes"], 7);
    assert_eq!(state["instances"][vm]["enforcement_probes"], 3);
    assert_eq!(fixture.guest_count("--start-enforcement"), 1);
    assert_eq!(fixture.guest_count("--check-kernel"), 0);
}

#[test]
fn cloud_init_completion_is_recorded_and_only_known_fedora_warnings_are_accepted() {
    for scenario in ["", "hostname-warning", "bootstrap-failure"] {
        let mut fixture = Fixture::new();
        fixture.config.distros[0].id = "fedora-44".into();
        fixture.change(|state| state["scenario"] = json!(scenario));
        let mut runner = fixture.runner(1);
        let vm = "run-100-1-primary";
        runner
            .create_vm("images:fixture-image", vm, "test-profile", None)
            .expect("fixture VM");
        let result = wait_for_cloud_init(&mut runner, &fixture.config.distros[0], vm);
        let evidence = runner.evidence().join("fedora-44");
        assert!(evidence.join("cloud-init-status.txt").is_file());
        if scenario == "bootstrap-failure" {
            assert!(
                result
                    .expect_err("failed cloud-init cannot admit provisioning")
                    .to_string()
                    .contains("did not complete successfully")
            );
            assert!(!evidence.join("cloud-init.json").exists());
        } else {
            let warnings = result.expect("completed cloud-init");
            assert_eq!(warnings.len(), usize::from(scenario == "hostname-warning"));
            assert!(evidence.join("cloud-init.json").is_file());
            if !warnings.is_empty() {
                assert!(
                    read_text(&runner.dir.join("transcript.log"))
                        .expect("transcript")
                        .contains("WARNING: cloud-init: Failed to set the hostname")
                );
            }
        }
        assert_eq!(fixture.guest_count("--prepare"), 0);
    }
}

#[test]
fn cloud_init_rejects_unfinished_errors_unknown_warnings_and_inconsistent_exit_status() {
    let good = json!({"status":"done", "errors":[], "recoverable_errors":{}});
    for (status, exit) in [
        (
            json!({"status":"running", "errors":[], "recoverable_errors":{}}),
            "0,0",
        ),
        (json!({"status":"done", "recoverable_errors":{}}), "0,0"),
        (
            json!({"status":"done", "errors":["failed"], "recoverable_errors":{}}),
            "0,0",
        ),
        (
            json!({"status":"done", "errors":[], "recoverable_errors":{"WARNING":["unknown warning"]}}),
            "2,2",
        ),
        (
            json!({"status":"done", "errors":[], "recoverable_errors":{}, "modules-final":{"errors":["failed"]}}),
            "0,0",
        ),
        (good.clone(), "2,2"),
        (good.clone(), "1,0"),
        (good.clone(), "0,1"),
    ] {
        let output = format!("{status}\nKIDOBO_CLOUD_INIT_EXIT={exit}\n");
        cloud_init_warnings(&output, true, "guest").expect_err("must reject invalid completion");
    }
    cloud_init_warnings(&good.to_string(), true, "guest").expect_err("exit status must be present");
    let warning = json!({"status":"done", "errors":[], "recoverable_errors":{"WARNING":["Failed to set the hostname to guest (guest)"]}});
    let output = format!("{warning}\nKIDOBO_CLOUD_INIT_EXIT=2,2\n");
    cloud_init_warnings(&output, false, "guest").expect_err("AlmaLinux warnings are not exempt");
    cloud_init_warnings(&output, true, "different-guest")
        .expect_err("warning must identify the current guest exactly");
    cloud_init_warnings(&output, true, "guest").expect("identified Fedora hostname warning");
}

#[test]
fn bootstrap_cloud_config_preserves_the_frozen_script_without_shell_interpolation() {
    let script = "printf '%s\\n' \"$guest\" `literal`\n";
    let user_data = cloud_init_user_data(script).expect("cloud-config");
    let document: Value = serde_json::from_str(
        user_data
            .strip_prefix("#cloud-config\n")
            .expect("cloud-init header"),
    )
    .expect("cloud-config JSON");
    assert_eq!(document, json!({"runcmd":[["bash", "-c", script]]}));
}

#[test]
fn preparation_readiness_bounds_failure_timeout_and_cancellation() {
    for scenario in [
        "enforcement-failure",
        "boot-timeout",
        "cancelled",
        "missing-probe-marker",
    ] {
        let fixture = Fixture::new();
        fixture.change(|state| state["scenario"] = json!(scenario));
        let mut runner = fixture.runner(1);
        let vm = "run-100-1-primary";
        runner
            .create_vm("images:fixture-image", vm, "test-profile", None)
            .expect("fixture VM");
        if scenario == "cancelled" {
            runner
                .cancelled
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
        let timeout = if scenario == "boot-timeout" {
            Duration::from_millis(100)
        } else {
            Duration::from_secs(5)
        };
        let error = reboot_prepared(&mut runner, vm, true, timeout, Duration::from_millis(1))
            .expect_err("preparation cannot be admitted")
            .to_string();
        let expected = match scenario {
            "enforcement-failure" => "detached SELinux enforcement failed: 17 Permissive",
            "boot-timeout" => "deadline expired",
            "missing-probe-marker" => "guest check inventory mismatch",
            _ => "interrupted",
        };
        assert!(error.contains(expected), "{scenario}: {error}");
        assert_eq!(fixture.guest_count("--check-kernel"), 0);
        assert_eq!(fixture.count("publish", None), 0);
    }
}

#[test]
fn successful_restart_then_agent_loss_keeps_snapshot_and_expires_before_admission() {
    let fixture = Fixture::new();
    fixture.change(|state| state["scenario"] = json!("post-reboot-agent-loss"));
    let mut runner = fixture.runner(1);
    let vm = "run-100-1-primary";
    runner
        .create_vm("images:fixture-image", vm, "test-profile", None)
        .expect("fixture VM");
    let target = runner.evidence().join("primary");
    assert_eq!(
        crate::diagnostics::pre_reboot(&mut runner, vm, &target).expect("snapshot before restart"),
        None
    );
    let error = reboot_prepared(
        &mut runner,
        vm,
        true,
        Duration::from_millis(500),
        Duration::from_millis(1),
    )
    .expect_err("agent never returned after successful restart")
    .to_string();
    assert!(error.contains("deadline expired"), "{error}");
    assert_eq!(fixture.count("restart", None), 1);
    assert_eq!(fixture.state()["instances"][vm]["boot"], 2);
    let restart = runner.report.document["commands"]
        .as_array()
        .expect("commands")
        .iter()
        .find(|command| {
            command["args"]
                .as_array()
                .is_some_and(|args| args.iter().any(|arg| arg == "restart"))
        })
        .expect("restart command");
    assert_eq!(restart["code"], 0);
    assert!(fixture.guest_count("--boot-status") > 0);
    assert_eq!(fixture.guest_count("--check-kernel"), 0);
    assert_eq!(fixture.guest_count("--admit"), 0);
    assert_eq!(fixture.count("publish", None), 0);
    let diagnostics = crate::diagnostics::collect(&mut runner, vm, &target);
    assert_eq!(diagnostics.errors, Vec::<String>::new());
    runner.delete(vm).expect("normal cleanup after lost agent");
    assert_eq!(fixture.state()["instances"], json!({}));
    assert_eq!(
        read_text(&target.join("pre-reboot/snapshot.log"))
            .expect("snapshot survives diagnostics and cleanup"),
        "pre-reboot kernel=fixture-kernel boot=1\n"
    );
    let status: Value = serde_json::from_str(
        &read_text(&target.join("pre-reboot/snapshot.capture.json")).expect("snapshot sidecar"),
    )
    .expect("JSON");
    assert_eq!(status["status"], "captured");
}

#[test]
fn fresh_preparation_requires_durable_security_transition_success() {
    for success in [false, true] {
        let mut fixture = Fixture::new();
        fixture.config.distros[0].selinux = "enforcing".into();
        fixture.config.distros[0].family = "dnf".into();
        fixture.change(|state| {
            state["scenario"] = json!(if success { "" } else { "enforcement-failure" });
        });
        let (_, outcome) = fixture.prepare(1);
        if success {
            let metadata = outcome.expect("enforcing fresh guest verified");
            assert_eq!(metadata["preparation"]["selinux"], "Enforcing");
            assert_eq!(fixture.guest_count("--check-kernel"), 1);
            assert_eq!(fixture.count("publish", None), 0);
        } else {
            assert!(
                outcome
                    .expect_err("enforcement failure must abort preparation")
                    .to_string()
                    .contains("detached SELinux enforcement failed")
            );
            assert_eq!(fixture.guest_count("--check-kernel"), 0);
            assert_eq!(fixture.count("publish", None), 0);
        }
    }
}

#[test]
fn each_run_prepares_a_fresh_guest_without_image_management() {
    let fixture = Fixture::new();
    for run in [1, 2] {
        let (_, outcome) = fixture.prepare(run);
        let metadata = outcome.expect("fresh preparation");
        assert_eq!(metadata["image_fingerprint"], "a".repeat(64));
        assert_eq!(metadata["preparation"]["kernel"], "fixture-kernel");
        assert_eq!(metadata["diagnostic_warnings"], json!([]));
    }
    assert_eq!(fixture.count("init", None), 2);
    assert_eq!(fixture.count("image", Some("info")), 2);
    assert_eq!(fixture.guest_count("--prepare"), 2);
    assert_eq!(fixture.guest_count("--validate"), 2);
    assert_eq!(fixture.count("publish", None), 0);
    assert_eq!(fixture.count("delete", None), 0);
}

#[test]
fn failed_supplemental_snapshot_does_not_prevent_guest_validation() {
    let fixture = Fixture::new();
    fixture.change(|state| state["scenario"] = json!("snapshot-failure"));
    let (_, outcome) = fixture.prepare(1);
    let metadata = outcome.expect("snapshot cannot veto preparation");
    assert_eq!(fixture.guest_count("--validate"), 1);
    assert_eq!(
        metadata["diagnostic_warnings"]
            .as_array()
            .expect("warnings")
            .len(),
        1
    );
    assert!(
        metadata["diagnostic_warnings"][0]
            .as_str()
            .expect("warning")
            .contains("pre-reboot snapshot")
    );
}

#[test]
fn shared_profile_mismatch_cancels_before_creating_a_guest() {
    let fixture = Fixture::new();
    fixture.change(|state| state["profile"]["config"]["limits.memory"] = json!("8GiB"));
    let (runner, outcome) = fixture.prepare(1);
    assert!(
        outcome
            .expect_err("shared infrastructure mismatch")
            .to_string()
            .contains("profile resources differ")
    );
    assert!(runner.cancelled.load(std::sync::atomic::Ordering::Relaxed));
    assert_eq!(fixture.count("init", None), 0);
}
