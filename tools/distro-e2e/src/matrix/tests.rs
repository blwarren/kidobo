use super::*;
use crate::tests::{TestDir, executable};
use crate::{Report, read_text};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::thread;
use std::time::Duration;

const RUN_ID: &str = "run-123-456";

struct Fixture {
    temp: TestDir,
    runner: Runner,
    config: Config,
}

impl Fixture {
    #[expect(
        clippy::too_many_lines,
        reason = "Stateful fake Incus fixture remains adjacent to its test configuration"
    )]
    fn new(scenario: &str, secondary_required: bool) -> Self {
        let temp = TestDir::new();
        let state = temp.path().join("state");
        fs::create_dir(&state).expect("create fake Incus state");
        fs::write(state.join("scenario"), scenario).expect("configure fake scenario");
        fs::write(state.join("limit"), "1").expect("configure running-VM limit");
        fs::write(
            state.join("checks.json"),
            include_str!("../../../../scripts/e2e/checks.json"),
        )
        .expect("freeze fake guest check inventory");
        let program = temp.path().join("fake-incus");
        executable(
            &program,
            r#"#!/usr/bin/env python3
import contextlib
import fcntl
import json
import shutil
import sys
import time
from pathlib import Path

state = Path(__file__).parent / "state"
scenario = (state / "scenario").read_text().strip()
args = sys.argv[1:]
if args[0] == "query":
    assert "--project" not in args, args
    assert args[-1].endswith("?project=test-project"), args
else:
    assert args[:2] == ["--project", "test-project"], args
    args = args[2:]
    assert args[0] != "query", "--project cannot be used with the query command"


def event(name, value):
    with (state / "events").open("a") as output:
        output.write(f"{name} {value}\n")


@contextlib.contextmanager
def lock():
    with (state / "state.lock").open("a") as guard:
        fcntl.flock(guard, fcntl.LOCK_EX)
        yield


def instances():
    return sorted(path for path in state.glob("run-*") if path.is_dir())


def describe(vm):
    return {"name": vm, "type": "virtual-machine",
            "status": "Running" if (state / vm / "running").exists() else "Stopped",
            "config": {"user.kidobo-e2e": "kidobo-e2e-v1", "volatile.base_image": "a" * 64}}


def start(vm):
    with lock():
        assert not (state / vm / "running").exists(), vm
        (state / vm / "running").touch()
        count = sum((instance / "running").exists() for instance in instances())
        event("power-start", vm)
        event("running-count", count)
        if count > int((state / "limit").read_text()):
            event("overlapping-start", vm)
            raise SystemExit(91)


def stop(vm):
    with lock():
        if scenario == "cleanup-and-stop-failure" and vm.endswith("-secondary"):
            event("stop-failure", vm)
            raise SystemExit(74)
        (state / vm / "running").unlink(missing_ok=True)
        event("park", vm)


def markers(profile, phase):
    checks = json.loads((state / "checks.json").read_text())["profiles"][profile][phase]
    for name, count in checks.items():
        for _ in range(count):
            print(f"E2E_CHECK\t{name}\tSTART\tfixture expectation", file=sys.stderr)
            print(f"E2E_CHECK\t{name}\tPASS\tfixture observation", file=sys.stderr)


def barrier(vm, interrupt=False):
    entered = state / "prepare-entered"
    entered.mkdir(exist_ok=True)
    (entered / vm).touch()
    deadline = time.monotonic() + 5
    while len(list(entered.iterdir())) < 2:
        assert time.monotonic() < deadline, "second worker never entered preparation"
        time.sleep(0.005)
    if interrupt:
        (state / "interruption-ready").touch()
        while not (state / "interruption-ack").exists():
            assert time.monotonic() < deadline, "interruption was not acknowledged"
            time.sleep(0.005)


operation = args[0]
if operation == "query":
    path = args[-1].split("?")[0]
    if path == "/1.0/profiles/test-profile":
        print(json.dumps({"metadata": {
            "config": {"user.kidobo-e2e": "kidobo-e2e-v1", "limits.cpu": "2", "limits.memory": "4GiB"},
            "devices": {"root": {"type": "disk", "path": "/", "pool": "test-pool", "size": "30GiB"},
                        "eth0": {"type": "nic", "network": "test-network", "name": "eth0"}}}}))
    elif path.endswith("/logs"):
        print(json.dumps([path + "/qemu.log"]))
    elif path.endswith("/logs/qemu.log"):
        vm = path.split("/")[3]
        event("runtime-log", vm)
        if scenario == "host-diagnostics-failure" and vm.endswith("-secondary"):
            print("runtime log unavailable", file=sys.stderr)
            raise SystemExit(74)
        print("QEMU boot evidence")
    else:
        raise AssertionError(args)
elif operation == "console":
    assert args[2] == "--show-log", args
    event("serial-log", args[1])
    if scenario == "console-unsupported":
        print("Error: Instance is not container type", file=sys.stderr)
        raise SystemExit(1)
    print("serial boot evidence")
elif operation == "image":
    assert args[1] == "info", args
    print("Fingerprint: " + "a" * 64)
elif operation == "init":
    vm = args[2]
    if scenario == "image-failure" and vm.endswith("-secondary"):
        event("image-failure", vm)
        raise SystemExit(70)
    (state / vm).mkdir()
    (state / vm / "boot").write_text("0\n")
    event("create", vm)
elif operation == "list":
    values = instances() if args[1] == "--format=json" else [state / args[1]]
    print(json.dumps([describe(path.name) for path in values if path.is_dir()]))
elif operation == "config":
    pass
elif operation == "file":
    if args[1] == "push":
        assert Path(args[-2]).is_file(), args
    elif args[1] == "pull":
        Path(args[-1]).mkdir(parents=True, exist_ok=True)
    else:
        raise AssertionError(args)
elif operation == "start":
    start(args[1])
elif operation == "stop":
    stop(args[1])
elif operation == "restart":
    vm = args[1]
    assert (state / vm / "running").exists(), vm
    boot = state / vm / "boot"
    boot.write_text(str(int(boot.read_text()) + 1) + "\n")
    event("reboot", vm)
elif operation == "delete":
    vm = args[1]
    event("delete", vm)
    if scenario in {"cleanup-failure", "cleanup-and-stop-failure"} and vm.endswith("-secondary"):
        raise SystemExit(72)
    with lock():
        shutil.rmtree(state / vm)
elif operation == "exec":
    vm = args[1]
    guest = args[4:]
    assert (state / vm / "running").exists(), vm
    if (state / vm / "agent-down").exists():
        print("VM agent is unavailable", file=sys.stderr)
        raise SystemExit(255)
    if guest[0] in {"true", "sh", "chmod", "mkdir", "test"}:
        pass
    elif guest[0] == "cat":
        path = guest[1]
        if path == "/proc/sys/kernel/random/boot_id":
            print((state / vm / "boot").read_text(), end="")
        elif path.endswith("/relabel-scheduled"):
            print("0")
        elif path.endswith("/manifest.json"):
            print(json.dumps({"prepared_at_unix": int(time.time()), "kernel": "fixture-kernel",
                              "selinux": "image-default"}))
        elif path.endswith("/admission.json"):
            print(json.dumps({"machine_id": vm, "kernel": "fixture-kernel", "selinux": "Disabled"}))
        else:
            raise AssertionError(guest)
    elif guest[0] == "bash":
        if guest[1] == "-c":
            if "=== uname ===" in guest[2]:
                if scenario == "diagnostics-failure" and vm.endswith("-secondary"):
                    raise SystemExit(73)
                print("fake guest diagnostics")
        elif guest[1] == "/opt/kidobo-e2e/provision.sh":
            phase = guest[2]
            if phase == "--boot-status":
                print((state / vm / "boot").read_text(), end="")
                markers("preparation", phase)
                raise SystemExit(0)
            if phase == "--prepare":
                event("dependencies", vm)
                if scenario in {"concurrent", "interrupt-both"} and not vm.endswith("-tertiary"):
                    barrier(vm, scenario == "interrupt-both")
            elif phase == "--check-kernel":
                event("kernel", vm)
                if scenario == "prerequisite-failure" and vm.endswith("-secondary"):
                    raise SystemExit(70)
            elif phase == "--admit":
                event("admit", vm)
                if ((scenario == "interrupt-first" and vm.endswith("-primary")) or
                        (scenario == "interrupt-second" and vm.endswith("-secondary"))):
                    (state / "interruption-ready").touch()
                    deadline = time.monotonic() + 5
                    while not (state / "interruption-ack").exists():
                        assert time.monotonic() < deadline, "interruption was not acknowledged"
                        time.sleep(0.005)
            markers("preparation", phase)
        elif guest[1] == "/opt/kidobo-e2e/lifecycle.sh":
            phase = guest[2]
            event(phase, vm)
            if phase == "start" and scenario == "host-diagnostics-failure" and vm.endswith("-secondary"):
                (state / vm / "agent-down").touch()
                raise SystemExit(255)
            if phase == "start" and scenario == "application-failure" and vm.endswith("-secondary"):
                raise SystemExit(71)
            if not (phase == "start" and scenario == "missing-checks"):
                markers(guest[4], phase)
        else:
            raise AssertionError(guest)
    else:
        raise AssertionError(guest)
else:
    raise AssertionError(args)
"#,
        );
        let dir = temp.path().join(RUN_ID);
        let report = Report::open(&dir).expect("create matrix report");
        fs::create_dir_all(dir.join(".evidence")).expect("create matrix evidence");
        fs::create_dir(dir.join(".evidence/inputs")).expect("create frozen input directory");
        for (name, contents) in [
            (
                "provision.sh",
                include_str!("../../../../scripts/e2e/provision.sh"),
            ),
            (
                "lifecycle.sh",
                include_str!("../../../../scripts/e2e/lifecycle.sh"),
            ),
            (
                "traffic.py",
                include_str!("../../../../scripts/e2e/traffic.py"),
            ),
            (
                "installer.sh",
                include_str!("../../../../scripts/install.sh"),
            ),
            (
                "checks.json",
                include_str!("../../../../scripts/e2e/checks.json"),
            ),
        ] {
            fs::write(dir.join(".evidence/inputs").join(name), contents)
                .expect("write frozen guest input");
        }
        fs::write(
            dir.join(".evidence/inputs/SHA256.json"),
            r#"{"harness":"fixture"}"#,
        )
        .expect("write frozen host validation identity");
        for (name, contents) in [
            ("baseline-tag", "v0.14.3"),
            ("baseline-installer.sh", "fixture baseline installer"),
            ("baseline-SHA256SUMS", "fixture baseline checksums"),
            ("baseline-archive.tar.gz", "fixture baseline archive"),
        ] {
            fs::write(dir.join(".evidence").join(name), contents)
                .expect("write frozen baseline input");
        }
        let runner = Runner {
            project: "test-project".into(),
            dir,
            incus_program: program,
            cancelled: Arc::new(AtomicBool::new(false)),
            report,
            command_poll_interval: Duration::from_millis(1),
            ignore_cancellation: false,
        };
        let config = Config {
            project: "test-project".into(),
            profile: "test-profile".into(),
            network: "test-network".into(),
            pool: "test-pool".into(),
            cpus: 2,
            memory: "4GiB".into(),
            disk: "30GiB".into(),
            max_parallel_vms: 1,
            prepared_images: crate::prepared::Settings {
                enabled: false,
                ..Default::default()
            },
            distros: ["primary", "secondary"]
                .into_iter()
                .map(|id| Distro {
                    id: id.into(),
                    image: "fixture/image".into(),
                    family: "apt".into(),
                    packages: vec!["fixture-package".into()],
                    required: id == "primary" || secondary_required,
                    selinux: "image-default".into(),
                })
                .collect(),
        };
        Self {
            temp,
            runner,
            config,
        }
    }

    fn parallelism(&mut self, count: usize) {
        self.config.max_parallel_vms = count;
        fs::write(self.temp.path().join("state/limit"), count.to_string())
            .expect("configure fake resource bound");
    }

    fn execute(&mut self) -> Result<()> {
        self.execute_with_keep_failed(false)
    }

    fn execute_with_keep_failed(&mut self, keep_failed: bool) -> Result<()> {
        let targets = self.config.distros.iter().collect::<Vec<_>>();
        execute(
            &mut self.runner,
            &self.config,
            RUN_ID,
            &targets,
            "v0.15.0",
            false,
            None,
            keep_failed,
            None,
        )
    }

    fn events(&self) -> Vec<String> {
        read_text(&self.temp.path().join("state/events"))
            .expect("read fake events")
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn result(&self, id: &str) -> &Value {
        self.runner.report.document["results"]
            .as_array()
            .expect("matrix results")
            .iter()
            .find(|result| result["distro"] == id)
            .expect("recorded target result")
    }

    fn interrupt_during_preparation(&mut self) -> Result<()> {
        let state = self.temp.path().join("state");
        let cancelled = Arc::clone(&self.runner.cancelled);
        let finished = Arc::new(AtomicBool::new(false));
        let notifier_finished = Arc::clone(&finished);
        let notifier = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(30);
            while !state.join("interruption-ready").exists() {
                if notifier_finished.load(Ordering::Relaxed) {
                    return false;
                }
                assert!(
                    Instant::now() < deadline,
                    "fake VM never reached the interruption barrier"
                );
                thread::sleep(Duration::from_millis(10));
            }
            cancelled.store(true, Ordering::Relaxed);
            fs::write(state.join("interruption-ack"), "ack").expect("acknowledge interruption");
            true
        });
        let outcome = self.execute();
        finished.store(true, Ordering::Relaxed);
        assert!(
            notifier.join().expect("interruption notifier"),
            "matrix ended before the interruption barrier: {outcome:?}; results={}",
            self.runner.report.document["results"]
        );
        outcome
    }
}

#[test]
fn prerequisites_precede_applications_and_the_final_prepared_guest_stays_running() {
    let mut fixture = Fixture::new("success", true);
    fixture.execute().expect("complete the fixture matrix");
    let events = fixture.events();
    let first_application = events
        .iter()
        .position(|event| event.starts_with("start "))
        .expect("first application lifecycle");
    for id in ["primary", "secondary"] {
        let admitted = events
            .iter()
            .position(|event| event == &format!("admit {RUN_ID}-{id}"))
            .expect("prerequisite pass admits the guest");
        assert!(admitted < first_application, "{id} prerequisites ran late");
        assert_eq!(
            events
                .iter()
                .filter(|event| *event == &format!("power-start {RUN_ID}-{id}"))
                .count(),
            if id == "primary" { 2 } else { 1 },
            "only the earlier guest parks and restarts; the final guest stays running"
        );
        assert_eq!(fixture.result(id)["phase"], "application");
        assert_eq!(fixture.result(id)["error"], Value::Null);
        assert_eq!(fixture.result(id)["cleanup_error"], Value::Null);
        assert_eq!(fixture.result(id)["diagnostic_errors"], json!([]));
    }
    assert!(
        !events
            .iter()
            .any(|event| event.starts_with("overlapping-start "))
    );
    assert!(
        !fixture
            .temp
            .path()
            .join("state")
            .read_dir()
            .expect("fake state")
            .any(|entry| entry
                .expect("fake state entry")
                .path()
                .join("running")
                .exists())
    );
}

#[test]
fn required_prerequisite_failure_suppresses_applications_and_cleans_all_created_vms() {
    let mut fixture = Fixture::new("prerequisite-failure", true);
    fixture
        .execute()
        .expect_err("required prerequisites must block the matrix");
    let events = fixture.events();
    assert!(!events.iter().any(|event| event.starts_with("start ")));
    for id in ["primary", "secondary"] {
        assert!(events.contains(&format!("delete {RUN_ID}-{id}")));
        assert_eq!(fixture.result(id)["cleanup_error"], Value::Null);
        assert_eq!(fixture.result(id)["diagnostic_errors"], json!([]));
        assert!(fixture.result(id)["error"].is_string());
        assert!(
            !fixture
                .temp
                .path()
                .join("state")
                .join(format!("{RUN_ID}-{id}"))
                .exists()
        );
    }
    assert_eq!(fixture.result("primary")["phase"], "provisioning");
    assert_eq!(fixture.result("secondary")["phase"], "provisioning");
}

#[test]
fn advisory_prerequisite_and_application_failures_warn_without_blocking_required_coverage() {
    for scenario in [
        "image-failure",
        "prerequisite-failure",
        "application-failure",
    ] {
        let mut fixture = Fixture::new(scenario, false);
        fixture.execute().expect("advisory failure is nonblocking");
        assert_eq!(fixture.result("primary")["phase"], "application");
        assert_eq!(fixture.result("primary")["error"], Value::Null);
        assert!(
            fixture
                .events()
                .contains(&format!("start {RUN_ID}-primary"))
        );
        assert!(fixture.result("secondary")["error"].is_string());
        assert_eq!(
            fixture.result("secondary")["phase"],
            if scenario == "application-failure" {
                "application"
            } else {
                "provisioning"
            }
        );
        let warnings = fixture.runner.report.document["warnings"]
            .as_array()
            .expect("advisory warnings");
        assert_eq!(warnings.len(), 1);
        assert!(
            warnings[0]
                .as_str()
                .expect("warning text")
                .contains("secondary")
        );
        assert_eq!(fixture.result("secondary")["required"], false);
        assert_eq!(fixture.result("secondary")["cleanup_error"], Value::Null);
        let events = fixture.events();
        assert!(events.contains(&format!("delete {RUN_ID}-primary")));
        if scenario == "image-failure" {
            assert!(events.contains(&format!("image-failure {RUN_ID}-secondary")));
            assert!(!events.contains(&format!("delete {RUN_ID}-secondary")));
        } else {
            assert!(events.contains(&format!("delete {RUN_ID}-secondary")));
        }
    }
}

#[test]
fn required_application_failure_and_advisory_cleanup_failure_block_matrix_success() {
    for (scenario, required) in [("application-failure", true), ("cleanup-failure", false)] {
        let mut fixture = Fixture::new(scenario, required);
        fixture
            .execute()
            .expect_err("required application or any cleanup failure must block");
        assert_eq!(fixture.result("primary")["error"], Value::Null);
        if scenario == "cleanup-failure" {
            assert!(fixture.result("secondary")["cleanup_error"].is_string());
        } else {
            assert!(fixture.result("secondary")["error"].is_string());
        }
        assert!(
            fixture
                .events()
                .contains(&format!("delete {RUN_ID}-secondary"))
        );
    }
}

#[test]
fn filtered_success_does_not_claim_the_configured_release_gate_passed() {
    let fixture = Fixture::new("success", true);
    let primary =
        json!({"distro":"primary","error":null,"cleanup_error":null,"diagnostic_errors":[]});
    let secondary =
        json!({"distro":"secondary","error":null,"cleanup_error":null,"diagnostic_errors":[]});
    assert!(!configured_release_passed(
        &fixture.config,
        std::slice::from_ref(&primary)
    ));
    assert!(configured_release_passed(
        &fixture.config,
        &[primary, secondary]
    ));
}

#[test]
fn interruption_cleans_parked_targets_and_cannot_pass_incomplete_coverage() {
    for (scenario, result_count) in [("interrupt-first", 1), ("interrupt-second", 2)] {
        let mut fixture = Fixture::new(scenario, true);
        fixture
            .interrupt_during_preparation()
            .expect_err("interrupted matrix cannot pass");
        assert!(fixture.runner.cancelled.load(Ordering::Relaxed));
        let results = fixture.runner.report.document["results"]
            .as_array()
            .expect("interrupted target results");
        assert_eq!(results.len(), result_count);
        let events = fixture.events();
        assert!(!events.iter().any(|event| event.starts_with("start ")));
        for result in results {
            let id = result["distro"].as_str().expect("target ID");
            assert!(events.contains(&format!("admit {RUN_ID}-{id}")));
            assert!(events.contains(&format!("delete {RUN_ID}-{id}")));
            assert_eq!(result["cleanup_error"], Value::Null);
            if scenario == "interrupt-second" && id == "primary" {
                assert_eq!(
                    result["diagnostic_errors"],
                    json!([
                        "VM metadata: stopped guest was not restarted during interrupted cleanup"
                    ])
                );
                assert_eq!(
                    events
                        .iter()
                        .filter(|event| **event == format!("power-start {RUN_ID}-{id}"))
                        .count(),
                    1
                );
            } else {
                assert_eq!(result["diagnostic_errors"], json!([]));
            }
        }
        assert!(
            !fixture
                .temp
                .path()
                .join("state")
                .read_dir()
                .expect("fake state")
                .any(|entry| entry
                    .expect("fake state entry")
                    .path()
                    .join("running")
                    .exists())
        );
    }
}

#[test]
fn two_workers_overlap_without_a_third_running_vm_and_preserve_the_prerequisite_barrier() {
    let mut fixture = Fixture::new("concurrent", true);
    fixture.parallelism(2);
    let mut tertiary = fixture.config.distros[0].clone();
    tertiary.id = "tertiary".into();
    fixture.config.distros.push(tertiary);

    fixture
        .execute()
        .expect("complete three targets with two workers");

    let events = fixture.events();
    let first_application = events
        .iter()
        .position(|event| event.starts_with("start "))
        .expect("application lifecycle");
    for id in ["primary", "secondary", "tertiary"] {
        let admitted = events
            .iter()
            .position(|event| event == &format!("admit {RUN_ID}-{id}"))
            .expect("target admitted before applications");
        assert!(admitted < first_application, "{id} admission ran late");
        assert_eq!(fixture.result(id)["error"], Value::Null);
        assert_eq!(fixture.result(id)["cleanup_error"], Value::Null);
        assert_eq!(fixture.result(id)["diagnostic_errors"], json!([]));
    }
    let running = events
        .iter()
        .filter_map(|event| event.strip_prefix("running-count "))
        .map(|count| count.parse::<usize>().expect("running VM count"))
        .collect::<Vec<_>>();
    assert!(running.contains(&2), "both workers must actually overlap");
    assert!(running.iter().all(|count| *count <= 2));
    assert!(
        !events
            .iter()
            .any(|event| event.starts_with("overlapping-start "))
    );
    assert_eq!(fixture.runner.report.document["release_gate_passed"], true);
    assert_eq!(
        fixture.runner.report.document["all_selected_targets_passed"],
        true
    );
}

#[test]
fn a_successful_guest_without_check_markers_cannot_qualify_the_matrix() {
    let mut fixture = Fixture::new("missing-checks", true);
    fixture
        .execute()
        .expect_err("missing lifecycle checks must fail");

    for id in ["primary", "secondary"] {
        assert!(
            fixture.result(id)["error"]
                .as_str()
                .expect("guest-check contract failure")
                .contains("guest check inventory mismatch")
        );
        assert_eq!(fixture.result(id)["cleanup_error"], Value::Null);
    }
    assert_eq!(fixture.runner.report.document["release_gate_passed"], false);
    assert_eq!(
        fixture.runner.report.document["all_selected_targets_passed"],
        false
    );
}

#[test]
fn advisory_diagnostic_failure_is_visible_and_does_not_qualify_all_targets() {
    let mut fixture = Fixture::new("diagnostics-failure", false);
    fixture.execute().expect("required coverage still passes");

    assert_eq!(fixture.result("secondary")["error"], Value::Null);
    assert_eq!(
        fixture.result("secondary")["diagnostic_errors"]
            .as_array()
            .expect("diagnostic failures")
            .len(),
        1
    );
    assert_eq!(fixture.runner.report.document["release_gate_passed"], true);
    assert_eq!(
        fixture.runner.report.document["all_selected_targets_passed"],
        false
    );
    let summary = read_text(&fixture.runner.dir.join("summary.txt")).expect("summary");
    assert!(!summary.contains("secondary: PASS"));
    let host = fixture.runner.evidence().join("secondary/host-diagnostics");
    assert_eq!(
        read_text(&host.join("console.log")).expect("serial log"),
        "serial boot evidence\n"
    );
    assert_eq!(
        read_text(&host.join("qemu.log")).expect("runtime log"),
        "QEMU boot evidence\n"
    );
    let events = fixture.events();
    let deleted = events
        .iter()
        .position(|event| event == &format!("delete {RUN_ID}-secondary"))
        .expect("guest deleted");
    for event in ["serial-log", "runtime-log"] {
        assert!(
            events
                .iter()
                .position(|value| value == &format!("{event} {RUN_ID}-secondary"))
                .expect("host evidence")
                < deleted
        );
    }
}

#[test]
fn unsupported_vm_console_warns_without_failing_coverage_or_cleanup() {
    let mut fixture = Fixture::new("console-unsupported", true);
    fixture
        .execute()
        .expect("valid lifecycle and required runtime diagnostics pass");
    assert_eq!(fixture.runner.report.document["release_gate_passed"], true);
    assert_eq!(
        fixture.runner.report.document["all_selected_targets_passed"],
        true
    );
    assert_eq!(
        fixture.runner.report.document["warnings"]
            .as_array()
            .expect("warnings")
            .len(),
        2
    );
    for id in ["primary", "secondary"] {
        assert_eq!(fixture.result(id)["diagnostic_errors"], json!([]));
        assert_eq!(fixture.result(id)["cleanup_error"], Value::Null);
        assert_eq!(
            fixture.result(id)["diagnostic_warnings"]
                .as_array()
                .expect("target warning")
                .len(),
            1
        );
        let host = fixture.runner.evidence().join(id).join("host-diagnostics");
        assert_eq!(
            read_text(&host.join("qemu.log")).expect("required runtime log"),
            "QEMU boot evidence\n"
        );
        assert!(
            !fixture
                .temp
                .path()
                .join(format!("state/{RUN_ID}-{id}"))
                .exists()
        );
    }
    let summary = read_text(&fixture.runner.dir.join("summary.txt")).expect("summary");
    assert!(summary.contains("primary: PASS"));
    assert!(summary.contains("does not support saved serial-console logs for VMs"));
    assert!(summary.contains("diagnostic_warnings:"));
}

#[test]
fn host_diagnostic_failure_preserves_partial_evidence_and_still_cleans_guests() {
    let mut fixture = Fixture::new("host-diagnostics-failure", false);
    fixture.execute().expect("required target passed");
    let result = fixture.result("secondary");
    assert!(
        result["error"]
            .as_str()
            .expect("agent failure")
            .contains("255")
    );
    assert_eq!(result["cleanup_error"], Value::Null);
    assert!(
        result["diagnostic_errors"]
            .as_array()
            .expect("diagnostic errors")
            .iter()
            .any(|error| error
                .as_str()
                .expect("error text")
                .contains("runtime qemu.log"))
    );
    let host = fixture.runner.evidence().join("secondary/host-diagnostics");
    assert_eq!(
        read_text(&host.join("qemu.log")).expect("partial runtime log"),
        "runtime log unavailable\n"
    );
    crate::archive_evidence(&mut fixture.runner).expect("archive partial diagnostics");
    let archived = std::process::Command::new("tar")
        .args(["-xOzf"])
        .arg(fixture.runner.dir.join("evidence.tar.gz"))
        .arg("./secondary/host-diagnostics/console.log")
        .output()
        .expect("read archived serial log");
    assert!(archived.status.success());
    assert_eq!(archived.stdout, b"serial boot evidence\n");
}

#[test]
fn retained_failed_guests_are_stopped_before_releasing_worker_slots() {
    let mut fixture = Fixture::new("application-failure", true);
    fixture.parallelism(2);
    fixture
        .execute_with_keep_failed(true)
        .expect_err("required application failed");

    let retained = fixture
        .temp
        .path()
        .join(format!("state/{RUN_ID}-secondary"));
    assert!(retained.is_dir());
    assert!(!retained.join("running").exists());
    assert!(
        fixture
            .events()
            .contains(&format!("park {RUN_ID}-secondary")),
        "retained guest must be explicitly stopped"
    );
    assert_eq!(fixture.result("secondary")["cleanup_error"], Value::Null);
    assert!(
        !fixture
            .temp
            .path()
            .join(format!("state/{RUN_ID}-primary"))
            .exists()
    );
}

#[test]
fn deletion_and_stop_failure_cancel_before_any_parked_guest_restarts() {
    let mut fixture = Fixture::new("cleanup-and-stop-failure", false);
    fixture
        .execute()
        .expect_err("an owned guest that cannot be removed or stopped must block the run");

    assert!(fixture.runner.cancelled.load(Ordering::Relaxed));
    let events = fixture.events();
    assert!(events.contains(&format!("stop-failure {RUN_ID}-secondary")));
    assert!(events.contains(&format!("start {RUN_ID}-secondary")));
    assert!(
        !events.contains(&format!("start {RUN_ID}-primary")),
        "the parked required target must not begin application checks"
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| *event == &format!("power-start {RUN_ID}-primary"))
            .count(),
        1,
        "cancellation must not restart a parked guest for diagnostics"
    );
    assert!(
        !events
            .iter()
            .any(|event| event.starts_with("overlapping-start ")),
        "failed cleanup must not release an occupied running-VM slot"
    );
    assert!(fixture.result("secondary")["cleanup_error"].is_string());
    assert!(fixture.result("primary")["error"].is_string());
    assert_eq!(
        fixture.runner.report.document["all_selected_targets_passed"],
        false
    );
}

#[test]
fn concurrent_interruption_stays_sticky_through_both_workers_cleanup() {
    let mut fixture = Fixture::new("interrupt-both", true);
    fixture.parallelism(2);
    fixture
        .interrupt_during_preparation()
        .expect_err("interrupted concurrent preparation cannot pass");

    assert!(fixture.runner.cancelled.load(Ordering::Relaxed));
    let events = fixture.events();
    assert!(events.contains(&"running-count 2".to_owned()));
    assert!(!events.iter().any(|event| event.starts_with("start ")));
    for id in ["primary", "secondary"] {
        assert!(events.contains(&format!("delete {RUN_ID}-{id}")));
        assert_eq!(fixture.result(id)["cleanup_error"], Value::Null);
        assert!(
            !fixture
                .temp
                .path()
                .join(format!("state/{RUN_ID}-{id}"))
                .exists()
        );
    }
}
