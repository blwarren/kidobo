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
        let program = temp.path().join("fake-incus");
        executable(
            &program,
            r#"#!/bin/bash
set -euo pipefail
state="${0%/*}/state"
scenario=$(<"$state/scenario")
[[ "$1" == --project && "$2" == test-project ]] || exit 90
shift 2
event() { printf '%s %s\n' "$1" "$2" >> "$state/events"; }
describe() {
  status=Stopped
  if [[ -f "$state/running" && $(<"$state/running") == "$1" ]]; then status=Running; fi
  printf '{"name":"%s","type":"virtual-machine","status":"%s","config":{"user.kidobo-e2e":"kidobo-e2e-v1","volatile.base_image":"fake-image"}}' "$1" "$status"
}
case "$1" in
  init)
    vm=$3
    if [[ "$scenario" == image-failure && "$vm" == *-secondary ]]; then
      event image-failure "$vm"
      exit 70
    fi
    mkdir "$state/$vm"
    printf '0\n' > "$state/$vm/boot"
    event create "$vm"
    ;;
  list)
    vm=$2
    printf '['
    if [[ "$vm" == --format=json ]]; then
      separator=""
      for instance in "$state"/run-*; do
        [[ -d "$instance" ]] || continue
        printf '%s' "$separator"
        describe "${instance##*/}"
        separator=,
      done
    elif [[ -d "$state/$vm" ]]; then
      describe "$vm"
    fi
    printf ']\n'
    ;;
  config|file) ;;
  start)
    vm=$2
    if [[ -e "$state/running" ]]; then event overlapping-start "$vm"; exit 91; fi
    printf '%s\n' "$vm" > "$state/running"
    event power-start "$vm"
    ;;
  stop)
    vm=$2
    [[ $(<"$state/running") == "$vm" ]] || exit 92
    rm "$state/running"
    event park "$vm"
    if [[ "$scenario" == interrupt-first && "$vm" == *-primary \
       || "$scenario" == interrupt-second && "$vm" == *-secondary ]]; then
      : > "$state/interruption-ready"
      while [[ ! -e "$state/interruption-ack" ]]; do sleep 0.01; done
    fi
    ;;
  restart)
    vm=$2
    [[ $(<"$state/running") == "$vm" ]] || exit 93
    boot=$(<"$state/$vm/boot")
    printf '%s\n' "$((boot + 1))" > "$state/$vm/boot"
    event reboot "$vm"
    ;;
  delete)
    vm=$2
    event delete "$vm"
    if [[ "$scenario" == cleanup-failure && "$vm" == *-secondary ]]; then exit 72; fi
    if [[ -f "$state/running" && $(<"$state/running") == "$vm" ]]; then rm "$state/running"; fi
    rm -r "$state/$vm"
    ;;
  exec)
    vm=$2
    shift 4
    [[ -f "$state/running" && $(<"$state/running") == "$vm" ]] || exit 94
    case "$1" in
      true|sh|chmod|mkdir|test) ;;
      cat)
        [[ "$2" == /proc/sys/kernel/random/boot_id ]] || exit 95
        cat "$state/$vm/boot"
        ;;
      bash)
        case "$2" in
          -c) printf 'fake guest diagnostics\n' ;;
          /opt/kidobo-e2e/provision.sh)
            if [[ "$3" == --check-kernel ]]; then
              event kernel "$vm"
              if [[ "$scenario" == prerequisite-failure && "$vm" == *-secondary ]]; then exit 70; fi
            else
              event dependencies "$vm"
            fi
            ;;
          /opt/kidobo-e2e/lifecycle.sh)
            event "$3" "$vm"
            if [[ "$3" == start && "$scenario" == application-failure && "$vm" == *-secondary ]]; then exit 71; fi
            ;;
          *) exit 96 ;;
        esac
        ;;
      *) exit 97 ;;
    esac
    ;;
  *) exit 98 ;;
esac
"#,
        );
        let dir = temp.path().join(RUN_ID);
        let report = Report::open(&dir).expect("create matrix report");
        fs::create_dir_all(dir.join(".evidence")).expect("create matrix evidence");
        fs::write(dir.join(".evidence/baseline-tag"), "v0.14.3")
            .expect("write frozen baseline fixture");
        let runner = Runner {
            project: "test-project".into(),
            dir,
            incus_program: program,
            cancelled: Arc::new(AtomicBool::new(false)),
            report,
            command_poll_interval: Duration::from_millis(1),
        };
        let config = Config {
            project: "test-project".into(),
            profile: "test-profile".into(),
            network: "test-network".into(),
            pool: "test-pool".into(),
            cpus: 2,
            memory: "4GiB".into(),
            disk: "30GiB".into(),
            distros: ["primary", "secondary"]
                .into_iter()
                .map(|id| Distro {
                    id: id.into(),
                    image: "fixture/image".into(),
                    family: "apt".into(),
                    packages: vec!["fixture-package".into()],
                    required: id == "primary" || secondary_required,
                })
                .collect(),
        };
        Self {
            temp,
            runner,
            config,
        }
    }

    fn execute(&mut self) -> Result<()> {
        let targets = self.config.distros.iter().collect::<Vec<_>>();
        execute(
            &mut self.runner,
            &self.config,
            RUN_ID,
            &targets,
            "v0.15.0",
            false,
            None,
            false,
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

    fn interrupt_after_parking(&mut self) -> Result<()> {
        let state = self.temp.path().join("state");
        let cancelled = Arc::clone(&self.runner.cancelled);
        let notifier = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(30);
            while !state.join("interruption-ready").exists() {
                assert!(Instant::now() < deadline, "fake VM never reached parking");
                thread::sleep(Duration::from_millis(10));
            }
            cancelled.store(true, Ordering::Relaxed);
            fs::write(state.join("interruption-ack"), "ack").expect("acknowledge interruption");
        });
        let outcome = self.execute();
        notifier.join().expect("interruption notifier");
        outcome
    }
}

#[test]
fn all_prerequisites_precede_applications_with_at_most_one_running_vm() {
    let mut fixture = Fixture::new("success", true);
    fixture.execute().expect("complete the fixture matrix");
    let events = fixture.events();
    let first_application = events
        .iter()
        .position(|event| event == &format!("start {RUN_ID}-primary"))
        .expect("first application lifecycle");
    for id in ["primary", "secondary"] {
        let parked = events
            .iter()
            .position(|event| event == &format!("park {RUN_ID}-{id}"))
            .expect("prerequisite pass parks VM");
        assert!(parked < first_application, "{id} prerequisites ran late");
        assert_eq!(
            events
                .iter()
                .filter(|event| *event == &format!("power-start {RUN_ID}-{id}"))
                .count(),
            2,
            "each VM boots for preparation, parks, and resumes for applications"
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
    assert!(!fixture.temp.path().join("state/running").exists());
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
fn interruption_cleans_parked_targets_and_cannot_pass_incomplete_coverage() {
    for (scenario, result_count) in [("interrupt-first", 1), ("interrupt-second", 2)] {
        let mut fixture = Fixture::new(scenario, true);
        fixture
            .interrupt_after_parking()
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
            assert!(events.contains(&format!("park {RUN_ID}-{id}")));
            assert!(events.contains(&format!("delete {RUN_ID}-{id}")));
            assert_eq!(result["cleanup_error"], Value::Null);
            assert_eq!(result["diagnostic_errors"], json!([]));
        }
        assert!(!fixture.temp.path().join("state/running").exists());
    }
}
