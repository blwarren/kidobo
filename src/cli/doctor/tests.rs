use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use super::build_doctor_report;
use super::checks::{BinaryLocator, Ipv6Mode, collect_binary_checks, ipv6_skip_reason};
use super::probes::SudoProbeRunner;
use super::{DoctorCheckStatus, DoctorOverall};
use crate::adapters::command_runner::{CommandResult, CommandRunnerError, ProcessStatus};
use crate::adapters::path::{ENV_KIDOBO_ROOT, PathResolutionInput};

struct MockBinaryLocator {
    availability: BTreeMap<String, bool>,
}

impl MockBinaryLocator {
    fn new(available: &[&str]) -> Self {
        let mut availability = BTreeMap::new();
        for binary in available {
            availability.insert((*binary).to_string(), true);
        }
        Self { availability }
    }
}

impl BinaryLocator for MockBinaryLocator {
    fn find_in_path(&self, binary: &str) -> Option<PathBuf> {
        if self.availability.get(binary).copied().unwrap_or(false) {
            Some(PathBuf::from(format!("/mock/bin/{binary}")))
        } else {
            None
        }
    }
}

struct MockProbeRunner {
    responses: RefCell<VecDeque<Result<CommandResult, CommandRunnerError>>>,
    invocations: RefCell<Vec<(String, Vec<String>)>>,
}

impl MockProbeRunner {
    fn new(responses: Vec<Result<CommandResult, CommandRunnerError>>) -> Self {
        Self {
            responses: RefCell::new(VecDeque::from(responses)),
            invocations: RefCell::new(Vec::new()),
        }
    }
}

impl SudoProbeRunner for MockProbeRunner {
    fn run_probe(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
        self.invocations.borrow_mut().push((
            command.to_string(),
            args.iter().map(|value| (*value).to_string()).collect(),
        ));
        self.responses
            .borrow_mut()
            .pop_front()
            .expect("queued probe response")
    }
}

fn path_input_for_root(root: &Path) -> PathResolutionInput {
    let mut env = BTreeMap::new();
    env.insert(ENV_KIDOBO_ROOT.to_string(), root.display().to_string());
    PathResolutionInput {
        explicit_config_path: None,
        temp_dir: root.join("tmp"),
        env,
    }
}

fn write_config(root: &Path, enable_ipv6: bool) {
    let config_dir = root.join("config");
    fs::create_dir_all(&config_dir).expect("mkdir config");
    fs::write(
        config_dir.join("config.toml"),
        format!("[ipset]\nset_name = \"kidobo\"\nenable_ipv6 = {enable_ipv6}\n"),
    )
    .expect("write config");
}

fn write_blocklist(root: &Path) {
    let data_dir = root.join("data");
    fs::create_dir_all(&data_dir).expect("mkdir data");
    fs::write(data_dir.join("blocklist.txt"), "# test\n").expect("write blocklist");
}

#[test]
fn ipv6_skip_reason_matches_mode() {
    assert_eq!(ipv6_skip_reason(Ipv6Mode::Enabled), None);
    assert_eq!(
        ipv6_skip_reason(Ipv6Mode::Disabled),
        Some("ipv6 disabled in config")
    );
    assert_eq!(
        ipv6_skip_reason(Ipv6Mode::Unknown),
        Some("config unavailable; ipv6 state unknown")
    );
}

#[test]
fn collect_binary_checks_skips_ipv6_binary_when_disabled() {
    let locator = MockBinaryLocator::new(&[
        "sudo",
        "bgpq4",
        "ipset",
        "iptables",
        "iptables-save",
        "iptables-restore",
    ]);
    let mut checks = Vec::new();
    let availability = collect_binary_checks(&mut checks, &locator, Ipv6Mode::Disabled);

    assert_eq!(availability.get("ip6tables"), Some(&false));
    assert!(
        checks.iter().any(
            |check| check.name == "binary_ip6tables" && check.status == DoctorCheckStatus::Skip
        )
    );
}

#[test]
fn build_doctor_report_preserves_json_status_shape() {
    let temp = TempDir::new().expect("tempdir");
    write_config(temp.path(), true);
    write_blocklist(temp.path());
    fs::create_dir_all(temp.path().join("cache/remote")).expect("mkdir cache");

    let input = path_input_for_root(temp.path());
    let locator = MockBinaryLocator::new(&[
        "sudo",
        "bgpq4",
        "ipset",
        "iptables",
        "iptables-save",
        "iptables-restore",
        "ip6tables",
    ]);
    let runner = MockProbeRunner::new(vec![
        Ok(success()),
        Ok(success()),
        Ok(success()),
        Ok(success()),
        Ok(success()),
    ]);

    let report = build_doctor_report(&input, &locator, &runner);
    assert_eq!(report.overall, DoctorOverall::Ok);
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.name == "config_parse" && check.status == DoctorCheckStatus::Ok)
    );

    let json = serde_json::to_value(&report).expect("doctor report serializes");
    assert_eq!(json["overall"], "OK");
    assert!(
        json["checks"]
            .as_array()
            .expect("checks is an array")
            .iter()
            .any(|check| check["name"] == "config_parse" && check["status"] == "OK")
    );
}

#[test]
fn build_doctor_report_preserves_json_fail_and_skip_status_shape() {
    let temp = TempDir::new().expect("tempdir");
    write_config(temp.path(), false);
    write_blocklist(temp.path());
    fs::create_dir_all(temp.path().join("cache/remote")).expect("mkdir cache");

    let input = path_input_for_root(temp.path());
    let locator = MockBinaryLocator::new(&[
        "sudo",
        "ipset",
        "iptables",
        "iptables-save",
        "iptables-restore",
    ]);
    let runner = MockProbeRunner::new(vec![
        Ok(success()),
        Ok(success()),
        Ok(success()),
        Ok(success()),
    ]);

    let report = build_doctor_report(&input, &locator, &runner);
    assert_eq!(report.overall, DoctorOverall::Fail);
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.name == "binary_bgpq4" && check.status == DoctorCheckStatus::Fail)
    );
    assert!(
        report.checks.iter().any(
            |check| check.name == "binary_ip6tables" && check.status == DoctorCheckStatus::Skip
        )
    );

    let json = serde_json::to_value(&report).expect("doctor report serializes");
    assert_eq!(json["overall"], "FAIL");
    let checks = json["checks"].as_array().expect("checks is an array");
    assert!(
        checks
            .iter()
            .any(|check| check["name"] == "binary_bgpq4" && check["status"] == "FAIL")
    );
    assert!(
        checks
            .iter()
            .any(|check| check["name"] == "binary_ip6tables" && check["status"] == "SKIP")
    );
}

fn success() -> CommandResult {
    CommandResult {
        status: ProcessStatus::Exited(0),
        stdout: String::new(),
        stderr: String::new(),
    }
}
