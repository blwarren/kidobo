use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use super::provision::render_init_summary;
use super::systemd::{
    InitCommandRunner, ensure_systemd_timer_enabled, resolve_installed_executable_path,
};
use super::templates::{
    DEFAULT_BLOCKLIST_TEMPLATE, DEFAULT_CONFIG_TEMPLATE, DEFAULT_SYSTEMD_DIR,
    DEFAULT_SYSTEMD_TIMER_TEMPLATE, KIDOBO_SYNC_SERVICE_FILE, KIDOBO_SYNC_TIMER_FILE,
    build_systemd_service_template, resolve_systemd_dir,
};
use super::{
    run_init_with_paths, run_init_with_paths_and_runner, run_init_with_paths_with_summary,
};
use crate::adapters::command_runner::{CommandResult, CommandRunnerError, ProcessStatus};
use crate::adapters::limited_io::read_to_string_with_limit;
use crate::adapters::path::ResolvedPaths;
use crate::error::KidoboError;

const INIT_FILE_READ_LIMIT: usize = 256 * 1024;

struct MockInitCommandRunner {
    responses: RefCell<VecDeque<Result<CommandResult, CommandRunnerError>>>,
    invocations: RefCell<Vec<(String, Vec<String>)>>,
}

impl MockInitCommandRunner {
    fn new(responses: Vec<Result<CommandResult, CommandRunnerError>>) -> Self {
        Self {
            responses: RefCell::new(VecDeque::from(responses)),
            invocations: RefCell::new(Vec::new()),
        }
    }

    fn invocations(&self) -> Vec<(String, Vec<String>)> {
        self.invocations.borrow().clone()
    }
}

impl InitCommandRunner for MockInitCommandRunner {
    fn run(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
        self.invocations.borrow_mut().push((
            command.to_string(),
            args.iter().map(|value| (*value).to_string()).collect(),
        ));
        self.responses
            .borrow_mut()
            .pop_front()
            .expect("queued response")
    }
}

fn success_result() -> CommandResult {
    CommandResult {
        status: ProcessStatus::Exited(0),
        stdout: String::new(),
        stderr: String::new(),
    }
}

fn test_paths(root: &Path) -> ResolvedPaths {
    ResolvedPaths {
        config_dir: root.join("config"),
        config_file: root.join("config/config.toml"),
        data_dir: root.join("data"),
        blocklist_file: root.join("data/blocklist.txt"),
        cache_dir: root.join("cache"),
        remote_cache_dir: root.join("cache/remote"),
        lock_file: root.join("cache/sync.lock"),
    }
}

#[test]
fn resolve_systemd_dir_uses_default_or_root_override() {
    assert_eq!(
        resolve_systemd_dir(None),
        PathBuf::from(DEFAULT_SYSTEMD_DIR)
    );
    assert_eq!(
        resolve_systemd_dir(Some(Path::new("/tmp/root"))),
        PathBuf::from("/tmp/root/systemd/system")
    );
}

#[test]
fn build_systemd_service_template_includes_exec_start() {
    let template = build_systemd_service_template(Path::new("/usr/local/bin/kidobo"), None);
    assert!(template.contains("ExecStart=\"/usr/local/bin/kidobo\" sync"));
}

#[test]
fn resolve_installed_executable_path_selects_existing_candidate() {
    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().join("kidobo");
    fs::write(&path, "binary").expect("write");

    let resolved = resolve_installed_executable_path(&[temp.path().join("missing"), path.clone()])
        .expect("resolve");
    assert_eq!(resolved, path);
}

#[test]
fn ensure_systemd_timer_enabled_runs_expected_commands() {
    let runner = MockInitCommandRunner::new(vec![
        Ok(success_result()),
        Ok(success_result()),
        Ok(success_result()),
    ]);

    ensure_systemd_timer_enabled(&runner).expect("enable timer");
    assert_eq!(
        runner.invocations(),
        vec![
            ("systemctl".to_string(), vec!["daemon-reload".to_string()]),
            (
                "systemctl".to_string(),
                vec![
                    "reset-failed".to_string(),
                    KIDOBO_SYNC_SERVICE_FILE.to_string()
                ]
            ),
            (
                "systemctl".to_string(),
                vec![
                    "enable".to_string(),
                    "--now".to_string(),
                    KIDOBO_SYNC_TIMER_FILE.to_string()
                ]
            ),
        ]
    );
}

#[test]
fn ensure_systemd_timer_enabled_propagates_non_zero_exit_as_init_systemd() {
    let runner = MockInitCommandRunner::new(vec![Ok(CommandResult {
        status: ProcessStatus::Exited(1),
        stdout: String::new(),
        stderr: "failed".to_string(),
    })]);

    let err = ensure_systemd_timer_enabled(&runner).expect_err("must fail");
    assert!(matches!(err, KidoboError::InitSystemd { .. }));
}

#[test]
fn run_init_with_paths_creates_expected_files() {
    let temp = TempDir::new().expect("tempdir");
    let paths = test_paths(temp.path());

    run_init_with_paths(&paths).expect("init");

    assert_eq!(
        read_to_string_with_limit(&paths.config_file, INIT_FILE_READ_LIMIT).expect("read config"),
        DEFAULT_CONFIG_TEMPLATE
    );
    assert_eq!(
        read_to_string_with_limit(&paths.blocklist_file, INIT_FILE_READ_LIMIT)
            .expect("read blocklist"),
        DEFAULT_BLOCKLIST_TEMPLATE
    );
}

#[test]
fn run_init_rejects_directory_at_config_file_path() {
    let temp = TempDir::new().expect("tempdir");
    let paths = test_paths(temp.path());
    fs::create_dir_all(&paths.config_file).expect("create blocking directory");

    let err = run_init_with_paths(&paths).expect_err("init must fail");

    match err {
        KidoboError::InitIo { path, reason } => {
            assert_eq!(path, paths.config_file);
            assert_eq!(reason, "path exists but is not a file");
        }
        _ => panic!("expected InitIo"),
    }
}

#[test]
fn run_init_with_paths_with_summary_reports_created_files() {
    let temp = TempDir::new().expect("tempdir");
    let paths = test_paths(temp.path());

    let summary = run_init_with_paths_with_summary(&paths).expect("summary");
    let rendered = render_init_summary(&summary);
    assert!(rendered.contains("init completed:"));
}

#[test]
fn run_init_with_paths_and_runner_skips_systemd_commands_for_root_override() {
    let temp = TempDir::new().expect("tempdir");
    let paths = test_paths(temp.path());
    let runner = MockInitCommandRunner::new(vec![]);

    run_init_with_paths_and_runner(&paths, &runner, Some(temp.path())).expect("init");
    assert!(runner.invocations().is_empty());
}

#[test]
fn init_writes_default_timer_template() {
    assert!(DEFAULT_SYSTEMD_TIMER_TEMPLATE.contains("OnUnitActiveSec=1h"));
}

#[test]
fn init_default_config_includes_remote_cache_staleness() {
    assert!(DEFAULT_CONFIG_TEMPLATE.contains("cache_stale_after_secs = 86400\nurls = []"));
}
