#![cfg(unix)]

use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

fn read_fixture(path: impl AsRef<Path>) -> std::io::Result<String> {
    let file = fs::File::open(path)?;
    assert!(
        file.metadata()?.len() <= 64 * 1024,
        "fixture log is too large"
    );
    let mut text = String::new();
    file.take(64 * 1024).read_to_string(&mut text)?;
    Ok(text)
}

fn executable(path: &Path, text: &str) {
    fs::write(path, text).expect("write fixture");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("executable fixture");
}

struct Fixture {
    root: TempDir,
}

impl Fixture {
    fn new(state: &str, exit: u8) -> Self {
        let root = TempDir::new().expect("fixture directory");
        fs::create_dir(root.path().join("bin")).expect("bin directory");
        fs::write(root.path().join("state"), state).expect("session state");
        fs::write(root.path().join("result"), exit.to_string()).expect("command result");
        executable(
            &root.path().join("bin/just"),
            r#"#!/bin/bash
printf '%s\n' "$@" > "$FIXTURE/arguments"
echo 'candidate stdout'
echo 'candidate stderr' >&2
exit "$(cat "$FIXTURE/result")"
"#,
        );
        executable(
            &root.path().join("bin/tmux"),
            r#"#!/bin/bash
set -eu
case "$1" in
    has-session) [[ "$(cat "$FIXTURE/state")" != absent ]] ;;
    list-panes)
        if [[ "${@: -1}" == '#{pane_id}' ]]; then echo %0
        else
            case "$(cat "$FIXTURE/state")" in
                dead) echo 1 ;;
                mixed) printf '1\n0\n' ;;
                *) echo 0 ;;
            esac
        fi ;;
    capture-pane) echo 'retained failure output' ;;
    kill-session) echo absent > "$FIXTURE/state" ;;
    set-option) printf '%s\n' "${@: -1}" > "$FIXTURE/remain" ;;
    new-session)
        echo active > "$FIXTURE/state"
        shift 6
        set +e
        "$@"
        status=$?
        echo "$status" > "$FIXTURE/pane-status"
        if [[ "$(cat "$FIXTURE/remain")" == off ]]; then
            echo absent > "$FIXTURE/state"
        else
            echo dead > "$FIXTURE/state"
        fi
        exit 0 ;;
    *) exit 99 ;;
esac
"#,
        );
        Self { root }
    }

    fn launch(&self) -> Output {
        Command::new("bash")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/e2e-tmux.sh"))
            .args(["--tag", "literal $(false); value"])
            .env("FIXTURE", self.root.path())
            .env("KIDOBO_E2E_RESULTS_DIR", self.results())
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    self.root.path().join("bin").display(),
                    std::env::var("PATH").expect("PATH")
                ),
            )
            .output()
            .expect("launch fake E2E command")
    }

    fn results(&self) -> PathBuf {
        self.root.path().join("results with spaces")
    }

    fn directory(&self, prefix: &str) -> PathBuf {
        fs::read_dir(self.results())
            .expect("results directory")
            .map(|entry| entry.expect("result entry"))
            .find(|entry| entry.file_name().to_string_lossy().starts_with(prefix))
            .expect("saved launcher output")
            .path()
    }
}

#[test]
fn finished_launches_release_session_and_preserve_output_and_status() {
    for exit in [0, 7] {
        let fixture = Fixture::new("absent", exit);
        let output = fixture.launch();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(
            read_fixture(fixture.root.path().join("state")).unwrap(),
            "absent\n"
        );
        let log = fixture.directory("launcher-");
        assert_eq!(
            read_fixture(log.join("exit-status")).unwrap(),
            format!("{exit}\n")
        );
        let text = read_fixture(log.join("output.log")).unwrap();
        assert!(text.contains("candidate stdout"));
        assert!(text.contains("candidate stderr"));
        assert!(text.contains(&format!("finished with exit status {exit}")));
        assert!(
            read_fixture(fixture.root.path().join("arguments"))
                .unwrap()
                .ends_with("--tag\nliteral $(false); value\n")
        );
        assert!(
            fixture.launch().status.success(),
            "next launch must not need cleanup"
        );
    }
}

#[test]
fn handled_child_signals_release_session_and_keep_final_output() {
    for (signal, exit) in [("INT", 130), ("TERM", 143), ("HUP", 129)] {
        let fixture = Fixture::new("absent", 0);
        executable(
            &fixture.root.path().join("bin/just"),
            &format!(
                "#!/bin/bash\ntrap 'echo handled-{signal}; exit {exit}' {signal}\nkill -{signal} \"$$\"\nexit 99\n"
            ),
        );
        let output = fixture.launch();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(
            read_fixture(fixture.root.path().join("state")).unwrap(),
            "absent\n"
        );
        let log = fixture.directory("launcher-");
        assert_eq!(
            read_fixture(log.join("exit-status")).unwrap(),
            format!("{exit}\n")
        );
        let text = read_fixture(log.join("output.log")).unwrap();
        assert!(text.contains(&format!("handled-{signal}")));
        assert!(text.contains(&format!("finished with exit status {exit}")));
        assert!(fixture.launch().status.success(), "rerun after {signal}");
    }
}

#[test]
fn dead_legacy_session_is_archived_and_replaced() {
    let fixture = Fixture::new("dead", 0);
    let output = fixture.launch();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        read_fixture(fixture.directory("recovered-session-").join("%0.log")).unwrap(),
        "retained failure output\n"
    );
    assert_eq!(
        read_fixture(fixture.root.path().join("state")).unwrap(),
        "absent\n"
    );
}

#[test]
fn any_live_pane_prevents_replacement() {
    for state in ["active", "mixed"] {
        let fixture = Fixture::new(state, 0);
        let output = fixture.launch();
        assert!(!output.status.success());
        assert_eq!(
            read_fixture(fixture.root.path().join("state")).unwrap(),
            state
        );
        assert!(!fixture.root.path().join("arguments").exists());
    }
}
