#![cfg(unix)]

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

const CURRENT_VERSION: &str = "0.11.1";
const RELEASE_VERSION: &str = "0.12.0";
const RELEASE_TAG: &str = "v0.12.0";
const FIXTURE_LOG_READ_LIMIT: usize = 1024 * 1024;
const REPOSITORY_LOCAL_GIT_ENV_VARS: [&str; 9] = [
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_DIR",
    "GIT_GRAFT_FILE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_PREFIX",
    "GIT_SHALLOW_FILE",
    "GIT_WORK_TREE",
];

fn read_to_string_with_limit(path: &Path, limit: usize) -> String {
    let file = fs::File::open(path).expect("open bounded fixture file");
    assert!(
        file.metadata().expect("fixture metadata").len()
            <= u64::try_from(limit).expect("read limit fits u64"),
        "fixture exceeds {limit} byte read limit: {}",
        path.display()
    );
    let mut contents = String::new();
    file.take(u64::try_from(limit).expect("read limit fits u64"))
        .read_to_string(&mut contents)
        .expect("read bounded UTF-8 fixture file");
    contents
}

fn publisher_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/publish-release.sh")
}

fn write_executable(path: &Path, contents: &str) {
    fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    fs::write(path, contents).expect("write executable");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("chmod");
}

fn clear_repository_local_git_env(command: &mut Command) {
    for variable in REPOSITORY_LOCAL_GIT_ENV_VARS {
        command.env_remove(variable);
    }
}

fn run_git_at(path: &Path, args: &[&str]) -> Output {
    let mut command = Command::new("/usr/bin/git");
    command.args(args).current_dir(path);
    clear_repository_local_git_env(&mut command);
    command.output().expect("run git")
}

fn assert_success(output: &Output, context: &str) {
    assert!(
        output.status.success(),
        "{context} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

struct ReleaseFixture {
    _temp: TempDir,
    repo: PathBuf,
    remote: PathBuf,
    fake_bin: PathBuf,
    git_log: PathBuf,
    just_log: PathBuf,
}

impl ReleaseFixture {
    fn new() -> Self {
        let temp = TempDir::new().expect("tempdir");
        let repo = temp.path().join("repo");
        let remote = temp.path().join("origin.git");
        let fake_bin = temp.path().join("fake-bin");
        let git_log = temp.path().join("git.log");
        let just_log = temp.path().join("just.log");
        fs::create_dir_all(&repo).expect("mkdir repo");

        assert_success(
            &run_git_at(
                temp.path(),
                &["init", "--bare", remote.to_str().expect("remote path")],
            ),
            "init bare origin",
        );
        assert_success(&run_git_at(&repo, &["init", "-b", "main"]), "init repo");
        assert_success(
            &run_git_at(&repo, &["config", "user.name", "Kidobo Test"]),
            "configure user name",
        );
        assert_success(
            &run_git_at(&repo, &["config", "user.email", "kidobo@example.test"]),
            "configure user email",
        );

        fs::create_dir_all(repo.join("release-notes")).expect("mkdir release notes");
        fs::write(
            repo.join("Cargo.toml"),
            format!("[package]\nname = \"kidobo\"\nversion = \"{CURRENT_VERSION}\"\n"),
        )
        .expect("write Cargo.toml");
        fs::write(repo.join("Cargo.lock"), "# fixture lockfile\n").expect("write lockfile");
        fs::write(
            repo.join("README.md"),
            format!("install --version v{CURRENT_VERSION}\n"),
        )
        .expect("write README");
        fs::write(
            repo.join("release-notes/unreleased.md"),
            "- Test release behavior.\n",
        )
        .expect("write unreleased notes");
        fs::write(repo.join("release-notes/dates.tsv"), "").expect("write dates");
        fs::write(repo.join("CHANGELOG.md"), "# Changelog\n").expect("write changelog");
        fs::copy(publisher_path(), repo.join("publish-release.sh")).expect("copy publisher");

        assert_success(&run_git_at(&repo, &["add", "."]), "stage fixture");
        assert_success(
            &run_git_at(&repo, &["commit", "-m", "Initial fixture"]),
            "commit fixture",
        );
        assert_success(
            &run_git_at(
                &repo,
                &[
                    "remote",
                    "add",
                    "origin",
                    remote.to_str().expect("remote path"),
                ],
            ),
            "add origin",
        );
        assert_success(
            &run_git_at(&repo, &["push", "-u", "origin", "main"]),
            "push initial main",
        );

        write_executable(
            &fake_bin.join("git"),
            r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${KIDOBO_TEST_GIT_LOG}"
exec "${KIDOBO_TEST_REAL_GIT}" "$@"
"#,
        );
        write_executable(
            &fake_bin.join("cargo"),
            "#!/usr/bin/env bash\nset -euo pipefail\nexit 0\n",
        );
        write_executable(
            &fake_bin.join("just"),
            r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${KIDOBO_TEST_JUST_LOG}"
if [[ "${KIDOBO_TEST_FAIL_VERIFY_RELEASE:-0}" == "1" && "$*" == "verify-release" ]]; then
  echo "injected release readiness failure" >&2
  exit 19
fi
if [[ -n "${KIDOBO_TEST_READY_MARKER:-}" && "$*" == "ci" ]]; then
  : > "${KIDOBO_TEST_READY_MARKER}"
fi
exit 0
"#,
        );

        Self {
            _temp: temp,
            repo,
            remote,
            fake_bin,
            git_log,
            just_log,
        }
    }

    fn git(&self, args: &[&str]) -> Output {
        run_git_at(&self.repo, args)
    }

    fn git_success(&self, args: &[&str], context: &str) {
        assert_success(&self.git(args), context);
    }

    fn head(&self) -> String {
        let output = self.git(&["rev-parse", "HEAD"]);
        assert_success(&output, "read HEAD");
        String::from_utf8(output.stdout)
            .expect("UTF-8 HEAD")
            .trim()
            .to_string()
    }

    fn branch(&self) -> String {
        let output = self.git(&["branch", "--show-current"]);
        assert_success(&output, "read branch");
        String::from_utf8(output.stdout)
            .expect("UTF-8 branch")
            .trim()
            .to_string()
    }

    fn tag_exists(&self) -> bool {
        self.git(&["rev-parse", "--verify", "--quiet", RELEASE_TAG])
            .status
            .success()
    }

    fn publisher_command(&self) -> Command {
        let mut command = Command::new(self.repo.join("publish-release.sh"));
        let path = match std::env::var("PATH") {
            Ok(existing) if !existing.is_empty() => {
                format!("{}:{existing}", self.fake_bin.display())
            }
            _ => self.fake_bin.display().to_string(),
        };
        command
            .arg(RELEASE_VERSION)
            .current_dir(&self.repo)
            .env("PATH", path)
            .env("KIDOBO_TEST_GIT_LOG", &self.git_log)
            .env("KIDOBO_TEST_JUST_LOG", &self.just_log)
            .env("KIDOBO_TEST_REAL_GIT", "/usr/bin/git");
        clear_repository_local_git_env(&mut command);
        command
    }

    fn run_publisher(&self, confirmation: &str) -> Output {
        let mut child = self
            .publisher_command()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn publisher");
        child
            .stdin
            .take()
            .expect("publisher stdin")
            .write_all(confirmation.as_bytes())
            .expect("write confirmation");
        child.wait_with_output().expect("wait for publisher")
    }

    fn run_after_validation<F>(&self, action: F) -> Output
    where
        F: FnOnce(),
    {
        let ready = self
            .repo
            .parent()
            .expect("fixture parent")
            .join("validation-ready");
        let mut child = self
            .publisher_command()
            .env("KIDOBO_TEST_READY_MARKER", &ready)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn publisher");
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() {
            assert!(
                Instant::now() < deadline,
                "publisher did not reach the final validation gate"
            );
            thread::sleep(Duration::from_millis(10));
        }
        action();
        child
            .stdin
            .take()
            .expect("publisher stdin")
            .write_all(b"y\n")
            .expect("confirm release");
        child.wait_with_output().expect("wait for publisher")
    }

    fn advance_origin_main(&self, clone_name: &str) {
        let clone = self.repo.parent().expect("fixture parent").join(clone_name);
        assert_success(
            &run_git_at(
                self.repo.parent().expect("fixture parent"),
                &[
                    "clone",
                    "--quiet",
                    "--branch",
                    "main",
                    self.remote.to_str().expect("remote path"),
                    clone.to_str().expect("clone path"),
                ],
            ),
            "clone origin",
        );
        assert_success(
            &run_git_at(&clone, &["config", "user.name", "Remote Test"]),
            "configure clone name",
        );
        assert_success(
            &run_git_at(&clone, &["config", "user.email", "remote@example.test"]),
            "configure clone email",
        );
        fs::write(clone.join("remote-change"), clone_name).expect("write remote change");
        assert_success(&run_git_at(&clone, &["add", "."]), "stage remote change");
        assert_success(
            &run_git_at(&clone, &["commit", "-m", "Advance remote"]),
            "commit remote change",
        );
        assert_success(
            &run_git_at(&clone, &["push", "origin", "main"]),
            "push remote change",
        );
    }
}

#[test]
fn publisher_script_has_valid_bash_syntax() {
    let status = Command::new("bash")
        .arg("-n")
        .arg(publisher_path())
        .status()
        .expect("check publisher syntax");
    assert!(status.success());
}

#[test]
fn publisher_fixture_clears_repository_local_git_environment() {
    let fixture = ReleaseFixture::new();
    let command = fixture.publisher_command();
    let environment = command.get_envs().collect::<Vec<_>>();

    for variable in REPOSITORY_LOCAL_GIT_ENV_VARS {
        assert!(
            environment
                .iter()
                .any(|(key, value)| { key == &std::ffi::OsStr::new(variable) && value.is_none() }),
            "publisher command did not clear {variable}"
        );
    }
}

#[test]
fn publisher_requires_exactly_one_version() {
    let output = Command::new(publisher_path())
        .output()
        .expect("run publisher without version");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Usage:"));
}

#[test]
fn publisher_rejects_invalid_version_before_repository_changes() {
    let output = Command::new(publisher_path())
        .arg("release-0.11.0")
        .output()
        .expect("run publisher with invalid version");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("expected X.Y.Z or vX.Y.Z"));
}

#[test]
fn publisher_rejects_a_dirty_worktree_before_switching_or_fetching() {
    let fixture = ReleaseFixture::new();
    fs::write(fixture.repo.join("dirty"), "dirty").expect("dirty worktree");

    let output = fixture.run_publisher("n\n");

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("requires a clean worktree"));
    let log = read_to_string_with_limit(&fixture.git_log, FIXTURE_LOG_READ_LIMIT);
    assert!(!log.contains("switch main"));
    assert!(!log.contains("fetch --quiet"));
}

#[test]
fn publisher_stops_before_release_preparation_when_readiness_fails() {
    let fixture = ReleaseFixture::new();
    let original_head = fixture.head();
    let output = fixture
        .publisher_command()
        .env("KIDOBO_TEST_FAIL_VERIFY_RELEASE", "1")
        .output()
        .expect("run publisher with failing readiness gate");

    assert_eq!(output.status.code(), Some(19));
    assert!(String::from_utf8_lossy(&output.stderr).contains("injected release readiness failure"));
    assert_eq!(fixture.head(), original_head);
    assert!(!fixture.tag_exists());

    let just_log = read_to_string_with_limit(&fixture.just_log, FIXTURE_LOG_READ_LIMIT);
    assert_eq!(
        just_log.lines().collect::<Vec<_>>(),
        [
            "_install-deny _install-audit _install-coverage",
            "verify-release"
        ]
    );
    let git_log = read_to_string_with_limit(&fixture.git_log, FIXTURE_LOG_READ_LIMIT);
    assert!(
        !git_log
            .lines()
            .any(|line| line.starts_with("worktree add "))
    );
    assert!(!git_log.lines().any(|line| line.starts_with("commit ")));
    assert!(!git_log.lines().any(|line| line.starts_with("tag -a ")));
    assert!(
        !git_log
            .lines()
            .any(|line| line.starts_with("push --atomic "))
    );

    let manifest =
        read_to_string_with_limit(&fixture.repo.join("Cargo.toml"), FIXTURE_LOG_READ_LIMIT);
    assert!(manifest.contains(&format!("version = \"{CURRENT_VERSION}\"")));
    assert!(!manifest.contains(&format!("version = \"{RELEASE_VERSION}\"")));
}

#[test]
fn publisher_cancel_restores_the_original_branch_and_leaves_no_release_state() {
    let fixture = ReleaseFixture::new();
    fixture.git_success(&["switch", "-c", "feature"], "create feature branch");
    let original_head = fixture.head();

    let output = fixture.run_publisher("n\n");

    assert!(output.status.success());
    assert_eq!(fixture.branch(), "feature");
    assert_eq!(fixture.head(), original_head);
    assert!(!fixture.tag_exists());
    assert!(fixture.git(&["status", "--porcelain"]).stdout.is_empty());
    let log = read_to_string_with_limit(&fixture.git_log, FIXTURE_LOG_READ_LIMIT);
    assert!(log.contains("switch main"));
    assert!(log.contains("switch --quiet feature"));
}

#[test]
fn publisher_rejects_behind_and_diverged_main() {
    for scenario in ["behind", "diverged"] {
        let fixture = ReleaseFixture::new();
        let base = fixture.head();
        fs::write(fixture.repo.join("remote-source"), scenario).expect("write remote source");
        fixture.git_success(&["add", "."], "stage remote source");
        fixture.git_success(&["commit", "-m", "Remote source"], "commit remote source");
        fixture.git_success(&["push", "origin", "main"], "push remote source");
        fixture.git_success(&["reset", "--hard", &base], "reset local main");
        if scenario == "diverged" {
            fs::write(fixture.repo.join("local-source"), scenario).expect("write local source");
            fixture.git_success(&["add", "."], "stage local source");
            fixture.git_success(&["commit", "-m", "Local source"], "commit local source");
        }

        let output = fixture.run_publisher("n\n");

        assert_eq!(
            output.status.code(),
            Some(1),
            "{scenario} main was accepted"
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("must not be behind or diverged"));
        assert!(!fixture.tag_exists());
    }
}

#[test]
fn publisher_rejects_existing_local_and_remote_tags() {
    for location in ["local", "remote"] {
        let fixture = ReleaseFixture::new();
        fixture.git_success(&["tag", RELEASE_TAG], "create release tag");
        if location == "remote" {
            fixture.git_success(&["push", "origin", RELEASE_TAG], "push release tag");
            fixture.git_success(&["tag", "--delete", RELEASE_TAG], "delete local tag");
        }

        let output = fixture.run_publisher("n\n");

        assert_eq!(output.status.code(), Some(1), "{location} tag was accepted");
        assert!(String::from_utf8_lossy(&output.stderr).contains("tag already exists"));
    }
}

#[test]
fn publisher_rolls_back_the_tag_when_original_worktree_changes() {
    let fixture = ReleaseFixture::new();
    let original_head = fixture.head();
    let output = fixture.run_after_validation(|| {
        fs::write(fixture.repo.join("external-change"), "preserve").expect("external change");
    });

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("worktree changed"));
    assert_eq!(fixture.head(), original_head);
    assert!(!fixture.tag_exists());
    assert!(fixture.repo.join("external-change").exists());
}

#[test]
fn publisher_rolls_back_the_tag_when_origin_changes_during_validation() {
    let fixture = ReleaseFixture::new();
    let original_head = fixture.head();
    let output = fixture.run_after_validation(|| fixture.advance_origin_main("late-origin"));

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("origin/main changed"));
    assert_eq!(fixture.head(), original_head);
    assert!(!fixture.tag_exists());
}

#[test]
fn publisher_pushes_main_and_tag_with_one_exact_atomic_refspec() {
    let fixture = ReleaseFixture::new();
    let original_head = fixture.head();

    let output = fixture.run_publisher("y\n");

    assert!(
        output.status.success(),
        "publisher failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let release_head = fixture.head();
    assert_ne!(release_head, original_head);
    assert!(fixture.tag_exists());
    let log = read_to_string_with_limit(&fixture.git_log, FIXTURE_LOG_READ_LIMIT);
    let expected_push = format!(
        "push --atomic origin {release_head}:refs/heads/main refs/tags/{RELEASE_TAG}:refs/tags/{RELEASE_TAG}"
    );
    assert!(
        log.lines().any(|line| line == expected_push),
        "missing exact atomic push `{expected_push}` in: {log}"
    );
    let remote_main = run_git_at(&fixture.remote, &["rev-parse", "refs/heads/main"]);
    assert_success(&remote_main, "read remote main");
    assert_eq!(
        String::from_utf8(remote_main.stdout)
            .expect("UTF-8 remote main")
            .trim(),
        release_head
    );
}
