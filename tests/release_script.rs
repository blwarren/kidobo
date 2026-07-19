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
const PRERELEASE_VERSION: &str = "0.12.0-rc.1";
const PRERELEASE_TAG: &str = "v0.12.0-rc.1";
const GITHUB_REPOSITORY: &str = "blwarren/kidobo";
const GITHUB_REMOTE_URL: &str = "https://github.com/blwarren/kidobo.git";
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
    event_log: PathBuf,
    git_log: PathBuf,
    gh_log: PathBuf,
    gh_release_dir: PathBuf,
}

impl ReleaseFixture {
    fn new() -> Self {
        let temp = TempDir::new().expect("tempdir");
        let repo = temp.path().join("repo");
        let remote = temp.path().join("origin.git");
        let fake_bin = temp.path().join("fake-bin");
        let event_log = temp.path().join("events.log");
        let git_log = temp.path().join("git.log");
        let gh_log = temp.path().join("gh.log");
        let gh_release_dir = temp.path().join("github-release");
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
        fs::write(repo.join("LICENSE"), "fixture license\n").expect("write license");
        fs::write(
            repo.join("release-notes/unreleased.md"),
            "- Test release behavior.\n",
        )
        .expect("write unreleased notes");
        fs::write(repo.join("release-notes/dates.tsv"), "").expect("write dates");
        fs::write(repo.join("CHANGELOG.md"), "# Changelog\n").expect("write changelog");
        fs::write(repo.join(".gitignore"), "/target\n").expect("write gitignore");
        fs::copy(publisher_path(), repo.join("publish-release.sh")).expect("copy publisher");

        assert_success(&run_git_at(&repo, &["add", "."]), "stage fixture");
        assert_success(
            &run_git_at(&repo, &["commit", "-m", "Initial fixture"]),
            "commit fixture",
        );
        assert_success(
            &run_git_at(&repo, &["remote", "add", "origin", GITHUB_REMOTE_URL]),
            "add origin",
        );
        let rewrite_key = format!("url.{}.insteadOf", remote.display());
        assert_success(
            &run_git_at(&repo, &["config", &rewrite_key, GITHUB_REMOTE_URL]),
            "configure GitHub URL rewrite",
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
printf 'git %s\n' "$*" >> "${KIDOBO_TEST_EVENT_LOG}"
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
printf 'just %s\n' "$*" >> "${KIDOBO_TEST_EVENT_LOG}"
if [[ -n "${KIDOBO_TEST_READY_MARKER:-}" && "$*" == "exercise-release" ]]; then
  : > "${KIDOBO_TEST_READY_MARKER}"
fi
if [[ "$*" == "exercise-release" ]]; then
  mkdir -p target/release
  printf '#!/usr/bin/env bash\nprintf '\''kidobo %%s\\n'\'' %q\n' \
    "${KIDOBO_TEST_BINARY_VERSION}" > target/release/kidobo
  chmod 0755 target/release/kidobo
fi
exit 0
"#,
        );
        write_executable(
            &fake_bin.join("gh"),
            r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${KIDOBO_TEST_GH_LOG}"
printf 'gh %s\n' "$*" >> "${KIDOBO_TEST_EVENT_LOG}"

if [[ "$1" == "auth" && "$2" == "status" ]]; then
  [[ "${KIDOBO_TEST_FAIL_GH_AUTH:-0}" != "1" ]]
  exit
fi
if [[ "$1" == "repo" && "$2" == "view" ]]; then
  printf '%s\n' "${KIDOBO_TEST_GITHUB_REPOSITORY}"
  exit 0
fi
if [[ "$1" == "release" && "$2" == "view" ]]; then
  if [[ "${KIDOBO_TEST_EXISTING_RELEASE:-0}" == "1" \
      || -e "${KIDOBO_TEST_GH_RELEASE_DIR}/draft" \
      || -e "${KIDOBO_TEST_GH_RELEASE_DIR}/published" ]]; then
    printf 'https://github.com/%s/releases/tag/%s\n' \
      "${KIDOBO_TEST_GITHUB_REPOSITORY}" "$3"
    exit 0
  fi
  exit 1
fi
if [[ "$1" == "release" && "$2" == "create" ]]; then
  if [[ "${KIDOBO_TEST_FAIL_GH_CREATE:-0}" == "1" ]]; then
    echo "injected GitHub release creation failure" >&2
    exit 41
  fi
  mkdir -p "${KIDOBO_TEST_GH_RELEASE_DIR}"
  for argument in "$@"; do
    if [[ -f "${argument}" ]]; then
      case "$(basename "${argument}")" in
        *.tar.gz|SHA256SUMS)
          cp "${argument}" "${KIDOBO_TEST_GH_RELEASE_DIR}/"
          ;;
      esac
    fi
  done
  : > "${KIDOBO_TEST_GH_RELEASE_DIR}/draft"
  exit 0
fi
if [[ "$1" == "release" && "$2" == "download" ]]; then
  if [[ "${KIDOBO_TEST_FAIL_GH_DOWNLOAD:-0}" == "1" ]]; then
    echo "injected GitHub release download failure" >&2
    exit 42
  fi
  destination=""
  while [[ $# -gt 0 ]]; do
    if [[ "$1" == "--dir" ]]; then
      destination="$2"
      shift 2
      continue
    fi
    shift
  done
  mkdir -p "${destination}"
  cp "${KIDOBO_TEST_GH_RELEASE_DIR}"/*.tar.gz \
    "${KIDOBO_TEST_GH_RELEASE_DIR}/SHA256SUMS" "${destination}/"
  if [[ "${KIDOBO_TEST_CORRUPT_DOWNLOAD:-0}" == "1" ]]; then
    printf 'corrupt\n' >> "${destination}"/*.tar.gz
  fi
  exit 0
fi
if [[ "$1" == "release" && "$2" == "edit" ]]; then
  if [[ "${KIDOBO_TEST_FAIL_GH_EDIT:-0}" == "1" ]]; then
    echo "injected GitHub release publication failure" >&2
    exit 43
  fi
  rm -f "${KIDOBO_TEST_GH_RELEASE_DIR}/draft"
  : > "${KIDOBO_TEST_GH_RELEASE_DIR}/published"
  exit 0
fi

echo "unexpected gh invocation: $*" >&2
exit 44
"#,
        );
        write_executable(
            &fake_bin.join("uname"),
            r#"#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == "-s" ]]; then
  printf 'Linux\n'
elif [[ "$1" == "-m" ]]; then
  printf '%s\n' "${KIDOBO_TEST_UNAME_MACHINE:-x86_64}"
else
  exec /usr/bin/uname "$@"
fi
"#,
        );

        Self {
            _temp: temp,
            repo,
            remote,
            fake_bin,
            event_log,
            git_log,
            gh_log,
            gh_release_dir,
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
        self.local_tag_exists(RELEASE_TAG)
    }

    fn local_tag_exists(&self, tag: &str) -> bool {
        self.git(&["rev-parse", "--verify", "--quiet", tag])
            .status
            .success()
    }

    fn remote_tag_exists(&self, tag: &str) -> bool {
        run_git_at(
            &self.remote,
            &[
                "rev-parse",
                "--verify",
                "--quiet",
                &format!("refs/tags/{tag}"),
            ],
        )
        .status
        .success()
    }

    fn artifact_root(&self, tag: &str) -> PathBuf {
        self.repo.join("target/release-artifacts").join(tag)
    }

    fn publisher_command(&self) -> Command {
        self.publisher_command_for(RELEASE_VERSION)
    }

    fn publisher_command_for(&self, version: &str) -> Command {
        let mut command = Command::new(self.repo.join("publish-release.sh"));
        let path = match std::env::var("PATH") {
            Ok(existing) if !existing.is_empty() => {
                format!("{}:{existing}", self.fake_bin.display())
            }
            _ => self.fake_bin.display().to_string(),
        };
        command
            .arg(version)
            .current_dir(&self.repo)
            .env("PATH", path)
            .env("KIDOBO_TEST_EVENT_LOG", &self.event_log)
            .env("KIDOBO_TEST_GIT_LOG", &self.git_log)
            .env("KIDOBO_TEST_GH_LOG", &self.gh_log)
            .env("KIDOBO_TEST_GH_RELEASE_DIR", &self.gh_release_dir)
            .env("KIDOBO_TEST_GITHUB_REPOSITORY", GITHUB_REPOSITORY)
            .env("KIDOBO_TEST_REAL_GIT", "/usr/bin/git")
            .env(
                "KIDOBO_TEST_BINARY_VERSION",
                version.strip_prefix('v').unwrap_or(version),
            );
        clear_repository_local_git_env(&mut command);
        command
    }

    fn run_publisher(&self, confirmation: &str) -> Output {
        self.run_publisher_for(RELEASE_VERSION, confirmation)
    }

    fn run_publisher_for(&self, version: &str, confirmation: &str) -> Output {
        let mut child = self
            .publisher_command_for(version)
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
fn publisher_requires_github_cli() {
    let output = Command::new("/usr/bin/bash")
        .arg(publisher_path())
        .arg(RELEASE_VERSION)
        .env("PATH", "/missing")
        .output()
        .expect("run publisher without GitHub CLI");

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("missing required command: gh"));
}

#[test]
fn publisher_requires_github_authentication_before_repository_changes() {
    let fixture = ReleaseFixture::new();
    let output = fixture
        .publisher_command()
        .env("KIDOBO_TEST_FAIL_GH_AUTH", "1")
        .output()
        .expect("run publisher without GitHub authentication");

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("gh auth login"));
    assert!(!fixture.git_log.exists());
}

#[test]
fn publisher_rejects_a_github_repository_that_does_not_match_origin() {
    let fixture = ReleaseFixture::new();
    let output = fixture
        .publisher_command()
        .env("KIDOBO_TEST_GITHUB_REPOSITORY", "someone/else")
        .output()
        .expect("run publisher with mismatched GitHub repository");

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("does not match origin"));
    assert!(!fixture.tag_exists());
}

#[test]
fn publisher_rejects_non_x86_64_hosts_before_repository_changes() {
    let fixture = ReleaseFixture::new();
    let output = fixture
        .publisher_command()
        .env("KIDOBO_TEST_UNAME_MACHINE", "aarch64")
        .output()
        .expect("run publisher on unsupported architecture");

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Linux x86_64 host"));
    assert!(!fixture.git_log.exists());
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
fn publisher_rejects_an_existing_github_release() {
    let fixture = ReleaseFixture::new();
    let output = fixture
        .publisher_command()
        .env("KIDOBO_TEST_EXISTING_RELEASE", "1")
        .output()
        .expect("run publisher with existing GitHub release");

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("GitHub release already exists"));
    assert!(!fixture.tag_exists());
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
    assert!(!fixture.artifact_root(RELEASE_TAG).exists());
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
fn publisher_atomically_pushes_then_verifies_and_publishes_local_artifacts() {
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
    assert!(fixture.remote_tag_exists(RELEASE_TAG));
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

    let artifact_root = fixture.artifact_root(RELEASE_TAG);
    let archive_name = format!("kidobo-{RELEASE_TAG}-linux-x86_64.tar.gz");
    let archive = artifact_root.join(&archive_name);
    assert!(archive.is_file());
    assert!(artifact_root.join("SHA256SUMS").is_file());
    assert!(artifact_root.join("release-notes.md").is_file());
    let checksum = Command::new("sha256sum")
        .args(["--check", "SHA256SUMS"])
        .current_dir(&artifact_root)
        .output()
        .expect("verify retained release checksum");
    assert_success(&checksum, "verify retained release checksum");
    let listing = Command::new("tar")
        .args(["-tzf", archive.to_str().expect("archive path")])
        .output()
        .expect("list retained release archive");
    assert_success(&listing, "list retained release archive");
    let mut entries = String::from_utf8(listing.stdout)
        .expect("UTF-8 archive listing")
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    entries.sort();
    assert_eq!(
        entries,
        [
            format!("kidobo-{RELEASE_TAG}-linux-x86_64/"),
            format!("kidobo-{RELEASE_TAG}-linux-x86_64/LICENSE"),
            format!("kidobo-{RELEASE_TAG}-linux-x86_64/README.md"),
            format!("kidobo-{RELEASE_TAG}-linux-x86_64/kidobo"),
        ]
    );

    let gh_log = read_to_string_with_limit(&fixture.gh_log, FIXTURE_LOG_READ_LIMIT);
    let create = gh_log
        .lines()
        .find(|line| line.starts_with("release create "))
        .expect("draft release creation");
    assert!(create.contains("--draft"));
    assert!(create.contains("--verify-tag"));
    assert!(!create.contains("--prerelease"));
    let edit = gh_log
        .lines()
        .find(|line| line.starts_with("release edit "))
        .expect("release publication");
    assert!(edit.contains("--draft=false"));
    assert!(edit.contains("--latest"));

    let events = read_to_string_with_limit(&fixture.event_log, FIXTURE_LOG_READ_LIMIT);
    let exercise_position = events
        .find("just exercise-release\n")
        .expect("release binary exercise event");
    let push_position = events
        .find("git push --atomic ")
        .expect("atomic push event");
    let create_position = events
        .find("gh release create ")
        .expect("draft creation event");
    let download_position = events
        .find("gh release download ")
        .expect("asset download event");
    let edit_position = events
        .find("gh release edit ")
        .expect("draft publication event");
    assert!(exercise_position < push_position);
    assert!(push_position < create_position);
    assert!(create_position < download_position);
    assert!(download_position < edit_position);
    assert!(fixture.gh_release_dir.join("published").is_file());
}

#[test]
fn publisher_marks_suffixed_versions_as_prereleases_without_changing_latest() {
    let fixture = ReleaseFixture::new();

    let output = fixture.run_publisher_for(PRERELEASE_VERSION, "y\n");

    assert!(
        output.status.success(),
        "publisher failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(fixture.local_tag_exists(PRERELEASE_TAG));
    assert!(fixture.remote_tag_exists(PRERELEASE_TAG));
    let gh_log = read_to_string_with_limit(&fixture.gh_log, FIXTURE_LOG_READ_LIMIT);
    let create = gh_log
        .lines()
        .find(|line| line.starts_with("release create "))
        .expect("prerelease draft creation");
    assert!(create.contains("--prerelease"));
    let edit = gh_log
        .lines()
        .find(|line| line.starts_with("release edit "))
        .expect("prerelease publication");
    assert!(edit.contains("--draft=false"));
    assert!(!edit.contains("--latest"));
}

#[test]
fn publisher_retains_recovery_state_after_post_push_failures() {
    for (failure_variable, failure_value, expected_status) in [
        ("KIDOBO_TEST_FAIL_GH_CREATE", "1", 41),
        ("KIDOBO_TEST_FAIL_GH_DOWNLOAD", "1", 42),
        ("KIDOBO_TEST_CORRUPT_DOWNLOAD", "1", 1),
        ("KIDOBO_TEST_BINARY_VERSION", "9.9.9", 1),
        ("KIDOBO_TEST_FAIL_GH_EDIT", "1", 43),
    ] {
        let fixture = ReleaseFixture::new();
        let output = fixture
            .publisher_command()
            .env(failure_variable, failure_value)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                child
                    .stdin
                    .take()
                    .expect("publisher stdin")
                    .write_all(b"y\n")?;
                child.wait_with_output()
            })
            .expect("run publisher with post-push failure");

        assert_eq!(
            output.status.code(),
            Some(expected_status),
            "unexpected status for {failure_variable}: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(fixture.tag_exists());
        assert!(fixture.remote_tag_exists(RELEASE_TAG));
        assert!(fixture.artifact_root(RELEASE_TAG).is_dir());
        assert!(!fixture.gh_release_dir.join("published").exists());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("Local recovery artifacts were retained"));
        assert!(stderr.contains("gh release upload"));
        assert!(stderr.contains("gh release download"));
        assert!(stderr.contains("gh release edit"));

        let gh_log = read_to_string_with_limit(&fixture.gh_log, FIXTURE_LOG_READ_LIMIT);
        if failure_variable != "KIDOBO_TEST_FAIL_GH_EDIT" {
            assert!(
                !gh_log.lines().any(|line| line.starts_with("release edit ")),
                "failed validation must not attempt publication: {failure_variable}"
            );
        }
    }
}
