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

fn compatibility_script_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/check-release-compat.sh")
}

fn write_executable(path: &Path, contents: &str) {
    fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    fs::write(path, contents).expect("write executable");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("chmod");
}

fn path_with_prefix(path: &Path) -> String {
    match std::env::var("PATH") {
        Ok(existing) if !existing.is_empty() => format!("{}:{existing}", path.display()),
        _ => path.display().to_string(),
    }
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

fn run_with_confirmation(command: &mut Command, confirmation: &str) -> Output {
    let mut child = command
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

struct CommandFixture {
    _temp: TempDir,
    repo: PathBuf,
    fake_bin: PathBuf,
    event_log: PathBuf,
}

impl CommandFixture {
    fn new() -> Self {
        let temp = TempDir::new().expect("tempdir");
        let repo = temp.path().join("repo");
        let fake_bin = temp.path().join("fake-bin");
        let event_log = temp.path().join("events.log");
        fs::create_dir_all(repo.join("scripts")).expect("create recipe directory");
        for tool in ["git", "cargo", "gh"] {
            write_executable(
                &fake_bin.join(tool),
                "#!/bin/bash\nprintf 'unexpected tool: %s\\n' \"$0\" >> \"$KIDOBO_TEST_EVENT_LOG\"\nexit 99\n",
            );
        }
        Self {
            _temp: temp,
            repo,
            fake_bin,
            event_log,
        }
    }

    fn publisher_command(&self) -> Command {
        let mut command = Command::new(publisher_path());
        command
            .arg(RELEASE_VERSION)
            .current_dir(&self.repo)
            .env("PATH", path_with_prefix(&self.fake_bin))
            .env("KIDOBO_TEST_EVENT_LOG", &self.event_log);
        command
    }
}

struct ReleaseFixture {
    temp: TempDir,
    repo: PathBuf,
    remote: PathBuf,
    fake_bin: PathBuf,
    event_log: PathBuf,
    git_log: PathBuf,
    gh_log: PathBuf,
    gh_release_dir: PathBuf,
}

impl ReleaseFixture {
    #[expect(
        clippy::too_many_lines,
        reason = "keep the isolated repository setup and embedded release-tool fakes in one fixture"
    )]
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
        fs::create_dir_all(repo.join("scripts")).expect("mkdir scripts");
        fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/package-release.sh"),
            repo.join("scripts/package-release.sh"),
        )
        .expect("copy packager");

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
if [[ -n "${KIDOBO_TEST_READY_MARKER:-}" && "$*" == '--no-pager diff --cached' ]]; then
  : > "${KIDOBO_TEST_READY_MARKER}"
fi
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
if [[ "$1" == "${KIDOBO_TEST_FAIL_GATE:-}" ]]; then exit 44; fi
if [[ "$1" == "e2e-artifact" ]]; then
  [[ "${KIDOBO_E2E_RESULTS_DIR}" == "${KIDOBO_TEST_REPO_ROOT}/target/e2e" ]] || exit 46
  if [[ "${KIDOBO_TEST_FAIL_E2E:-0}" == "1" ]]; then exit 45; fi
  if [[ "${KIDOBO_TEST_MUTATE_ARCHIVE:-0}" == "1" ]]; then printf corrupt >> "$2"; fi
fi
if [[ "$*" == "exercise-release" ]]; then
  binary="${CARGO_TARGET_DIR:-target}/x86_64-unknown-linux-musl/release/kidobo"
  mkdir -p "$(dirname "$binary")"
  printf '#!/usr/bin/env bash\nprintf '\''kidobo %%s\\n'\'' %q\n' \
    "${KIDOBO_TEST_BINARY_VERSION}" > "$binary"
  chmod 0755 "$binary"
  mkdir -p "${KIDOBO_TEST_GH_RELEASE_DIR}"
  cp "$binary" "${KIDOBO_TEST_GH_RELEASE_DIR}/validated-candidate"
fi
exit 0
"#,
        );
        write_executable(
            &fake_bin.join("date"),
            r#"#!/usr/bin/env bash
set -euo pipefail
if [[ -n "${KIDOBO_TEST_RELEASE_DATE:-}" && "$*" == "-u +%F" ]]; then
  printf '%s\n' "${KIDOBO_TEST_RELEASE_DATE}"
else
  exec /usr/bin/date "$@"
fi
"#,
        );
        for command in ["docker", "genisoimage", "incus", "musl-gcc", "readelf"] {
            write_executable(
                &fake_bin.join(command),
                "#!/usr/bin/env bash\nset -euo pipefail\nexit 0\n",
            );
        }
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
            temp,
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
            .env_remove("CARGO_TARGET_DIR")
            .env("KIDOBO_TEST_REPO_ROOT", &self.repo)
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
        run_with_confirmation(&mut self.publisher_command_for(version), confirmation)
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
fn release_compatibility_script_has_valid_bash_syntax() {
    let status = Command::new("bash")
        .arg("-n")
        .arg(compatibility_script_path())
        .status()
        .expect("check compatibility script syntax");
    assert!(status.success());
}

#[test]
fn release_compatibility_gate_checks_both_container_baselines() {
    let temp = TempDir::new().expect("tempdir");
    let fake_bin = temp.path().join("fake-bin");
    let docker_log = temp.path().join("docker.log");
    let binary = temp.path().join("kidobo");
    write_executable(&binary, "#!/usr/bin/env bash\nexit 0\n");
    write_executable(
        &fake_bin.join("readelf"),
        "#!/usr/bin/env bash\nset -euo pipefail\nexit 0\n",
    );
    write_executable(
        &fake_bin.join("docker"),
        r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${KIDOBO_TEST_DOCKER_LOG}"
if [[ " $* " == *" lookup 203.0.113.7 --format tsv "* ]]; then
  printf '203.0.113.7\tinternal:blocklist\t203.0.113.0/24\n'
fi
"#,
    );

    let output = Command::new(compatibility_script_path())
        .arg(&binary)
        .env("PATH", path_with_prefix(&fake_bin))
        .env("KIDOBO_TEST_DOCKER_LOG", &docker_log)
        .output()
        .expect("run compatibility gate");

    assert_success(&output, "release compatibility gate");
    let log = read_to_string_with_limit(&docker_log, FIXTURE_LOG_READ_LIMIT);
    assert_eq!(log.lines().count(), 6);
    assert!(log.contains("debian:11-slim"));
    assert!(log.contains("alpine:3.22"));
    assert!(log.contains("--network none"));
    assert!(log.contains("--read-only"));
}

#[test]
fn release_compatibility_gate_rejects_an_elf_interpreter() {
    let temp = TempDir::new().expect("tempdir");
    let fake_bin = temp.path().join("fake-bin");
    let binary = temp.path().join("kidobo");
    write_executable(&binary, "#!/usr/bin/env bash\nexit 0\n");
    write_executable(
        &fake_bin.join("readelf"),
        "#!/usr/bin/env bash\nset -euo pipefail\nif [[ \"$1\" == \"-l\" ]]; then echo 'Requesting program interpreter'; fi\n",
    );
    write_executable(&fake_bin.join("docker"), "#!/usr/bin/env bash\nexit 99\n");

    let output = Command::new(compatibility_script_path())
        .arg(&binary)
        .env("PATH", path_with_prefix(&fake_bin))
        .output()
        .expect("run compatibility gate");

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("ELF interpreter"));
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
    for args in [
        vec![],
        vec![RELEASE_VERSION, RELEASE_VERSION],
        vec![RELEASE_VERSION, "--skip-e2e", "extra"],
    ] {
        let output = Command::new(publisher_path())
            .args(&args)
            .output()
            .expect("reject missing or extra arguments");
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("Usage:"));
    }
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
    assert_eq!(fixture.git(&["status", "--porcelain"]).stdout.len(), 0);
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
fn publisher_packages_the_validated_candidate_from_each_target_directory() {
    for target_directory in [
        None,
        Some("target/custom"),
        Some("target/custom with spaces"),
        Some("absolute"),
    ] {
        let fixture = ReleaseFixture::new();
        let mut command = fixture.publisher_command();
        if let Some(directory) = target_directory {
            let path = if directory == "absolute" {
                fixture.temp.path().join("absolute build with spaces")
            } else {
                PathBuf::from(directory)
            };
            command.env("CARGO_TARGET_DIR", path);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn fixture publisher");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(b"y\n")
            .expect("confirm fixture publication");
        let output = child.wait_with_output().expect("wait publisher");
        assert_success(&output, &format!("target directory {target_directory:?}"));
        let archive = fixture
            .artifact_root(RELEASE_TAG)
            .join(format!("kidobo-{RELEASE_TAG}-linux-x86_64.tar.gz"));
        let packaged = Command::new("tar")
            .arg("-xOzf")
            .arg(archive)
            .arg(format!("kidobo-{RELEASE_TAG}-linux-x86_64/kidobo"))
            .output()
            .expect("read packaged binary");
        assert_success(&packaged, "extract candidate");
        assert_eq!(
            packaged.stdout,
            read_to_string_with_limit(
                &fixture.gh_release_dir.join("validated-candidate"),
                FIXTURE_LOG_READ_LIMIT,
            )
            .into_bytes()
        );
    }
}

#[test]
fn publisher_atomically_pushes_then_verifies_and_publishes_local_artifacts() {
    let fixture = ReleaseFixture::new();
    let original_head = fixture.head();

    let output = fixture.run_publisher("y\n");

    assert_success(&output, "publish fixture release");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("running required distro lifecycle matrix"));
    assert!(stdout.contains("PASSED (required targets; advisory coverage separate)"));
    let release_head = fixture.head();
    assert_ne!(release_head, original_head);
    assert!(fixture.tag_exists());
    assert!(fixture.remote_tag_exists(RELEASE_TAG));
    let log = read_to_string_with_limit(&fixture.git_log, FIXTURE_LOG_READ_LIMIT);
    let expected_push = format!(
        "-c core.hooksPath=/dev/null push --atomic origin {release_head}:refs/heads/main refs/tags/{RELEASE_TAG}:refs/tags/{RELEASE_TAG}"
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
    let compatibility_position = events
        .find("just release-compat\n")
        .expect("release compatibility event");
    let push_position = events
        .find("git -c core.hooksPath=/dev/null push --atomic ")
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
    assert!(exercise_position < compatibility_position);
    let e2e_position = events.find("just e2e-artifact ").expect("distro gate");
    assert!(compatibility_position < e2e_position && e2e_position < push_position);
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

#[test]
fn distro_gate_failure_or_artifact_changes_prevent_publication() {
    for variable in ["KIDOBO_TEST_FAIL_E2E", "KIDOBO_TEST_MUTATE_ARCHIVE"] {
        let fixture = ReleaseFixture::new();
        let output = fixture
            .publisher_command()
            .env(variable, "1")
            .output()
            .expect("run failing distro gate");
        assert!(
            !output.status.success(),
            "{variable} must block publication"
        );
        assert!(!fixture.tag_exists());
        let events = read_to_string_with_limit(&fixture.event_log, FIXTURE_LOG_READ_LIMIT);
        assert!(events.contains("just e2e-artifact "));
        assert!(!events.contains("git -c core.hooksPath=/dev/null push --atomic "));
        assert!(!events.contains("gh release create "));
    }
}

#[test]
fn publisher_resumes_the_same_candidate_without_rebuilding_or_repeating_gates() {
    let fixture = ReleaseFixture::new();
    let original_head = fixture.head();
    let first = fixture
        .publisher_command()
        .env("KIDOBO_TEST_FAIL_E2E", "1")
        .env("KIDOBO_TEST_RELEASE_DATE", "2026-10-27")
        .output()
        .expect("retain candidate after matrix failure");
    assert_eq!(first.status.code(), Some(45));
    let artifact_root = fixture.artifact_root(RELEASE_TAG);
    let original_manifest =
        read_to_string_with_limit(&artifact_root.join("candidate.txt"), FIXTURE_LOG_READ_LIMIT);
    assert!(original_manifest.contains("release_date=2026-10-27\n"));
    assert_eq!(fixture.head(), original_head);
    assert!(!fixture.tag_exists());
    assert!(String::from_utf8_lossy(&first.stderr).contains("Validated candidate retained"));

    let resumed = run_with_confirmation(
        fixture
            .publisher_command()
            .args(["--resume-e2e", "run-123-456"])
            .env("KIDOBO_TEST_RELEASE_DATE", "2026-10-28")
            .env("KIDOBO_TEST_FAIL_GATE", "ci"),
        "y\n",
    );
    assert_success(&resumed, "resume retained candidate on the following day");
    assert_eq!(
        read_to_string_with_limit(&artifact_root.join("candidate.txt"), FIXTURE_LOG_READ_LIMIT),
        original_manifest
    );
    assert!(
        String::from_utf8_lossy(&resumed.stdout)
            .contains("Reused local CI, release-note, coverage")
    );
    let dates = read_to_string_with_limit(
        &fixture.repo.join("release-notes/dates.tsv"),
        FIXTURE_LOG_READ_LIMIT,
    );
    assert!(dates.contains("2026-10-27"));
    assert!(!dates.contains("2026-10-28"));
    let events = read_to_string_with_limit(&fixture.event_log, FIXTURE_LOG_READ_LIMIT);
    for gate in [
        "ci",
        "coverage",
        "release-notes-check",
        "rustdoc",
        "exercise-release",
        "release-compat",
    ] {
        assert_eq!(events.matches(&format!("just {gate}\n")).count(), 1);
    }
    let matrix_events = events
        .lines()
        .filter(|line| line.starts_with("just e2e-artifact "))
        .collect::<Vec<_>>();
    assert_eq!(matrix_events.len(), 2);
    assert!(matrix_events[1].ends_with("--resume run-123-456"));
    assert!(fixture.gh_release_dir.join("published").is_file());
}

#[test]
fn publisher_resume_rejects_changed_source_and_retained_artifacts() {
    for changed_file in [
        "README.md",
        "candidate.txt",
        "SHA256SUMS",
        "release-notes.md",
        "kidobo-v0.12.0-linux-x86_64.tar.gz",
    ] {
        let fixture = ReleaseFixture::new();
        let first = fixture
            .publisher_command()
            .env("KIDOBO_TEST_FAIL_E2E", "1")
            .output()
            .expect("retain failed candidate");
        assert_eq!(first.status.code(), Some(45));
        if changed_file == "README.md" {
            let path = fixture.repo.join(changed_file);
            let original = read_to_string_with_limit(&path, FIXTURE_LOG_READ_LIMIT);
            fs::write(path, format!("{original}Changed source.\n")).expect("change source");
            fixture.git_success(&["add", "README.md"], "stage changed source");
            fixture.git_success(&["commit", "-m", "Change source"], "commit changed source");
        } else {
            let path = fixture.artifact_root(RELEASE_TAG).join(changed_file);
            fs::OpenOptions::new()
                .append(true)
                .open(path)
                .expect("open retained artifact")
                .write_all(b"corrupt\n")
                .expect("change retained artifact");
        }
        let output = fixture
            .publisher_command()
            .args(["--resume-e2e", "run-123-456"])
            .output()
            .expect("reject changed candidate");
        assert_eq!(output.status.code(), Some(1), "{changed_file}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("cannot resume"),
            "{changed_file}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("mv -- "));
        assert!(String::from_utf8_lossy(&output.stderr).contains(".saved-"));
        assert!(fixture.artifact_root(RELEASE_TAG).is_dir());
        assert!(!fixture.tag_exists());
        let events = read_to_string_with_limit(&fixture.event_log, FIXTURE_LOG_READ_LIMIT);
        assert_eq!(events.matches("just e2e-artifact ").count(), 1);
        assert!(!events.contains("git -c core.hooksPath=/dev/null push --atomic "));
    }
}

#[test]
fn publisher_resume_requires_complete_metadata_and_retains_inputs_on_failure() {
    let fixture = ReleaseFixture::new();
    let missing = fixture
        .publisher_command()
        .args(["--resume-e2e", "run-123-456"])
        .output()
        .expect("reject nonexistent candidate");
    assert_eq!(missing.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("missing candidate metadata"));
    assert!(
        !fixture.event_log.exists()
            || !read_to_string_with_limit(&fixture.event_log, FIXTURE_LOG_READ_LIMIT)
                .contains("just ci\n")
    );

    let failed = fixture
        .publisher_command()
        .env("KIDOBO_TEST_FAIL_E2E", "1")
        .output()
        .expect("retain failed candidate");
    assert_eq!(failed.status.code(), Some(45));
    let repeated = fixture
        .publisher_command()
        .args(["--resume-e2e", "run-123-456"])
        .env("KIDOBO_TEST_FAIL_E2E", "1")
        .output()
        .expect("retain candidate through repeated matrix failure");
    assert_eq!(repeated.status.code(), Some(45));
    let manifest = fixture.artifact_root(RELEASE_TAG).join("candidate.txt");
    assert!(manifest.is_file());
    fs::remove_file(&manifest).expect("remove metadata to emulate legacy candidate");
    let legacy = fixture
        .publisher_command()
        .args(["--resume-e2e", "run-123-456"])
        .output()
        .expect("reject candidate without validated identity");
    assert_eq!(legacy.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&legacy.stderr).contains("missing candidate metadata"));
    assert!(fixture.artifact_root(RELEASE_TAG).is_dir());
}

#[test]
fn publisher_rejects_conflicting_or_malformed_resume_options_before_tools() {
    for options in [
        vec!["--resume-e2e"],
        vec!["--resume-e2e", "../run-123-456"],
        vec!["--resume-e2e", "run-123-456", "--skip-e2e"],
        vec!["--skip-e2e", "--resume-e2e", "run-123-456"],
        vec!["--resume-e2e", "run-123-456", "--resume-e2e", "run-123-789"],
        vec!["--skip-e2e", "--skip-e2e"],
        vec!["--skip-e2e", "--refresh-e2e-images"],
        vec!["--refresh-e2e-images", "--skip-e2e"],
        vec!["--refresh-e2e-images", "--refresh-e2e-images"],
    ] {
        let fixture = CommandFixture::new();
        let output = fixture
            .publisher_command()
            .args(&options)
            .output()
            .expect("reject malformed release options");
        assert_eq!(output.status.code(), Some(2), "{options:?}");
        assert!(!fixture.event_log.exists());
    }
}

#[test]
fn publisher_forwards_prepared_image_refresh_to_the_required_matrix() {
    let fixture = ReleaseFixture::new();
    let output = fixture
        .publisher_command()
        .arg("--refresh-e2e-images")
        .env("KIDOBO_TEST_FAIL_E2E", "1")
        .output()
        .expect("request fresh prepared images at the fake matrix gate");
    assert_eq!(output.status.code(), Some(45));
    let events = read_to_string_with_limit(&fixture.event_log, FIXTURE_LOG_READ_LIMIT);
    let matrix = events
        .lines()
        .find(|line| line.starts_with("just e2e-artifact "))
        .expect("required matrix invocation");
    assert!(matrix.ends_with("--refresh-images"));
    assert!(!matrix.contains("--resume"));
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("refreshing prepared images and rerunning every selected distro target")
    );
    assert!(!fixture.tag_exists());
    assert!(!fixture.gh_release_dir.join("published").exists());
}

#[test]
fn publisher_refreshes_images_on_resume_without_repeating_local_validation() {
    let fixture = ReleaseFixture::new();
    let first = fixture
        .publisher_command()
        .env("KIDOBO_TEST_FAIL_E2E", "1")
        .output()
        .expect("retain the candidate after a fake matrix failure");
    assert_eq!(first.status.code(), Some(45));
    let resumed = run_with_confirmation(
        fixture
            .publisher_command()
            .args(["--resume-e2e", "run-123-456", "--refresh-e2e-images"])
            .env("KIDOBO_TEST_FAIL_GATE", "ci"),
        "y\n",
    );
    assert_success(&resumed, "refresh image coverage for a retained candidate");
    let events = read_to_string_with_limit(&fixture.event_log, FIXTURE_LOG_READ_LIMIT);
    for gate in [
        "ci",
        "coverage",
        "release-notes-check",
        "rustdoc",
        "exercise-release",
        "release-compat",
    ] {
        assert_eq!(events.matches(&format!("just {gate}\n")).count(), 1);
    }
    let matrix_events = events
        .lines()
        .filter(|line| line.starts_with("just e2e-artifact "))
        .collect::<Vec<_>>();
    assert_eq!(matrix_events.len(), 2);
    assert!(matrix_events[1].ends_with("--resume run-123-456 --refresh-images"));
    assert!(fixture.gh_release_dir.join("published").is_file());
}

#[test]
fn publisher_can_skip_e2e_without_vm_tools_and_keeps_other_gates() {
    let fixture = ReleaseFixture::new();
    let no_vm_tools = fixture.temp.path().join("no-vm-tools.sh");
    fs::write(
        &no_vm_tools,
        r#"
command() {
  if [[ "$1" == -v ]]; then
    case "$2" in incus|genisoimage|mkisofs) return 1 ;; esac
  fi
  builtin command "$@"
}
"#,
    )
    .expect("hide VM tools independently of the host PATH");
    let default = fixture
        .publisher_command()
        .env("BASH_ENV", &no_vm_tools)
        .output()
        .expect("check default VM prerequisites");
    assert_eq!(default.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&default.stderr).contains("missing required command: incus"));

    let output = run_with_confirmation(
        fixture
            .publisher_command()
            .arg("--skip-e2e")
            .env("BASH_ENV", &no_vm_tools)
            .env("KIDOBO_TEST_FAIL_E2E", "1"),
        "y\n",
    );
    assert_success(
        &output,
        "publish without VM prerequisites or matrix execution",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let notice = "Distro lifecycle matrix: SKIPPED (--skip-e2e)";
    let first_notice = stdout.find(notice).expect("initial skipped-gate notice");
    assert!(first_notice < stdout.find("running local CI").expect("local CI"));
    let last_notice = stdout
        .rfind(notice)
        .expect("confirmation skipped-gate notice");
    assert!(
        last_notice
            > stdout
                .find("is ready to publish")
                .expect("publication review")
    );
    let events = read_to_string_with_limit(&fixture.event_log, FIXTURE_LOG_READ_LIMIT);
    assert!(!events.contains("just e2e-artifact "));
    for gate in [
        "ci",
        "release-notes-check",
        "coverage",
        "rustdoc",
        "exercise-release",
        "release-compat",
    ] {
        assert!(events.contains(&format!("just {gate}\n")), "missing {gate}");
    }
    assert!(events.contains("gh release download "));
    assert!(fixture.gh_release_dir.join("published").exists());
}

#[test]
fn publisher_rejects_unknown_options_before_running_tools() {
    let fixture = CommandFixture::new();
    let output = fixture
        .publisher_command()
        .arg("--skip-e2")
        .output()
        .expect("reject misspelled option");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown option: --skip-e2"));
    assert!(!fixture.event_log.exists());
}

#[test]
fn publisher_runs_explicit_gates_without_repeating_git_hooks() {
    let fixture = ReleaseFixture::new();
    let hooks = fixture.temp.path().join("hooks");
    for hook in ["pre-commit", "pre-push"] {
        write_executable(&hooks.join(hook), "#!/bin/bash\nexit 91\n");
    }
    assert_success(
        &run_git_at(
            &fixture.repo,
            &[
                "config",
                "core.hooksPath",
                hooks.to_str().expect("hook path"),
            ],
        ),
        "configure hooks that reject unvalidated ordinary Git operations",
    );
    assert_success(
        &fixture.run_publisher("y\n"),
        "publish already validated candidate",
    );
    let events = read_to_string_with_limit(&fixture.event_log, FIXTURE_LOG_READ_LIMIT);
    for gate in [
        "ci",
        "release-notes-check",
        "coverage",
        "rustdoc",
        "exercise-release",
        "release-compat",
    ] {
        assert_eq!(
            events.matches(&format!("just {gate}\n")).count(),
            1,
            "{gate}"
        );
    }
    assert_eq!(
        run_git_at(
            &fixture.repo,
            &["commit", "--allow-empty", "-m", "ordinary commit"]
        )
        .status
        .code(),
        Some(1)
    );
}

#[test]
fn publisher_rejects_candidate_changes_after_validation() {
    let fixture = ReleaseFixture::new();
    let output = fixture.run_after_validation(|| {
        let worktrees = run_git_at(&fixture.repo, &["worktree", "list", "--porcelain"]);
        assert_success(&worktrees, "list candidate worktree");
        let listing = String::from_utf8(worktrees.stdout).expect("worktree paths");
        let candidate = listing
            .lines()
            .filter_map(|line| line.strip_prefix("worktree "))
            .map(PathBuf::from)
            .find(|path| path != &fixture.repo)
            .expect("candidate worktree");
        fs::write(candidate.join("LICENSE"), "changed after validation\n")
            .expect("change candidate");
        assert_success(
            &run_git_at(&candidate, &["add", "LICENSE"]),
            "restage changed candidate",
        );
    });
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("validation produced uncommitted changes")
            || stderr.contains("validated candidate changed"),
        "{stderr}"
    );
    assert!(!fixture.tag_exists());
    assert!(!fixture.remote_tag_exists(RELEASE_TAG));
}

#[test]
fn skipping_e2e_still_blocks_publication_on_other_gate_failures() {
    for gate in ["ci", "release-compat"] {
        let fixture = ReleaseFixture::new();
        let output = fixture
            .publisher_command()
            .arg("--skip-e2e")
            .env("KIDOBO_TEST_FAIL_GATE", gate)
            .output()
            .expect("exercise retained gate failure");
        assert_eq!(output.status.code(), Some(44), "{gate}");
        assert!(!fixture.tag_exists());
        assert!(!fixture.remote_tag_exists(RELEASE_TAG));
        let events = read_to_string_with_limit(&fixture.event_log, FIXTURE_LOG_READ_LIMIT);
        assert!(!events.contains("git -c core.hooksPath=/dev/null push --atomic "));
        assert!(!events.contains("gh release create "));
    }
}

#[test]
fn candidate_recipe_runs_an_existing_archive_without_building_or_packaging() {
    let fixture = CommandFixture::new();
    let justfile = fixture.repo.join("Justfile");
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("Justfile"),
        &justfile,
    )
    .expect("copy recipes into isolated repository");
    write_executable(
        &fixture.fake_bin.join("cargo"),
        "#!/bin/bash\n[[ \"$1\" == run ]] || exit 91\nprintf '%s\\n' \"$@\"\n",
    );
    write_executable(
        &fixture.repo.join("scripts/package-release.sh"),
        "#!/bin/bash\nprintf unexpected-package > \"$KIDOBO_TEST_EVENT_LOG\"\nexit 92\n",
    );
    for options in [
        vec![
            "--archive".to_owned(),
            "/tmp/existing candidate.tar.gz".to_owned(),
            "--tag".to_owned(),
            RELEASE_TAG.to_owned(),
        ],
        vec![
            "--archive=/tmp/existing candidate.tar.gz".to_owned(),
            format!("--tag={RELEASE_TAG}"),
            "--refresh-images".to_owned(),
        ],
    ] {
        let output = Command::new("just")
            .arg("--justfile")
            .arg(&justfile)
            .arg("_e2e")
            .args(&options)
            .env("PATH", path_with_prefix(&fixture.fake_bin))
            .env("KIDOBO_TEST_EVENT_LOG", &fixture.event_log)
            .output()
            .expect("forward an existing archive without a build");
        assert_success(&output, "run the prebuilt candidate recipe");
        assert_eq!(
            String::from_utf8(output.stdout).expect("UTF-8 candidate arguments"),
            format!(
                "run\n--locked\n-p\nkidobo-e2e\n--\nrun\n{}\n",
                options.join("\n")
            )
        );
        assert!(
            !fixture.event_log.exists(),
            "prebuilt archives must not be repackaged"
        );
    }
}

#[test]
fn candidate_recipe_still_builds_and_packages_when_no_archive_is_supplied() {
    let fixture = CommandFixture::new();
    let justfile = fixture.repo.join("Justfile");
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("Justfile"),
        &justfile,
    )
    .expect("copy recipes into isolated repository");
    write_executable(
        &fixture.fake_bin.join("cargo"),
        r#"#!/bin/bash
set -euo pipefail
printf 'cargo %s\n' "$1" >> "$KIDOBO_TEST_EVENT_LOG"
case "$1" in
  build)
    binary="$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/kidobo"
    mkdir -p "${binary%/*}"
    printf '#!/bin/bash\nprintf '\''kidobo %s\\n'\''\n' "$KIDOBO_TEST_BINARY_VERSION" > "$binary"
    chmod 0755 "$binary"
    ;;
  run) printf '%s\n' "$@" ;;
  *) exit 91 ;;
esac
"#,
    );
    write_executable(
        &fixture.repo.join("scripts/package-release.sh"),
        r#"#!/bin/bash
set -euo pipefail
[[ -x "$1" && "$2" == "v$KIDOBO_TEST_BINARY_VERSION" && -d "$3" ]]
printf 'package %s\n' "$2" >> "$KIDOBO_TEST_EVENT_LOG"
: > "$3/kidobo-$2-linux-x86_64.tar.gz"
"#,
    );
    let output = Command::new("just")
        .arg("--justfile")
        .arg(&justfile)
        .args(["_e2e", "--keep-failed"])
        .env("PATH", path_with_prefix(&fixture.fake_bin))
        .env("CARGO_TARGET_DIR", fixture.repo.join("custom build target"))
        .env("KIDOBO_TEST_EVENT_LOG", &fixture.event_log)
        .env("KIDOBO_TEST_BINARY_VERSION", RELEASE_VERSION)
        .output()
        .expect("build and package a candidate with inert tools");
    assert_success(&output, "build the normal candidate recipe");
    assert_eq!(
        read_to_string_with_limit(&fixture.event_log, FIXTURE_LOG_READ_LIMIT),
        format!("cargo build\npackage {RELEASE_TAG}\ncargo run\n")
    );
    let arguments = String::from_utf8(output.stdout).expect("UTF-8 candidate arguments");
    let arguments = arguments.lines().collect::<Vec<_>>();
    let archive = arguments
        .windows(2)
        .find(|pair| pair[0] == "--archive")
        .expect("packaged archive argument")[1];
    assert!(fixture.repo.join(archive).is_file());
    assert!(archive.ends_with(&format!("kidobo-{RELEASE_TAG}-linux-x86_64.tar.gz")));
    assert_eq!(
        &arguments[arguments.len() - 3..],
        &["--tag", RELEASE_TAG, "--keep-failed"]
    );
    assert!(!arguments.contains(&"--required-only"));
}

#[test]
fn publication_recipe_forwards_the_skip_option_as_an_argument() {
    let fixture = CommandFixture::new();
    let justfile = fixture.repo.join("Justfile");
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("Justfile"),
        &justfile,
    )
    .expect("copy recipes into isolated repository");
    write_executable(
        &fixture.repo.join("scripts/publish-release.sh"),
        "#!/bin/bash\nprintf '%s\\n' \"$@\"\n",
    );
    let output = Command::new("just")
        .arg("--justfile")
        .arg(&justfile)
        .args(["publish-release", RELEASE_VERSION, "--skip-e2e"])
        .output()
        .expect("exercise recipe with an inert publisher");
    assert_success(&output, "forward publisher arguments");
    assert_eq!(
        String::from_utf8(output.stdout).expect("forwarded arguments"),
        format!("{RELEASE_VERSION}\n--skip-e2e\n")
    );
}

#[test]
fn artifact_recipe_allows_resume_and_refresh_and_preserves_argument_boundaries() {
    let fixture = CommandFixture::new();
    let justfile = fixture.repo.join("Justfile");
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("Justfile"),
        &justfile,
    )
    .expect("copy recipe into isolated repository");
    write_executable(
        &fixture.fake_bin.join("cargo"),
        "#!/bin/bash\nprintf '%s\\n' \"$@\"\n",
    );
    let mut command = Command::new("just");
    command
        .arg("--justfile")
        .arg(&justfile)
        .env("PATH", path_with_prefix(&fixture.fake_bin))
        .args([
            "e2e-artifact",
            "/tmp/candidate with spaces.tar.gz",
            RELEASE_TAG,
            "--resume",
            "run-123-456",
        ]);
    let output = command.output().expect("forward artifact resume arguments");
    assert_success(&output, "forward artifact resume");
    assert_eq!(
        String::from_utf8(output.stdout).expect("UTF-8 forwarded arguments"),
        format!(
            "run\n--locked\n-p\nkidobo-e2e\n--\nrun\n--required-only\n--archive\n/tmp/candidate with spaces.tar.gz\n--tag\n{RELEASE_TAG}\n--resume\nrun-123-456\n"
        )
    );
    for options in [
        vec!["--refresh-images"],
        vec!["--resume", "run-123-456", "--refresh-images"],
        vec!["--refresh-images", "--resume", "run-123-456"],
    ] {
        let output = Command::new("just")
            .arg("--justfile")
            .arg(&justfile)
            .env("PATH", path_with_prefix(&fixture.fake_bin))
            .args([
                "e2e-artifact",
                "/tmp/candidate with spaces.tar.gz",
                RELEASE_TAG,
            ])
            .args(&options)
            .output()
            .expect("forward artifact refresh arguments");
        assert_success(&output, "forward artifact image refresh");
        assert_eq!(
            String::from_utf8(output.stdout).expect("UTF-8 forwarded arguments"),
            format!(
                "run\n--locked\n-p\nkidobo-e2e\n--\nrun\n--required-only\n--archive\n/tmp/candidate with spaces.tar.gz\n--tag\n{RELEASE_TAG}\n{}\n",
                options.join("\n")
            )
        );
    }
    for options in [
        vec!["--distro", "debian-12"],
        vec!["--resume"],
        vec!["--resume", "../run-123-456"],
        vec!["--resume", "run-123-456", "--distro", "debian-12"],
        vec!["--resume", "run-123-456", "--resume", "run-123-789"],
        vec!["--refresh-images", "--refresh-images"],
        vec!["--refresh-image"],
    ] {
        let output = Command::new("just")
            .arg("--justfile")
            .arg(&justfile)
            .env("PATH", path_with_prefix(&fixture.fake_bin))
            .args(["e2e-artifact", "/tmp/candidate.tar.gz", RELEASE_TAG])
            .args(&options)
            .output()
            .expect("reject artifact filtering or malformed resume");
        assert!(!output.status.success(), "{options:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("Usage:"));
        assert_eq!(output.stdout, [] as [u8; 0]);
    }
}

#[test]
fn resume_recipe_forwards_required_only_and_refresh_without_filtering_targets() {
    let fixture = CommandFixture::new();
    let justfile = fixture.repo.join("Justfile");
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("Justfile"),
        &justfile,
    )
    .expect("copy recipes into isolated repository");
    write_executable(
        &fixture.fake_bin.join("cargo"),
        "#!/bin/bash\nprintf '%s\\n' \"$@\"\n",
    );
    for options in [
        vec![],
        vec!["--required-only"],
        vec!["--refresh-images"],
        vec!["--required-only", "--refresh-images"],
        vec!["--refresh-images", "--required-only"],
    ] {
        let output = Command::new("just")
            .arg("--justfile")
            .arg(&justfile)
            .env("PATH", path_with_prefix(&fixture.fake_bin))
            .args(["e2e-resume", "run-123-456"])
            .args(&options)
            .output()
            .expect("forward resume target selection");
        assert_success(&output, "forward resume target selection");
        let expected_suffix = if options.is_empty() {
            String::new()
        } else {
            format!("{}\n", options.join("\n"))
        };
        assert_eq!(
            String::from_utf8(output.stdout).expect("UTF-8 forwarded arguments"),
            format!(
                "run\n--locked\n-p\nkidobo-e2e\n--\nrun\n--resume\nrun-123-456\n{expected_suffix}"
            )
        );
    }
    for options in [
        vec!["--distro", "debian-12"],
        vec!["--required-only", "--distro", "debian-12"],
        vec!["--required-only", "--required-only"],
        vec!["--refresh-images", "--refresh-images"],
        vec!["--refresh-image"],
    ] {
        let output = Command::new("just")
            .arg("--justfile")
            .arg(&justfile)
            .env("PATH", path_with_prefix(&fixture.fake_bin))
            .args(["e2e-resume", "run-123-456"])
            .args(&options)
            .output()
            .expect("reject unsupported resume target selection");
        assert!(!output.status.success(), "{options:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("Usage:"));
        assert_eq!(output.stdout, [] as [u8; 0]);
    }
}
