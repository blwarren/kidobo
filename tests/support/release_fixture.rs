use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

pub(crate) const CURRENT_VERSION: &str = "0.11.1";
pub(crate) const RELEASE_VERSION: &str = "0.12.0";
pub(crate) const RELEASE_TAG: &str = "v0.12.0";
pub(crate) const GITHUB_REPOSITORY: &str = "blwarren/kidobo";
pub(crate) const GITHUB_REMOTE_URL: &str = "https://github.com/blwarren/kidobo.git";
pub(crate) const FIXTURE_LOG_READ_LIMIT: usize = 1024 * 1024;
pub(crate) const REPOSITORY_LOCAL_GIT_ENV_VARS: [&str; 9] = [
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

pub(crate) fn read_to_string_with_limit(path: &Path, limit: usize) -> String {
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

pub(crate) fn publisher_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/publish-release.sh")
}

pub(crate) fn write_executable(path: &Path, contents: &str) {
    fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    fs::write(path, contents).expect("write executable");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("chmod");
}

pub(crate) fn path_with_prefix(path: &Path) -> String {
    match std::env::var("PATH") {
        Ok(existing) if !existing.is_empty() => format!("{}:{existing}", path.display()),
        _ => path.display().to_string(),
    }
}

pub(crate) fn clear_repository_local_git_env(command: &mut Command) {
    for variable in REPOSITORY_LOCAL_GIT_ENV_VARS {
        command.env_remove(variable);
    }
}

pub(crate) fn run_git_at(path: &Path, args: &[&str]) -> Output {
    let mut command = Command::new("/usr/bin/git");
    command.args(args).current_dir(path);
    clear_repository_local_git_env(&mut command);
    command.output().expect("run git")
}

pub(crate) fn assert_success(output: &Output, context: &str) {
    assert!(
        output.status.success(),
        "{context} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

pub(crate) fn run_with_confirmation(command: &mut Command, confirmation: &str) -> Output {
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

pub(crate) struct CommandFixture {
    pub(crate) _temp: TempDir,
    pub(crate) repo: PathBuf,
    pub(crate) fake_bin: PathBuf,
    pub(crate) event_log: PathBuf,
}

impl CommandFixture {
    pub(crate) fn new() -> Self {
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

    pub(crate) fn publisher_command(&self) -> Command {
        let mut command = Command::new(publisher_path());
        command
            .arg(RELEASE_VERSION)
            .current_dir(&self.repo)
            .env("PATH", path_with_prefix(&self.fake_bin))
            .env("KIDOBO_TEST_EVENT_LOG", &self.event_log);
        command
    }
}

pub(crate) struct ReleaseFixture {
    pub(crate) temp: TempDir,
    pub(crate) repo: PathBuf,
    pub(crate) remote: PathBuf,
    pub(crate) fake_bin: PathBuf,
    pub(crate) event_log: PathBuf,
    pub(crate) git_log: PathBuf,
    pub(crate) gh_log: PathBuf,
    pub(crate) gh_release_dir: PathBuf,
}

impl ReleaseFixture {
    #[expect(
        clippy::too_many_lines,
        reason = "keep the isolated repository setup and embedded release-tool fakes in one fixture"
    )]
    pub(crate) fn new() -> Self {
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
        for command in ["docker", "musl-gcc", "readelf"] {
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

    pub(crate) fn git(&self, args: &[&str]) -> Output {
        run_git_at(&self.repo, args)
    }

    pub(crate) fn head(&self) -> String {
        let output = self.git(&["rev-parse", "HEAD"]);
        assert_success(&output, "read HEAD");
        String::from_utf8(output.stdout)
            .expect("UTF-8 HEAD")
            .trim()
            .to_string()
    }

    pub(crate) fn tag_exists(&self) -> bool {
        self.local_tag_exists(RELEASE_TAG)
    }

    pub(crate) fn local_tag_exists(&self, tag: &str) -> bool {
        self.git(&["rev-parse", "--verify", "--quiet", tag])
            .status
            .success()
    }

    pub(crate) fn remote_tag_exists(&self, tag: &str) -> bool {
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

    pub(crate) fn artifact_root(&self, tag: &str) -> PathBuf {
        self.repo.join("target/release-artifacts").join(tag)
    }

    pub(crate) fn publisher_command(&self) -> Command {
        self.publisher_command_for(RELEASE_VERSION)
    }

    pub(crate) fn publisher_command_for(&self, version: &str) -> Command {
        self.command_with_options(version, &["--skip-e2e"])
    }

    pub(crate) fn command_with_options(&self, version: &str, options: &[&str]) -> Command {
        let mut command = Command::new(self.repo.join("publish-release.sh"));
        let path = match std::env::var("PATH") {
            Ok(existing) if !existing.is_empty() => {
                format!("{}:{existing}", self.fake_bin.display())
            }
            _ => self.fake_bin.display().to_string(),
        };
        command
            .arg(version)
            .args(options)
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
}
