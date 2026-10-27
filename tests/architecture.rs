use std::sync::OnceLock;

use serde_json::Value;

fn packages() -> &'static [Value] {
    static METADATA: OnceLock<Value> = OnceLock::new();
    METADATA.get_or_init(|| {
        let output = std::process::Command::new(env!("CARGO"))
            .args([
                "metadata",
                "--offline",
                "--locked",
                "--no-deps",
                "--format-version",
                "1",
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .expect("read Cargo package structure");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("Cargo metadata JSON")
    })["packages"]
        .as_array()
        .expect("workspace packages")
}

fn package(name: &str) -> &'static Value {
    packages()
        .iter()
        .find(|package| package["name"] == name)
        .expect("workspace package")
}

#[test]
fn dependency_direction_points_inward() {
    for (name, required, forbidden) in [
        (
            "kidobo-core",
            vec![],
            vec!["kidobo-app", "kidobo-adapters", "clap"],
        ),
        (
            "kidobo-app",
            vec!["kidobo-core"],
            vec!["kidobo-adapters", "clap"],
        ),
        (
            "kidobo-adapters",
            vec!["kidobo-core", "kidobo-app"],
            vec!["clap"],
        ),
    ] {
        let dependencies = package(name)["dependencies"]
            .as_array()
            .expect("dependencies");
        for expected in required {
            assert!(
                dependencies
                    .iter()
                    .any(|dependency| dependency["name"] == expected),
                "{name} requires {expected}"
            );
        }
        for disallowed in forbidden {
            assert!(
                !dependencies
                    .iter()
                    .any(|dependency| dependency["name"] == disallowed),
                "{name} must not depend on {disallowed}"
            );
        }
    }
}

#[test]
fn internal_crates_remain_unpublished_and_unversioned() {
    for name in ["kidobo-core", "kidobo-app", "kidobo-adapters"] {
        assert_eq!(package(name)["version"], "0.0.0", "{name}");
        assert_eq!(package(name)["publish"], serde_json::json!([]), "{name}");
    }
}

#[test]
fn root_package_owns_the_release_version() {
    assert_eq!(package("kidobo")["version"], env!("CARGO_PKG_VERSION"));
    assert_ne!(package("kidobo")["version"], "0.0.0");
}

#[cfg(unix)]
#[test]
fn commit_hook_selects_fast_checks_without_rewriting_files() {
    use kidobo_adapters::limited_io::read_to_string_with_limit;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::Command;

    for (path, contents, checks) in [
        ("README.md", "documentation\n", false),
        ("src/new.rs", "fn example() {}\n", true),
        ("Cargo.lock", "# lockfile\n", true),
        ("former.txt", "fn example() {}\n", true),
        ("README.md", "trailing whitespace \n", false),
    ] {
        let temp = tempfile::tempdir().expect("repository");
        let git = |args: &[&str]| {
            Command::new("git")
                .args(args)
                .current_dir(temp.path())
                .env_remove("GIT_DIR")
                .env_remove("GIT_WORK_TREE")
                .env_remove("GIT_INDEX_FILE")
                .output()
                .expect("prepare staged fixture")
        };
        assert!(git(&["init", "--quiet"]).status.success());
        let source = temp.path().join(path);
        fs::create_dir_all(source.parent().expect("parent")).expect("source directory");
        if path == "former.txt" {
            fs::write(temp.path().join("before.rs"), contents).expect("original Rust source");
            assert!(git(&["add", "before.rs"]).status.success());
            assert!(
                git(&[
                    "-c",
                    "user.name=Kidobo Test",
                    "-c",
                    "user.email=kidobo@example.test",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "commit",
                    "--quiet",
                    "-m",
                    "fixture"
                ])
                .status
                .success()
            );
            assert!(git(&["mv", "before.rs", path]).status.success());
        } else {
            fs::write(&source, contents).expect("source");
            assert!(git(&["add", path]).status.success());
        }
        let bin = temp.path().join("bin");
        fs::create_dir(&bin).expect("fake command directory");
        let just = bin.join("just");
        fs::write(&just, "#!/bin/bash\nif [[ \"$*\" == commit-check ]]; then exec \"$KIDOBO_TEST_COMMIT_CHECK\"; fi\nprintf '%s\\n' \"$*\" >> \"$KIDOBO_TEST_JUST_LOG\"\n").expect("fake just");
        fs::set_permissions(&just, fs::Permissions::from_mode(0o755)).expect("executable just");
        let log = temp.path().join("checks.log");
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
        let output = Command::new(repo.join(".githooks/pre-commit"))
            .current_dir(temp.path())
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .env(
                "PATH",
                std::env::join_paths(std::iter::once(bin).chain(std::env::split_paths(
                    &std::env::var_os("PATH").expect("PATH"),
                )))
                .expect("fixture PATH"),
            )
            .env(
                "KIDOBO_TEST_COMMIT_CHECK",
                repo.join("scripts/check-commit.sh"),
            )
            .env("KIDOBO_TEST_JUST_LOG", &log)
            .output()
            .expect("run pre-commit hook");
        assert_eq!(
            output.status.success(),
            !contents.ends_with(" \n"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(log.exists(), checks);
        if checks {
            assert_eq!(
                read_to_string_with_limit(&log, 4096).expect("checks"),
                "format-check test-fast\n"
            );
        }
        assert_eq!(
            read_to_string_with_limit(&source, 4096).expect("unchanged source"),
            contents
        );
    }
}
