#![cfg(unix)]

use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::TempDir;

const APPLICATION_PACKAGES: [&str; 4] = ["kidobo", "kidobo-adapters", "kidobo-app", "kidobo-core"];

fn repository() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn executable(path: &Path, source: &str) {
    fs::write(path, source).expect("write fake tool");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .expect("make fake tool executable");
}

struct Fixture {
    root: TempDir,
}

impl Fixture {
    fn new() -> Self {
        let root = TempDir::new().expect("fixture directory");
        let bin = root.path().join("bin");
        fs::create_dir(&bin).expect("fake tool directory");
        for tool in ["cargo", "rustfmt"] {
            executable(
                &bin.join(tool),
                r#"#!/bin/bash
set -eu
tool=${0##*/}
printf '%s' "$tool" >> "$VALIDATION_TRACE"
printf '\t%s' "$@" >> "$VALIDATION_TRACE"
printf '\n' >> "$VALIDATION_TRACE"
if [[ "$tool" == cargo && "${1:-}" == doc ]]; then
    printf '%s\n' "${RUSTDOCFLAGS:-}" > "$VALIDATION_RUSTDOC_FLAGS"
fi
if [[ "${VALIDATION_FAIL:-}" == "$tool" || "${VALIDATION_FAIL:-}" == "$tool:${1:-}" ]]; then
    exit 37
fi
"#,
            );
        }
        for tool in [
            "incus",
            "tmux",
            "curl",
            "gpg",
            "qemu-img",
            "genisoimage",
            "mkisofs",
        ] {
            executable(
                &bin.join(tool),
                "#!/bin/bash\nprintf 'FORBIDDEN:%s\\n' \"${0##*/}\" >> \"$VALIDATION_TRACE\"\nexit 98\n",
            );
        }
        Self { root }
    }

    fn command(&self, program: &str) -> Command {
        let mut command = Command::new(program);
        command
            .current_dir(repository())
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    self.root.path().join("bin").display(),
                    std::env::var("PATH").expect("PATH")
                ),
            )
            .env("VALIDATION_TRACE", self.root.path().join("trace"))
            .env("VALIDATION_RUSTDOC_FLAGS", self.root.path().join("rustdoc"))
            .env_remove("VALIDATION_FAIL");
        command
    }

    fn recipe(&self, name: &str) -> Output {
        self.command("just")
            .arg(name)
            .output()
            .expect("run actual Just recipe with fake tools")
    }

    fn text(&self, name: &str) -> String {
        let path = self.root.path().join(name);
        if !path.exists() {
            return String::new();
        }
        let file = fs::File::open(path).expect("open fixture log");
        assert!(file.metadata().unwrap().len() <= 128 * 1024);
        let mut text = String::new();
        file.take(128 * 1024)
            .read_to_string(&mut text)
            .expect("read bounded fixture log");
        text
    }

    fn commands(&self) -> Vec<Vec<String>> {
        self.text("trace")
            .lines()
            .map(|line| line.split('\t').map(str::to_owned).collect())
            .collect()
    }
}

fn selection(arguments: &[String], flags: &[&str]) -> BTreeSet<String> {
    arguments
        .windows(2)
        .filter(|pair| flags.contains(&pair[0].as_str()))
        .map(|pair| pair[1].clone())
        .collect()
}

fn has(arguments: &[String], value: &str) -> bool {
    arguments.iter().any(|argument| argument == value)
}

fn invocation<'a>(commands: &'a [Vec<String>], tool: &str, action: &str) -> &'a [String] {
    commands
        .iter()
        .find(|arguments| arguments[0] == tool && arguments.get(1).is_some_and(|arg| arg == action))
        .expect("expected validation command")
}

struct Inventory {
    tests: BTreeSet<String>,
    roots: BTreeSet<PathBuf>,
    benches: BTreeSet<String>,
    examples: BTreeSet<String>,
}

fn inventory() -> Inventory {
    let output = Command::new(env!("CARGO"))
        .current_dir(repository())
        .args([
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
            "--offline",
            "--locked",
        ])
        .output()
        .expect("read Cargo target inventory without building");
    assert!(output.status.success(), "{output:?}");
    let metadata: Value = serde_json::from_slice(&output.stdout).expect("Cargo metadata JSON");
    let packages = metadata["packages"].as_array().expect("workspace packages");
    let names: BTreeSet<_> = packages
        .iter()
        .map(|package| package["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        APPLICATION_PACKAGES
            .into_iter()
            .chain(["kidobo-e2e"])
            .collect(),
        "classify any new workspace package before changing the scoped release policy"
    );
    let mut inventory = Inventory {
        tests: BTreeSet::new(),
        roots: BTreeSet::new(),
        benches: BTreeSet::new(),
        examples: BTreeSet::new(),
    };
    for package in packages {
        let package_name = package["name"].as_str().unwrap();
        if package_name == "kidobo-e2e" {
            continue;
        }
        for target in package["targets"].as_array().unwrap() {
            let name = target["name"].as_str().unwrap();
            let kinds = target["kind"].as_array().unwrap();
            assert_eq!(kinds.len(), 1, "classify new target kinds explicitly");
            let kind = kinds[0].as_str().unwrap();
            if name.starts_with("e2e_") {
                assert_eq!(package_name, "kidobo");
                assert_eq!(
                    kind, "test",
                    "E2E targets belong in root e2e_* tests or kidobo-e2e"
                );
                continue;
            }
            inventory
                .roots
                .insert(PathBuf::from(target["src_path"].as_str().unwrap()));
            match kind {
                "lib" | "bin" => {}
                "test" | "bench" | "example" => {
                    assert_eq!(
                        package_name, "kidobo",
                        "extend scoped selection for new package targets"
                    );
                    match kind {
                        "test" => &mut inventory.tests,
                        "bench" => &mut inventory.benches,
                        _ => &mut inventory.examples,
                    }
                    .insert(name.to_owned());
                }
                _ => panic!("classify new target kind {kind} in the scoped release policy"),
            }
        }
    }
    inventory
}

#[test]
fn scoped_recipes_select_every_application_target_without_e2e() {
    let inventory = inventory();
    let fixture = Fixture::new();
    for recipe in [
        "_release-ci-without-e2e",
        "_release-coverage-without-e2e",
        "_release-rustdoc-without-e2e",
    ] {
        let output = fixture.recipe(recipe);
        assert!(output.status.success(), "{recipe}: {output:?}");
    }
    let commands = fixture.commands();
    assert_eq!(
        commands.len(),
        7,
        "unexpected tools or validation actions: {commands:?}"
    );
    for command in &commands {
        assert!(
            !command
                .iter()
                .any(|arg| arg.contains("e2e_") || arg.contains("distro-e2e")),
            "{command:?}"
        );
        assert!(!has(command, "--all-targets"), "{command:?}");
    }
    let format = invocation(&commands, "rustfmt", "--check");
    assert_eq!(
        selection(format, &["--edition"]),
        BTreeSet::from(["2024".into()])
    );
    let roots = format
        .iter()
        .filter(|arg| Path::new(arg).extension().is_some_and(|ext| ext == "rs"))
        .map(|arg| repository().join(arg))
        .collect();
    assert_eq!(
        inventory.roots, roots,
        "formatter must cover exactly the non-E2E Cargo target roots"
    );
    for action in ["clippy", "llvm-cov", "doc"] {
        let arguments = invocation(&commands, "cargo", action);
        assert_eq!(
            selection(arguments, &["-p", "--package"]),
            APPLICATION_PACKAGES.map(str::to_owned).into()
        );
        assert!(has(arguments, "--all-features"));
        assert!(!has(arguments, "--workspace"));
        assert!(!has(arguments, "kidobo-e2e"));
        if action != "doc" {
            assert!(has(arguments, "--lib"));
            assert!(has(arguments, "--bins"));
            assert_eq!(selection(arguments, &["--test"]), inventory.tests);
        }
    }
    let lint = invocation(&commands, "cargo", "clippy");
    assert_eq!(selection(lint, &["--bench"]), inventory.benches);
    assert_eq!(selection(lint, &["--example"]), inventory.examples);
    assert!(lint.ends_with(&["--".into(), "-D".into(), "warnings".into()]));
    let coverage = invocation(&commands, "cargo", "llvm-cov");
    for threshold in [
        "--fail-under-regions",
        "--fail-under-functions",
        "--fail-under-lines",
    ] {
        assert_eq!(
            selection(coverage, &[threshold]),
            BTreeSet::from(["90".into()])
        );
    }
    assert!(has(invocation(&commands, "cargo", "doc"), "--no-deps"));
    assert_eq!(fixture.text("rustdoc"), "-D warnings\n");
    assert_application_correctness_and_dependencies(&commands);
}

fn assert_application_correctness_and_dependencies(commands: &[Vec<String>]) {
    assert_eq!(
        invocation(commands, "cargo", "deny"),
        [
            "cargo",
            "deny",
            "check",
            "advisories",
            "bans",
            "licenses",
            "sources"
        ]
    );
    assert_eq!(invocation(commands, "cargo", "audit"), ["cargo", "audit"]);
    let tests = invocation(commands, "cargo", "test");
    assert!(has(tests, "--workspace"));
    assert!(has(tests, "--lib"));
    assert_eq!(
        selection(tests, &["--exclude"]),
        BTreeSet::from(["kidobo-e2e".into()])
    );
    assert_eq!(
        selection(tests, &["--test"]),
        [
            "cli_runtime",
            "configuration_cli",
            "doctor_command",
            "error_contracts",
            "inspection_cli",
            "mutation_cli",
            "preview_cli",
            "setup_cli",
            "terminal_cli"
        ]
        .map(str::to_owned)
        .into()
    );
}

#[test]
fn scoped_checks_propagate_each_gate_failure_without_later_work() {
    for (action, failure) in [
        ("ci", "rustfmt"),
        ("ci", "cargo:clippy"),
        ("ci", "cargo:deny"),
        ("ci", "cargo:audit"),
        ("ci", "cargo:test"),
        ("coverage", "cargo:llvm-cov"),
        ("rustdoc", "cargo:doc"),
    ] {
        let fixture = Fixture::new();
        let output = fixture
            .command("just")
            .arg(format!("_release-{action}-without-e2e"))
            .env("VALIDATION_FAIL", failure)
            .output()
            .expect("run failing validation boundary");
        assert!(!output.status.success(), "{failure}: {output:?}");
        let commands = fixture.commands();
        let last = commands.last().expect("failing tool was invoked");
        let expected: Vec<_> = failure.split(':').collect();
        assert_eq!(
            last[..expected.len()],
            expected,
            "work continued after failure"
        );
    }
}

#[test]
fn explicit_e2e_tests_and_other_developer_gates_cover_workspace() {
    let fixture = Fixture::new();
    let output = fixture
        .command("just")
        .args(["test", "--include-e2e"])
        .output()
        .expect("run full workspace tests with fake tools");
    assert!(output.status.success(), "{output:?}");
    for recipe in ["lint", "format-check", "coverage", "rustdoc"] {
        let output = fixture.recipe(recipe);
        assert!(output.status.success(), "{recipe}: {output:?}");
    }
    let commands = fixture.commands();
    assert_eq!(commands.len(), 5);
    for action in ["test", "clippy", "llvm-cov", "doc"] {
        let arguments = invocation(&commands, "cargo", action);
        assert!(has(arguments, "--workspace"));
        assert!(!has(arguments, "--exclude"));
        assert!(!has(arguments, "--test"));
    }
    assert_eq!(
        invocation(&commands, "cargo", "fmt"),
        ["cargo", "fmt", "--all", "--check"]
    );
}
