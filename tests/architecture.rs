use std::path::Path;

fn manifest(path: &str) -> String {
    kidobo_adapters::limited_io::read_to_string_with_limit(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join(path),
        128 * 1024,
    )
    .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

#[test]
fn dependency_direction_points_inward() {
    let core = manifest("crates/kidobo-core/Cargo.toml");
    assert!(!core.contains("kidobo-app"));
    assert!(!core.contains("kidobo-adapters"));
    assert!(!core.contains("clap"));

    let app = manifest("crates/kidobo-app/Cargo.toml");
    assert!(app.contains("kidobo-core.workspace = true"));
    assert!(!app.contains("kidobo-adapters"));
    assert!(!app.contains("clap"));

    let adapters = manifest("crates/kidobo-adapters/Cargo.toml");
    assert!(adapters.contains("kidobo-app.workspace = true"));
    assert!(adapters.contains("kidobo-core.workspace = true"));
    assert!(!adapters.contains("clap"));
}

#[test]
fn internal_crates_remain_unpublished_and_unversioned() {
    for path in [
        "crates/kidobo-core/Cargo.toml",
        "crates/kidobo-app/Cargo.toml",
        "crates/kidobo-adapters/Cargo.toml",
    ] {
        let contents = manifest(path);
        assert!(contents.contains("version = \"0.0.0\""), "{path}");
        assert!(contents.contains("publish = false"), "{path}");
    }
}

#[test]
fn root_manifest_keeps_direct_release_version() {
    let root = manifest("Cargo.toml");
    let package = root
        .split_once("[package]")
        .map(|(_, package)| package)
        .expect("root package table");
    assert!(package.starts_with(&format!(
        "\nname = \"kidobo\"\nversion = \"{}\"",
        env!("CARGO_PKG_VERSION")
    )));
}

#[test]
fn cli_dispatch_does_not_hold_global_output_locks() {
    let root_cli = manifest("src/cli/mod.rs");
    assert!(
        !root_cli.contains("stdout.lock()"),
        "root CLI dispatch must not hold the global stdout lock while worker threads can log"
    );
    assert!(
        !root_cli.contains("stderr.lock()"),
        "root CLI dispatch must not hold the global stderr lock while worker threads can log"
    );
}

#[test]
fn local_ci_gate_covers_release_policy_and_executes_the_built_binary() {
    let justfile = manifest("Justfile");
    let exercise_recipe = justfile
        .lines()
        .find(|line| line.starts_with("exercise-release:"))
        .expect("release exercise recipe");
    assert!(
        exercise_recipe
            .split_whitespace()
            .any(|word| word == "build-release"),
        "the release exercise must build the release binary first"
    );
    assert!(
        justfile.contains(
            "KIDOBO_TEST_BINARY=\"${CARGO_TARGET_DIR:-target}/release/kidobo\" cargo test"
        ),
        "the release exercise must run CLI tests against the built release binary"
    );

    let ci_recipe = justfile
        .lines()
        .find(|line| line.starts_with("ci:"))
        .expect("CI recipe");
    for required_step in ["release-notes-check", "coverage", "exercise-release"] {
        assert!(
            ci_recipe
                .split_whitespace()
                .any(|word| word == required_step),
            "local CI must include {required_step}"
        );
    }
    assert!(
        !justfile
            .lines()
            .any(|line| line.starts_with("verify-release:")),
        "the overlapping verify-release recipe must remain removed"
    );
}

#[test]
fn dependabot_is_the_only_github_hosted_automation() {
    let repository_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(repository_root.join(".github/dependabot.yml").is_file());
    for workflow in ["ci.yml", "release.yml", "udeps-audit.yml"] {
        assert!(
            !repository_root
                .join(".github/workflows")
                .join(workflow)
                .is_file(),
            "GitHub Actions workflow must remain removed: {workflow}"
        );
    }
}
