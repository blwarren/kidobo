#![cfg(unix)]

use std::fs;

use kidobo_adapters::limited_io::read_to_string_with_limit;

#[path = "support/terminal.rs"]
mod terminal;

use terminal::{Fixture, OutputDestination};

const INLINE_CONFIG: &str = "# preserve this comment\nipset = { set_name = 'custom' }\nsafe = { ips = ['192.0.2.0/24'], include_github_meta = false }\nremote = { urls = ['https://feed.example/list'], timeout_secs = 30 } # preserve inline table\nasn = { banned = [64512] }\n";

fn saved_config(fixture: &Fixture) -> String {
    read_to_string_with_limit(&fixture.root().join("config/config.toml"), 65_536)
        .expect("read bounded config")
}

#[test]
fn source_listing_is_offline_and_reports_unknown_freshness_without_ansi() {
    let fixture = Fixture::new(INLINE_CONFIG, "");
    let output = fixture
        .spawn(&["sources", "list"], 80, OutputDestination::Pipe, &[])
        .wait();

    assert!(output.status.success(), "{}", output.stderr);
    assert!(output.stdout.contains("Configured remote feeds"));
    assert!(output.stdout.contains("Freshness"));
    assert!(output.stdout.contains("Unknown"));
    assert!(!output.stdout.contains('\u{1b}'));
    assert_eq!(fixture.tool_log(), "");
    assert_eq!(saved_config(&fixture), INLINE_CONFIG);
}

#[test]
fn source_add_preserves_comments_inline_tables_and_unrelated_configuration() {
    let fixture = Fixture::new(INLINE_CONFIG, "");
    let output = fixture
        .spawn(
            &["sources", "add", "https://new.example/feed"],
            80,
            OutputDestination::Pipe,
            &[],
        )
        .wait();

    assert!(output.status.success(), "{}", output.stderr);
    assert!(output.stdout.contains("live enforcement is pending"));
    let contents = saved_config(&fixture);
    assert!(contents.starts_with("# preserve this comment\n"));
    assert!(contents.contains("remote = {"));
    assert!(contents.contains("# preserve inline table"));
    assert!(contents.contains("timeout_secs = 30"));
    assert!(contents.contains("https://feed.example/list"));
    assert!(contents.contains("https://new.example/feed"));
    assert!(contents.contains("set_name = 'custom'"));
    assert!(contents.contains("banned = [64512]"));
    assert_eq!(fixture.tool_log(), "");
}

#[test]
fn duplicate_or_invalid_source_add_does_not_rewrite_configuration() {
    let fixture = Fixture::new(INLINE_CONFIG, "");
    for url in ["https://FEED.example:443/list", "file:///tmp/feed"] {
        let before = saved_config(&fixture);
        let output = fixture
            .spawn(&["sources", "add", url], 80, OutputDestination::Pipe, &[])
            .wait();

        assert!(!output.status.success(), "{url} unexpectedly succeeded");
        assert_eq!(saved_config(&fixture), before);
        assert_eq!(fixture.tool_log(), "");
    }
}

#[test]
fn duplicate_source_error_does_not_echo_url_credentials_or_tokens() {
    let secret_config = "[ipset]\nset_name = 'kidobo'\n[remote]\nurls = ['https://alice:password-secret@feed.example/list?token=query-secret#fragment-secret']\n";
    let fixture = Fixture::new(secret_config, "");
    let output = fixture
        .spawn(
            &["sources", "add", "https://alice:password-secret@feed.example/list?token=query-secret#fragment-secret"],
            80,
            OutputDestination::Pipe,
            &[],
        )
        .wait();
    let rendered = format!("{}{}", output.stdout, output.stderr);

    assert!(!output.status.success());
    for secret in [
        "alice",
        "password-secret",
        "query-secret",
        "fragment-secret",
    ] {
        assert!(
            !rendered.contains(secret),
            "error leaked {secret}: {rendered}"
        );
    }
    assert_eq!(
        read_to_string_with_limit(&fixture.root().join("config/config.toml"), 65_536)
            .expect("read config"),
        secret_config
    );
    assert_eq!(fixture.tool_log(), "");
}

#[test]
fn exact_allow_duplicate_is_a_no_op_without_confirmation() {
    let fixture = Fixture::new(INLINE_CONFIG, "");
    let before = saved_config(&fixture);
    let output = fixture
        .spawn(
            &["allow", "add", "192.0.2.0/24"],
            80,
            OutputDestination::Terminal,
            &[],
        )
        .wait();

    assert!(output.status.success(), "{}", output.stderr);
    assert!(output.stdout.contains("No configuration change was needed"));
    assert!(
        !output
            .stdout
            .contains("Expand the saved safelist exemption?")
    );
    assert_eq!(saved_config(&fixture), before);
    assert_eq!(fixture.tool_log(), "");
}

#[test]
fn covered_distinct_allow_can_be_saved_without_a_confirmation_prompt() {
    let fixture = Fixture::new(INLINE_CONFIG, "");
    let output = fixture
        .spawn(
            &["allow", "add", "192.0.2.7"],
            80,
            OutputDestination::Pipe,
            &[],
        )
        .wait();

    assert!(output.status.success(), "{}", output.stderr);
    assert!(output.stdout.contains("Configuration change saved"));
    assert!(
        !output
            .stdout
            .contains("Expand the saved safelist exemption?")
    );
    let saved = saved_config(&fixture);
    assert!(saved.contains("192.0.2.0/24"));
    assert!(saved.contains("192.0.2.7"));
    assert_eq!(fixture.tool_log(), "");
}

#[test]
fn expanding_allow_needs_yes_when_piped_and_tty_decline_does_not_save() {
    let fixture = Fixture::new(INLINE_CONFIG, "");
    let before = saved_config(&fixture);
    let piped = fixture
        .spawn(
            &["allow", "add", "198.51.100.0/24"],
            80,
            OutputDestination::Pipe,
            &[],
        )
        .wait();
    assert_eq!(piped.status.code(), Some(2));
    assert!(piped.stderr.contains("use --yes"));
    assert_eq!(saved_config(&fixture), before);

    let declined = fixture
        .spawn(
            &["allow", "add", "198.51.100.0/24"],
            80,
            OutputDestination::Terminal,
            &[],
        )
        .respond_after("Expand the saved safelist exemption?", "n\n");
    assert!(declined.status.success(), "{}", declined.stderr);
    assert!(declined.stdout.contains("Safelist unchanged"));
    assert_eq!(saved_config(&fixture), before);
    assert_eq!(fixture.tool_log(), "");
}

#[test]
fn explicit_allow_approval_saves_configuration_without_syncing() {
    let fixture = Fixture::new(INLINE_CONFIG, "");
    let output = fixture
        .spawn(
            &["allow", "add", "198.51.100.0/24", "--yes"],
            80,
            OutputDestination::Pipe,
            &[],
        )
        .wait();

    assert!(output.status.success(), "{}", output.stderr);
    assert!(saved_config(&fixture).contains("198.51.100.0/24"));
    assert!(output.stdout.contains("live enforcement is pending"));
    assert_eq!(fixture.tool_log(), "");
}

#[test]
fn config_show_redacts_sensitive_url_parts_and_reports_origins_and_unused_legacy_value() {
    let config = "[ipset]\nset_name = 'custom'\n[safe]\ninclude_github_meta = false\n[remote]\nurls = ['https://alice:password-secret@feed.example/list?token=query-secret#fragment-secret']\ncache_stale_after_secs = 123\n[asn]\nbanned = []\n";
    let fixture = Fixture::new(config, "");
    let output = fixture
        .spawn(&["config", "show"], 80, OutputDestination::Pipe, &[])
        .wait();
    let rendered = format!("{}{}", output.stdout, output.stderr);

    assert!(output.status.success(), "{}", output.stderr);
    for secret in [
        "alice",
        "password-secret",
        "query-secret",
        "fragment-secret",
    ] {
        assert!(!rendered.contains(secret), "leaked {secret}: {rendered}");
    }
    assert!(output.stdout.contains("explicit"));
    assert!(output.stdout.contains("default"));
    assert!(output.stdout.contains("derived"));
    assert!(output.stdout.contains("remote.cache_stale_after_secs"));
    assert!(
        output
            .stdout
            .contains("Compatibility only; this value does not control refresh")
    );
    assert!(!output.stdout.contains('\u{1b}'));
    assert_eq!(fixture.tool_log(), "");
}

#[test]
fn config_path_is_available_before_initialization_and_does_not_create_files() {
    let fixture = Fixture::new(INLINE_CONFIG, "");
    fs::remove_file(fixture.root().join("config/config.toml")).expect("remove config fixture");
    let output = fixture
        .spawn(&["config", "path"], 80, OutputDestination::Pipe, &[])
        .wait();

    assert!(output.status.success(), "{}", output.stderr);
    assert_eq!(
        output.stdout.trim(),
        fixture
            .root()
            .join("config/config.toml")
            .display()
            .to_string()
    );
    assert!(!fixture.root().join("config/config.toml").exists());
    assert_eq!(fixture.tool_log(), "");
}
