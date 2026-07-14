use std::fmt::Write;
use std::path::{Path, PathBuf};

pub(super) const DEFAULT_CONFIG_TEMPLATE: &str = r#"[ipset]
set_name = "kidobo"
chain_action = "DROP"

[safe]
ips = []
include_github_meta = true
github_meta_url = "https://api.github.com/meta"
# github_meta_categories = ["api", "git", "hooks", "packages"]

[remote]
timeout_secs = 30
cache_stale_after_secs = 86400
urls = []

[asn]
banned = []
cache_stale_after_secs = 86400
"#;

pub(super) const DEFAULT_BLOCKLIST_TEMPLATE: &str =
    "# Add one IP or CIDR entry per line.\n# Example: 203.0.113.7\n";

pub(super) const DEFAULT_SYSTEMD_DIR: &str = "/etc/systemd/system";
pub(super) const KIDOBO_SYNC_SERVICE_FILE: &str = "kidobo-sync.service";
pub(super) const KIDOBO_SYNC_TIMER_FILE: &str = "kidobo-sync.timer";

pub(super) const DEFAULT_SYSTEMD_TIMER_TEMPLATE: &str = r#"[Unit]
Description=Run kidobo sync periodically

[Timer]
OnBootSec=2min
OnUnitActiveSec=1h
Persistent=true
Unit=kidobo-sync.service

[Install]
WantedBy=timers.target
"#;

pub(super) fn resolve_systemd_dir(kido_root_override: Option<&Path>) -> PathBuf {
    kido_root_override.map_or_else(
        || PathBuf::from(DEFAULT_SYSTEMD_DIR),
        |root| root.join("systemd/system"),
    )
}

pub(super) fn build_systemd_service_template(
    executable_path: &Path,
    kido_root_override: Option<&Path>,
) -> String {
    let mut output = String::from(
        "[Unit]\n\
Description=Kidobo firewall blocklist sync\n\
After=network-online.target\n\
Wants=network-online.target\n\
\n\
[Service]\n\
Type=oneshot\n",
    );

    let _journal_environment_write =
        writeln!(&mut output, "Environment=\"KIDOBO_LOG_FORMAT=journal\"");

    if let Some(root) = kido_root_override {
        let root_value = root.to_string_lossy();
        let _root_environment_write = writeln!(
            &mut output,
            "Environment=\"KIDOBO_ROOT={}\"",
            escape_systemd_value(root_value.as_ref())
        );
    }

    let executable = executable_path.to_string_lossy();
    let _exec_start_write = writeln!(
        &mut output,
        "ExecStart=\"{}\" sync",
        escape_systemd_value(executable.as_ref())
    );

    output
}

fn escape_systemd_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            _ => escaped.push(ch),
        }
    }

    escaped
}
