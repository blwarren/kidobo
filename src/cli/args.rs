use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;

use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum, ValueHint};
use kidobo_app::blocklist::BanDuration;
use log::LevelFilter;

const ROOT_HELP: &str = "{name} {version}\n{about-with-newline}\n{usage-heading} {usage}\n\nEveryday:\n  setup     Review first-time configuration\n  ban       Save a permanent or temporary ban\n  unban     Remove a saved local ban\n  sync      Apply saved sources to the firewall\n\nInspect and troubleshoot:\n  status    Inspect live managed enforcement\n  check     Verify Kidobo blocking for one IP\n  bans      List saved operator-managed bans\n  doctor    Check configuration and prerequisites\n  lookup    Find offline source overlaps\n\nConfiguration and advanced:\n  completions  Print shell completion scripts\n  sources   Manage configured remote feeds\n  allow     Manage safelist exemptions\n  config    Inspect settings and file paths\n  init      Create missing files and enable scheduling\n  flush     Remove managed firewall state and cache\n  help      Show help for a command\n\nOptions:\n{options}\n{after-help}";

#[derive(Debug, Parser)]
#[command(
    name = "kidobo",
    version,
    about = "One-shot firewall blocklist manager",
    long_about = "Manage Kidobo firewall blocklists with one-shot commands.",
    help_template = ROOT_HELP,
    after_help = "Examples: kidobo ban 203.0.113.7 --for 12h\n          kidobo ban --asn AS64496\n          kidobo lookup 203.0.113.7 --format tsv"
)]
pub struct Cli {
    #[arg(
        long = "log-level",
        value_enum,
        default_value_t = LogLevel::Info,
        global = true,
        help = "Set stderr log verbosity"
    )]
    pub log_level: LogLevel,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LookupFormat {
    Human,
    Tsv,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReportFormat {
    Human,
    Json,
}

#[derive(Debug, Args)]
pub struct ApplicationArgs {
    #[arg(
        long,
        conflicts_with = "no_apply",
        help = "Run sync after saving; also repair enforcement when no source change is needed"
    )]
    pub apply: bool,
    #[arg(long, help = "Save sources only; never offer to run sync")]
    pub no_apply: bool,
}

impl ApplicationArgs {
    pub fn mode(&self) -> super::mutation::ApplyMode {
        if self.apply {
            super::mutation::ApplyMode::Apply
        } else if self.no_apply {
            super::mutation::ApplyMode::SaveOnly
        } else {
            super::mutation::ApplyMode::Prompt
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum SourceAction {
    #[command(
        about = "List configured feeds and validated cache availability",
        after_help = "Example: kidobo sources list"
    )]
    List,
    #[command(
        about = "Save one HTTP(S) feed URL; enforcement waits for sync",
        after_help = "Example: sudo kidobo sources add https://example.org/feed.txt"
    )]
    Add {
        #[arg(value_hint = ValueHint::Url)]
        url: String,
    },
    #[command(
        about = "Remove a configured feed URL; enforcement waits for sync",
        after_help = "Example: sudo kidobo sources remove https://example.org/feed.txt"
    )]
    Remove {
        #[arg(value_hint = ValueHint::Url)]
        url: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum AllowAction {
    #[command(
        about = "List saved operator-controlled exemptions",
        after_help = "Example: kidobo allow list"
    )]
    List,
    #[command(
        about = "Save an exemption applied by the next sync",
        after_help = "Examples: sudo kidobo allow add 203.0.113.7\n          sudo kidobo allow add 2001:db8::/64 --yes"
    )]
    Add {
        #[arg(value_name = "IP_OR_CIDR", value_hint = ValueHint::Other)]
        target: String,
        #[arg(
            long,
            help = "Explicitly approve expanding the exemption; required without an interactive terminal"
        )]
        yes: bool,
    },
    #[command(
        about = "Remove an exact saved exemption; enforcement waits for sync",
        after_help = "Example: sudo kidobo allow remove 203.0.113.7"
    )]
    Remove {
        #[arg(value_name = "IP_OR_CIDR", value_hint = ValueHint::Other)]
        target: String,
    },
}

#[derive(Debug, Clone, Copy, Subcommand)]
pub enum ConfigAction {
    #[command(
        about = "Show redacted settings, defaults, and their origins",
        after_help = "Example: kidobo config show"
    )]
    Show,
    #[command(
        about = "Print the resolved configuration filename",
        after_help = "Example: kidobo config path"
    )]
    Path,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CompletionShell {
    Bash,
    Zsh,
    Fish,
}

impl CompletionShell {
    pub fn generator(self) -> clap_complete::Shell {
        match self {
            Self::Bash => clap_complete::Shell::Bash,
            Self::Zsh => clap_complete::Shell::Zsh,
            Self::Fish => clap_complete::Shell::Fish,
        }
    }
}

impl From<LogLevel> for LevelFilter {
    fn from(value: LogLevel) -> Self {
        match value {
            LogLevel::Trace => LevelFilter::Trace,
            LogLevel::Debug => LevelFilter::Debug,
            LogLevel::Info => LevelFilter::Info,
            LogLevel::Warn => LevelFilter::Warn,
            LogLevel::Error => LevelFilter::Error,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(
        about = "Print shell completion code without reading configuration",
        long_about = "Generate Bash, Zsh, or Fish completion code and write it to stdout without reading configuration.",
        after_help = "Examples: kidobo completions bash > kidobo.bash\n          source ./kidobo.bash\n          kidobo completions zsh\n          kidobo completions fish"
    )]
    Completions {
        #[arg(value_enum)]
        shell: CompletionShell,
    },
    #[command(
        about = "Review settings and guide first-time configuration",
        long_about = "Interactively review IPv4/IPv6, feeds, and safelists before saving. Preserve existing files, provision missing files, and run doctor. Confirm initial sync and timer activation separately.",
        after_help = "Example: sudo kidobo setup"
    )]
    Setup,
    #[command(
        about = "Inspect, add, or remove configured remote feeds",
        long_about = "List configured feeds and validated cache availability, or edit remote.urls. Edits take effect at the next sync. Sensitive URL values are redacted.",
        after_help = "Examples: kidobo sources\n          sudo kidobo sources add https://example.org/feed.txt\n          sudo kidobo sources remove https://example.org/feed.txt"
    )]
    Sources {
        #[command(subcommand)]
        action: Option<SourceAction>,
    },
    #[command(
        about = "Manage operator-controlled safelist exemptions",
        long_about = "List or edit safe.ips exemptions, applied at the next sync. Expanding coverage requires confirmation or --yes. Removal uses exact canonical identity.",
        after_help = "Examples: kidobo allow\n          sudo kidobo allow add 203.0.113.7\n          sudo kidobo allow add 2001:db8::/64 --yes\n          sudo kidobo allow remove 203.0.113.7"
    )]
    Allow {
        #[command(subcommand)]
        action: Option<AllowAction>,
    },
    #[command(
        about = "Show effective configuration or its filename",
        after_help = "Examples: kidobo config show\n          kidobo config path"
    )]
    Config {
        #[command(subcommand)]
        action: Option<ConfigAction>,
    },
    #[command(
        about = "Inspect configuration and live managed enforcement",
        long_about = "Inspect saved configuration, live managed sets and wiring, local bans, and timer scheduling. Unverified fields are shown as unknown.",
        after_help = "Examples: kidobo\n          sudo kidobo status\n          kidobo status --format json"
    )]
    Status {
        #[arg(long, value_enum, default_value_t = ReportFormat::Human)]
        format: ReportFormat,
    },
    #[command(
        about = "Check Kidobo's live enforcement for one IP",
        long_about = "Check managed set membership and incoming firewall wiring for one IPv4 or IPv6 address. Report BLOCKED BY KIDOBO, NOT BLOCKED BY KIDOBO, or UNKNOWN. Verified verdicts exit 0; unknown exits 1.",
        after_help = "Examples: sudo kidobo check 203.0.113.7\n          sudo kidobo check 2001:db8::7 --format json"
    )]
    Check {
        #[arg(
            value_name = "IP",
            value_parser = parse_check_ip,
            value_hint = ValueHint::Other
        )]
        ip: IpAddr,
        #[arg(long, value_enum, default_value_t = ReportFormat::Human)]
        format: ReportFormat,
    },
    #[command(
        about = "List saved operator-managed bans",
        long_about = "List saved permanent IP/CIDR and ASN bans and temporary bans, including expired records awaiting cleanup. Read-only and offline.",
        after_help = "Examples: kidobo bans\n          kidobo bans --temporary\n          kidobo bans --permanent --asn --all\n          kidobo bans --limit 100"
    )]
    Bans {
        #[arg(long, conflicts_with = "permanent")]
        temporary: bool,
        #[arg(long)]
        permanent: bool,
        #[arg(long, help = "Only list operator-managed ASN identities")]
        asn: bool,
        #[arg(
            long,
            default_value = "50",
            value_hint = ValueHint::Other,
            help = "Maximum saved entries to display"
        )]
        limit: NonZeroUsize,
        #[arg(
            long,
            conflicts_with = "limit",
            help = "Display all entries within the storage limits"
        )]
        all: bool,
    },
    #[command(
        about = "Create missing config/data/cache files and systemd units",
        long_about = "Create missing config, data, cache, and systemd unit files. Preserve existing files. At default system paths, reload systemd, reset failed units, and enable and start kidobo-sync.timer.",
        after_help = "Example: sudo kidobo init"
    )]
    Init,
    #[command(
        about = "Check configuration and host prerequisites read-only",
        long_about = "Check configuration, environment, and dependencies without changing state. Default to human output in a terminal and JSON when redirected. Exit 0 when all required checks pass, otherwise 1.",
        after_help = "Examples: kidobo doctor\n          sudo kidobo doctor --format human\n          kidobo doctor --format json"
    )]
    Doctor {
        #[arg(
            long,
            value_enum,
            help = "Select human output or the compatible JSON report"
        )]
        format: Option<ReportFormat>,
    },
    #[command(
        about = "Sync local+remote blocklists into firewall/ipset state",
        long_about = "Load sources, subtract safelists, collapse entries, and update managed ipsets and firewall wiring. Validate both enabled families before replacing either set; each set replacement is atomic.",
        after_help = "Examples: sudo kidobo sync\n          sudo kidobo sync --timer\n          sudo kidobo sync --dry-run\n          sudo kidobo sync --dry-run --allow-network"
    )]
    Sync {
        #[arg(
            long,
            conflicts_with = "timer",
            help = "Preview using saved sources and validated caches; never write state or enforce"
        )]
        dry_run: bool,
        #[arg(
            long,
            requires = "dry_run",
            help = "Permit network reads held in memory during --dry-run; no cache writes"
        )]
        allow_network: bool,
        #[arg(
            long = "timer",
            help = "Emit per-stage sync timing logs to help profile runtime bottlenecks"
        )]
        timer: bool,
    },
    #[command(
        about = "Best-effort cleanup of kidobo runtime state",
        long_about = "Remove Kidobo's managed firewall rules, ipsets, and remote cache. Preserve local bans, configuration, and temporary-ban records. --cache-only clears the remote cache while preserving enforcement.",
        after_help = "Examples: sudo kidobo flush --yes\n          kidobo flush --cache-only"
    )]
    Flush {
        #[arg(long, help = "Confirm full removal without an interactive prompt")]
        yes: bool,
        #[arg(
            long = "cache-only",
            help = "Only clear cached remote source files (leave firewall/ipset state unchanged)"
        )]
        cache_only: bool,
    },
    #[command(
        about = "Add permanent or temporary IP/CIDR or ASN bans",
        long_about = "Save an IP/CIDR, targets from --file, or ASNs from --asn. Bans are permanent unless --for sets a duration. Repeating a temporary ban replaces its deadline. Sync applies saved bans and expiration. Interactive terminals offer sync after changes; noninteractive runs save only by default.",
        after_help = "Examples: sudo kidobo ban 203.0.113.7\n          sudo kidobo ban 203.0.113.7 --for 12h\n          sudo kidobo ban --asn AS64496\n          sudo kidobo ban 203.0.113.7 --apply",
        group(
            ArgGroup::new("ban_input")
                .args(["target", "file", "asn"])
                .required(true)
                .multiple(false)
        )
    )]
    Ban {
        #[command(flatten)]
        application: ApplicationArgs,
        #[arg(
            long = "for",
            value_name = "DURATION",
            value_hint = ValueHint::Other,
            help = "Ban for whole hours or days (12h, 3d), starting when recorded; applied/removed by sync"
        )]
        duration: Option<BanDuration>,
        #[arg(
            value_name = "IP_OR_CIDR",
            value_hint = ValueHint::Other,
            help = "Single IPv4/IPv6 address or CIDR to add"
        )]
        target: Option<String>,

        #[arg(
            long,
            value_name = "PATH",
            value_hint = ValueHint::FilePath,
            help = "File with one IPv4/IPv6 address or CIDR per line"
        )]
        file: Option<PathBuf>,

        #[arg(
            long = "asn",
            value_name = "ASN",
            num_args = 1..,
            value_hint = ValueHint::Other,
            help = "ASNs to ban (e.g. 213412 or AS213412)"
        )]
        asn: Option<Vec<String>>,
    },
    #[command(
        about = "Remove permanent and temporary IP/CIDR or ASN bans",
        long_about = "Remove an IP/CIDR, targets from --file, or ASNs from --asn from permanent and temporary local sources. Interactive terminals offer sync after changes; noninteractive runs save only by default. --yes approves overlap removal only.",
        after_help = "Examples: sudo kidobo unban 203.0.113.7\n          sudo kidobo unban --asn AS64496\n          sudo kidobo unban 203.0.113.0/24 --yes",
        group(
            ArgGroup::new("unban_input")
                .args(["target", "file", "asn"])
                .required(true)
                .multiple(false)
        )
    )]
    Unban {
        #[command(flatten)]
        application: ApplicationArgs,
        #[arg(
            value_name = "IP_OR_CIDR",
            value_hint = ValueHint::Other,
            help = "Single IPv4/IPv6 address or CIDR to remove"
        )]
        target: Option<String>,

        #[arg(
            long,
            value_name = "PATH",
            value_hint = ValueHint::FilePath,
            help = "File with one IPv4/IPv6 address or CIDR per line"
        )]
        file: Option<PathBuf>,

        #[arg(
            long = "asn",
            value_name = "ASN",
            num_args = 1..,
            value_hint = ValueHint::Other,
            help = "ASNs to unban (e.g. 213412 or AS213412)"
        )]
        asn: Option<Vec<String>>,

        #[arg(
            long,
            help = "Skip confirmation and remove overlapping entries if needed"
        )]
        yes: bool,
    },
    #[command(
        about = "Offline lookup across blocklist, safelist, and ASN sources",
        long_about = "Find offline source overlaps for an IP/CIDR or targets from --file. Search saved bans, safelists, and validated caches without fetching data. Warnings identify unavailable sources.",
        after_help = "Examples: kidobo lookup 203.0.113.7\n          kidobo lookup --file targets.txt --format tsv",
        group(
            ArgGroup::new("lookup_input")
                .args(["ip", "file"])
                .required(true)
                .multiple(false)
        )
    )]
    Lookup {
        #[arg(
            value_name = "IP_OR_CIDR",
            value_hint = ValueHint::Other,
            help = "Single target IP/CIDR to match"
        )]
        ip: Option<String>,

        #[arg(
            long,
            value_name = "PATH",
            value_hint = ValueHint::FilePath,
            help = "File with one target IP/CIDR per line"
        )]
        file: Option<PathBuf>,

        #[arg(
            long,
            value_enum,
            default_value_t = LookupFormat::Human,
            help = "Select readable records or tab-separated output for scripts"
        )]
        format: LookupFormat,
    },
}

fn parse_check_ip(value: &str) -> Result<IpAddr, String> {
    if value.contains('/') {
        return Err(
            "check accepts one IP address; use kidobo lookup IP_OR_CIDR for range/source overlaps"
                .to_string(),
        );
    }
    value
        .trim()
        .parse()
        .map_err(|_| "expected one IPv4 or IPv6 address".to_string())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{Cli, Command, LogLevel, LookupFormat};
    use clap::Parser;
    use clap::error::ErrorKind;
    use log::LevelFilter;

    #[test]
    fn log_level_mapping_matches_rust_levels() {
        assert_eq!(LevelFilter::from(LogLevel::Trace), LevelFilter::Trace);
        assert_eq!(LevelFilter::from(LogLevel::Debug), LevelFilter::Debug);
        assert_eq!(LevelFilter::from(LogLevel::Info), LevelFilter::Info);
        assert_eq!(LevelFilter::from(LogLevel::Warn), LevelFilter::Warn);
        assert_eq!(LevelFilter::from(LogLevel::Error), LevelFilter::Error);
    }

    #[test]
    fn flush_cache_only_flag_is_parsed() {
        let cli = Cli::try_parse_from(["kidobo", "flush", "--cache-only"]).expect("flush parse");
        match cli.command.expect("subcommand") {
            Command::Flush { cache_only, .. } => assert!(cache_only),
            _ => panic!("unexpected command variant"),
        }
    }

    #[test]
    fn sync_timer_flag_is_parsed() {
        let cli = Cli::try_parse_from(["kidobo", "sync", "--timer"]).expect("sync parse");
        match cli.command.expect("subcommand") {
            Command::Sync { timer, .. } => assert!(timer),
            _ => panic!("unexpected command variant"),
        }
    }

    #[test]
    fn ban_command_parses_target() {
        let cli = Cli::try_parse_from(["kidobo", "ban", "203.0.113.7"]).expect("ban parse");
        match cli.command.expect("subcommand") {
            Command::Ban {
                target, file, asn, ..
            } => {
                assert_eq!(target, Some("203.0.113.7".to_string()));
                assert!(file.is_none());
                assert!(asn.is_none());
            }
            _ => panic!("unexpected command variant"),
        }
    }

    #[test]
    fn ban_command_parses_file_mode() {
        let cli = Cli::try_parse_from(["kidobo", "ban", "--file", "targets.txt"]).expect("parse");
        match cli.command.expect("subcommand") {
            Command::Ban {
                target, file, asn, ..
            } => {
                assert!(target.is_none());
                assert_eq!(file, Some(PathBuf::from("targets.txt")));
                assert!(asn.is_none());
            }
            _ => panic!("unexpected command variant"),
        }
    }

    #[test]
    fn unban_command_parses_yes_flag() {
        let cli = Cli::try_parse_from(["kidobo", "unban", "203.0.113.0/24", "--yes"])
            .expect("unban parse");
        match cli.command.expect("subcommand") {
            Command::Unban {
                target,
                file,
                asn,
                yes,
                ..
            } => {
                assert_eq!(target, Some("203.0.113.0/24".to_string()));
                assert!(file.is_none());
                assert!(asn.is_none());
                assert!(yes);
            }
            _ => panic!("unexpected command variant"),
        }
    }

    #[test]
    fn unban_command_parses_file_mode() {
        let cli = Cli::try_parse_from(["kidobo", "unban", "--file", "targets.txt"]).expect("parse");
        match cli.command.expect("subcommand") {
            Command::Unban {
                target,
                file,
                asn,
                yes,
                ..
            } => {
                assert!(target.is_none());
                assert_eq!(file, Some(PathBuf::from("targets.txt")));
                assert!(asn.is_none());
                assert!(!yes);
            }
            _ => panic!("unexpected command variant"),
        }
    }

    #[test]
    fn ban_command_parses_multiple_asns() {
        let cli =
            Cli::try_parse_from(["kidobo", "ban", "--asn", "AS213412", "64512"]).expect("parse");
        match cli.command.expect("subcommand") {
            Command::Ban {
                target, file, asn, ..
            } => {
                assert!(target.is_none());
                assert!(file.is_none());
                assert_eq!(asn, Some(vec!["AS213412".to_string(), "64512".to_string()]));
            }
            _ => panic!("unexpected command variant"),
        }
    }

    #[test]
    fn analyze_umbrella_is_rejected() {
        let err = Cli::try_parse_from(["kidobo", "analyze", "overlap"])
            .expect_err("removed analyze command must fail");
        assert_eq!(err.kind(), ErrorKind::InvalidSubcommand);
    }

    #[test]
    fn lookup_command_parses_ip_mode() {
        let cli = Cli::try_parse_from(["kidobo", "lookup", "203.0.113.7"]).expect("lookup parse");
        match cli.command.expect("subcommand") {
            Command::Lookup { ip, file, format } => {
                assert_eq!(ip, Some("203.0.113.7".to_string()));
                assert!(file.is_none());
                assert_eq!(format, LookupFormat::Human);
            }
            _ => panic!("unexpected command variant"),
        }
    }

    #[test]
    fn lookup_command_parses_file_mode() {
        let cli =
            Cli::try_parse_from(["kidobo", "lookup", "--file", "targets.txt"]).expect("parse");
        match cli.command.expect("subcommand") {
            Command::Lookup { ip, file, format } => {
                assert!(ip.is_none());
                assert_eq!(file, Some(PathBuf::from("targets.txt")));
                assert_eq!(format, LookupFormat::Human);
            }
            _ => panic!("unexpected command variant"),
        }
    }

    #[test]
    fn lookup_command_parses_tsv_format() {
        let cli = Cli::try_parse_from(["kidobo", "lookup", "203.0.113.7", "--format", "tsv"])
            .expect("lookup parse");
        match cli.command.expect("subcommand") {
            Command::Lookup { format, .. } => assert_eq!(format, LookupFormat::Tsv),
            _ => panic!("unexpected command variant"),
        }
    }

    #[test]
    fn lookup_command_rejects_unknown_format() {
        let err = Cli::try_parse_from(["kidobo", "lookup", "203.0.113.7", "--format", "csv"])
            .expect_err("unknown lookup format must fail");
        assert_eq!(err.kind(), clap::error::ErrorKind::InvalidValue);
    }

    #[test]
    fn lookup_command_rejects_missing_input_mode() {
        let err = Cli::try_parse_from(["kidobo", "lookup"]).expect_err("lookup must fail");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn lookup_command_rejects_multiple_input_modes() {
        let err = Cli::try_parse_from(["kidobo", "lookup", "203.0.113.7", "--file", "targets.txt"])
            .expect_err("lookup must fail");
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn ban_command_rejects_missing_input_mode() {
        let err = Cli::try_parse_from(["kidobo", "ban"]).expect_err("ban must fail");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn ban_command_rejects_multiple_input_modes() {
        let err = Cli::try_parse_from(["kidobo", "ban", "203.0.113.7", "--file", "targets.txt"])
            .expect_err("ban must fail");
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn unban_command_rejects_missing_input_mode() {
        let err = Cli::try_parse_from(["kidobo", "unban"]).expect_err("unban must fail");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn unban_command_rejects_multiple_input_modes() {
        let err = Cli::try_parse_from(["kidobo", "unban", "203.0.113.7", "--file", "targets.txt"])
            .expect_err("unban must fail");
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn no_subcommand_selects_dashboard_without_a_parse_error() {
        assert!(
            Cli::try_parse_from(["kidobo"])
                .expect("default invocation")
                .command
                .is_none()
        );
    }

    #[test]
    fn check_rejects_ranges_before_execution_and_keeps_ipv6_distinct() {
        let error = Cli::try_parse_from(["kidobo", "check", "203.0.113.0/24"])
            .expect_err("range unsupported");
        assert_eq!(error.kind(), ErrorKind::ValueValidation);
        assert!(error.to_string().contains("kidobo lookup"));
        let parsed = Cli::try_parse_from(["kidobo", "check", "::ffff:203.0.113.7"])
            .expect("mapped IPv6 literal");
        match parsed.command.expect("command") {
            Command::Check { ip, .. } => assert!(ip.is_ipv6()),
            other => panic!("unexpected command {other:?}"),
        }
    }

    #[test]
    fn ban_list_bounds_and_lifetime_conflicts_are_checked() {
        for arguments in [
            vec!["kidobo", "bans", "--limit", "0"],
            vec!["kidobo", "bans", "--temporary", "--permanent"],
            vec!["kidobo", "bans", "--limit", "2", "--all"],
        ] {
            Cli::try_parse_from(arguments).expect_err("invalid filters");
        }
        Cli::try_parse_from(["kidobo", "bans", "--asn", "--all"]).expect("all ASN records");
    }

    #[test]
    fn application_controls_conflict_without_changing_overlap_yes() {
        for command in ["ban", "unban"] {
            let error =
                Cli::try_parse_from(["kidobo", command, "203.0.113.7", "--apply", "--no-apply"])
                    .expect_err("conflicting application choices");
            assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
        }
        let cli = Cli::try_parse_from(["kidobo", "unban", "203.0.113.7", "--yes"])
            .expect("overlap confirmation");
        match cli.command.expect("command") {
            Command::Unban {
                application, yes, ..
            } => {
                assert!(yes);
                assert!(!application.apply);
                assert!(!application.no_apply);
            }
            other => panic!("unexpected command {other:?}"),
        }
    }

    #[test]
    fn preview_permissions_are_explicit_and_normal_timer_mode_is_distinct() {
        Cli::try_parse_from(["kidobo", "sync", "--allow-network"])
            .expect_err("network permission requires preview");
        Cli::try_parse_from(["kidobo", "sync", "--dry-run", "--timer"])
            .expect_err("timer profiles the real sync sequence");
        let cli = Cli::try_parse_from(["kidobo", "sync", "--dry-run", "--allow-network"])
            .expect("explicit online preview");
        match cli.command.expect("command") {
            Command::Sync {
                dry_run,
                allow_network,
                timer,
            } => {
                assert!(dry_run);
                assert!(allow_network);
                assert!(!timer);
            }
            other => panic!("unexpected command {other:?}"),
        }
    }

    #[test]
    fn all_user_commands_have_built_in_examples() {
        use clap::CommandFactory;
        fn inspect(command: &clap::Command) {
            for child in command
                .get_subcommands()
                .filter(|child| child.get_name() != "help")
            {
                let help = child
                    .get_after_help()
                    .expect("each command has examples")
                    .to_string();
                assert!(
                    help.contains("Example"),
                    "missing examples for {}",
                    child.get_name()
                );
                inspect(child);
            }
        }
        inspect(&Cli::command());
    }
}
