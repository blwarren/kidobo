use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;

use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};
use kidobo_app::blocklist::BanDuration;
use log::LevelFilter;

const ROOT_HELP: &str = "{name} {version}\n{about-with-newline}\n{usage-heading} {usage}\n\nEveryday:\n  setup     Review first-time configuration\n  ban       Save a permanent or temporary ban\n  unban     Remove a saved local ban\n  sync      Apply saved sources to the firewall\n\nInspect and troubleshoot:\n  status    Inspect live managed enforcement\n  check     Verify Kidobo blocking for one IP\n  bans      List saved operator-managed bans\n  doctor    Check configuration and prerequisites\n  lookup    Find offline source overlaps\n\nConfiguration and advanced:\n  completions  Print shell completion scripts\n  sources   Manage configured remote feeds\n  allow     Manage safelist exemptions\n  config    Inspect settings and file paths\n  init      Create missing files and enable scheduling\n  flush     Remove managed firewall state and cache\n  help      Show help for a command\n\nOptions:\n{options}\n{after-help}";

#[derive(Debug, Parser)]
#[command(
    name = "kidobo",
    version,
    about = "One-shot firewall blocklist manager",
    long_about = "Manage Kidobo firewall blocklists with one-shot commands (no daemon/background service).",
    help_template = ROOT_HELP,
    after_help = "Start: kidobo\nDiagnose: kidobo doctor\nExamples: kidobo ban 203.0.113.7 --for 12h\n          kidobo ban --asn AS64496\n          kidobo lookup 203.0.113.7 --format tsv\nUse kidobo COMMAND --help for effects, examples, and recovery."
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
        after_help = "Example: kidobo sources list\nRead-only; does not fetch or refresh caches. No sync or reversal is needed."
    )]
    List,
    #[command(
        about = "Save one HTTP(S) feed URL; enforcement waits for sync",
        after_help = "Example: sudo kidobo sources add https://example.org/feed.txt\nTo reverse: sudo kidobo sources remove URL, then sync."
    )]
    Add { url: String },
    #[command(
        about = "Remove a configured feed URL; enforcement waits for sync",
        after_help = "Example: sudo kidobo sources remove https://example.org/feed.txt\nTo reverse: add the same URL, then sync."
    )]
    Remove { url: String },
}

#[derive(Debug, Subcommand)]
pub enum AllowAction {
    #[command(
        about = "List saved operator-controlled exemptions",
        after_help = "Example: kidobo allow list\nRead-only saved state; live enforcement changes only through sync. No reversal is needed."
    )]
    List,
    #[command(
        about = "Save an exemption applied by the next sync",
        after_help = "Examples: sudo kidobo allow add 203.0.113.7\n          sudo kidobo allow add 2001:db8::/64 --yes\nThis subtracts addresses from Kidobo's effective blocklist. It does not install an ACCEPT rule.\nTo reverse: sudo kidobo allow remove IP_OR_CIDR, then sync."
    )]
    Add {
        #[arg(value_name = "IP_OR_CIDR")]
        target: String,
        #[arg(
            long,
            help = "Explicitly approve expanding the exemption; required without an interactive terminal"
        )]
        yes: bool,
    },
    #[command(
        about = "Remove an exact saved exemption; enforcement waits for sync",
        after_help = "Example: sudo kidobo allow remove 203.0.113.7\nUses canonical exact identity, without splitting ranges. To reverse: add the same exemption and sync."
    )]
    Remove {
        #[arg(value_name = "IP_OR_CIDR")]
        target: String,
    },
}

#[derive(Debug, Clone, Copy, Subcommand)]
pub enum ConfigAction {
    #[command(
        about = "Show effective settings, defaults, and their origins",
        after_help = "Example: kidobo config show\nRead-only; credentials and URL query/fragment values are redacted. No sync or reversal is needed."
    )]
    Show,
    #[command(
        about = "Print the resolved configuration filename",
        after_help = "Example: kidobo config path\nRead-only and available before initialization. No sync or reversal is needed."
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
        long_about = "Generate completion code for Bash, Zsh, or Fish from Kidobo's own command definitions. Writes the script to stdout only; does not read configuration, contact services, or install files.",
        after_help = "Examples: kidobo completions bash > kidobo.bash\n          source ./kidobo.bash\n          kidobo completions zsh\n          kidobo completions fish\nNo sync is needed. To reverse installation, remove your completion file or start a fresh shell."
    )]
    Completions {
        #[arg(value_enum)]
        shell: CompletionShell,
    },
    #[command(
        about = "Review settings and guide first-time configuration",
        long_about = "Interactive, linear setup: review IPv4/IPv6, remote feeds, and safelists before saving. Existing files are preserved. After saving, provision missing files and run doctor, then separately confirm first sync and timer activation. Never installs packages or elevates privileges. Existing active timers are not stopped and may apply saved settings.",
        after_help = "Example: sudo kidobo setup\nNoninteractive alternatives: kidobo init, sources, allow, doctor, and sync.\nAt default paths, init activates scheduling immediately; setup defers activation.\nTo reverse source choices, use sources remove or allow remove and sync; flush removes managed enforcement."
    )]
    Setup,
    #[command(
        about = "Inspect, add, or remove configured remote feeds",
        long_about = "List feeds without fetching, or edit remote.urls atomically while preserving other configuration. Cache availability is validated; refresh time is Unknown because no trustworthy receipt is recorded. Source edits do not change live enforcement until sync. Sensitive URL values are redacted in output.",
        after_help = "Examples: kidobo sources\n          sudo kidobo sources add https://example.org/feed.txt\n          sudo kidobo sources remove https://example.org/feed.txt\nNext after an edit: sudo kidobo sync. Reverse an addition with remove and vice versa."
    )]
    Sources {
        #[command(subcommand)]
        action: Option<SourceAction>,
    },
    #[command(
        about = "Manage operator-controlled safelist exemptions",
        long_about = "List or edit safe.ips. Exemptions subtract from all Kidobo blocklist sources at the next sync; they are not kernel ACCEPT rules. Additions expanding coverage require confirmation, or explicit --yes without a terminal. Broad ranges can exempt an entire address family. Removals use exact canonical identity.",
        after_help = "Examples: kidobo allow\n          sudo kidobo allow add 203.0.113.7\n          sudo kidobo allow add 2001:db8::/64 --yes\n          sudo kidobo allow remove 203.0.113.7\nNext after an edit: sudo kidobo sync. Reverse using the opposite edit and sync."
    )]
    Allow {
        #[command(subcommand)]
        action: Option<AllowAction>,
    },
    #[command(
        about = "Show effective configuration or its filename",
        after_help = "Examples: kidobo config show\n          kidobo config path\nRead-only; manual editing remains supported. Use setup, sources, and allow for guided changes, then sync."
    )]
    Config {
        #[command(subcommand)]
        action: Option<ConfigAction>,
    },
    #[command(
        about = "Inspect configuration and live managed enforcement",
        long_about = "Read-only overview of saved configuration, managed live sets and wiring, local bans, and timer scheduling. Unknown fields mean the evidence could not be verified. No sources are fetched and no sync is needed.",
        after_help = "Examples: kidobo\n          sudo kidobo status\n          kidobo status --format json\nIf permissions prevent verification, retry sudo kidobo status. No reversal is needed."
    )]
    Status {
        #[arg(long, value_enum, default_value_t = ReportFormat::Human)]
        format: ReportFormat,
    },
    #[command(
        about = "Check Kidobo's live enforcement for one IP",
        long_about = "Probe managed set membership and firewall wiring for one IPv4 or IPv6 address. Reports BLOCKED BY KIDOBO, NOT BLOCKED BY KIDOBO, or UNKNOWN. This verifies Kidobo's managed incoming blocking path, not the entire host's packet-filtering verdict. Read-only; never fetches sources. Offline overlaps are separate evidence and can be stale.",
        after_help = "Examples: sudo kidobo check 203.0.113.7\n          sudo kidobo check 2001:db8::7 --format json\nCIDR/source overlaps: kidobo lookup 203.0.113.0/24\nVerified verdicts exit 0; unknown exits 1; invalid usage exits 2. No reversal or sync is needed."
    )]
    Check {
        #[arg(value_name = "IP", value_parser = parse_check_ip)]
        ip: IpAddr,
        #[arg(long, value_enum, default_value_t = ReportFormat::Human)]
        format: ReportFormat,
    },
    #[command(
        about = "List saved operator-managed bans",
        long_about = "List permanent local IP/CIDR and ASN bans and saved temporary bans, including expired records awaiting cleanup. This is saved source state; it does not prove live enforcement. Read-only and offline. Use sync to apply source changes and expiration.",
        after_help = "Examples: kidobo bans\n          kidobo bans --temporary\n          kidobo bans --permanent --asn --all\n          kidobo bans --limit 100\nTo remove an entry: sudo kidobo unban IP_OR_CIDR (or --asn ASN), then sync."
    )]
    Bans {
        #[arg(long, conflicts_with = "permanent")]
        temporary: bool,
        #[arg(long)]
        permanent: bool,
        #[arg(long, help = "Only list operator-managed ASN identities")]
        asn: bool,
        #[arg(long, default_value = "50", help = "Maximum saved entries to display")]
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
        long_about = "Create any missing Kidobo config/data/cache files and default systemd unit files.\n\nAt default system paths, this also runs systemctl daemon-reload, reset-failed, and enable --now for kidobo-sync.timer. Existing files are preserved. The timer runs sync and can change firewall enforcement.",
        after_help = "Example: sudo kidobo init\nNext: sudo kidobo doctor\nTo remove enforcement: sudo kidobo flush; inspect timer scheduling separately."
    )]
    Init,
    #[command(
        about = "Check configuration and host prerequisites read-only",
        long_about = "Run read-only environment and dependency checks. Terminal output is grouped for people; redirected output defaults to the existing JSON report. Existing privileged probes use noninteractive sudo -n and never ask for a password.\n\nExits 0 when overall status is OK and 1 when a required check fails. No sync is needed.",
        after_help = "Examples: kidobo doctor\n          sudo kidobo doctor --format human\n          kidobo doctor --format json\nFix reported prerequisites, rerun doctor, then use sudo kidobo sync."
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
        long_about = "Load config and sources, apply safelist subtraction, collapse entries, then update managed ipsets and firewall wiring. Each family replacement is atomic; a later failure can leave a partial update. Existing firewall adapters use noninteractive sudo -n.\n\nThis one-shot command writes firewall and cache state. Both enabled families are capacity checked before either replacement.",
        after_help = "Examples: sudo kidobo sync\n          sudo kidobo sync --timer\n          sudo kidobo sync --dry-run\n          sudo kidobo sync --dry-run --allow-network\nDry-run is offline unless --allow-network is explicit. It never writes caches, files, sets, or rules. An existing process lock is required; setup creates it. Preview does not prove future cache persistence or sync success.\nAfter failure: inspect kidobo doctor, correct the cause, and retry sync.\nTo remove managed enforcement: sudo kidobo flush."
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
        long_about = "Remove Kidobo's managed firewall rules/ipsets and remote cache. This is a destructive removal operation. Local bans, configuration, and temporary-ban records are preserved. Use --cache-only to leave enforcement unchanged.",
        after_help = "Examples: sudo kidobo flush --yes\n          kidobo flush --cache-only\nTo restore enforcement: sudo kidobo sync."
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
        long_about = "Ban one IPv4/IPv6 address or CIDR, targets from `--file`, or one or more ASNs with `--asn`.\n\nUse `--for 12h` or `--for 3d` for temporary bans. Durations start when recorded; repeating a temporary ban replaces its deadline, even if shorter. Without `--for`, bans are permanent.\n\nThis saves local source data. Interactive terminals offer to run sync after a change; --apply requests sync explicitly and --no-apply saves only. Noninteractive runs save only by default. Expiration/removal takes effect at a subsequent successful sync.",
        after_help = "Examples: sudo kidobo ban 203.0.113.7\n          sudo kidobo ban 203.0.113.7 --for 12h\n          sudo kidobo ban --asn AS64496\n          sudo kidobo ban 203.0.113.7 --apply\nNext: sudo kidobo sync\nTo reverse: sudo kidobo unban 203.0.113.7, then sync.",
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
            help = "Ban for whole hours or days (12h, 3d), starting when recorded; applied/removed by sync"
        )]
        duration: Option<BanDuration>,
        #[arg(
            value_name = "IP_OR_CIDR",
            help = "Single IPv4/IPv6 address or CIDR to add"
        )]
        target: Option<String>,

        #[arg(
            long,
            value_name = "PATH",
            help = "File with one IPv4/IPv6 address or CIDR per line"
        )]
        file: Option<PathBuf>,

        #[arg(
            long = "asn",
            value_name = "ASN",
            num_args = 1..,
            help = "ASN(s) to ban (e.g. 213412 or AS213412)"
        )]
        asn: Option<Vec<String>>,
    },
    #[command(
        about = "Remove permanent and temporary IP/CIDR or ASN bans",
        long_about = "Remove one IPv4/IPv6 address or CIDR, targets from `--file`, or one or more ASNs with `--asn` from both permanent and temporary local sources.\n\nThis saves local source changes. Interactive terminals offer to run sync afterward; --apply requests sync explicitly and --no-apply saves only. Noninteractive runs save only by default. --yes approves overlapping-entry removal only, never synchronization.",
        after_help = "Examples: sudo kidobo unban 203.0.113.7\n          sudo kidobo unban --asn AS64496\n          sudo kidobo unban 203.0.113.0/24 --yes\nNext: sudo kidobo sync\nOther sources can still block this address. To restore a local ban, use ban and sync.",
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
            help = "Single IPv4/IPv6 address or CIDR to remove"
        )]
        target: Option<String>,

        #[arg(
            long,
            value_name = "PATH",
            help = "File with one IPv4/IPv6 address or CIDR per line"
        )]
        file: Option<PathBuf>,

        #[arg(
            long = "asn",
            value_name = "ASN",
            num_args = 1..,
            help = "ASN(s) to unban (e.g. 213412 or AS213412)"
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
        long_about = "Lookup candidate targets against the local blocklist, unexpired temporary bans, cached remote sources, configured safelist entries, cached GitHub safelist entries, and cached prefixes for permanent or temporary ASN bans.\n\nLookup reports source overlaps, runs offline only, and never fetches or refreshes source data. Config-backed sources are included when the config is valid; local, temporary, and cached remote lookup remains available without a valid config. Warnings identify unavailable source coverage. Expired temporary entries may still be enforced until sync applies their removal.",
        after_help = "Examples: kidobo lookup 203.0.113.7\n          kidobo lookup --file targets.txt --format tsv\nRead-only and offline: overlaps do not prove live firewall enforcement. No reversal or sync is needed.",
        group(
            ArgGroup::new("lookup_input")
                .args(["ip", "file"])
                .required(true)
                .multiple(false)
        )
    )]
    Lookup {
        #[arg(value_name = "IP_OR_CIDR", help = "Single target IP/CIDR to match")]
        ip: Option<String>,

        #[arg(
            long,
            value_name = "PATH",
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
    fn all_user_commands_have_built_in_examples_and_recovery_guidance() {
        use clap::CommandFactory;
        fn inspect(command: &clap::Command) {
            for child in command
                .get_subcommands()
                .filter(|child| child.get_name() != "help")
            {
                let help = child
                    .get_after_help()
                    .expect("each command has effects/examples/recovery guidance")
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
