//! Read-only operational status, live address checks, and inspection capabilities.

use std::net::IpAddr;
use std::path::PathBuf;

use kidobo_core::config::FirewallAction;
use serde::Serialize;

use crate::AppError;
use crate::paths::{ConfigRequirement, PathResolutionInput, ResolvedPaths};
use crate::ports::{Cancellation, ConfigRepository, PathResolver};
use crate::sync::{AddressFamily, EnforcementPlan, ManagedSetSpec};
use crate::temporary_bans::Clock;

/// Whether read-only evidence verifies an artifact, proves its absence, or is inconclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verification {
    /// Applicable managed state was positively verified.
    Verified,
    /// Sufficient live evidence established absence.
    Absent,
    /// Evidence was unavailable, unsupported, inconsistent, or changed during inspection.
    Unknown,
}

/// Selected-address membership in one validated managed set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Membership {
    /// The selected address was found in the managed set.
    Present,
    /// A successful inspection conclusively reported nonmembership.
    Absent,
    /// Membership could not safely be determined.
    Unknown,
}

/// Bounded observations of one address family's managed firewall state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FamilyInspection {
    /// `ipv4` or `ipv6`; addresses are never mapped across families.
    pub family: String,
    /// Enabled in saved configuration, independently of live observations.
    pub configured_enabled: Option<bool>,
    /// Configured managed set name, when configuration is usable.
    pub set_name: Option<String>,
    /// Presence and expected type/family of the selected managed set.
    pub set_state: Verification,
    /// Verification of the effective managed INPUT blocking path.
    pub wiring: Verification,
    /// Whether Kidobo's managed blocking path is verified as enforcing this family.
    pub enforcement: Verification,
    /// Actual kernel entry count, when a validated header is readable.
    pub entries: Option<usize>,
    /// Selected-address membership; absent for a status-only inspection.
    pub membership: Option<Membership>,
    /// Relevant observations remained consistent across before/after probes.
    pub stable: bool,
    /// Concise reason for the aggregate state.
    pub detail: String,
    /// Read-only evidence and actionable explanations for unavailable observations.
    pub evidence: Vec<String>,
}

impl FamilyInspection {
    #[must_use]
    /// Creates an inconclusive result without inventing a configured or live state.
    pub fn unknown(
        family: AddressFamily,
        set_name: Option<&str>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            family: match family {
                AddressFamily::Ipv4 => "ipv4",
                AddressFamily::Ipv6 => "ipv6",
            }
            .to_string(),
            configured_enabled: None,
            set_name: set_name.map(ToString::to_string),
            set_state: Verification::Unknown,
            wiring: Verification::Unknown,
            enforcement: Verification::Unknown,
            entries: None,
            membership: None,
            stable: false,
            detail: detail.into(),
            evidence: Vec::new(),
        }
    }
}

/// Read-only systemd timer evidence, independent of firewall enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TimerInspection {
    /// Whether the timer's relevant properties were verified.
    pub state: Verification,
    /// Whether persistent activation is enabled, when established.
    pub enabled: Option<bool>,
    /// Whether systemd currently reports the timer as active.
    pub active: Option<bool>,
    /// Evidence or explanation for an unavailable timer state.
    pub detail: String,
}

impl TimerInspection {
    #[must_use]
    /// Creates an explicitly unavailable timer observation.
    pub fn unknown(detail: impl Into<String>) -> Self {
        Self {
            state: Verification::Unknown,
            enabled: None,
            active: None,
            detail: detail.into(),
        }
    }
}

/// Counts of operator-managed saved state; missing observations remain null.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SavedBanCounts {
    /// Distinct permanent local IP/CIDR identities.
    pub permanent_ip_cidrs: Option<usize>,
    /// Distinct permanent configured ASNs.
    pub permanent_asns: Option<usize>,
    /// Saved temporary IP/CIDR records, including expired records awaiting cleanup.
    pub temporary_ip_cidrs: Option<usize>,
    /// Saved temporary ASN records, including expired records awaiting cleanup.
    pub temporary_asns: Option<usize>,
    /// Temporary IP/CIDR records active at the shared inspection cutoff.
    pub active_temporary_ip_cidrs: Option<usize>,
    /// Temporary ASN records active at the shared inspection cutoff.
    pub active_temporary_asns: Option<usize>,
    /// Reasons particular saved-state counts could not be established.
    pub notices: Vec<String>,
}

/// Reads saved-source counts without refreshing sources or rewriting files.
pub trait SavedBanCountReader {
    /// Returns independently readable counts; clock failure makes only active counts unknown.
    fn read_counts(&self, paths: &ResolvedPaths, cutoff: Option<u64>) -> SavedBanCounts;
}

/// Bounded direct probes that never elevate, write files, or alter managed state.
pub trait LiveProbe {
    /// Inspects one family and optionally one address, checking cancellation between probes.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Interrupted`] on cancellation; probe failures become unknown evidence.
    fn inspect_family(
        &self,
        spec: &ManagedSetSpec,
        action: FirewallAction,
        target: Option<IpAddr>,
        cancellation: &dyn Cancellation,
    ) -> Result<FamilyInspection, AppError>;

    /// Reads the managed timer's current properties without starting or enabling it.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Interrupted`] on cancellation; other failures become unknown evidence.
    fn inspect_timer(&self, cancellation: &dyn Cancellation) -> Result<TimerInspection, AppError>;
}

/// Version-one dashboard report with explicit partial and unknown observations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatusReport {
    /// Structured output version, independent of the existing doctor report.
    pub schema_version: u8,
    /// True for usable configuration, false for a missing file, unknown otherwise.
    pub initialized: Option<bool>,
    /// Whether configuration is valid, missing, or unusable.
    pub configuration: Verification,
    /// Configuration observation or recovery explanation.
    pub configuration_detail: String,
    /// Exact resolved configuration filename.
    pub configuration_path: PathBuf,
    /// IPv4 state observed through read-only probes.
    pub ipv4: FamilyInspection,
    /// IPv6 state, including residual artifacts when disabled in configuration.
    pub ipv6: FamilyInspection,
    /// Configured remote feed count; no feeds are fetched or enumerated.
    pub configured_feeds: Option<usize>,
    /// Independently readable saved-state counts.
    pub saved_bans: SavedBanCounts,
    /// Timer observation or explicit unavailability.
    pub timer: TimerInspection,
    /// No successful-sync receipt is currently persisted; remains null.
    pub last_successful_sync: Option<String>,
    /// Inspection limitations and next steps.
    pub notices: Vec<String>,
}

/// Capabilities used to collect a partial read-only dashboard.
pub struct StatusDependencies<'a> {
    /// Cooperative cancellation between read operations.
    pub cancellation: &'a dyn Cancellation,
    /// Existing path-resolution policy.
    pub paths: &'a dyn PathResolver,
    /// Bounded validated configuration reads.
    pub configs: &'a dyn ConfigRepository,
    /// Read-only saved-source counts.
    pub saved_counts: &'a dyn SavedBanCountReader,
    /// One shared cutoff for temporary-ban counts.
    pub clock: &'a dyn Clock,
    /// Direct live-state probes.
    pub live_probe: &'a dyn LiveProbe,
}

/// Verdict restricted to Kidobo's managed INPUT source-address blocking path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckVerdict {
    /// Set membership and an effective managed blocking path were verified.
    Blocked,
    /// Sufficient live information verifies no managed block for this address.
    NotBlocked,
    /// Live information is insufficient or inconsistent.
    Unknown,
}

/// Separately labeled offline source overlap; it does not establish enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OfflineMatch {
    /// Source label reported by the offline lookup use case.
    pub source: String,
    /// Matched saved or cached source entry.
    pub entry: String,
}

/// Version-one live address assessment with separately labeled offline evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckReport {
    /// Structured output version, independent of doctor.
    pub schema_version: u8,
    /// Canonical individual address that was inspected.
    pub target: String,
    /// Live managed-path verdict.
    pub verdict: CheckVerdict,
    /// Read-only live observations for the selected family.
    pub family: FamilyInspection,
    /// Offline overlaps, populated by CLI composition through the lookup use case.
    pub offline_matches: Vec<OfflineMatch>,
    /// Offline coverage limitations; never used to infer a live verdict.
    pub offline_notices: Vec<String>,
    /// Limitations and recovery hints for the live assessment.
    pub notices: Vec<String>,
}

/// One individual address and existing path-resolution inputs.
pub struct CheckRequest {
    /// Native runtime path inputs.
    pub paths: PathResolutionInput,
    /// Individual IPv4 or IPv6 address; CIDRs are rejected at the CLI boundary.
    pub target: IpAddr,
}

/// Capabilities required by a live check; no HTTP or source-refresh capability is present.
pub struct CheckDependencies<'a> {
    /// Cooperative cancellation between probes.
    pub cancellation: &'a dyn Cancellation,
    /// Existing runtime path policy.
    pub paths: &'a dyn PathResolver,
    /// Validated configuration reads.
    pub configs: &'a dyn ConfigRepository,
    /// Direct read-only managed state probes.
    pub live_probe: &'a dyn LiveProbe,
}

/// Collects read-only status, retaining partial information when individual observations fail.
///
/// # Errors
///
/// Returns path-resolution failures or cancellation; ordinary probe failures stay in the report.
pub fn status(
    request: &PathResolutionInput,
    dependencies: &StatusDependencies<'_>,
) -> Result<StatusReport, AppError> {
    dependencies.cancellation.check()?;
    let paths = dependencies
        .paths
        .resolve(request, ConfigRequirement::Optional)?;
    let config_result = dependencies.configs.load(&paths.config_file);
    let (config, initialized, configuration, configuration_detail) = match config_result {
        Ok(config) => (
            Some(config),
            Some(true),
            Verification::Verified,
            "Configuration is valid".to_string(),
        ),
        Err(AppError::Interrupted) => return Err(AppError::Interrupted),
        Err(error @ AppError::MissingConfigFile { .. }) => {
            (None, Some(false), Verification::Absent, error.to_string())
        }
        Err(error) => (None, None, Verification::Unknown, error.to_string()),
    };
    dependencies.cancellation.check()?;
    let mut notices = Vec::new();
    let cutoff = match dependencies.clock.now_unix_secs() {
        Ok(cutoff) => Some(cutoff),
        Err(AppError::Interrupted) => return Err(AppError::Interrupted),
        Err(error) => {
            notices.push(format!("Active temporary-ban counts are unknown: {error}"));
            None
        }
    };
    let mut saved_bans = dependencies.saved_counts.read_counts(&paths, cutoff);
    let (ipv4, ipv6) = if let Some(config) = &config {
        saved_bans.permanent_asns = Some(config.asn.banned.len());
        let plan = EnforcementPlan::from_config(config);
        let mut ipv4 = dependencies.live_probe.inspect_family(
            &plan.ipv4,
            plan.chain_action,
            None,
            dependencies.cancellation,
        )?;
        dependencies.cancellation.check()?;
        let mut ipv6 = dependencies.live_probe.inspect_family(
            &plan.ipv6,
            plan.chain_action,
            None,
            dependencies.cancellation,
        )?;
        apply_configuration(&mut ipv4, true);
        apply_configuration(&mut ipv6, plan.enable_ipv6);
        (ipv4, ipv6)
    } else {
        let detail = "Live managed state cannot be verified without valid configuration";
        (
            FamilyInspection::unknown(AddressFamily::Ipv4, None, detail),
            FamilyInspection::unknown(AddressFamily::Ipv6, None, detail),
        )
    };
    dependencies.cancellation.check()?;
    let timer = if paths.root_override.is_some() {
        TimerInspection::unknown("An alternate root does not identify a host systemd timer")
    } else {
        dependencies
            .live_probe
            .inspect_timer(dependencies.cancellation)?
    };
    let mut report = StatusReport {
        schema_version: 1,
        initialized,
        configuration,
        configuration_detail,
        configuration_path: paths.config_file.clone(),
        ipv4,
        ipv6,
        configured_feeds: config.as_ref().map(|config| config.remote.urls.len()),
        saved_bans,
        timer,
        last_successful_sync: None,
        notices,
    };
    if let Some(config) = &config {
        dependencies.cancellation.check()?;
        match dependencies.configs.load(&paths.config_file) {
            Ok(current) if current == *config => {}
            Err(AppError::Interrupted) => return Err(AppError::Interrupted),
            _ => {
                report.initialized = None;
                report.configuration = Verification::Unknown;
                report.configuration_detail =
                    "Configuration changed or became unreadable during inspection; retry status"
                        .to_string();
                report.configured_feeds = None;
                report.saved_bans.permanent_asns = None;
                report.ipv4.configured_enabled = None;
                report.ipv6.configured_enabled = None;
                invalidate_family(&mut report.ipv4, &report.configuration_detail);
                invalidate_family(&mut report.ipv6, &report.configuration_detail);
            }
        }
    }
    dependencies.cancellation.check()?;
    Ok(report)
}

/// Assesses a single address using live managed state only.
///
/// # Errors
///
/// Returns path-resolution failures or cancellation; insufficient evidence returns an unknown verdict.
pub fn check(
    request: &CheckRequest,
    dependencies: &CheckDependencies<'_>,
) -> Result<CheckReport, AppError> {
    dependencies.cancellation.check()?;
    let paths = dependencies
        .paths
        .resolve(&request.paths, ConfigRequirement::Optional)?;
    let family = match request.target {
        IpAddr::V4(_) => AddressFamily::Ipv4,
        IpAddr::V6(_) => AddressFamily::Ipv6,
    };
    let mut report = CheckReport {
        schema_version: 1,
        target: request.target.to_string(),
        verdict: CheckVerdict::Unknown,
        family: FamilyInspection::unknown(family, None, "Valid configuration is required to identify the managed set"),
        offline_matches: Vec::new(),
        offline_notices: Vec::new(),
        notices: vec!["This assesses Kidobo's managed INPUT blocking path only; it does not determine the entire host's packet-filtering outcome".to_string()],
    };
    let config = match dependencies.configs.load(&paths.config_file) {
        Ok(config) => config,
        Err(AppError::Interrupted) => return Err(AppError::Interrupted),
        Err(error) => {
            report.family.detail = error.to_string();
            report
                .notices
                .push("Run kidobo doctor to diagnose configuration and prerequisites".to_string());
            return Ok(report);
        }
    };
    let plan = EnforcementPlan::from_config(&config);
    let spec = match family {
        AddressFamily::Ipv4 => &plan.ipv4,
        AddressFamily::Ipv6 => &plan.ipv6,
    };
    report.family = dependencies.live_probe.inspect_family(
        spec,
        plan.chain_action,
        Some(request.target),
        dependencies.cancellation,
    )?;
    apply_configuration(
        &mut report.family,
        family == AddressFamily::Ipv4 || plan.enable_ipv6,
    );
    dependencies.cancellation.check()?;
    match dependencies.configs.load(&paths.config_file) {
        Ok(current) if current == config => {}
        Err(AppError::Interrupted) => return Err(AppError::Interrupted),
        _ => {
            report.family.configured_enabled = None;
            invalidate_family(
                &mut report.family,
                "Configuration changed or became unreadable during inspection; retry check",
            );
        }
    }
    report.verdict = classify_target(&report.family);
    dependencies.cancellation.check()?;
    Ok(report)
}

fn apply_configuration(inspection: &mut FamilyInspection, enabled: bool) {
    inspection.configured_enabled = Some(enabled);
    if !enabled && inspection.wiring == Verification::Verified {
        let detail = "IPv6 is disabled in configuration, but managed blocking wiring remains live; sync is needed to reconcile it";
        inspection.enforcement = Verification::Unknown;
        inspection.detail = detail.to_string();
        inspection.evidence.push(detail.to_string());
    }
}

fn invalidate_family(inspection: &mut FamilyInspection, detail: &str) {
    inspection.set_state = Verification::Unknown;
    inspection.wiring = Verification::Unknown;
    inspection.enforcement = Verification::Unknown;
    inspection.entries = None;
    inspection.membership = inspection.membership.map(|_| Membership::Unknown);
    inspection.stable = false;
    inspection.detail = detail.to_string();
    inspection.evidence.push(detail.to_string());
}

fn classify_target(inspection: &FamilyInspection) -> CheckVerdict {
    if !inspection.stable || inspection.enforcement == Verification::Unknown {
        return CheckVerdict::Unknown;
    }
    match (
        inspection.wiring,
        inspection.set_state,
        inspection.membership,
    ) {
        (Verification::Verified, Verification::Verified, Some(Membership::Present)) => {
            CheckVerdict::Blocked
        }
        (Verification::Absent, _, _)
        | (Verification::Verified, Verification::Verified, Some(Membership::Absent)) => {
            CheckVerdict::NotBlocked
        }
        _ => CheckVerdict::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::path::Path;
    use std::sync::Mutex;

    use kidobo_core::config::Config;

    use super::*;
    use crate::ports::NoCancellation;

    struct Paths;

    impl PathResolver for Paths {
        fn resolve(
            &self,
            _: &PathResolutionInput,
            requirement: ConfigRequirement,
        ) -> Result<ResolvedPaths, AppError> {
            assert_eq!(requirement, ConfigRequirement::Optional);
            let root = PathBuf::from("/inspection-fixture");
            Ok(ResolvedPaths {
                root_override: Some(root.clone()),
                config_dir: root.join("config"),
                config_file: root.join("config/config.toml"),
                data_dir: root.join("data"),
                blocklist_file: root.join("data/blocklist.txt"),
                cache_dir: root.join("cache"),
                remote_cache_dir: root.join("cache/remote"),
                lock_file: root.join("cache/lock"),
            })
        }
    }

    #[derive(Clone, Copy)]
    enum ConfigMode {
        Valid,
        Missing,
        Unreadable,
        Changed,
    }

    struct Configs {
        mode: ConfigMode,
        ipv6: bool,
        calls: Cell<usize>,
    }

    impl Configs {
        fn new(mode: ConfigMode, ipv6: bool) -> Self {
            Self {
                mode,
                ipv6,
                calls: Cell::new(0),
            }
        }
    }

    impl ConfigRepository for Configs {
        fn load(&self, path: &Path) -> Result<Config, AppError> {
            let calls = self.calls.get();
            self.calls.set(calls + 1);
            match self.mode {
                ConfigMode::Missing => Err(AppError::MissingConfigFile {
                    path: path.to_path_buf(),
                }),
                ConfigMode::Unreadable => Err(AppError::ConfigRead {
                    path: path.to_path_buf(),
                    source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
                }),
                ConfigMode::Valid | ConfigMode::Changed => {
                    let set = if matches!(self.mode, ConfigMode::Changed) && calls > 0 {
                        "changed"
                    } else {
                        "kidobo"
                    };
                    Ok(Config::from_toml_str(&format!("[ipset]\nset_name='{set}'\nenable_ipv6={}\n[remote]\nurls=['https://feed.test/list']\n[asn]\nbanned=[64512]\n", self.ipv6)).expect("fixture config"))
                }
            }
        }
    }

    struct ClockFixture;
    impl Clock for ClockFixture {
        fn now_unix_secs(&self) -> Result<u64, AppError> {
            Ok(100)
        }
    }

    struct Counts;
    impl SavedBanCountReader for Counts {
        fn read_counts(&self, _: &ResolvedPaths, cutoff: Option<u64>) -> SavedBanCounts {
            assert_eq!(cutoff, Some(100));
            SavedBanCounts {
                permanent_ip_cidrs: Some(3),
                active_temporary_ip_cidrs: Some(2),
                ..SavedBanCounts::default()
            }
        }
    }

    struct Probe {
        membership: Membership,
        wiring: Verification,
        stable: bool,
        calls: Mutex<Vec<AddressFamily>>,
    }

    impl Probe {
        fn new(membership: Membership, wiring: Verification, stable: bool) -> Self {
            Self {
                membership,
                wiring,
                stable,
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl LiveProbe for Probe {
        fn inspect_family(
            &self,
            spec: &ManagedSetSpec,
            _: FirewallAction,
            target: Option<IpAddr>,
            _: &dyn Cancellation,
        ) -> Result<FamilyInspection, AppError> {
            self.calls.lock().expect("calls").push(spec.family);
            let mut result =
                FamilyInspection::unknown(spec.family, Some(&spec.set_name), "fixture evidence");
            result.set_state = Verification::Verified;
            result.wiring = self.wiring;
            result.enforcement = self.wiring;
            result.entries = Some(17);
            result.membership = target.map(|_| self.membership);
            result.stable = self.stable;
            Ok(result)
        }

        fn inspect_timer(&self, _: &dyn Cancellation) -> Result<TimerInspection, AppError> {
            panic!("alternate roots must not query the host timer")
        }
    }

    fn path_input() -> PathResolutionInput {
        PathResolutionInput {
            explicit_config_path: None,
            temp_dir: PathBuf::from("/tmp"),
            env: std::collections::BTreeMap::new(),
        }
    }

    fn run_check(configs: &Configs, probe: &Probe, target: &str) -> CheckReport {
        check(
            &CheckRequest {
                paths: path_input(),
                target: target.parse().expect("IP"),
            },
            &CheckDependencies {
                cancellation: &NoCancellation,
                paths: &Paths,
                configs,
                live_probe: probe,
            },
        )
        .expect("check report")
    }

    #[test]
    fn target_verdict_requires_live_membership_effective_wiring_and_consistent_evidence() {
        for (membership, wiring, stable, expected) in [
            (
                Membership::Present,
                Verification::Verified,
                true,
                CheckVerdict::Blocked,
            ),
            (
                Membership::Absent,
                Verification::Verified,
                true,
                CheckVerdict::NotBlocked,
            ),
            (
                Membership::Unknown,
                Verification::Verified,
                true,
                CheckVerdict::Unknown,
            ),
            (
                Membership::Present,
                Verification::Unknown,
                true,
                CheckVerdict::Unknown,
            ),
            (
                Membership::Present,
                Verification::Verified,
                false,
                CheckVerdict::Unknown,
            ),
            (
                Membership::Present,
                Verification::Absent,
                true,
                CheckVerdict::NotBlocked,
            ),
        ] {
            let report = run_check(
                &Configs::new(ConfigMode::Valid, true),
                &Probe::new(membership, wiring, stable),
                "203.0.113.7",
            );
            assert_eq!(report.verdict, expected);
            assert_eq!(report.offline_matches, Vec::<OfflineMatch>::new());
        }
    }

    #[test]
    fn disabled_ipv6_is_probed_without_mapping_and_residual_wiring_is_unknown() {
        for (wiring, expected) in [
            (Verification::Verified, CheckVerdict::Unknown),
            (Verification::Absent, CheckVerdict::NotBlocked),
        ] {
            let probe = Probe::new(Membership::Present, wiring, true);
            let report = run_check(
                &Configs::new(ConfigMode::Valid, false),
                &probe,
                "::ffff:203.0.113.7",
            );
            assert_eq!(report.verdict, expected);
            assert_eq!(report.family.configured_enabled, Some(false));
            assert_eq!(report.family.wiring, wiring);
            assert_eq!(report.family.set_state, Verification::Verified);
            assert_eq!(report.family.entries, Some(17));
            assert_eq!(report.family.membership, Some(Membership::Present));
            assert!(report.family.stable);
            assert_eq!(
                report.family.enforcement,
                if wiring == Verification::Verified {
                    Verification::Unknown
                } else {
                    wiring
                }
            );
            assert_eq!(*probe.calls.lock().expect("calls"), [AddressFamily::Ipv6]);
        }
    }

    #[test]
    fn changed_configuration_invalidates_an_otherwise_verified_check() {
        let report = run_check(
            &Configs::new(ConfigMode::Changed, true),
            &Probe::new(Membership::Present, Verification::Verified, true),
            "203.0.113.7",
        );
        assert_eq!(report.verdict, CheckVerdict::Unknown);
        assert!(!report.family.stable);
        assert_eq!(report.family.configured_enabled, None);
        assert_eq!(report.family.entries, None);
        assert_eq!(report.family.membership, Some(Membership::Unknown));
        assert!(report.family.detail.contains("Configuration changed"));
    }

    #[test]
    fn changed_configuration_clears_stale_dashboard_settings_and_enforcement_claims() {
        let probe = Probe::new(Membership::Present, Verification::Verified, true);
        let configs = Configs::new(ConfigMode::Changed, true);
        let report = status(
            &path_input(),
            &StatusDependencies {
                cancellation: &NoCancellation,
                paths: &Paths,
                configs: &configs,
                saved_counts: &Counts,
                clock: &ClockFixture,
                live_probe: &probe,
            },
        )
        .expect("partial status");
        assert_eq!(report.configuration, Verification::Unknown);
        assert_eq!(report.configured_feeds, None);
        assert_eq!(report.saved_bans.permanent_asns, None);
        assert_eq!(report.ipv4.configured_enabled, None);
        assert_eq!(report.ipv6.configured_enabled, None);
        assert_eq!(report.ipv4.enforcement, Verification::Unknown);
        assert_eq!(report.ipv6.enforcement, Verification::Unknown);
        assert_eq!(report.ipv4.entries, None);
        assert_eq!(report.ipv6.entries, None);
    }

    #[test]
    fn missing_and_unreadable_configuration_keep_saved_counts_and_do_not_invent_live_state() {
        for (mode, initialized, verification) in [
            (ConfigMode::Missing, Some(false), Verification::Absent),
            (ConfigMode::Unreadable, None, Verification::Unknown),
        ] {
            let probe = Probe::new(Membership::Present, Verification::Verified, true);
            let configs = Configs::new(mode, true);
            let report = status(
                &path_input(),
                &StatusDependencies {
                    cancellation: &NoCancellation,
                    paths: &Paths,
                    configs: &configs,
                    saved_counts: &Counts,
                    clock: &ClockFixture,
                    live_probe: &probe,
                },
            )
            .expect("partial status");
            assert_eq!(report.initialized, initialized);
            assert_eq!(report.configuration, verification);
            assert_eq!(report.saved_bans.permanent_ip_cidrs, Some(3));
            assert_eq!(report.saved_bans.permanent_asns, None);
            assert_eq!(report.ipv4.enforcement, Verification::Unknown);
            assert_eq!(report.ipv6.enforcement, Verification::Unknown);
            assert!(probe.calls.lock().expect("calls").is_empty());
            assert_eq!(report.timer.state, Verification::Unknown);
            assert_eq!(report.last_successful_sync, None);
        }
    }

    #[test]
    fn status_includes_configuration_counts_and_checks_disabled_family_residuals() {
        let probe = Probe::new(Membership::Present, Verification::Verified, true);
        let configs = Configs::new(ConfigMode::Valid, false);
        let report = status(
            &path_input(),
            &StatusDependencies {
                cancellation: &NoCancellation,
                paths: &Paths,
                configs: &configs,
                saved_counts: &Counts,
                clock: &ClockFixture,
                live_probe: &probe,
            },
        )
        .expect("status");
        assert_eq!(report.configured_feeds, Some(1));
        assert_eq!(report.saved_bans.permanent_asns, Some(1));
        assert_eq!(report.ipv4.enforcement, Verification::Verified);
        assert_eq!(report.ipv6.enforcement, Verification::Unknown);
        assert_eq!(
            *probe.calls.lock().expect("calls"),
            [AddressFamily::Ipv4, AddressFamily::Ipv6]
        );
    }

    #[test]
    fn cancellation_stops_before_any_live_probe() {
        let cancelled = std::sync::atomic::AtomicBool::new(true);
        let probe = Probe::new(Membership::Present, Verification::Verified, true);
        let configs = Configs::new(ConfigMode::Valid, true);
        let result = check(
            &CheckRequest {
                paths: path_input(),
                target: "203.0.113.7".parse().expect("IP"),
            },
            &CheckDependencies {
                cancellation: &cancelled,
                paths: &Paths,
                configs: &configs,
                live_probe: &probe,
            },
        );
        assert!(matches!(result, Err(AppError::Interrupted)));
        assert!(probe.calls.lock().expect("calls").is_empty());
    }
}
