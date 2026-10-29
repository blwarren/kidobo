//! Bounded direct read-only probes for Kidobo's managed firewall and saved state.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::net::IpAddr;
use std::time::Duration;

use kidobo_app::AppError;
use kidobo_app::inspection::{
    FamilyInspection, LiveProbe, Membership, SavedBanCountReader, SavedBanCounts, TimerInspection,
    Verification,
};
use kidobo_app::paths::ResolvedPaths;
use kidobo_app::ports::Cancellation;
use kidobo_app::sync::{AddressFamily, ManagedSetSpec};
use kidobo_app::temporary_bans::TemporaryBanRepository;
use kidobo_core::config::FirewallAction;

use crate::blocklist_file::load_blocklist_document;
use crate::command_runner::{
    CommandExecutor, CommandRequest, CommandResult, SystemCommandExecutor,
};
use crate::iptables::KIDOBO_CHAIN_NAME;
use crate::temporary_bans::FileTemporaryBanRepository;

const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const STAGING_CHAIN: &str = "kidobo-input-stage";

/// Counts only bounded operator-managed files; it never reads remote or ASN cache contents.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemSavedBanCountReader;

impl SavedBanCountReader for SystemSavedBanCountReader {
    fn read_counts(&self, paths: &ResolvedPaths, cutoff: Option<u64>) -> SavedBanCounts {
        let mut counts = SavedBanCounts::default();
        match load_blocklist_document(&paths.blocklist_file) {
            Ok(document) => {
                counts.permanent_ip_cidrs = Some(
                    document
                        .lines
                        .iter()
                        .filter_map(|line| line.canonical)
                        .collect::<BTreeSet<_>>()
                        .len(),
                );
            }
            Err(error) => counts.notices.push(error.to_string()),
        }
        match FileTemporaryBanRepository.load(&paths.temporary_bans_file()) {
            Ok(state) => {
                counts.temporary_ip_cidrs = Some(state.ips.len());
                counts.temporary_asns = Some(state.asns.len());
                if let Some(cutoff) = cutoff {
                    counts.active_temporary_ip_cidrs = Some(
                        state
                            .ips
                            .values()
                            .filter(|expiry| **expiry > cutoff)
                            .count(),
                    );
                    counts.active_temporary_asns = Some(
                        state
                            .asns
                            .values()
                            .filter(|expiry| **expiry > cutoff)
                            .count(),
                    );
                }
            }
            Err(error) => counts.notices.push(error.to_string()),
        }
        counts
    }
}

/// Live probes execute fixed program/argument vectors directly, without sudo or shell evaluation.
#[derive(Debug)]
pub struct SystemLiveProbe<E = SystemCommandExecutor> {
    executor: E,
}

impl<E> SystemLiveProbe<E> {
    #[must_use]
    /// Creates a live probe around an injected bounded command executor.
    pub fn new(executor: E) -> Self {
        Self { executor }
    }
}

impl Default for SystemLiveProbe {
    fn default() -> Self {
        Self::new(SystemCommandExecutor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SetSnapshot {
    state: Verification,
    entries: Option<usize>,
    signature: Option<(String, String, String, usize)>,
    detail: String,
}

impl SetSnapshot {
    fn unknown(detail: impl Into<String>) -> Self {
        Self {
            state: Verification::Unknown,
            entries: None,
            signature: None,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WiringSnapshot {
    state: Verification,
    signature: Vec<String>,
    detail: String,
}

impl WiringSnapshot {
    fn unknown(detail: impl Into<String>) -> Self {
        Self {
            state: Verification::Unknown,
            signature: Vec::new(),
            detail: detail.into(),
        }
    }
}

impl<E: CommandExecutor> SystemLiveProbe<E> {
    fn run(&self, program: &str, args: &[&str]) -> Result<CommandResult, String> {
        self.executor
            .execute(&CommandRequest {
                program: OsString::from(program),
                args: args.iter().map(OsString::from).collect(),
                timeout: PROBE_TIMEOUT,
            })
            .map_err(|error| error.to_string())
    }

    fn inspect_set(&self, spec: &ManagedSetSpec, cancellation: &dyn Cancellation) -> SetSnapshot {
        let names = match self.run("ipset", &["list", "-name"]) {
            Ok(result) if result.status.success() => result.stdout,
            Ok(result) => return SetSnapshot::unknown(probe_failure("ipset list -name", &result)),
            Err(reason) => return SetSnapshot::unknown(reason),
        };
        if !names.lines().any(|name| name == spec.set_name) {
            return SetSnapshot {
                state: Verification::Absent,
                entries: None,
                signature: None,
                detail: format!(
                    "Managed set {} is absent from the readable live set listing",
                    spec.set_name
                ),
            };
        }
        if cancellation.is_cancelled() {
            return SetSnapshot::unknown("Inspection interrupted before managed-set header probe");
        }
        let result = match self.run("ipset", &["list", &spec.set_name, "-terse"]) {
            Ok(result) if result.status.success() => result,
            Ok(result) => {
                return SetSnapshot::unknown(probe_failure("ipset header inspection", &result));
            }
            Err(reason) => return SetSnapshot::unknown(reason),
        };
        parse_set_header(spec, &result.stdout)
    }

    fn inspect_wiring(&self, spec: &ManagedSetSpec, action: FirewallAction) -> WiringSnapshot {
        let program = family_binary(spec.family);
        match self.run(program, &["-S"]) {
            Ok(result) if result.status.success() => parse_wiring(spec, action, &result.stdout),
            Ok(result) => WiringSnapshot::unknown(probe_failure(program, &result)),
            Err(reason) => WiringSnapshot::unknown(reason),
        }
    }

    fn membership(&self, spec: &ManagedSetSpec, target: IpAddr) -> (Membership, String) {
        let target_text = target.to_string();
        let result = match self.run("ipset", &["test", &spec.set_name, &target_text]) {
            Ok(result) => result,
            Err(reason) => return (Membership::Unknown, reason),
        };
        let diagnostic = result
            .stdout
            .lines()
            .chain(result.stderr.lines())
            .filter(|line| !line.trim().is_empty())
            .collect::<Vec<_>>();
        let negative = diagnostic.len() == 1
            && diagnostic
                .first()
                .is_some_and(|line| recognized_nonmember(line, target, &spec.set_name));
        if result.status.success() && !negative {
            (
                Membership::Present,
                format!("Live ipset test verified membership for {target_text}"),
            )
        } else if result.status.code() == Some(1) && negative {
            (
                Membership::Absent,
                format!("Live ipset test verified nonmembership for {target_text}"),
            )
        } else {
            (Membership::Unknown, probe_failure("ipset test", &result))
        }
    }
}

impl<E: CommandExecutor> LiveProbe for SystemLiveProbe<E> {
    fn inspect_family(
        &self,
        spec: &ManagedSetSpec,
        action: FirewallAction,
        target: Option<IpAddr>,
        cancellation: &dyn Cancellation,
    ) -> Result<FamilyInspection, AppError> {
        cancellation.check()?;
        if target.is_some_and(|target| target.is_ipv4() != (spec.family == AddressFamily::Ipv4)) {
            return Ok(FamilyInspection::unknown(
                spec.family,
                Some(&spec.set_name),
                "Address and managed-set families do not match",
            ));
        }
        let before_set = self.inspect_set(spec, cancellation);
        cancellation.check()?;
        let before_wiring = self.inspect_wiring(spec, action);
        cancellation.check()?;
        let before_membership = target.map(|target| {
            if before_set.state == Verification::Verified {
                self.membership(spec, target)
            } else {
                (
                    Membership::Unknown,
                    "Membership is unavailable without a verified managed set".to_string(),
                )
            }
        });
        let mut inspection = FamilyInspection::unknown(
            spec.family,
            Some(&spec.set_name),
            "Unable to verify managed state; inspect evidence and retry with explicit privileges if needed",
        );
        inspection.set_state = before_set.state;
        inspection.entries = before_set.entries;
        inspection.wiring = before_wiring.state;
        inspection.membership = before_membership
            .as_ref()
            .map(|(membership, _)| *membership);
        inspection.evidence = vec![before_set.detail.clone(), before_wiring.detail.clone()];
        if let Some((_, detail)) = &before_membership {
            inspection.evidence.push(detail.clone());
        }
        if before_set.state == Verification::Unknown || before_wiring.state == Verification::Unknown
        {
            return Ok(inspection);
        }
        cancellation.check()?;
        let after_set = self.inspect_set(spec, cancellation);
        cancellation.check()?;
        let after_wiring = self.inspect_wiring(spec, action);
        cancellation.check()?;
        let after_membership = target.map(|target| {
            if after_set.state == Verification::Verified {
                self.membership(spec, target)
            } else {
                (
                    Membership::Unknown,
                    "Membership is unavailable without a verified managed set".to_string(),
                )
            }
        });
        cancellation.check()?;
        let stable = before_set == after_set
            && before_wiring == after_wiring
            && before_membership.as_ref().map(|(membership, _)| membership)
                == after_membership.as_ref().map(|(membership, _)| membership);
        if !stable {
            inspection.set_state = Verification::Unknown;
            inspection.wiring = Verification::Unknown;
            inspection.entries = None;
            inspection.membership = target.map(|_| Membership::Unknown);
            inspection.detail =
                "Managed state changed during inspection; retry the command".to_string();
            inspection
                .evidence
                .extend([after_set.detail, after_wiring.detail]);
            if let Some((_, detail)) = after_membership {
                inspection.evidence.push(detail);
            }
            return Ok(inspection);
        }
        inspection.stable = true;
        inspection.enforcement = match (before_set.state, before_wiring.state) {
            (_, Verification::Absent) => Verification::Absent,
            (Verification::Verified, Verification::Verified) => Verification::Verified,
            _ => Verification::Unknown,
        };
        inspection.detail = match inspection.enforcement {
            Verification::Verified => "Managed set and first INPUT blocking path verified",
            Verification::Absent => "No effective Kidobo-managed INPUT path is present",
            Verification::Unknown => "Managed set and firewall wiring are inconsistent",
        }
        .to_string();
        if inspection.membership == Some(Membership::Unknown)
            && inspection.wiring != Verification::Absent
        {
            inspection.stable = false;
            inspection.detail = "Unable to verify selected-address membership".to_string();
        }
        Ok(inspection)
    }

    fn inspect_timer(&self, cancellation: &dyn Cancellation) -> Result<TimerInspection, AppError> {
        cancellation.check()?;
        let result = self.run(
            "systemctl",
            &[
                "--no-pager",
                "--no-ask-password",
                "show",
                "kidobo-sync.timer",
                "--property=LoadState,ActiveState,UnitFileState",
            ],
        );
        cancellation.check()?;
        Ok(match result {
            Ok(result) if result.status.success() => parse_timer(&result.stdout),
            Ok(result) => {
                TimerInspection::unknown(probe_failure("systemctl timer inspection", &result))
            }
            Err(reason) => TimerInspection::unknown(reason),
        })
    }
}

fn field<'a>(contents: &'a str, prefix: &str) -> Option<&'a str> {
    let mut values = contents
        .lines()
        .filter_map(|line| line.strip_prefix(prefix).map(str::trim));
    let value = values.next()?;
    (values.next().is_none() && !value.is_empty()).then_some(value)
}

fn parse_set_header(spec: &ManagedSetSpec, contents: &str) -> SetSnapshot {
    let Some((name, kind, header, entries)) = field(contents, "Name:")
        .zip(field(contents, "Type:"))
        .zip(field(contents, "Header:"))
        .zip(field(contents, "Number of entries:").and_then(|count| count.parse::<usize>().ok()))
        .map(|(((name, kind), header), entries)| (name, kind, header, entries))
    else {
        return SetSnapshot::unknown("Managed set header is malformed or lacks an entry count");
    };
    let tokens = header.split_whitespace().collect::<Vec<_>>();
    let mut families = tokens.windows(2).filter_map(|pair| match pair {
        ["family", family] => Some(*family),
        _ => None,
    });
    let family = families.next();
    let expected_family = match spec.family {
        AddressFamily::Ipv4 => "inet",
        AddressFamily::Ipv6 => "inet6",
    };
    if name != spec.set_name
        || kind != "hash:net"
        || kind != spec.set_type
        || family != Some(expected_family)
        || families.next().is_some()
    {
        return SetSnapshot::unknown(
            "Managed set name, type, or address family differs from the supported configuration",
        );
    }
    SetSnapshot {
        state: Verification::Verified,
        entries: Some(entries),
        signature: Some((
            name.to_string(),
            kind.to_string(),
            header.to_string(),
            entries,
        )),
        detail: format!(
            "Verified {} {expected_family} set {name}: {entries} kernel entries",
            spec.set_type
        ),
    }
}

fn family_binary(family: AddressFamily) -> &'static str {
    match family {
        AddressFamily::Ipv4 => "iptables",
        AddressFamily::Ipv6 => "ip6tables",
    }
}

fn refers_to_managed_chain(line: &str) -> bool {
    let tokens = line.split_whitespace().collect::<Vec<_>>();
    tokens.windows(2).any(|pair| {
        matches!(
            pair,
            [
                "-j" | "--jump" | "-g" | "--goto",
                KIDOBO_CHAIN_NAME | STAGING_CHAIN
            ]
        )
    })
}

fn parse_wiring(spec: &ManagedSetSpec, action: FirewallAction, contents: &str) -> WiringSnapshot {
    let lines = contents
        .lines()
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let policies = lines
        .iter()
        .filter(|line| matches!(**line, "-P INPUT ACCEPT" | "-P INPUT DROP"))
        .count();
    if policies != 1
        || lines.iter().any(|line| {
            !(line.starts_with("-P ") || line.starts_with("-N ") || line.starts_with("-A "))
        })
    {
        return WiringSnapshot::unknown(
            "Firewall rule output is malformed or lacks an authoritative INPUT policy",
        );
    }
    let references = lines
        .iter()
        .copied()
        .filter(|line| refers_to_managed_chain(line))
        .collect::<Vec<_>>();
    let signature = lines
        .iter()
        .copied()
        .filter(|line| {
            line.starts_with("-P INPUT ")
                || line.starts_with("-A INPUT ")
                || line.starts_with("-A kidobo-input ")
                || line.starts_with("-A kidobo-input-stage ")
                || refers_to_managed_chain(line)
        })
        .map(ToString::to_string)
        .collect();
    if references.is_empty() {
        return WiringSnapshot {
            state: Verification::Absent,
            signature,
            detail: "Readable filter rules contain no reference to Kidobo's managed chains"
                .to_string(),
        };
    }
    let input_first = lines
        .iter()
        .copied()
        .find(|line| line.starts_with("-A INPUT "));
    let managed_rules = lines
        .iter()
        .copied()
        .filter(|line| line.starts_with("-A kidobo-input "))
        .collect::<Vec<_>>();
    let target = match action {
        FirewallAction::Drop => "DROP",
        FirewallAction::Reject => "REJECT",
    };
    let expected = format!(
        "-A kidobo-input -m set --match-set {} src -j {target}",
        spec.set_name
    );
    let reject_suffix = match spec.family {
        AddressFamily::Ipv4 => " --reject-with icmp-port-unreachable",
        AddressFamily::Ipv6 => " --reject-with icmp6-port-unreachable",
    };
    let valid_rule = managed_rules.first().is_some_and(|rule| {
        *rule == expected
            || (action == FirewallAction::Reject
                && rule.strip_prefix(&expected) == Some(reject_suffix))
    });
    let staging = lines
        .iter()
        .any(|line| *line == "-N kidobo-input-stage" || line.starts_with("-A kidobo-input-stage "));
    if references == ["-A INPUT -j kidobo-input"]
        && input_first == Some("-A INPUT -j kidobo-input")
        && managed_rules.len() == 1
        && valid_rule
        && !staging
    {
        WiringSnapshot {
            state: Verification::Verified,
            signature,
            detail: format!("Verified first INPUT jump and managed source-set {target} rule"),
        }
    } else {
        WiringSnapshot::unknown(
            "Managed firewall wiring is noncanonical, indirect, duplicated, staged, or differs from configuration",
        )
    }
}

fn recognized_nonmember(line: &str, target: IpAddr, set_name: &str) -> bool {
    let Some((address, name)) = line.trim().split_once(" is NOT in set ") else {
        return false;
    };
    address.parse::<IpAddr>().ok() == Some(target)
        && (name == set_name || name.strip_suffix('.') == Some(set_name))
}

fn probe_failure(operation: &str, result: &CommandResult) -> String {
    let detail = if result.stderr.trim().is_empty() {
        result.stdout.trim()
    } else {
        result.stderr.trim()
    };
    format!(
        "Unable to verify {operation}: status {:?}: {detail}",
        result.status
    )
}

fn parse_timer(contents: &str) -> TimerInspection {
    let Some(load) = field(contents, "LoadState=") else {
        return TimerInspection::unknown("systemd returned no unambiguous timer load state");
    };
    if load == "not-found" {
        return TimerInspection {
            state: Verification::Absent,
            enabled: Some(false),
            active: Some(false),
            detail: "kidobo-sync.timer is not installed in this systemd instance".to_string(),
        };
    }
    if load != "loaded" {
        return TimerInspection::unknown(format!("Timer load state is {load}"));
    }
    let active_state = field(contents, "ActiveState=");
    let enabled_state = field(contents, "UnitFileState=");
    let active = match active_state {
        Some("active") => Some(true),
        Some("inactive" | "failed") => Some(false),
        _ => None,
    };
    let enabled = match enabled_state {
        Some("enabled" | "enabled-runtime") => Some(true),
        Some("disabled" | "masked" | "masked-runtime") => Some(false),
        _ => None,
    };
    TimerInspection {
        state: if active.is_some() && enabled.is_some() {
            Verification::Verified
        } else {
            Verification::Unknown
        },
        enabled,
        active,
        detail: format!(
            "systemd reports ActiveState={} UnitFileState={}",
            active_state.unwrap_or("unknown"),
            enabled_state.unwrap_or("unknown")
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::path::Path;
    use std::sync::Mutex;

    use kidobo_app::ports::NoCancellation;
    use kidobo_core::config::Config;
    use tempfile::TempDir;

    use super::*;
    use crate::command_runner::{CommandRunnerError, ProcessStatus};

    struct Step {
        program: String,
        args: Vec<String>,
        result: CommandResult,
    }

    struct ScriptedExecutor {
        steps: Mutex<VecDeque<Step>>,
    }

    impl ScriptedExecutor {
        fn new(steps: Vec<Step>) -> Self {
            Self {
                steps: Mutex::new(steps.into()),
            }
        }
        fn finished(&self) {
            assert!(self.steps.lock().expect("steps").is_empty());
        }
    }

    impl CommandExecutor for ScriptedExecutor {
        fn execute(&self, request: &CommandRequest) -> Result<CommandResult, CommandRunnerError> {
            let step = self
                .steps
                .lock()
                .expect("steps")
                .pop_front()
                .expect("unexpected command");
            assert_eq!(request.program, OsString::from(step.program));
            assert_eq!(
                request.args,
                step.args
                    .into_iter()
                    .map(OsString::from)
                    .collect::<Vec<_>>()
            );
            assert_eq!(request.timeout, PROBE_TIMEOUT);
            Ok(step.result)
        }
    }

    fn response(code: i32, stdout: &str, stderr: &str) -> CommandResult {
        CommandResult {
            status: ProcessStatus::Exited(code),
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
        }
    }

    fn step(program: &str, args: &[&str], result: CommandResult) -> Step {
        assert!(!matches!(program, "sudo" | "sh" | "bash"));
        Step {
            program: program.to_string(),
            args: args.iter().map(ToString::to_string).collect(),
            result,
        }
    }

    fn spec(ipv6: bool) -> ManagedSetSpec {
        let config = Config::from_toml_str("[ipset]\nset_name='kidobo'\n").expect("config");
        let plan = kidobo_app::sync::EnforcementPlan::from_config(&config);
        if ipv6 { plan.ipv6 } else { plan.ipv4 }
    }

    fn header(spec: &ManagedSetSpec, count: usize) -> String {
        let family = if spec.family == AddressFamily::Ipv4 {
            "inet"
        } else {
            "inet6"
        };
        format!(
            "Name: {}\nType: hash:net\nRevision: 7\nHeader: family {family} hashsize 65536 maxelem 500000\nSize in memory: 1024\nReferences: 1\nNumber of entries: {count}\n",
            spec.set_name
        )
    }

    fn wiring(spec: &ManagedSetSpec) -> String {
        format!(
            "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n-N kidobo-input\n-A INPUT -j kidobo-input\n-A kidobo-input -m set --match-set {} src -j DROP\n",
            spec.set_name
        )
    }

    fn round(
        spec: &ManagedSetSpec,
        target: Option<IpAddr>,
        count: usize,
        rules: &str,
        membership: CommandResult,
    ) -> Vec<Step> {
        let mut steps = vec![
            step(
                "ipset",
                &["list", "-name"],
                response(0, &format!("{}\n", spec.set_name), ""),
            ),
            step(
                "ipset",
                &["list", &spec.set_name, "-terse"],
                response(0, &header(spec, count), ""),
            ),
            step(family_binary(spec.family), &["-S"], response(0, rules, "")),
        ];
        if let Some(target) = target {
            steps.push(step(
                "ipset",
                &["test", &spec.set_name, &target.to_string()],
                membership,
            ));
        }
        steps
    }

    #[test]
    fn live_membership_and_wiring_are_verified_for_each_family_using_direct_bounded_probes() {
        for (ipv6, address) in [(false, "203.0.113.7"), (true, "2001:db8::7")] {
            let spec = spec(ipv6);
            let target = address.parse().expect("IP");
            let rules = wiring(&spec);
            let mut steps = round(&spec, Some(target), 17, &rules, response(0, "", ""));
            steps.extend(round(&spec, Some(target), 17, &rules, response(0, "", "")));
            let probe = SystemLiveProbe::new(ScriptedExecutor::new(steps));
            let result = probe
                .inspect_family(&spec, FirewallAction::Drop, Some(target), &NoCancellation)
                .expect("inspection");
            assert_eq!(result.enforcement, Verification::Verified);
            assert_eq!(result.membership, Some(Membership::Present));
            assert_eq!(result.entries, Some(17));
            assert!(result.stable);
            probe.executor.finished();
        }
    }

    #[test]
    fn recognized_nonmembership_is_distinct_from_permission_and_unrecognized_errors() {
        let spec = spec(false);
        let target: IpAddr = "203.0.113.7".parse().expect("IP");
        let rules = wiring(&spec);
        for (diagnostic, expected) in [
            ("203.0.113.7 is NOT in set kidobo.", Membership::Absent),
            (
                "ipset v7: Kernel error received: Operation not permitted",
                Membership::Unknown,
            ),
            ("localized or unsupported diagnostic", Membership::Unknown),
        ] {
            let mut steps = round(&spec, Some(target), 17, &rules, response(1, "", diagnostic));
            steps.extend(round(
                &spec,
                Some(target),
                17,
                &rules,
                response(1, "", diagnostic),
            ));
            let probe = SystemLiveProbe::new(ScriptedExecutor::new(steps));
            let result = probe
                .inspect_family(&spec, FirewallAction::Drop, Some(target), &NoCancellation)
                .expect("inspection");
            assert_eq!(result.membership, Some(expected));
            assert_eq!(result.stable, expected != Membership::Unknown);
            probe.executor.finished();
        }
    }

    #[test]
    fn malformed_headers_or_permission_failures_preserve_unknown_state() {
        let spec = spec(false);
        for malformed in [false, true] {
            let mut steps = vec![step(
                "ipset",
                &["list", "-name"],
                if malformed {
                    response(0, "kidobo\n", "")
                } else {
                    response(1, "", "Operation not permitted")
                },
            )];
            if malformed {
                steps.push(step(
                    "ipset",
                    &["list", "kidobo", "-terse"],
                    response(0, "Name: kidobo\nType: hash:net\nHeader: family inet\n", ""),
                ));
            }
            steps.push(step("iptables", &["-S"], response(0, &wiring(&spec), "")));
            let probe = SystemLiveProbe::new(ScriptedExecutor::new(steps));
            let result = probe
                .inspect_family(&spec, FirewallAction::Drop, None, &NoCancellation)
                .expect("partial inspection");
            assert_eq!(result.set_state, Verification::Unknown);
            assert_eq!(result.enforcement, Verification::Unknown);
            assert_eq!(result.entries, None);
            probe.executor.finished();
        }
    }

    #[test]
    fn authoritative_absence_needs_readable_set_listing_and_firewall_policy() {
        let spec = spec(false);
        let mut steps = Vec::new();
        for _ in 0..2 {
            steps.push(step("ipset", &["list", "-name"], response(0, "", "")));
            steps.push(step(
                "iptables",
                &["-S"],
                response(0, "-P INPUT ACCEPT\n-P OUTPUT ACCEPT\n", ""),
            ));
        }
        let probe = SystemLiveProbe::new(ScriptedExecutor::new(steps));
        let result = probe
            .inspect_family(
                &spec,
                FirewallAction::Drop,
                Some("203.0.113.7".parse().expect("IP")),
                &NoCancellation,
            )
            .expect("inspection");
        assert_eq!(result.set_state, Verification::Absent);
        assert_eq!(result.wiring, Verification::Absent);
        assert_eq!(result.enforcement, Verification::Absent);
        assert!(result.stable);
        assert_eq!(
            parse_wiring(&spec, FirewallAction::Drop, "").state,
            Verification::Unknown
        );
        probe.executor.finished();
    }

    #[test]
    fn duplicate_indirect_staged_shadowed_and_wrong_action_wiring_is_inconclusive() {
        let spec = spec(false);
        let canonical = wiring(&spec);
        for rules in [
            canonical.replace("-A INPUT -j kidobo-input", "-A INPUT -j kidobo-input\n-A INPUT -j kidobo-input"),
            canonical.replace("-A INPUT -j kidobo-input", "-A INPUT -j other\n-A other -j kidobo-input"),
            canonical.replace("-A INPUT -j kidobo-input", "-N kidobo-input-stage\n-A INPUT -j kidobo-input-stage\n-A kidobo-input-stage -j kidobo-input"),
            canonical.replace("-A INPUT -j kidobo-input", "-A INPUT -j ACCEPT\n-A INPUT -j kidobo-input"),
            canonical.replace("--match-set kidobo src", "--match-set other src"),
            canonical.replace("-j DROP", "-j ACCEPT"),
        ] {
            assert_eq!(parse_wiring(&spec, FirewallAction::Drop, &rules).state, Verification::Unknown, "{rules}");
        }
        let reject = canonical.replace("-j DROP", "-j REJECT --reject-with icmp-port-unreachable");
        assert_eq!(
            parse_wiring(&spec, FirewallAction::Reject, &reject).state,
            Verification::Verified
        );
    }

    #[test]
    fn default_reject_rendering_is_verified_for_the_correct_family_only() {
        for (ipv6, suffix, wrong_suffix) in [
            (false, "icmp-port-unreachable", "icmp6-port-unreachable"),
            (true, "icmp6-port-unreachable", "icmp-port-unreachable"),
        ] {
            let spec = spec(ipv6);
            let canonical = wiring(&spec);
            let reject = canonical.replace("-j DROP", &format!("-j REJECT --reject-with {suffix}"));
            assert_eq!(
                parse_wiring(&spec, FirewallAction::Reject, &reject).state,
                Verification::Verified
            );
            for unsupported in [
                canonical.replace(
                    "-j DROP",
                    &format!("-j REJECT --reject-with {wrong_suffix}"),
                ),
                reject.replace(" src -j ", " src -p tcp -j "),
                reject.replace(" src -j ", " src -s 203.0.113.7/32 -j "),
            ] {
                assert_eq!(
                    parse_wiring(&spec, FirewallAction::Reject, &unsupported).state,
                    Verification::Unknown
                );
            }
        }
    }

    #[test]
    fn changing_counts_or_membership_invalidate_the_snapshot() {
        let spec = spec(false);
        let target: IpAddr = "203.0.113.7".parse().expect("IP");
        let rules = wiring(&spec);
        for (count, second_membership) in [
            (18, response(0, "", "")),
            (17, response(1, "", "203.0.113.7 is NOT in set kidobo.")),
        ] {
            let mut steps = round(&spec, Some(target), 17, &rules, response(0, "", ""));
            steps.extend(round(&spec, Some(target), count, &rules, second_membership));
            let probe = SystemLiveProbe::new(ScriptedExecutor::new(steps));
            let result = probe
                .inspect_family(&spec, FirewallAction::Drop, Some(target), &NoCancellation)
                .expect("inspection");
            assert_eq!(result.enforcement, Verification::Unknown);
            assert!(!result.stable);
            assert_eq!(result.set_state, Verification::Unknown);
            assert_eq!(result.wiring, Verification::Unknown);
            assert_eq!(result.entries, None);
            assert_eq!(result.membership, Some(Membership::Unknown));
            assert!(result.detail.contains("changed"));
            probe.executor.finished();
        }
    }

    #[test]
    fn cancellation_between_set_listing_and_header_stops_further_commands() {
        struct CancellingExecutor(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl CommandExecutor for CancellingExecutor {
            fn execute(
                &self,
                request: &CommandRequest,
            ) -> Result<CommandResult, CommandRunnerError> {
                assert!(!self.0.load(std::sync::atomic::Ordering::SeqCst));
                assert_eq!(request.program, OsString::from("ipset"));
                assert_eq!(
                    request.args,
                    [OsString::from("list"), OsString::from("-name")]
                );
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(response(0, "kidobo\n", ""))
            }
        }
        let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let probe = SystemLiveProbe::new(CancellingExecutor(std::sync::Arc::clone(&cancelled)));
        let result =
            probe.inspect_family(&spec(false), FirewallAction::Drop, None, cancelled.as_ref());
        assert!(matches!(result, Err(AppError::Interrupted)));
    }

    #[test]
    fn timer_properties_are_read_directly_and_unknown_values_are_not_guessed() {
        let probe = SystemLiveProbe::new(ScriptedExecutor::new(vec![step(
            "systemctl",
            &[
                "--no-pager",
                "--no-ask-password",
                "show",
                "kidobo-sync.timer",
                "--property=LoadState,ActiveState,UnitFileState",
            ],
            response(
                0,
                "LoadState=loaded\nActiveState=active\nUnitFileState=enabled\n",
                "",
            ),
        )]));
        let timer = probe.inspect_timer(&NoCancellation).expect("timer");
        assert_eq!(
            (timer.state, timer.active, timer.enabled),
            (Verification::Verified, Some(true), Some(true))
        );
        probe.executor.finished();
        assert_eq!(
            parse_timer("LoadState=not-found\n").state,
            Verification::Absent
        );
        let ambiguous =
            parse_timer("LoadState=loaded\nActiveState=activating\nUnitFileState=static\n");
        assert_eq!(
            (ambiguous.state, ambiguous.active, ambiguous.enabled),
            (Verification::Unknown, None, None)
        );
        assert_eq!(
            parse_timer("LoadState=loaded\nLoadState=error\n").state,
            Verification::Unknown
        );
    }

    fn paths(root: &Path) -> ResolvedPaths {
        ResolvedPaths {
            root_override: Some(root.to_path_buf()),
            config_dir: root.join("config"),
            config_file: root.join("config/config.toml"),
            data_dir: root.join("data"),
            blocklist_file: root.join("data/blocklist.txt"),
            cache_dir: root.join("cache"),
            remote_cache_dir: root.join("cache/remote"),
            lock_file: root.join("cache/lock"),
        }
    }

    #[test]
    fn saved_counts_are_read_only_and_keep_partial_counts_on_malformed_state() {
        let temp = TempDir::new().expect("tempdir");
        let paths = paths(temp.path());
        std::fs::create_dir(&paths.data_dir).expect("data");
        let blocklist = "203.0.113.7\n203.0.113.7/32\n2001:db8::/64\n";
        std::fs::write(&paths.blocklist_file, blocklist).expect("blocklist");
        let temporary = "version=1\n[[ips]]\ncidr='198.51.100.1/32'\nexpires_at=101\n[[ips]]\ncidr='198.51.100.2/32'\nexpires_at=100\n[[asns]]\nasn=64512\nexpires_at=101\n[[asns]]\nasn=64513\nexpires_at=99\n";
        std::fs::write(paths.temporary_bans_file(), temporary).expect("temporary");
        let counts = SystemSavedBanCountReader.read_counts(&paths, Some(100));
        assert_eq!(counts.permanent_ip_cidrs, Some(2));
        assert_eq!(
            (counts.temporary_ip_cidrs, counts.active_temporary_ip_cidrs),
            (Some(2), Some(1))
        );
        assert_eq!(
            (counts.temporary_asns, counts.active_temporary_asns),
            (Some(2), Some(1))
        );
        assert_eq!(
            crate::limited_io::read_to_string_with_limit(&paths.blocklist_file, 1024)
                .expect("unchanged blocklist"),
            blocklist
        );
        assert_eq!(
            crate::limited_io::read_to_string_with_limit(&paths.temporary_bans_file(), 1024)
                .expect("unchanged temporary state"),
            temporary
        );
        assert!(!paths.cache_dir.exists());
        std::fs::write(paths.temporary_bans_file(), "invalid").expect("malformed temporary");
        let partial = SystemSavedBanCountReader.read_counts(&paths, Some(100));
        assert_eq!(partial.permanent_ip_cidrs, Some(2));
        assert_eq!(partial.temporary_ip_cidrs, None);
        assert_eq!(partial.notices.len(), 1);
        assert!(!paths.cache_dir.exists());
    }
}
