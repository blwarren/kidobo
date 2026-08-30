//! Production ipset and iptables implementation of the sync enforcement port.

use kidobo_app::AppError;
use kidobo_app::source::Notice;
use kidobo_app::sync::{EnforcementBackend, EnforcementPlan, ManagedSetSpec};
use kidobo_core::AddressFamily;
use kidobo_core::config::FirewallAction;
use kidobo_core::network::CanonicalCidr;

use crate::command_runner::{SudoCommandRunner, SystemCommandExecutor};
use crate::ipset::{
    IpsetCommandRunner, IpsetFamily, IpsetSetSpec, atomic_replace_ipset_values, ensure_ipset_exists,
};
use crate::iptables::{
    ChainAction, FirewallFamily, cleanup_firewall_wiring, ensure_firewall_artifacts_for_families,
    ensure_firewall_wiring_for_families,
};

/// Enforcement backend using injected ipset and firewall command runners.
#[derive(Debug)]
pub struct CommandEnforcementBackend<R> {
    runner: R,
}

impl<R> CommandEnforcementBackend<R> {
    #[must_use]
    /// Creates an enforcement backend around the supplied runner.
    pub fn new(runner: R) -> Self {
        Self { runner }
    }
}

impl Default for CommandEnforcementBackend<SudoCommandRunner<SystemCommandExecutor>> {
    fn default() -> Self {
        Self::new(SudoCommandRunner::default())
    }
}

/// Production enforcement backend using noninteractive bounded sudo commands.
pub type SystemEnforcementBackend =
    CommandEnforcementBackend<SudoCommandRunner<SystemCommandExecutor>>;

impl<R> EnforcementBackend for CommandEnforcementBackend<R>
where
    R: IpsetCommandRunner + crate::iptables::FirewallCommandRunner,
{
    fn ensure_artifacts(&self, plan: &EnforcementPlan) -> Result<(), AppError> {
        ensure_ipset_exists(&self.runner, &to_ipset_spec(&plan.ipv4))
            .map_err(|error| map_ipset_error(&error))?;
        if plan.enable_ipv6 {
            ensure_ipset_exists(&self.runner, &to_ipset_spec(&plan.ipv6))
                .map_err(|error| map_ipset_error(&error))?;
        }
        ensure_firewall_artifacts_for_families(&self.runner, plan.enable_ipv6)
            .map_err(|error| map_firewall_error(&error))
    }

    fn replace_set(
        &self,
        spec: &ManagedSetSpec,
        entries: &[CanonicalCidr],
    ) -> Result<(), AppError> {
        atomic_replace_ipset_values(&self.runner, &to_ipset_spec(spec), entries)
            .map_err(|error| map_ipset_error(&error))
    }

    fn activate(&self, plan: &EnforcementPlan) -> Result<(), AppError> {
        ensure_firewall_wiring_for_families(
            &self.runner,
            &plan.ipv4.set_name,
            &plan.ipv6.set_name,
            plan.enable_ipv6,
            to_chain_action(plan.chain_action),
        )
        .map_err(|error| map_firewall_error(&error))
    }

    fn cleanup_disabled_ipv6(&self, plan: &EnforcementPlan) -> Vec<Notice> {
        let mut notices = Vec::new();
        if let Err(error) = cleanup_firewall_wiring(&self.runner, FirewallFamily::Ipv6) {
            notices.push(Notice::warning(format!(
                "disabled IPv6 firewall cleanup failed softly: {error}"
            )));
        }

        if plan.ipv6.set_name == plan.ipv4.set_name {
            notices.push(Notice::warning(
                "disabled IPv6 ipset cleanup skipped because its name matches the IPv4 set",
            ));
            return notices;
        }

        if let Err(error) =
            IpsetCommandRunner::run(&self.runner, "ipset", &["destroy", &plan.ipv6.set_name])
        {
            notices.push(Notice::warning(format!(
                "disabled IPv6 ipset cleanup failed softly for {}: {error}",
                plan.ipv6.set_name
            )));
        }
        notices
    }
}

fn to_ipset_spec(spec: &ManagedSetSpec) -> IpsetSetSpec {
    IpsetSetSpec {
        set_name: spec.set_name.clone(),
        set_type: spec.set_type.clone(),
        family: match spec.family {
            AddressFamily::Ipv4 => IpsetFamily::Inet,
            AddressFamily::Ipv6 => IpsetFamily::Inet6,
        },
        hashsize: spec.hashsize,
        maxelem: spec.maxelem,
        timeout: spec.timeout,
    }
}

fn to_chain_action(action: FirewallAction) -> ChainAction {
    match action {
        FirewallAction::Drop => ChainAction::Drop,
        FirewallAction::Reject => ChainAction::Reject,
    }
}

fn map_ipset_error(error: &crate::ipset::IpsetError) -> AppError {
    AppError::Ipset {
        reason: error.to_string(),
    }
}

fn map_firewall_error(error: &crate::iptables::FirewallError) -> AppError {
    AppError::Firewall {
        reason: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use kidobo_app::sync::{EnforcementBackend, EnforcementPlan, ManagedSetSpec};
    use kidobo_core::AddressFamily;
    use kidobo_core::config::FirewallAction;

    use super::CommandEnforcementBackend;
    use crate::command_runner::{CommandResult, CommandRunnerError, ProcessStatus};
    use crate::ipset::IpsetCommandRunner;
    use crate::iptables::FirewallCommandRunner;

    struct Runner(RefCell<Vec<(String, Vec<String>)>>);

    impl Runner {
        fn run(&self, command: &str, args: &[&str]) -> CommandResult {
            self.0.borrow_mut().push((
                command.to_string(),
                args.iter().map(|value| (*value).to_string()).collect(),
            ));
            let effective = if args.starts_with(&["-w", "5"]) {
                &args[2..]
            } else {
                args
            };
            if effective.starts_with(&["-D", "INPUT"]) {
                CommandResult {
                    status: ProcessStatus::Exited(1),
                    stdout: String::new(),
                    stderr: "Bad rule (does a matching rule exist in that chain?).".to_string(),
                }
            } else {
                CommandResult {
                    status: ProcessStatus::Exited(0),
                    stdout: String::new(),
                    stderr: String::new(),
                }
            }
        }
    }

    impl IpsetCommandRunner for Runner {
        fn run(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
            Ok(self.run(command, args))
        }
    }

    impl FirewallCommandRunner for Runner {
        fn run(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
            Ok(self.run(command, args))
        }
    }

    fn set(family: AddressFamily, name: &str) -> ManagedSetSpec {
        ManagedSetSpec {
            family,
            set_name: name.to_string(),
            set_type: "hash:net".to_string(),
            hashsize: 1024,
            maxelem: 100,
            timeout: 0,
        }
    }

    #[test]
    fn disabled_ipv6_cleanup_never_destroys_shared_ipv4_set_name() {
        let backend = CommandEnforcementBackend::new(Runner(RefCell::new(Vec::new())));
        let notices = backend.cleanup_disabled_ipv6(&EnforcementPlan {
            ipv4: set(AddressFamily::Ipv4, "shared"),
            ipv6: set(AddressFamily::Ipv6, "shared"),
            enable_ipv6: false,
            chain_action: FirewallAction::Drop,
        });

        assert!(
            notices
                .iter()
                .any(|notice| notice.message.contains("name matches"))
        );
        assert!(
            backend
                .runner
                .0
                .borrow()
                .iter()
                .all(|(command, _)| command != "ipset")
        );
    }
}
