use std::fmt::Write;
use std::path::PathBuf;

use crate::cli::CliIo;
use crate::error::KidoboError;
use kidobo_adapters::init::SystemInitProvisioner;
use kidobo_adapters::path::{SystemPathResolver, path_resolution_input_from_process};
use kidobo_app::init::{
    self, DEFAULT_KIDOBO_BINARY_PATH, FALLBACK_KIDOBO_BINARY_PATH, InitDependencies, InitOutcome,
    InitRequest, ProvisionState,
};
use kidobo_app::paths::ConfigRequirement;
use kidobo_app::ports::PathResolver;

pub(super) fn init_request() -> Result<InitRequest, KidoboError> {
    let paths = path_resolution_input_from_process(None);
    let resolved = SystemPathResolver.resolve(&paths, ConfigRequirement::Optional)?;
    let executable_candidates = if resolved.root_override.is_some() {
        vec![std::env::current_exe()?]
    } else {
        vec![
            PathBuf::from(DEFAULT_KIDOBO_BINARY_PATH),
            PathBuf::from(FALLBACK_KIDOBO_BINARY_PATH),
        ]
    };
    Ok(InitRequest {
        paths,
        executable_candidates,
    })
}

pub fn run_init_command(io: &mut CliIo<'_>) -> Result<(), KidoboError> {
    let outcome = init::execute(
        &init_request()?,
        &InitDependencies {
            cancellation: &crate::cli::interrupt::SigintCancellation,
            paths: &SystemPathResolver,
            provisioner: &SystemInitProvisioner::default(),
        },
    )?;
    write_init_outcome(&outcome, io)
}

pub(super) fn write_init_outcome(
    outcome: &InitOutcome,
    io: &mut CliIo<'_>,
) -> Result<(), KidoboError> {
    if !io.stdout_is_terminal {
        io.stdout
            .write_all(render_init_outcome(outcome).as_bytes())?;
        return Ok(());
    }
    let view = io.presentation();
    view.heading(io.stdout, "Kidobo initialization")?;
    for artifact in &outcome.artifacts {
        let (status, label) = match artifact.state {
            ProvisionState::Created => (crate::cli::presentation::Status::Pass, "Created"),
            ProvisionState::Preserved => (crate::cli::presentation::Status::Skip, "Preserved"),
            ProvisionState::Secured => (
                crate::cli::presentation::Status::Pass,
                "Secured permissions; contents preserved",
            ),
        };
        view.status(
            io.stdout,
            status,
            label,
            &artifact.path.display().to_string(),
        )?;
    }
    view.paragraph(
        io.stdout,
        if outcome.systemd_enabled {
            "The managed sync timer was enabled."
        } else {
            "No host timer activation was requested by provisioning."
        },
    )?;
    Ok(())
}

pub(super) fn render_init_outcome(outcome: &InitOutcome) -> String {
    let created = outcome
        .artifacts
        .iter()
        .filter(|artifact| artifact.state == ProvisionState::Created)
        .collect::<Vec<_>>();
    let preserved = outcome
        .artifacts
        .iter()
        .filter(|artifact| artifact.state == ProvisionState::Preserved)
        .collect::<Vec<_>>();
    let mut output = String::new();
    let secured = outcome
        .artifacts
        .iter()
        .filter(|artifact| artifact.state == ProvisionState::Secured)
        .collect::<Vec<_>>();
    let _header = writeln!(
        &mut output,
        "init completed: created={} unchanged={}",
        created.len(),
        preserved.len()
    );
    if !secured.is_empty() {
        let _secured_count = writeln!(&mut output, "secured permissions: {}", secured.len());
    }
    for artifact in created {
        let _created = writeln!(
            &mut output,
            "created: {}",
            crate::cli::presentation::escape(&artifact.path.display().to_string())
        );
    }
    for artifact in preserved {
        let _preserved = writeln!(
            &mut output,
            "unchanged: {}",
            crate::cli::presentation::escape(&artifact.path.display().to_string())
        );
    }
    for artifact in secured {
        let _secured = writeln!(
            &mut output,
            "secured permissions (contents preserved): {}",
            crate::cli::presentation::escape(&artifact.path.display().to_string())
        );
    }
    output
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use kidobo_app::init::{InitOutcome, ProvisionState, ProvisionedArtifact};

    use super::render_init_outcome;

    #[test]
    fn renderer_groups_created_before_preserved_artifacts() {
        let rendered = render_init_outcome(&InitOutcome {
            artifacts: vec![
                ProvisionedArtifact {
                    path: PathBuf::from("/unchanged"),
                    state: ProvisionState::Preserved,
                },
                ProvisionedArtifact {
                    path: PathBuf::from("/created"),
                    state: ProvisionState::Created,
                },
            ],
            systemd_enabled: false,
        });
        assert_eq!(
            rendered,
            "init completed: created=1 unchanged=1\ncreated: /created\nunchanged: /unchanged\n"
        );
    }

    #[test]
    fn renderer_reports_secured_permissions_without_claiming_unchanged_metadata() {
        let rendered = render_init_outcome(&InitOutcome {
            artifacts: vec![ProvisionedArtifact {
                path: PathBuf::from("/config.toml"),
                state: ProvisionState::Secured,
            }],
            systemd_enabled: false,
        });
        assert_eq!(
            rendered,
            "init completed: created=0 unchanged=0\nsecured permissions: 1\nsecured permissions (contents preserved): /config.toml\n"
        );
    }
}
