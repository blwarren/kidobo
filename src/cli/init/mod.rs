use std::ffi::OsStr;
use std::fmt::Write;
use std::path::PathBuf;

use crate::cli::CliIo;
use crate::error::KidoboError;
use kidobo_adapters::init::SystemInitProvisioner;
use kidobo_adapters::path::{
    ENV_KIDOBO_ROOT, SystemPathResolver, path_resolution_input_from_process,
};
use kidobo_app::init::{
    self, DEFAULT_KIDOBO_BINARY_PATH, FALLBACK_KIDOBO_BINARY_PATH, InitDependencies, InitOutcome,
    InitRequest, ProvisionState,
};

pub fn run_init_command(io: &mut CliIo<'_>) -> Result<(), KidoboError> {
    let paths_input = path_resolution_input_from_process(None);
    let root_override = paths_input
        .env
        .get(OsStr::new(ENV_KIDOBO_ROOT))
        .map(PathBuf::from);
    let paths = SystemPathResolver;
    let provisioner = SystemInitProvisioner::default();
    let outcome = init::execute(
        &InitRequest {
            paths: paths_input,
            root_override,
            executable_candidates: vec![
                PathBuf::from(DEFAULT_KIDOBO_BINARY_PATH),
                PathBuf::from(FALLBACK_KIDOBO_BINARY_PATH),
            ],
        },
        &InitDependencies {
            paths: &paths,
            provisioner: &provisioner,
        },
    )?;
    io.stdout
        .write_all(render_init_outcome(&outcome).as_bytes())
        .map_err(|error| KidoboError::CliIo {
            reason: error.to_string(),
        })?;
    Ok(())
}

fn render_init_outcome(outcome: &InitOutcome) -> String {
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
    let _header = writeln!(
        &mut output,
        "init completed: created={} unchanged={}",
        created.len(),
        preserved.len()
    );
    for artifact in created {
        let _created = writeln!(&mut output, "created: {}", artifact.path.display());
    }
    for artifact in preserved {
        let _preserved = writeln!(&mut output, "unchanged: {}", artifact.path.display());
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
}
