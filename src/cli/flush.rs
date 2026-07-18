use crate::error::KidoboError;
use kidobo_adapters::config::FileConfigRepository;
use kidobo_adapters::flush::SystemFlushBackend;
use kidobo_adapters::lock::FileLockManager;
use kidobo_adapters::path::{SystemPathResolver, path_resolution_input_from_process};
use kidobo_app::AppError;
use kidobo_app::flush::{self, FlushDependencies, FlushRequest};

pub fn run_flush_command(cache_only: bool) -> Result<(), KidoboError> {
    let paths = SystemPathResolver;
    let configs = FileConfigRepository;
    let locks = FileLockManager;
    let backend = SystemFlushBackend::default();
    let outcome = flush::execute(
        &FlushRequest {
            paths: path_resolution_input_from_process(None),
            cache_only,
        },
        &FlushDependencies {
            paths: &paths,
            configs: &configs,
            locks: &locks,
            backend: &backend,
        },
    )?;

    if outcome.failed.is_empty() {
        Ok(())
    } else {
        Err(AppError::FlushIncomplete {
            failures: outcome.failed.len(),
            details: outcome.failure_details(),
        }
        .into())
    }
}
