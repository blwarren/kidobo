mod args;
mod blocklist;
mod commands;
mod doctor;
mod flush;
mod init;
mod interrupt;
mod sync;

use std::process::ExitCode;

use clap::Parser;
use clap::error::ErrorKind;

use crate::error::KidoboError;

#[allow(
    clippy::print_stderr,
    reason = "CLI entry point writes operator-facing diagnostics"
)]
pub fn run() -> ExitCode {
    if let Err(err) = interrupt::install_handler() {
        eprintln!("{err}");
        return ExitCode::from(err.exit_code());
    }

    let cli = match args::Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            let exit = clap_error_exit_code(&err);
            let _print_result = err.print();
            return ExitCode::from(exit);
        }
    };

    if let Err(err) = crate::logging::init(cli.log_level.into()) {
        eprintln!("{err}");
        return ExitCode::from(err.exit_code());
    }

    if interrupt::was_interrupted() {
        return ExitCode::from(130);
    }

    let dispatch_result = commands::dispatch(cli.command);

    if interrupt::was_interrupted() {
        return ExitCode::from(130);
    }

    match dispatch_result {
        Ok(()) => ExitCode::SUCCESS,
        Err(KidoboError::Interrupted) => ExitCode::from(130),
        Err(KidoboError::DoctorFailed) => ExitCode::from(1),
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(err.exit_code())
        }
    }
}

fn clap_error_exit_code(err: &clap::Error) -> u8 {
    match err.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => 0,
        _ => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::clap_error_exit_code;
    use crate::cli::args::Cli;
    use clap::Parser;
    use clap::error::ErrorKind;

    #[test]
    fn cli_usage_errors_map_to_exit_code_2() {
        let err =
            Cli::try_parse_from(["kidobo", "lookup"]).expect_err("lookup without target must fail");
        assert_eq!(clap_error_exit_code(&err), 2);
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn help_maps_to_exit_code_0() {
        let err = Cli::try_parse_from(["kidobo", "--help"]).expect_err("help should early-exit");
        assert_eq!(clap_error_exit_code(&err), 0);
    }
}
