use std::env;
use std::fmt::Display;
use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use log::warn;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::adapters::command_common::{display_command, ensure_command_succeeded};
use crate::adapters::command_runner::{
    CommandExecutor, CommandResult, CommandRunnerError, ProcessStatus, SudoCommandRunner,
};
use crate::adapters::hash::hex_lower;

const IPSET_NAME_MAX_LEN: usize = 31;
#[cfg(test)]
const RESTORE_SCRIPT_READ_LIMIT: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpsetFamily {
    Inet,
    Inet6,
}

impl IpsetFamily {
    fn as_str(self) -> &'static str {
        match self {
            Self::Inet => "inet",
            Self::Inet6 => "inet6",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpsetSetSpec {
    pub set_name: String,
    pub set_type: String,
    pub family: IpsetFamily,
    pub hashsize: u32,
    pub maxelem: u32,
    pub timeout: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IpsetSetInfo {
    set_type: String,
    family: IpsetFamily,
}

#[derive(Debug, Error)]
pub enum IpsetError {
    #[error("ipset command execution failed: {source}")]
    CommandExecution {
        #[from]
        source: CommandRunnerError,
    },

    #[error("ipset command failed `{command}` with status {status:?}: {stderr}")]
    CommandFailed {
        command: String,
        status: ProcessStatus,
        stderr: String,
    },

    #[error("failed to write ipset restore script {path}: {reason}")]
    WriteRestoreScript { path: PathBuf, reason: String },

    #[error("failed to create ipset restore script {path}: {reason}")]
    CreateRestoreScript { path: PathBuf, reason: String },

    #[error("failed to inspect existing ipset `{set_name}`: {reason}")]
    MalformedInspection { set_name: String, reason: String },

    #[error(
        "existing ipset `{set_name}` is incompatible: expected type `{expected_type}` family `{expected_family}`, found type `{actual_type}` family `{actual_family}`"
    )]
    IncompatibleSet {
        set_name: String,
        expected_type: String,
        expected_family: &'static str,
        actual_type: String,
        actual_family: &'static str,
    },
}

pub trait IpsetCommandRunner {
    fn run(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError>;
}

impl<E: CommandExecutor> IpsetCommandRunner for SudoCommandRunner<E> {
    fn run(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
        SudoCommandRunner::run(self, command, args)
    }
}

pub fn ensure_ipset_exists(
    runner: &dyn IpsetCommandRunner,
    spec: &IpsetSetSpec,
) -> Result<(), IpsetError> {
    if let Some(info) = inspect_ipset(runner, &spec.set_name)? {
        if info.set_type != spec.set_type || info.family != spec.family {
            return Err(IpsetError::IncompatibleSet {
                set_name: spec.set_name.clone(),
                expected_type: spec.set_type.clone(),
                expected_family: spec.family.as_str(),
                actual_type: info.set_type,
                actual_family: info.family.as_str(),
            });
        }
        return Ok(());
    }

    create_ipset(runner, spec)
}

fn inspect_ipset(
    runner: &dyn IpsetCommandRunner,
    set_name: &str,
) -> Result<Option<IpsetSetInfo>, IpsetError> {
    let terse_args = ["list", set_name, "-terse"];
    let terse_result = runner.run("ipset", &terse_args)?;
    let result = if terse_result.status.success() {
        terse_result
    } else if is_missing_set_result(&terse_result) {
        return Ok(None);
    } else if is_unsupported_terse_option_result(&terse_result) {
        let list_args = ["list", set_name];
        let result = runner.run("ipset", &list_args)?;
        if is_missing_set_result(&result) {
            return Ok(None);
        }
        ensure_command_succeeded(result, "ipset", &list_args, |command, status, stderr| {
            IpsetError::CommandFailed {
                command,
                status,
                stderr,
            }
        })?
    } else {
        return Err(IpsetError::CommandFailed {
            command: display_command("ipset", &terse_args),
            status: terse_result.status,
            stderr: terse_result.stderr,
        });
    };

    parse_ipset_info(&result.stdout)
        .map(Some)
        .map_err(|reason| IpsetError::MalformedInspection {
            set_name: set_name.to_string(),
            reason,
        })
}

fn parse_ipset_info(stdout: &str) -> Result<IpsetSetInfo, String> {
    let set_type = stdout
        .lines()
        .find_map(|line| line.strip_prefix("Type:").map(str::trim))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "missing `Type:` field".to_string())?;
    let header = stdout
        .lines()
        .find_map(|line| line.strip_prefix("Header:").map(str::trim))
        .ok_or_else(|| "missing `Header:` field".to_string())?;
    let tokens = header.split_whitespace().collect::<Vec<_>>();
    let family = tokens
        .windows(2)
        .find_map(|pair| {
            pair.first()
                .zip(pair.get(1))
                .and_then(|(key, value)| (*key == "family").then_some(*value))
        })
        .ok_or_else(|| "missing family in `Header:` field".to_string())?;
    let family = match family {
        "inet" => IpsetFamily::Inet,
        "inet6" => IpsetFamily::Inet6,
        other => return Err(format!("unsupported family `{other}`")),
    };

    Ok(IpsetSetInfo {
        set_type: set_type.to_string(),
        family,
    })
}

pub fn create_ipset(
    runner: &dyn IpsetCommandRunner,
    spec: &IpsetSetSpec,
) -> Result<(), IpsetError> {
    let hashsize = spec.hashsize.to_string();
    let maxelem = spec.maxelem.to_string();
    let timeout = spec.timeout.to_string();

    run_checked(
        runner,
        "ipset",
        &[
            "create",
            &spec.set_name,
            &spec.set_type,
            "family",
            spec.family.as_str(),
            "hashsize",
            &hashsize,
            "maxelem",
            &maxelem,
            "timeout",
            &timeout,
            "-exist",
        ],
    )?;

    Ok(())
}

pub fn generate_temp_set_name(base_set_name: &str) -> String {
    let suffix = random_hex_suffix(8);
    let max_base_len = IPSET_NAME_MAX_LEN.saturating_sub(suffix.len() + 1);
    let mut base = truncate_to_max_bytes(base_set_name, max_base_len).to_string();
    if base.is_empty() {
        base = "kidobo".to_string();
    }

    let candidate = format!("{base}-{suffix}");
    if candidate.len() <= IPSET_NAME_MAX_LEN {
        candidate
    } else {
        truncate_to_max_bytes(&candidate, IPSET_NAME_MAX_LEN).to_string()
    }
}

pub fn atomic_replace_ipset_values<T: Ord + Display>(
    runner: &dyn IpsetCommandRunner,
    spec: &IpsetSetSpec,
    entries: &[T],
) -> Result<(), IpsetError> {
    let temp_set_name = generate_temp_set_name(&spec.set_name);

    best_effort_destroy_set(runner, &temp_set_name);

    let restore_result = execute_ipset_restore_with_entries(runner, spec, &temp_set_name, entries);

    best_effort_destroy_set(runner, &temp_set_name);

    restore_result
}

fn run_checked(
    runner: &dyn IpsetCommandRunner,
    command: &str,
    args: &[&str],
) -> Result<CommandResult, IpsetError> {
    let result = runner.run(command, args)?;
    ensure_command_succeeded(result, command, args, |rendered, status, stderr| {
        IpsetError::CommandFailed {
            command: rendered,
            status,
            stderr,
        }
    })
}

fn best_effort_destroy_set(runner: &dyn IpsetCommandRunner, set_name: &str) {
    let args = ["destroy", set_name];
    match runner.run("ipset", &args) {
        Ok(result) if result.status.success() || is_missing_set_result(&result) => {}
        Ok(result) => warn!(
            "best-effort {} failed with status {:?}: {}",
            display_command("ipset", &args),
            result.status,
            stderr_detail(&result.stderr)
        ),
        Err(err) => warn!(
            "best-effort {} execution failed: {err}",
            display_command("ipset", &args)
        ),
    }
}

fn stderr_detail(stderr: &str) -> &str {
    let trimmed = stderr.trim();
    if trimmed.is_empty() {
        "no stderr"
    } else {
        trimmed
    }
}

fn execute_ipset_restore_with_entries<T: Ord + Display>(
    runner: &dyn IpsetCommandRunner,
    spec: &IpsetSetSpec,
    temp_set_name: &str,
    entries: &[T],
) -> Result<(), IpsetError> {
    let (file, path) = create_restore_script_file()?;
    let script = TempRestoreScript { path };
    let mut writer = BufWriter::new(file);
    write_restore_script(&mut writer, spec, temp_set_name, entries).map_err(|err| {
        IpsetError::WriteRestoreScript {
            path: script.path.clone(),
            reason: err.to_string(),
        }
    })?;
    writer
        .flush()
        .map_err(|err| IpsetError::WriteRestoreScript {
            path: script.path.clone(),
            reason: err.to_string(),
        })?;
    drop(writer);

    let path_string = script.path.display().to_string();
    let restore_result = run_checked(runner, "ipset", &["restore", "-file", &path_string]);

    restore_result.map(|_| ())
}

struct TempRestoreScript {
    path: PathBuf,
}

impl Drop for TempRestoreScript {
    fn drop(&mut self) {
        if let Err(err) = fs::remove_file(&self.path) {
            warn!(
                "failed to remove temporary ipset restore script {}: {err}",
                self.path.display()
            );
        }
    }
}

fn write_restore_script<T: Ord + Display>(
    writer: &mut impl Write,
    spec: &IpsetSetSpec,
    temp_set_name: &str,
    entries: &[T],
) -> Result<(), std::io::Error> {
    writeln!(
        writer,
        "create {} {} family {} hashsize {} maxelem {} timeout {}",
        temp_set_name,
        spec.set_type,
        spec.family.as_str(),
        spec.hashsize,
        spec.maxelem,
        spec.timeout
    )?;

    write_restore_entry_lines(writer, temp_set_name, entries)?;

    writeln!(writer, "swap {temp_set_name} {}", spec.set_name)
}

fn write_restore_entry_lines<T: Ord + Display>(
    writer: &mut impl Write,
    temp_set_name: &str,
    entries: &[T],
) -> Result<(), std::io::Error> {
    for entry in sorted_unique_entries(entries) {
        writeln!(writer, "add {temp_set_name} {entry}")?;
    }
    Ok(())
}

fn is_sorted_and_unique<T: Ord>(entries: &[T]) -> bool {
    entries.windows(2).all(|window| {
        window
            .first()
            .zip(window.get(1))
            .is_some_and(|(left, right)| left < right)
    })
}

fn sorted_unique_entries<T: Ord>(entries: &[T]) -> Vec<&T> {
    let mut sorted_entries = entries.iter().collect::<Vec<_>>();
    if !is_sorted_and_unique(entries) {
        sorted_entries.sort_unstable();
        sorted_entries.dedup();
    }
    sorted_entries
}

fn is_missing_set_result(result: &CommandResult) -> bool {
    result.status.code() == Some(1)
        && result
            .stderr
            .to_ascii_lowercase()
            .contains("does not exist")
}

fn is_unsupported_terse_option_result(result: &CommandResult) -> bool {
    let stderr = result.stderr.to_ascii_lowercase();
    stderr.contains("terse")
        && (stderr.contains("unknown")
            || stderr.contains("unrecognized")
            || stderr.contains("invalid")
            || stderr.contains("syntax"))
}

fn restore_script_path() -> PathBuf {
    env::temp_dir().join(format!("kidobo-ipset-{}.restore", random_hex_suffix(12)))
}

fn create_restore_script_file() -> Result<(std::fs::File, PathBuf), IpsetError> {
    for _ in 0..16 {
        let path = restore_script_path();
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        match options.open(&path) {
            Ok(file) => return Ok((file, path)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(err) => {
                return Err(IpsetError::CreateRestoreScript {
                    path,
                    reason: err.to_string(),
                });
            }
        }
    }

    let path = restore_script_path();
    Err(IpsetError::CreateRestoreScript {
        path,
        reason: "failed to create a unique temporary restore script path".to_string(),
    })
}

fn truncate_to_max_bytes(input: &str, max_bytes: usize) -> &str {
    if input.len() <= max_bytes {
        return input;
    }

    let mut idx = max_bytes;
    while idx > 0 && !input.is_char_boundary(idx) {
        idx -= 1;
    }
    &input[..idx]
}

fn random_hex_suffix(length: usize) -> String {
    let now_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0_u128, |value| value.as_nanos());

    let seed = format!("{}-{now_nanos}", process::id());
    let digest = Sha256::digest(seed.as_bytes());
    let mut hex = hex_lower(digest.as_ref());
    hex.truncate(length.min(hex.len()));
    hex
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::fs;

    use super::{
        IpsetCommandRunner, IpsetError, IpsetFamily, IpsetSetSpec, RESTORE_SCRIPT_READ_LIMIT,
        atomic_replace_ipset_values, ensure_ipset_exists, generate_temp_set_name,
        write_restore_script,
    };
    use crate::adapters::command_runner::{CommandResult, CommandRunnerError, ProcessStatus};
    use crate::adapters::limited_io::read_to_string_with_limit;

    struct MockRunner {
        responses: RefCell<VecDeque<Result<CommandResult, CommandRunnerError>>>,
        invocations: RefCell<Vec<(String, Vec<String>)>>,
        restore_scripts: RefCell<Vec<String>>,
    }

    impl MockRunner {
        fn new(responses: Vec<Result<CommandResult, CommandRunnerError>>) -> Self {
            Self {
                responses: RefCell::new(VecDeque::from(responses)),
                invocations: RefCell::new(Vec::new()),
                restore_scripts: RefCell::new(Vec::new()),
            }
        }

        fn invocations(&self) -> Vec<(String, Vec<String>)> {
            self.invocations.borrow().clone()
        }

        fn restore_scripts(&self) -> Vec<String> {
            self.restore_scripts.borrow().clone()
        }
    }

    impl IpsetCommandRunner for MockRunner {
        fn run(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
            self.invocations.borrow_mut().push((
                command.to_string(),
                args.iter().map(|value| (*value).to_string()).collect(),
            ));

            if command == "ipset" && args.first() == Some(&"restore") && args.len() == 3 {
                let script = read_to_string_with_limit(
                    std::path::Path::new(args[2]),
                    RESTORE_SCRIPT_READ_LIMIT,
                )
                .expect("restore script readable");
                self.restore_scripts.borrow_mut().push(script);
            }

            self.responses
                .borrow_mut()
                .pop_front()
                .expect("queued response")
        }
    }

    fn ok(status: i32) -> CommandResult {
        CommandResult {
            status: ProcessStatus::Exited(status),
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    fn test_spec(family: IpsetFamily) -> IpsetSetSpec {
        IpsetSetSpec {
            set_name: "kidobo".to_string(),
            set_type: "hash:net".to_string(),
            family,
            hashsize: 65_536,
            maxelem: 500_000,
            timeout: 0,
        }
    }

    #[test]
    fn temp_set_name_is_capped_at_31_chars() {
        let name = generate_temp_set_name("kidobo-super-long-name-that-must-be-truncated");
        assert!(name.len() <= 31);
        assert!(name.contains('-'));
    }

    #[test]
    fn temp_set_name_uses_eight_lower_hex_suffix_chars() {
        let name = generate_temp_set_name("kidobo");
        let suffix = name.rsplit('-').next().expect("suffix");

        assert_eq!(suffix.len(), 8);
        assert!(suffix.chars().all(|ch| matches!(ch, '0'..='9' | 'a'..='f')));
    }

    #[test]
    fn temp_set_name_falls_back_to_kidobo_for_empty_base() {
        let name = generate_temp_set_name("");

        assert!(name.starts_with("kidobo-"));
        assert!(name.len() <= 31);
    }

    #[test]
    fn temp_set_name_truncates_on_utf8_boundaries() {
        let name = generate_temp_set_name("kidobo-ääääääääääääääää");

        assert!(name.starts_with("kidobo-"));
        assert!(name.len() <= 31);
    }

    #[test]
    fn restore_script_is_deterministic_and_sorted() {
        let spec = IpsetSetSpec {
            set_name: "kidobo".to_string(),
            set_type: "hash:net".to_string(),
            family: IpsetFamily::Inet,
            hashsize: 65536,
            maxelem: 500000,
            timeout: 0,
        };

        let mut script = Vec::new();
        write_restore_script(
            &mut script,
            &spec,
            "kidobo-temp",
            &[
                "203.0.113.0/24".to_string(),
                "10.0.0.0/24".to_string(),
                "203.0.113.0/24".to_string(),
            ],
        )
        .expect("write restore script");
        let script = String::from_utf8(script).expect("restore script is utf8");

        assert_eq!(
            script,
            "create kidobo-temp hash:net family inet hashsize 65536 maxelem 500000 timeout 0\nadd kidobo-temp 10.0.0.0/24\nadd kidobo-temp 203.0.113.0/24\nswap kidobo-temp kidobo\n"
        );
    }

    #[test]
    fn ensure_existing_ipset_validates_type_and_family() {
        let runner = MockRunner::new(vec![Ok(CommandResult {
            status: ProcessStatus::Exited(0),
            stdout:
                "Name: kidobo\nType: hash:net\nHeader: family inet hashsize 1024 maxelem 500000\n"
                    .to_string(),
            stderr: String::new(),
        })]);

        ensure_ipset_exists(&runner, &test_spec(IpsetFamily::Inet)).expect("compatible set");
        assert_eq!(runner.invocations().len(), 1);
    }

    #[test]
    fn ensure_existing_ipset_falls_back_when_terse_is_unsupported() {
        let runner = MockRunner::new(vec![
            Ok(CommandResult {
                status: ProcessStatus::Exited(2),
                stdout: String::new(),
                stderr: "Unknown argument: -terse".to_string(),
            }),
            Ok(CommandResult {
                status: ProcessStatus::Exited(0),
                stdout: "Name: kidobo\nType: hash:net\nHeader: family inet hashsize 1024\n"
                    .to_string(),
                stderr: String::new(),
            }),
        ]);

        ensure_ipset_exists(&runner, &test_spec(IpsetFamily::Inet)).expect("compatible set");
        assert_eq!(runner.invocations().len(), 2);
    }

    #[test]
    fn ensure_existing_ipset_rejects_wrong_type_or_family() {
        for stdout in [
            "Name: kidobo\nType: hash:ip\nHeader: family inet hashsize 1024\n",
            "Name: kidobo\nType: hash:net\nHeader: family inet6 hashsize 1024\n",
        ] {
            let runner = MockRunner::new(vec![Ok(CommandResult {
                status: ProcessStatus::Exited(0),
                stdout: stdout.to_string(),
                stderr: String::new(),
            })]);

            let err = ensure_ipset_exists(&runner, &test_spec(IpsetFamily::Inet))
                .expect_err("incompatible set");
            assert!(matches!(err, IpsetError::IncompatibleSet { .. }));
            assert_eq!(runner.invocations().len(), 1);
        }
    }

    #[test]
    fn ensure_existing_ipset_rejects_malformed_inspection_output() {
        let runner = MockRunner::new(vec![Ok(CommandResult {
            status: ProcessStatus::Exited(0),
            stdout: "Name: kidobo\nHeader: hashsize 1024\n".to_string(),
            stderr: String::new(),
        })]);

        let err = ensure_ipset_exists(&runner, &test_spec(IpsetFamily::Inet))
            .expect_err("malformed inspection");
        assert!(matches!(err, IpsetError::MalformedInspection { .. }));
    }

    #[test]
    fn ensure_missing_ipset_creates_it() {
        let runner = MockRunner::new(vec![
            Ok(CommandResult {
                status: ProcessStatus::Exited(1),
                stdout: String::new(),
                stderr: "The set with the given name does not exist".to_string(),
            }),
            Ok(ok(0)),
        ]);

        ensure_ipset_exists(&runner, &test_spec(IpsetFamily::Inet)).expect("created");
        let invocations = runner.invocations();
        assert_eq!(invocations.len(), 2);
        assert_eq!(invocations[1].1[0], "create");
    }

    #[test]
    fn atomic_replace_runs_restore_swap_and_destroy_paths() {
        let runner = MockRunner::new(vec![
            Ok(CommandResult {
                status: ProcessStatus::Exited(1),
                stdout: String::new(),
                stderr: "The set with the given name does not exist".to_string(),
            }), // expected absent temporary set
            Ok(ok(0)), // restore
            Ok(ok(0)), // final destroy
        ]);

        let spec = IpsetSetSpec {
            set_name: "kidobo".to_string(),
            set_type: "hash:net".to_string(),
            family: IpsetFamily::Inet,
            hashsize: 65536,
            maxelem: 500000,
            timeout: 0,
        };

        atomic_replace_ipset_values(
            &runner,
            &spec,
            &["198.51.100.7/32".to_string(), "10.0.0.0/24".to_string()],
        )
        .expect("atomic replace");

        let invocations = runner.invocations();
        assert_eq!(invocations.len(), 3);
        assert_eq!(invocations[0].0, "ipset");
        assert_eq!(invocations[0].1[0], "destroy");
        assert_eq!(invocations[1].1[0], "restore");
        assert_eq!(invocations[1].1[1], "-file");
        assert_eq!(invocations[2].1[0], "destroy");
        assert!(
            invocations
                .iter()
                .all(|(_, args)| args.first().map(String::as_str) != Some("add")),
            "atomic replace must use ipset restore script, not incremental ipset add commands"
        );

        let scripts = runner.restore_scripts();
        assert_eq!(scripts.len(), 1);
        assert!(scripts[0].contains("create"));
        assert!(scripts[0].contains("swap"));
        assert!(scripts[0].contains("add"));
    }

    #[test]
    fn atomic_replace_attempts_final_destroy_after_restore_failure() {
        let runner = MockRunner::new(vec![
            Ok(ok(0)), // best-effort stale temp destroy
            Ok(CommandResult {
                status: ProcessStatus::Exited(1),
                stdout: String::new(),
                stderr: "restore failed".to_string(),
            }),
            Ok(ok(0)), // final destroy still attempted
        ]);

        let spec = IpsetSetSpec {
            set_name: "kidobo".to_string(),
            set_type: "hash:net".to_string(),
            family: IpsetFamily::Inet,
            hashsize: 65536,
            maxelem: 500000,
            timeout: 0,
        };

        let err = atomic_replace_ipset_values(&runner, &spec, &["10.0.0.0/24".to_string()])
            .expect_err("must fail");
        assert!(matches!(err, IpsetError::CommandFailed { .. }));

        let invocations = runner.invocations();
        assert_eq!(invocations.len(), 3);
        assert_eq!(invocations[2].1[0], "destroy");
    }

    #[test]
    fn create_restore_script_file_uses_restrictive_permissions() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let (file, path) = super::create_restore_script_file().expect("create temp script");
            drop(file);

            let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);

            fs::remove_file(path).expect("cleanup");
        }
    }
}
