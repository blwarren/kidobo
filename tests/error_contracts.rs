use std::error::Error;
use std::fs;
use std::io;

use kidobo_adapters::asn::load_cached_asn_prefixes;
use kidobo_adapters::config::load_config_from_file;
use kidobo_adapters::lock::FileLockManager;
use kidobo_adapters::lookup_sources::build_offline_lookup_registry;
use kidobo_adapters::target_file::LookupTargetFileReader;
use kidobo_app::AppError;
use kidobo_app::paths::ResolvedPaths;
use kidobo_app::ports::{LockManager, NoCancellation, TargetFileReader};
use kidobo_app::source::OfflineLookupContext;
use kidobo_core::blocklist::{
    BlocklistDocument, BlocklistTargetParseError, InvalidBlocklistLine, parse_blocklist_target,
};
use kidobo_core::lookup::{LookupTargetParseError, parse_target_strict};
use kidobo_core::network::CanonicalCidr;
use tempfile::TempDir;

fn io_cause<'a>(mut error: &'a (dyn Error + 'static)) -> &'a io::Error {
    loop {
        if let Some(source) = error.downcast_ref::<io::Error>() {
            return source;
        }
        error = error
            .source()
            .expect("filesystem error must retain its I/O cause");
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "keep the recording provisioner and complete path-resolution matrix in one contract test"
)]
fn init_uses_the_resolved_root_for_all_provisioning() {
    use std::cell::{Cell, RefCell};
    use std::path::{Path, PathBuf};

    use kidobo_adapters::path::{
        ENV_KIDOBO_DISABLE_TEST_SANDBOX, ENV_KIDOBO_ROOT, ENV_KIDOBO_TEST_SANDBOX,
        SystemPathResolver,
    };
    use kidobo_app::init::{self, InitDependencies, InitProvisioner, InitRequest, ProvisionState};
    use kidobo_app::paths::PathResolutionInput;

    #[derive(Default)]
    struct Provisioner {
        directories: RefCell<Vec<PathBuf>>,
        files: RefCell<Vec<(PathBuf, String)>>,
        activations: Cell<usize>,
    }
    impl InitProvisioner for Provisioner {
        fn resolve_installed_executable(&self, _: &[PathBuf]) -> Result<PathBuf, AppError> {
            Ok(PathBuf::from("/usr/local/bin/kidobo"))
        }
        fn ensure_dir(&self, path: &Path) -> Result<ProvisionState, AppError> {
            self.directories.borrow_mut().push(path.to_path_buf());
            Ok(ProvisionState::Created)
        }
        fn ensure_file(&self, path: &Path, contents: &str) -> Result<ProvisionState, AppError> {
            self.files
                .borrow_mut()
                .push((path.to_path_buf(), contents.to_string()));
            Ok(ProvisionState::Created)
        }
        fn enable_systemd_timer(&self) -> Result<(), AppError> {
            self.activations.set(self.activations.get() + 1);
            Ok(())
        }
    }

    for (explicit, sandbox, disabled) in [
        (false, false, false),
        (true, false, false),
        (false, true, false),
        (false, true, true),
        (true, true, false),
        (true, true, true),
    ] {
        let temp = TempDir::new().expect("tempdir");
        let explicit_root = temp.path().join("explicit");
        let mut env = std::collections::BTreeMap::new();
        if explicit {
            env.insert(ENV_KIDOBO_ROOT.into(), explicit_root.as_os_str().to_owned());
        }
        if sandbox {
            env.insert(ENV_KIDOBO_TEST_SANDBOX.into(), "true".into());
        }
        if disabled {
            env.insert(ENV_KIDOBO_DISABLE_TEST_SANDBOX.into(), "".into());
        }
        let expected_root = if explicit {
            Some(explicit_root.clone())
        } else if sandbox && !disabled {
            Some(temp.path().join("kidobo-tests"))
        } else {
            None
        };
        let directories = expected_root.as_ref().map_or_else(
            || {
                vec![
                    "/etc/kidobo".into(),
                    "/var/lib/kidobo".into(),
                    "/var/cache/kidobo/remote".into(),
                    "/etc/systemd/system".into(),
                ]
            },
            |root| {
                vec![
                    root.join("config"),
                    root.join("data"),
                    root.join("cache/remote"),
                    root.join("systemd/system"),
                ]
            },
        );
        let files = expected_root.as_ref().map_or_else(
            || {
                vec![
                    "/etc/kidobo/config.toml".into(),
                    "/var/lib/kidobo/blocklist.txt".into(),
                    "/var/cache/kidobo/sync.lock".into(),
                    "/var/lib/kidobo/temporary-bans.toml".into(),
                    "/etc/systemd/system/kidobo-sync.service".into(),
                    "/etc/systemd/system/kidobo-sync.timer".into(),
                ]
            },
            |root| {
                vec![
                    root.join("config/config.toml"),
                    root.join("data/blocklist.txt"),
                    root.join("cache/sync.lock"),
                    root.join("data/temporary-bans.toml"),
                    root.join("systemd/system/kidobo-sync.service"),
                    root.join("systemd/system/kidobo-sync.timer"),
                ]
            },
        );
        let provisioner = Provisioner::default();
        let outcome = init::execute(
            &InitRequest {
                paths: PathResolutionInput {
                    explicit_config_path: None,
                    temp_dir: temp.path().to_path_buf(),
                    env,
                },
                executable_candidates: vec![],
            },
            &InitDependencies {
                cancellation: &NoCancellation,
                paths: &SystemPathResolver,
                provisioner: &provisioner,
            },
        )
        .expect("record init");
        assert_eq!(
            *provisioner.directories.borrow(),
            directories,
            "{explicit}/{sandbox}/{disabled}"
        );
        let recorded = provisioner.files.borrow();
        assert_eq!(
            recorded
                .iter()
                .map(|(path, _)| path.clone())
                .collect::<Vec<_>>(),
            files
        );
        assert_eq!(
            provisioner.activations.get(),
            usize::from(expected_root.is_none())
        );
        assert_eq!(outcome.systemd_enabled, expected_root.is_none());
        let service = &recorded
            .iter()
            .find(|(path, _)| path.ends_with("kidobo-sync.service"))
            .expect("service")
            .1;
        if let Some(root) = expected_root {
            assert!(service.contains(&format!("Environment=\"KIDOBO_ROOT={}\"\n", root.display())));
        } else {
            assert!(!service.contains("KIDOBO_ROOT="));
        }
    }
}

#[cfg(unix)]
#[test]
fn atomic_writes_accept_relative_filenames() {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::Command;

    use kidobo_adapters::limited_io::{
        read_bytes_with_limit, read_to_string_with_limit, write_bytes_atomic, write_string_atomic,
    };

    const CHILD: &str = "KIDOBO_TEST_RELATIVE_ATOMIC_WRITE";
    if std::env::var_os(CHILD).is_none() {
        let temp = TempDir::new().expect("tempdir");
        let output = Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "atomic_writes_accept_relative_filenames",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .current_dir(temp.path())
            .output()
            .expect("run isolated relative-path test");
        assert!(output.status.success(), "{output:?}");
        return;
    }
    fs::create_dir("nested").expect("nested directory");
    for name in ["bare", "./explicit", "nested/file"] {
        let path = Path::new(name);
        write_bytes_atomic(path, b"created").expect("create relative file");
        assert_eq!(
            read_bytes_with_limit(path, 1024).expect("created file"),
            b"created"
        );
        fs::set_permissions(path, fs::Permissions::from_mode(0o640)).expect("set permissions");
        write_string_atomic(path, "replaced").expect("replace relative file");
        assert_eq!(
            read_to_string_with_limit(path, 1024).expect("replaced file"),
            "replaced"
        );
        assert_eq!(
            fs::metadata(path)
                .expect("permissions")
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
    }
    assert_eq!(fs::read_dir(".").expect("current directory").count(), 3);
    assert_eq!(fs::read_dir("nested").expect("nested directory").count(), 1);
}

#[test]
fn core_parse_errors_support_standard_error_propagation() {
    fn lookup(input: &str) -> Result<CanonicalCidr, Box<dyn Error>> {
        Ok(parse_target_strict(input)?)
    }
    fn blocklist(input: &str) -> Result<CanonicalCidr, Box<dyn Error>> {
        Ok(parse_blocklist_target(input)?)
    }
    fn document(input: &str) -> Result<BlocklistDocument, Box<dyn Error>> {
        Ok(BlocklistDocument::parse(input)?)
    }

    let empty = lookup("  ").expect_err("empty target");
    assert_eq!(
        empty.downcast_ref::<LookupTargetParseError>(),
        Some(&LookupTargetParseError::Empty)
    );
    assert_eq!(empty.to_string(), "lookup target is empty");
    let invalid = lookup("not-an-ip").expect_err("invalid target");
    assert_eq!(
        invalid.downcast_ref::<LookupTargetParseError>(),
        Some(&LookupTargetParseError::Invalid)
    );
    assert_ne!(empty.to_string(), invalid.to_string());
    let invalid = blocklist("not-an-ip").expect_err("invalid blocklist target");
    assert_eq!(
        invalid.downcast_ref::<BlocklistTargetParseError>(),
        Some(&BlocklistTargetParseError::Invalid)
    );
    let invalid = document("# header\nnot-an-ip\n").expect_err("invalid line");
    assert_eq!(
        invalid.downcast_ref::<InvalidBlocklistLine>(),
        Some(&InvalidBlocklistLine {
            line_number: 2,
            content: "not-an-ip".into()
        })
    );
    assert_eq!(
        invalid.to_string(),
        "invalid blocklist entry at line 2: not-an-ip"
    );
}

#[cfg(unix)]
#[test]
fn config_and_target_read_errors_keep_os_codes_and_path_context() {
    let temp = TempDir::new().expect("tempdir");
    let config = load_config_from_file(temp.path()).expect_err("directory is not a config file");
    assert!(matches!(&config, AppError::ConfigRead { path, .. } if path == temp.path()));
    let source = io_cause(&config);
    assert_eq!(source.kind(), io::ErrorKind::IsADirectory);
    assert!(source.raw_os_error().is_some());
    assert_eq!(
        config.to_string(),
        format!(
            "failed to read config file {}: {source}",
            temp.path().display()
        )
    );

    let target = LookupTargetFileReader
        .read_lines(temp.path())
        .expect_err("directory is not a target file");
    assert!(matches!(&target, AppError::LookupTargetFileRead { path, .. } if path == temp.path()));
    let source = io_cause(&target);
    assert_eq!(source.kind(), io::ErrorKind::IsADirectory);
    assert!(source.raw_os_error().is_some());
}

#[cfg(unix)]
#[test]
fn lock_errors_keep_nested_io_causes() {
    let temp = TempDir::new().expect("tempdir");
    let blocked = temp.path().join("blocked");
    fs::write(&blocked, b"not a directory").expect("block parent");
    let lock_path = blocked.join("nested/lock");
    let error = FileLockManager
        .acquire(&lock_path)
        .err()
        .expect("lock parent must fail");
    assert!(matches!(&error, AppError::Lock { .. }));
    assert_eq!(io_cause(&error).kind(), io::ErrorKind::NotADirectory);
    assert!(io_cause(&error).raw_os_error().is_some());
    assert!(
        error
            .to_string()
            .contains(&blocked.join("nested").display().to_string())
    );
}

#[cfg(unix)]
#[test]
fn offline_cache_errors_keep_io_causes_through_source_wrappers() {
    let temp = TempDir::new().expect("tempdir");
    let remote = temp.path().join("remote");
    fs::write(&remote, b"not a directory").expect("block remote directory");
    let enumeration = kidobo_adapters::source_files::collect_remote_cache_files(&remote)
        .expect_err("cache enumeration must retain its I/O source");
    assert_eq!(io_cause(&enumeration).kind(), io::ErrorKind::NotADirectory);
    assert!(io_cause(&enumeration).raw_os_error().is_some());
    let paths = ResolvedPaths {
        root_override: Some(temp.path().to_path_buf()),
        config_dir: temp.path().join("config"),
        config_file: temp.path().join("config/config.toml"),
        data_dir: temp.path().join("data"),
        blocklist_file: temp.path().join("data/blocklist.txt"),
        cache_dir: temp.path().join("cache"),
        remote_cache_dir: remote.clone(),
        lock_file: temp.path().join("lock"),
    };
    let error = build_offline_lookup_registry()
        .expect("registry")
        .load(&OfflineLookupContext {
            temporary_bans: &kidobo_core::temporary_bans::TemporaryBans::default(),
            cutoff: 100,
            paths: &paths,
            config: None,
            cancellation: &NoCancellation,
        })
        .expect_err("offline cache directory must fail");
    assert!(matches!(&error, AppError::LookupSourceLoad { .. }));
    assert_eq!(io_cause(&error).kind(), io::ErrorKind::NotADirectory);
    assert!(io_cause(&error).raw_os_error().is_some());
    assert!(error.to_string().contains(&remote.display().to_string()));

    let asn_cache = temp.path().join("asn");
    fs::create_dir_all(asn_cache.join("as64512.iplist")).expect("create invalid cache directory");
    let error = load_cached_asn_prefixes(64512, &asn_cache).expect_err("ASN cache must be a file");
    assert_eq!(io_cause(&error).kind(), io::ErrorKind::IsADirectory);
    assert!(io_cause(&error).raw_os_error().is_some());
}

#[cfg(unix)]
#[test]
fn blocklist_read_failures_are_not_missing_files() {
    use kidobo_adapters::blocklist_file::{
        load_blocklist_document, normalize_local_blocklist,
        normalize_local_blocklist_with_fast_state,
    };

    let temp = TempDir::new().expect("tempdir");
    let blocked = temp.path().join("blocked");
    fs::write(&blocked, "not a directory").expect("block parent");
    let path = blocked.join("blocklist.txt");
    let error = load_blocklist_document(&path).expect_err("failed read is not an empty list");
    assert_eq!(io_cause(&error).kind(), io::ErrorKind::NotADirectory);
    let error = normalize_local_blocklist(&path).expect_err("failed read is not absence");
    assert_eq!(io_cause(&error).kind(), io::ErrorKind::NotADirectory);
    let error = normalize_local_blocklist_with_fast_state(&path, &temp.path().join("state"))
        .expect_err("failed inspection is not absence");
    assert_eq!(io_cause(&error).kind(), io::ErrorKind::NotADirectory);
}

#[cfg(unix)]
#[test]
fn required_config_inspection_retains_its_io_cause() {
    use kidobo_adapters::path::{ENV_KIDOBO_ROOT, SystemPathResolver};
    use kidobo_app::paths::{ConfigRequirement, PathResolutionInput};
    use kidobo_app::ports::PathResolver;

    let temp = TempDir::new().expect("tempdir");
    let config_dir = temp.path().join("config");
    fs::write(&config_dir, "not a directory").expect("block config parent");
    let path = config_dir.join("config.toml");
    let error = load_config_from_file(&path).expect_err("failed read is not missing config");
    assert!(matches!(&error, AppError::ConfigRead { path: actual, .. } if actual == &path));
    assert_eq!(io_cause(&error).kind(), io::ErrorKind::NotADirectory);

    let input = PathResolutionInput {
        explicit_config_path: None,
        temp_dir: temp.path().to_path_buf(),
        env: [(ENV_KIDOBO_ROOT.into(), temp.path().as_os_str().to_owned())].into(),
    };
    let error = SystemPathResolver
        .resolve(&input, ConfigRequirement::Required)
        .expect_err("required config cannot be inspected");
    assert_eq!(io_cause(&error).kind(), io::ErrorKind::NotADirectory);
    let optional = SystemPathResolver
        .resolve(&input, ConfigRequirement::Optional)
        .expect("optional resolution does not inspect configuration");
    assert_eq!(optional.config_file, path);
}

#[cfg(unix)]
#[test]
fn cache_inspection_failures_are_not_missing_sources() {
    use kidobo_adapters::cached_sources::load_remote_sources;

    let temp = TempDir::new().expect("tempdir");
    let blocked = temp.path().join("blocked");
    fs::write(&blocked, "not a directory").expect("block parent");
    let error = load_cached_asn_prefixes(64512, &blocked.join("asn"))
        .expect_err("failed ASN inspection is not missing cache");
    assert_eq!(io_cause(&error).kind(), io::ErrorKind::NotADirectory);
    let error = load_remote_sources(&blocked.join("remote"))
        .expect_err("failed directory inspection is not missing cache");
    assert_eq!(io_cause(&error).kind(), io::ErrorKind::NotADirectory);
}

#[cfg(unix)]
#[test]
fn selected_cache_entry_inspection_failures_are_reported() {
    use kidobo_adapters::cached_sources::load_remote_sources;

    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().join("source.iplist");
    std::os::unix::fs::symlink("source.iplist", &path).expect("symlink loop");
    let expected = fs::metadata(&path)
        .expect_err("metadata loop")
        .raw_os_error();
    let error = load_remote_sources(temp.path()).expect_err("selected entry cannot be inspected");
    assert_eq!(io_cause(&error).raw_os_error(), expected);
    fs::remove_file(&path).expect("remove loop");

    let stores = temp.path().join("v2/remote");
    fs::create_dir_all(&stores).expect("create stores");
    let hash = "0123456789abcdef";
    std::os::unix::fs::symlink(hash, stores.join(hash)).expect("store symlink loop");
    let error = load_remote_sources(temp.path()).expect_err("selected store cannot be inspected");
    assert_eq!(io_cause(&error).raw_os_error(), expected);
}

#[cfg(unix)]
#[test]
fn atomic_writes_and_init_preserve_uninspectable_destinations() {
    use kidobo_adapters::command_runner::{CommandResult, CommandRunnerError};
    use kidobo_adapters::init::{FileInitProvisioner, InitCommandRunner};
    use kidobo_adapters::limited_io::write_string_atomic;
    use kidobo_app::init::InitProvisioner;

    struct NoCommands;
    impl InitCommandRunner for NoCommands {
        fn run(&self, _: &str, _: &[&str]) -> Result<CommandResult, CommandRunnerError> {
            panic!("filesystem provisioning must not execute commands");
        }
    }
    for initialize in [false, true] {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("destination");
        std::os::unix::fs::symlink("destination", &path).expect("symlink loop");
        let expected = fs::metadata(&path)
            .expect_err("metadata loop")
            .raw_os_error();
        if initialize {
            let error = FileInitProvisioner::new(NoCommands)
                .ensure_file(&path, "replacement")
                .expect_err("init must preserve uninspectable file");
            assert_eq!(io_cause(&error).raw_os_error(), expected);
        } else {
            let error = write_string_atomic(&path, "replacement")
                .expect_err("atomic write must preserve uninspectable file");
            assert_eq!(error.raw_os_error(), expected);
        }
        assert_eq!(
            fs::read_link(&path).expect("preserved symlink"),
            std::path::Path::new("destination")
        );
        assert_eq!(fs::read_dir(temp.path()).expect("read parent").count(), 1);
    }
}

#[cfg(unix)]
#[test]
fn doctor_cache_inspection_does_not_skip_errors() {
    use kidobo_adapters::doctor::SystemDoctorProbe;
    use kidobo_app::doctor::DoctorProbe;

    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().join("loop");
    std::os::unix::fs::symlink("loop", &path).expect("symlink loop");
    let expected = fs::metadata(&path)
        .expect_err("metadata loop")
        .raw_os_error();
    for cache in [&path, &path.join("nested/cache")] {
        let error = SystemDoctorProbe::default()
            .cache_readiness(cache)
            .expect_err("inspection errors must not imply a creatable cache");
        assert_eq!(io_cause(error.as_ref()).raw_os_error(), expected);
    }
}

#[cfg(unix)]
#[test]
fn local_lookup_and_append_report_unreadable_blocklists() {
    use kidobo_adapters::blocklist_file::FileBlocklistRepository;
    use kidobo_adapters::path::{ENV_KIDOBO_ROOT, SystemPathResolver};
    use kidobo_app::blocklist::BlocklistRepository;
    use kidobo_app::paths::{ConfigRequirement, PathResolutionInput};
    use kidobo_app::ports::PathResolver;

    let temp = TempDir::new().expect("tempdir");
    fs::create_dir(temp.path().join("data")).expect("create data");
    let blocklist = temp.path().join("data/blocklist.txt");
    std::os::unix::fs::symlink("blocklist.txt", &blocklist).expect("blocklist loop");
    let expected = fs::metadata(&blocklist)
        .expect_err("metadata loop")
        .raw_os_error();
    let error = FileBlocklistRepository
        .append_entries(&blocklist, &["192.0.2.1/32".into()], false, false)
        .expect_err("append must preserve unreadable blocklist");
    assert!(matches!(&error, AppError::BlocklistRead { .. }));
    assert_eq!(io_cause(&error).raw_os_error(), expected);

    let paths = SystemPathResolver
        .resolve(
            &PathResolutionInput {
                explicit_config_path: None,
                temp_dir: temp.path().to_path_buf(),
                env: [(ENV_KIDOBO_ROOT.into(), temp.path().as_os_str().to_owned())].into(),
            },
            ConfigRequirement::Optional,
        )
        .expect("optional paths");
    let error = build_offline_lookup_registry()
        .expect("registry")
        .load(&OfflineLookupContext {
            temporary_bans: &kidobo_core::temporary_bans::TemporaryBans::default(),
            cutoff: 100,
            paths: &paths,
            config: None,
            cancellation: &NoCancellation,
        })
        .expect_err("offline lookup must report failed blocklist read");
    assert!(matches!(&error, AppError::LookupSourceLoad { .. }));
    assert_eq!(io_cause(&error).raw_os_error(), expected);
    assert_eq!(
        fs::read_link(&blocklist).expect("preserved blocklist"),
        std::path::Path::new("blocklist.txt")
    );
}

#[cfg(unix)]
#[test]
fn asn_cache_deletion_handles_symlinks_and_reports_parent_errors() {
    use kidobo_adapters::asn::delete_asn_cache_file;

    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().join("as64512.iplist");
    std::os::unix::fs::symlink("as64512.iplist", &path).expect("cache loop");
    assert!(delete_asn_cache_file(64512, temp.path()).expect("delete symlink itself"));
    assert_eq!(
        fs::symlink_metadata(&path)
            .expect_err("symlink removed")
            .kind(),
        io::ErrorKind::NotFound
    );
    assert!(!delete_asn_cache_file(64512, temp.path()).expect("missing cache"));
    fs::write(&path, "not a directory").expect("block parent");
    let error = delete_asn_cache_file(64512, &path.join("nested"))
        .expect_err("failed removal is not missing cache");
    assert_eq!(io_cause(&error).kind(), io::ErrorKind::NotADirectory);
}

#[test]
fn command_and_firewall_errors_keep_nested_io_causes() {
    use kidobo_adapters::command_runner::{
        CommandExecutor, CommandRequest, CommandResult, CommandRunnerError, SystemCommandExecutor,
    };
    use kidobo_adapters::enforcement::CommandEnforcementBackend;
    use kidobo_adapters::ipset::IpsetCommandRunner;
    use kidobo_adapters::iptables::FirewallCommandRunner;
    use kidobo_app::sync::{EnforcementBackend, EnforcementPlan};

    struct MissingCommand(CommandRequest);
    impl IpsetCommandRunner for MissingCommand {
        fn run_os(
            &self,
            _: &str,
            _: &[&std::ffi::OsStr],
        ) -> Result<CommandResult, CommandRunnerError> {
            panic!("firewall activation must not execute ipset commands");
        }
    }
    impl FirewallCommandRunner for MissingCommand {
        fn run(&self, _: &str, _: &[&str]) -> Result<CommandResult, CommandRunnerError> {
            SystemCommandExecutor.execute(&self.0)
        }
    }
    let temp = TempDir::new().expect("tempdir");
    let request = CommandRequest {
        program: temp.path().join("missing-executable").into_os_string(),
        args: Vec::new(),
        timeout: std::time::Duration::from_secs(1),
    };
    let error = SystemCommandExecutor
        .execute(&request)
        .expect_err("missing program");
    assert_eq!(io_cause(&error).kind(), io::ErrorKind::NotFound);
    assert!(io_cause(&error).raw_os_error().is_some());
    assert_eq!(
        error.to_string(),
        format!(
            "failed to spawn command `{}`: {}",
            request.program.to_string_lossy(),
            io_cause(&error)
        )
    );

    let plan = EnforcementPlan::from_config(
        &kidobo_core::config::Config::from_toml_str(
            "[ipset]\nset_name='kidobo'\nenable_ipv6=false\n",
        )
        .expect("config"),
    );
    let error = CommandEnforcementBackend::new(MissingCommand(request))
        .activate(&plan)
        .expect_err("firewall command cannot start");
    assert!(matches!(&error, AppError::Firewall { .. }));
    assert_eq!(io_cause(&error).kind(), io::ErrorKind::NotFound);
    assert!(io_cause(&error).raw_os_error().is_some());
    assert!(error.to_string().starts_with(
        "firewall operation failed: firewall command execution failed: failed to spawn command"
    ));
}
