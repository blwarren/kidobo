use std::error::Error;
use std::fs;
use std::io;

use kidobo_adapters::asn::load_cached_asn_prefixes;
use kidobo_adapters::cached_fetch::write_json_pretty_atomic;
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
fn lock_and_cache_write_errors_keep_nested_io_causes() {
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

    let path = blocked.join("nested/meta.json");
    let error = write_json_pretty_atomic(&path, &vec![1]).expect_err("cache parent must fail");
    assert_eq!(io_cause(&error).kind(), io::ErrorKind::NotADirectory);
    assert!(io_cause(&error).raw_os_error().is_some());
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
