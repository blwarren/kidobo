//! ASN resolution and cache adapter.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use thiserror::Error;

use crate::command_runner::{
    CommandExecutor, CommandRequest, ProcessStatus, SystemCommandExecutor,
};
use crate::limited_io::{read_to_string_with_limit, write_string_atomic};
use kidobo_core::network::{CanonicalCidr, parse_ip_cidr_token};

const ASN_CACHE_FILE_READ_LIMIT: usize = 8 * 1024 * 1024;
const ASN_CACHE_FILE_WRITE_HEADER: &str = "# kidobo-asn-cache-v1";
const DEFAULT_BGPQ4_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AsnError {
    #[error("invalid ASN token `{input}`")]
    InvalidAsnToken { input: String },

    #[error("failed to resolve ASN {asn} prefixes via bgpq4: {reason}")]
    ResolveFailed { asn: u32, reason: String },

    #[error("ASN cache read failed at {path}: {reason}")]
    CacheRead { path: PathBuf, reason: String },

    #[error("ASN cache write failed at {path}: {reason}")]
    CacheWrite { path: PathBuf, reason: String },
}

pub trait AsnPrefixResolver {
    /// Resolves and canonicalizes IPv4 and IPv6 prefixes for one ASN.
    ///
    /// # Errors
    ///
    /// Returns [`AsnError::ResolveFailed`] when the resolver cannot execute successfully.
    fn resolve_prefixes(&self, asn: u32) -> Result<Vec<CanonicalCidr>, AsnError>;
}

#[derive(Debug, Clone, Copy)]
pub struct Bgpq4AsnPrefixResolver<E: CommandExecutor> {
    executor: E,
    timeout: Duration,
}

impl Bgpq4AsnPrefixResolver<SystemCommandExecutor> {
    #[must_use]
    pub fn with_default_timeout() -> Self {
        Self {
            executor: SystemCommandExecutor,
            timeout: DEFAULT_BGPQ4_TIMEOUT,
        }
    }
}

impl<E: CommandExecutor> Bgpq4AsnPrefixResolver<E> {
    #[cfg(test)]
    pub fn new(executor: E, timeout: Duration) -> Self {
        Self { executor, timeout }
    }

    fn run_bgpq4(&self, asn: u32, family_flag: &str) -> Result<Vec<CanonicalCidr>, AsnError> {
        let asn_token = format!("AS{asn}");
        let request = CommandRequest {
            program: "bgpq4".to_string(),
            args: vec![
                family_flag.to_string(),
                "-F".to_string(),
                "%n/%l\n".to_string(),
                asn_token,
            ],
            timeout: self.timeout,
        };

        let command = format!("{} {}", request.program, request.args.join(" "));
        let result = self
            .executor
            .execute(&request)
            .map_err(|err| AsnError::ResolveFailed {
                asn,
                reason: err.to_string(),
            })?;

        if result.status != ProcessStatus::Exited(0) {
            let stderr = result.stderr.trim();
            return Err(AsnError::ResolveFailed {
                asn,
                reason: if stderr.is_empty() {
                    format!("{command} exited with {:?}", result.status)
                } else {
                    format!("{command} failed: {stderr}")
                },
            });
        }

        Ok(parse_cidrs_from_bgpq4_output(&result.stdout))
    }
}

impl<E: CommandExecutor> AsnPrefixResolver for Bgpq4AsnPrefixResolver<E> {
    fn resolve_prefixes(&self, asn: u32) -> Result<Vec<CanonicalCidr>, AsnError> {
        let mut prefixes = self.run_bgpq4(asn, "-4")?;
        prefixes.extend(self.run_bgpq4(asn, "-6")?);
        prefixes.sort_unstable();
        prefixes.dedup();
        Ok(prefixes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedAsnPrefixes {
    pub prefixes: Vec<CanonicalCidr>,
    pub stale: bool,
}

/// Parses, sorts, and deduplicates ASN tokens.
///
/// # Errors
///
/// Returns [`AsnError::InvalidAsnToken`] for the first empty, malformed, or zero-valued token.
pub fn normalize_asn_tokens<I, S>(tokens: I) -> Result<Vec<u32>, AsnError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut normalized = Vec::new();
    for token in tokens {
        normalized.push(parse_asn_token(token.as_ref())?);
    }
    normalized.sort_unstable();
    normalized.dedup();
    Ok(normalized)
}

/// Parses a positive ASN with an optional case-insensitive `AS` prefix.
///
/// # Errors
///
/// Returns [`AsnError::InvalidAsnToken`] when the input is empty, malformed, zero, or outside the
/// `u32` range.
pub fn parse_asn_token(input: &str) -> Result<u32, AsnError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(AsnError::InvalidAsnToken {
            input: input.to_string(),
        });
    }

    let normalized = trimmed
        .strip_prefix("AS")
        .or_else(|| trimmed.strip_prefix("as"))
        .unwrap_or(trimmed);

    let asn = normalized
        .parse::<u32>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| AsnError::InvalidAsnToken {
            input: input.to_string(),
        })?;

    Ok(asn)
}

/// Loads fresh ASN prefixes or falls back to a stale bounded cache.
///
/// # Errors
///
/// Returns an error when the cache cannot be read, a fresh result cannot be resolved without a
/// fallback, or a successful resolution cannot be cached atomically.
pub fn load_asn_prefixes_with_cache(
    asn: u32,
    cache_dir: &Path,
    stale_after: Duration,
    resolver: &dyn AsnPrefixResolver,
) -> Result<CachedAsnPrefixes, AsnError> {
    let cache_file = asn_cache_file(cache_dir, asn);
    let cache_state = read_asn_cache_file(&cache_file)?;

    if cache_state
        .as_ref()
        .is_some_and(|state| !state_is_stale(state.modified, stale_after))
    {
        return Ok(CachedAsnPrefixes {
            prefixes: cache_state.map_or_else(Vec::new, |state| state.prefixes),
            stale: false,
        });
    }

    match resolver.resolve_prefixes(asn) {
        Ok(prefixes) => {
            write_asn_cache_file(&cache_file, &prefixes)?;
            Ok(CachedAsnPrefixes {
                prefixes,
                stale: false,
            })
        }
        Err(err) => {
            if let Some(stale) = cache_state {
                Ok(CachedAsnPrefixes {
                    prefixes: stale.prefixes,
                    stale: true,
                })
            } else {
                Err(err)
            }
        }
    }
}

/// Loads cached ASN prefixes without network or subprocess access.
///
/// # Errors
///
/// Returns [`AsnError::CacheRead`] when an existing cache cannot be inspected, read, or parsed.
pub fn load_cached_asn_prefixes(
    asn: u32,
    cache_dir: &Path,
) -> Result<Option<Vec<CanonicalCidr>>, AsnError> {
    let cache_file = asn_cache_file(cache_dir, asn);
    Ok(read_asn_cache_file(&cache_file)?.map(|state| state.prefixes))
}

/// Deletes one ASN cache file, reporting whether it existed.
///
/// # Errors
///
/// Returns [`AsnError::CacheWrite`] when an existing cache file cannot be removed.
pub fn delete_asn_cache_file(asn: u32, cache_dir: &Path) -> Result<bool, AsnError> {
    let path = asn_cache_file(cache_dir, asn);
    if !path.exists() {
        return Ok(false);
    }

    fs::remove_file(&path).map_err(|err| AsnError::CacheWrite {
        path: path.clone(),
        reason: err.to_string(),
    })?;
    Ok(true)
}

#[derive(Debug)]
struct AsnCacheState {
    modified: SystemTime,
    prefixes: Vec<CanonicalCidr>,
}

fn asn_cache_file(cache_dir: &Path, asn: u32) -> PathBuf {
    cache_dir.join(format!("as{asn}.iplist"))
}

fn state_is_stale(modified: SystemTime, stale_after: Duration) -> bool {
    SystemTime::now()
        .duration_since(modified)
        .map_or(true, |age| age >= stale_after)
}

fn read_asn_cache_file(path: &Path) -> Result<Option<AsnCacheState>, AsnError> {
    if !path.exists() {
        return Ok(None);
    }

    let metadata = fs::metadata(path).map_err(|err| AsnError::CacheRead {
        path: path.to_path_buf(),
        reason: err.to_string(),
    })?;
    let modified = metadata.modified().map_err(|err| AsnError::CacheRead {
        path: path.to_path_buf(),
        reason: err.to_string(),
    })?;
    let contents = read_to_string_with_limit(path, ASN_CACHE_FILE_READ_LIMIT).map_err(|err| {
        AsnError::CacheRead {
            path: path.to_path_buf(),
            reason: err.to_string(),
        }
    })?;

    let Some(prefixes) = parse_cidrs_from_cache_contents(&contents) else {
        return Ok(None);
    };

    Ok(Some(AsnCacheState { modified, prefixes }))
}

fn write_asn_cache_file(path: &Path, prefixes: &[CanonicalCidr]) -> Result<(), AsnError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| AsnError::CacheWrite {
            path: parent.to_path_buf(),
            reason: err.to_string(),
        })?;
    }

    let mut output = String::new();
    output.push_str(ASN_CACHE_FILE_WRITE_HEADER);
    output.push('\n');
    for prefix in prefixes {
        output.push_str(&prefix.to_string());
        output.push('\n');
    }

    write_string_atomic(path, &output).map_err(|err| AsnError::CacheWrite {
        path: path.to_path_buf(),
        reason: err.to_string(),
    })
}

fn parse_cidrs_from_bgpq4_output(contents: &str) -> Vec<CanonicalCidr> {
    contents
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                None
            } else {
                parse_ip_cidr_token(trimmed)
            }
        })
        .collect()
}

fn parse_cidrs_from_cache_contents(contents: &str) -> Option<Vec<CanonicalCidr>> {
    let mut prefixes = Vec::new();

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let cidr = parse_ip_cidr_token(trimmed)?;
        prefixes.push(cidr);
    }

    prefixes.sort_unstable();
    prefixes.dedup();
    Some(prefixes)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::sync::Mutex;
    use std::time::Duration;

    use tempfile::TempDir;

    use super::{
        ASN_CACHE_FILE_READ_LIMIT, AsnError, AsnPrefixResolver, Bgpq4AsnPrefixResolver,
        CachedAsnPrefixes, delete_asn_cache_file, load_asn_prefixes_with_cache,
        normalize_asn_tokens, parse_asn_token,
    };
    use crate::command_runner::{
        CommandExecutor, CommandRequest, CommandResult, CommandRunnerError, ProcessStatus,
    };
    use crate::limited_io::read_to_string_with_limit;
    use kidobo_core::network::{CanonicalCidr, Ipv4Cidr};

    struct MockResolver {
        responses: VecDeque<Result<Vec<CanonicalCidr>, AsnError>>,
    }

    impl MockResolver {
        fn new(responses: Vec<Result<Vec<CanonicalCidr>, AsnError>>) -> Self {
            Self {
                responses: VecDeque::from(responses),
            }
        }
    }

    impl AsnPrefixResolver for Mutex<MockResolver> {
        fn resolve_prefixes(&self, _asn: u32) -> Result<Vec<CanonicalCidr>, AsnError> {
            self.lock()
                .expect("lock")
                .responses
                .pop_front()
                .expect("response")
        }
    }

    struct MockCommandExecutor {
        requests: Mutex<Vec<CommandRequest>>,
        responses: Mutex<VecDeque<Result<CommandResult, CommandRunnerError>>>,
    }

    impl MockCommandExecutor {
        fn new(responses: Vec<Result<CommandResult, CommandRunnerError>>) -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                responses: Mutex::new(VecDeque::from(responses)),
            }
        }

        fn requests(&self) -> Vec<CommandRequest> {
            self.requests.lock().expect("lock").clone()
        }
    }

    impl CommandExecutor for &MockCommandExecutor {
        fn execute(&self, request: &CommandRequest) -> Result<CommandResult, CommandRunnerError> {
            self.requests.lock().expect("lock").push(request.clone());
            self.responses
                .lock()
                .expect("lock")
                .pop_front()
                .expect("response")
        }
    }

    #[test]
    fn parse_asn_token_accepts_bare_and_as_prefixed() {
        assert_eq!(parse_asn_token("213412").expect("parse"), 213_412);
        assert_eq!(parse_asn_token("AS213412").expect("parse"), 213_412);
        assert_eq!(parse_asn_token("as213412").expect("parse"), 213_412);
    }

    #[test]
    fn normalize_asn_tokens_dedupes_and_sorts() {
        let values = normalize_asn_tokens(["AS64513", "64512", "64513"]).expect("normalize");
        assert_eq!(values, vec![64512, 64513]);
    }

    #[test]
    fn parse_asn_token_rejects_invalid_values() {
        let err = parse_asn_token("AS0").expect_err("must fail");
        assert!(matches!(err, AsnError::InvalidAsnToken { .. }));
    }

    #[test]
    fn parse_asn_token_rejects_blank_input() {
        let err = parse_asn_token("   ").expect_err("must fail");
        assert_eq!(
            err,
            AsnError::InvalidAsnToken {
                input: "   ".to_string()
            }
        );
    }

    #[test]
    fn bgpq4_resolver_executes_both_families_and_dedupes_prefixes() {
        let executor = MockCommandExecutor::new(vec![
            Ok(CommandResult {
                status: ProcessStatus::Exited(0),
                stdout: "203.0.113.0/24\n198.51.100.0/24\n".to_string(),
                stderr: String::new(),
            }),
            Ok(CommandResult {
                status: ProcessStatus::Exited(0),
                stdout: "2001:db8::/64\n198.51.100.0/24\n".to_string(),
                stderr: String::new(),
            }),
        ]);
        let resolver = Bgpq4AsnPrefixResolver::new(&executor, Duration::from_secs(5));

        let prefixes = resolver.resolve_prefixes(64512).expect("resolve");
        let rendered = prefixes
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>();
        assert_eq!(
            rendered,
            vec!["198.51.100.0/24", "203.0.113.0/24", "2001:db8::/64"]
        );

        let requests = executor.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].program, "bgpq4");
        assert_eq!(requests[0].args, vec!["-4", "-F", "%n/%l\n", "AS64512"]);
        assert_eq!(requests[1].args, vec!["-6", "-F", "%n/%l\n", "AS64512"]);
    }

    #[test]
    fn bgpq4_resolver_reports_nonzero_exit_with_stderr() {
        let executor = MockCommandExecutor::new(vec![Ok(CommandResult {
            status: ProcessStatus::Exited(1),
            stdout: String::new(),
            stderr: "no route object".to_string(),
        })]);
        let resolver = Bgpq4AsnPrefixResolver::new(&executor, Duration::from_secs(5));

        let err = resolver.resolve_prefixes(64512).expect_err("must fail");
        match err {
            AsnError::ResolveFailed { asn, reason } => {
                assert_eq!(asn, 64512);
                assert!(reason.contains("bgpq4 -4 -F"));
                assert!(reason.contains("failed: no route object"));
            }
            _ => panic!("unexpected error variant"),
        }
    }

    #[test]
    fn bgpq4_resolver_reports_nonzero_exit_without_stderr() {
        let executor = MockCommandExecutor::new(vec![Ok(CommandResult {
            status: ProcessStatus::Exited(2),
            stdout: String::new(),
            stderr: "   ".to_string(),
        })]);
        let resolver = Bgpq4AsnPrefixResolver::new(&executor, Duration::from_secs(5));

        let err = resolver.resolve_prefixes(64512).expect_err("must fail");
        match err {
            AsnError::ResolveFailed { asn, reason } => {
                assert_eq!(asn, 64512);
                assert!(reason.contains("exited with Exited(2)"));
            }
            _ => panic!("unexpected error variant"),
        }
    }

    #[test]
    fn bgpq4_resolver_propagates_second_family_failure_after_ipv4_success() {
        let executor = MockCommandExecutor::new(vec![
            Ok(CommandResult {
                status: ProcessStatus::Exited(0),
                stdout: "203.0.113.0/24\n".to_string(),
                stderr: String::new(),
            }),
            Ok(CommandResult {
                status: ProcessStatus::Exited(1),
                stdout: String::new(),
                stderr: "ipv6 failed".to_string(),
            }),
        ]);
        let resolver = Bgpq4AsnPrefixResolver::new(&executor, Duration::from_secs(5));

        let err = resolver.resolve_prefixes(64512).expect_err("must fail");
        match err {
            AsnError::ResolveFailed { asn, reason } => {
                assert_eq!(asn, 64512);
                assert!(reason.contains("bgpq4 -6 -F"));
                assert!(reason.contains("ipv6 failed"));
            }
            _ => panic!("unexpected error variant"),
        }

        let requests = executor.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].args[0], "-4");
        assert_eq!(requests[1].args[0], "-6");
    }

    #[test]
    fn cache_load_uses_fresh_cache_without_resolve() {
        let temp = TempDir::new().expect("tempdir");
        let cache_dir = temp.path();
        fs::write(cache_dir.join("as64512.iplist"), "203.0.113.0/24\n").expect("write");
        let resolver = Mutex::new(MockResolver::new(vec![]));

        let loaded =
            load_asn_prefixes_with_cache(64512, cache_dir, Duration::from_hours(24), &resolver)
                .expect("load");

        assert_eq!(
            loaded,
            CachedAsnPrefixes {
                prefixes: vec![CanonicalCidr::V4(Ipv4Cidr::from_parts(0xcb00_7100, 24))],
                stale: false
            }
        );
    }

    #[test]
    fn cache_load_parses_fresh_cache_with_comments_duplicates_and_unsorted_entries() {
        let temp = TempDir::new().expect("tempdir");
        let cache_dir = temp.path();
        fs::write(
            cache_dir.join("as64512.iplist"),
            "# kidobo-asn-cache-v1\n2001:db8::/64\n203.0.113.0/24\n# comment\n203.0.113.0/24\n",
        )
        .expect("write cache");
        let resolver = Mutex::new(MockResolver::new(vec![]));

        let loaded =
            load_asn_prefixes_with_cache(64512, cache_dir, Duration::from_hours(24), &resolver)
                .expect("load");

        assert_eq!(
            loaded
                .prefixes
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["203.0.113.0/24", "2001:db8::/64"]
        );
        assert!(!loaded.stale);
    }

    #[test]
    fn invalid_cache_line_triggers_refresh() {
        let temp = TempDir::new().expect("tempdir");
        let cache_dir = temp.path();
        fs::write(
            cache_dir.join("as64512.iplist"),
            "# kidobo-asn-cache-v1\n2001:db8::/64\ninvalid\n",
        )
        .expect("write cache");
        let resolver = Mutex::new(MockResolver::new(vec![Ok(vec![CanonicalCidr::V4(
            Ipv4Cidr::from_parts(0xc633_6400, 24),
        )])]));

        let loaded =
            load_asn_prefixes_with_cache(64512, cache_dir, Duration::from_hours(24), &resolver)
                .expect("load");

        assert_eq!(
            loaded,
            CachedAsnPrefixes {
                prefixes: vec![CanonicalCidr::V4(Ipv4Cidr::from_parts(0xc633_6400, 24))],
                stale: false
            }
        );
    }

    #[test]
    fn invalid_cache_line_does_not_fallback_when_refresh_fails() {
        let temp = TempDir::new().expect("tempdir");
        let cache_dir = temp.path();
        fs::write(
            cache_dir.join("as64512.iplist"),
            "# kidobo-asn-cache-v1\n203.0.113.0/24\ninvalid\n",
        )
        .expect("write cache");
        let resolver = Mutex::new(MockResolver::new(vec![Err(AsnError::ResolveFailed {
            asn: 64512,
            reason: "boom".to_string(),
        })]));

        let err = load_asn_prefixes_with_cache(64512, cache_dir, Duration::from_secs(0), &resolver)
            .expect_err("invalid cache must not be reused");
        assert_eq!(
            err,
            AsnError::ResolveFailed {
                asn: 64512,
                reason: "boom".to_string()
            }
        );
    }

    #[test]
    fn stale_cache_fallback_parses_valid_prefixes_only() {
        let temp = TempDir::new().expect("tempdir");
        let cache_dir = temp.path();
        fs::write(
            cache_dir.join("as64512.iplist"),
            "# kidobo-asn-cache-v1\n2001:db8::/64\n203.0.113.0/24\n2001:db8::/64\n",
        )
        .expect("write cache");
        let resolver = Mutex::new(MockResolver::new(vec![Err(AsnError::ResolveFailed {
            asn: 64512,
            reason: "boom".to_string(),
        })]));

        let loaded =
            load_asn_prefixes_with_cache(64512, cache_dir, Duration::from_secs(0), &resolver)
                .expect("load");

        assert!(loaded.stale);
        assert_eq!(
            loaded
                .prefixes
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["203.0.113.0/24", "2001:db8::/64"]
        );
    }

    #[test]
    fn cache_load_falls_back_to_stale_when_refresh_fails() {
        let temp = TempDir::new().expect("tempdir");
        let cache_dir = temp.path();
        fs::write(cache_dir.join("as64512.iplist"), "203.0.113.0/24\n").expect("write");
        let resolver = Mutex::new(MockResolver::new(vec![Err(AsnError::ResolveFailed {
            asn: 64512,
            reason: "boom".to_string(),
        })]));

        let loaded =
            load_asn_prefixes_with_cache(64512, cache_dir, Duration::from_secs(0), &resolver)
                .expect("load");
        assert!(loaded.stale);
        assert_eq!(loaded.prefixes.len(), 1);
    }

    #[test]
    fn cache_load_refreshes_and_persists_when_cache_is_missing() {
        let temp = TempDir::new().expect("tempdir");
        let cache_dir = temp.path();
        let resolver = Mutex::new(MockResolver::new(vec![Ok(vec![
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0xcb00_7100, 24)),
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0xc633_6400, 24)),
        ])]));

        let first =
            load_asn_prefixes_with_cache(64512, cache_dir, Duration::from_hours(24), &resolver)
                .expect("initial load");
        assert!(!first.stale);
        assert_eq!(first.prefixes.len(), 2);

        let cache_file = cache_dir.join("as64512.iplist");
        let cache_contents =
            read_to_string_with_limit(&cache_file, ASN_CACHE_FILE_READ_LIMIT).expect("read cache");
        assert!(cache_contents.starts_with("# kidobo-asn-cache-v1\n"));
        assert!(cache_contents.contains("203.0.113.0/24\n"));
        assert!(cache_contents.contains("198.51.100.0/24\n"));

        let second =
            load_asn_prefixes_with_cache(64512, cache_dir, Duration::from_hours(24), &resolver)
                .expect("cached load");
        assert!(!second.stale);
        assert_eq!(
            second
                .prefixes
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["198.51.100.0/24", "203.0.113.0/24"]
        );
    }

    #[test]
    fn cache_load_without_cache_propagates_refresh_error() {
        let temp = TempDir::new().expect("tempdir");
        let resolver = Mutex::new(MockResolver::new(vec![Err(AsnError::ResolveFailed {
            asn: 64512,
            reason: "boom".to_string(),
        })]));

        let err =
            load_asn_prefixes_with_cache(64512, temp.path(), Duration::from_secs(1), &resolver)
                .expect_err("must fail");
        assert_eq!(
            err,
            AsnError::ResolveFailed {
                asn: 64512,
                reason: "boom".to_string()
            }
        );
    }

    #[test]
    fn cache_file_delete_is_best_effort_for_missing_files() {
        let temp = TempDir::new().expect("tempdir");
        assert!(!delete_asn_cache_file(64512, temp.path()).expect("delete"));
        fs::write(temp.path().join("as64512.iplist"), "203.0.113.0/24\n").expect("write");
        assert!(delete_asn_cache_file(64512, temp.path()).expect("delete"));
    }
}
