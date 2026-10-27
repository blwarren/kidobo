//! Reviewed configuration edits and read-only effective configuration views.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};

use kidobo_core::config::{Config, DEFAULT_GITHUB_META_CATEGORIES, FirewallAction};
use kidobo_core::sync::compute_effective_blocklists;

use crate::AppError;
use crate::init::DEFAULT_CONFIG_TEMPLATE;
use crate::paths::{ConfigRequirement, PathResolutionInput, ResolvedPaths};
use crate::ports::{Cancellation, LockManager, PathResolver};

/// A bounded configuration document and metadata from the same read.
#[derive(Clone)]
pub struct ConfigurationDocument {
    /// Original UTF-8 bytes, retained exactly for revision revalidation.
    pub contents: String,
    /// Known field paths explicitly present in this document.
    pub explicit_fields: BTreeSet<String>,
    /// Accepted legacy value which is deliberately absent from the runtime model.
    pub legacy_remote_stale_after_secs: Option<u64>,
}

impl fmt::Debug for ConfigurationDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigurationDocument")
            .field("bytes", &self.contents.len())
            .field("explicit_field_count", &self.explicit_fields.len())
            .finish_non_exhaustive()
    }
}

/// Reads exact bounded documents without mutating configuration or runtime state.
pub trait ConfigurationReader {
    /// Returns `None` only when the configuration filename is absent.
    ///
    /// # Errors
    ///
    /// Returns bounded I/O, UTF-8, or document parsing failures.
    fn read(&self, path: &Path) -> Result<Option<ConfigurationDocument>, AppError>;
}

/// Pure formatting-preserving edits of one configuration document.
pub trait ConfigurationEditor {
    /// Produces a bounded candidate while preserving unrelated text and URL spelling.
    ///
    /// # Errors
    ///
    /// Returns invalid or duplicate input, malformed structure, or serialized size failures.
    fn render(&self, original: &str, edit: &ConfigurationEdit) -> Result<String, AppError>;
}

/// Atomic publication mode selected from the reviewed document revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigurationWriteMode {
    /// Replace the existing, revalidated configuration atomically.
    ReplaceExisting,
    /// Publish a new file atomically and fail if another file has appeared.
    CreateNew,
}

/// Bounded atomic configuration publication; callers hold the Kidobo process lock.
pub trait ConfigurationWriter {
    /// Publishes the complete validated candidate in the requested mode.
    ///
    /// # Errors
    ///
    /// Returns size, atomic publication, permission, or durability failures.
    fn write(
        &self,
        path: &Path,
        contents: &str,
        mode: ConfigurationWriteMode,
    ) -> Result<(), AppError>;
}

/// Named edits authorized by the configuration-management CLI.
#[derive(Clone)]
pub enum ConfigurationEdit {
    /// Add one HTTP(S) source, rejecting a normalized duplicate.
    AddSource(String),
    /// Remove the configured source matching the normalized URL identity.
    RemoveSource(String),
    /// Add one exact canonical operator-controlled exemption identity.
    AddAllow(String),
    /// Remove one exact canonical exemption identity, without range carving.
    RemoveAllow(String),
    /// Reviewed basic settings collected by the setup assistant.
    SetBasic {
        /// Whether subsequent syncs should enforce IPv6.
        enable_ipv6: bool,
        /// Whether subsequent syncs include the existing GitHub metadata safelist.
        include_github_meta: bool,
        /// Requested source URLs; retained URLs keep their stored spelling.
        remote_urls: Vec<String>,
        /// Requested operator exemption identities.
        safe_ips: Vec<String>,
    },
}

impl fmt::Debug for ConfigurationEdit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AddSource(_) => "AddSource(<redacted>)",
            Self::RemoveSource(_) => "RemoveSource(<redacted>)",
            Self::AddAllow(_) => "AddAllow(<redacted>)",
            Self::RemoveAllow(_) => "RemoveAllow(<redacted>)",
            Self::SetBasic { .. } => "SetBasic(<redacted>)",
        })
    }
}

/// One source/safelist edit or reviewed setup settings.
pub struct ConfigurationRequest {
    /// Existing native path-resolution inputs.
    pub paths: PathResolutionInput,
    /// Requested change to saved configuration.
    pub edit: ConfigurationEdit,
    /// Setup alone may preview a virtual starter when the file is absent.
    pub allow_missing: bool,
}

/// Read-only capabilities used to display effective configuration.
pub struct ReadDependencies<'a> {
    /// Cooperative cancellation around bounded reads.
    pub cancellation: &'a dyn Cancellation,
    /// Existing runtime path policy.
    pub paths: &'a dyn PathResolver,
    /// Exact bounded configuration reads.
    pub reader: &'a dyn ConfigurationReader,
}

/// Capabilities used before prompting; there is no lock or write capability.
pub struct PreviewDependencies<'a> {
    /// Cooperative cancellation around preview preparation.
    pub cancellation: &'a dyn Cancellation,
    /// Existing path-resolution policy.
    pub paths: &'a dyn PathResolver,
    /// Exact bounded configuration reads.
    pub reader: &'a dyn ConfigurationReader,
    /// Pure formatting-preserving candidate generation.
    pub editor: &'a dyn ConfigurationEditor,
}

/// Capabilities used only after the operator has reviewed a proposed change.
pub struct ApplyDependencies<'a> {
    /// Cooperative cancellation before starting the atomic write.
    pub cancellation: &'a dyn Cancellation,
    /// Existing exclusive process lock.
    pub locks: &'a dyn LockManager,
    /// Exact revalidation of the reviewed revision.
    pub reader: &'a dyn ConfigurationReader,
    /// Bounded atomic configuration publisher.
    pub writer: &'a dyn ConfigurationWriter,
}

/// Explicit approval of a reviewed exemption expansion.
#[derive(Debug, Clone, Copy)]
pub struct ConfigurationDecision {
    /// True only after affirmative interactive confirmation or explicit `--yes`.
    pub approve_exemption: bool,
}

/// Opaque reviewed candidate; neither its revision nor persistence contents can be altered.
pub struct ConfigurationPreview {
    paths: ResolvedPaths,
    original: Option<String>,
    candidate: String,
    before: Config,
    after: Config,
    changed_fields: Vec<&'static str>,
    expands_exemption: bool,
}

impl fmt::Debug for ConfigurationPreview {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigurationPreview")
            .field("path", &self.paths.config_file)
            .field("creates_file", &self.creates_file())
            .field("changed_fields", &self.changed_fields)
            .field("expands_exemption", &self.expands_exemption)
            .finish_non_exhaustive()
    }
}

impl ConfigurationPreview {
    #[must_use]
    /// Saved or virtual starter configuration used to calculate the change.
    pub fn before(&self) -> &Config {
        &self.before
    }

    #[must_use]
    /// Complete validated effective configuration proposed for persistence.
    pub fn after(&self) -> &Config {
        &self.after
    }

    #[must_use]
    /// Whether persistence would create or change the configuration file.
    pub fn changed(&self) -> bool {
        self.original.as_ref() != Some(&self.candidate)
    }

    #[must_use]
    /// Whether the candidate exempts any address not covered by saved operator exemptions.
    pub fn expands_exemption(&self) -> bool {
        self.expands_exemption
    }

    #[must_use]
    /// Whether the reviewed revision had no configuration file.
    pub fn creates_file(&self) -> bool {
        self.original.is_none()
    }

    #[must_use]
    /// Saved settings whose effective values change.
    pub fn changed_fields(&self) -> &[&'static str] {
        &self.changed_fields
    }

    #[must_use]
    /// Paths bound to the reviewed document, including its process lock.
    pub fn paths(&self) -> &ResolvedPaths {
        &self.paths
    }
}

/// Exact saved-state outcome; configuration edits never apply firewall enforcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigurationOutcome {
    /// A complete configuration file was saved.
    pub changed: bool,
    /// The file was created rather than replaced.
    pub created: bool,
    /// Effective settings changed by this request.
    pub changed_fields: Vec<&'static str>,
}

/// Origin of one effective value in the displayed configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingOrigin {
    /// The field exists in the current file.
    Explicit,
    /// The value comes from the documented default or virtual starter.
    Default,
    /// The value is derived from another effective setting.
    Derived,
}

/// Typed values let root renderers redact URL strings before composing human output.
#[derive(Clone, PartialEq, Eq)]
pub enum SettingValue {
    /// Text, potentially containing sensitive URL components.
    Text(String),
    /// Boolean configuration value.
    Boolean(bool),
    /// Positive or zero numeric configuration value.
    Number(u64),
    /// Text array, potentially containing sensitive source URLs.
    Strings(Vec<String>),
    /// Configured ASN numbers.
    Numbers(Vec<u32>),
    /// No active value exists for an omitted legacy compatibility setting.
    NotSet,
}

impl fmt::Debug for SettingValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Text(_) => "Text(<redacted>)",
            Self::Boolean(_) => "Boolean(..)",
            Self::Number(_) => "Number(..)",
            Self::Strings(_) => "Strings(<redacted>)",
            Self::Numbers(_) => "Numbers(..)",
            Self::NotSet => "NotSet",
        })
    }
}

/// One effective, attributed configuration setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigSetting {
    /// Existing documented TOML field path.
    pub key: &'static str,
    /// Effective value; root rendering applies secret redaction.
    pub value: SettingValue,
    /// Explicit, default, or derived origin.
    pub origin: SettingOrigin,
    /// Semantic explanation for special defaults or ignored compatibility values.
    pub note: Option<&'static str>,
}

/// Read-only effective configuration and source attribution.
pub struct ConfigurationView {
    /// Exact resolved runtime paths.
    pub paths: ResolvedPaths,
    /// False only for an explicitly requested setup virtual starter.
    pub exists: bool,
    /// Validated effective values, used by the setup assistant's defaults.
    pub config: Config,
    /// Every supported setting, including the ignored legacy value.
    pub settings: Vec<ConfigSetting>,
}

impl fmt::Debug for ConfigurationView {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigurationView")
            .field("path", &self.paths.config_file)
            .field("exists", &self.exists)
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

/// Availability of selected compatible cached data; it does not establish feed freshness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheAvailability {
    /// Compatible selected cached contents were successfully read and validated.
    Available,
    /// No usable compatible cache could be selected.
    Unavailable,
    /// A bounded inspection could not determine cache availability.
    Unknown,
}

/// Read-only cached-source evidence without invented refresh timestamps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceCacheStatus {
    /// Whether usable cached contents were selected.
    pub availability: CacheAvailability,
    /// Generation or compatible legacy provenance, when known.
    pub provenance: Option<String>,
    /// Evidence or limitation of this observation.
    pub detail: String,
}

/// Inspects the cache of one configured URL without fetching, staging, or cleanup.
pub trait SourceCacheInspector {
    /// Returns bounded cache evidence for this exact stored URL/cache identity.
    fn inspect(&self, cache_dir: &Path, url: &str, maxelem: u32) -> SourceCacheStatus;
}

/// One configured feed and separately labeled compatible-cache evidence.
#[derive(Clone)]
pub struct ConfiguredSource {
    /// Exact configured URL spelling; root display redacts credentials and sensitive values.
    pub url: String,
    /// Read-only cache availability and provenance.
    pub cache: SourceCacheStatus,
    /// No trustworthy refresh timestamp exists in current metadata; remains absent.
    pub freshness: Option<String>,
}

impl fmt::Debug for ConfiguredSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfiguredSource")
            .field("url", &"<redacted>")
            .field("availability", &self.cache.availability)
            .finish_non_exhaustive()
    }
}

/// Read-only capabilities required to list configured sources and their cache evidence.
pub struct SourceListDependencies<'a> {
    /// Cooperative cancellation between configured URLs.
    pub cancellation: &'a dyn Cancellation,
    /// Existing path-resolution policy.
    pub paths: &'a dyn PathResolver,
    /// Exact bounded configuration reads.
    pub reader: &'a dyn ConfigurationReader,
    /// Per-URL cache inspection without HTTP or filesystem mutation.
    pub cache_inspector: &'a dyn SourceCacheInspector,
}

/// Resolves the configuration filename even before initialization.
///
/// # Errors
///
/// Returns invalid path/environment resolution failures.
pub fn config_path(
    request: &PathResolutionInput,
    paths: &dyn PathResolver,
) -> Result<PathBuf, AppError> {
    Ok(paths
        .resolve(request, ConfigRequirement::Optional)?
        .config_file)
}

/// Reads effective configuration without a write capability.
///
/// # Errors
///
/// Returns missing files unless setup explicitly requests a virtual starter, invalid configuration,
/// bounded I/O failures, path failures, or cancellation.
pub fn read(
    request: &PathResolutionInput,
    allow_missing: bool,
    dependencies: &ReadDependencies<'_>,
) -> Result<ConfigurationView, AppError> {
    dependencies.cancellation.check()?;
    let paths = dependencies
        .paths
        .resolve(request, ConfigRequirement::Optional)?;
    let original = dependencies.reader.read(&paths.config_file)?;
    let exists = original.is_some();
    let document = document_or_starter(original, allow_missing, &paths.config_file)?;
    let config = Config::from_toml_str(&document.contents)?;
    let settings = effective_settings(&config, &document);
    dependencies.cancellation.check()?;
    Ok(ConfigurationView {
        paths,
        exists,
        config,
        settings,
    })
}

/// Prepares and validates a complete candidate without locking or writing state.
///
/// # Errors
///
/// Returns invalid edits/configuration, duplicate source additions, size/read failures, or cancellation.
pub fn prepare(
    request: &ConfigurationRequest,
    dependencies: &PreviewDependencies<'_>,
) -> Result<ConfigurationPreview, AppError> {
    dependencies.cancellation.check()?;
    let paths = dependencies
        .paths
        .resolve(&request.paths, ConfigRequirement::Optional)?;
    let original = dependencies.reader.read(&paths.config_file)?;
    let revision = original.as_ref().map(|document| document.contents.clone());
    let document = document_or_starter(original, request.allow_missing, &paths.config_file)?;
    let before = Config::from_toml_str(&document.contents)?;
    let candidate = dependencies
        .editor
        .render(&document.contents, &request.edit)?;
    let after = Config::from_toml_str(&candidate)?;
    let changed_fields = changed_fields(&before, &after);
    let additional = compute_effective_blocklists(&after.safe.ips, &before.safe.ips, true);
    let expands_exemption = !additional.ipv4.is_empty() || !additional.ipv6.is_empty();
    dependencies.cancellation.check()?;
    Ok(ConfigurationPreview {
        paths,
        original: revision,
        candidate,
        before,
        after,
        changed_fields,
        expands_exemption,
    })
}

/// Applies exactly the reviewed candidate after consent and revision revalidation under the lock.
///
/// # Errors
///
/// Returns unapproved exemption expansion before locking, changed revisions, invalid candidates,
/// lock/write failures, or cancellation. No firewall or cache-promotion capability is available.
pub fn apply(
    preview: &ConfigurationPreview,
    decision: &ConfigurationDecision,
    dependencies: &ApplyDependencies<'_>,
) -> Result<ConfigurationOutcome, AppError> {
    dependencies.cancellation.check()?;
    if preview.expands_exemption && !decision.approve_exemption {
        return Err(AppError::ConfirmationRequired);
    }
    if !preview.changed() {
        return Ok(ConfigurationOutcome {
            changed: false,
            created: false,
            changed_fields: Vec::new(),
        });
    }
    let _lock = dependencies.locks.acquire(&preview.paths.lock_file)?;
    dependencies.cancellation.check()?;
    let current = dependencies.reader.read(&preview.paths.config_file)?;
    if current.as_ref().map(|document| &document.contents) != preview.original.as_ref() {
        return Err(AppError::ConfigurationChanged);
    }
    Config::from_toml_str(&preview.candidate)?;
    dependencies.cancellation.check()?;
    let mode = if preview.creates_file() {
        ConfigurationWriteMode::CreateNew
    } else {
        ConfigurationWriteMode::ReplaceExisting
    };
    dependencies
        .writer
        .write(&preview.paths.config_file, &preview.candidate, mode)?;
    Ok(ConfigurationOutcome {
        changed: true,
        created: preview.creates_file(),
        changed_fields: preview.changed_fields.clone(),
    })
}

/// Lists configured sources and read-only compatible-cache evidence without HTTP fetching.
///
/// # Errors
///
/// Returns invalid/missing configuration, path/read failures, or cancellation.
pub fn sources(
    request: &PathResolutionInput,
    dependencies: &SourceListDependencies<'_>,
) -> Result<Vec<ConfiguredSource>, AppError> {
    let view = read(
        request,
        false,
        &ReadDependencies {
            cancellation: dependencies.cancellation,
            paths: dependencies.paths,
            reader: dependencies.reader,
        },
    )?;
    let mut sources = Vec::with_capacity(view.config.remote.urls.len());
    for url in view.config.remote.urls {
        dependencies.cancellation.check()?;
        let cache = dependencies.cache_inspector.inspect(
            &view.paths.remote_cache_dir,
            &url,
            view.config.ipset.maxelem.get(),
        );
        sources.push(ConfiguredSource {
            url,
            cache,
            freshness: None,
        });
    }
    dependencies.cancellation.check()?;
    Ok(sources)
}

/// Lists only saved operator-controlled exemption identities.
///
/// # Errors
///
/// Returns the same bounded read and validation failures as [`read`].
pub fn allow_list(
    request: &PathResolutionInput,
    dependencies: &ReadDependencies<'_>,
) -> Result<Vec<String>, AppError> {
    let view = read(request, false, dependencies)?;
    Ok(view
        .config
        .safe
        .ips
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

fn document_or_starter(
    document: Option<ConfigurationDocument>,
    allow_missing: bool,
    path: &Path,
) -> Result<ConfigurationDocument, AppError> {
    match document {
        Some(document) => Ok(document),
        None if allow_missing => Ok(ConfigurationDocument {
            contents: DEFAULT_CONFIG_TEMPLATE.to_string(),
            explicit_fields: BTreeSet::new(),
            legacy_remote_stale_after_secs: None,
        }),
        None => Err(AppError::MissingConfigFile {
            path: path.to_path_buf(),
        }),
    }
}

fn changed_fields(before: &Config, after: &Config) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if before.ipset.enable_ipv6 != after.ipset.enable_ipv6 {
        fields.push("ipset.enable_ipv6");
    }
    if before.safe.include_github_meta != after.safe.include_github_meta {
        fields.push("safe.include_github_meta");
    }
    if before.remote.urls != after.remote.urls {
        fields.push("remote.urls");
    }
    if before.safe.ips != after.safe.ips {
        fields.push("safe.ips");
    }
    fields
}

#[expect(
    clippy::too_many_lines,
    reason = "keep the complete documented settings and attribution table together"
)]
fn effective_settings(config: &Config, document: &ConfigurationDocument) -> Vec<ConfigSetting> {
    let entries = vec![
        (
            "ipset.set_name",
            SettingValue::Text(config.ipset.set_name.clone()),
        ),
        (
            "ipset.set_name_v6",
            SettingValue::Text(config.ipset.set_name_v6.clone()),
        ),
        (
            "ipset.enable_ipv6",
            SettingValue::Boolean(config.ipset.enable_ipv6),
        ),
        (
            "ipset.chain_action",
            SettingValue::Text(
                match config.ipset.chain_action {
                    FirewallAction::Drop => "DROP",
                    FirewallAction::Reject => "REJECT",
                }
                .to_string(),
            ),
        ),
        (
            "ipset.set_type",
            SettingValue::Text(config.ipset.set_type.clone()),
        ),
        (
            "ipset.hashsize",
            SettingValue::Number(u64::from(config.ipset.hashsize.get())),
        ),
        (
            "ipset.maxelem",
            SettingValue::Number(u64::from(config.ipset.maxelem.get())),
        ),
        (
            "ipset.timeout",
            SettingValue::Number(u64::from(config.ipset.timeout)),
        ),
        (
            "safe.ips",
            SettingValue::Strings(config.safe.ips.iter().map(ToString::to_string).collect()),
        ),
        (
            "safe.include_github_meta",
            SettingValue::Boolean(config.safe.include_github_meta),
        ),
        (
            "safe.github_meta_url",
            SettingValue::Text(config.safe.github_meta_url.clone()),
        ),
        (
            "safe.github_meta_categories",
            SettingValue::Strings(config.safe.github_meta_categories.clone().unwrap_or_else(
                || {
                    DEFAULT_GITHUB_META_CATEGORIES
                        .iter()
                        .map(ToString::to_string)
                        .collect()
                },
            )),
        ),
        (
            "remote.urls",
            SettingValue::Strings(config.remote.urls.clone()),
        ),
        (
            "remote.timeout_secs",
            SettingValue::Number(u64::from(config.remote.timeout_secs.get())),
        ),
        (
            "remote.cache_stale_after_secs",
            document
                .legacy_remote_stale_after_secs
                .map_or(SettingValue::NotSet, SettingValue::Number),
        ),
        (
            "asn.banned",
            SettingValue::Numbers(config.asn.banned.clone()),
        ),
        (
            "asn.cache_stale_after_secs",
            SettingValue::Number(u64::from(config.asn.cache_stale_after_secs.get())),
        ),
    ];
    entries
        .into_iter()
        .map(|(key, value)| ConfigSetting {
            key,
            value,
            origin: if document.explicit_fields.contains(key) {
                SettingOrigin::Explicit
            } else if key == "ipset.set_name_v6" {
                SettingOrigin::Derived
            } else {
                SettingOrigin::Default
            },
            note: match key {
                "remote.cache_stale_after_secs" => {
                    Some("Compatibility only; this value does not control refresh")
                }
                "safe.github_meta_categories"
                    if config
                        .safe
                        .github_meta_categories
                        .as_ref()
                        .is_some_and(Vec::is_empty) =>
                {
                    Some("An empty category list selects all categories")
                }
                _ => None,
            },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;
    use crate::ports::{LockGuard, NoCancellation};

    type Events = Rc<RefCell<Vec<&'static str>>>;

    struct Paths;
    impl PathResolver for Paths {
        fn resolve(
            &self,
            _: &PathResolutionInput,
            requirement: ConfigRequirement,
        ) -> Result<ResolvedPaths, AppError> {
            assert_eq!(requirement, ConfigRequirement::Optional);
            let root = PathBuf::from("/configuration-fixture");
            Ok(ResolvedPaths {
                root_override: Some(root.clone()),
                config_dir: root.join("config"),
                config_file: root.join("config/config.toml"),
                data_dir: root.join("data"),
                blocklist_file: root.join("data/blocklist.txt"),
                cache_dir: root.join("cache"),
                remote_cache_dir: root.join("cache/remote"),
                lock_file: root.join("cache/lock"),
            })
        }
    }

    struct Documents {
        contents: RefCell<Option<String>>,
        events: Events,
        fail_write: bool,
        writes: RefCell<Vec<ConfigurationWriteMode>>,
    }

    impl Documents {
        fn new(contents: Option<&str>) -> Self {
            Self {
                contents: RefCell::new(contents.map(ToString::to_string)),
                events: Events::default(),
                fail_write: false,
                writes: RefCell::new(Vec::new()),
            }
        }
    }

    impl ConfigurationReader for Documents {
        fn read(&self, _: &Path) -> Result<Option<ConfigurationDocument>, AppError> {
            self.events.borrow_mut().push("read");
            Ok(self
                .contents
                .borrow()
                .as_ref()
                .map(|contents| ConfigurationDocument {
                    contents: contents.clone(),
                    explicit_fields: BTreeSet::new(),
                    legacy_remote_stale_after_secs: None,
                }))
        }
    }

    impl ConfigurationWriter for Documents {
        fn write(
            &self,
            path: &Path,
            contents: &str,
            mode: ConfigurationWriteMode,
        ) -> Result<(), AppError> {
            self.events.borrow_mut().push("write");
            if self.fail_write {
                return Err(AppError::ConfigWrite {
                    path: path.to_path_buf(),
                    source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
                });
            }
            self.writes.borrow_mut().push(mode);
            *self.contents.borrow_mut() = Some(contents.to_string());
            Ok(())
        }
    }

    struct Editor<'a> {
        candidate: &'a str,
        events: Events,
    }
    impl ConfigurationEditor for Editor<'_> {
        fn render(&self, _: &str, _: &ConfigurationEdit) -> Result<String, AppError> {
            self.events.borrow_mut().push("render");
            Ok(self.candidate.to_string())
        }
    }

    struct Locks(Events);
    struct Guard(Events);
    impl LockGuard for Guard {}
    impl Drop for Guard {
        fn drop(&mut self) {
            self.0.borrow_mut().push("unlock");
        }
    }
    impl LockManager for Locks {
        fn acquire(&self, _: &Path) -> Result<Box<dyn LockGuard>, AppError> {
            self.0.borrow_mut().push("lock");
            Ok(Box::new(Guard(Rc::clone(&self.0))))
        }
    }

    fn input() -> PathResolutionInput {
        PathResolutionInput {
            explicit_config_path: None,
            temp_dir: PathBuf::from("/tmp"),
            env: BTreeMapForTest::new(),
        }
    }
    type BTreeMapForTest = std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString>;

    fn preview(
        documents: &Documents,
        candidate: &str,
        allow_missing: bool,
    ) -> ConfigurationPreview {
        prepare(
            &ConfigurationRequest {
                paths: input(),
                edit: ConfigurationEdit::AddAllow("203.0.113.7".to_string()),
                allow_missing,
            },
            &PreviewDependencies {
                cancellation: &NoCancellation,
                paths: &Paths,
                reader: documents,
                editor: &Editor {
                    candidate,
                    events: Rc::clone(&documents.events),
                },
            },
        )
        .expect("preview")
    }

    fn save(
        documents: &Documents,
        preview: &ConfigurationPreview,
        approve: bool,
    ) -> Result<ConfigurationOutcome, AppError> {
        apply(
            preview,
            &ConfigurationDecision {
                approve_exemption: approve,
            },
            &ApplyDependencies {
                cancellation: &NoCancellation,
                locks: &Locks(Rc::clone(&documents.events)),
                reader: documents,
                writer: documents,
            },
        )
    }

    #[test]
    fn exemption_expansion_requires_approval_before_any_lock_or_write() {
        let original = "[ipset]\nset_name='kidobo'\n";
        let candidate = "[ipset]\nset_name='kidobo'\n[safe]\nips=['0.0.0.0/0']\n";
        let documents = Documents::new(Some(original));
        let preview = preview(&documents, candidate, false);
        assert!(preview.expands_exemption());
        assert_eq!(*documents.events.borrow(), ["read", "render"]);
        documents.events.borrow_mut().clear();
        assert!(matches!(
            save(&documents, &preview, false),
            Err(AppError::ConfirmationRequired)
        ));
        assert_eq!(*documents.events.borrow(), Vec::<&str>::new());
        assert_eq!(documents.contents.borrow().as_deref(), Some(original));
        let outcome = save(&documents, &preview, true).expect("approved save");
        assert!(outcome.changed);
        assert_eq!(
            *documents.events.borrow(),
            ["lock", "read", "write", "unlock"]
        );
        assert_eq!(documents.contents.borrow().as_deref(), Some(candidate));
    }

    #[test]
    fn covered_ranges_do_not_expand_exemptions_but_new_ranges_in_either_family_do() {
        let original = "[ipset]\nset_name='kidobo'\nenable_ipv6=false\n[safe]\nips=['10.0.0.0/8','2001:db8::/32']\n";
        for (additional, expands) in [
            ("10.1.0.0/16", false),
            ("11.0.0.0/8", true),
            ("2001:db9::/32", true),
        ] {
            let candidate = format!(
                "[ipset]\nset_name='kidobo'\nenable_ipv6=false\n[safe]\nips=['10.0.0.0/8','2001:db8::/32','{additional}']\n"
            );
            let documents = Documents::new(Some(original));
            let preview = preview(&documents, &candidate, false);
            assert_eq!(preview.expands_exemption(), expands);
            if !expands {
                save(&documents, &preview, false).expect("covered addition");
            }
        }
    }

    #[test]
    fn changed_revision_is_rejected_even_when_only_a_comment_changed() {
        let original = "[ipset]\nset_name='kidobo'\n";
        let documents = Documents::new(Some(original));
        let preview = preview(
            &documents,
            "[ipset]\nset_name='kidobo'\nenable_ipv6=false\n",
            false,
        );
        *documents.contents.borrow_mut() = Some(format!("# another operator's edit\n{original}"));
        documents.events.borrow_mut().clear();
        assert!(matches!(
            save(&documents, &preview, true),
            Err(AppError::ConfigurationChanged)
        ));
        assert_eq!(*documents.events.borrow(), ["lock", "read", "unlock"]);
        assert_eq!(
            *documents.writes.borrow(),
            Vec::<ConfigurationWriteMode>::new()
        );
    }

    #[test]
    fn unchanged_candidate_does_not_lock_or_rewrite_and_write_errors_preserve_causes() {
        let original = "[ipset]\nset_name='kidobo'\n";
        let mut documents = Documents::new(Some(original));
        let unchanged = preview(&documents, original, false);
        documents.events.borrow_mut().clear();
        assert!(
            !save(&documents, &unchanged, false)
                .expect("unchanged")
                .changed
        );
        assert_eq!(*documents.events.borrow(), Vec::<&str>::new());
        let changed = preview(
            &documents,
            "[ipset]\nset_name='kidobo'\nenable_ipv6=false\n",
            false,
        );
        documents.fail_write = true;
        documents.events.borrow_mut().clear();
        let error = save(&documents, &changed, false).expect_err("write fails");
        match error {
            AppError::ConfigWrite { source, .. } => {
                assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
            }
            other => panic!("unexpected error: {other}"),
        }
        assert_eq!(
            *documents.events.borrow(),
            ["lock", "read", "write", "unlock"]
        );
        assert_eq!(documents.contents.borrow().as_deref(), Some(original));
    }

    #[test]
    fn setup_virtual_starter_is_never_saved_without_review_and_uses_create_new_publication() {
        let documents = Documents::new(None);
        let deps = ReadDependencies {
            cancellation: &NoCancellation,
            paths: &Paths,
            reader: &documents,
        };
        assert!(matches!(
            read(&input(), false, &deps),
            Err(AppError::MissingConfigFile { .. })
        ));
        let view = read(&input(), true, &deps).expect("virtual starter");
        assert!(!view.exists);
        assert!(view.config.safe.include_github_meta);
        assert_eq!(documents.contents.borrow().as_deref(), None);
        let preview = preview(&documents, DEFAULT_CONFIG_TEMPLATE, true);
        assert!(preview.creates_file());
        assert!(preview.changed());
        save(&documents, &preview, false).expect("create reviewed starter");
        assert_eq!(
            *documents.writes.borrow(),
            [ConfigurationWriteMode::CreateNew]
        );
    }

    #[test]
    fn whole_candidate_validation_rejects_unknown_fields_before_any_write_capability() {
        let documents = Documents::new(Some("[ipset]\nset_name='kidobo'\n"));
        let result = prepare(
            &ConfigurationRequest {
                paths: input(),
                edit: ConfigurationEdit::AddSource("https://feed.test".to_string()),
                allow_missing: false,
            },
            &PreviewDependencies {
                cancellation: &NoCancellation,
                paths: &Paths,
                reader: &documents,
                editor: &Editor {
                    candidate: "[ipset]\nset_name='kidobo'\nunknown=true\n",
                    events: Rc::clone(&documents.events),
                },
            },
        );
        assert!(matches!(result, Err(AppError::ConfigParse { .. })));
        assert_eq!(*documents.events.borrow(), ["read", "render"]);
    }

    #[test]
    fn setup_rejects_a_configuration_created_after_the_missing_file_preview() {
        let documents = Documents::new(None);
        let preview = preview(&documents, DEFAULT_CONFIG_TEMPLATE, true);
        let appeared = "[ipset]\nset_name='another-operator'\n";
        *documents.contents.borrow_mut() = Some(appeared.to_string());
        documents.events.borrow_mut().clear();
        assert!(matches!(
            save(&documents, &preview, false),
            Err(AppError::ConfigurationChanged)
        ));
        assert_eq!(*documents.events.borrow(), ["lock", "read", "unlock"]);
        assert_eq!(documents.contents.borrow().as_deref(), Some(appeared));
        assert_eq!(
            *documents.writes.borrow(),
            Vec::<ConfigurationWriteMode>::new()
        );
    }

    #[test]
    fn debug_views_do_not_expose_source_credentials_or_tokens() {
        let original = "[ipset]\nset_name='kidobo'\n[remote]\nurls=['https://fixture-user:fixture-password@feed.test/list?token=fixture-token']\n";
        let documents = Documents::new(Some(original));
        let preview = preview(&documents, original, false);
        let document = documents
            .read(Path::new("fixture"))
            .expect("read")
            .expect("document");
        let text = format!(
            "{preview:?} {document:?} {:?}",
            ConfigurationEdit::AddSource(original.to_string())
        );
        for secret in ["fixture-user", "fixture-password", "fixture-token"] {
            assert!(!text.contains(secret));
        }
    }
}
