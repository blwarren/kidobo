use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathResolutionInput {
    pub explicit_config_path: Option<PathBuf>,
    pub temp_dir: PathBuf,
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPaths {
    pub config_dir: PathBuf,
    pub config_file: PathBuf,
    pub data_dir: PathBuf,
    pub blocklist_file: PathBuf,
    pub cache_dir: PathBuf,
    pub remote_cache_dir: PathBuf,
    pub lock_file: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigRequirement {
    Required,
    Optional,
}
