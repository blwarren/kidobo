//! Production ASN operations used by blocklist application use cases.

use std::path::Path;
use std::time::Duration;

use kidobo_app::AppError;
use kidobo_app::blocklist::{
    AsnCacheRemover, AsnConfigEditor, AsnConfigUpdate, AsnPrefixBatch, AsnPrefixLoader,
};

use crate::asn::{Bgpq4AsnPrefixResolver, delete_asn_cache_file, load_asn_prefixes_with_cache};
use crate::config_edit::update_asn_bans;

/// Production ASN operations backed by `bgpq4`, cache files, and atomic config edits.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemAsnOperations;

impl AsnPrefixLoader for SystemAsnOperations {
    fn load_prefixes(
        &self,
        asn: u32,
        cache_dir: &Path,
        stale_after: Duration,
    ) -> Result<AsnPrefixBatch, AppError> {
        let resolver = Bgpq4AsnPrefixResolver::with_default_timeout();
        let loaded = load_asn_prefixes_with_cache(asn, cache_dir, stale_after, &resolver)
            .map_err(map_asn_error)?;
        Ok(AsnPrefixBatch {
            prefixes: loaded.prefixes,
            stale: loaded.stale,
        })
    }
}

impl AsnConfigEditor for SystemAsnOperations {
    fn update_config(
        &self,
        config_path: &Path,
        add: &[u32],
        remove: &[u32],
    ) -> Result<AsnConfigUpdate, AppError> {
        let update = update_asn_bans(config_path, add, remove)?;
        Ok(AsnConfigUpdate {
            added: update.added,
            removed: update.removed,
        })
    }
}

impl AsnCacheRemover for SystemAsnOperations {
    fn delete_cache(&self, asn: u32, cache_dir: &Path) -> Result<bool, AppError> {
        delete_asn_cache_file(asn, cache_dir).map_err(map_asn_error)
    }
}

fn map_asn_error(error: crate::asn::AsnError) -> AppError {
    AppError::Asn {
        source: Box::new(error),
    }
}
