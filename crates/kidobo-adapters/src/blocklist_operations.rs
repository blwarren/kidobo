//! Production ASN operations used by blocklist application use cases.

use std::path::Path;
use std::time::Duration;

use kidobo_app::AppError;
use kidobo_app::blocklist::{AsnConfigUpdate, AsnOperations, AsnPrefixBatch};

use crate::asn::{
    Bgpq4AsnPrefixResolver, delete_asn_cache_file, load_asn_prefixes_with_cache,
    normalize_asn_tokens,
};
use crate::config_edit::update_asn_bans;

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemAsnOperations;

impl AsnOperations for SystemAsnOperations {
    fn normalize_tokens(&self, tokens: &[String]) -> Result<Vec<u32>, AppError> {
        normalize_asn_tokens(tokens).map_err(|error| map_asn_error(&error))
    }

    fn load_prefixes(
        &self,
        asn: u32,
        cache_dir: &Path,
        stale_after: Duration,
    ) -> Result<AsnPrefixBatch, AppError> {
        let resolver = Bgpq4AsnPrefixResolver::with_default_timeout();
        let loaded = load_asn_prefixes_with_cache(asn, cache_dir, stale_after, &resolver)
            .map_err(|error| map_asn_error(&error))?;
        Ok(AsnPrefixBatch {
            prefixes: loaded.prefixes,
            stale: loaded.stale,
        })
    }

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

    fn delete_cache(&self, asn: u32, cache_dir: &Path) -> Result<bool, AppError> {
        delete_asn_cache_file(asn, cache_dir).map_err(|error| map_asn_error(&error))
    }
}

fn map_asn_error(error: &crate::asn::AsnError) -> AppError {
    AppError::Asn {
        reason: error.to_string(),
    }
}
