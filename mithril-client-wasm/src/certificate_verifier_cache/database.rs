use anyhow::anyhow;
use js_sys::{Array, Reflect};
use wasm_bindgen::prelude::Closure;
use wasm_bindgen::{JsCast, JsValue};
use web_sys::{
    IdbDatabase, IdbFactory, IdbObjectStore, IdbObjectStoreParameters, IdbTransaction,
    IdbTransactionMode, IdbVersionChangeEvent,
};

use mithril_client::MithrilResult;

use super::error::JsErrorContext;
use super::promise::IdbRequestExt;

const DATABASE_VERSION: u32 = 1;
pub(super) const COMMITTED_CERTIFICATES_STORE: &str = "committed_certificates";
pub(super) const STAGED_CERTIFICATES_STORE: &str = "staged_certificates";
pub(super) const STAGED_BATCHES_STORE: &str = "staged_batches";
pub(super) const ALL_STORES: [&str; 3] = [
    COMMITTED_CERTIFICATES_STORE,
    STAGED_CERTIFICATES_STORE,
    STAGED_BATCHES_STORE,
];
pub(super) const EXPIRE_AT_INDEX: &str = "expire_at";

/// A connection to the cache database, closed when dropped
pub(super) struct DatabaseConnection {
    /// The open database
    database: IdbDatabase,
}

impl DatabaseConnection {
    /// Open the database with the given name, upgrading its schema on first use
    pub(super) async fn open(database_name: &str) -> MithrilResult<Self> {
        let open_request = Self::factory()?
            .open_with_u32(database_name, DATABASE_VERSION)
            .js_context("Failed to open the certificate cache database")?;
        let upgraded_request = open_request.clone();
        let on_upgrade_needed = Closure::once(move |event: IdbVersionChangeEvent| {
            let upgraded = upgraded_request
                .result()
                .and_then(|database| database.dyn_into::<IdbDatabase>())
                .and_then(|database| Self::upgrade(&database, event.old_version()));
            if upgraded.is_err()
                && let Some(transaction) = upgraded_request.transaction()
            {
                let _ = transaction.abort();
            }
        });
        open_request.set_onupgradeneeded(Some(on_upgrade_needed.as_ref().unchecked_ref()));

        let database = open_request
            .settled()
            .await
            .js_context("Failed to open the certificate cache database")?
            .dyn_into::<IdbDatabase>()
            .map_err(|value| anyhow!("Unexpected certificate cache database handle: {value:?}"))?;

        Ok(Self { database })
    }

    /// The IndexedDB factory of the JS global scope, a window or a worker
    pub(super) fn factory() -> MithrilResult<IdbFactory> {
        Reflect::get(&js_sys::global(), &JsValue::from_str("indexedDB"))
            .js_context("Failed to read the IndexedDB factory of the global scope")?
            .dyn_into()
            .map_err(|_| anyhow!("IndexedDB is not available in this environment"))
    }

    /// Open a transaction on the given stores
    pub(super) fn transaction(
        &self,
        stores: &[&str],
        mode: IdbTransactionMode,
    ) -> MithrilResult<IdbTransaction> {
        let store_names = stores.iter().map(|name| JsValue::from_str(name)).collect::<Array>();

        self.database
            .transaction_with_str_sequence_and_mode(&store_names, mode)
            .js_context("Failed to open a certificate cache transaction")
    }

    /// Apply the schema changes introduced after the given version, one step per version
    fn upgrade(database: &IdbDatabase, old_version: f64) -> Result<(), JsValue> {
        if old_version < 1.0 {
            Self::create_stores(database)?;
        }

        Ok(())
    }

    /// Create the object stores and their expiration indexes
    fn create_stores(database: &IdbDatabase) -> Result<(), JsValue> {
        let committed = Self::create_store(
            database,
            COMMITTED_CERTIFICATES_STORE,
            &Array::of2(
                &JsValue::from_str("space"),
                &JsValue::from_str("certificate_hash"),
            ),
        )?;
        committed.create_index_with_str(EXPIRE_AT_INDEX, "expire_at")?;
        Self::create_store(
            database,
            STAGED_CERTIFICATES_STORE,
            &Array::of2(
                &JsValue::from_str("certificate_chain_validation_id"),
                &JsValue::from_str("certificate_hash"),
            ),
        )?;
        let batches = Self::create_store(
            database,
            STAGED_BATCHES_STORE,
            &JsValue::from_str("certificate_chain_validation_id"),
        )?;
        batches.create_index_with_str(EXPIRE_AT_INDEX, "expire_at")?;

        Ok(())
    }

    /// Create an object store whose records are keyed by the given key path
    fn create_store(
        database: &IdbDatabase,
        name: &str,
        key_path: &JsValue,
    ) -> Result<IdbObjectStore, JsValue> {
        let parameters = IdbObjectStoreParameters::new();
        parameters.set_key_path(key_path);

        database.create_object_store_with_optional_parameters(name, &parameters)
    }
}

impl Drop for DatabaseConnection {
    fn drop(&mut self) {
        self.database.close();
    }
}
