use anyhow::anyhow;
use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use js_sys::{Array, JsString, Number, Object, Reflect};
use serde::Serialize;
use serde::de::DeserializeOwned;
use wasm_bindgen::{JsCast, JsValue};
use web_sys::{IdbKeyRange, IdbObjectStore, IdbRequest, IdbTransaction, IdbTransactionMode};

use mithril_client::certificate_client::{CertificateVerifierCache, CertificateVerifierCacheSpace};
use mithril_client::{MithrilCertificate, MithrilResult};

use super::database::{
    ALL_STORES, COMMITTED_CERTIFICATES_STORE, DatabaseConnection, EXPIRE_AT_INDEX,
    STAGED_BATCHES_STORE, STAGED_CERTIFICATES_STORE,
};
use super::error::JsErrorContext;
use super::promise::{IdbRequestExt, IdbTransactionExt};
use super::records::{CommittedCertificateRecord, StagedBatchRecord, StagedCertificateRecord};

const DEFAULT_STAGING_BATCH_TTL: TimeDelta = TimeDelta::minutes(15);

/// An IndexedDB cache for the certificate verifier, persisted by the browser across page loads.
///
/// Object stores of the database:
/// - `committed_certificates`: one record per verified certificate, keyed by the space that
///   validated it and by certificate hash, holding the certificate and its expiration date.
/// - `staged_certificates`: the certificates of the chain validations in progress, keyed by
///   certificate chain validation id and certificate hash.
/// - `staged_batches`: one record per chain validation in progress, keyed by certificate chain
///   validation id, holding the expiration date of the batch.
///
/// A commit moves the staged records of a batch to the committed store in a single transaction,
/// so an interrupted commit never leaves a partially committed batch.
/// A staged batch expires when it was created more than the staging expiration delay ago,
/// expired batches and committed certificates are swept when a new batch is staged and, in a
/// transaction of their own, before a batch is committed, so a failed commit never rolls the
/// sweep back. A committed record that cannot be decoded is evicted when it is read.
///
/// Note: as this cache is based on IndexedDB, it can only be used in a browser (it is not
/// compatible with nodejs or other environments without IndexedDB).
pub struct IndexedDbCertificateVerifierCache {
    /// Name of the IndexedDB database
    database_name: String,
    /// Time a committed certificate stays valid
    expiration_delay: TimeDelta,
    /// Time a staged batch survives before being dropped
    staging_expiration_delay: TimeDelta,
}

impl IndexedDbCertificateVerifierCache {
    /// `IndexedDbCertificateVerifierCache` factory
    ///
    /// The database is created on first use.
    pub fn new(database_name: &str, expiration_delay: TimeDelta) -> Self {
        Self {
            database_name: database_name.to_string(),
            expiration_delay,
            staging_expiration_delay: DEFAULT_STAGING_BATCH_TTL,
        }
    }

    /// Set how long a staged (uncommitted) batch survives before being silently dropped
    /// instead of committed.
    ///
    /// Warn: Too short and a slow-but-valid `verify_chain` call may never get to commit, and too
    /// long and an abandoned batch from a failed run lingers longer.
    pub fn with_staging_expiration_delay(mut self, staging_expiration_delay: TimeDelta) -> Self {
        self.staging_expiration_delay = staging_expiration_delay;
        self
    }

    /// Whether IndexedDB is available in the current environment, a browser window or worker
    pub fn is_available() -> bool {
        DatabaseConnection::factory().is_ok()
    }

    /// Run the given operation in a transaction on the given stores, the database is opened for
    /// the operation and closed afterward, the transaction is aborted when the operation fails
    /// and its abort is awaited so that the event callbacks outlive the event.
    async fn run_transaction<T>(
        &self,
        stores: &[&str],
        mode: IdbTransactionMode,
        operation: impl AsyncFnOnce(IdbTransaction) -> MithrilResult<T>,
    ) -> MithrilResult<T> {
        let connection = DatabaseConnection::open(&self.database_name).await?;
        let transaction = connection.transaction(stores, mode)?;
        let completion = transaction.completion();

        match operation(transaction.clone()).await {
            Ok(value) => {
                completion
                    .settled()
                    .await
                    .js_context("Certificate cache transaction failed")?;
                Ok(value)
            }
            Err(error) => {
                let _ = transaction.abort();
                let _ = completion.settled().await;
                Err(error)
            }
        }
    }

    /// Read a certificate committed to the given space, ignoring an expired one and evicting one
    /// that cannot be decoded
    async fn read_committed_certificate(
        &self,
        space: &CertificateVerifierCacheSpace,
        certificate_hash: &str,
    ) -> MithrilResult<Option<MithrilCertificate>> {
        let committed_key = Self::committed_key(space, certificate_hash);
        let value = self
            .run_transaction(
                &[COMMITTED_CERTIFICATES_STORE],
                IdbTransactionMode::Readonly,
                async move |transaction| {
                    Self::request_result(
                        Self::object_store(&transaction, COMMITTED_CERTIFICATES_STORE)?
                            .get(&committed_key),
                    )
                    .await
                },
            )
            .await?;

        let certificate = Self::decode_committed_certificate(value, Utc::now());
        if certificate.is_err() {
            let _ = self.evict_committed(space, certificate_hash).await;
        }

        certificate
    }

    /// Decode a committed record value into its certificate, absent when the record is unknown
    /// or expired at the given date
    fn decode_committed_certificate(
        value: JsValue,
        date: DateTime<Utc>,
    ) -> MithrilResult<Option<MithrilCertificate>> {
        if value.is_undefined() {
            return Ok(None);
        }
        let record = Self::decode_record::<CommittedCertificateRecord>(value)?;
        if !record.is_valid_at(date) {
            return Ok(None);
        }

        record.certificate().map(Some)
    }

    /// Delete the record of the certificate committed to the given space if it still cannot be
    /// decoded, so that a valid record committed in the meantime by another client is kept
    async fn evict_committed(
        &self,
        space: &CertificateVerifierCacheSpace,
        certificate_hash: &str,
    ) -> MithrilResult<()> {
        let committed_key = Self::committed_key(space, certificate_hash);

        self.run_transaction(
            &[COMMITTED_CERTIFICATES_STORE],
            IdbTransactionMode::Readwrite,
            async move |transaction| {
                let committed = Self::object_store(&transaction, COMMITTED_CERTIFICATES_STORE)?;
                let value = Self::request_result(committed.get(&committed_key)).await?;
                if Self::decode_committed_certificate(value, Utc::now()).is_err() {
                    committed
                        .delete(&committed_key)
                        .js_context("Failed to evict an undecodable committed certificate")?;
                }

                Ok(())
            },
        )
        .await
    }

    /// Delete the expired staged batches with their certificates and the expired committed
    /// certificates in a transaction of their own, a failed sweep is ignored
    async fn sweep_expired(&self) {
        let _ = self
            .run_transaction(
                &ALL_STORES,
                IdbTransactionMode::Readwrite,
                async move |transaction| Self::sweep_expired_in(&transaction).await,
            )
            .await;
    }

    /// Delete the expired staged batches with their certificates and the expired committed
    /// certificates in the given transaction
    async fn sweep_expired_in(transaction: &IdbTransaction) -> MithrilResult<()> {
        let now = Utc::now();
        let batches = Self::object_store(transaction, STAGED_BATCHES_STORE)?;
        let staged = Self::object_store(transaction, STAGED_CERTIFICATES_STORE)?;
        for batch_key in Self::expired_keys(&batches, now).await? {
            let batch_range = Self::batch_key_range(&batch_key)?;
            staged
                .delete(&batch_range)
                .js_context("Failed to delete the certificates of an expired batch")?;
            batches
                .delete(&batch_key)
                .js_context("Failed to delete an expired batch")?;
        }

        let committed = Self::object_store(transaction, COMMITTED_CERTIFICATES_STORE)?;
        for certificate_key in Self::expired_keys(&committed, now).await? {
            committed
                .delete(&certificate_key)
                .js_context("Failed to delete an expired committed certificate")?;
        }

        Ok(())
    }

    /// Turn a staged record into the record committed to the given space and expiring at the
    /// given date, in place and without decoding it
    fn committed_value(
        staged_record: JsValue,
        space_id: &JsString,
        expire_at: &Number,
    ) -> MithrilResult<Object> {
        let record = staged_record
            .dyn_into::<Object>()
            .map_err(|value| anyhow!("Unexpected certificate cache staged record: {value:?}"))?;
        Reflect::set(&record, &JsValue::from_str("space"), space_id)
            .js_context("Failed to set the space of a committed record")?;
        Reflect::set(&record, &JsValue::from_str("expire_at"), expire_at)
            .js_context("Failed to set the expiration of a committed record")?;
        Reflect::delete_property(
            &record,
            &JsValue::from_str("certificate_chain_validation_id"),
        )
        .js_context("Failed to detach a committed record from its batch")?;

        Ok(record)
    }

    /// Keys of the records of a store expired at the given date
    async fn expired_keys(
        store: &IdbObjectStore,
        date: DateTime<Utc>,
    ) -> MithrilResult<Vec<JsValue>> {
        let index = store
            .index(EXPIRE_AT_INDEX)
            .js_context("Failed to access the certificate cache expiration index")?;
        let expired_range = IdbKeyRange::upper_bound_with_open(&Self::timestamp(date), true)
            .js_context("Failed to build the certificate cache expiration range")?;

        Self::read_keys(index.get_all_keys_with_key(&expired_range)).await
    }

    /// Key range of the certificates staged under the given batch key
    fn batch_key_range(batch_key: &JsValue) -> MithrilResult<IdbKeyRange> {
        IdbKeyRange::bound(
            &Array::of1(batch_key),
            &Array::of2(batch_key, &Array::new()),
        )
        .js_context("Failed to build a certificate cache batch key range")
    }

    /// Key of the record of a certificate committed to the given space
    fn committed_key(space: &CertificateVerifierCacheSpace, certificate_hash: &str) -> Array {
        Array::of2(
            &JsValue::from_str(space.as_str()),
            &JsValue::from_str(certificate_hash),
        )
    }

    /// The given date as stored in the expiration indexes
    fn timestamp(date: DateTime<Utc>) -> Number {
        Number::from(date.timestamp_millis() as f64)
    }

    /// Access the given object store of the transaction
    fn object_store(transaction: &IdbTransaction, name: &str) -> MithrilResult<IdbObjectStore> {
        transaction.object_store(name).js_context(format!(
            "Failed to access the certificate cache store '{name}'"
        ))
    }

    /// Store a record, replacing the record with the same key if any
    fn put_record<T: Serialize>(store: &IdbObjectStore, record: &T) -> MithrilResult<()> {
        let value = serde_wasm_bindgen::to_value(record)
            .map_err(|error| anyhow!("Failed to encode a certificate cache record: {error}"))?;
        store
            .put(&value)
            .js_context("Failed to store a certificate cache record")?;

        Ok(())
    }

    /// Issue a request and decode its result as one record, absent when the key is unknown
    async fn read_record<T: DeserializeOwned>(
        request: Result<IdbRequest, JsValue>,
    ) -> MithrilResult<Option<T>> {
        let value = Self::request_result(request).await?;
        if value.is_undefined() {
            return Ok(None);
        }

        Self::decode_record(value).map(Some)
    }

    /// Issue a request and return its result as a list of keys
    async fn read_keys(request: Result<IdbRequest, JsValue>) -> MithrilResult<Vec<JsValue>> {
        Ok(Self::read_array(request).await?.iter().collect())
    }

    /// Issue a request and return its result as an array
    async fn read_array(request: Result<IdbRequest, JsValue>) -> MithrilResult<Array> {
        Self::request_result(request)
            .await?
            .dyn_into::<Array>()
            .map_err(|value| anyhow!("Unexpected certificate cache request result: {value:?}"))
    }

    /// Issue a request and await its result
    async fn request_result(request: Result<IdbRequest, JsValue>) -> MithrilResult<JsValue> {
        request
            .js_context("Failed to issue a certificate cache request")?
            .settled()
            .await
            .js_context("Certificate cache request failed")
    }

    /// Decode a stored record
    fn decode_record<T: DeserializeOwned>(value: JsValue) -> MithrilResult<T> {
        serde_wasm_bindgen::from_value(value)
            .map_err(|error| anyhow!("Failed to decode a certificate cache record: {error}"))
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl CertificateVerifierCache for IndexedDbCertificateVerifierCache {
    async fn stage_certificate(
        &self,
        certificate_chain_validation_id: &str,
        certificate: MithrilCertificate,
    ) -> MithrilResult<()> {
        let record = StagedCertificateRecord::new(certificate_chain_validation_id, &certificate)?;
        let batch = StagedBatchRecord {
            certificate_chain_validation_id: certificate_chain_validation_id.to_string(),
            expire_at: Utc::now() + self.staging_expiration_delay,
        };

        self.run_transaction(
            &ALL_STORES,
            IdbTransactionMode::Readwrite,
            async move |transaction| {
                let batches = Self::object_store(&transaction, STAGED_BATCHES_STORE)?;
                let batch_key = JsValue::from_str(certificate_chain_validation_id);
                let is_new_batch = Self::read_record::<StagedBatchRecord>(batches.get(&batch_key))
                    .await?
                    .is_none();
                if is_new_batch {
                    Self::sweep_expired_in(&transaction).await?;
                    Self::put_record(&batches, &batch)?;
                }

                Self::put_record(
                    &Self::object_store(&transaction, STAGED_CERTIFICATES_STORE)?,
                    &record,
                )
            },
        )
        .await
    }

    async fn commit_staged_certificates(
        &self,
        space: &CertificateVerifierCacheSpace,
        certificate_chain_validation_id: &str,
    ) -> MithrilResult<()> {
        let expire_at = Self::timestamp(Utc::now() + self.expiration_delay);
        let space_id = JsString::from(space.as_str());
        self.sweep_expired().await;

        self.run_transaction(
            &ALL_STORES,
            IdbTransactionMode::Readwrite,
            async move |transaction| {
                let staged = Self::object_store(&transaction, STAGED_CERTIFICATES_STORE)?;
                let committed = Self::object_store(&transaction, COMMITTED_CERTIFICATES_STORE)?;
                let batch_key = JsValue::from_str(certificate_chain_validation_id);
                let batch_range = Self::batch_key_range(&batch_key)?;
                for staged_record in
                    Self::read_array(staged.get_all_with_key(&batch_range)).await?.iter()
                {
                    let committed_record =
                        Self::committed_value(staged_record, &space_id, &expire_at)?;
                    committed
                        .put(&committed_record)
                        .js_context("Failed to store a committed certificate")?;
                }

                staged
                    .delete(&batch_range)
                    .js_context("Failed to delete the staged certificates of a committed batch")?;
                Self::object_store(&transaction, STAGED_BATCHES_STORE)?
                    .delete(&batch_key)
                    .js_context("Failed to delete a committed batch")?;

                Ok(())
            },
        )
        .await
    }

    async fn get_certificate_by_hash(
        &self,
        space: &CertificateVerifierCacheSpace,
        certificate_hash: &str,
    ) -> MithrilResult<Option<MithrilCertificate>> {
        self.read_committed_certificate(space, certificate_hash).await
    }

    async fn reset(&self) -> MithrilResult<()> {
        self.run_transaction(
            &ALL_STORES,
            IdbTransactionMode::Readwrite,
            async move |transaction| {
                for store in ALL_STORES {
                    Self::object_store(&transaction, store)?.clear().js_context(format!(
                        "Failed to clear the certificate cache store '{store}'"
                    ))?;
                }

                Ok(())
            },
        )
        .await
    }
}

#[cfg(all(test, not(feature = "test-node")))]
mod tests {
    use std::collections::{HashMap, HashSet};

    use chrono::SubsecRound;
    use wasm_bindgen_test::*;
    use web_sys::IdbDatabase;

    use mithril_common::crypto_helper::{GenesisEd25519Signer, GenesisSigner};
    use mithril_common::test::double::Dummy;

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    /// A delay expiring an entry as soon as it is written, a zero delay keeps it valid during
    /// the millisecond of its creation which is the resolution of the browser clock
    const ALREADY_EXPIRED_DELAY: TimeDelta = TimeDelta::milliseconds(-1);

    fn dummy_certificate(hash: &str, previous_hash: &str) -> MithrilCertificate {
        MithrilCertificate {
            hash: hash.to_string(),
            previous_hash: previous_hash.to_string(),
            ..Dummy::dummy()
        }
    }

    fn space() -> CertificateVerifierCacheSpace {
        CertificateVerifierCacheSpace::from_genesis_verifier(
            &GenesisSigner::create_deterministic_signer().create_verifier(),
        )
    }

    fn other_space() -> CertificateVerifierCacheSpace {
        CertificateVerifierCacheSpace::from_genesis_verifier(
            &GenesisSigner::from_ed25519(GenesisEd25519Signer::create_non_deterministic_signer())
                .create_verifier(),
        )
    }

    async fn empty_cache(
        database_name: &str,
        expiration_delay: TimeDelta,
    ) -> IndexedDbCertificateVerifierCache {
        let cache = IndexedDbCertificateVerifierCache::new(database_name, expiration_delay);
        cache.reset().await.unwrap();
        cache
    }

    async fn commit_certificates(
        cache: &IndexedDbCertificateVerifierCache,
        space: &CertificateVerifierCacheSpace,
        certificate_chain_validation_id: &str,
        certificates: impl IntoIterator<Item = MithrilCertificate>,
    ) {
        for certificate in certificates {
            cache
                .stage_certificate(certificate_chain_validation_id, certificate)
                .await
                .unwrap();
        }
        cache
            .commit_staged_certificates(space, certificate_chain_validation_id)
            .await
            .unwrap();
    }

    impl IndexedDbCertificateVerifierCache {
        /// `Test only` Issue a request and decode its result as a list of records
        async fn read_records<T: DeserializeOwned>(
            request: Result<IdbRequest, JsValue>,
        ) -> MithrilResult<Vec<T>> {
            Self::read_array(request)
                .await?
                .iter()
                .map(Self::decode_record)
                .collect()
        }

        /// `Test only` Store a record in the given store as is
        async fn put_raw_record<T: Serialize>(&self, store: &str, record: &T) {
            let record_value = serde_wasm_bindgen::to_value(record).unwrap();
            self.run_transaction(
                &[store],
                IdbTransactionMode::Readwrite,
                async move |transaction| {
                    Self::object_store(&transaction, store)?
                        .put(&record_value)
                        .js_context("Failed to store a raw record")?;

                    Ok(())
                },
            )
            .await
            .unwrap();
        }

        /// `Test only` Return the committed records
        async fn committed_records(&self) -> Vec<CommittedCertificateRecord> {
            self.run_transaction(
                &[COMMITTED_CERTIFICATES_STORE],
                IdbTransactionMode::Readonly,
                async move |transaction| {
                    Self::read_records(
                        Self::object_store(&transaction, COMMITTED_CERTIFICATES_STORE)?.get_all(),
                    )
                    .await
                },
            )
            .await
            .unwrap()
        }

        /// `Test only` Return the record of the given certificate hash committed to the given space
        async fn committed_record(
            &self,
            space: &CertificateVerifierCacheSpace,
            certificate_hash: &str,
        ) -> CommittedCertificateRecord {
            self.committed_records()
                .await
                .into_iter()
                .find(|record| {
                    record.space == space.as_str() && record.certificate_hash == certificate_hash
                })
                .expect("Key not found")
        }

        /// `Test only` Return the content of the given space of the cache (without the expiration date)
        async fn content(
            &self,
            space: &CertificateVerifierCacheSpace,
        ) -> HashMap<String, MithrilCertificate> {
            self.committed_records()
                .await
                .into_iter()
                .filter(|record| record.space == space.as_str())
                .map(|record| {
                    (
                        record.certificate_hash.clone(),
                        record.certificate().unwrap(),
                    )
                })
                .collect()
        }

        /// `Test only` Return the keys of the committed records expired at the given date
        async fn expired_committed_keys(&self, date: DateTime<Utc>) -> Vec<JsValue> {
            self.run_transaction(
                &[COMMITTED_CERTIFICATES_STORE],
                IdbTransactionMode::Readonly,
                async move |transaction| {
                    Self::expired_keys(
                        &Self::object_store(&transaction, COMMITTED_CERTIFICATES_STORE)?,
                        date,
                    )
                    .await
                },
            )
            .await
            .unwrap()
        }

        /// `Test only` Return the ids of staged batches
        async fn staged_batch_ids(&self) -> HashSet<String> {
            let batches: Vec<StagedBatchRecord> = self
                .run_transaction(
                    &[STAGED_BATCHES_STORE],
                    IdbTransactionMode::Readonly,
                    async move |transaction| {
                        Self::read_records(
                            Self::object_store(&transaction, STAGED_BATCHES_STORE)?.get_all(),
                        )
                        .await
                    },
                )
                .await
                .unwrap();

            batches
                .into_iter()
                .map(|batch| batch.certificate_chain_validation_id)
                .collect()
        }

        /// `Test only` Return the hashes of the certificates staged under the given id
        async fn staged_hashes(&self, certificate_chain_validation_id: &str) -> HashSet<String> {
            let records: Vec<StagedCertificateRecord> = self
                .run_transaction(
                    &[STAGED_CERTIFICATES_STORE],
                    IdbTransactionMode::Readonly,
                    async move |transaction| {
                        let batch_range = Self::batch_key_range(&JsValue::from_str(
                            certificate_chain_validation_id,
                        ))?;
                        Self::read_records(
                            Self::object_store(&transaction, STAGED_CERTIFICATES_STORE)?
                                .get_all_with_key(&batch_range),
                        )
                        .await
                    },
                )
                .await
                .unwrap();

            records.into_iter().map(|record| record.certificate_hash).collect()
        }
    }

    mod stage_commit {
        use super::*;

        #[wasm_bindgen_test]
        async fn staging_a_certificate_does_not_make_it_retrievable_before_commit() {
            let cache = empty_cache(
                "staging_a_certificate_does_not_make_it_retrievable_before_commit",
                TimeDelta::hours(1),
            )
            .await;
            cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();

            assert_eq!(
                None,
                cache.get_certificate_by_hash(&space(), "hash").await.unwrap()
            );
            assert_eq!(
                HashSet::from(["hash".to_string()]),
                cache.staged_hashes("chain_validation_id").await
            );
        }

        #[wasm_bindgen_test]
        async fn committing_makes_previously_staged_certificates_retrievable() {
            let cache = empty_cache(
                "committing_makes_previously_staged_certificates_retrievable",
                TimeDelta::hours(1),
            )
            .await;
            cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();
            cache
                .commit_staged_certificates(&space(), "chain_validation_id")
                .await
                .unwrap();

            assert_eq!(
                Some(dummy_certificate("hash", "parent")),
                cache.get_certificate_by_hash(&space(), "hash").await.unwrap()
            );
            assert!(cache.staged_hashes("chain_validation_id").await.is_empty());
            assert!(cache.staged_batch_ids().await.is_empty());
        }

        #[wasm_bindgen_test]
        async fn committing_one_id_does_not_expose_certificates_staged_under_another_id() {
            let cache = empty_cache(
                "committing_one_id_does_not_expose_certificates_staged_under_another_id",
                TimeDelta::hours(1),
            )
            .await;
            cache
                .stage_certificate("chain_id_a", dummy_certificate("hash_a", "parent"))
                .await
                .unwrap();
            cache
                .stage_certificate("chain_id_b", dummy_certificate("hash_b", "parent"))
                .await
                .unwrap();
            cache
                .commit_staged_certificates(&space(), "chain_id_a")
                .await
                .unwrap();

            assert!(
                cache
                    .get_certificate_by_hash(&space(), "hash_a")
                    .await
                    .unwrap()
                    .is_some()
            );
            assert_eq!(
                None,
                cache.get_certificate_by_hash(&space(), "hash_b").await.unwrap()
            );
            assert_eq!(
                HashSet::from(["chain_id_b".to_string()]),
                cache.staged_batch_ids().await
            );
        }

        #[wasm_bindgen_test]
        async fn committing_an_unknown_id_is_a_no_op_not_an_error() {
            let cache = empty_cache(
                "committing_an_unknown_id_is_a_no_op_not_an_error",
                TimeDelta::hours(1),
            )
            .await;

            cache
                .commit_staged_certificates(&space(), "never_staged")
                .await
                .unwrap();

            assert_eq!(HashMap::new(), cache.content(&space()).await);
        }

        #[wasm_bindgen_test]
        async fn committing_the_same_id_twice_is_a_no_op_the_second_time() {
            let cache = empty_cache(
                "committing_the_same_id_twice_is_a_no_op_the_second_time",
                TimeDelta::hours(1),
            )
            .await;
            cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();
            cache
                .commit_staged_certificates(&space(), "chain_validation_id")
                .await
                .unwrap();

            cache
                .commit_staged_certificates(&space(), "chain_validation_id")
                .await
                .unwrap();

            assert_eq!(1, cache.content(&space()).await.len());
        }

        #[wasm_bindgen_test]
        async fn committing_an_expired_staged_batch_does_not_commit_it() {
            let cache = empty_cache(
                "committing_an_expired_staged_batch_does_not_commit_it",
                TimeDelta::hours(1),
            )
            .await
            .with_staging_expiration_delay(ALREADY_EXPIRED_DELAY);
            cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();

            cache
                .commit_staged_certificates(&space(), "chain_validation_id")
                .await
                .unwrap();

            assert_eq!(
                None,
                cache.get_certificate_by_hash(&space(), "hash").await.unwrap()
            );
            assert!(cache.staged_batch_ids().await.is_empty());
        }

        #[wasm_bindgen_test]
        async fn committing_in_empty_cache_adds_new_item_that_expires_after_parametrized_delay() {
            let expiration_delay = TimeDelta::hours(1);
            let start_time = Utc::now().trunc_subsecs(3);
            let cache = empty_cache(
                "committing_in_empty_cache_adds_new_item_that_expires_after_parametrized_delay",
                expiration_delay,
            )
            .await;
            commit_certificates(
                &cache,
                &space(),
                "chain_validation_id",
                [dummy_certificate("hash", "parent")],
            )
            .await;

            let records = cache.committed_records().await;

            assert_eq!(1, records.len());
            assert_eq!("hash", records[0].certificate_hash);
            assert!(records[0].expire_at - start_time >= expiration_delay);
        }

        #[wasm_bindgen_test]
        async fn committing_new_hash_does_not_alter_existing_values() {
            let cache = empty_cache(
                "committing_new_hash_does_not_alter_existing_values",
                TimeDelta::hours(1),
            )
            .await;
            commit_certificates(
                &cache,
                &space(),
                "initial_id",
                [
                    dummy_certificate("existing_hash", "existing_parent"),
                    dummy_certificate("another_hash", "another_parent"),
                ],
            )
            .await;

            commit_certificates(
                &cache,
                &space(),
                "chain_validation_id",
                [dummy_certificate("new_hash", "new_parent")],
            )
            .await;

            assert_eq!(
                HashMap::from([
                    (
                        "existing_hash".to_string(),
                        dummy_certificate("existing_hash", "existing_parent")
                    ),
                    (
                        "another_hash".to_string(),
                        dummy_certificate("another_hash", "another_parent")
                    ),
                    (
                        "new_hash".to_string(),
                        dummy_certificate("new_hash", "new_parent")
                    ),
                ]),
                cache.content(&space()).await
            );
        }

        #[wasm_bindgen_test]
        async fn committing_a_certificate_with_an_existing_hash_updates_data_and_expiration_time() {
            let expiration_delay = TimeDelta::days(2);
            let cache = empty_cache(
                "committing_a_certificate_with_an_existing_hash_updates_data_and_expiration_time",
                expiration_delay,
            )
            .await;
            let before_update = dummy_certificate("hash", "parent");
            let unaltered = dummy_certificate("another_hash", "another_parent");
            let expected = MithrilCertificate {
                epoch: before_update.epoch + 10,
                previous_hash: "updated_parent".to_string(),
                ..before_update.clone()
            };
            commit_certificates(
                &cache,
                &space(),
                "initial_id",
                [before_update, unaltered.clone()],
            )
            .await;
            let initial_record = cache.committed_record(&space(), "hash").await;
            let start_time = Utc::now().trunc_subsecs(3);

            commit_certificates(&cache, &space(), "update_id", [expected.clone()]).await;

            let updated_record = cache.committed_record(&space(), "hash").await;
            assert_eq!(2, cache.content(&space()).await.len());
            assert_eq!(
                Some(expected),
                cache.get_certificate_by_hash(&space(), "hash").await.unwrap()
            );
            assert_eq!(
                Some(unaltered),
                cache.get_certificate_by_hash(&space(), "another_hash").await.unwrap(),
                "Existing but not updated value should not have been altered"
            );
            assert_ne!(initial_record, updated_record);
            assert!(updated_record.expire_at - start_time >= expiration_delay);
        }

        #[wasm_bindgen_test]
        async fn committing_certificates_sweeps_away_expired_batches() {
            let database_name = "committing_certificates_sweeps_away_expired_batches";
            let cache = empty_cache(database_name, TimeDelta::hours(1))
                .await
                .with_staging_expiration_delay(TimeDelta::hours(1));
            let expired_batches_cache =
                IndexedDbCertificateVerifierCache::new(database_name, TimeDelta::hours(1))
                    .with_staging_expiration_delay(ALREADY_EXPIRED_DELAY);
            cache
                .stage_certificate("to_commit_id", dummy_certificate("hash2", "parent2"))
                .await
                .unwrap();
            cache
                .stage_certificate("remaining_id", dummy_certificate("hash3", "parent3"))
                .await
                .unwrap();
            expired_batches_cache
                .stage_certificate("abandoned_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();

            assert_eq!(3, cache.staged_batch_ids().await.len());

            cache
                .commit_staged_certificates(&space(), "to_commit_id")
                .await
                .unwrap();

            assert_eq!(
                HashSet::from(["remaining_id".to_string()]),
                cache.staged_batch_ids().await
            );
            assert!(cache.staged_hashes("abandoned_id").await.is_empty());
        }

        #[wasm_bindgen_test]
        async fn committing_certificates_sweeps_away_expired_committed_certificates() {
            let database_name =
                "committing_certificates_sweeps_away_expired_committed_certificates";
            let cache = empty_cache(database_name, TimeDelta::hours(1)).await;
            let expired_cache =
                IndexedDbCertificateVerifierCache::new(database_name, ALREADY_EXPIRED_DELAY);
            commit_certificates(
                &cache,
                &space(),
                "valid_id",
                [dummy_certificate("new_hash", "parent")],
            )
            .await;
            commit_certificates(
                &expired_cache,
                &space(),
                "expired_id",
                [dummy_certificate("expired_hash", "parent")],
            )
            .await;

            assert_eq!(2, cache.committed_records().await.len());

            cache
                .commit_staged_certificates(&space(), "another_id")
                .await
                .unwrap();

            assert_eq!(
                HashMap::from([(
                    "new_hash".to_string(),
                    dummy_certificate("new_hash", "parent")
                )]),
                cache.content(&space()).await
            );
        }

        #[wasm_bindgen_test]
        async fn staging_a_new_batch_sweeps_away_other_expired_batches() {
            let database_name = "staging_a_new_batch_sweeps_away_other_expired_batches";
            let cache = empty_cache(database_name, TimeDelta::hours(1))
                .await
                .with_staging_expiration_delay(TimeDelta::hours(1));
            let expired_batches_cache =
                IndexedDbCertificateVerifierCache::new(database_name, TimeDelta::hours(1))
                    .with_staging_expiration_delay(ALREADY_EXPIRED_DELAY);
            expired_batches_cache
                .stage_certificate("expired_batch", dummy_certificate("hash", "parent"))
                .await
                .unwrap();

            cache
                .stage_certificate("new_batch", dummy_certificate("hash2", "parent2"))
                .await
                .unwrap();

            assert_eq!(
                HashSet::from(["new_batch".to_string()]),
                cache.staged_batch_ids().await
            );
            assert!(cache.staged_hashes("expired_batch").await.is_empty());
        }

        #[wasm_bindgen_test]
        async fn staging_a_new_batch_sweeps_away_expired_committed_certificates() {
            let database_name = "staging_a_new_batch_sweeps_away_expired_committed_certificates";
            let cache = empty_cache(database_name, TimeDelta::hours(1)).await;
            let expired_cache =
                IndexedDbCertificateVerifierCache::new(database_name, ALREADY_EXPIRED_DELAY);
            commit_certificates(
                &cache,
                &space(),
                "valid_id",
                [dummy_certificate("new_hash", "parent")],
            )
            .await;
            commit_certificates(
                &expired_cache,
                &space(),
                "expired_id",
                [dummy_certificate("expired_hash", "parent")],
            )
            .await;

            assert_eq!(2, cache.committed_records().await.len());

            cache
                .stage_certificate("new_batch", dummy_certificate("hash2", "parent2"))
                .await
                .unwrap();

            assert_eq!(
                HashMap::from([(
                    "new_hash".to_string(),
                    dummy_certificate("new_hash", "parent")
                )]),
                cache.content(&space()).await
            );
        }

        #[wasm_bindgen_test]
        async fn staging_under_an_existing_batch_does_not_sweep_other_expired_batches() {
            let database_name =
                "staging_under_an_existing_batch_does_not_sweep_other_expired_batches";
            let cache = empty_cache(database_name, TimeDelta::hours(1))
                .await
                .with_staging_expiration_delay(TimeDelta::hours(1));
            let expired_batches_cache =
                IndexedDbCertificateVerifierCache::new(database_name, TimeDelta::hours(1))
                    .with_staging_expiration_delay(ALREADY_EXPIRED_DELAY);
            cache
                .stage_certificate("existing_id", dummy_certificate("hash2", "parent2"))
                .await
                .unwrap();
            expired_batches_cache
                .stage_certificate("expired_batch", dummy_certificate("hash", "parent"))
                .await
                .unwrap();

            cache
                .stage_certificate("existing_id", dummy_certificate("hash3", "parent3"))
                .await
                .unwrap();

            assert_eq!(
                HashSet::from(["expired_batch".to_string(), "existing_id".to_string()]),
                cache.staged_batch_ids().await
            );
        }

        #[wasm_bindgen_test]
        async fn staging_under_an_expired_batch_does_not_extend_it() {
            let database_name = "staging_under_an_expired_batch_does_not_extend_it";
            let cache = empty_cache(database_name, TimeDelta::hours(1)).await;
            let expired_batches_cache =
                IndexedDbCertificateVerifierCache::new(database_name, TimeDelta::hours(1))
                    .with_staging_expiration_delay(ALREADY_EXPIRED_DELAY);
            expired_batches_cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();

            cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash2", "parent2"))
                .await
                .unwrap();
            cache
                .commit_staged_certificates(&space(), "chain_validation_id")
                .await
                .unwrap();

            assert_eq!(HashMap::new(), cache.content(&space()).await);
            assert_eq!(HashSet::new(), cache.staged_batch_ids().await);
        }

        #[wasm_bindgen_test]
        async fn sweep_keeps_a_committed_certificate_until_its_expiration_date_included() {
            let cache = empty_cache(
                "sweep_keeps_a_committed_certificate_until_its_expiration_date_included",
                TimeDelta::hours(1),
            )
            .await;
            let expire_at = Utc::now().trunc_subsecs(3);
            cache
                .put_raw_record(
                    COMMITTED_CERTIFICATES_STORE,
                    &CommittedCertificateRecord {
                        space: space().as_str().to_string(),
                        certificate_hash: "hash".to_string(),
                        expire_at,
                        certificate: "certificate".to_string(),
                    },
                )
                .await;

            assert!(cache.expired_committed_keys(expire_at).await.is_empty());
            assert_eq!(
                1,
                cache
                    .expired_committed_keys(expire_at + TimeDelta::milliseconds(1))
                    .await
                    .len()
            );
        }

        #[wasm_bindgen_test]
        async fn staging_under_an_undecodable_batch_record_fails_and_stages_nothing() {
            #[derive(Serialize)]
            struct UndecodableBatchRecord {
                certificate_chain_validation_id: String,
                expire_at: String,
            }
            let cache = empty_cache(
                "staging_under_an_undecodable_batch_record_fails_and_stages_nothing",
                TimeDelta::hours(1),
            )
            .await;
            cache
                .put_raw_record(
                    STAGED_BATCHES_STORE,
                    &UndecodableBatchRecord {
                        certificate_chain_validation_id: "chain_validation_id".to_string(),
                        expire_at: "not a date".to_string(),
                    },
                )
                .await;

            cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash", "parent"))
                .await
                .expect_err("an undecodable batch record must be reported");

            assert!(cache.staged_hashes("chain_validation_id").await.is_empty());
        }
    }

    mod get_certificate_by_hash {
        use super::*;

        #[wasm_bindgen_test]
        async fn returns_the_certificate_when_committed() {
            let cache = empty_cache(
                "returns_the_certificate_when_committed",
                TimeDelta::hours(1),
            )
            .await;
            let expected = dummy_certificate("hash", "parent");
            commit_certificates(
                &cache,
                &space(),
                "chain_validation_id",
                [expected.clone(), dummy_certificate("another_hash", "another_parent")],
            )
            .await;

            assert_eq!(
                Some(expected),
                cache.get_certificate_by_hash(&space(), "hash").await.unwrap()
            );
        }

        #[wasm_bindgen_test]
        async fn returns_none_if_not_found() {
            let cache = empty_cache("returns_none_if_not_found", TimeDelta::hours(1)).await;
            commit_certificates(
                &cache,
                &space(),
                "chain_validation_id",
                [dummy_certificate("hash", "parent")],
            )
            .await;

            assert_eq!(
                None,
                cache.get_certificate_by_hash(&space(), "not_found").await.unwrap()
            );
        }

        #[wasm_bindgen_test]
        async fn evicts_an_undecodable_committed_record_and_reports_the_error() {
            let cache = empty_cache(
                "evicts_an_undecodable_committed_record_and_reports_the_error",
                TimeDelta::hours(1),
            )
            .await;
            cache
                .put_raw_record(
                    COMMITTED_CERTIFICATES_STORE,
                    &CommittedCertificateRecord {
                        space: space().as_str().to_string(),
                        certificate_hash: "hash".to_string(),
                        expire_at: Utc::now() + TimeDelta::hours(1),
                        certificate: "not a certificate".to_string(),
                    },
                )
                .await;

            cache
                .get_certificate_by_hash(&space(), "hash")
                .await
                .expect_err("an undecodable record must be reported");

            assert!(cache.committed_records().await.is_empty());
            assert_eq!(
                None,
                cache.get_certificate_by_hash(&space(), "hash").await.unwrap()
            );
        }

        #[wasm_bindgen_test]
        async fn evicts_a_committed_record_with_an_undecodable_expiration_and_reports_the_error() {
            #[derive(Serialize)]
            struct UndecodableCommittedRecord {
                space: String,
                certificate_hash: String,
                expire_at: String,
                certificate: String,
            }
            let cache = empty_cache(
                "evicts_a_committed_record_with_an_undecodable_expiration_and_reports_the_error",
                TimeDelta::hours(1),
            )
            .await;
            cache
                .put_raw_record(
                    COMMITTED_CERTIFICATES_STORE,
                    &UndecodableCommittedRecord {
                        space: space().as_str().to_string(),
                        certificate_hash: "hash".to_string(),
                        expire_at: "not a date".to_string(),
                        certificate: serde_json::to_string(&dummy_certificate("hash", "parent"))
                            .unwrap(),
                    },
                )
                .await;

            cache
                .get_certificate_by_hash(&space(), "hash")
                .await
                .expect_err("an undecodable record must be reported");

            assert!(cache.committed_records().await.is_empty());
            assert_eq!(
                None,
                cache.get_certificate_by_hash(&space(), "hash").await.unwrap()
            );
        }

        #[wasm_bindgen_test]
        async fn eviction_keeps_a_decodable_record_committed_in_the_meantime() {
            let cache = empty_cache(
                "eviction_keeps_a_decodable_record_committed_in_the_meantime",
                TimeDelta::hours(1),
            )
            .await;
            commit_certificates(
                &cache,
                &space(),
                "chain_validation_id",
                [dummy_certificate("hash", "parent")],
            )
            .await;

            cache.evict_committed(&space(), "hash").await.unwrap();

            assert_eq!(
                Some(dummy_certificate("hash", "parent")),
                cache.get_certificate_by_hash(&space(), "hash").await.unwrap()
            );
        }

        #[wasm_bindgen_test]
        async fn returns_none_for_an_expired_certificate() {
            let cache = empty_cache(
                "returns_none_for_an_expired_certificate",
                ALREADY_EXPIRED_DELAY,
            )
            .await;
            commit_certificates(
                &cache,
                &space(),
                "chain_validation_id",
                [dummy_certificate("hash", "parent")],
            )
            .await;

            assert_eq!(1, cache.committed_records().await.len());
            assert_eq!(
                None,
                cache.get_certificate_by_hash(&space(), "hash").await.unwrap()
            );
        }
    }

    mod reset {
        use super::*;

        #[wasm_bindgen_test]
        async fn reset_empty_cache_dont_raise_error() {
            let cache =
                empty_cache("reset_empty_cache_dont_raise_error", TimeDelta::hours(1)).await;

            cache.reset().await.unwrap();

            assert_eq!(HashMap::new(), cache.content(&space()).await);
        }

        #[wasm_bindgen_test]
        async fn reset_clears_committed_data() {
            let cache = empty_cache("reset_clears_committed_data", TimeDelta::hours(1)).await;
            commit_certificates(
                &cache,
                &space(),
                "chain_validation_id",
                [
                    dummy_certificate("hash", "parent"),
                    dummy_certificate("another_hash", "another_parent"),
                ],
            )
            .await;

            assert_eq!(2, cache.content(&space()).await.len());

            cache.reset().await.unwrap();

            assert_eq!(HashMap::new(), cache.content(&space()).await);
        }

        #[wasm_bindgen_test]
        async fn reset_clears_staged_data() {
            let cache = empty_cache("reset_clears_staged_data", TimeDelta::hours(1)).await;
            cache
                .stage_certificate("chain_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();

            assert_eq!(1, cache.staged_batch_ids().await.len());

            cache.reset().await.unwrap();

            assert_eq!(HashSet::new(), cache.staged_batch_ids().await);
            assert!(cache.staged_hashes("chain_id").await.is_empty());
        }
    }

    mod spaces {
        use super::*;

        #[wasm_bindgen_test]
        async fn a_certificate_committed_to_a_space_is_not_visible_from_another_space() {
            let cache = empty_cache(
                "a_certificate_committed_to_a_space_is_not_visible_from_another_space",
                TimeDelta::hours(1),
            )
            .await;
            commit_certificates(
                &cache,
                &space(),
                "chain_validation_id",
                [dummy_certificate("hash", "parent")],
            )
            .await;

            assert_eq!(
                None,
                cache.get_certificate_by_hash(&other_space(), "hash").await.unwrap()
            );
            assert_eq!(HashMap::new(), cache.content(&other_space()).await);
        }

        #[wasm_bindgen_test]
        async fn the_same_certificate_can_be_committed_to_several_spaces() {
            let cache = empty_cache(
                "the_same_certificate_can_be_committed_to_several_spaces",
                TimeDelta::hours(1),
            )
            .await;
            let other_space = other_space();
            commit_certificates(
                &cache,
                &space(),
                "first_id",
                [dummy_certificate("hash", "parent")],
            )
            .await;
            commit_certificates(
                &cache,
                &other_space,
                "second_id",
                [dummy_certificate("hash", "parent")],
            )
            .await;

            assert_eq!(2, cache.committed_records().await.len());
            assert!(
                cache
                    .get_certificate_by_hash(&space(), "hash")
                    .await
                    .unwrap()
                    .is_some()
            );
            assert!(
                cache
                    .get_certificate_by_hash(&other_space, "hash")
                    .await
                    .unwrap()
                    .is_some()
            );
        }

        #[wasm_bindgen_test]
        async fn reset_clears_all_spaces() {
            let cache = empty_cache("reset_clears_all_spaces", TimeDelta::hours(1)).await;
            commit_certificates(
                &cache,
                &space(),
                "first_id",
                [dummy_certificate("hash", "parent")],
            )
            .await;
            commit_certificates(
                &cache,
                &other_space(),
                "second_id",
                [dummy_certificate("another_hash", "parent")],
            )
            .await;

            cache.reset().await.unwrap();

            assert!(cache.committed_records().await.is_empty());
        }
    }

    mod transaction {
        use super::*;

        #[wasm_bindgen_test]
        async fn a_failed_operation_rolls_back_the_writes_of_its_transaction() {
            let cache = empty_cache(
                "a_failed_operation_rolls_back_the_writes_of_its_transaction",
                TimeDelta::hours(1),
            )
            .await;
            let batch = StagedBatchRecord {
                certificate_chain_validation_id: "chain_validation_id".to_string(),
                expire_at: Utc::now() + TimeDelta::hours(1),
            };

            cache
                .run_transaction(
                    &[STAGED_BATCHES_STORE],
                    IdbTransactionMode::Readwrite,
                    async move |transaction| {
                        IndexedDbCertificateVerifierCache::put_record(
                            &IndexedDbCertificateVerifierCache::object_store(
                                &transaction,
                                STAGED_BATCHES_STORE,
                            )?,
                            &batch,
                        )?;

                        Err::<(), _>(anyhow!("operation failure"))
                    },
                )
                .await
                .expect_err("the operation failure must be reported");

            assert!(cache.staged_batch_ids().await.is_empty());
        }

        #[wasm_bindgen_test]
        async fn operations_fail_on_a_database_with_a_newer_version() {
            let database_name = "operations_fail_on_a_database_with_a_newer_version";
            DatabaseConnection::factory()
                .unwrap()
                .open_with_u32(database_name, 2)
                .unwrap()
                .settled()
                .await
                .unwrap()
                .dyn_into::<IdbDatabase>()
                .unwrap()
                .close();
            let cache = IndexedDbCertificateVerifierCache::new(database_name, TimeDelta::hours(1));

            let error = cache.get_certificate_by_hash(&space(), "hash").await.unwrap_err();

            assert!(
                error.to_string().contains("VersionError"),
                "Unexpected error: {error}"
            );
        }
    }

    mod availability {
        use super::*;

        #[wasm_bindgen_test]
        fn indexed_db_is_available_in_a_browser() {
            assert!(IndexedDbCertificateVerifierCache::is_available());
        }
    }

    mod persistence {
        use super::*;

        #[wasm_bindgen_test]
        async fn committed_certificates_are_shared_by_caches_on_the_same_database() {
            let database_name = "committed_certificates_are_shared_by_caches_on_the_same_database";
            let cache = empty_cache(database_name, TimeDelta::hours(1)).await;
            commit_certificates(
                &cache,
                &space(),
                "chain_validation_id",
                [dummy_certificate("hash", "parent")],
            )
            .await;

            let other_cache =
                IndexedDbCertificateVerifierCache::new(database_name, TimeDelta::hours(1));

            assert_eq!(
                Some(dummy_certificate("hash", "parent")),
                other_cache.get_certificate_by_hash(&space(), "hash").await.unwrap()
            );
        }

        #[wasm_bindgen_test]
        async fn caches_on_different_databases_are_isolated() {
            let cache = empty_cache(
                "caches_on_different_databases_are_isolated",
                TimeDelta::hours(1),
            )
            .await;
            commit_certificates(
                &cache,
                &space(),
                "chain_validation_id",
                [dummy_certificate("hash", "parent")],
            )
            .await;

            let other_cache = empty_cache(
                "caches_on_different_databases_are_isolated_other",
                TimeDelta::hours(1),
            )
            .await;

            assert_eq!(
                None,
                other_cache.get_certificate_by_hash(&space(), "hash").await.unwrap()
            );
            assert!(
                cache
                    .get_certificate_by_hash(&space(), "hash")
                    .await
                    .unwrap()
                    .is_some()
            );
        }
    }
}

#[cfg(all(test, feature = "test-node"))]
mod tests_without_indexed_db {
    use wasm_bindgen_test::*;

    use mithril_common::crypto_helper::GenesisSigner;

    use super::*;

    #[wasm_bindgen_test]
    fn indexed_db_is_not_available_without_a_browser() {
        assert!(!IndexedDbCertificateVerifierCache::is_available());
    }

    #[wasm_bindgen_test]
    async fn operations_fail_when_indexed_db_is_unavailable() {
        let cache = IndexedDbCertificateVerifierCache::new("unavailable", TimeDelta::hours(1));
        let space = CertificateVerifierCacheSpace::from_genesis_verifier(
            &GenesisSigner::create_deterministic_signer().create_verifier(),
        );

        let error = cache.get_certificate_by_hash(&space, "hash").await.unwrap_err();

        assert!(
            error.to_string().contains("IndexedDB is not available"),
            "Unexpected error: {error}"
        );
    }
}
