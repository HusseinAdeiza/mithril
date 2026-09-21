use anyhow::Context;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use mithril_client::{MithrilCertificate, MithrilResult};

/// A record of the committed certificates store
#[derive(Debug, PartialEq, Clone, Deserialize)]
#[cfg_attr(test, derive(Serialize))]
pub(super) struct CommittedCertificateRecord {
    /// Identifier of the space the certificate is committed to, first part of the record key
    pub(super) space: String,
    /// Hash of the certificate, second part of the record key
    pub(super) certificate_hash: String,
    /// Date after which the record is ignored
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub(super) expire_at: DateTime<Utc>,
    /// The certificate encoded in JSON
    pub(super) certificate: String,
}

impl CommittedCertificateRecord {
    /// Whether the record is still valid at the given date
    pub(super) fn is_valid_at(&self, date: DateTime<Utc>) -> bool {
        self.expire_at >= date
    }

    /// Decode the cached certificate
    pub(super) fn certificate(&self) -> MithrilResult<MithrilCertificate> {
        serde_json::from_str(&self.certificate).context("Failed to decode a cached certificate")
    }
}

/// A record of the staged certificates store
#[derive(Debug, PartialEq, Clone, Serialize)]
#[cfg_attr(test, derive(Deserialize))]
pub(super) struct StagedCertificateRecord {
    /// Id of the chain validation that staged the certificate, first part of the record key
    pub(super) certificate_chain_validation_id: String,
    /// Hash of the certificate, second part of the record key
    pub(super) certificate_hash: String,
    /// The certificate encoded in JSON
    pub(super) certificate: String,
}

impl StagedCertificateRecord {
    /// Encode a certificate staged by the given chain validation
    pub(super) fn new(
        certificate_chain_validation_id: &str,
        certificate: &MithrilCertificate,
    ) -> MithrilResult<Self> {
        Ok(Self {
            certificate_chain_validation_id: certificate_chain_validation_id.to_string(),
            certificate_hash: certificate.hash.clone(),
            certificate: serde_json::to_string(certificate)
                .context("Failed to encode a certificate to cache")?,
        })
    }
}

/// A record of the staged batches store
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub(super) struct StagedBatchRecord {
    /// Id of the chain validation, key of the record
    pub(super) certificate_chain_validation_id: String,
    /// Date after which the batch is dropped
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub(super) expire_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use chrono::TimeDelta;
    use wasm_bindgen_test::*;

    use super::*;

    #[wasm_bindgen_test]
    fn committed_record_is_valid_until_its_expiration_date_included() {
        let expire_at = Utc::now();
        let record = CommittedCertificateRecord {
            space: "space".to_string(),
            certificate_hash: "hash".to_string(),
            expire_at,
            certificate: "certificate".to_string(),
        };

        assert!(record.is_valid_at(expire_at - TimeDelta::milliseconds(1)));
        assert!(record.is_valid_at(expire_at));
        assert!(!record.is_valid_at(expire_at + TimeDelta::milliseconds(1)));
    }
}
