use std::path::Path;
#[cfg(feature = "snark")]
use std::sync::Arc;

#[cfg(feature = "snark")]
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "snark")]
use mithril_stm::{Parameters, SchnorrSigningKey, Stake};

use crate::crypto_helper::{CodecParseError, ProtocolParameters, SerDeShelleyFileFormat};
#[cfg(feature = "snark")]
use crate::{
    StdResult,
    crypto_helper::{KesPeriod, KesSigner},
    entities::Epoch,
};

/// Extension trait adding test utilities to [ProtocolInitializer][crate::crypto_helper::ProtocolInitializer]
pub trait ProtocolInitializerTestExtension {
    /// `TEST ONLY` - Override the protocol parameters of the `Initializer`
    fn override_protocol_parameters(&mut self, protocol_parameters: &ProtocolParameters);

    /// `TEST ONLY` - Same as `StmInitializerWrapper::setup`, but forces the resulting signer to
    /// use the given Schnorr signing key instead of generating a fresh one. Used to build two (or
    /// more) signers that share one SNARK key, to test SNARK-vk deduplication.
    #[cfg(feature = "snark")]
    fn setup_with_shared_schnorr_key<R: RngCore + CryptoRng>(
        params: Parameters,
        kes_signer: Option<Arc<dyn KesSigner>>,
        current_kes_period: Option<KesPeriod>,
        stake: Stake,
        epoch: Epoch,
        shared_schnorr_signing_key: SchnorrSigningKey,
        rng: &mut R,
    ) -> StdResult<Self>
    where
        Self: Sized;
}

/// Extension trait adding test-only file export utilities to any type implementing [SerDeShelleyFileFormat].
pub trait SerDeShelleyFileFormatTestExtension: SerDeShelleyFileFormat {
    /// `TEST ONLY` - Serialize the structure to a Shelley-formatted file.
    fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), CodecParseError>;
}
