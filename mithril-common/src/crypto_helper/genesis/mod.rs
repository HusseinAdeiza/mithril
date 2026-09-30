//! Genesis-certificate cryptographic primitives.
//!
//! Groups the Ed25519 and SNARK-friendly (Schnorr over Jubjub) genesis
//! signers, the dual signing/verification-key bundles that pair them, and the wrapped
//! [`GenesisSigner`] and [`GenesisVerifier`] that hide their parsing and selection behind
//! single types.

#[cfg(feature = "snark")]
mod bundles;
mod ed25519;
#[cfg(feature = "snark")]
mod schnorr;
mod signer;
mod verifier;

#[cfg(feature = "snark")]
pub use bundles::*;
pub use ed25519::*;
#[cfg(feature = "snark")]
pub use schnorr::*;
pub use signer::*;
pub use verifier::*;
