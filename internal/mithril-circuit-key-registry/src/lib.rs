//! Genesis-signed registry of the circuit verification keys trusted for SNARK certificates.
//!
//! The registry holds one entry per circuit verification key digest, allowed over an inclusive
//! epoch range or revoked, e.g. after a circuit vulnerability. It is published in the repository
//! per network, retrieved at runtime and verified against the Ed25519 half of the genesis
//! verification key before use.

#![warn(missing_docs)]

#[cfg(feature = "snark")]
mod certifier;
#[cfg(feature = "snark")]
mod http_downloader;
#[cfg(feature = "snark")]
mod registry;
#[cfg(feature = "snark")]
mod retriever;
#[cfg(feature = "snark")]
pub mod test;

#[cfg(feature = "snark")]
pub use certifier::*;
#[cfg(feature = "snark")]
pub use http_downloader::*;
#[cfg(feature = "snark")]
pub use registry::*;
#[cfg(feature = "snark")]
pub use retriever::*;
