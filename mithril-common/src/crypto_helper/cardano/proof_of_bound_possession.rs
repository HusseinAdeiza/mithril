use mithril_stm::ProofOfBoundPossessionPrefixBytes;
use sha2::{Digest, Sha256};

use crate::{
    crypto_helper::ProtocolPartyIdBytes,
    entities::{Epoch, Stake},
};

/// Structure representing the information needed to create a prefix
/// for the Proof of Bound Possession (PoBP).
/// It is used to compute the hash value signed for the PoBP :
/// H(DST || prefix || vk)
pub(crate) struct ProofOfBoundPossessionPrefix {
    stake: Stake,
    epoch: Epoch,
    pool_id: ProtocolPartyIdBytes,
}

impl ProofOfBoundPossessionPrefix {
    pub(crate) fn new(stake: Stake, epoch: Epoch, pool_id: ProtocolPartyIdBytes) -> Self {
        Self {
            stake,
            epoch,
            pool_id,
        }
    }

    /// Converts a Proof of Bound Possession challenge into prefix bytes
    /// in the form:
    /// stake || epoch || pool_id
    /// and hash it to a fix 32 bytes using Sha256
    pub(crate) fn to_prefix_bytes(&self) -> ProofOfBoundPossessionPrefixBytes {
        let mut hasher = Sha256::new();
        hasher.update(self.stake.to_be_bytes());
        hasher.update(self.epoch.to_be_bytes());
        hasher.update(self.pool_id);
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn different_stakes_produce_different_bytes() {
        let a = ProofOfBoundPossessionPrefix::new(100u64, Epoch(5), [1u8; 28]);
        let b = ProofOfBoundPossessionPrefix::new(200u64, Epoch(5), [1u8; 28]);

        assert_ne!(a.to_prefix_bytes(), b.to_prefix_bytes());
    }

    #[test]
    fn different_epochs_produce_different_bytes() {
        let a = ProofOfBoundPossessionPrefix::new(100u64, Epoch(5), [1u8; 28]);
        let b = ProofOfBoundPossessionPrefix::new(100u64, Epoch(6), [1u8; 28]);

        assert_ne!(a.to_prefix_bytes(), b.to_prefix_bytes());
    }

    #[test]
    fn different_pool_ids_produce_different_bytes() {
        let a = ProofOfBoundPossessionPrefix::new(100u64, Epoch(5), [1u8; 28]);
        let b = ProofOfBoundPossessionPrefix::new(100u64, Epoch(5), [2u8; 28]);

        assert_ne!(a.to_prefix_bytes(), b.to_prefix_bytes());
    }

    mod golden {
        use super::*;

        const GOLDEN_BYTES_POOLID_ONE: [u8; 32] = [
            153, 124, 96, 77, 74, 221, 239, 181, 44, 130, 1, 249, 100, 105, 126, 212, 46, 155, 215,
            162, 85, 188, 57, 236, 180, 157, 60, 203, 211, 222, 45, 230,
        ];

        const GOLDEN_BYTES_POOLID_ZERO: [u8; 32] = [
            128, 35, 52, 100, 62, 68, 161, 195, 86, 228, 199, 215, 239, 96, 105, 234, 185, 14, 205,
            179, 188, 33, 160, 69, 52, 173, 122, 19, 206, 112, 205, 164,
        ];

        #[test]
        fn golden_to_prefix_bytes_all_one_pool_id() {
            let prefix = ProofOfBoundPossessionPrefix::new(100u64, Epoch(5), [1u8; 28]);

            let bytes = prefix.to_prefix_bytes();

            assert_eq!(GOLDEN_BYTES_POOLID_ONE, bytes);
        }

        #[test]
        fn golden_to_prefix_bytes_all_zero_pool_id() {
            let prefix = ProofOfBoundPossessionPrefix::new(100u64, Epoch(5), [0u8; 28]);

            let bytes = prefix.to_prefix_bytes();

            assert_eq!(GOLDEN_BYTES_POOLID_ZERO, bytes);
        }
    }
}
