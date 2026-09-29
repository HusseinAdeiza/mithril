//! This example shows how to implement a Mithril client and use its features.
//!
//! In this example, the client interacts with an aggregator whose URL must be specified in the command to get the data.

use anyhow::anyhow;
use chrono::TimeDelta;
use clap::Parser;
use slog::info;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;

use mithril_client::certificate_client::{
    CertificateVerifierCache, CertificateVerifierCacheMode, FileCertificateVerifierCache,
};
use mithril_client::common::BlockHash;
use mithril_client::{
    AggregatorDiscoveryType, ClientBuilder, GenesisVerificationKey, MessageBuilder, MithrilResult,
    VerifiedCardanoBlocks,
};

#[derive(Parser, Debug)]
#[command(version)]
pub struct Args {
    /// Genesis verification key.
    #[clap(
        long,
        env = "GENESIS_VERIFICATION_KEY",
        default_value = "5b3132372c37332c3132342c3136312c362c3133372c3133312c3231332c3230372c3131372c3139382c38352c3137362c3139392c3136322c3234312c36382c3132332c3131392c3134352c31332c3233322c3234332c34392c3232392c322c3234392c3230352c3230352c33392c3233352c34345d"
    )]
    genesis_verification_key: String,

    /// Aggregator endpoint URL.
    ///
    /// Either:
    /// - Full URL of the aggregator endpoint (e.g., "https://aggregator.testing-preview.api.mithril.network/aggregator").
    /// - "auto:<mithril_network>" to use automatic discovery (e.g., "auto:testing-preview") (unstable).
    #[clap(
        long,
        env = "AGGREGATOR_ENDPOINT",
        default_value = "https://aggregator.testing-preview.api.mithril.network/aggregator"
    )]
    aggregator_endpoint: String,

    /// Hashes of the blocks to certify.
    #[clap(value_delimiter = ',', required = true)]
    blocks_hashes: Vec<String>,

    /// Use the certificate chain cache to verify the certificate chain.
    #[clap(long)]
    use_certificate_chain_cache: bool,

    /// Verification mode of the certificate chain when the cache is used.
    ///
    /// Either "FullVerification" (cached certificates are re-verified) or "EarlyStopVerification"
    /// (the verification stops at the first cached certificate).
    #[clap(long, default_value_t, requires = "use_certificate_chain_cache")]
    certificate_chain_cache_mode: CertificateVerifierCacheMode,

    /// Directory of the certificate chain cache.
    #[clap(
        long,
        default_value = "./certificate-chain-cache",
        requires = "use_certificate_chain_cache"
    )]
    certificate_chain_cache_path: PathBuf,
}

impl Args {
    /// Time a verified certificate stays in the certificate chain cache.
    const CERTIFICATE_CHAIN_CACHE_EXPIRATION_DELAY: TimeDelta = TimeDelta::weeks(1);

    /// File system certificate chain cache stored in the configured directory, if enabled.
    fn certificate_verifier_cache(&self) -> Option<Arc<dyn CertificateVerifierCache>> {
        self.use_certificate_chain_cache.then(|| {
            let cache: Arc<dyn CertificateVerifierCache> =
                Arc::new(FileCertificateVerifierCache::new(
                    &self.certificate_chain_cache_path,
                    Self::CERTIFICATE_CHAIN_CACHE_EXPIRATION_DELAY,
                ));
            cache
        })
    }
}

#[tokio::main]
async fn main() -> MithrilResult<()> {
    let args = Args::parse();
    let blocks_hashes = &args.blocks_hashes.iter().map(|s| s.as_str()).collect::<Vec<&str>>();
    let logger = build_logger();
    let client = ClientBuilder::new(AggregatorDiscoveryType::from_str(
        &args.aggregator_endpoint,
    )?)
    .set_genesis_verification_key(GenesisVerificationKey::JsonHex(
        args.genesis_verification_key.clone(),
    ))
    .with_origin_tag(Some("EXAMPLE".to_string()))
    .with_certificate_verifier_cache(
        args.certificate_verifier_cache(),
        args.certificate_chain_cache_mode,
    )
    .with_logger(logger.clone())
    .build()?;

    info!(logger, "Fetching a proof for the given blocks...",);
    let cardano_block_proof = client.cardano_block().get_proof(blocks_hashes).await?;

    info!(logger, "Verifying the proof…",);
    let verified_blocks = cardano_block_proof.verify().unwrap();

    info!(
        logger,
        "Fetching the associated certificate and verifying the certificate chain…",
    );
    let certificate_chain_verification_start = Instant::now();
    let certificate = client
        .certificate()
        .verify_chain(&cardano_block_proof.certificate_hash)
        .await?;
    info!(
        logger,
        "Certificate chain verified in {:?} (certificate chain cache enabled: {})",
        certificate_chain_verification_start.elapsed(),
        args.use_certificate_chain_cache,
    );

    info!(
        logger,
        "Verify that the proof is signed in the associated certificate",
    );
    let message =
        MessageBuilder::new().compute_cardano_blocks_proofs_message(&certificate, &verified_blocks);
    if !certificate.match_message(&message) {
        return Err(anyhow!(
            "Proof and certificate don't match (certificate hash = '{}').",
            certificate.hash
        ));
    }

    log_certify_information(&verified_blocks, &cardano_block_proof.non_certified_blocks);

    Ok(())
}

pub fn log_certify_information(
    verified_blocks: &VerifiedCardanoBlocks,
    non_certified_blocks: &[BlockHash],
) {
    if !verified_blocks.certified_blocks().is_empty() {
        println!("Following Cardano blocks have been successfully certified by Mithril.");
        for block in verified_blocks.certified_blocks() {
            println!(
                r###"- block hash '{}', block number '{}', block slot '{}', block depth '{}'"###,
                block.block_hash,
                block.block_number,
                block.slot_number,
                verified_blocks.security_parameter()
            );
        }
    }

    if !non_certified_blocks.is_empty() {
        println!(
            r###"No proof could be computed for Cardano blocks with hashes "'{}'".
            
            Mithril may not have signed those blocks yet, please try again later."###,
            non_certified_blocks.join(","),
        );
    }
}

fn build_logger() -> slog::Logger {
    use slog::Drain;

    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    slog::Logger::root(Arc::new(drain), slog::o!())
}
