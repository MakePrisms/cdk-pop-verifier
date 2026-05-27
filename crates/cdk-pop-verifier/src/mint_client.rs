//! Mint client abstraction used by the PoP validator.
//!
//! The validator confirms a token's structural fit against a
//! [`PopRequirement`][crate::PopRequirement] locally, then calls the issuing
//! mint to perform an atomic swap. A successful swap proves the proofs are
//! unexpired (mint enforces `final_expiry`) and unspent (mint enforces
//! nullifier replay protection), and yields new proofs under the verifier's
//! secrets — PoP is transfer-on-use.
//!
//! This module exposes only the trait + error surface. A concrete
//! `cdk`-backed implementation lands in Commit 4; tests in Commit 3 use a
//! mock impl defined alongside the validator tests.
//!
//! The trait deliberately takes a [`MintUrl`] and [`Proofs`] rather than the
//! decoded [`Token`][cashu::Token] so concrete implementations can fetch
//! mint keyset info up front and feed already-expanded proofs to the swap
//! call. Translating a [`Token`][cashu::Token] into [`Proofs`] is the
//! validator's responsibility.
//!
//! `MintClientError` is intentionally coarse: `Unreachable` for transport
//! failures and `RejectedSwap` for any mint-side refusal. Refining
//! `RejectedSwap` (e.g. distinguishing expired vs. double-spent vs.
//! keyset-rotated) is deferred until the cdk-backed implementation lands
//! and can surface specific NUT-03 error codes.

use async_trait::async_trait;
use cashu::{MintUrl, Proofs};
use thiserror::Error;

/// Abstraction over the calls the validator makes to a Cashu mint.
///
/// Implementations are expected to be `Send + Sync` so the validator can be
/// shared across async tasks (e.g. inside an HTTP handler chain).
#[async_trait]
pub trait MintClient: Send + Sync {
    /// Swap `proofs` at `mint_url` for new proofs held by the verifier.
    ///
    /// The semantics match NUT-03 swap: the mint atomically consumes the
    /// inputs (failing if any are spent, expired, or otherwise invalid) and
    /// returns blinded signatures the verifier unblinds into the returned
    /// [`Proofs`].
    async fn swap(
        &self,
        mint_url: &MintUrl,
        proofs: Proofs,
    ) -> Result<Proofs, MintClientError>;
}

/// Errors returned by [`MintClient`] implementations.
#[derive(Debug, Error)]
pub enum MintClientError {
    /// The mint could not be reached (DNS, TCP, TLS, timeout, etc.).
    #[error("mint unreachable: {0}")]
    Unreachable(String),

    /// The mint reached us but refused the swap (expired credential,
    /// double-spent proof, invalid signature, keyset rotated, etc.).
    #[error("mint rejected swap: {0}")]
    RejectedSwap(String),
}
