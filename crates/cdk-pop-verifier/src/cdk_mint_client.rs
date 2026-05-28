//! Real `cdk`-backed [`MintClient`] implementation.
//!
//! Wraps [`cdk::wallet::HttpClient`] — the same HTTP surface the cdk
//! wallet uses to talk to a mint — and exposes only the two endpoints
//! the PoP validator needs: NUT-02 `/v1/keysets` and NUT-03 `/v1/swap`.
//!
//! A fresh [`cdk::wallet::HttpClient`] is constructed per call. Mints
//! are addressed by the [`MintUrl`] passed in; the validator (or its
//! caller) decides which mint to talk to per token, so caching a
//! pinned client on this struct would be wrong.
//!
//! **Error mapping.** `cdk::Error` is a large enum covering wallet
//! storage, signatures, parsing, transport, and mint responses. We
//! collapse it into the coarse [`MintClientError`] split the
//! validator cares about:
//!
//! * [`cdk::Error::is_definitive_failure`] true → [`MintClientError::RejectedSwap`]
//!   (HTTP 4xx, crypto/parse errors, anything the mint definitely
//!   refused on its end).
//! * False → [`MintClientError::Unreachable`] (HTTP 5xx, transport,
//!   timeout, ambiguous network condition). Re-trying may succeed.
//!
//! **Swap ceremony.** Hand-rolled (no `Wallet` localstore needed):
//!
//! 1. Fetch active V1-unit keyset via `MintConnector::get_mint_keysets`.
//! 2. Fetch its [`Keys`] via `MintConnector::get_mint_keyset`.
//! 3. Build [`PreMintSecrets`] for the total input amount split into
//!    powers-of-two against the keyset's signing denominations.
//! 4. POST the [`SwapRequest`] (inputs + blinded outputs) to the mint.
//! 5. Unblind the returned signatures with
//!    [`cashu::dhke::construct_proofs`] into [`Proofs`] under fresh
//!    verifier-owned secrets.
//!
//! The implementation assumes a zero-fee keyset (pop_<ts> credentials
//! per the v1 spec). A non-zero `input_fee_ppk` would require pulling
//! a fee amount off the swap output total; not wired here because PoP
//! v1 fixes fees at 0.

use async_trait::async_trait;
use cashu::amount::{FeeAndAmounts, SplitTarget};
use cashu::dhke::construct_proofs;
use cashu::nuts::nut00::PreMintSecrets;
use cashu::nuts::nut02::{KeySetInfo, KeySetInfosMethods};
use cashu::nuts::nut03::SwapRequest;
use cashu::nuts::ProofsMethods;
use cashu::{MintUrl, Proofs};
use cdk::wallet::{HttpClient, MintConnector};

use crate::mint_client::{MintClient, MintClientError};

/// `cdk`-backed [`MintClient`].
///
/// Holds no state — every call builds a fresh
/// [`cdk::wallet::HttpClient`] for the supplied [`MintUrl`]. Stateless
/// design keeps the validator free to talk to many mints without a
/// per-mint registration step.
#[derive(Debug, Default, Clone, Copy)]
pub struct CdkMintClient;

impl CdkMintClient {
    /// Construct a fresh client. Costs nothing; the actual
    /// [`HttpClient`] is built per request inside the trait methods.
    pub fn new() -> Self {
        Self
    }

    /// Build the per-mint [`HttpClient`] used to issue HTTP calls.
    /// Kept private so callers cannot accidentally hold onto an
    /// HttpClient pinned to one mint.
    fn http(mint_url: &MintUrl) -> HttpClient {
        HttpClient::new(mint_url.clone(), None)
    }
}

/// Translate a [`cdk::Error`] into the coarse [`MintClientError`]
/// the validator understands. Uses `is_definitive_failure` as the
/// split point (4xx and parse/crypto errors → rejected;
/// 5xx/timeout/transport → unreachable).
fn map_cdk_err(e: cdk::Error) -> MintClientError {
    if e.is_definitive_failure() {
        MintClientError::RejectedSwap(e.to_string())
    } else {
        MintClientError::Unreachable(e.to_string())
    }
}

#[async_trait]
impl MintClient for CdkMintClient {
    async fn keysets(
        &self,
        mint_url: &MintUrl,
    ) -> Result<Vec<KeySetInfo>, MintClientError> {
        let client = Self::http(mint_url);
        let response = client.get_mint_keysets().await.map_err(map_cdk_err)?;
        Ok(response.keysets)
    }

    async fn swap(
        &self,
        mint_url: &MintUrl,
        proofs: Proofs,
    ) -> Result<Proofs, MintClientError> {
        if proofs.is_empty() {
            // Defensive: the validator should never call swap with no
            // proofs (it short-circuits on TokenEmpty), but a zero-input
            // swap would be malformed at the mint anyway. Surface as
            // RejectedSwap rather than make a wasted call.
            return Err(MintClientError::RejectedSwap(
                "cannot swap empty proof set".to_string(),
            ));
        }

        let client = Self::http(mint_url);

        // Resolve the active keyset for the unit carried on the input
        // proofs. All inputs are assumed to share a unit (the validator
        // already verified that against the requirement upstream).
        let input_keyset_id = proofs[0].keyset_id;
        let keysets = client.get_mint_keysets().await.map_err(map_cdk_err)?;

        // For the output keyset we prefer the mint's currently-active
        // keyset for the same unit. The input keyset may have rotated
        // (signed by it but no longer active for new outputs).
        let input_unit = keysets
            .keysets
            .iter()
            .find(|k| k.id == input_keyset_id)
            .map(|k| k.unit.clone())
            .ok_or_else(|| {
                MintClientError::RejectedSwap(format!(
                    "input keyset {input_keyset_id} unknown at mint"
                ))
            })?;

        let active_keyset = keysets
            .keysets
            .active()
            .find(|k| k.unit == input_unit)
            .ok_or_else(|| {
                MintClientError::RejectedSwap(format!(
                    "no active keyset at mint for unit {input_unit:?}"
                ))
            })?
            .clone();

        // Fetch signing keys for the active keyset so we can unblind
        // the swap response into proofs.
        let active_keyset_full = client
            .get_mint_keyset(active_keyset.id)
            .await
            .map_err(map_cdk_err)?;

        // Sum the inputs — outputs must sum to the same value (PoP v1
        // is zero-fee; we surface a RejectedSwap if a non-zero
        // input_fee_ppk shows up because that violates the v1 spec).
        if active_keyset.input_fee_ppk != 0 {
            return Err(MintClientError::RejectedSwap(format!(
                "active keyset {} has non-zero input_fee_ppk; PoP v1 requires zero fee",
                active_keyset.id
            )));
        }
        let total = proofs
            .total_amount()
            .map_err(|e| MintClientError::RejectedSwap(e.to_string()))?;

        // FeeAndAmounts drives the power-of-two split; the amounts list
        // must come from the keyset's signing denominations so we only
        // request outputs the mint can sign. Sorted ascending.
        // `Keys::keys()` returns `&BTreeMap<Amount, _>` — already
        // sorted ascending by `Amount` (which is `Ord` by value), so
        // iterating its keys hands us the canonical denomination list.
        let signing_amounts: Vec<u64> = active_keyset_full
            .keys
            .keys()
            .keys()
            .map(|a| u64::from(*a))
            .collect();
        let fee_and_amounts: FeeAndAmounts = (0u64, signing_amounts).into();

        // Generate blinded outputs against the active keyset id with
        // fresh verifier secrets.
        let pre_mint = PreMintSecrets::random(
            active_keyset.id,
            total,
            &SplitTarget::None,
            &fee_and_amounts,
        )
        .map_err(|e| MintClientError::RejectedSwap(e.to_string()))?;

        let swap_request = SwapRequest::new(proofs, pre_mint.blinded_messages());

        let response = client.post_swap(swap_request).await.map_err(map_cdk_err)?;

        // Unblind: combine the mint's signatures with our blinding
        // factors and secrets to produce spendable proofs.
        let new_proofs = construct_proofs(
            response.signatures,
            pre_mint.rs(),
            pre_mint.secrets(),
            &active_keyset_full.keys,
        )
        .map_err(|e| MintClientError::RejectedSwap(e.to_string()))?;

        Ok(new_proofs)
    }
}
