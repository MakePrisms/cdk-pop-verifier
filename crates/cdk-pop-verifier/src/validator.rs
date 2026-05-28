//! Swap-at-mint validator for PoP credentials.
//!
//! Given a decoded [`Token`] from a holder retrying a 402-gated request and a
//! [`PopRequirement`] the verifier originally advertised, [`PopValidator`]:
//!
//! 1. Confirms structural fit (unit, mint, amount) without touching the
//!    network.
//! 2. Calls the issuing mint's swap endpoint via [`MintClient`] — a
//!    successful swap is the proof of unspentness *and* of
//!    `final_expiry` not having passed.
//! 3. Returns a [`ValidatedPop`] holding the new proofs the verifier
//!    received from the swap. Per the PoP v1 spec (§4.6) PoP is
//!    transfer-on-use: the verifier keeps the value.
//!
//! Structural checks run first so an obviously-bad token never produces a
//! network round trip to the mint.

use cashu::nuts::nut00::ProofsMethods;
use cashu::{Amount, CurrencyUnit, MintUrl, Proofs, Token};
use thiserror::Error;

use crate::challenge::PopRequirement;
use crate::mint_client::{MintClient, MintClientError};

/// Result of a successful PoP validation.
///
/// `new_proofs` are the proofs the verifier now controls (the mint signed
/// them against blinded outputs the swap call generated). `mint_url`,
/// `unit`, and `amount` echo the validated facts about the original token so
/// callers do not have to re-derive them.
#[derive(Debug, Clone)]
pub struct ValidatedPop {
    /// Proofs returned by the mint's swap response, now under verifier
    /// secrets.
    pub new_proofs: Proofs,
    /// Mint that signed both the original and the new proofs.
    pub mint_url: MintUrl,
    /// Currency unit of the swapped value (matches the
    /// [`PopRequirement`]).
    pub unit: CurrencyUnit,
    /// Total amount of the swapped proofs (sum of `new_proofs.amount`).
    pub amount: Amount,
}

/// Errors a [`PopValidator`] can return.
///
/// Variants split into two groups: structural (`UnitMismatch`,
/// `MintNotAllowed`, `AmountInsufficient`, `TokenEmpty`) — raised before
/// any network call — and mint-mediated (`MintRejectedSwap`,
/// `MintUnreachable`) — raised after the swap attempt.
#[derive(Debug, Error)]
pub enum ValidationError {
    /// Token unit does not match the requirement's unit.
    #[error("token unit {got:?} does not match requirement unit {expected:?}")]
    UnitMismatch {
        /// Unit advertised by the verifier in the challenge.
        expected: CurrencyUnit,
        /// Unit found on the presented token.
        got: CurrencyUnit,
    },

    /// Token was issued by a mint not in the requirement's allowlist.
    #[error("token mint {got} is not in the requirement's allowed mints: {allowed:?}")]
    MintNotAllowed {
        /// Mint URL embedded in the token.
        got: MintUrl,
        /// Mints the verifier explicitly allowed.
        allowed: Vec<MintUrl>,
    },

    /// Token's total proof amount is below the requirement.
    #[error("token amount {got} is below required {required}")]
    AmountInsufficient {
        /// Amount the verifier required in the challenge.
        required: Amount,
        /// Total of all proof amounts in the presented token.
        got: Amount,
    },

    /// Mint accepted the swap call but rejected the proofs (expired
    /// credential, double-spent proof, invalid signature, keyset rotated,
    /// etc.).
    #[error("mint rejected swap: {0}")]
    MintRejectedSwap(String),

    /// Mint could not be reached (DNS, TCP, TLS, timeout, etc.).
    #[error("mint unreachable: {0}")]
    MintUnreachable(String),

    /// Token carried zero proofs — nothing to validate or swap.
    #[error("token contains no proofs")]
    TokenEmpty,

    /// Token internals (proof extraction, value summation, mint-url
    /// parsing) failed before the swap could be attempted.
    #[error("malformed token: {0}")]
    MalformedToken(String),
}

/// Validates PoP tokens against a [`PopRequirement`] by calling the issuing
/// mint's swap endpoint.
///
/// Construct once with a configured [`MintClient`] and reuse for many
/// validations. The validator holds no per-request state.
#[derive(Debug)]
pub struct PopValidator<M: MintClient> {
    mint_client: M,
}

impl<M: MintClient> PopValidator<M> {
    /// Construct a validator backed by the supplied mint client.
    pub fn new(mint_client: M) -> Self {
        Self { mint_client }
    }

    /// Run the full validation pipeline on `token` against `requirement`.
    ///
    /// Structural checks run first; the mint swap is only attempted if the
    /// token is structurally valid. This keeps obviously-bad tokens from
    /// producing network traffic.
    pub async fn validate(
        &self,
        token: &Token,
        requirement: &PopRequirement,
    ) -> Result<ValidatedPop, ValidationError> {
        // Structural: unit.
        //
        // `Token::unit()` returns `Option<CurrencyUnit>` because V3 tokens
        // make the unit optional on the wire. We treat a missing unit as a
        // mismatch — the verifier always advertises one.
        let token_unit = token
            .unit()
            .ok_or_else(|| ValidationError::UnitMismatch {
                expected: requirement.unit.clone(),
                got: CurrencyUnit::Custom(String::new()),
            })?;
        if token_unit != requirement.unit {
            return Err(ValidationError::UnitMismatch {
                expected: requirement.unit.clone(),
                got: token_unit,
            });
        }

        // Structural: mint allowlist.
        //
        // An empty `requirement.mints` means "any mint" — see
        // `PopRequirement` docs. Otherwise the token's mint must be a
        // member.
        let token_mint = token
            .mint_url()
            .map_err(|e| ValidationError::MalformedToken(e.to_string()))?;
        if !requirement.mints.is_empty() && !requirement.mints.contains(&token_mint) {
            return Err(ValidationError::MintNotAllowed {
                got: token_mint,
                allowed: requirement.mints.clone(),
            });
        }

        // Network: fetch keysets for V1 short-id resolution.
        //
        // V0 keyset IDs round-trip locally; V1 short IDs are a 7-byte
        // prefix on the wire and need a full 32-byte ID from the mint's
        // `/v1/keysets` response to expand. We fetch up front so the
        // proof-extraction step below works for both formats. If the
        // mint is unreachable, surface that before the swap call — no
        // point attempting swap when we can't even read the inputs.
        let keysets = self
            .mint_client
            .keysets(&token_mint)
            .await
            .map_err(|e| match e {
                MintClientError::Unreachable(msg) => ValidationError::MintUnreachable(msg),
                MintClientError::RejectedSwap(msg) => ValidationError::MintRejectedSwap(msg),
            })?;

        // Extract proofs against the fetched keyset list. Resolves V1
        // short IDs cleanly; V0 short IDs do not consult the list. If a
        // V1 ID has no matching keyset, this surfaces as MalformedToken
        // (the cashu crate returns `UnknownShortKeysetId`).
        let proofs = token
            .proofs(&keysets)
            .map_err(|e| ValidationError::MalformedToken(e.to_string()))?;

        // Structural: non-empty.
        if proofs.is_empty() {
            return Err(ValidationError::TokenEmpty);
        }

        // Structural: amount.
        //
        // We sum proof amounts directly instead of using `Token::value()`
        // so we can compare against the requirement before any network
        // call. Insufficient amount short-circuits before swap.
        let token_amount = proofs
            .total_amount()
            .map_err(|e| ValidationError::MalformedToken(e.to_string()))?;
        if token_amount < requirement.amount {
            return Err(ValidationError::AmountInsufficient {
                required: requirement.amount,
                got: token_amount,
            });
        }

        // Network: swap at the issuing mint.
        //
        // A successful swap proves both unspentness (nullifier check) and
        // unexpired credential (`final_expiry` check) atomically.
        let new_proofs = self
            .mint_client
            .swap(&token_mint, proofs)
            .await
            .map_err(|e| match e {
                MintClientError::Unreachable(msg) => ValidationError::MintUnreachable(msg),
                MintClientError::RejectedSwap(msg) => ValidationError::MintRejectedSwap(msg),
            })?;

        let new_amount = new_proofs
            .total_amount()
            .map_err(|e| ValidationError::MalformedToken(e.to_string()))?;

        Ok(ValidatedPop {
            new_proofs,
            mint_url: token_mint,
            unit: token_unit,
            amount: new_amount,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use async_trait::async_trait;
    use cashu::dhke::hash_to_curve;
    use cashu::nuts::nut02::{Id, KeySetInfo};
    use cashu::nuts::Proof;
    use cashu::secret::Secret;
    use cashu::{Amount, CurrencyUnit, MintUrl, Proofs, Token};

    use super::{PopValidator, ValidatedPop, ValidationError};
    use crate::challenge::PopRequirement;
    use crate::mint_client::{MintClient, MintClientError};

    /// Canned outcome for the mock [`MintClient::swap`] call.
    enum SwapResponse {
        /// Echo the incoming proofs back as the "new" proofs. Lets tests
        /// assert amount preservation without constructing fresh proofs.
        Echo,
        /// Return [`MintClientError::Unreachable`] with a fixed message.
        Unreachable,
        /// Return [`MintClientError::RejectedSwap`] with a fixed message.
        RejectedSwap,
    }

    /// Canned outcome for the mock [`MintClient::keysets`] call.
    enum KeysetsResponse {
        /// Return the supplied list of [`KeySetInfo`]s.
        Ok(Vec<KeySetInfo>),
        /// Return [`MintClientError::Unreachable`] with a fixed message.
        Unreachable,
    }

    /// Mock [`MintClient`] used in validator unit tests.
    ///
    /// `swap_response` and `keysets_response` are the canned outcomes for
    /// each trait method. `swap_calls` and `keysets_calls` let tests
    /// assert whether and how often each endpoint was actually contacted
    /// (structural failures must short-circuit before any network call).
    struct MockMintClient {
        swap_response: SwapResponse,
        keysets_response: KeysetsResponse,
        swap_calls: Arc<AtomicUsize>,
        keysets_calls: Arc<AtomicUsize>,
    }

    /// Call counters returned by [`MockMintClient::new`] so tests can
    /// observe behaviour without holding a reference to the mock itself.
    #[derive(Clone)]
    struct MockCounters {
        swap: Arc<AtomicUsize>,
        keysets: Arc<AtomicUsize>,
    }

    impl MockMintClient {
        fn new(
            swap_response: SwapResponse,
            keysets_response: KeysetsResponse,
        ) -> (Self, MockCounters) {
            let swap_calls = Arc::new(AtomicUsize::new(0));
            let keysets_calls = Arc::new(AtomicUsize::new(0));
            let counters = MockCounters {
                swap: swap_calls.clone(),
                keysets: keysets_calls.clone(),
            };
            (
                Self {
                    swap_response,
                    keysets_response,
                    swap_calls,
                    keysets_calls,
                },
                counters,
            )
        }

        /// Convenience: build a mock that returns the default empty
        /// keyset list (sufficient for V0-format tokens) and the supplied
        /// swap response.
        fn with_swap(swap_response: SwapResponse) -> (Self, MockCounters) {
            Self::new(swap_response, KeysetsResponse::Ok(Vec::new()))
        }
    }

    #[async_trait]
    impl MintClient for MockMintClient {
        async fn keysets(
            &self,
            _mint_url: &MintUrl,
        ) -> Result<Vec<KeySetInfo>, MintClientError> {
            self.keysets_calls.fetch_add(1, Ordering::SeqCst);
            match &self.keysets_response {
                KeysetsResponse::Ok(infos) => Ok(infos.clone()),
                KeysetsResponse::Unreachable => {
                    Err(MintClientError::Unreachable("mock keysets unreachable".into()))
                }
            }
        }

        async fn swap(
            &self,
            _mint_url: &MintUrl,
            proofs: Proofs,
        ) -> Result<Proofs, MintClientError> {
            self.swap_calls.fetch_add(1, Ordering::SeqCst);
            match self.swap_response {
                SwapResponse::Echo => Ok(proofs),
                SwapResponse::Unreachable => {
                    Err(MintClientError::Unreachable("mock unreachable".into()))
                }
                SwapResponse::RejectedSwap => {
                    Err(MintClientError::RejectedSwap("mock rejected".into()))
                }
            }
        }
    }

    fn pop_unit() -> CurrencyUnit {
        CurrencyUnit::Custom("pop_1700000000".to_string())
    }

    fn mint_a() -> MintUrl {
        MintUrl::from_str("https://mint-a.example.com").expect("valid mint url")
    }

    fn mint_b() -> MintUrl {
        MintUrl::from_str("https://mint-b.example.com").expect("valid mint url")
    }

    /// Build a `Proof` with a deterministic-but-unique C point. The
    /// `index` byte differentiates proofs so `Token` does not flag them as
    /// duplicates.
    fn make_proof(amount: u64, index: u8) -> Proof {
        // V0 keyset id (`00` prefix); `Token::proofs(&[])` round-trips V0
        // short ids without needing KeySetInfo.
        let keyset_id = Id::from_str("009a1f293253e41e").expect("valid v0 keyset id");
        proof_with_keyset(amount, index, keyset_id)
    }

    /// As [`make_proof`] but parameterised by keyset id so tests can mint
    /// V1-format proofs (`01` prefix, 32 bytes of id).
    fn proof_with_keyset(amount: u64, index: u8, keyset_id: Id) -> Proof {
        let mut preimage = [0u8; 33];
        preimage[0] = 1;
        preimage[1] = index;
        let c = hash_to_curve(&preimage).expect("hash_to_curve");
        Proof::new(Amount::from(amount), keyset_id, Secret::generate(), c)
    }

    /// Build a representative V1 keyset id (`01` prefix + 32 bytes).
    /// The bytes are arbitrary — V1 short-id resolution only checks
    /// that the 7-byte token prefix matches the first 7 bytes of the
    /// full id, so any well-formed 32-byte id round-trips through the
    /// token codec.
    fn v1_keyset_id() -> Id {
        Id::from_str(
            "01aabbccddeeff001122334455667788\
              99aabbccddeeff00112233445566778899",
        )
        .expect("valid v1 keyset id")
    }

    /// Build a [`KeySetInfo`] for a V1 id that matches the proofs
    /// produced via [`proof_with_keyset`] with that same id.
    fn keyset_info(id: Id, unit: CurrencyUnit) -> KeySetInfo {
        KeySetInfo {
            id,
            unit,
            active: true,
            input_fee_ppk: 0,
            final_expiry: None,
        }
    }

    fn make_token(mint: MintUrl, unit: CurrencyUnit, proofs: Proofs) -> Token {
        Token::new(mint, proofs, None, unit)
    }

    fn requirement(unit: CurrencyUnit, mints: Vec<MintUrl>, amount: u64) -> PopRequirement {
        PopRequirement {
            unit,
            mints,
            amount: Amount::from(amount),
            payment_id: None,
            description: None,
            single_use: true,
        }
    }

    #[tokio::test]
    async fn validate_happy_path() {
        let proofs = vec![make_proof(8, 0), make_proof(2, 1)];
        let token = make_token(mint_a(), pop_unit(), proofs);
        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) = MockMintClient::with_swap(SwapResponse::Echo);
        let validator = PopValidator::new(mock);

        let ValidatedPop {
            new_proofs,
            mint_url,
            unit,
            amount,
        } = validator
            .validate(&token, &req)
            .await
            .expect("happy-path validation succeeds");

        assert_eq!(
            counters.keysets.load(Ordering::SeqCst),
            1,
            "keysets endpoint must be called once"
        );
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            1,
            "swap endpoint must be called once"
        );
        assert_eq!(mint_url, mint_a());
        assert_eq!(unit, pop_unit());
        assert_eq!(amount, Amount::from(10));
        assert_eq!(new_proofs.len(), 2);
    }

    #[tokio::test]
    async fn validate_rejects_unit_mismatch() {
        let token = make_token(mint_a(), CurrencyUnit::Sat, vec![make_proof(10, 0)]);
        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) = MockMintClient::with_swap(SwapResponse::Echo);
        let validator = PopValidator::new(mock);

        let err = validator
            .validate(&token, &req)
            .await
            .expect_err("unit mismatch must fail");
        assert!(
            matches!(err, ValidationError::UnitMismatch { .. }),
            "expected UnitMismatch, got {err:?}"
        );
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            0,
            "swap must NOT be called on unit mismatch"
        );
        assert_eq!(
            counters.keysets.load(Ordering::SeqCst),
            0,
            "keysets must NOT be called on unit mismatch"
        );
    }

    #[tokio::test]
    async fn validate_rejects_disallowed_mint() {
        // Token issued by mint_b, requirement only allows mint_a.
        let token = make_token(mint_b(), pop_unit(), vec![make_proof(10, 0)]);
        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) = MockMintClient::with_swap(SwapResponse::Echo);
        let validator = PopValidator::new(mock);

        let err = validator
            .validate(&token, &req)
            .await
            .expect_err("disallowed mint must fail");
        assert!(
            matches!(err, ValidationError::MintNotAllowed { .. }),
            "expected MintNotAllowed, got {err:?}"
        );
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            0,
            "swap must NOT be called on mint-allowlist failure"
        );
        assert_eq!(
            counters.keysets.load(Ordering::SeqCst),
            0,
            "keysets must NOT be called on mint-allowlist failure"
        );
    }

    #[tokio::test]
    async fn validate_rejects_insufficient_amount() {
        // Token totals 5, requirement asks for 10.
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(2, 0), make_proof(3, 1)]);
        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) = MockMintClient::with_swap(SwapResponse::Echo);
        let validator = PopValidator::new(mock);

        let err = validator
            .validate(&token, &req)
            .await
            .expect_err("insufficient amount must fail");
        assert!(
            matches!(err, ValidationError::AmountInsufficient { .. }),
            "expected AmountInsufficient, got {err:?}"
        );
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            0,
            "swap must NOT be called on insufficient amount"
        );
    }

    #[tokio::test]
    async fn validate_rejects_empty_token() {
        let token = make_token(mint_a(), pop_unit(), vec![]);
        let req = requirement(pop_unit(), vec![mint_a()], 1);

        let (mock, counters) = MockMintClient::with_swap(SwapResponse::Echo);
        let validator = PopValidator::new(mock);

        let err = validator
            .validate(&token, &req)
            .await
            .expect_err("empty token must fail");
        assert!(
            matches!(err, ValidationError::TokenEmpty),
            "expected TokenEmpty, got {err:?}"
        );
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            0,
            "swap must NOT be called on empty token"
        );
    }

    #[tokio::test]
    async fn validate_propagates_mint_unreachable() {
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) = MockMintClient::with_swap(SwapResponse::Unreachable);
        let validator = PopValidator::new(mock);

        let err = validator
            .validate(&token, &req)
            .await
            .expect_err("unreachable mint must fail");
        assert!(
            matches!(err, ValidationError::MintUnreachable(_)),
            "expected MintUnreachable, got {err:?}"
        );
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            1,
            "swap must be called once before unreachable surfaces"
        );
    }

    #[tokio::test]
    async fn validate_propagates_mint_rejected_swap() {
        // This is the case where `final_expiry` has passed or a nullifier
        // collided (double-spend).
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) = MockMintClient::with_swap(SwapResponse::RejectedSwap);
        let validator = PopValidator::new(mock);

        let err = validator
            .validate(&token, &req)
            .await
            .expect_err("rejected swap must fail");
        assert!(
            matches!(err, ValidationError::MintRejectedSwap(_)),
            "expected MintRejectedSwap, got {err:?}"
        );
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            1,
            "swap must be called once before rejection surfaces"
        );
    }

    #[tokio::test]
    async fn validate_happy_path_v1_keyset() {
        // Synthesize a V1-format token: proofs whose keyset id has the
        // `01` version byte. On the wire the token serializes the id as
        // a 7-byte short id; decoding back into proofs needs the matching
        // full 32-byte `KeySetInfo` from the mint's keysets endpoint.
        let v1_id = v1_keyset_id();
        let proofs = vec![
            proof_with_keyset(7, 0, v1_id),
            proof_with_keyset(3, 1, v1_id),
        ];
        // Round-trip the token through encode/decode so the proofs lose
        // their full id and force the validator to resolve via keysets().
        let token_str = make_token(mint_a(), pop_unit(), proofs).to_string();
        let token = Token::from_str(&token_str).expect("v1 token round-trips");

        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) = MockMintClient::new(
            SwapResponse::Echo,
            KeysetsResponse::Ok(vec![keyset_info(v1_id, pop_unit())]),
        );
        let validator = PopValidator::new(mock);

        let ValidatedPop { amount, .. } = validator
            .validate(&token, &req)
            .await
            .expect("v1 happy path validates");
        assert_eq!(amount, Amount::from(10));
        assert_eq!(counters.keysets.load(Ordering::SeqCst), 1);
        assert_eq!(counters.swap.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn validate_propagates_keysets_unreachable() {
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) =
            MockMintClient::new(SwapResponse::Echo, KeysetsResponse::Unreachable);
        let validator = PopValidator::new(mock);

        let err = validator
            .validate(&token, &req)
            .await
            .expect_err("keysets-unreachable must fail");
        assert!(
            matches!(err, ValidationError::MintUnreachable(_)),
            "expected MintUnreachable, got {err:?}"
        );
        assert_eq!(
            counters.keysets.load(Ordering::SeqCst),
            1,
            "keysets must be called once before unreachable surfaces"
        );
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            0,
            "swap must NOT be called when keysets() failed"
        );
    }

    #[tokio::test]
    async fn validate_rejects_v1_token_with_no_matching_keyset() {
        // V1 token but the mint returns an empty keysets list — the
        // 7-byte short id cannot be resolved into a full id, so proof
        // extraction surfaces as MalformedToken. Swap must not be
        // attempted: we cannot construct a swap request without proofs.
        let v1_id = v1_keyset_id();
        let proofs = vec![proof_with_keyset(10, 0, v1_id)];
        let token_str = make_token(mint_a(), pop_unit(), proofs).to_string();
        let token = Token::from_str(&token_str).expect("v1 token round-trips");

        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) =
            MockMintClient::new(SwapResponse::Echo, KeysetsResponse::Ok(Vec::new()));
        let validator = PopValidator::new(mock);

        let err = validator
            .validate(&token, &req)
            .await
            .expect_err("no-matching-keyset must fail");
        assert!(
            matches!(err, ValidationError::MalformedToken(_)),
            "expected MalformedToken, got {err:?}"
        );
        assert_eq!(
            counters.keysets.load(Ordering::SeqCst),
            1,
            "keysets must be called"
        );
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            0,
            "swap must NOT be called when no proofs can be extracted"
        );
    }
}
