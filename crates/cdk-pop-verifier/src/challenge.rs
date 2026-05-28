//! NUT-24 challenge encode + token decode helpers.
//!
//! `PopRequirement` is the verifier-side description of what a holder must
//! present: a Cashu mint set, unit, amount and metadata. `encode_challenge`
//! serializes it into the `creqA...` string the server uses inside the
//! draft-httpauth-payment-00 `request` auth-param on the 402 response.
//! `decode_token` parses the `cashuB...` token the client returns inside
//! the credentials payload on retry.
//!
//! Transports are intentionally left empty: NUT-24 is in-band over HTTP, so
//! no separate Nostr/HTTPS transport hop is advertised. `nut10` is left
//! `None`: PoP v1 is bearer (no spend lock).
//!
//! `PopRequirement.unit` is expected to be `CurrencyUnit::Custom("pop_<ts>")`
//! for PoP credentials, but this module does not enforce the prefix — it
//! only round-trips whatever unit the caller supplies.
//!
//! ## Request envelope
//!
//! draft-httpauth-payment-00 §5.1.1 requires the `request` auth-param to be
//! a base64url-nopad-encoded JSON blob. For the cashu method we wrap our
//! NUT-18 `creqA…` string inside that JSON as a single `cashu_request`
//! field. [`encode_request_envelope`] does the wrap; the client unwraps
//! it after base64url-decoding the auth-param value.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use cashu::nuts::nut18::PaymentRequest;
use cashu::nuts::CurrencyUnit;
use cashu::{Amount, MintUrl, Token};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::error::Error;

/// What the verifier requires from a holder for a single PoP challenge.
///
/// Maps 1:1 onto the NUT-18 `PaymentRequest` fields the verifier cares
/// about. `single_use` is forwarded as-is; the verifier is responsible for
/// enforcing replay semantics — this module does not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PopRequirement {
    /// Currency unit the proofs must carry. For PoP this is
    /// `CurrencyUnit::Custom("pop_<unix_ts>")` where `<unix_ts>` is the
    /// CLTV expiry of the credential.
    pub unit: CurrencyUnit,
    /// Mints the verifier accepts. Empty means "any mint" — callers that
    /// want a closed set must populate this.
    pub mints: Vec<MintUrl>,
    /// Exact amount of proofs required.
    pub amount: Amount,
    /// Optional payment correlation id (NUT-18 `i`).
    pub payment_id: Option<String>,
    /// Optional human-readable description (NUT-18 `d`).
    pub description: Option<String>,
    /// Whether the challenge is one-shot. Forwarded to NUT-18 `s`.
    pub single_use: bool,
}

impl PopRequirement {
    /// Construct the underlying NUT-18 `PaymentRequest` with no transports
    /// (NUT-24 in-band) and no NUT-10 spending conditions (bearer v1).
    fn to_payment_request(&self) -> PaymentRequest {
        PaymentRequest {
            payment_id: self.payment_id.clone(),
            amount: Some(self.amount),
            unit: Some(self.unit.clone()),
            single_use: Some(self.single_use),
            mints: self.mints.clone(),
            description: self.description.clone(),
            transports: vec![],
            nut10: None,
        }
    }
}

/// Encode a `PopRequirement` into the `creqA...` string that becomes the
/// `cashu_request` field inside the draft-httpauth-payment-00 `request`
/// auth-param on a 402 response.
///
/// Cannot fail: NUT-18 CBOR + base64url encoding of these fields is
/// infallible in `cashu` 0.16.
pub fn encode_challenge(req: &PopRequirement) -> String {
    req.to_payment_request().to_string()
}

/// JSON envelope carried inside the WWW-Authenticate `request`
/// auth-param. draft-httpauth-payment-00 §5.1.1 mandates a
/// base64url-nopad-encoded JSON object for this parameter; for the
/// cashu method we put the NUT-18 `creqA…` string in a single
/// `cashu_request` field.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RequestEnvelope {
    cashu_request: String,
}

/// Wrap a NUT-18 `creqA…` string in the draft-httpauth-payment-00
/// `request` envelope and base64url-nopad-encode it.
///
/// The returned string is what goes inside the `request="…"` auth-param
/// of `WWW-Authenticate: Payment`. Cannot fail.
pub fn encode_request_envelope(creq_a: &str) -> String {
    let envelope = RequestEnvelope {
        cashu_request: creq_a.to_string(),
    };
    let json = serde_json::to_string(&envelope)
        .expect("RequestEnvelope always serializes");
    URL_SAFE_NO_PAD.encode(json.as_bytes())
}

/// Unwrap the base64url-nopad-encoded `request` envelope and return the
/// inner `cashu_request` string (which should be a `creqA…` NUT-18
/// payment-request).
///
/// Returns an error if the envelope cannot be base64-decoded, is not
/// valid UTF-8/JSON, or lacks the `cashu_request` field. Provided for
/// symmetry + downstream client use; the middleware does not call this.
pub fn decode_request_envelope(b64: &str) -> Result<String, Error> {
    let bytes = URL_SAFE_NO_PAD
        .decode(b64.trim())
        .map_err(|e| Error::DecodeFailed(format!("request envelope base64: {e}")))?;
    let envelope: RequestEnvelope = serde_json::from_slice(&bytes)
        .map_err(|e| Error::DecodeFailed(format!("request envelope json: {e}")))?;
    Ok(envelope.cashu_request)
}

/// Decode the `X-Cashu` header value carrying a `cashuB...` token on a
/// client retry.
///
/// Returns `InvalidHeader` when the value lacks a recognized cashu token
/// prefix, `DecodeFailed` when the payload itself is malformed.
pub fn decode_token(x_cashu_header: &str) -> Result<Token, Error> {
    let trimmed = x_cashu_header.trim();
    if !(trimmed.starts_with("cashuA") || trimmed.starts_with("cashuB")) {
        return Err(Error::InvalidHeader(format!(
            "expected cashuA/cashuB prefix, got {:?}",
            trimmed.chars().take(8).collect::<String>()
        )));
    }
    Token::from_str(trimmed).map_err(|e| Error::DecodeFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_requirement() -> PopRequirement {
        PopRequirement {
            unit: CurrencyUnit::Custom("pop_1700000000".to_string()),
            mints: vec![
                MintUrl::from_str("https://mint1.example.com").expect("valid mint url"),
                MintUrl::from_str("https://mint2.example.com").expect("valid mint url"),
            ],
            amount: Amount::from(42),
            payment_id: Some("pop-test-id".to_string()),
            description: Some("test challenge".to_string()),
            single_use: true,
        }
    }

    #[test]
    fn encode_challenge_has_creqa_prefix() {
        let req = sample_requirement();
        let encoded = encode_challenge(&req);
        assert!(
            encoded.starts_with("creqA"),
            "expected creqA prefix, got {}",
            &encoded[..encoded.len().min(16)]
        );
    }

    #[test]
    fn encode_challenge_roundtrips_through_payment_request() {
        let req = sample_requirement();
        let encoded = encode_challenge(&req);

        let parsed = PaymentRequest::from_str(&encoded).expect("decodes as PaymentRequest");

        assert_eq!(parsed.payment_id, req.payment_id);
        assert_eq!(parsed.amount, Some(req.amount));
        assert_eq!(parsed.unit, Some(req.unit.clone()));
        assert_eq!(parsed.single_use, Some(req.single_use));
        assert_eq!(parsed.mints, req.mints);
        assert_eq!(parsed.description, req.description);
        assert!(
            parsed.transports.is_empty(),
            "NUT-24 in-band: transports must be empty"
        );
        assert!(parsed.nut10.is_none(), "PoP v1 bearer: nut10 must be None");
    }

    #[test]
    fn encode_challenge_preserves_pop_custom_unit() {
        // The "pop_<ts>" custom unit must survive the CBOR round-trip
        // unchanged — the verifier later parses the timestamp out of it.
        let req = PopRequirement {
            unit: CurrencyUnit::Custom("pop_1700000000".to_string()),
            mints: vec![],
            amount: Amount::from(1),
            payment_id: None,
            description: None,
            single_use: false,
        };
        let parsed = PaymentRequest::from_str(&encode_challenge(&req)).unwrap();
        assert_eq!(
            parsed.unit,
            Some(CurrencyUnit::Custom("pop_1700000000".to_string()))
        );
    }

    /// `cashuB` test vector lifted from cashu-0.16.0
    /// `nuts::nut00::token::tests` so we exercise a real token without
    /// pulling in additional fixtures.
    const VALID_CASHU_B: &str = "cashuBpGF0gaJhaUgArSaMTR9YJmFwgaNhYQFhc3hAOWE2ZGJiODQ3YmQyMzJiYTc2ZGIwZGYxOTcyMTZiMjlkM2I4Y2MxNDU1M2NkMjc4MjdmYzFjYzk0MmZlZGI0ZWFjWCEDhhhUP_trhpXfStS6vN6So0qWvc2X3O4NfM-Y1HISZ5JhZGlUaGFuayB5b3VhbXVodHRwOi8vbG9jYWxob3N0OjMzMzhhdWNzYXQ=";

    #[test]
    fn decode_token_accepts_valid_cashub() {
        let token = decode_token(VALID_CASHU_B).expect("decodes valid cashuB token");
        // Sanity: re-encoding yields a cashuB string again.
        let reencoded = token.to_string();
        assert!(
            reencoded.starts_with("cashuB"),
            "expected cashuB roundtrip, got {}",
            &reencoded[..reencoded.len().min(8)]
        );
    }

    #[test]
    fn decode_token_trims_whitespace() {
        let padded = format!("  {VALID_CASHU_B}\n");
        decode_token(&padded).expect("trimmed whitespace decodes");
    }

    #[test]
    fn decode_token_rejects_unknown_prefix() {
        let err = decode_token("notatoken").expect_err("should reject unknown prefix");
        assert!(
            matches!(err, Error::InvalidHeader(_)),
            "expected InvalidHeader, got {err:?}"
        );
    }

    #[test]
    fn decode_token_rejects_empty_input() {
        let err = decode_token("").expect_err("should reject empty input");
        assert!(matches!(err, Error::InvalidHeader(_)));
    }

    #[test]
    fn decode_token_rejects_malformed_cashub_payload() {
        // Valid prefix, garbage payload — must surface as DecodeFailed,
        // not InvalidHeader.
        let err = decode_token("cashuB!!!notbase64!!!")
            .expect_err("malformed payload should fail to decode");
        assert!(
            matches!(err, Error::DecodeFailed(_)),
            "expected DecodeFailed, got {err:?}"
        );
    }

    #[test]
    fn request_envelope_roundtrips() {
        let req = sample_requirement();
        let creq = encode_challenge(&req);
        let envelope = encode_request_envelope(&creq);
        let unwrapped = decode_request_envelope(&envelope)
            .expect("request envelope round-trips");
        assert_eq!(unwrapped, creq);
    }

    #[test]
    fn request_envelope_is_base64url_nopad() {
        let envelope = encode_request_envelope("creqAdummy");
        // base64url-nopad alphabet excludes '+', '/', '='. Confirm none
        // of those leak through.
        for c in envelope.chars() {
            assert!(
                c.is_ascii_alphanumeric() || c == '-' || c == '_',
                "envelope contains non-base64url char {c:?}: {envelope}"
            );
        }
    }

    #[test]
    fn decode_request_envelope_rejects_bad_base64() {
        let err = decode_request_envelope("!!!notbase64!!!")
            .expect_err("bad base64");
        assert!(matches!(err, Error::DecodeFailed(_)));
    }

    #[test]
    fn decode_request_envelope_rejects_missing_field() {
        // Valid base64 + valid JSON, but no `cashu_request`.
        let bad = URL_SAFE_NO_PAD.encode(br#"{"other":"x"}"#);
        let err = decode_request_envelope(&bad)
            .expect_err("missing cashu_request");
        assert!(matches!(err, Error::DecodeFailed(_)));
    }
}
