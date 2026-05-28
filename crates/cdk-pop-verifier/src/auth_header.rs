//! Parser for the `Authorization: Payment <credentials>` request header
//! per `draft-httpauth-payment-00` §5.2.
//!
//! The retry credentials are a single opaque token: `auth-scheme` =
//! `Payment` followed by a base64url-nopad-encoded JSON object. The
//! object has the shape:
//!
//! ```json
//! {
//!   "challenge": {
//!     "id":      "<echo of WWW-Authenticate id>",
//!     "realm":   "<echo of realm>",
//!     "method":  "<echo of method, e.g. \"cashu\">",
//!     "intent":  "<echo of intent, e.g. \"charge\">",
//!     "request": "<echo of request param>"
//!   },
//!   "payload": {
//!     "cashu_token": "cashuB..."
//!   }
//! }
//! ```
//!
//! This module parses that envelope and exposes the two pieces a
//! consumer cares about: the echoed `challenge.method` (so the caller
//! can reject non-cashu methods) and the `payload.cashu_token` (the
//! `cashuB…` string the validator decodes via [`crate::decode_token`]).
//!
//! Every field marked `Required` by the draft is honoured here;
//! `RECOMMENDED`/`OPTIONAL` fields (`source`, `description`, `opaque`,
//! `digest`, `expires`) are tolerated on the wire but otherwise ignored.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// HTTP auth-scheme for the Payment Authentication envelope.
/// Case-insensitive per RFC 7235 §2.1.
pub const PAYMENT_SCHEME: &str = "Payment";

/// Required value for the `method` field on the echoed challenge for
/// the cashu method extension. Per draft §5.1.1 the wire value MUST be
/// a lowercase ASCII string, so this comparison is case-sensitive.
pub const CASHU_METHOD: &str = "cashu";

/// Echo of the WWW-Authenticate auth-params per draft §5.2 Table 4.
///
/// The Payment Authentication draft requires the client to round-trip
/// every required parameter from the 402's `WWW-Authenticate: Payment`
/// header. All required fields are deserialized; optional fields
/// (`description`, `opaque`, `digest`, `expires`) are accepted but not
/// surfaced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EchoedChallenge {
    /// Echo of the server-issued challenge id.
    pub id: String,
    /// Echo of the protection-space realm.
    pub realm: String,
    /// Echo of the payment method (we require `"cashu"`).
    pub method: String,
    /// Echo of the payment intent (we emit `"charge"`).
    pub intent: String,
    /// Echo of the base64url-encoded method-specific request blob.
    pub request: String,
}

/// Cashu-method `payload` per draft §5.2: payment-method-specific data
/// needed to complete the challenge.
///
/// For cashu this is the `cashuB…` token the holder mints from the PoP
/// issuer. The token's structural validation (prefix, base64, CBOR,
/// proof shape) is the validator's job; this struct just carries the
/// string out of the JSON envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CashuPayload {
    /// The `cashuB…` token string. Forwarded as-is to
    /// [`crate::decode_token`].
    pub cashu_token: String,
}

/// Full credentials object per draft §5.2.
///
/// `challenge` and `payload` are `Required`; `source` is `RECOMMENDED`
/// (DID) and ignored here. Deserializing tolerates unknown fields so a
/// `source` field from clients that send it round-trips silently.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentCredentials {
    /// Echo of the WWW-Authenticate auth-params.
    pub challenge: EchoedChallenge,
    /// Method-specific payload (cashu = `{ "cashu_token": "..." }`).
    pub payload: CashuPayload,
}

/// Why an `Authorization: Payment <blob>` header failed to parse.
///
/// Per draft §4.2 the server MUST reply `402` with a fresh
/// `WWW-Authenticate: Payment` re-challenge on any validation failure,
/// so every variant here maps to a 402 in the middleware — they are
/// distinct enums only to make the response body intelligible to the
/// client.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthParseError {
    /// First whitespace-separated token is not `Payment`.
    #[error("auth scheme is not 'Payment'")]
    UnknownScheme,

    /// `Payment` scheme present but no credentials blob follows.
    #[error("Payment header missing credentials blob")]
    MissingCredentials,

    /// Credentials blob is not valid base64url-nopad.
    #[error("Payment credentials are not valid base64url-nopad: {0}")]
    Base64Decode(String),

    /// Base64-decoded bytes are not valid UTF-8 (so cannot be JSON).
    #[error("Payment credentials are not valid UTF-8: {0}")]
    Utf8Decode(String),

    /// JSON does not parse, or required fields are missing/of the wrong
    /// shape.
    #[error("Payment credentials JSON is malformed: {0}")]
    JsonParse(String),

    /// `challenge.method` is present but is not `"cashu"`.
    #[error("Payment method must be 'cashu', got {0:?}")]
    WrongMethod(String),
}

/// Parse an `Authorization: Payment <base64url-nopad-blob>` header and
/// return the structured credentials.
///
/// On success the caller still needs to:
/// 1. Validate that `credentials.challenge.method == "cashu"` —
///    `WrongMethod` is surfaced here for any other value.
/// 2. Decode `credentials.payload.cashu_token` via
///    [`crate::decode_token`].
pub fn parse_payment_authorization(
    header_value: &str,
) -> Result<PaymentCredentials, AuthParseError> {
    let trimmed = header_value.trim();
    if trimmed.is_empty() {
        return Err(AuthParseError::UnknownScheme);
    }

    // Split scheme off the first whitespace run. RFC 7235 §2.1 mandates
    // at least one SP between scheme and credentials.
    let (scheme, rest) = match trimmed.split_once(|c: char| c.is_ascii_whitespace()) {
        Some((s, r)) => (s, r.trim()),
        None => (trimmed, ""),
    };

    if !scheme.eq_ignore_ascii_case(PAYMENT_SCHEME) {
        return Err(AuthParseError::UnknownScheme);
    }

    if rest.is_empty() {
        return Err(AuthParseError::MissingCredentials);
    }

    // Per draft §5.2 the credentials blob is base64url without padding.
    // Anything else (including the legacy key=value RFC 7235 param
    // form) trips up the base64 decoder and is rejected.
    let bytes = URL_SAFE_NO_PAD
        .decode(rest)
        .map_err(|e| AuthParseError::Base64Decode(e.to_string()))?;

    let json = std::str::from_utf8(&bytes)
        .map_err(|e| AuthParseError::Utf8Decode(e.to_string()))?;

    let credentials: PaymentCredentials = serde_json::from_str(json)
        .map_err(|e| AuthParseError::JsonParse(e.to_string()))?;

    if credentials.challenge.method != CASHU_METHOD {
        return Err(AuthParseError::WrongMethod(
            credentials.challenge.method.clone(),
        ));
    }

    Ok(credentials)
}

/// Helper for tests + downstream consumers: build a credentials blob
/// (the inverse of [`parse_payment_authorization`]).
///
/// Returns the bare base64url-nopad string — the caller is responsible
/// for prepending `Payment ` to form the full header value.
pub fn encode_payment_credentials(credentials: &PaymentCredentials) -> String {
    // `serde_json::to_string` cannot fail on these owned-String fields,
    // but we surface a panic via `expect` rather than introduce a
    // result-typed signature for a path that has no recoverable error.
    let json = serde_json::to_string(credentials).expect("PaymentCredentials always serializes");
    URL_SAFE_NO_PAD.encode(json.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_credentials(method: &str, token: &str) -> PaymentCredentials {
        PaymentCredentials {
            challenge: EchoedChallenge {
                id: "challenge-1".into(),
                realm: "cdk-pop-verifier".into(),
                method: method.into(),
                intent: "charge".into(),
                request: "ZHVtbXkK".into(),
            },
            payload: CashuPayload {
                cashu_token: token.into(),
            },
        }
    }

    fn header_for(creds: &PaymentCredentials) -> String {
        format!("Payment {}", encode_payment_credentials(creds))
    }

    #[test]
    fn happy_path_decodes_credentials() {
        let creds = make_credentials("cashu", "cashuBabc");
        let header = header_for(&creds);
        let parsed = parse_payment_authorization(&header).expect("parses");
        assert_eq!(parsed.challenge.id, "challenge-1");
        assert_eq!(parsed.challenge.realm, "cdk-pop-verifier");
        assert_eq!(parsed.challenge.method, "cashu");
        assert_eq!(parsed.challenge.intent, "charge");
        assert_eq!(parsed.payload.cashu_token, "cashuBabc");
    }

    #[test]
    fn scheme_is_case_insensitive() {
        let creds = make_credentials("cashu", "cashuBabc");
        let blob = encode_payment_credentials(&creds);
        for scheme in &["Payment", "PAYMENT", "payment", "pAyMeNt"] {
            let header = format!("{scheme} {blob}");
            parse_payment_authorization(&header).expect("scheme is case-insensitive");
        }
    }

    #[test]
    fn missing_scheme_returns_unknown_scheme() {
        assert_eq!(
            parse_payment_authorization("").unwrap_err(),
            AuthParseError::UnknownScheme,
        );
        assert_eq!(
            parse_payment_authorization("   ").unwrap_err(),
            AuthParseError::UnknownScheme,
        );
    }

    #[test]
    fn bearer_scheme_returns_unknown_scheme() {
        assert_eq!(
            parse_payment_authorization("Bearer abc123").unwrap_err(),
            AuthParseError::UnknownScheme,
        );
    }

    #[test]
    fn payment_with_no_blob_returns_missing_credentials() {
        assert_eq!(
            parse_payment_authorization("Payment").unwrap_err(),
            AuthParseError::MissingCredentials,
        );
        assert_eq!(
            parse_payment_authorization("Payment  ").unwrap_err(),
            AuthParseError::MissingCredentials,
        );
    }

    #[test]
    fn legacy_key_value_param_form_is_not_accepted() {
        // The old transitional form `Payment method="cashu",
        // token="cashuBabc"` is not valid base64url; the parser surfaces
        // a Base64Decode error which the middleware maps to a 402 +
        // fresh re-challenge per draft §4.2.
        let err = parse_payment_authorization(
            r#"Payment method="cashu", token="cashuBabc""#,
        )
        .expect_err("param form must be rejected");
        assert!(
            matches!(err, AuthParseError::Base64Decode(_)),
            "expected Base64Decode, got {err:?}"
        );
    }

    #[test]
    fn malformed_base64_returns_base64_decode() {
        let err = parse_payment_authorization("Payment !!!notbase64!!!")
            .expect_err("garbage base64");
        assert!(
            matches!(err, AuthParseError::Base64Decode(_)),
            "expected Base64Decode, got {err:?}"
        );
    }

    #[test]
    fn valid_base64_not_utf8_returns_utf8_decode() {
        // 0xff is not a valid UTF-8 start byte — base64-encode raw 0xff.
        let blob = URL_SAFE_NO_PAD.encode([0xffu8, 0xfe, 0xfd]);
        let header = format!("Payment {blob}");
        let err = parse_payment_authorization(&header).expect_err("non-utf8 payload");
        assert!(
            matches!(err, AuthParseError::Utf8Decode(_)),
            "expected Utf8Decode, got {err:?}"
        );
    }

    #[test]
    fn valid_base64_not_json_returns_json_parse() {
        let blob = URL_SAFE_NO_PAD.encode(b"not a json object");
        let header = format!("Payment {blob}");
        let err = parse_payment_authorization(&header).expect_err("not json");
        assert!(
            matches!(err, AuthParseError::JsonParse(_)),
            "expected JsonParse, got {err:?}"
        );
    }

    #[test]
    fn json_missing_challenge_returns_json_parse() {
        let blob = URL_SAFE_NO_PAD.encode(br#"{"payload":{"cashu_token":"x"}}"#);
        let header = format!("Payment {blob}");
        let err = parse_payment_authorization(&header).expect_err("no challenge");
        assert!(
            matches!(err, AuthParseError::JsonParse(_)),
            "expected JsonParse, got {err:?}"
        );
    }

    #[test]
    fn json_missing_payload_returns_json_parse() {
        let blob = URL_SAFE_NO_PAD.encode(
            br#"{"challenge":{"id":"a","realm":"b","method":"cashu","intent":"charge","request":"r"}}"#,
        );
        let header = format!("Payment {blob}");
        let err = parse_payment_authorization(&header).expect_err("no payload");
        assert!(
            matches!(err, AuthParseError::JsonParse(_)),
            "expected JsonParse, got {err:?}"
        );
    }

    #[test]
    fn payload_missing_cashu_token_returns_json_parse() {
        let blob = URL_SAFE_NO_PAD.encode(
            br#"{"challenge":{"id":"a","realm":"b","method":"cashu","intent":"charge","request":"r"},"payload":{}}"#,
        );
        let header = format!("Payment {blob}");
        let err = parse_payment_authorization(&header).expect_err("no cashu_token");
        assert!(
            matches!(err, AuthParseError::JsonParse(_)),
            "expected JsonParse, got {err:?}"
        );
    }

    #[test]
    fn wrong_method_returns_wrong_method() {
        let creds = make_credentials("tempo", "abc");
        let header = header_for(&creds);
        assert_eq!(
            parse_payment_authorization(&header).unwrap_err(),
            AuthParseError::WrongMethod("tempo".into()),
        );
    }

    #[test]
    fn extra_unknown_fields_are_ignored() {
        // `source` is RECOMMENDED but not required for cashu; the draft
        // also allows arbitrary other fields on the JSON object. We must
        // not refuse to parse a credentials blob that carries them.
        let json = serde_json::json!({
            "challenge": {
                "id": "x",
                "realm": "cdk-pop-verifier",
                "method": "cashu",
                "intent": "charge",
                "request": "r",
                "description": "ignored",
                "opaque": "ignored",
                "expires": "2030-01-01T00:00:00Z"
            },
            "source": "did:example:123",
            "payload": {
                "cashu_token": "cashuBxyz",
                "extra": "ignored"
            }
        });
        let blob = URL_SAFE_NO_PAD.encode(json.to_string().as_bytes());
        let header = format!("Payment {blob}");
        let parsed = parse_payment_authorization(&header).expect("optional fields ok");
        assert_eq!(parsed.payload.cashu_token, "cashuBxyz");
    }

    #[test]
    fn extra_whitespace_around_blob_is_trimmed() {
        let creds = make_credentials("cashu", "cashuBabc");
        let blob = encode_payment_credentials(&creds);
        let header = format!("  Payment   {blob}   ");
        parse_payment_authorization(&header).expect("extra whitespace tolerated");
    }
}
