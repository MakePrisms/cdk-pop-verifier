//! Axum middleware that gates a route behind an MPP-Cashu PoP challenge.
//!
//! Drop into an `axum::Router` with [`axum::middleware::from_fn_with_state`]
//! to enforce the v1 happy path:
//!
//! 1. Request arrives without an `Authorization: Payment method="cashu"`
//!    header — middleware responds `402 Payment Required` and places
//!    `WWW-Authenticate: Payment method="cashu", challenge="creqA…"` on
//!    the response. The `challenge` value is the standard NUT-18
//!    [`PopRequirement`][crate::PopRequirement] in its canonical
//!    `creqA…` encoding.
//! 2. Client retries the same URL and method with `Authorization:
//!    Payment method="cashu", token="cashuB…"` — middleware decodes the
//!    token, runs the full [`PopValidator`] pipeline, and on success
//!    attaches a [`ValidatedPop`] to `request.extensions_mut()` so the
//!    downstream handler can read it via `Extension<ValidatedPop>`. On
//!    failure the middleware writes a structured HTTP error per the
//!    NUT-24 "Errors" section.
//!
//! ## MPP-Cashu envelope
//!
//! The envelope follows RFC 7235's `auth-scheme + auth-param*` shape:
//!
//! ```text
//! HTTP/1.1 402 Payment Required
//! WWW-Authenticate: Payment method="cashu", challenge="creqA…"
//!
//! GET /resource
//! Authorization: Payment method="cashu", token="cashuB…"
//! ```
//!
//! The MPP-Cashu *method extension* itself is not yet formalized in the
//! MPP spec at <https://mpp.dev>; the shape here is gudnuf's tentative
//! pre-spec form. The `creqA…` and `cashuB…` payloads are unchanged
//! from the standalone NUT-24 path — only the framing changed.
//!
//! Per the v1 lock-ins this middleware is MPP-only: no `X-Cashu` header
//! is read or emitted, and there is no separate `/pay` endpoint. The
//! same URL + method that produced the 402 is what the client retries
//! with the proof.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use http::{header::HeaderValue, StatusCode};

use crate::auth_header::{
    parse_payment_authorization, AuthParseError, CASHU_METHOD, CHALLENGE_PARAM, METHOD_PARAM,
    PAYMENT_SCHEME,
};
use crate::challenge::{decode_token, encode_challenge, PopRequirement};
use crate::error::Error as ChallengeError;
use crate::mint_client::MintClient;
use crate::validator::{PopValidator, ValidationError};

/// State the middleware needs at request time: the [`PopRequirement`]
/// to advertise on 402 and the [`PopValidator`] that validates proofs
/// on retry.
///
/// Constructed once at router-build time and shared (`Arc`) across
/// requests. Storing the validator as `Arc<PopValidator<M>>` lets the
/// caller decide how to share the underlying [`MintClient`] — typically
/// also behind an `Arc` so HTTP+TLS connection state is reused.
#[derive(Debug)]
pub struct PopMiddlewareState<M: MintClient> {
    /// What the verifier requires from the holder. Emitted as the
    /// `challenge="creqA…"` parameter of `WWW-Authenticate: Payment`
    /// on the 402.
    pub requirement: PopRequirement,
    /// Validator the middleware delegates to once the client retries
    /// with an `Authorization: Payment` proof header.
    pub validator: Arc<PopValidator<M>>,
}

impl<M: MintClient> PopMiddlewareState<M> {
    /// Convenience constructor: wraps `validator` in an [`Arc`] and
    /// pairs it with the [`PopRequirement`] to advertise.
    pub fn new(requirement: PopRequirement, validator: PopValidator<M>) -> Self {
        Self {
            requirement,
            validator: Arc::new(validator),
        }
    }
}

/// Axum middleware entry point: enforces the MPP-Cashu PoP envelope on
/// the request.
///
/// Register with `axum::middleware::from_fn_with_state(state, require_pop)`
/// where `state` is `Arc<PopMiddlewareState<M>>`. The `'static` bound on
/// `M` is what axum's `from_fn_with_state` requires to spawn the handler
/// future; in practice every realistic [`MintClient`] (cdk-backed or
/// mock) satisfies it.
pub async fn require_pop<M>(
    State(ctx): State<Arc<PopMiddlewareState<M>>>,
    mut req: Request,
    next: Next,
) -> Response
where
    M: MintClient + 'static,
{
    // Step 1: client must present an `Authorization: Payment …` header.
    // Missing header or any non-`Payment` scheme is treated as "no PoP
    // attempt" → 402 with the encoded challenge. This matches RFC 7235
    // §3.1 semantics: a 402 advertises which schemes the resource
    // accepts; clients that try a different scheme effectively didn't
    // try.
    let Some(header_raw) = req.headers().get(http::header::AUTHORIZATION) else {
        return challenge_response(&ctx.requirement);
    };

    // Step 2: header must be valid UTF-8. Per RFC 7230 header values
    // are ASCII; a non-UTF-8 value never carries a valid Payment auth
    // envelope, so we surface 400 rather than treating it as "no
    // header".
    let header_value = match header_raw.to_str() {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                "invalid Authorization header encoding",
            )
                .into_response();
        }
    };

    // Step 3: parse the MPP envelope. `UnknownScheme` is the one
    // non-error error: it means "the client used Basic/Bearer/whatever
    // — they didn't try MPP-Cashu", which is identical from a control-
    // flow perspective to "no header at all". Every other parse error
    // is "tried Payment but malformed" → 400.
    let token_value = match parse_payment_authorization(header_value) {
        Ok(t) => t,
        Err(AuthParseError::UnknownScheme) => return challenge_response(&ctx.requirement),
        Err(e) => return auth_parse_error_to_response(e),
    };

    // Step 4: decode the token. `decode_token` already rejects empty
    // input, unknown prefix, and malformed payload — we just propagate.
    let token = match decode_token(&token_value) {
        Ok(t) => t,
        Err(e) => return decode_error_to_response(e),
    };

    // Step 5: run the full validator pipeline. Structural and mint-side
    // failures both produce HTTP errors per NUT-24 §"Errors".
    let validated = match ctx.validator.validate(&token, &ctx.requirement).await {
        Ok(v) => v,
        Err(e) => return validation_error_to_response(e),
    };

    // Step 6: hand the validated PoP to downstream handlers. They can
    // extract it via `Extension<ValidatedPop>`.
    req.extensions_mut().insert(validated);
    next.run(req).await
}

/// Build a 402 response carrying the encoded challenge in
/// `WWW-Authenticate: Payment method="cashu", challenge="creqA…"`.
fn challenge_response(requirement: &PopRequirement) -> Response {
    let encoded = encode_challenge(requirement);
    // `encode_challenge` outputs `creqA…` which is base64url —
    // strictly ASCII printable, no `"` or `\` to escape. Building the
    // header value via plain concatenation is safe; we still call
    // `HeaderValue::from_str` to enforce the ASCII invariant in case a
    // future encoder change breaks it.
    let header = format!(
        r#"{} {}="{}", {}="{}""#,
        PAYMENT_SCHEME, METHOD_PARAM, CASHU_METHOD, CHALLENGE_PARAM, encoded
    );
    match HeaderValue::from_str(&header) {
        Ok(hv) => (
            StatusCode::PAYMENT_REQUIRED,
            [(http::header::WWW_AUTHENTICATE, hv)],
        )
            .into_response(),
        // Defensive fallback — only triggers if the encoder regresses.
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to encode WWW-Authenticate challenge header",
        )
            .into_response(),
    }
}

/// Map an [`AuthParseError`] (from the MPP envelope parser) to an HTTP
/// response. `UnknownScheme` is handled upstream (→ 402); the rest are
/// client malformed-header errors → 400.
fn auth_parse_error_to_response(e: AuthParseError) -> Response {
    debug_assert!(
        !matches!(e, AuthParseError::UnknownScheme),
        "UnknownScheme must be handled upstream as 402"
    );
    let msg = format!("invalid Authorization: Payment header: {e}");
    (StatusCode::BAD_REQUEST, msg).into_response()
}

/// Map a [`ChallengeError`] (from [`decode_token`]) to an HTTP response.
///
/// All variants are client-attributable (bad header) so they all map to
/// 400 with a short message. We preserve the variant in the message so
/// clients can distinguish "wrong prefix" from "bad payload".
fn decode_error_to_response(e: ChallengeError) -> Response {
    let msg = match &e {
        ChallengeError::InvalidHeader(_) => format!("invalid token value: {e}"),
        ChallengeError::DecodeFailed(_) => format!("decode failed: {e}"),
        // EncodeFailed never originates from decode_token, but the
        // ChallengeError enum is shared — surface it as a 400 if it
        // ever leaks through.
        ChallengeError::EncodeFailed(_) => format!("encode failed: {e}"),
    };
    (StatusCode::BAD_REQUEST, msg).into_response()
}

/// Map a [`ValidationError`] to an HTTP response per NUT-24 §"Errors":
///
/// > Servers return HTTP 400 if tokens come from unauthorized mints,
/// > use incorrect units, provide insufficient amounts, or lack proper
/// > locking conditions.
///
/// Transport failures (mint unreachable) are mapped to 503 so clients
/// see a transient signal — the client may retry the same proof later.
/// All other validation errors are 400 (client must obtain a new
/// token).
fn validation_error_to_response(e: ValidationError) -> Response {
    let status = match &e {
        ValidationError::MintUnreachable(_) => StatusCode::SERVICE_UNAVAILABLE,
        ValidationError::UnitMismatch { .. }
        | ValidationError::MintNotAllowed { .. }
        | ValidationError::AmountInsufficient { .. }
        | ValidationError::TokenEmpty
        | ValidationError::MalformedToken(_)
        | ValidationError::MintRejectedSwap(_) => StatusCode::BAD_REQUEST,
    };
    (status, e.to_string()).into_response()
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::Arc;

    use async_trait::async_trait;
    use axum::body::{to_bytes, Body};
    use axum::extract::Extension;
    use axum::middleware::from_fn_with_state;
    use axum::routing::get;
    use axum::Router;
    use cashu::dhke::hash_to_curve;
    use cashu::nuts::nut02::{Id, KeySetInfo};
    use cashu::nuts::Proof;
    use cashu::secret::Secret;
    use cashu::{Amount, CurrencyUnit, MintUrl, Proofs, Token};
    use http::{header::AUTHORIZATION, Request as HttpRequest, StatusCode};
    use tower::ServiceExt;

    use super::*;
    use crate::challenge::PopRequirement;
    use crate::mint_client::{MintClient, MintClientError};
    use crate::validator::{PopValidator, ValidatedPop};

    // ---- Mock MintClient (mirrors the validator's test helper) -------
    //
    // Kept duplicated rather than reaching into validator::tests so that
    // Commit 5 changes nothing in validator.rs. The two mocks may diverge
    // later (e.g. middleware tests may want call-count probes that the
    // validator tests don't need).

    enum SwapResponse {
        Echo,
        Unreachable,
        RejectedSwap,
    }

    struct MockMintClient {
        swap_response: SwapResponse,
    }

    impl MockMintClient {
        fn new(swap_response: SwapResponse) -> Self {
            Self { swap_response }
        }
    }

    #[async_trait]
    impl MintClient for MockMintClient {
        async fn keysets(
            &self,
            _mint_url: &MintUrl,
        ) -> Result<Vec<KeySetInfo>, MintClientError> {
            // V0 proofs in these tests; empty list is fine.
            Ok(Vec::new())
        }

        async fn swap(
            &self,
            _mint_url: &MintUrl,
            proofs: Proofs,
        ) -> Result<Proofs, MintClientError> {
            match self.swap_response {
                SwapResponse::Echo => Ok(proofs),
                SwapResponse::Unreachable => Err(MintClientError::Unreachable(
                    "mock unreachable".into(),
                )),
                SwapResponse::RejectedSwap => {
                    Err(MintClientError::RejectedSwap("mock rejected".into()))
                }
            }
        }
    }

    // ---- Fixtures ----------------------------------------------------

    fn pop_unit() -> CurrencyUnit {
        CurrencyUnit::Custom("pop_1700000000".to_string())
    }

    fn mint_a() -> MintUrl {
        MintUrl::from_str("https://mint-a.example.com").expect("valid mint url")
    }

    fn make_proof(amount: u64, index: u8) -> Proof {
        let keyset_id = Id::from_str("009a1f293253e41e").expect("valid v0 keyset id");
        let mut preimage = [0u8; 33];
        preimage[0] = 1;
        preimage[1] = index;
        let c = hash_to_curve(&preimage).expect("hash_to_curve");
        Proof::new(Amount::from(amount), keyset_id, Secret::generate(), c)
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

    /// Construct an axum router with the middleware in front of a tiny
    /// echo handler. The handler returns 200 on success and writes the
    /// validated amount into the body so tests can assert the
    /// `ValidatedPop` made it through the extensions.
    fn router_with(state: Arc<PopMiddlewareState<MockMintClient>>) -> Router {
        async fn echo(Extension(pop): Extension<ValidatedPop>) -> String {
            format!("ok:{}", u64::from(pop.amount))
        }
        Router::new()
            .route("/gated", get(echo))
            .layer(from_fn_with_state(state, require_pop::<MockMintClient>))
    }

    /// Build a state with the supplied swap response and the standard
    /// PoP requirement (`pop_1700000000`, mint_a, amount=10).
    fn state_with(swap: SwapResponse) -> Arc<PopMiddlewareState<MockMintClient>> {
        let mock = MockMintClient::new(swap);
        let validator = PopValidator::new(mock);
        Arc::new(PopMiddlewareState::new(
            requirement(pop_unit(), vec![mint_a()], 10),
            validator,
        ))
    }

    /// Build a GET /gated request with no body.
    fn bare_request() -> HttpRequest<Body> {
        HttpRequest::builder()
            .uri("/gated")
            .body(Body::empty())
            .expect("build request")
    }

    /// Build a GET /gated request with the supplied raw `Authorization`
    /// header value.
    fn request_with_authorization(value: &str) -> HttpRequest<Body> {
        HttpRequest::builder()
            .uri("/gated")
            .header(AUTHORIZATION, value)
            .body(Body::empty())
            .expect("build request with header")
    }

    /// Wrap a raw `cashuB…` token in the MPP-Cashu envelope.
    fn payment_header_with_token(token: &str) -> String {
        format!(r#"Payment method="cashu", token="{token}""#)
    }

    /// Build a GET /gated request whose `Authorization` header is the
    /// MPP envelope around `token`.
    fn request_with_token(token: &str) -> HttpRequest<Body> {
        request_with_authorization(&payment_header_with_token(token))
    }

    /// Build a GET /gated request with raw header bytes (used for the
    /// non-utf8 test case).
    fn request_with_raw_authorization(value: &[u8]) -> HttpRequest<Body> {
        // `header()` rejects non-ASCII at builder time; reach down to
        // HeaderValue::from_bytes which accepts arbitrary bytes.
        let mut req = HttpRequest::builder()
            .uri("/gated")
            .body(Body::empty())
            .expect("build request");
        let hv = http::HeaderValue::from_bytes(value).expect("non-utf8 header bytes are valid");
        req.headers_mut().insert(AUTHORIZATION, hv);
        req
    }

    // ---- Tests -------------------------------------------------------

    #[tokio::test]
    async fn no_authorization_header_returns_402_with_www_authenticate() {
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app.oneshot(bare_request()).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let header = response
            .headers()
            .get(http::header::WWW_AUTHENTICATE)
            .expect("WWW-Authenticate header present on 402");
        let header_str = header.to_str().expect("WWW-Authenticate is ASCII");
        assert!(
            header_str.starts_with(r#"Payment method="cashu", challenge="creqA"#),
            "expected MPP-Cashu envelope, got {header_str}"
        );
        assert!(
            header_str.ends_with('"'),
            "challenge value must be quoted-string-terminated, got {header_str}"
        );
        // Confirm no legacy X-Cashu header leaks onto the 402.
        assert!(
            response.headers().get("x-cashu").is_none(),
            "X-Cashu must not be emitted in MPP-only mode"
        );
    }

    #[tokio::test]
    async fn valid_token_passes_through_to_handler() {
        // Token exactly matches the requirement: pop_unit, mint_a, amount=10.
        let token = make_token(
            mint_a(),
            pop_unit(),
            vec![make_proof(8, 0), make_proof(2, 1)],
        );
        let encoded = token.to_string();

        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_token(&encoded))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::OK);

        // The handler reads ValidatedPop out of extensions and echoes
        // the amount. If the extension was missing the handler would
        // have failed to extract and the response status would not be
        // 200, but we additionally assert the body to prove the
        // ValidatedPop reached the handler intact.
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        assert_eq!(&body_bytes[..], b"ok:10");
    }

    #[tokio::test]
    async fn invalid_header_encoding_returns_400() {
        // 0xFF is not valid UTF-8.
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_raw_authorization(&[0xFFu8, 0xFE, 0xFD]))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        let body = std::str::from_utf8(&body_bytes).unwrap_or("<non-utf8 body>");
        assert!(
            body.contains("invalid Authorization header encoding"),
            "unexpected body: {body}"
        );
    }

    #[tokio::test]
    async fn malformed_token_returns_400() {
        // Recognized prefix, garbage payload — Error::DecodeFailed path.
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_token("cashuB!!!notbase64!!!"))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        let body = std::str::from_utf8(&body_bytes).unwrap_or("<non-utf8 body>");
        assert!(
            body.contains("decode failed"),
            "expected decode-failed message, got: {body}"
        );
    }

    #[tokio::test]
    async fn unit_mismatch_returns_400() {
        // Token uses CurrencyUnit::Sat but the requirement expects pop_unit.
        let token = make_token(mint_a(), CurrencyUnit::Sat, vec![make_proof(10, 0)]);
        let encoded = token.to_string();

        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_token(&encoded))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        let body = std::str::from_utf8(&body_bytes).unwrap_or("<non-utf8 body>");
        assert!(
            body.contains("does not match requirement unit"),
            "expected unit-mismatch message, got: {body}"
        );
    }

    #[tokio::test]
    async fn mint_unreachable_returns_503() {
        // Structurally valid token, but the mock swap surfaces
        // MintClientError::Unreachable. Middleware must translate to 503.
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let encoded = token.to_string();

        let app = router_with(state_with(SwapResponse::Unreachable));
        let response = app
            .oneshot(request_with_token(&encoded))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        let body = std::str::from_utf8(&body_bytes).unwrap_or("<non-utf8 body>");
        assert!(
            body.contains("mint unreachable"),
            "expected mint-unreachable message, got: {body}"
        );
    }

    #[tokio::test]
    async fn mint_rejected_returns_400() {
        // Structurally valid token; mock swap returns RejectedSwap
        // (expired credential, double-spent, etc.). Middleware must
        // surface as 400 per NUT-24 §"Errors".
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let encoded = token.to_string();

        let app = router_with(state_with(SwapResponse::RejectedSwap));
        let response = app
            .oneshot(request_with_token(&encoded))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        let body = std::str::from_utf8(&body_bytes).unwrap_or("<non-utf8 body>");
        assert!(
            body.contains("mint rejected swap"),
            "expected mint-rejected-swap message, got: {body}"
        );
    }

    // ---- MPP envelope parsing tests ----------------------------------

    #[tokio::test]
    async fn non_payment_scheme_returns_402() {
        // `Authorization: Bearer …` is not an MPP-Cashu attempt at all.
        // RFC 7235 §3.1 lets the server treat unsupported schemes as
        // "credentials not presented" — same flow as a missing header.
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_authorization("Bearer abcdef"))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let header = response
            .headers()
            .get(http::header::WWW_AUTHENTICATE)
            .expect("challenge re-issued on non-Payment scheme");
        assert!(header
            .to_str()
            .unwrap()
            .starts_with(r#"Payment method="cashu""#));
    }

    #[tokio::test]
    async fn payment_with_wrong_method_returns_400() {
        // `Payment` scheme is right but the method extension isn't
        // ours — middleware must reject (400) instead of re-challenging.
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_authorization(
                r#"Payment method="tempo", token="cashuBabc""#,
            ))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        let body = std::str::from_utf8(&body_bytes).unwrap_or("<non-utf8 body>");
        assert!(
            body.contains("method must be 'cashu'"),
            "expected wrong-method message, got: {body}"
        );
    }

    #[tokio::test]
    async fn payment_with_missing_token_returns_400() {
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_authorization(r#"Payment method="cashu""#))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        let body = std::str::from_utf8(&body_bytes).unwrap_or("<non-utf8 body>");
        assert!(
            body.contains("missing 'token'"),
            "expected missing-token message, got: {body}"
        );
    }

    #[tokio::test]
    async fn payment_with_missing_method_returns_400() {
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_authorization(
                r#"Payment token="cashuBabc""#,
            ))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        let body = std::str::from_utf8(&body_bytes).unwrap_or("<non-utf8 body>");
        assert!(
            body.contains("missing 'method'"),
            "expected missing-method message, got: {body}"
        );
    }
}
