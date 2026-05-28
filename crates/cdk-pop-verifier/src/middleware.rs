//! Axum middleware that gates a route behind a `draft-httpauth-payment-00`
//! Payment Authentication challenge for the cashu method.
//!
//! Drop into an `axum::Router` with [`axum::middleware::from_fn_with_state`]
//! to enforce the v1 happy path:
//!
//! 1. Request arrives without an `Authorization: Payment <blob>`
//!    header — middleware responds `402 Payment Required` and places
//!    `WWW-Authenticate: Payment id="…", realm="…", method="cashu",
//!    intent="charge", request="<base64url-nopad>"` on the response
//!    along with `Cache-Control: no-store`. The `request` value wraps
//!    the standard NUT-18 [`PopRequirement`][crate::PopRequirement] in
//!    its canonical `creqA…` encoding via
//!    [`encode_request_envelope`].
//! 2. Client retries the same URL and method with `Authorization:
//!    Payment <base64url-nopad-JSON>` where the JSON has the shape
//!    described in [`crate::auth_header::PaymentCredentials`]. The
//!    middleware extracts the `cashuB…` token from
//!    `payload.cashu_token`, runs the full [`PopValidator`] pipeline,
//!    and on success attaches a [`ValidatedPop`] to
//!    `request.extensions_mut()` so the downstream handler can read it
//!    via `Extension<ValidatedPop>`.
//!
//! ## Failure mapping
//!
//! Per draft §4.2 the server MUST return `402 Payment Required` with a
//! fresh `WWW-Authenticate: Payment` re-challenge on *any* validation
//! failure — bad header, bad token, wrong unit, wrong mint, insufficient
//! amount, malformed proof, or a mint that refused the swap. Only
//! transport-level failures to reach the mint (DNS/TCP/TLS/timeout)
//! surface as `503 Service Unavailable`, because the draft does not
//! constrain backend failure modes.
//!
//! Every 402 carries `Cache-Control: no-store` per draft §11.10.
//!
//! ## Response body
//!
//! 402 bodies are plain-text descriptions of why the previous attempt
//! failed (e.g. `unit mismatch: expected pop_…, got sat`). RFC 9457
//! Problem Details bodies are a SHOULD in the draft and intentionally
//! skipped here per the MUST-only directive.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use http::{header::HeaderValue, StatusCode};
use uuid::Uuid;

use crate::auth_header::{
    parse_payment_authorization, AuthParseError, EchoedChallenge, PAYMENT_SCHEME,
};
use crate::challenge::{
    decode_token, encode_challenge, encode_request_envelope, PopRequirement,
};
use crate::error::Error as ChallengeError;
use crate::mint_client::MintClient;
use crate::validator::{PopValidator, ValidationError};

/// Default `realm` value emitted in `WWW-Authenticate: Payment`. The
/// draft mandates a `realm` auth-param but leaves the value
/// operator-defined. We hardcode a sensible identifier for v1;
/// operator-configurable wiring lands later (see TODO at use site).
pub const DEFAULT_REALM: &str = "cdk-pop-verifier";

/// `intent` value the verifier emits per draft §7. `charge` means "the
/// server consumes the payment as a one-shot charge" — matches PoP's
/// transfer-on-use semantics.
pub const INTENT_CHARGE: &str = "charge";

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
    /// What the verifier requires from the holder. Wrapped into the
    /// `request="…"` auth-param of `WWW-Authenticate: Payment` on the
    /// 402.
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

/// Axum middleware entry point: enforces the Payment Authentication
/// envelope on the request.
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
    // Step 1: client must present an `Authorization: Payment <blob>`
    // header. Missing header or any non-`Payment` scheme is treated as
    // "no payment attempt" → 402 with a fresh challenge. RFC 7235 §3.1
    // semantics: a 402 advertises which schemes the resource accepts;
    // clients that try a different scheme effectively didn't try.
    let Some(header_raw) = req.headers().get(http::header::AUTHORIZATION) else {
        return challenge_response(&ctx.requirement, None);
    };

    // Step 2: header must be valid UTF-8. Per RFC 7230 header values
    // are ASCII; a non-UTF-8 value never carries a valid Payment auth
    // envelope. Draft §4.2: validation failures get 402 + re-challenge.
    let header_value = match header_raw.to_str() {
        Ok(v) => v,
        Err(_) => {
            return challenge_response(
                &ctx.requirement,
                Some("invalid Authorization header encoding"),
            );
        }
    };

    // Step 3: parse the Payment Authentication envelope. `UnknownScheme`
    // means "the client used Basic/Bearer/whatever — they didn't try
    // Payment", which is identical from a control-flow perspective to
    // "no header at all". Every other parse error is a validation
    // failure and must be a 402 re-challenge.
    let credentials = match parse_payment_authorization(header_value) {
        Ok(c) => c,
        Err(AuthParseError::UnknownScheme) => {
            return challenge_response(&ctx.requirement, None);
        }
        Err(e) => return challenge_response(&ctx.requirement, Some(&e.to_string())),
    };

    // Step 4: decode the token from the payload. `decode_token` rejects
    // empty input, unknown prefix, and malformed payload — draft §4.2
    // says all of these go to a 402 re-challenge.
    let token = match decode_token(&credentials.payload.cashu_token) {
        Ok(t) => t,
        Err(e) => {
            return challenge_response(&ctx.requirement, Some(&decode_error_message(&e)));
        }
    };

    // Step 5: run the full validator pipeline. Validation failures map
    // to 402 per draft §4.2; only transport-level failures to reach the
    // mint become 503.
    let validated = match ctx.validator.validate(&token, &ctx.requirement).await {
        Ok(v) => v,
        Err(e) => return validation_error_to_response(e, &ctx.requirement),
    };

    // Step 6: hand the validated PoP to downstream handlers. They can
    // extract it via `Extension<ValidatedPop>`.
    req.extensions_mut().insert(validated);
    next.run(req).await
}

/// Build a 402 response carrying a fresh Payment Authentication
/// challenge. Always emits `Cache-Control: no-store` per draft §11.10.
///
/// `failure_reason`, when provided, becomes the response body — it
/// lets the client see why the previous attempt was rejected. A bare
/// "no attempt yet" 402 (the client never sent an `Authorization`
/// header) gets an empty body.
fn challenge_response(requirement: &PopRequirement, failure_reason: Option<&str>) -> Response {
    // Per draft §5.1.1 `id` is a "Unique challenge identifier".
    // Operators that want stateless binding compute `id =
    // HMAC(secret, params)` per §5.1.2.1 — that's a SHOULD and skipped
    // here. A random UUIDv4 satisfies the "unique" MUST.
    let id = Uuid::new_v4().to_string();

    let creq_a = encode_challenge(requirement);
    let request_envelope = encode_request_envelope(&creq_a);

    // TODO(operator-configurable): wire `realm` through middleware
    // state once an operator-side config story lands. For v1 a fixed
    // identifier is fine — the draft only requires the parameter be
    // present and meaningful.
    let realm = DEFAULT_REALM;

    let header = format!(
        r#"{} id="{}", realm="{}", method="cashu", intent="{}", request="{}""#,
        PAYMENT_SCHEME, id, realm, INTENT_CHARGE, request_envelope,
    );

    // All values produced above are base64url-nopad alphabet or
    // ASCII-printable. `HeaderValue::from_str` still validates as a
    // belt-and-braces guard against a future encoder regression.
    let www_auth = match HeaderValue::from_str(&header) {
        Ok(hv) => hv,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to encode WWW-Authenticate challenge header",
            )
                .into_response();
        }
    };

    let cache_control = HeaderValue::from_static("no-store");

    let body = failure_reason.unwrap_or("").to_string();

    (
        StatusCode::PAYMENT_REQUIRED,
        [
            (http::header::WWW_AUTHENTICATE, www_auth),
            (http::header::CACHE_CONTROL, cache_control),
        ],
        body,
    )
        .into_response()
}

/// Format a [`ChallengeError`] (from [`decode_token`]) as a short
/// description suitable for the 402 response body.
fn decode_error_message(e: &ChallengeError) -> String {
    match e {
        ChallengeError::InvalidHeader(_) => format!("invalid token value: {e}"),
        ChallengeError::DecodeFailed(_) => format!("decode failed: {e}"),
        // EncodeFailed never originates from decode_token, but the
        // ChallengeError enum is shared.
        ChallengeError::EncodeFailed(_) => format!("encode failed: {e}"),
    }
}

/// Map a [`ValidationError`] to an HTTP response.
///
/// Per draft §4.2 all validation failures get `402 Payment Required`
/// with a fresh `WWW-Authenticate: Payment` re-challenge — the client
/// should try again with a better proof. Only transport-level failures
/// to reach the mint get `503 Service Unavailable`, since the draft
/// does not constrain backend failure modes.
fn validation_error_to_response(e: ValidationError, requirement: &PopRequirement) -> Response {
    match &e {
        // Transport failure → backend issue, surface 503 so the client
        // can choose to retry the same proof later.
        ValidationError::MintUnreachable(_) => {
            (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response()
        }
        // Every other failure is a validation failure → 402 +
        // re-challenge.
        ValidationError::UnitMismatch { .. }
        | ValidationError::MintNotAllowed { .. }
        | ValidationError::AmountInsufficient { .. }
        | ValidationError::TokenEmpty
        | ValidationError::MalformedToken(_)
        | ValidationError::MintRejectedSwap(_) => {
            challenge_response(requirement, Some(&e.to_string()))
        }
    }
}

/// Pluck the echoed challenge fields out of a successfully-parsed
/// credentials blob. Surfaced for test helpers; the middleware itself
/// doesn't need to consult them past the `method` check that
/// [`parse_payment_authorization`] already did.
#[allow(dead_code)]
pub(crate) fn echoed_challenge_for_test(creds: &crate::auth_header::PaymentCredentials) -> &EchoedChallenge {
    &creds.challenge
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
    use crate::auth_header::{
        encode_payment_credentials, CashuPayload, PaymentCredentials,
    };
    use crate::challenge::PopRequirement;
    use crate::mint_client::{MintClient, MintClientError};
    use crate::validator::{PopValidator, ValidatedPop};

    // ---- Mock MintClient (mirrors the validator's test helper) -------

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

    /// Wrap a raw `cashuB…` token in the Payment Authentication
    /// envelope, echoing a fake-but-shapely challenge. The middleware
    /// does not currently validate that `challenge.id` matches what it
    /// previously issued (binding is SHOULD, skipped per directive), so
    /// any well-formed echo works.
    fn payment_header_with_token(token: &str) -> String {
        let creds = PaymentCredentials {
            challenge: EchoedChallenge {
                id: "test-challenge-id".into(),
                realm: DEFAULT_REALM.into(),
                method: "cashu".into(),
                intent: INTENT_CHARGE.into(),
                request: "echoed-request-envelope".into(),
            },
            payload: CashuPayload {
                cashu_token: token.into(),
            },
        };
        format!("Payment {}", encode_payment_credentials(&creds))
    }

    /// Build a GET /gated request whose `Authorization` header is the
    /// Payment Authentication envelope around `token`.
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

    /// Pluck the `WWW-Authenticate` header off a response as a string
    /// — convenience for the many tests that assert on its shape.
    fn www_authenticate(response: &Response) -> String {
        response
            .headers()
            .get(http::header::WWW_AUTHENTICATE)
            .expect("WWW-Authenticate present")
            .to_str()
            .expect("WWW-Authenticate is ASCII")
            .to_string()
    }

    // ---- Core 402 challenge shape ------------------------------------

    #[tokio::test]
    async fn no_authorization_header_returns_402_with_www_authenticate() {
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app.oneshot(bare_request()).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let header = www_authenticate(&response);
        // Cover all five MUST fields from draft §5.1.1.
        assert!(header.starts_with("Payment "), "got: {header}");
        assert!(header.contains(r#"id=""#), "missing id: {header}");
        assert!(header.contains(r#"realm=""#), "missing realm: {header}");
        assert!(
            header.contains(r#"method="cashu""#),
            "missing method=cashu: {header}"
        );
        assert!(
            header.contains(r#"intent="charge""#),
            "missing intent=charge: {header}"
        );
        assert!(header.contains(r#"request=""#), "missing request: {header}");
    }

    #[tokio::test]
    async fn www_authenticate_includes_id_realm_method_intent_request() {
        // Dedicated MUST-coverage test: each draft §5.1.1 required
        // field appears with a non-empty value.
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app.oneshot(bare_request()).await.expect("oneshot");
        let header = www_authenticate(&response);

        for (field, prefix) in &[
            ("id", r#"id=""#),
            ("realm", r#"realm=""#),
            ("method", r#"method=""#),
            ("intent", r#"intent=""#),
            ("request", r#"request=""#),
        ] {
            let start = header
                .find(prefix)
                .unwrap_or_else(|| panic!("missing {field} param in {header}"));
            let rest = &header[start + prefix.len()..];
            let end = rest
                .find('"')
                .unwrap_or_else(|| panic!("unterminated {field} param in {header}"));
            let value = &rest[..end];
            assert!(
                !value.is_empty(),
                "{field} value must be non-empty in {header}"
            );
        }
    }

    #[tokio::test]
    async fn realm_default_is_cdk_pop_verifier() {
        // Lock the default `realm` so an operator-configurable change
        // later is a visible diff. Doc-comment on DEFAULT_REALM
        // explains the operator-configurable plan.
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app.oneshot(bare_request()).await.expect("oneshot");
        let header = www_authenticate(&response);
        assert!(
            header.contains(r#"realm="cdk-pop-verifier""#),
            "got: {header}"
        );
    }

    #[tokio::test]
    async fn www_authenticate_request_is_base64url_nopad_envelope() {
        // The `request` param's contents are base64url-nopad encoded
        // JSON `{ "cashu_request": "creqA..." }` — confirm the encoded
        // string round-trips back to a creqA payload.
        use crate::challenge::decode_request_envelope;
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app.oneshot(bare_request()).await.expect("oneshot");
        let header = www_authenticate(&response);
        let start = header.find(r#"request=""#).expect("has request param");
        let after = &header[start + r#"request=""#.len()..];
        let end = after.find('"').expect("terminated request param");
        let request_value = &after[..end];
        let creq_a = decode_request_envelope(request_value).expect("decodes envelope");
        assert!(
            creq_a.starts_with("creqA"),
            "envelope must wrap a creqA payload, got: {creq_a}"
        );
    }

    #[tokio::test]
    async fn response_402_has_cache_control_no_store() {
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app.oneshot(bare_request()).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let cache = response
            .headers()
            .get(http::header::CACHE_CONTROL)
            .expect("Cache-Control present on 402");
        assert_eq!(
            cache.to_str().expect("ASCII"),
            "no-store",
            "draft §11.10 MUST: Cache-Control: no-store on 402"
        );
    }

    // ---- Happy path --------------------------------------------------

    #[tokio::test]
    async fn valid_token_passes_through_to_handler() {
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

        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        assert_eq!(&body_bytes[..], b"ok:10");
    }

    #[tokio::test]
    async fn authorization_blob_echoes_challenge_id() {
        // The middleware does not enforce binding (SHOULD, skipped),
        // but the round-trip must work: we hand the server a credentials
        // blob with our test id, get 200, and the handler runs.
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let encoded = token.to_string();

        let creds = PaymentCredentials {
            challenge: EchoedChallenge {
                id: "echoed-id-from-client".into(),
                realm: DEFAULT_REALM.into(),
                method: "cashu".into(),
                intent: INTENT_CHARGE.into(),
                request: "echoed-request".into(),
            },
            payload: CashuPayload {
                cashu_token: encoded,
            },
        };
        let header = format!("Payment {}", encode_payment_credentials(&creds));

        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_authorization(&header))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::OK);
    }

    // ---- Validation-failure mapping (all → 402 + re-challenge) -------

    #[tokio::test]
    async fn invalid_header_encoding_returns_402() {
        // 0xFF is not valid UTF-8.
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_raw_authorization(&[0xFFu8, 0xFE, 0xFD]))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        // Must come with a fresh re-challenge per draft §4.2.
        assert!(response
            .headers()
            .get(http::header::WWW_AUTHENTICATE)
            .is_some());
    }

    #[tokio::test]
    async fn malformed_token_returns_402() {
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_token("cashuB!!!notbase64!!!"))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
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
    async fn validation_failure_returns_402_not_400() {
        // The flagship draft §4.2 test: a structurally-OK but
        // unit-mismatched token must come back as 402 + re-challenge,
        // NOT 400.
        let token = make_token(mint_a(), CurrencyUnit::Sat, vec![make_proof(10, 0)]);
        let encoded = token.to_string();

        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_token(&encoded))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        // Fresh challenge present.
        let header = www_authenticate(&response);
        assert!(header.contains(r#"method="cashu""#));
        // Cache-Control still no-store.
        assert_eq!(
            response
                .headers()
                .get(http::header::CACHE_CONTROL)
                .expect("Cache-Control")
                .to_str()
                .unwrap(),
            "no-store"
        );
        // Body explains the failure.
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        let body = std::str::from_utf8(&body_bytes).unwrap_or("<non-utf8 body>");
        assert!(
            body.contains("does not match requirement unit"),
            "expected unit-mismatch body, got: {body}"
        );
    }

    #[tokio::test]
    async fn mint_unreachable_returns_503() {
        // Transport failure: stays as 503 per the comments on
        // validation_error_to_response.
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
    async fn mint_rejected_returns_402() {
        // Swap rejected (expired, double-spent, etc.) is a *validation*
        // failure per draft §4.2 — 402 with a fresh re-challenge so the
        // client can try a different proof.
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let encoded = token.to_string();

        let app = router_with(state_with(SwapResponse::RejectedSwap));
        let response = app
            .oneshot(request_with_token(&encoded))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        let body = std::str::from_utf8(&body_bytes).unwrap_or("<non-utf8 body>");
        assert!(
            body.contains("mint rejected swap"),
            "expected mint-rejected-swap message, got: {body}"
        );
    }

    // ---- Envelope-shape rejection (legacy param form etc.) -----------

    #[tokio::test]
    async fn non_payment_scheme_returns_402_with_no_failure_body() {
        // RFC 7235 §3.1: unsupported scheme is identical to no
        // attempt. Body should be empty (no failure to describe).
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_authorization("Bearer abcdef"))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let header = www_authenticate(&response);
        assert!(header.starts_with(r#"Payment id=""#));
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        assert!(
            body_bytes.is_empty(),
            "bare 402 (no attempt) should have empty body, got: {body_bytes:?}"
        );
    }

    #[tokio::test]
    async fn authorization_must_be_opaque_base64url_blob() {
        // The transitional `method="cashu", token="..."` param form is
        // no longer accepted — base64 decode trips → 402 re-challenge.
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_authorization(
                r#"Payment method="cashu", token="cashuBabc""#,
            ))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    }

    #[tokio::test]
    async fn base64url_decode_failure_returns_402() {
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_authorization("Payment !!!notbase64!!!"))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        let body = std::str::from_utf8(&body_bytes).unwrap_or("<non-utf8>");
        assert!(
            body.contains("base64url"),
            "expected base64 error message, got: {body}"
        );
    }

    #[tokio::test]
    async fn json_parse_failure_returns_402() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let blob = URL_SAFE_NO_PAD.encode(b"not a json object at all");
        let header = format!("Payment {blob}");

        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_authorization(&header))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        let body = std::str::from_utf8(&body_bytes).unwrap_or("<non-utf8>");
        assert!(
            body.contains("JSON is malformed"),
            "expected JSON error message, got: {body}"
        );
    }

    #[tokio::test]
    async fn json_missing_challenge_field_returns_402() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let blob = URL_SAFE_NO_PAD.encode(br#"{"payload":{"cashu_token":"cashuBabc"}}"#);
        let header = format!("Payment {blob}");

        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_authorization(&header))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    }

    #[tokio::test]
    async fn json_missing_payload_field_returns_402() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let blob = URL_SAFE_NO_PAD.encode(
            br#"{"challenge":{"id":"a","realm":"b","method":"cashu","intent":"charge","request":"r"}}"#,
        );
        let header = format!("Payment {blob}");

        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_authorization(&header))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    }

    #[tokio::test]
    async fn wrong_method_returns_402() {
        // `Payment` scheme + valid envelope + `method="tempo"` →
        // validation failure → 402 re-challenge.
        let creds = PaymentCredentials {
            challenge: EchoedChallenge {
                id: "id".into(),
                realm: "r".into(),
                method: "tempo".into(),
                intent: "charge".into(),
                request: "r".into(),
            },
            payload: CashuPayload {
                cashu_token: "cashuBabc".into(),
            },
        };
        let header = format!("Payment {}", encode_payment_credentials(&creds));

        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_authorization(&header))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        let body = std::str::from_utf8(&body_bytes).unwrap_or("<non-utf8>");
        assert!(
            body.contains("must be 'cashu'"),
            "expected wrong-method message, got: {body}"
        );
    }

    #[tokio::test]
    async fn payment_with_empty_credentials_returns_402() {
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_authorization("Payment"))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    }
}
