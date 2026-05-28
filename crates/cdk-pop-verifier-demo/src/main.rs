//! `cdk-pop-verifier-demo` — minimal HTTP service that exercises the
//! `cdk-pop-verifier` SDK end-to-end against a real (or test) PoP mint.
//!
//! Exposes one endpoint:
//!
//! * `GET /random-number` — returns `{ "number": <random u64> }` after
//!   the MPP-Cashu PoP challenge has been satisfied.
//!
//! The endpoint is wrapped in [`cdk_pop_verifier::require_pop`], so the
//! first request from a fresh client gets a `402 Payment Required` with
//! a `WWW-Authenticate: Payment method="cashu", challenge="creqA…"`
//! header. The client obtains a PoP credential from the configured
//! mint (out of band — e.g. via a Cashu wallet), then retries the same
//! URL with `Authorization: Payment method="cashu", token="cashuB…"`.
//! On validation success the handler runs and returns a random number.
//!
//! This binary is intentionally tiny: it exists to prove the protocol
//! works against a live mint, not to ship a product feature. There is
//! no agent-side client integration and no automated tests — see
//! `README.md` for the manual smoke-test recipe.

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use axum::extract::Extension;
use axum::middleware::from_fn_with_state;
use axum::routing::get;
use axum::{Json, Router};
use cashu::{Amount, CurrencyUnit, MintUrl};
use cdk_pop_verifier::{
    CdkMintClient, PopMiddlewareState, PopRequirement, PopValidator, ValidatedPop, require_pop,
};
use clap::Parser;
use rand::RngCore;
use serde::Serialize;
use tracing::info;

// CLI arguments for the demo (parsed via clap's derive API). All flags
// except `--port` and `--bind` are required: the demo cannot construct a
// `PopRequirement` without a mint URL, a unit, and an amount. The struct
// has a `//` (non-doc) comment instead of `///` so clap's derive picks up
// the `#[command(about = …)]` line below for the help banner rather than
// a leaked doc-comment paragraph.
#[derive(Debug, Parser)]
#[command(
    name = "cdk-pop-verifier-demo",
    about = "PoP-gated random-number HTTP service (cdk-pop-verifier smoke target)"
)]
struct Args {
    /// TCP port to listen on.
    #[arg(long, default_value_t = 3000)]
    port: u16,

    /// Address to bind to. Defaults to loopback; pass `0.0.0.0` to expose
    /// the demo on all interfaces.
    #[arg(long, default_value = "127.0.0.1")]
    bind: IpAddr,

    /// URL of the PoP-issuing mint, e.g. `https://mint.example.com`.
    /// Echoed back to clients as the only allowed mint inside the
    /// `creqA…` challenge.
    #[arg(long, value_parser = parse_mint_url)]
    mint_url: MintUrl,

    /// `CurrencyUnit` the verifier requires on incoming proofs. For PoP
    /// this is the literal string `pop_<unix_ts>` (with `<unix_ts>` the
    /// CLTV expiry of the credential). Stored verbatim as
    /// `CurrencyUnit::Custom`.
    #[arg(long, value_parser = parse_unit)]
    unit: CurrencyUnit,

    /// Exact amount (in unit-base) the verifier requires in each proof
    /// presentation.
    #[arg(long)]
    amount: u64,
}

/// clap value-parser for `MintUrl`. Returns a human-readable error so
/// the CLI surfaces a useful message instead of a `Debug` dump.
fn parse_mint_url(s: &str) -> Result<MintUrl, String> {
    MintUrl::from_str(s).map_err(|e| format!("invalid mint url {s:?}: {e}"))
}

/// clap value-parser for `CurrencyUnit`. `CurrencyUnit::from_str` is
/// infallible on the PoP path (any non-builtin string becomes
/// `Custom`), but we keep the `Result` boundary in case cashu later
/// rejects e.g. control characters.
fn parse_unit(s: &str) -> Result<CurrencyUnit, String> {
    CurrencyUnit::from_str(s).map_err(|e| format!("invalid currency unit {s:?}: {e}"))
}

/// Body of a successful `/random-number` response.
///
/// One field, named `number`, matches the spec from
/// `crates/cdk-pop-verifier-demo/README.md`. `Serialize` is all axum
/// needs to render it via `Json<…>`.
#[derive(Debug, Serialize)]
struct RandomNumberResponse {
    number: u64,
}

/// `GET /random-number` handler. The middleware has already validated
/// the PoP — the `Extension<ValidatedPop>` extraction proves it ran
/// (otherwise axum returns 500 here). We deliberately ignore the
/// `ValidatedPop` body: the demo's only job is to return a fresh u64.
async fn handler(Extension(_validated): Extension<ValidatedPop>) -> Json<RandomNumberResponse> {
    // `OsRng` would be overkill for a smoke target; `thread_rng` is
    // fast and seeded once per worker. Quality of randomness is not a
    // property the PoP protocol claims.
    let number = rand::thread_rng().next_u64();
    Json(RandomNumberResponse { number })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // `try_from_default_env` honours `RUST_LOG`; the fallback gives the
    // operator something useful even when the env is bare.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("cdk_pop_verifier_demo=info,info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let args = Args::parse();

    // Build the requirement the verifier will advertise on the 402.
    // The mint allowlist is a single-element vec — the demo only knows
    // about one mint per process.
    let requirement = PopRequirement {
        unit: args.unit.clone(),
        mints: vec![args.mint_url.clone()],
        amount: Amount::from(args.amount),
        payment_id: None,
        description: Some("cdk-pop-verifier-demo random-number".to_string()),
        single_use: true,
    };

    // The real cdk-backed client. Stateless — see `CdkMintClient` docs.
    let mint_client = CdkMintClient::new();
    let validator = PopValidator::new(mint_client);
    let state = Arc::new(PopMiddlewareState::new(requirement, validator));

    // Wire the middleware in front of `/random-number`. The turbofish
    // on `require_pop::<CdkMintClient>` is required: the function is
    // generic over `M: MintClient`, and axum's `from_fn_with_state`
    // can't infer it from the state type alone.
    let app = Router::new().route("/random-number", get(handler)).layer(
        from_fn_with_state(state, require_pop::<CdkMintClient>),
    );

    let addr = SocketAddr::new(args.bind, args.port);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(
        %addr,
        mint = %args.mint_url,
        unit = %args.unit,
        amount = args.amount,
        "cdk-pop-verifier-demo listening"
    );

    axum::serve(listener, app).await?;
    Ok(())
}
