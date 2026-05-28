# cdk-pop-verifier-demo

A minimal HTTP service that exercises the [`cdk-pop-verifier`](../cdk-pop-verifier) SDK
end-to-end against a real (or test) PoP-issuing Cashu mint.

One endpoint:

- `GET /random-number` — returns `{ "number": <random u64> }` after a
  PoP challenge has been satisfied.

The demo is intentionally bare. It is a **smoke target**: spin it up
against a running mint and prove the protocol works. No automated tests
in this crate — the whole point is the live wire path.

## Build & run

```sh
cargo run -p cdk-pop-verifier-demo -- \
  --mint-url https://your-pop-mint.example.com \
  --unit pop_1700000000 \
  --amount 100
```

Default bind: `127.0.0.1:3000`. Override with `--bind 0.0.0.0` and
`--port 8080` as needed.

`--help`:

```text
PoP-gated random-number HTTP service (cdk-pop-verifier smoke target)

Usage: cdk-pop-verifier-demo [OPTIONS] --mint-url <MINT_URL> --unit <UNIT> --amount <AMOUNT>

Options:
      --port <PORT>          TCP port to listen on [default: 3000]
      --bind <BIND>          Address to bind to [default: 127.0.0.1]
      --mint-url <MINT_URL>  URL of the PoP-issuing mint
      --unit <UNIT>          CurrencyUnit (e.g. pop_1700000000)
      --amount <AMOUNT>      Exact amount required per presentation
  -h, --help                 Print help
```

## TLS deployment (MUST in production)

`draft-httpauth-payment-00` §11 requires TLS for any deployment that
processes real value:

> "Implementations MUST use TLS 1.2 or later for all communications
> carrying Payment Authentication credentials."

The demo binary listens on plain HTTP for local-loopback convenience
only — that is fine for a smoke target running on `127.0.0.1`. **Any
internet-facing deployment of this code (or downstream code reusing
`cdk-pop-verifier`) MUST sit behind a TLS-terminating reverse proxy
(nginx, caddy, traefik, AWS ALB, etc.) or be modified to terminate
TLS directly via `axum-server` / `hyper-rustls`.** Without TLS, the
`Authorization: Payment …` credentials blob — which carries the
holder's `cashuB…` token — is exposed to any on-path observer, who
could then race the legitimate client to the mint's swap endpoint and
steal the value before the verifier completes its own swap.

## Manual smoke test

The wire shape is `draft-httpauth-payment-00`. The 402 carries five
required auth-params on `WWW-Authenticate: Payment`; the retry carries
a single base64url-nopad-encoded JSON credentials blob on
`Authorization: Payment`.

### 1. Hit the endpoint with no credential

```sh
curl -i http://localhost:3000/random-number
```

You should see:

```text
HTTP/1.1 402 Payment Required
www-authenticate: Payment id="<uuid>", realm="cdk-pop-verifier", method="cashu", intent="charge", request="<base64url-nopad>"
cache-control: no-store
content-length: 0
```

Per draft §11.10 every 402 carries `Cache-Control: no-store`. The
`request` auth-param is a base64url-nopad-encoded JSON object
`{ "cashu_request": "creqA…" }` — the inner `creqA…` is the
standard NUT-18 payment-request the wallet uses to mint a PoP
credential.

### 2. Extract the inner `creqA…` from the `request` envelope

```sh
# 1. Pull the WWW-Authenticate value.
WWW=$(curl -si http://localhost:3000/random-number | awk 'BEGIN{IGNORECASE=1} /^www-authenticate:/' | tr -d '\r')

# 2. Pluck the request auth-param.
REQ_BLOB=$(echo "$WWW" | sed -E 's/.*request="([^"]+)".*/\1/')

# 3. Base64url-nopad-decode, parse JSON, extract cashu_request.
CREQ=$(printf '%s' "$REQ_BLOB" | base64 -d --ignore-garbage 2>/dev/null | python3 -c 'import sys,json; print(json.load(sys.stdin)["cashu_request"])')
echo "$CREQ"
```

(GNU `base64` doesn't natively handle the URL-safe alphabet without
padding; on systems where it does, prefer the native flag. The Python
JSON unwrap is the only readable way to extract the inner field from
the shell.)

Hand that `creqA…` string to a NUT-18-aware Cashu wallet to mint the
required PoP credential.

### 3. Wrap the `cashuB…` token in the credentials envelope and retry

Once the wallet returns a `cashuB…` token, build the credentials
JSON, base64url-nopad-encode it, and replay the request with it
inside an `Authorization: Payment` header. The `challenge` field
echoes every auth-param the server sent on the 402:

```sh
# Assume $ID, $REALM, $METHOD, $INTENT, $REQ_BLOB pulled from the WWW-Authenticate above,
# and $CASHU_TOKEN is the cashuB... string from the wallet.
BLOB=$(python3 -c "
import base64, json
creds = {
  'challenge': {
    'id':      '$ID',
    'realm':   '$REALM',
    'method':  '$METHOD',
    'intent':  '$INTENT',
    'request': '$REQ_BLOB'
  },
  'payload': {'cashu_token': '$CASHU_TOKEN'}
}
print(base64.urlsafe_b64encode(json.dumps(creds).encode()).rstrip(b'=').decode())
")

curl -i \
  -H "Authorization: Payment $BLOB" \
  http://localhost:3000/random-number
```

Expected:

```text
HTTP/1.1 200 OK
content-type: application/json

{"number": 12035623854761340121}
```

The number is fresh per request; `rand::thread_rng().next_u64()` under
the hood.

### Error cases worth poking at

Per `draft-httpauth-payment-00` §4.2 every validation failure (bad
header, bad token, wrong unit, wrong mint, insufficient amount,
malformed proof, mint-rejected swap) returns `402 Payment Required`
with a *fresh* `WWW-Authenticate: Payment` re-challenge and
`Cache-Control: no-store`. The response body is a plain-text
description of why the previous attempt failed.

- **Bad token (`cashuB!!!notbase64!!!` inside the credentials)**:
  `402` with body `decode failed: …`.
- **Wrong method (`challenge.method = "tempo"`)**: `402` with body
  `… method must be 'cashu', got "tempo"`.
- **Wrong scheme (`Authorization: Bearer …`)**: middleware responds
  `402` again with the cashu challenge — the request is treated as
  "no PoP attempt" and the body is empty.
- **Legacy param form (`Payment method="cashu", token="…"`)**: the
  parser now requires a base64url-nopad blob; the old form trips the
  base64 decoder → `402` re-challenge.
- **Wrong unit (e.g. wallet minted `sat` instead of `pop_<ts>`)**:
  `402` with body `token unit … does not match requirement unit …`.
- **Mint unreachable mid-validation**: `503 Service Unavailable` with
  body `mint unreachable: …`. Client may safely retry the same token —
  this is the only non-402 failure mode, because the draft does not
  constrain backend transport failures.
- **Wrong mint URL (token from another mint)**: `402` with body
  `token mint … is not in the requirement's allowed mints: …`.

See `crates/cdk-pop-verifier/src/middleware.rs` for the full
status-code → error mapping.

## Out of scope

This commit ships only the MUST-level subset of
`draft-httpauth-payment-00`. The following draft features are
SHOULD/MAY/OPTIONAL and intentionally not implemented:

- `Payment-Receipt` response header on 200 (SHOULD)
- RFC 9457 Problem Details JSON response bodies (SHOULD)
- `digest` / `expires` / `description` / `opaque` auth-params on
  `WWW-Authenticate` (OPTIONAL)
- `source` (DID) field on the credentials JSON (RECOMMENDED)
- Multi-method advertisement (MAY)
- `Idempotency-Key` request header / `Accept-Payment` request header
  (SHOULD / MAY)
- Stateless challenge-id binding via HMAC per draft §5.1.2.1.1 — the
  `id` is currently a fresh UUIDv4 (SHOULD)
- IANA registration of `cashu` as a `method` value or `charge` as an
  `intent` value (deferred)
