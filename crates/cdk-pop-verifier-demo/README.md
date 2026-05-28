# cdk-pop-verifier-demo

A minimal HTTP service that exercises the [`cdk-pop-verifier`](../cdk-pop-verifier) SDK
end-to-end against a real (or test) PoP-issuing Cashu mint.

One endpoint:

- `GET /random-number` — returns `{ "number": <random u64> }` after a
  NUT-24 PoP challenge has been satisfied.

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

## Manual smoke test

### 1. Hit the endpoint with no credential

```sh
curl -i http://localhost:3000/random-number
```

You should see:

```text
HTTP/1.1 402 Payment Required
x-cashu: creqA...<base64url>
content-length: 0
```

The `x-cashu` header carries the NUT-18 `creqA…` payment request that
encodes everything a wallet needs to mint a PoP credential: mint URL,
unit (e.g. `pop_1700000000`), and amount.

### 2. Extract the challenge

```sh
curl -si http://localhost:3000/random-number \
  | awk '/^x-cashu:/ {print $2}' \
  | tr -d '\r\n'
```

Hand that `creqA…` string to a NUT-18-aware Cashu wallet to mint the
required PoP credential. (Wallet integration is out of scope for this
demo — Commit 7 wires up an agent-side client.)

### 3. Retry with the proof

Once the wallet hands back a `cashuB…` token, replay the request with
it in the `X-Cashu` header:

```sh
curl -i \
  -H 'X-Cashu: cashuB...<your token>' \
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

- **No header, expired mint**: 402 returned but wallet melt/mint fails
  out-of-band. Demo log stays quiet.
- **Bad token (`cashuB!!!notbase64!!!`)**: `400 Bad Request` with body
  `decode failed: …`.
- **Wrong unit (e.g. wallet minted `sat` instead of `pop_<ts>`)**: `400
  Bad Request` with body `token unit … does not match requirement
  unit …`.
- **Mint unreachable mid-validation**: `503 Service Unavailable` with
  body `mint unreachable: …`. Client may safely retry the same token.
- **Wrong mint URL (token from another mint)**: `400 Bad Request` with
  body `token mint … is not in the requirement's allowed mints: …`.

See `crates/cdk-pop-verifier/src/middleware.rs` for the full
status-code → error mapping (per NUT-24 §"Errors").

## Out of scope

This commit ships the bearer arm only. There is **no** MPP-Cashu
`WWW-Authenticate: Payment` emitted alongside the 402, and **no**
separate `/pay` endpoint — clients retry the same URL with the proof
in `X-Cashu`. The MPP-Cashu extension is being drafted separately.
