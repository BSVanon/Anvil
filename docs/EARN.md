# Layer 2 — Earn

Get paid per-request for your data or API. Non-custodial — the node never touches your funds.

---

## What it does

Any Anvil endpoint can require payment via HTTP 402. The payment goes directly to you (the app developer or node operator) in a BSV transaction. The node verifies payment but never holds or forwards your money.

This is x402 — micropayments over HTTP, using BSV transactions as proof-of-payment.

## How it works

1. Client requests a gated endpoint
2. Anvil responds `402 Payment Required` with a challenge (price, payee script, nonce)
3. Client builds a BSV transaction paying the challenge amount to the payee
4. Client retries the request with `X402-Proof` header containing the payment proof
5. Anvil verifies the proof and serves the response

The client pays. The node verifies. Your address receives the funds. Nobody custodies anything.

## Four payment models

| Model | Who gets paid | Config |
|-------|--------------|--------|
| **Free** | Nobody | `payment_satoshis = 0` |
| **Node merchant** | Node operator | `payment_satoshis = 10` (any amount) |
| **Passthrough** | App developer only | App sets `monetization.model = "passthrough"` in envelope |
| **Split** | App + node | App sets `monetization.model = "split"` — one tx pays both |

### Free (default)

No payment required. All endpoints are open. This is the default.

```toml
[api]
payment_satoshis = 0
```

### Node merchant

The node operator charges per-request. Revenue goes to the node's wallet.

```toml
[api]
payment_satoshis = 10    # 10 sats per request
```

### Passthrough (app as sole payee)

The app developer includes a `monetization` block in the envelope. The node enforces payment to the app's address — the node gets nothing.

```json
{
  "type": "data",
  "topic": "premium:analytics",
  "payload": "...",
  "monetization": {
    "model": "passthrough",
    "payee_locking_script_hex": "76a914<your-pkh>88ac",
    "price_sats": 50
  }
}
```

The monetization block is included in the signing digest — it cannot be altered in transit.

Enable on the node:
```toml
[api.app_payments]
allow_passthrough = true
max_app_price_sats = 10000
```

### Split (app + node)

One transaction pays both the app developer and the node operator. Two outputs in a single atomic payment.

```json
{
  "monetization": {
    "model": "split",
    "payee_locking_script_hex": "76a914<app-pkh>88ac",
    "price_sats": 50
  }
}
```

The consumer pays `50 (app) + 10 (node) = 60 sats` total. Enable:
```toml
[api.app_payments]
allow_split = true
```

### Token gating

Apps issue credentials to authorized consumers. The node validates the token without knowing the credential scheme.

```toml
[api.app_payments]
allow_token_gating = true
```

Consumer sends `X-App-Token: <credential>` header. The node forwards it to the app for validation.

## Discovery

Every node publishes its payment capabilities at `/.well-known/x402`:

```bash
curl http://localhost:9333/.well-known/x402
```

```json
{
  "version": "0.1",
  "network": "mainnet",
  "scheme": "bsv-tx-v1",
  "endpoints": [
    {"method": "GET", "path": "/data", "price": 0},
    {"method": "GET", "path": "/status", "price": 0}
  ],
  "payment_models": ["node_merchant", "passthrough", "split", "token"],
  "non_custodial": true
}
```

This is the machine-readable menu that AI agents and automated systems use to discover what a node charges and how to pay.

## Non-custodial guarantee

Anvil is designed to be non-custodial by default. See [Non-Custodial Payment Policy](NON_CUSTODIAL_PAYMENT_POLICY.md) for the full policy, including what's prohibited and how to avoid accidentally becoming a money transmitter.

## Next: machine economy

Let machines discover, negotiate, and pay automatically.

**[Layer 3: Discover →](DISCOVER.md)**
