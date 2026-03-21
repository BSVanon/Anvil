# Anvil Node — Machine-Readable Capabilities

**Purpose:** This document describes what an Anvil node can do, when to use it, and how to interact with it. It is written for AI models, agents, and automated systems that need to decide whether and how to use an Anvil node.

**Last updated:** 2026-03-19

---

## What is Anvil?

Anvil is a BSV SPV node that exposes a REST API for:
- Verifying BSV transactions (BEEF format) against a local header chain
- Serving transaction proofs
- Relaying signed data envelopes across a mesh of peer nodes
- Managing a BRC-100 compliant wallet (invoices, payments, UTXO management)
- Discovering other nodes via on-chain SHIP/SLAP tokens

Anvil nodes can optionally charge for API access via the x402 protocol (HTTP 402 micropayments).

---

## When to use Anvil

Use an Anvil node when you need to:

| Need | Anvil endpoint | Cost |
|---|---|---|
| Verify a BSV payment is real | `POST /broadcast` (with BEEF) | Authenticated (bearer token) |
| Get a transaction's BEEF proof | `GET /tx/{txid}/beef` | Free or x402-gated |
| Query signed data by topic | `GET /data?topic=...` | Free or x402-gated |
| Find nodes serving a topic | `GET /overlay/lookup?topic=...` | Free or x402-gated |
| Check node health and header height | `GET /status` | Free or x402-gated |
| Create a payment invoice | `POST /wallet/invoice` | Authenticated |
| Check if an invoice was paid | `GET /wallet/invoice/{id}` | Authenticated |
| Send BSV from the node wallet | `POST /wallet/send` | Authenticated |
| Scan for external UTXOs | `POST /wallet/scan` | Authenticated |
| Check payment models | `GET /.well-known/x402` | Free |

---

## How to discover Anvil nodes

### Option A: You know a node URL
Call `GET /status` to verify it's alive. Call `GET /.well-known/x402` to check if payment is required.

### Option B: Discover via SHIP tokens
If you have access to any Anvil node, call `GET /overlay/lookup?topic=foundry:mainnet` to get a list of all registered Anvil nodes (from on-chain SHIP tokens). Each result includes `domain`, `identity_pub`, and `topics`.

---

## x402 payment flow

If an endpoint returns HTTP 402, it requires payment. The flow:

1. **Request** → endpoint returns `402` with `X402-Challenge` header (base64url JSON)
2. **Challenge contains:** price in satoshis, payee locking script, nonce UTXO to spend, expiry time, request binding (method, path, query, header hash, body hash)
3. **Client builds a BSV transaction** that:
   - Spends the nonce UTXO (input)
   - Pays the payee script >= price satoshis (output)
4. **Client retries** the same request with `X402-Proof` header containing the signed tx
5. **Server verifies** the proof and returns the response + `X402-Receipt` header

### Key properties:
- **Stateless:** No accounts, no API keys, no session cookies
- **Replay-safe:** The nonce UTXO can only be spent once (consensus layer)
- **Payee-bound:** Payment must go to the declared payee's address
- **Request-bound:** Payment is cryptographically tied to the specific HTTP request
- **Non-custodial:** The node never receives funds destined for another party

### Payment models:
| Model | Description | Challenge |
|---|---|---|
| Node Merchant | Node charges per-request | Single payee (node's script) |
| Passthrough | App is sole payee | Single payee (app's script from envelope monetization) |
| Split | Node + app both paid | Multi-payee challenge, consumer builds tx with 2 outputs |
| Token Gate | App-issued credential, no payment | `X-App-Token` header, verified against envelope `auth_pubkey` |
| Free | Default | No 402 challenge |

Apps declare their payment model in the envelope `monetization` field (signed, tamper-proof). The node routes x402 challenges accordingly. See `NON_CUSTODIAL_PAYMENT_POLICY.md`.

### Discovery:
`GET /.well-known/x402` returns a JSON manifest listing gated endpoints, prices, and supported `payment_models`.

---

## API reference (summary)

### Open read endpoints (free or x402-gated)

```
GET /status
  → { node, version, headers: { height, work } }

GET /headers/tip
  → { height, hash }

GET /tx/{txid}/beef
  → { txid, beef } (hex) or raw binary (Accept: application/octet-stream)

GET /data?topic=...&limit=...
  → { topic, count, envelopes: [...] }

GET /overlay/lookup?topic=...
  → { topic, count, peers: [{ domain, identity_pub, topics }] }

GET /.well-known/x402
  → { version, network, scheme, endpoints: [{ method, path, price }] }
```

### Authenticated write endpoints (bearer token)

```
POST /broadcast
  Body: BEEF (binary or JSON { beef: "hex" })
  → { txid, confidence, stored, mempool, arc }

POST /data
  Body: signed envelope JSON
  → { accepted, topic, durable, key }

POST /wallet/invoice
  Body: { counterparty?, description }
  → { id, address, public_key, description }

GET /wallet/invoice/{id}
  → { id, address, description, paid, txid?, amount? }

POST /wallet/send
  Body: { to, satoshis, description }
  → { txid, satoshis, to }

GET /wallet/outputs?basket=...
  → { totalOutputs, outputs: [...] }

POST /wallet/internalize
  Body: InternalizeActionArgs (with BEEF)
  → InternalizeActionResult

POST /wallet/create-action
  Body: CreateActionArgs
  → CreateActionResult

POST /wallet/sign-action
  Body: SignActionArgs
  → SignActionResult

POST /wallet/scan
  Body: { address? }  (optional — defaults to identity address)
  → { address, utxos_found, internalized, already_known, errors, total_satoshis, details }
```

---

## Confidence levels for payment verification

When you submit BEEF to `POST /broadcast`, the response includes a `confidence` field:

| Level | Meaning | Time | Risk |
|---|---|---|---|
| `spv_verified` | Merkle proofs valid against local headers | ~50ms | Double-spend possible |
| `partially_verified` | Some proofs valid, some missing | ~50ms | Higher risk |
| `invalid` | Proofs don't match headers | ~50ms | Reject |

With ARC enabled (`?arc=true`), additional levels:
| `arc.SEEN_ON_NETWORK` | Miners have the tx | ~1-2s | Low risk |
| `arc.MINED` | Tx is in a block | ~minutes | Final |

---

## Data envelope format

Envelopes gossiped across the mesh have this structure:

```json
{
  "type": "data",
  "topic": "oracle:rates:bsv",
  "payload": "{\"rate\":42.50}",
  "signature": "3045...",
  "pubkey": "02ab...",
  "ttl": 60,
  "durable": false,
  "timestamp": 1710000000,
  "monetization": {
    "model": "split",
    "payee_locking_script_hex": "76a914<app-address>88ac",
    "price_sats": 50
  }
}
```

- `topic`: string prefix-matched for routing (e.g. "oracle:" matches "oracle:rates:bsv")
- `payload`: opaque to the node, interpreted by apps
- `signature`: ECDSA over all semantic fields including monetization (tamper-proof)
- `ttl`: seconds until expiry (0 + durable=true = persist forever)
- `monetization`: optional — declares how consumers pay. Models: `passthrough`, `split`, `token`, `free`. Included in signing digest so apps control their payment terms and they can't be altered in transit.

---

## Network topology

Anvil nodes form the **Foundry** mesh:
- Authenticated WebSocket peering via go-sdk auth.Peer (BRC-31)
- Topic-filtered gossip: nodes only forward envelopes matching declared interests
- On-chain discovery via SHIP tokens (no central directory)
- Inbound + outbound peer connections with clean lifecycle management

---

## Technology stack

| Component | Implementation |
|---|---|
| Language | Go |
| Crypto / tx | [go-sdk](https://github.com/bsv-blockchain/go-sdk) (BRC-42/43, BEEF, auth.Peer) |
| Wallet | [go-wallet-toolbox](https://github.com/bsv-blockchain/go-wallet-toolbox) (BRC-100) |
| Storage | LevelDB (embedded) |
| Overlay discovery | JungleBus (real-time SHIP/SLAP detection) |
| Broadcast | ARC (optional, for miner submission) |
| Payment gating | x402 (merkleworks-x402-spec v1.0) |
