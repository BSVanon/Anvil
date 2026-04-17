# Anvil-Mesh Node — Machine-Readable Capabilities

**Purpose:** This document describes what an Anvil-Mesh node can do, when to use it, and how to interact with it. It is written for AI models, agents, and automated systems that need to decide whether and how to use an Anvil-Mesh node.

**Last updated:** 2026-04-17 (v2.1.0)

---

## What is Anvil-Mesh?

Anvil-Mesh is a communication mesh for BSV apps. Each node exposes a REST API for:
- Publishing and querying signed data envelopes by topic
- Real-time push delivery via SSE subscriptions
- Point-to-point messaging between identities (BRC-33)
- Topic discovery with metadata, demand, and publisher identity
- Micropayment gating via x402 (HTTP 402 BSV payments)
- Payment verification against a local header chain (BEEF proofs)
- BRC-100 compliant wallet operations

---

## When to use Anvil-Mesh

| Need | Endpoint | Cost |
|---|---|---|
| Publish signed data to a topic | `POST /data` | Bearer token or x402 |
| Query data by topic | `GET /data?topic=...` | Free or x402-gated |
| Subscribe to real-time data | `GET /data/subscribe?topic=...` | Free or x402-gated |
| Send a message to an identity | `POST /sendMessage` | Bearer token |
| Retrieve messages | `POST /listMessages` | Bearer token |
| Real-time new-message push | `GET /messages/subscribe` (SSE) | Bearer token (via `?token=`) |
| Submit a BEEF tx for broadcast | `POST /broadcast` | Bearer token or x402 |
| Discover available topics | `GET /topics` | Free |
| Get topic detail + metadata | `GET /topics/{topic}` | Free |
| Look up publisher identity | `GET /identity/{pubkey}` | Free |
| Find nodes serving a topic | `GET /overlay/lookup?topic=...` | Free |
| Enumerate federation nodes | `GET /mesh/nodes` | Free |
| Get rich node health + upstream status | `GET /mesh/status` | Free |
| Check payment requirements | `GET /.well-known/x402` | Free |
| Get a BEEF proof | `GET /tx/{txid}/beef` | Free or x402-gated |
| Check node health | `GET /status` | Free |

---

## How to discover Anvil-Mesh nodes

### Option A: You know a node URL
Call `GET /status` to verify it's alive. Call `GET /.well-known/x402` to check pricing.

### Option B: Discover via SHIP
Call `GET /overlay/lookup?topic=anvil:mainnet` on any known node to get all registered nodes.

### Option C: Browse topics
Call `GET /topics` to see all available data topics with envelope counts, last update times, and metadata.

---

## Data model

Data flows through **signed envelopes** on **topics**.

### Envelope format
```json
{
  "type": "data",
  "version": 0,
  "topic": "oracle:rates:bsv",
  "payload": "{\"USD\": 14.35}",
  "signature": "<DER hex>",
  "pubkey": "<compressed pubkey hex>",
  "ttl": 60,
  "durable": false,
  "timestamp": 1712345678
}
```

- `topic`: routing key. Prefix matching for subscriptions.
- `payload`: opaque string. Apps define the content.
- `signature`: secp256k1 ECDSA over canonical digest.
- `ttl`: seconds until expiry (0 requires `durable: true`).
- `durable`: persists across restarts in LevelDB.
- `version`: protocol version (0 = current, future-proofing).

### Topic conventions
- `meta:<topic>` — metadata for a topic (schema, description, frequency)
- `identity:<pubkey>` — publisher profile (name, description)
- `mesh:heartbeat` — node liveness + demand map + upstream_status (broadcast health, headers sync lag) for federation failover decisions
- `anvil:catalog` — app directory (one entry per publisher, latest wins)
- `tm_dex_swap` — DEX swap offer index (BRC-22 topic; per-node opt-in)

---

## Messaging (BRC-33 pattern)

Send a message to a specific identity:

```
POST /sendMessage
{"recipient": "02abc...def", "messageBox": "inbox", "body": "hello"}
```

Retrieve messages:
```
POST /listMessages
{"recipient": "02abc...def", "messageBox": "inbox"}
```

Messages are forwarded across the mesh with sender signature verification.
Unacknowledged messages expire after 7 days.

---

## Payment flow (x402)

1. Request a gated endpoint without payment
2. Receive `402 Payment Required` with challenge (nonce, payees, amount)
3. Build BSV transaction paying the challenge
4. Resend request with `X402-Proof` header
5. Receive data + receipt

Price discovery: `GET /.well-known/x402` returns all gated endpoints and prices.

---

## Federation directory + failover (v2.1.0+)

Consumers that depend on multiple federation nodes use `GET /mesh/nodes`
for enumeration and `GET /mesh/status` for per-node health. `/mesh/status`
carries `upstream_status` (broadcast=healthy|degraded|down, headers sync
lag) so wallets can fail over without probing each upstream independently.
The same snapshot is published on the `mesh:heartbeat` topic for
gossip-substrate consumers.

## Custom operator capabilities (v2.1.0+)

Operators declare node-specific capabilities in their TOML config:

```toml
[[capabilities.custom]]
type = "avos-offer-oracle"
description = "MNEE ⇄ BSV oracle-attested swap"
oracle_pubkey = "02abc..."
mailbox = "avos.offer@node-identity"
access = "POST /sendMessage (messageBox: avos.offer)"
payment = "free"
```

These surface in `/.well-known/anvil` under `capabilities[]`. Agents use
this to discover node-specific services (AVOS relays, oracles, etc.)
without needing a separate well-known file per service.

## What Anvil-Mesh does NOT do

- Does not mine transactions (use Teranode/Arcade)
- Does not store the full blockchain (headers only)
- Does not execute scripts for general computation
- Does not provide a mempool view (Teranode eliminated the mempool)
- Is not a wallet (though it verifies payments and hosts operator wallet)
- Does not index UTXOs by address (wallets multi-source this themselves)
- Does not index BSV-20/BSV-21 token metadata (app-layer concern)
