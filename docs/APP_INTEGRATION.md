# App Integration Guide

How to connect your app to an Anvil node.

---

## The short version

1. Your app **signs an envelope** (JSON with topic, payload, signature)
2. Your app **POSTs it** to `POST /data` on an Anvil node (with bearer token or x402 payment)
3. The Anvil mesh **gossips it** to all nodes interested in that topic
4. Consumers **query it** via `GET /data?topic=...` on any node in the mesh

That's it. Your app is a publisher. Anvil is the distribution layer.

---

## Step 1: Get access to an Anvil node

You need:
- **Node URL** — e.g. `http://212.56.43.191:9333`
- **Auth token** — the node operator gives you a bearer token, OR you pay per-request via x402

Test connectivity:
```bash
curl http://NODE_URL/status
# → {"node":"anvil","version":"0.1.0","headers":{"height":940965,"work":"..."}}
```

---

## Step 2: Build and sign an envelope

An envelope is a signed JSON object:

```json
{
  "type": "data",
  "topic": "your-app:your-topic",
  "payload": "{\"rate\":42.50,\"pair\":\"BSV/USD\"}",
  "signature": "3045...",
  "pubkey": "02ab...",
  "ttl": 60,
  "timestamp": 1710000000
}
```

**Fields:**
| Field | Required | Description |
|-------|----------|-------------|
| `type` | Yes | Always `"data"` |
| `topic` | Yes | Routing key — nodes subscribe by prefix (e.g. `oracle:` matches `oracle:rates:bsv`) |
| `payload` | Yes | Your data (opaque string — Anvil doesn't parse it) |
| `signature` | Yes | DER hex signature over the signing digest |
| `pubkey` | Yes | Compressed pubkey hex of the signer |
| `ttl` | Yes | Seconds until expiry. Use `0` + `durable: true` for persistent data |
| `durable` | No | `true` = persist forever (requires `ttl: 0`) |
| `timestamp` | Yes | Unix timestamp |

**Signing digest** (SHA-256 of this concatenation):
```
type + "\n" + topic + "\n" + payload + "\n" + ttl + "\n" + durable + "\n" + timestamp
```

### Example in Node.js

```javascript
import { PrivateKey } from '@bsv/sdk'

const key = PrivateKey.fromWif('your-wif')
const envelope = {
  type: 'data',
  topic: 'oracle:rates:bsv',
  payload: JSON.stringify({ rate: 42.50, pair: 'BSV/USD', ts: Date.now() }),
  ttl: 60,
  durable: false,
  timestamp: Math.floor(Date.now() / 1000),
}

// Build the signing preimage
const durableStr = envelope.durable ? 'true' : 'false'
const preimage = [envelope.type, envelope.topic, envelope.payload,
  envelope.ttl, durableStr, envelope.timestamp].join('\n')

// IMPORTANT: pass raw preimage bytes to sign() — it SHA-256s internally.
// Do NOT pre-hash. Pre-hashing causes double-SHA256 and signature mismatch.
const sig = key.sign(Array.from(Buffer.from(preimage, 'utf8')))
envelope.signature = sig.toDER('hex')
envelope.pubkey = key.toPublicKey().toString()
```

### Example in Go

```go
env := &envelope.Envelope{
    Type:    "data",
    Topic:   "oracle:rates:bsv",
    Payload: `{"rate":42.50}`,
    TTL:     60,
    Timestamp: time.Now().Unix(),
}
env.Sign(privateKey) // sets Signature + Pubkey
```

---

## Step 3: Publish to Anvil

```bash
curl -X POST http://NODE_URL/data \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"type":"data","topic":"oracle:rates:bsv","payload":"{...}","signature":"...","pubkey":"...","ttl":60,"timestamp":1710000000}'
```

Response:
```json
{"accepted": true, "topic": "oracle:rates:bsv", "durable": false, "key": "oracle:rates:bsv:02ab...:a1b2c3d4"}
```

The envelope is now stored on this node and gossiped to all mesh peers interested in the `oracle:` prefix.

---

## Step 4: Consumers query the data

From any Anvil node:
```bash
curl "http://NODE_URL/data?topic=oracle:rates:bsv&limit=10"
```

Response:
```json
{
  "topic": "oracle:rates:bsv",
  "count": 1,
  "envelopes": [
    {
      "type": "data",
      "topic": "oracle:rates:bsv",
      "payload": "{\"rate\":42.50}",
      "signature": "3045...",
      "pubkey": "02ab...",
      "ttl": 60,
      "timestamp": 1710000000
    }
  ]
}
```

Consumers can verify the signature themselves — all fields are signed.

---

## Topic naming convention

Use a hierarchical prefix:
```
your-app:category:specifics
```

Examples:
- `oracle:rates:bsv` — BSV rate feed
- `oracle:rates:btc` — BTC rate feed
- `session:auth:tokens` — session data
- `attestation:identity` — identity attestations

Anvil routes by prefix — a node subscribing to `oracle:` receives all `oracle:*` envelopes.

---

## What about monetization?

If your app wants to charge consumers for data, see [Non-Custodial Payment Policy](NON_CUSTODIAL_PAYMENT_POLICY.md).

The short version: add a `monetization` field to your envelope. The node enforces payment on your behalf without ever touching your funds.

```json
{
  "type": "data",
  "topic": "oracle:rates:bsv",
  "payload": "...",
  "monetization": {
    "model": "split",
    "payee_locking_script_hex": "76a914<your-address>88ac",
    "price_sats": 50
  }
}
```

Models: `passthrough` (app only), `split` (app + node), `token` (credential-based), `free`.

The monetization field is included in the signing digest — it can't be altered in transit.

---

## Quick reference

| Action | Endpoint | Auth |
|--------|----------|------|
| Publish envelope | `POST /data` | Bearer token or x402 |
| Query envelopes | `GET /data?topic=...` | None (or x402 if gated) |
| Check node health | `GET /status` | None |
| Discover peers | `GET /overlay/lookup?topic=...` | None |
| Payment models | `GET /.well-known/x402` | None |
