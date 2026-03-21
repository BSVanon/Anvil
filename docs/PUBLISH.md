# Layer 1 — Publish

Publish signed data to the Anvil mesh. Every node receives it.

---

## What it does

Your app signs a JSON envelope (topic + payload + signature) and POSTs it to any Anvil node. The mesh gossips it to all connected peers. Any consumer queries it from any node.

This is pub/sub over BSV infrastructure — authenticated, signed, and verifiable.

## The envelope

```json
{
  "type": "data",
  "topic": "oracle:rates:bsv",
  "payload": "{\"USD\":14.35,\"source\":\"sendbsv\"}",
  "signature": "3045...",
  "pubkey": "0231...",
  "ttl": 120,
  "durable": false,
  "timestamp": 1742403600
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `type` | Yes | Always `"data"` |
| `topic` | Yes | Routing key (hierarchical, e.g. `oracle:rates:bsv`) |
| `payload` | Yes | Your data (opaque string — Anvil doesn't parse it) |
| `signature` | Yes | DER hex over the signing digest |
| `pubkey` | Yes | Compressed pubkey hex of the signer |
| `ttl` | Yes | Seconds until expiry (`0` with `durable: true` = persistent) |
| `timestamp` | Yes | Unix epoch seconds |

## Signing

The signing digest is SHA-256 of this concatenation:

```
type + "\n" + topic + "\n" + payload + "\n" + ttl + "\n" + durable + "\n" + timestamp
```

### Node.js (@bsv/sdk)

```javascript
import { PrivateKey } from '@bsv/sdk'

const key = PrivateKey.fromWif('your-wif')
const preimage = [type, topic, payload, ttl, 'false', timestamp].join('\n')

// IMPORTANT: pass raw bytes to sign(). It SHA-256s internally.
// Do NOT pre-hash — that causes double-SHA256 and signature mismatch.
const sig = key.sign(Array.from(Buffer.from(preimage, 'utf8')))
envelope.signature = sig.toDER('hex')
envelope.pubkey = key.toPublicKey().toString()
```

### Go

```go
env := &envelope.Envelope{
    Type:    "data",
    Topic:   "oracle:rates:bsv",
    Payload: `{"USD":14.35}`,
    TTL:     120,
    Timestamp: time.Now().Unix(),
}
env.Sign(privateKey) // SHA-256 + ECDSA, sets Signature + Pubkey
```

## Publish

```bash
curl -X POST http://NODE_URL/data \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @envelope.json
```

Response: `{"accepted": true, "topic": "oracle:rates:bsv"}`

## Query

From any node in the mesh:

```bash
curl "http://NODE_URL/data?topic=oracle:rates:bsv&limit=10"
```

Consumers can verify signatures themselves — all semantic fields are signed.

## Topics

Use a hierarchical prefix:

```
your-app:category:specifics
```

Anvil routes by prefix — a node subscribing to `oracle:` receives all `oracle:*` envelopes.

Examples: `oracle:rates:bsv`, `session:auth:tokens`, `attestation:identity`

## Mesh gossip

When you POST an envelope to one node, it gossips to all mesh peers automatically. Peers discover each other via SHIP overlay tokens and authenticated WebSocket connections. No configuration needed beyond seed peers.

## Ephemeral vs durable

| | Ephemeral | Durable |
|---|-----------|---------|
| **TTL** | 1–3600 seconds | `0` |
| **`durable`** | `false` | `true` |
| **Storage** | In-memory, expires | On-disk, persistent |
| **Use case** | Live feeds, prices | Session data, attestations |
| **Size limit** | No practical limit | 64KB default |

## Auth

Two ways to authenticate `POST /data`:

1. **Bearer token** — the node operator provides a token (derived from the node's WIF via HMAC-SHA256)
2. **x402 payment** — pay per-request instead of using a token

## Next: get paid for your data

Add monetization to your envelopes — the node collects payment on your behalf.

**[Layer 2: Earn →](EARN.md)**
