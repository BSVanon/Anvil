# Discover

Machines, agents, and developers find what's on the mesh and how to use it.

---

## What it does

Every Anvil-Mesh node describes itself. Topics have metadata. Publishers
have identities. Demand is visible. Payment requirements are published.
A new participant — human, agent, or script — can arrive at any node
and understand what's available without reading documentation.

## Discovery endpoints

### Browse topics

```bash
curl http://any-node:9333/topics
```

Returns all topics with envelope counts, last update times, and metadata:

```json
{
  "topics": [
    {"topic": "oracle:rates:bsv", "count": 42, "last_updated": 1712345678, "metadata": {"description": "BSV/USD price feed", "update_interval": "60s"}},
    {"topic": "anvil:catalog", "count": 3, "last_updated": 1712340000}
  ],
  "count": 2
}
```

### Topic detail

```bash
curl http://any-node:9333/topics/oracle:rates:bsv
```

Returns everything about a topic: metadata, publisher, price, demand,
and publisher identity if available.

### Publisher identity

```bash
curl http://any-node:9333/identity/02abc...def
```

Returns the publisher's self-declared profile (name, description).

### Payment discovery

```bash
curl http://any-node:9333/.well-known/x402
```

Returns all gated endpoints and their prices in satoshis.

### Node discovery

```bash
curl http://any-node:9333/overlay/lookup?topic=anvil:mainnet
```

Returns all known nodes with identity, domain, and version.

### Federation directory (v2.1.0+)

```bash
curl http://any-node:9333/mesh/nodes
```

Authoritative merged view of federation nodes from three sources: overlay
SHIP registrations (identity ↔ URL), signed heartbeat envelopes (live
liveness), and direct gossip adjacency (WebSocket peers). Each entry
carries `evidence` flags so consumers can decide which nodes to trust.

### Node health + upstream status (v2.1.0+)

```bash
curl http://any-node:9333/mesh/status
```

Live snapshot including `upstream_status.broadcast` (healthy|degraded|
down) and `headers_sync_lag_secs`. Wallets poll this every 30–60s for
federation-node failover decisions. CORS-only, no rate limit, no x402.

### Operator-declared capabilities (v2.1.0+)

```bash
curl http://any-node:9333/.well-known/anvil
```

Returns the node manifest including any operator-declared custom
capabilities (AVOS oracles, custom data relays, etc.). The shape is
schema-less — agents parse whatever fields the operator chose to
publish.

## How a machine transacts

### 1. Discover topics

```
GET /topics → list of available data
GET /topics/{topic} → detail with metadata, price, demand
```

### 2. Evaluate

The machine reads topic metadata (schema, update interval, price) and
decides whether to subscribe. Demand count shows how popular the topic is.

### 3. Request data

```
GET /data?topic=oracle:rates:bsv → 402 Payment Required (if priced)
```

### 4. Pay

Build a BSV transaction paying the challenge amount. Standard P2PKH —
any BSV wallet SDK can build it.

### 5. Prove and consume

```
GET /data?topic=oracle:rates:bsv
X402-Proof: <base64-encoded payment proof>
```

### 6. Subscribe for real-time

```
GET /data/subscribe?topic=oracle:rates:bsv → SSE stream
```

### 7. Send messages

```
POST /sendMessage
{"recipient": "02abc...def", "messageBox": "inbox", "body": "hello"}
```

## For AI agent developers

If you're building an AI agent that needs to:

- **Find data** — `GET /topics` lists all available topics with metadata
- **Read real-time data** — `GET /data/subscribe?topic=...` for SSE push
- **Pay for premium data** — read `/.well-known/x402`, build payment, include proof
- **Publish data** — sign an envelope and POST to `/data`
- **Send messages to other agents** — `POST /sendMessage` with recipient pubkey
- **Verify data authenticity** — check envelope signatures (all fields are signed)
- **Declare your identity** — publish to `identity:<your-pubkey>`
- **Describe your topics** — publish to `meta:<your-topic>`

The entire flow is HTTP + JSON. No WebSocket required for consumers.
No API keys. No accounts.

## For node operators

Your node automatically participates by running. Every endpoint is
discoverable. If you enable pricing, machines pay you directly.

To maximize discovery:
1. Peer with other nodes (gossip spreads your registration)
2. Set pricing if you want revenue (`payment_satoshis > 0`)
3. Publish topic metadata so consumers know what you serve
