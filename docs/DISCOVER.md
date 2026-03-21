# Layer 3 — Discover

Machines find, negotiate, and pay for services automatically. Zero onboarding.

---

## What it does

Every Anvil node publishes a machine-readable service menu at `/.well-known/x402`. An AI agent, script, or automated system reads this endpoint, understands what's available, what it costs, and how to pay — without any human setup, API keys, or account creation.

This is the machine economy: services that machines can discover and purchase on their own.

## The discovery endpoint

```bash
curl http://any-anvil-node:9333/.well-known/x402
```

```json
{
  "version": "0.1",
  "network": "mainnet",
  "scheme": "bsv-tx-v1",
  "endpoints": [
    {"method": "GET", "path": "/status", "price": 0},
    {"method": "GET", "path": "/data", "price": 10, "note": "price may vary by topic"},
    {"method": "GET", "path": "/tx/{txid}/beef", "price": 10}
  ],
  "payment_models": ["node_merchant", "passthrough", "split", "token"],
  "non_custodial": true
}
```

A machine reads this and knows:
- Which endpoints exist
- What each one costs (in satoshis)
- What payment methods are accepted
- That payment is non-custodial (direct to the service provider)

## How a machine transacts

### 1. Discover

```
GET /.well-known/x402 → JSON menu
```

### 2. Request

```
GET /data?topic=oracle:rates:bsv → 402 Payment Required
```

The 402 response includes:
- `X402-Price`: amount in satoshis
- `X402-Payee`: locking script (who to pay)
- `X402-Nonce`: unique challenge binding this payment to this request

### 3. Pay

The machine builds a BSV transaction paying the required amount to the specified payee. This is a standard P2PKH transaction — any BSV wallet SDK can build it.

### 4. Prove

```
GET /data?topic=oracle:rates:bsv
X402-Proof: <base64-encoded payment proof>
```

The proof contains the transaction, the nonce, and request binding. Anvil verifies it and serves the response.

### 5. Consume

The machine receives the data and can verify the envelope signatures independently.

## Finding nodes

Nodes discover each other via SHIP (Simplified Host Identity Protocol) overlay tokens. Each node registers its identity and capabilities on the BSV blockchain.

Query any node's overlay directory:

```bash
curl "http://any-node:9333/overlay/lookup?topic=anvil:mainnet"
```

```json
{
  "topic": "anvil:mainnet",
  "count": 2,
  "peers": [
    {"identity_pub": "0257a1...", "domain": "node-a.example.com:8333", "topic": "anvil:mainnet"},
    {"identity_pub": "02d127...", "domain": "node-b.example.com:8334", "topic": "anvil:mainnet"}
  ]
}
```

Nodes gossip SHIP registrations across the mesh — querying any single node returns the full directory.

## For AI agent developers

If you're building an AI agent that needs to:

- **Read real-time data** — discover topic feeds via `/overlay/lookup`, subscribe via `/data?topic=...`
- **Pay for premium data** — read `/.well-known/x402`, build payment, include proof
- **Publish data** — sign an envelope and POST to `/data`
- **Verify data authenticity** — check envelope signatures (all fields are signed)

The entire flow is HTTP + JSON. No WebSocket required for consumers. No API keys. No accounts. Just HTTP 402.

## For node operators

Your node automatically participates in the machine economy by running. Every endpoint is discoverable. If you enable pricing, machines can pay you directly.

To maximize discovery:
1. Register SHIP tokens on-chain (Anvil does this on startup)
2. Peer with other nodes (gossip spreads your registration)
3. Set pricing if you want revenue (`payment_satoshis > 0`)

## Standards

| Standard | What Anvil implements |
|----------|----------------------|
| BRC-95 (BEEF) | Transaction proof format |
| BRC-74 (MerklePath) | Merkle proof encoding |
| BRC-42 (Key derivation) | Identity + invoice address derivation |
| BRC-31 (Auth) | Authenticated peer sessions |
| SHIP/SLAP | Overlay network discovery |
| HTTP 402 | Payment-required flow |
