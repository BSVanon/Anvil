# anvil-mesh

Thin TypeScript client for the [Anvil](https://github.com/BSVanon/Anvil) mesh network.

## Install

```bash
npm install anvil-mesh
```

## Usage

```typescript
import { AnvilClient } from 'anvil-mesh';

const anvil = new AnvilClient({
  wif: 'your-BSV-WIF-key',
  nodeUrl: 'http://your-anvil-node:9333',
});

// Publish data
await anvil.publish('oracle:rates:bsv', { USD: 14.35 });

// Query data
const data = await anvil.query('oracle:rates:bsv');

// Register your app in the catalog
await anvil.publishToCatalog({
  name: 'My App',
  description: 'Does something useful',
  topics: ['my:topic'],
  pricing: 'free',
  contact: 'https://x.com/myhandle',
});

// Node status
const status = await anvil.status();
const stats = await anvil.stats();
```

### Federation discovery + health (wallet failover)

For consumers that need to choose between federation nodes or poll health:

```typescript
// List all federation nodes (merged from SHIP registrations, heartbeats,
// and direct peer connections). Each entry carries evidence flags so the
// caller can decide which nodes to trust.
const { nodes, count } = await anvil.peers();
// nodes[0].evidence = { self, direct_peer, heartbeat, overlay, ... }

// Rich live health snapshot — prefer this over `status()` for polling.
// CORS-only, no rate limit, no x402. Recommended interval: 30–60s.
const health = await anvil.health();
// health.upstream_status = { broadcast: 'healthy' | 'degraded' | 'down',
//                            headers_sync_lag_secs: N }
```

Failover pattern:

```typescript
// Poll primary node; on degraded/down, fail over to secondary.
setInterval(async () => {
  const h = await primary.health();
  if (h.upstream_status?.broadcast !== 'healthy') {
    console.warn('primary degraded, switching to secondary');
    activeClient = secondary;
  }
}, 45_000);
```

### Messaging (BRC-33, real-time push)

```typescript
// Subscribe to new messages via SSE (replaces polling /listMessages):
const sub = anvil.subscribeMessages('avos.offer', (msg) => {
  console.log('new message:', msg.body);
});
// later: sub.close()
```

### Broadcast (transaction submission)

```typescript
// /broadcast now accepts auth token OR x402 payment (authOrPay).
// Consumers with an auth token work unchanged; machine consumers pay via x402.
// Returns derived `status` field: "propagated" | "queued" | "rejected" | "validated-only".
```

### Overlay (BRC-22/24)

```typescript
// List registered topic managers
const topics = await anvil.overlayTopics();
// → { "tm_uhrp": { documentation: "...", metadata: {...} } }

// List registered lookup services
const services = await anvil.overlayServices();
// → { "ls_uhrp": { documentation: "...", metadata: {...}, topics: ["tm_uhrp"] } }

// Submit a transaction to the overlay engine
const steak = await anvil.overlaySubmit(txBytes, ['tm_uhrp']);
// → { "tm_uhrp": { outputsToAdmit: [0], coinsToRetain: [], coinsRemoved: [] } }

// Query a lookup service (e.g. UHRP content hash resolution)
const answer = await anvil.overlayLookup('ls_uhrp', { content_hash: 'sha256-hex...' });
// → { type: "output-list", outputs: [...] }
```

## What it handles

- **Auth token derivation** — HMAC from WIF, no guessing
- **Envelope signing** — correct preimage format, no double-hash bugs
- **Monetization** — signed in digest so payment terms can't be altered
- **gossip:false** — local-only envelopes, signed in digest
- **Overlay engine** — BRC-22 submission (TaggedBEEF/STEAK), BRC-24 lookup queries
- **Federation discovery** — `peers()` merges SHIP directory + heartbeat + gossip adjacency
- **Health / failover** — `health()` returns `upstream_status` for wallet failover decisions
- **Real-time messaging** — `subscribeMessages()` SSE push for BRC-33 mailboxes
- **Topic catalog** — `getTopics()`, `getTopicDetail()` for AI-agent and DEX discovery

## Links

- [Example: mesh hello](examples/mesh-hello.ts)
- [Anvil](https://github.com/BSVanon/Anvil) — the node
- [Anvil Explorer](https://github.com/BSVanon/Anvil-Explorer) — the dashboard
- [@SendBSV](https://x.com/SendBSV)
