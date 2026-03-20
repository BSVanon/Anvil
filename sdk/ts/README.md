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

## What it handles

- **Auth token derivation** — HMAC from WIF, no guessing
- **Envelope signing** — correct preimage format, no double-hash bugs
- **Monetization** — signed in digest so payment terms can't be altered
- **gossip:false** — local-only envelopes, signed in digest

## Links

- [Anvil](https://github.com/BSVanon/Anvil) — the node
- [Anvil Explorer](https://github.com/BSVanon/Anvil-Explorer) — the dashboard
- [@SendBSV](https://x.com/SendBSV)
