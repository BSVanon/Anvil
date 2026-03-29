<p align="center">
  <img src="anvil-logo.svg" width="140" alt="Anvil" />
</p>

<h1 align="center">Anvil</h1>

<p align="center">A single-binary BSV overlay node. No blockchain download required.</p>

## What it does

- **Verify** — Syncs ~940k block headers in 30 seconds, then verifies any BSV transaction via BEEF/SPV proofs
- **Publish** — Signed data envelopes propagate across the mesh in real time via authenticated gossip
- **Subscribe** — Real-time push via SSE. Clients receive new envelopes the moment they arrive
- **Earn** — Non-custodial x402 micropayments per request. Your node enforces payment but never holds funds
- **Discover** — Machines find services via `/.well-known/x402`, pay, and consume. Zero onboarding

## Install

```bash
curl -fsSL https://anvil.sendbsv.com/install | sudo bash
```

The guided installer downloads the binary, generates your identity, syncs headers, and shows your funding address. Takes about 3 minutes.

After install:

```bash
sudo ufw allow 8333/tcp              # mesh peering
sudo ufw allow 9333/tcp              # REST API
sudo anvil info                       # your address + auth token
```

Send 1,000,000 sats to the address shown, wait for 1 confirmation, then:

```bash
TOKEN=$(sudo anvil token)
curl -X POST http://localhost:9333/wallet/scan \
  -H "Authorization: Bearer $TOKEN"
```

Your node is live. Run `anvil help` for the full command reference.

## anvil-mesh SDK

```bash
npm install anvil-mesh
```

```typescript
import { AnvilClient } from 'anvil-mesh';

const anvil = new AnvilClient({ wif: 'your-WIF', nodeUrl: 'http://your-node:9333' });
await anvil.publish('oracle:rates:bsv', { USD: 14.35 });
const data = await anvil.query('oracle:rates:bsv');
```

[SDK documentation](sdk/ts/README.md)

## Documentation

| Guide | What it covers |
|-------|---------------|
| [Verify](docs/VERIFY.md) | SPV verification, header sync, configuration |
| [Publish](docs/PUBLISH.md) | Data envelopes, signing, topics, mesh gossip |
| [Earn](docs/EARN.md) | Payment models, x402 flow, monetization |
| [Discover](docs/DISCOVER.md) | Machine economy, automated discovery, AI agents |
| [Add Your App](docs/ADD_YOUR_APP.md) | 5-minute path from app to live mesh publisher |
| [App Integration](docs/APP_INTEGRATION.md) | Step-by-step guide for connecting your app |
| [Mesh Peering](docs/MESH_PEERING.md) | Bonds, node names, overlay discovery, connection logging |
| [API Reference](docs/API_REFERENCE.md) | All endpoints, SSE subscription, auth, response formats |
| [Payment Policy](docs/NON_CUSTODIAL_PAYMENT_POLICY.md) | Non-custodial design constraints |
| [Capabilities](docs/ANVIL_CAPABILITIES.md) | Machine-readable reference for AI agents |

## Live network

| | |
|---|---|
| Explorer | https://anvil.sendbsv.com |
| x402 discovery | https://anvil.sendbsv.com/.well-known/x402 |
| Protocol spec | https://anvil.sendbsv.com/.well-known/x402-info |

## Requirements

- Linux (amd64 or arm64)
- 1 GB RAM, 20 GB disk
- Go 1.25+ (build from source only — binary has no runtime dependencies)

## License

See [LICENSE](LICENSE.txt).
