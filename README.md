<p align="center">
  <img src="anvil-logo.svg" width="140" alt="Anvil" />
</p>

<h1 align="center">Anvil</h1>

<p align="center">A single-binary BSV node. Verify transactions, publish data, get paid, let machines transact.</p>

## Four layers

### Layer 0 — Verify

Validate any BSV transaction in 30 seconds with no blockchain download. Anvil syncs headers from a BSV seed peer (~940k headers, ~30s) and verifies BEEF proofs against the local header chain.

```bash
go build -o anvil ./cmd/anvil
export ANVIL_IDENTITY_WIF="your-wif-here"
./anvil -config anvil.toml
```

You now have a running SPV node with a REST API on `:9333`.

**[Layer 0 guide: Verify](docs/VERIFY.md)** — install, configure, verify transactions

---

### Layer 1 — Publish

Publish signed data to the Anvil mesh. Your app signs a JSON envelope, POSTs it to any node, and every node in the mesh receives it.

```bash
curl -X POST http://localhost:9333/data \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"type":"data","topic":"oracle:rates:bsv","payload":"{...}","signature":"...","pubkey":"...","ttl":60,"timestamp":1710000000}'
```

Any consumer queries it from any node: `GET /data?topic=oracle:rates:bsv`

**[Layer 1 guide: Publish](docs/PUBLISH.md)** — envelopes, topics, signing, mesh gossip

---

### Layer 2 — Earn

Get paid per-request for your data or API. Non-custodial — the node enforces payment but never touches your funds. Add one field to your envelope:

```json
{
  "monetization": {
    "model": "passthrough",
    "payee_locking_script_hex": "76a914<your-address>88ac",
    "price_sats": 50
  }
}
```

Four models: `free`, `passthrough` (app collects), `split` (app + node), `token` (credential-gated).

**[Layer 2 guide: Earn](docs/EARN.md)** — payment models, x402 flow, configuration

---

### Layer 3 — Discover

Machines find, negotiate, and pay for services automatically. Every Anvil node exposes `/.well-known/x402` — a machine-readable menu of endpoints, prices, and payment models. An AI agent reads it, pays, and consumes. Zero onboarding.

```bash
curl http://localhost:9333/.well-known/x402
# → {"endpoints":[...],"payment_models":["node_merchant","passthrough"],...}
```

**[Layer 3 guide: Discover](docs/DISCOVER.md)** — machine economy, automated discovery, AI agent integration

---

## Quick reference

| Endpoint | Method | Auth | Layer |
|----------|--------|------|-------|
| `/status` | GET | No | 0 |
| `/stats` | GET | No | 0 |
| `/tx/{txid}/beef` | GET | No | 0 |
| `/content/{txid}_{vout}` | GET | No | 0 |
| `/data` | GET | No | 1 |
| `/data` | POST | Bearer or x402 | 1 |
| `/overlay/lookup` | GET | No | 1 |
| `/overlay/submit` | POST | No | 1 |
| `/overlay/query` | POST | No | 1 |
| `/overlay/topics` | GET | No | 1 |
| `/overlay/services` | GET | No | 1 |
| `/broadcast` | POST | Bearer | 0 |
| `/wallet/outputs` | GET | X-Anvil-Auth | 0 |
| `/wallet/send` | POST | X-Anvil-Auth | 0 |
| `/wallet/invoice` | POST | X-Anvil-Auth | 0 |
| `/wallet/scan` | POST | X-Anvil-Auth | 0 |
| `/.well-known/x402` | GET | No | 3 |
| `/.well-known/x402-info` | GET | No | 3 |
| `/.well-known/anvil` | GET | No | 3 |
| `/.well-known/identity` | GET | No | 3 |
| `/app/{name}` | GET | No | 3 |
| `/explorer` | GET | No | 3 |

## Operator wallet

Node operators authenticate with the `X-Anvil-Auth` header to access wallet endpoints (balance, send, receive). The auth token is derived from your identity WIF:

```bash
# Print your auth token
anvil token -config anvil.toml

# Check balance
curl -H "X-Anvil-Auth: $TOKEN" http://localhost:9333/wallet/outputs

# Or use the Explorer — click the node dropdown → Node Login → paste token
```

## Bonds and mesh peering

Nodes must hold a bond UTXO at their identity address to join the mesh. The bond amount is checked on connect and displayed in the Explorer. Misbehavior (spam, double-publish) triggers warnings via gossip with a 48-hour grace period before deregistration.

See [Mesh Peering](docs/MESH_PEERING.md) for configuration.

## x402 interoperability

Anvil accepts payments via two methods:
- **X402-Challenge/Proof** — nonce-bound, replay-safe (native Anvil)
- **X-Bsv-Payment** — direct raw tx in header (compatible with Rust x402 agents)

Machine-readable protocol spec: `GET /.well-known/x402-info` (JSON or markdown for LLMs via `Accept: text/markdown`)

## Overlay services engine

Generic BRC-22/24 overlay — any UTXO-based overlay type is a plugin. Topic managers decide which outputs to admit; lookup services answer queries. Babbage-compatible: TaggedBEEF submission, STEAK response, BRC-87 naming.

```bash
# What topics does this node host?
curl https://anvil.sendbsv.com/overlay/topics

# What lookup services are available?
curl https://anvil.sendbsv.com/overlay/services
```

Built-in topic managers:
- **SHIP/SLAP** — peer and service discovery (BRC-88)
- **UHRP** — content hash resolution (BRC-26) — maps SHA-256 file hashes to hosting locations

Adding a new overlay type is one interface implementation + one registration call. See [Capabilities Reference](docs/ANVIL_CAPABILITIES.md) for details.

## Live network

| | URL |
|---|---|
| Explorer | https://anvil.sendbsv.com |
| Direct IP | http://212.56.43.191:9333/explorer |
| x402 discovery | https://anvil.sendbsv.com/.well-known/x402 |
| Protocol spec | https://anvil.sendbsv.com/.well-known/x402-info |

## Operations

| Command | What it does |
|---------|-------------|
| `anvil -config anvil.toml` | Run the node |
| `anvil token -config anvil.toml` | Print your API auth token |
| `sudo anvil deploy --nodes ab` | Install systemd services, create dirs, health check |
| `anvil doctor -config /etc/anvil/node-a.toml` | Validate config, connectivity, wallet, mesh |

## Further reading

| Document | What it covers |
|----------|---------------|
| [App Integration Guide](docs/APP_INTEGRATION.md) | Step-by-step: connect your app to Anvil |
| [Non-Custodial Payment Policy](docs/NON_CUSTODIAL_PAYMENT_POLICY.md) | What's allowed, what's prohibited |
| [Capabilities Reference](docs/ANVIL_CAPABILITIES.md) | Full API reference |
| [Architecture](docs/ARCHITECTURE.md) | Internal design |
| [Mesh Peering](docs/MESH_PEERING.md) | Bonds, auto-reconnect, node names, overlay discovery |
| [Anvil Explorer](https://github.com/BSVanon/Anvil-Explorer) | Browser dashboard |
| [anvil-mesh SDK](https://www.npmjs.com/package/anvil-mesh) | TypeScript client — `npm install anvil-mesh` |

## Requirements

- Go 1.25+ (build only — binary has no runtime dependencies)
- BSV mainnet peer (default: `seed.bitcoinsv.io:8333`)
- Optional: GorillaPool ARC (free), JungleBus (free)

## License

See [LICENSE](LICENSE.txt).
