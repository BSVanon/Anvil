# Mesh Peering

Anvil nodes discover each other via overlay (SHIP) registration and gossip.

## Seed peers

Configure seed peers in `[mesh]` to connect to existing nodes:

```toml
[mesh]
seeds = ["wss://anvil.sendbsv.com/mesh"]
```

Seed connections auto-reconnect on disconnect (30-second retry loop).

## Bonds

Nodes can require a minimum bond before accepting mesh peers. A bond is BSV locked at the peer's identity address — verified via WhatsOnChain UTXO lookup.

```toml
[mesh]
min_bond_sats = 10000
```

This prevents spam peering and ensures operators have economic skin in the game. Bond verification results are cached for 1 hour (successes only — transient failures retry immediately).

When `min_bond_sats = 0` (default), any authenticated peer can join the mesh.

### Enforcement and slashing

Misbehaving peers receive `slash_warning` gossip messages with a **48-hour grace period**:

| Offense | Severity | Trigger |
|---------|----------|---------|
| Double-publish (3+ conflicting payloads) | 100% | Immediate after 2+ unique reporters |
| Gossip spam (sustained rate violation) | 25% | 3 warnings from 2+ unique reporters in 48h |
| Bad SPV proofs | 50% | Manual report with proof |

Enforcement is currently **soft-slash** — the offending peer is disconnected and deregistered from the overlay. On-chain bond redistribution to remaining peers is planned for v2.

Gossip rate limits are loose (30 envelopes/sec per peer, burst 100) — designed to protect nodes without punishing fast publishers or reconnection bursts.

If you run a fast local publisher on the same node, exempt its pubkey from double-publish slashing:

```toml
[mesh]
local_pubkeys = ["02...your-app-pubkey..."]
```

Recent peer connect/disconnect events are written to `<data_dir>/mesh/connections.jsonl` (default `/var/lib/anvil/mesh/connections.jsonl`).

## Node names

Each node advertises its name via overlay gossip. Set `name` in `[node]`:

```toml
[node]
name = "my-anvil-node"
```

Other nodes in the mesh will see this name in their Explorer and overlay lookups.

## Public URL

For your node to be discoverable by others with a reachable address, set `public_url`:

```toml
[node]
public_url = "https://my-node.example.com"
```

Without this, the overlay registers the bind address (e.g., `0.0.0.0:8333`) which isn't reachable from outside. `public_url` is optional — the node works without it, but won't be reachable for direct API calls from other Explorers.

## Overlay discovery

Nodes self-register on the `anvil:mainnet` overlay topic at startup. When two nodes connect via gossip, they exchange SHIP registrations — so every node learns about every other node in the mesh.

The overlay lookup API shows all known peers:

```bash
curl http://localhost:9333/overlay/lookup?topic=anvil:mainnet
```

### Federation directory + heartbeat health (v2.1.0+)

For consumers that need a merged federation view, `GET /mesh/nodes`
combines SHIP registrations, live heartbeat envelopes, and direct peer
adjacency, with evidence flags per node.

Each node also publishes an `upstream_status` field on its `mesh:heartbeat`
envelope (and surfaces the same on `GET /mesh/status`):

```json
{
  "upstream_status": {
    "broadcast": "healthy" | "degraded" | "down",
    "headers_sync_lag_secs": 12
  }
}
```

Field names are capability-named (not implementation-named) so the
contract survives the future ARC → Arcade migration. Wallets use this
for federation-node failover decisions.

## Operator-declared custom capabilities (v2.1.0+)

Advertise services this node provides (AVOS oracle relays, custom data
feeds, etc.) via the config — they surface in `/.well-known/anvil`:

```toml
[[capabilities.custom]]
type = "avos-offer-oracle"
description = "MNEE ⇄ BSV oracle-attested swap"
oracle_pubkey = "02abc..."
mailbox = "avos.offer@node-identity"
access = "POST /sendMessage (messageBox: avos.offer)"
payment = "free"
```

Schema-less: fields pass through to the manifest as-is. Agents use this
to discover node-specific services without requiring a new well-known
file per service.

## TOML example (full mesh config)

```toml
[node]
name = "my-node"
listen = "0.0.0.0:8333"
api_listen = "0.0.0.0:9333"
public_url = "https://my-node.example.com"

[mesh]
seeds = ["wss://seed-node.example.com/mesh"]
min_bond_sats = 10000
local_pubkeys = ["02...optional-local-app-pubkey..."]

[overlay]
enabled = true
topics = ["anvil:mainnet"]
```
