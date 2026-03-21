# Mesh Peering

Anvil nodes discover each other via overlay (SHIP) registration and gossip.

## Seed peers

Configure seed peers in `[mesh]` to connect to existing nodes:

```toml
[mesh]
seeds = ["ws://127.0.0.1:8333"]
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

## TOML example (full mesh config)

```toml
[node]
name = "my-node"
listen = "0.0.0.0:8333"
api_listen = "0.0.0.0:9333"
public_url = "https://my-node.example.com"

[mesh]
seeds = ["ws://seed-node.example.com:8333"]
min_bond_sats = 10000

[overlay]
enabled = true
topics = ["anvil:mainnet"]
```
