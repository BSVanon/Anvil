# Mesh Peering

Anvil nodes discover each other via overlay (SHIP) registration and gossip.

## Seed peers

Configure seed peers in `[mesh]` to connect to existing nodes:

```toml
[mesh]
seeds = ["wss://anvil.sendbsv.com/mesh"]
```

Seed connections auto-reconnect on disconnect (30-second retry loop). A seed
that authenticates as the local node is closed before any topic or overlay
announcement is sent; its reconnect loop then stops for the lifetime of the
process. This makes an accidental self-seed harmless after one diagnostic dial.

## Peer exchange

Peer exchange is enabled by default. A node places a verified `mesh_url` in its
signed `mesh:heartbeat` envelope. Heartbeats already propagate across multiple
mesh hops and are validated against the publisher identity, so another node can
learn the address without a new wire message. Older nodes ignore the field.

In open mode, a node with `[node] public_url` derives a WebSocket address and
verifies it with a 10-second WebSocket plus BRC-31 handshake back to itself. For
the common nginx layout, `https://node.example` is tried first as
`wss://node.example/mesh`, which proxies to the mesh listener at
`127.0.0.1:8333`. A direct address using the configured mesh listen port is the
fallback. Only an address whose handshake reveals this node's identity is
advertised. Verification repeats every six hours; a failed recheck immediately
removes the derived address until a retry succeeds.

An explicit `advertise_url` is advertised as configured. Its self-check is
diagnostic: failure logs a warning but does not remove the operator-supplied
address. URLs are limited to 512 bytes and must use `ws://` or `wss://` with a
host and no userinfo, query, or fragment.

Learned peers are considered every 30 seconds. At most two are dialed per tick,
and no more than `max_exchange_peers` learned connections are kept. Each dial
has a 10-second timeout, must authenticate as the identity that advertised it,
and still passes the normal bond and `allowed_peers` gates. Failures use
per-candidate exponential backoff. An identity mismatch is closed before any
announcement and suppressed for six hours.

Open-mode exchange dials reject loopback, private, link-local, CGNAT,
multicast, unspecified, and `0.0.0.0/8` destinations at the connected socket,
after DNS resolution. This prevents DNS rebinding from reaching internal
addresses. Configured seeds are never replaced by learned records and do not
count toward the exchange connection cap.

```toml
[mesh]
peer_exchange = true       # default; master switch for advertising and dialing
advertise_url = ""         # optional explicit ws:// or wss:// address
max_exchange_peers = 8     # default; 0..64, with 0 meaning advertise only
```

Anyone who can read the `mesh:heartbeat` topic can read its `mesh_url`. Do not
advertise an address that is intended to remain confidential.

## Duplicate connections

Current nodes advertise exact-connection removal support in their topic
declaration. Once both identities support it, only one live connection is
retained per remote identity. When two nodes dial each other, both retain the
same physical connection: the one dialed by the node whose lowercase compressed
identity-key hex sorts first. A configured-seed connection is preferred over a
learned exchange connection for the same identity. Otherwise, when two URLs
lead to the same identity from one side, the existing connection wins. The
loser is closed with reason `duplicate_connection`, and topic interests are
re-announced on the retained connection.

During a rolling upgrade, a current node does not close a reciprocal socket to
a peer that has not advertised exact-removal support. Both sockets remain open,
but application fan-out uses one preferred connection. This avoids triggering
the removal bug in older peers. Seed loops remember the identity behind an
endpoint and do not redial while that identity is already connected in either
direction.

## Bonds

Nodes can require a minimum bond before accepting mesh peers. A bond is BSV locked at the peer's identity address — verified via WhatsOnChain UTXO lookup.

```toml
[mesh]
min_bond_sats = 10000
```

This prevents spam peering and ensures operators have economic skin in the
game. Identity, allowlist, and bond checks all complete before a connection is
admitted, its pre-authentication frame limit is raised, or any interests, SHIP
directory, catch-up request, envelope, transaction, slash warning, or message
forward is sent to it. Bond verification results are cached for 1 hour
(successes only — transient failures retry immediately).

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

## Closed-network mode

Mesh gossip and overlay federation are separate layers, so a fully closed node
configures both allowlists:

```toml
[mesh]
allowed_peers = ["02...peer-identity-key..."]

[overlay]
named_peers = ["https://overlay-a.internal", "https://overlay-b.internal"]
```

`[mesh] allowed_peers` contains compressed identity public keys. When it is
non-empty, an inbound or outbound peer not on the list is dropped immediately
after the BRC-31 handshake and before either side exchanges gossip state. An
empty list keeps open peering; bond rules still apply.

Closed-network mode never derives a mesh advertisement from `public_url`; set
`advertise_url` explicitly if peers should learn one. Learned URLs are dialed
only when the signed advertising identity is in `allowed_peers`. Private
addresses are permitted for those allowlisted identities. Setting
`peer_exchange = false` disables both advertising and learned dialing without
changing configured seed maintenance.

`[overlay] named_peers` contains overlay base URLs. When it is non-empty, GASP
sync for every hosted topic, federated lookup, submit propagation, and SHIP/SLAP
resolution use only those URLs. The configured public trackers and built-in
tracker defaults are not consulted, `public_url` is not required, and the node
does not publish its own SHIP/SLAP advertisements. The built-in header-fallback
peer is also suppressed; explicitly configured `[bsv] header_fallback_peers`
still apply.

`allowed_peers` bounds which identities can be reached, but it does not narrow
message forwarding among those admitted peers. Use `[messaging] forward_peers`
for that additional filter. When `[messaging] private_homes = true`, routing is
stricter again: a private claim is synchronized only over the retained,
admitted primary connection for an allowed identity. Pending inbound sockets,
unbound sockets, duplicate losers, and bond- or allowlist-rejected sockets
receive neither private-home control records nor message forwards. A claimed
recipient is forwarded only to private-home-capable peers that acknowledged the
current claim version, preferring ready named homes over the ready fallback set.

Peer exchange changes how an allowed connection is discovered, not these
admission or private-home rules. Its signed heartbeat may expose `mesh_url` to
anyone able to read `mesh:heartbeat`; private-home claims and acknowledgements
are never placed in heartbeat envelopes or the peer-exchange candidate table.
Disabling `peer_exchange` stops learned advertising and dialing, while private
home synchronization still runs on configured seeds and admitted inbound
connections. See [Messaging privacy](operator/messaging-privacy.md).

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
peer_exchange = true
advertise_url = ""
max_exchange_peers = 8
min_bond_sats = 10000
local_pubkeys = ["02...optional-local-app-pubkey..."]

[overlay]
enabled = true
topics = ["anvil:mainnet"]
```
