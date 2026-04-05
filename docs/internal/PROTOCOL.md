# Anvil-Mesh Protocol — Master Document

Updated: 2026-04-02
Status: Phase 1 (Audit) complete. Phase 2 (Critique) complete. Phase 3 (Definition) next.

This document maps the entire Anvil-Mesh protocol: what exists, what conforms
to BRC standards, what is Anvil-specific, and what needs to be formalized
before adoption can proceed.

---

## How This Document Works

Three phases, worked sequentially:

- **Phase 1 — Audit** (done): What does Anvil-Mesh speak today? Every message,
  every field, every behavior, documented from code.
- **Phase 2 — Critique**: What's essential, what's legacy, what's missing,
  what's inconsistent? Evaluate every protocol element.
- **Phase 3 — Definition**: Write the spec. MUST/SHOULD/MAY. Publishable for
  implementers who want to build compatible nodes.

---

## BRC Conformance Map

### What BRC specs define (Anvil MUST conform)

| Behavior | BRC | What it specifies |
|----------|-----|-------------------|
| Transaction submission API | BRC-22 | `POST /submit` endpoint, JSON format, 6-step processing pipeline |
| Transaction lookup API | BRC-24 | `POST /lookup` endpoint, JSON format, error codes |
| Mutual authentication | BRC-31 | Authrite nonce exchange, `X-Authrite-*` headers, session keys |
| Peer discovery | BRC-88 | SHIP token format: `["SHIP", identity_key, domain, topic]` on-chain PushDrop |
| Service discovery | BRC-88 | SLAP token format: `["SLAP", identity_key, domain, service]` on-chain PushDrop |
| Transaction format | BRC-62 | BEEF binary encoding (version `0100BEEF`, BUMPs, topological ordering) |
| Token format | BRC-48 | PushDrop script: `<data> OP_DROP OP_2DROP <pubkey> OP_CHECKSIG` |
| Naming conventions | BRC-87 | Topic managers: `tm_*`, lookup services: `ls_*`, lowercase+underscore, max 50 chars |
| History tracking | BRC-64 | Extension to BRC-22/24 for UTXO chain history |

### What BRC specs explicitly do NOT define (Anvil's design space)

These are the behaviors where Anvil-Mesh defines its own protocol. Any
compatible node implementation must follow these rules once we formalize
them in Phase 3.

| Behavior | BRC status |
|----------|------------|
| Gossip protocol between overlay nodes | NOT SPECIFIED. BRC-22 step 6: "pursuant to any peering arrangements." |
| Mesh topology / peer selection | NOT SPECIFIED. BRC-90 is conceptual only. |
| Persistent connections (WebSocket) | NOT SPECIFIED. BRC-101 mentions `wss://` but defines no protocol. |
| Reconnection / failover | NOT SPECIFIED. |
| Slashing / reputation / peer scoring | NOT SPECIFIED. |
| Rate limiting / DoS protection | NOT SPECIFIED at overlay layer. |
| Envelope format (beyond BRC-62 BEEF) | NOT SPECIFIED. Anvil's signed envelope is custom. |
| Topic interest declaration | NOT SPECIFIED. |
| Data request/response (catchup) | NOT SPECIFIED. |
| Heartbeat / liveness | NOT SPECIFIED. |
| Header sync between overlay nodes | NOT SPECIFIED. |

### The BRC-specified propagation model

BRC-88 defines a **pull-from-discovery, push-via-submit** model:

```
1. Client → POST /submit (BRC-22) → Node A
2. Node A validates, admits to topics
3. Node A looks up SHIP ads (BRC-88) for same topics
4. Node A → POST /submit (BRC-22) → Node B, Node C
5. Each node validates independently
```

Each hop is a fresh HTTP POST with Authrite. No persistent connections,
no gossip, no fanout algorithm, no dedup protocol.

**Anvil-Mesh extends this** with persistent WebSocket connections, gossip
fanout, deduplication, and real-time subscriptions. Everything in the
next section is Anvil's extension to BRC.

---

## Phase 1 — Protocol Audit (complete)

### 1. Transport Layer

**Wire format:** JSON over WebSocket (RFC 6455)
- Outbound: `wss://` or `ws://` to seed peer endpoints
- Inbound: HTTP upgrade at configured listen address (e.g., `0.0.0.0:8333`)
- All messages wrapped in BRC-31 `auth.AuthMessage` (go-sdk)
- Identity: secp256k1 keypair from config `identity.wif`
- Session: Authenticated via BRC-31 Authrite mutual auth on connect

**Inner message format:**
```json
{
  "type": "<message_type>",
  "data": { /* type-specific payload */ }
}
```

**Send timeout:** 5 seconds per message
**Reconnect:** 30-second retry loop on disconnect (outbound only)

**Source:** `internal/gossip/transport.go`, `internal/gossip/manager_seed.go`

---

### 2. Connection Lifecycle

**Outbound (to seed peers):**
```
1. WebSocket dial to seed endpoint
2. BRC-31 Authrite handshake (mutual identity reveal)
3. Re-key from temp key to identity pubkey
4. Bond check (if min_bond_sats > 0): verify UTXO at peer address
5. Send: topics (interest declaration)
6. Send: ship_sync (all local SHIP registrations)
7. Send: data_request for catchup topics ["anvil:catalog", "mesh:heartbeat"]
   plus any non-empty local interest prefixes
8. Enter receive loop
9. On disconnect: cleanup, retry with exponential backoff (30s → 5min cap)
```

**Inbound (from connecting peers):**
```
1. HTTP → WebSocket upgrade at listen address
2. BRC-31 Authrite handshake
3. Re-key from "inbound-<addr>" to identity pubkey
4. Bond check (if required)
5. Enter receive loop
6. On disconnect: cleanup, log event
```

**Connection events logged as JSONL:**
`<data_dir>/mesh/connections.jsonl`
Events: `connected`, `identified`, `rejected`, `disconnected`

**Source:** `internal/gossip/manager.go:183-465`, `internal/gossip/manager_seed.go:15-138`

---

### 3. Message Types (9 total)

#### 3.1 `data` — Envelope delivery

**Direction:** Bidirectional (flood to interested peers)
**Purpose:** Carry a signed data envelope to peers matching topic interest

**Payload (Envelope):**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | yes | Always `"data"` |
| `topic` | string | yes | Application topic (e.g., `"oracle:rates:bsv"`) |
| `payload` | string | yes | Opaque application data |
| `signature` | string | yes | DER hex, ECDSA secp256k1 |
| `pubkey` | string | yes | Compressed pubkey hex (33 bytes) of signer |
| `ttl` | int | yes | Seconds until expiry (0 only if `durable=true`) |
| `durable` | bool | no | If true + TTL=0: persist in LevelDB forever |
| `timestamp` | int64 | no | Unix seconds when created |
| `no_gossip` | bool | no | If true: store locally, don't forward |
| `monetization` | object | no | Payment terms for gated access |

**Signing digest (canonical):**
```
SHA256(type + "\n" + topic + "\n" + payload + "\n" + ttl + "\n" +
       durable + "\n" + timestamp + [no_gossip] + [monetization fields])
```

**Processing on receive:**
1. Rate limit check (30/sec per peer, burst 100)
2. Parse envelope JSON
3. Dedup: `sha256(topic:pubkey:payload:timestamp)` → first 16 bytes hex
4. Verify ECDSA signature against canonical digest
5. Store: durable → LevelDB; ephemeral → memory with TTL
6. Callback: notify SSE subscribers via `onEnvelope` hook
7. Forward: if `!no_gossip`, send to all peers with matching topic interest

**Forwarding rules:**
- Never echo back to sender
- Match topic against each peer's declared interest prefixes
- Each peer receives at most once per envelope
- 5-second send timeout

**Source:** `internal/gossip/handlers.go:199-349`, `internal/envelope/envelope.go:84-156`

#### 3.2 `topics` — Interest declaration

**Direction:** Sent on connect; can be re-sent anytime
**Purpose:** Declare which topic prefixes this node wants to receive

**Payload:**
| Field | Type | Description |
|-------|------|-------------|
| `prefixes` | string[] | Topic prefixes to subscribe to |

**Behavior:**
- Empty prefix `[""]` matches all topics (wildcard)
- Stored in `interests[senderPK]`
- Controls which envelopes are forwarded to this peer

**Source:** `internal/gossip/handlers.go:257-268`

#### 3.3 `data_request` — Pull-based catchup

**Direction:** Requester → responder
**Purpose:** Request cached envelopes for a topic (used on connect for critical topics)

**Payload:**
| Field | Type | Description |
|-------|------|-------------|
| `topic` | string | Topic to fetch |
| `since` | int64 | Unix timestamp floor (optional) |
| `limit` | int | Max envelopes to return (default 50, max 100) |

**Source:** `internal/gossip/handlers.go:19-34`

#### 3.4 `data_response` — Catchup reply

**Direction:** Responder → requester
**Purpose:** Return cached envelopes in response to `data_request`

**Payload:**
| Field | Type | Description |
|-------|------|-------------|
| `topic` | string | Topic that was requested |
| `envelopes` | Envelope[] | Up to 100 envelopes |
| `hasMore` | bool | Whether more are available |

**Source:** `internal/gossip/handlers.go:283-284`

#### 3.5 `ship_sync` — Overlay registration exchange

**Direction:** Bidirectional (sent on connect + every 45 min)
**Purpose:** Share SHIP peer registrations across the mesh

**Payload:**
| Field | Type | Description |
|-------|------|-------------|
| `peers` | SHIPPeerInfo[] | Array of SHIP registrations |

**SHIPPeerInfo:**
| Field | Type | Description |
|-------|------|-------------|
| `identity_pub` | string | Compressed pubkey hex |
| `domain` | string | Reachable endpoint (e.g., `"relay.example.com:8333"`) |
| `node_name` | string | Human-readable name (optional) |
| `version` | string | Software version (optional) |
| `topic` | string | Overlay topic (e.g., `"anvil:mainnet"`) |

**Behavior:**
- Full-replace per domain+topic pair (handles re-keying)
- Only self-registered entries re-announced (prevents dead peer amplification)
- Forwarded to all peers except sender
- TTL: 6 hours (swept every 5 minutes)
- Re-announced every 45 minutes to refresh `LastSeen`

**Source:** `internal/gossip/handlers.go:46-164`, `internal/overlay/directory.go`

#### 3.6 `slash_warning` — Protocol violation report

**Direction:** Flood (forwarded to all peers)
**Purpose:** Report misbehavior for mesh consensus on deregistration

**Payload:**
| Field | Type | Description |
|-------|------|-------------|
| `target` | string | Identity pubkey hex of offender |
| `reason` | string | `"gossip_spam"` or `"bad_proof"` |
| `evidence` | string | Human-readable or proof hash (optional) |
| `timestamp` | int64 | Unix seconds |
| `reporter` | string | Identity pubkey hex of reporter |

**Severity:**
| Reason | Weight | Threshold |
|--------|--------|-----------|
| `double_publish` | Deprecated (dropped silently) | N/A |
| `gossip_spam` | 25% | 3 warnings from 2+ reporters in 48h |
| `bad_proof` | 50% | 3 warnings from 2+ reporters in 48h |

**Deregistration action:** Peer disconnected + removed from SHIP directory.
No on-chain bond penalty (planned for v2).

**Source:** `internal/gossip/slash.go`, `internal/gossip/protocol.go:109-142`

#### 3.7 `tx_announce` — Transaction announcement (DEPRECATED v1.2.0)

**Status:** Deprecated. Messages accepted but silently dropped. No forwarding.
**Direction:** Flood (to all peers except source)
**Purpose:** Was: announce a new txid available for request. Dead post-Teranode.

**Payload:**
| Field | Type | Description |
|-------|------|-------------|
| `txid` | string | 64-char hex |
| `size` | int | Tx size in bytes (optional hint) |

**Source:** `internal/gossip/handlers_tx.go:137-162`

#### 3.8 `tx_request` — Transaction request (DEPRECATED v1.2.0)

**Status:** Deprecated. See 3.7.
**Direction:** Requester → announcer
**Purpose:** Was: request full raw transaction by txid

**Payload:**
| Field | Type | Description |
|-------|------|-------------|
| `txid` | string | 64-char hex |

**Source:** `internal/gossip/handlers_tx.go:62-97`

#### 3.9 `tx_response` — Transaction delivery (DEPRECATED v1.2.0)

**Status:** Deprecated. See 3.7.
**Direction:** Responder → requester
**Purpose:** Was: deliver raw transaction hex

**Payload:**
| Field | Type | Description |
|-------|------|-------------|
| `txid` | string | 64-char hex |
| `raw_hex` | string | Hex-encoded raw transaction |

**Behavior on receive:** Store in local mempool, call `onTxCallback`
(feeds address watcher), re-announce to other peers (flood-fill).

**Source:** `internal/gossip/handlers_tx.go:99-162`

#### 3.10 `msg_forward` — Point-to-point message forwarding (v2.0.0)

**Direction:** Flood (to all peers, with dedup by messageId)
**Purpose:** Forward a signed message to the recipient's node

**Payload:**
| Field | Type | Description |
|-------|------|-------------|
| `message` | Message | Full message object (sender, recipient, messageBox, body, timestamp, messageId) |
| `signature` | string | DER hex, sender signs messageId:recipient:messageBox:body:timestamp. **Required.** |

**Behavior on receive:**
- Reject if signature missing or invalid
- Dedup by `msg:` + messageId
- Store via `Deliver()` (preserves original messageId)
- Re-forward to other peers (flood-fill with dedup)

**Source:** `internal/gossip/handlers_msg.go`

---

### 4. Periodic Behaviors

| Behavior | Interval | Topic/Target | Source |
|----------|----------|--------------|--------|
| Heartbeat publish | 60 sec | `mesh:heartbeat` | `main.go:403-407` |
| ~~Block tip publish~~ | ~~10 sec~~ | ~~`mesh:blocks`~~ | Removed in v1.2.0 |
| SHIP re-announce | 45 min | All peers | `main.go:384-392` |
| SHIP TTL sweep | 5 min | Overlay directory | `main.go:207-215` |
| Ephemeral envelope expiry + durable capacity check | 30 sec | Envelope store | `main.go:155-163` |
| Message expiry + demand decay | 5 min | Message store + demand map | `main.go:181-190` |
| Header re-sync | 2 min | BSV P2P peers | `main.go:109-125` |

---

### 5. Rate Limiting & Protection

**Per-peer gossip rate:** 30 envelopes/sec, burst 100 (token bucket)
**Escalation:** 200+ drops in 10 min → broadcast `slash_warning` (gossip_spam)
**Max one warning per peer per 10 min**
**Dedup map:** 10,000 entries max, LRU half-purge when full

**Source:** `internal/gossip/manager_seed.go:164-202`

---

### 6. Storage Limits

| Parameter | Default | Configurable |
|-----------|---------|:--:|
| Max ephemeral TTL | 3600 sec (1 hour) | Yes |
| Max durable payload size | 65536 bytes (64 KB) | Yes |
| Max durable store size | 10240 MB (10 GB) | Yes |
| Durable store warning | 80% | Yes |
| SHIP TTL | 6 hours | No (constant) |
| Dedup map max entries | 10,000 | No (constant) |
| Catchup limit | 100 envelopes | No (constant) |

**Source:** `internal/config/config.go:92-97`

---

### 7. API Surface (app-facing, not node-to-node)

| Method | Path | Auth | Purpose | Gossip interaction |
|--------|------|------|---------|-------------------|
| GET | `/data` | x402/token | Query envelopes by topic | Reads store |
| POST | `/data` | Bearer/x402 | Submit envelope | Broadcasts to mesh |
| DELETE | `/data` | Bearer | Delete envelope | Removes from store |
| GET | `/data/subscribe` | None | SSE subscription by topic | Receives from gossip hook |
| POST | `/overlay/register` | Bearer | Register SHIP token | Updates directory |
| POST | `/overlay/deregister` | Bearer | Remove SHIP peer | Updates directory |
| GET | `/overlay/lookup` | None | Discover SHIP peers | Reads directory |
| POST | `/overlay/submit` | Bearer/x402 | Submit to overlay (BRC-22) | Processes + gossips |
| POST | `/overlay/query` | None | Query overlay (BRC-24) | Reads directory |
| GET | `/mesh/status` | None | Mesh health | Returns peer list + stats |
| GET | `/mesh/nodes` | None | List known nodes | Returns SHIP + heartbeat data |
| POST | `/broadcast` | Bearer | Broadcast BEEF tx to ARC | ARC submission (not gossip) |
| GET | `/topics` | None | List all topics with count and metadata | Reads store |
| GET | `/topics/{topic}` | None | Topic detail: metadata, publisher, price, demand | Reads store + demand map |
| GET | `/identity/{pubkey}` | None | Publisher identity envelope | Reads store |
| POST | `/node/publish` | Bearer | Publish envelope signed by node identity key | Signs + stores + gossips |
| POST | `/sendMessage` | Bearer | Send point-to-point message by pubkey | Stores + forwards via gossip |
| POST | `/listMessages` | Bearer | Retrieve messages for a recipient | Reads message store |
| POST | `/acknowledgeMessage` | Bearer | Delete messages after receipt | Deletes from store |

---

### 8. Built-in Topics

| Topic | Publisher | TTL | Purpose |
|-------|-----------|-----|---------|
| `mesh:heartbeat` | Each node | 300 sec | Node liveness + chain tip + peer count + demand map |
| ~~`mesh:blocks`~~ | — | — | Removed in v1.2.0 (no consumers) |
| `anvil:catalog` | Apps via API | Durable | App catalog entries (name, version, URL). One per publisher, latest wins. |

**Convention topics (v2.0.0):**
| Topic pattern | Purpose |
|---------------|---------|
| `meta:<topic>` | Topic metadata (description, render hints, schema, update interval) |
| `identity:<pubkey>` | Publisher identity (name, description) |

**App topics:** Arbitrary. No enforced naming convention beyond BRC-87
(`tm_*` / `ls_*` for topic managers and lookup services).
TrueProof uses: `proofroom:session:*`, `anvilcast:inbox:*`, `anvilcast:chat:*`, `anvilcast:live`
ClawSats uses: `clawsats:capability:*`, `clawsats:task:*`

---

## Phase 2 — Critique (next)

For each protocol element, evaluate:

1. **Essential or legacy?** Does this serve the mesh's core value (topic
   routing, real-time delivery, signed data, access control)? Or is it
   left over from SPV/mempool era?

2. **BRC-conformant?** Does it align with or contradict the BRC specs?
   Where Anvil extends BRC, is the extension clean or does it create
   friction for BRC-conformant clients?

3. **Scale-ready?** Does this work at 50 nodes? At 500? What breaks first?

4. **Spec-ready?** Is this behavior well-defined enough that another
   developer could implement a compatible node from the description alone?

### C1. Envelope Format

**Question:** Is this the right schema?

**Current fields:** type, topic, payload, signature, pubkey, ttl, durable,
timestamp, no_gossip, monetization

**Assessment:**
- `type` — Always "data". Redundant as a field since it's already the
  message type wrapper. But useful if envelopes travel outside gossip
  (e.g., stored in DB, returned by API). **Keep. Stable.**
- `topic` — Essential. The routing key for everything. **Stable.**
- `payload` — Essential. Opaque app data. **Stable.**
- `signature` + `pubkey` — Essential. Identity and integrity. **Stable.**
- `ttl` — Essential. Controls storage and expiry. **Stable.**
- `durable` — Essential. The split between "message" (ephemeral) and
  "record" (persistent) is real and important. **Stable.**
- `timestamp` — Essential for ordering and dedup. Currently optional
  (`omitempty`). Should be required — dedup hash includes it, and the
  `since` query depends on it. **Stable, but should be required.**
- `no_gossip` — This is an API concern, not a data concern. An app
  submits locally and doesn't want mesh forwarding. But it's baked into
  the envelope and the signing digest. If it's in the digest, changing
  it changes the signature — which means it's a semantic field, not just
  a flag. **Experimental. Consider moving to API-layer-only in v2.**
- `monetization` — Declares payment terms (passthrough, split, token,
  free). Currently included in the signing digest. This is correct —
  the publisher commits to the payment terms. If it were API-only, a
  node could change the terms after the publisher signed. But it adds
  complexity to every envelope even when there's no payment. Most
  envelopes are free. **Stable, but the nil/omitempty handling must be
  spec'd precisely for digest computation.**

**Missing:**
- No `version` field. If the envelope format changes, there's no way
  for a receiver to know which format it's parsing. **Add in v2.**
- No `content_type` or `encoding` field. Payload is always a string.
  Apps encode JSON, but nothing enforces or declares this. For now
  this is fine — keep payloads opaque. **Not needed yet.**

**Verdict:** The envelope is close to right. Lock the core 7 fields as
stable (type, topic, payload, signature, pubkey, ttl, durable, timestamp).
Mark no_gossip and monetization as stable-with-caveats. Plan version
field for next format revision.

**Stability: STABLE** (core fields), **EXPERIMENTAL** (no_gossip)

---

### C2. Gossip Model

**Question:** Does flood-to-interested scale?

**Current model:** Every envelope is forwarded to every connected peer
whose declared interest prefixes match the topic. No hop count, no TTL
on gossip hops, no relay limits.

**At 2 nodes:** Perfect. Every envelope hits both nodes. Zero waste.

**At 10 nodes:** Still fine. Each node connects to seeds, envelopes
flood the full mesh. Some duplicates via multiple paths, caught by dedup.

**At 50 nodes:** Problems emerge. If all 50 declare interest in `""` (all
topics), every envelope is sent 49 times by the originator, plus
re-forwarded by each recipient to its peers. With dedup this doesn't
loop, but the fan-out is O(N) per envelope per hop. A node publishing
10 envelopes/sec generates 490 sends/sec just from its direct peers.

**At 500 nodes:** Unworkable with full-mesh flood. Need structured relay.

**But:** Anvil-Mesh doesn't need to solve for 500 nodes today. The
realistic near-term target is 5-20 nodes. Flood-to-interested works
fine there. The architecture already has the right primitive (interest
prefixes) to evolve into something smarter later — e.g., relay trees
where interior nodes aggregate interests and filter traffic.

**The real scale question is interest granularity.** If every node
subscribes to `""` (all topics), flood is maximally wasteful. If nodes
specialize — "I only care about `oracle:*`" — traffic naturally
partitions. The protocol should *encourage* narrow interests, not
require wildcard.

**What to lock now:**
- Prefix-based interest matching: **Stable.**
- Dedup by content hash: **Stable.**
- Flood-to-all-interested: **Experimental.** Works now, will need
  structured relay at scale. Don't spec this as the permanent model.

**Open question for Phase 3:** Should envelopes carry a `hop` counter?
This would let nodes implement TTL-based relay limits without changing
the gossip model. Low cost, high optionality.

**Stability: EXPERIMENTAL** (gossip fanout), **STABLE** (interest matching, dedup)

---

### C3. Topic Naming

**Question:** Should topics be structured or freeform?

**Current state:** Arbitrary strings. No enforced convention. Apps use
colon-delimited names by convention (`proofroom:session:ROOM_ID`,
`oracle:rates:bsv`, `mesh:heartbeat`). BRC-87 says topic managers
should use `tm_*` prefix, lookup services `ls_*`.

**Tension:** BRC-87 naming (`tm_uhrp_files`) doesn't match Anvil's
current convention (`oracle:rates:bsv`). These are different things —
BRC-87 names topic *managers* (server-side components), Anvil topics
are data *channels*. They can coexist.

**What matters for the protocol:**
- Topics are routing keys. Prefix matching is the filter mechanism.
- A bad naming convention means interest prefixes don't partition
  traffic well (C2 problem).
- A too-strict convention discourages adoption.

**Recommendation:**
- Reserve `mesh:*` for protocol-level topics (heartbeat, blocks).
  **Stable.**
- Reserve `anvil:*` for node-level topics (catalog). **Stable.**
- Recommend but don't enforce colon-delimited structure for app topics:
  `appname:category:id`. **Recommendation, not requirement.**
- Don't build a registry. Let apps own their namespace by convention.
  If two apps collide, they collide — same as DNS without registration.
  At current scale this is fine.

**Stability: STABLE** (reserved prefixes), **RECOMMENDATION** (app naming)

---

### C4. SHIP Gossip vs BRC-88 On-Chain

**Question:** Is gossip-based SHIP a conformance gap?

**BRC-88 model:** Nodes publish SHIP tokens as on-chain PushDrop
transactions. Discovery happens by looking up these tokens via overlay
lookup services. Each advertisement costs a transaction.

**Anvil model:** Nodes announce SHIP registrations via gossip messages
(`ship_sync`). No on-chain transactions. Discovery is immediate (gossip
propagation) instead of delayed (tx confirmation + lookup query).
Directory entries have 6-hour TTL, refreshed every 45 minutes.

**Is this a conformance gap?**
Technically yes — BRC-88 specifies on-chain tokens. Anvil doesn't
produce them. But BRC-88 also says "pursuant to any peering
arrangements" for propagation. Anvil's gossip IS the peering
arrangement.

**Does it matter practically?**
For Anvil-Mesh interoperability with Anvil-Mesh nodes: no. Gossip SHIP
is faster, cheaper (no tx fee), and works offline from the chain.

For interoperability with non-Anvil BRC-88 nodes: yes. A BRC-88
node would look for on-chain SHIP tokens and not find Anvil's
gossip-based registrations. They'd be invisible to each other.

**Recommendation:**
- Keep gossip SHIP as the primary discovery mechanism. **Stable.**
- Optionally publish on-chain SHIP tokens for cross-ecosystem
  visibility. The directory already validates BRC-42 SHIP tokens
  (directory.go:77-112) and subscribes to JungleBus for on-chain
  discovery. The gap is outbound only — Anvil reads on-chain tokens
  but doesn't write them.
- This is a bridge problem, not a protocol problem. Solve it when
  a non-Anvil overlay node wants to discover Anvil nodes.

**Stability: STABLE** (gossip SHIP), **FUTURE** (on-chain SHIP publish)

---

### C5. tx_announce/request/response

**Question:** Still needed after Teranode kills the mempool?

**What they do:** Flood-fill relay of raw transactions between mesh
nodes. Source was: (a) P2P mempool monitor, (b) API broadcast, (c)
peer announcement. Receiver stores in local mempool, triggers address
watcher, re-announces.

**What's dead:** Source (a) — P2P mempool monitor. No mempool to watch.
Source (c) depends on (a) and (b).

**What survives:** Source (b) — API broadcast. When an app submits a
tx via `POST /broadcast`, the broadcaster can announce it to mesh
peers. This is still valid: an app publishes a tx, mesh nodes learn
about it before it's mined.

**But is it valuable?** The mesh tx relay was built to support the
address watcher (D2) and mempool marketplace (E1). Both are dead.
What remains is: "mesh nodes have a copy of the raw tx for a few
minutes before it's mined." This enables:
- BEEF proof building from local mempool (don't need to fetch from WoC)
- Mesh-internal tx awareness (node B knows about node A's tx)

These are marginal. The tx relay adds 3 message types, dedup logic,
a mempool interface, and wiring in main.go — meaningful complexity
for marginal value.

**Recommendation:**
- **Deprecate.** Mark tx_announce/request/response as deprecated.
  Don't remove from code yet (backward compat during transition).
  Don't include in the protocol spec.
- If a clear use case emerges, un-deprecate. But don't carry 3
  message types that exist for dead features.

**Stability: DEPRECATED**

---

### C6. slash_warning

**Question:** Formalize or replace with peer scoring?

**Current state:** Two active slash reasons: `gossip_spam` (25%
severity, auto-triggered after 200 rate-limit drops) and `bad_proof`
(50%, manual). `double_publish` is deprecated (dropped silently).
Deregistration requires 3+ warnings from 2+ reporters in 48 hours.

**What works:**
- The 2-reporter requirement prevents single-node attacks. Good.
- The 48-hour grace period prevents permanent bans for transient
  issues. Good.
- `gossip_spam` auto-detection catches genuinely abusive peers. Good.

**What doesn't work:**
- At 2-3 nodes, "2+ unique reporters" means essentially all other
  nodes must agree. That's consensus, not reputation.
- `bad_proof` requires manual reporting. Nobody does this.
- Soft-slash (disconnect only) is toothless if the peer reconnects.
- No positive reputation — nodes can't build trust, only lose it.

**Recommendation:**
- Keep `gossip_spam` auto-detection and the 2-reporter threshold.
  It's the right mechanism at small scale. **Stable.**
- Keep `bad_proof` as a manual report mechanism. Even if unused,
  it's the right concept. **Stable.**
- Don't formalize severity percentages or grace periods in the spec.
  These are tuning knobs. Let implementations choose. **Experimental.**
- Don't build peer scoring yet. At 2-5 nodes you know your peers
  by name. Scoring becomes necessary at 10+. Premature now.
- Plan: when scoring is built, slash becomes an input to the score,
  not a standalone system. This is backward-compatible.

**Stability: STABLE** (gossip_spam + bad_proof + multi-reporter), **EXPERIMENTAL** (thresholds/tuning)

---

### C7. Heartbeat and Block Tip

**Question:** Essential or noise?

**Heartbeat (mesh:heartbeat, every 60s):**
Publishes: header height, peer count, active topics. This is how
the Explorer and `/mesh/nodes` know which nodes are alive. Without
heartbeats, node liveness is only detectable by connection state —
which is only visible to directly connected peers, not the whole mesh.

Heartbeats are what make the mesh *observable*. An app can subscribe
to `mesh:heartbeat` via SSE and build a live dashboard without any
special access. This is essential for TrueProof, Explorer, and any
monitoring use case.

**Block tip (mesh:blocks, every 10s on change):**
Publishes: header height + block hash. This is SPV-era infrastructure.
Apps on the Anvil-Mesh mostly don't care about block heights. The
header chain matters for x402 payment verification, but that's internal
to each node — broadcasting block tips doesn't help.

**Recommendation:**
- Heartbeat: **Stable.** Essential for observability. Consider whether
  the payload should be richer (uptime, version, storage stats) or if
  that creeps toward surveillance.
- Block tip: **Removed in v1.2.0.** No consumers. Header sync is
  node-internal. Decision confirmed.

**Stability: STABLE** (heartbeat), **REMOVED** (block tip)

---

### C8. Catchup Model

**Question:** Should catchup be generalized?

**Current state:** On connect, nodes request cached envelopes for 3
hardcoded topics: `anvil:catalog`, `mesh:heartbeat`, `mesh:blocks`.
Limit 50-100 envelopes per request. Single request/response, no
pagination follow-up.

**What works:** The concept is right. A reconnecting node needs to
catch up on what it missed. Without catchup, transient disconnects
mean lost data.

**What doesn't work:**
- 3 hardcoded topics. What about app topics? TrueProof publishes to
  `proofroom:session:*` — if a node reconnects, it misses session
  signaling. ClawSats publishes capabilities — missed on reconnect.
- No pagination. If there are 500 envelopes, you get the first 100
  and `hasMore=true`, but nothing sends a follow-up request.
- Catchup is connect-time only. No way to request catchup mid-session.

**Resolved in v1.2.0:**
- Catchup generalized to non-empty interest prefixes + built-in topics.
- Pagination implemented: `Since` as older-than cursor, `HasMore`
  correctly set, up to 5 follow-up rounds per peer:topic.
- Round counters keyed by `peer:topic`, no cross-peer interference.

**Stability: STABLE** (message format + generalized catchup + pagination)

---

### C9. Authentication Model

**Question:** Is BRC-31 Authrite right for WebSocket?

**Current state:** go-sdk `auth.Peer` wraps each WebSocket connection.
Authrite mutual authentication happens on first message exchange.
Both sides reveal identity pubkeys. Session is authenticated for the
life of the connection.

**BRC-31 was designed for:** HTTP request/response. Each request
carries `X-Authrite-*` headers. Session state tracked across requests
via nonce pairs.

**Does it map to WebSocket?** The go-sdk auth.Peer abstracts this —
it handles the initial handshake and then wraps subsequent messages.
It works. The mapping is: "first message = auth handshake, all
subsequent messages = authenticated session."

**Concerns:**
- Session rotation: BRC-31 supports certificate exchange and
  re-scoping. Over a long-lived WebSocket, there's no mechanism
  to rotate session keys or re-authenticate. If a connection stays
  open for days, the initial auth is stale.
- But: node connections are meant to be persistent. Re-auth on
  every message would be wasteful. The 30-second reconnect on
  disconnect provides natural session refresh.

**Recommendation:**
- BRC-31 over WebSocket via go-sdk auth.Peer is the right approach.
  It works, it's BRC-conformant, and the go-sdk handles the
  abstraction. **Stable.**
- Don't add session rotation complexity. Reconnection is the
  natural rotation mechanism.
- Document that the auth model is "BRC-31 initial handshake,
  authenticated session for connection lifetime." This is enough
  for another implementer.

**Stability: STABLE**

---

### C10. Bond Checking

**Question:** Still the right mechanism?

**Current state:** If `min_bond_sats > 0`, new peers must have a UTXO
at their identity address with at least that many satoshis. Checked
via WhatsOnChain API. Cached for 1 hour on success, no cache on
failure. Peer rejected if bond insufficient.

**What it provides:** Sybil resistance. Running a mesh node costs
money (the bond is locked up). Prevents free creation of unlimited
fake nodes.

**Problems:**
- WhatsOnChain dependency. External API for a core protocol decision.
  Fragile. Will need to migrate to Asset Server post-Teranode.
- Bond is "prove you have money at this address." It's not staked —
  the peer can spend it immediately after passing the check. The
  1-hour cache means a peer could bond-check, then move the funds.
- At 2 nodes with `min_bond_sats=0`, this is completely unused.

**Recommendation:**
- Keep as opt-in (`min_bond_sats=0` default). Don't spec it as
  required behavior. **Experimental.**
- Migrate UTXO lookup from WhatsOnChain to Asset Server when
  available. This is an AM2 TODO item.
- Long-term: real bonding requires a locked UTXO (e.g., time-locked
  output or covenant). That's v2/governance territory. Don't
  over-engineer now.
- For the spec: document that nodes MAY require bonds and MAY
  choose their own verification method. Don't specify the
  verification mechanism.

**Stability: EXPERIMENTAL**

---

### C11. Rate Limiting

**Question:** Should rate limits be configurable or negotiable?

**Current state:** 30 envelopes/sec per peer, burst 100. Hardcoded.
Token bucket algorithm. Drops silently, escalates to slash warning
after 200 drops in 10 minutes.

**What works:** Simple, effective, prevents abuse. The burst of 100
handles reconnection catchup without false positives.

**What doesn't work:**
- An oracle publishing price updates every 100ms legitimately hits
  10/sec. Fine under the 30/sec limit. But an IoT network with
  1000 sensors publishing through one gateway node could easily
  exceed 30/sec. The gateway gets rate-limited even though the
  traffic is legitimate.
- 30/sec is a single global number. No per-topic differentiation.
  A node publishing 25/sec of heartbeats crowds out app data.

**Recommendation:**
- Keep 30/sec as the default. It's a reasonable baseline. **Stable
  as default.**
- Make the rate configurable per node (already partially true —
  it's set in manager.go but not exposed in config). Expose it.
  **Change needed.**
- Don't add per-topic rate limits yet. The complexity isn't
  justified at current scale. But design the rate limiter so
  per-topic could be added later (key the bucket by peer+topic
  instead of just peer).
- Don't add negotiation. Peers don't negotiate rate limits in
  any protocol I know of that works. The receiver sets the limit,
  the sender respects it or gets dropped. Simple.
- The escalation path (200 drops → slash warning) is good.
  **Stable.**

**Stability: STABLE** (mechanism + escalation), **NEEDS CHANGE** (expose in config)

---

### C12. Storage Model

**Question:** What happens at scale?

**Current state:**
- Durable envelopes: LevelDB, keyed by `d:topic:pubkey_prefix:payload_hash`.
  No eviction. Max store size configurable (default 10 GB), warning at 80%.
- Ephemeral envelopes: in-memory map, swept every 30 seconds.
- Dedup: in-memory map, max 10,000 entries, LRU half-purge.

**What works:** LevelDB is fast, embedded, no external dependency.
The dual storage model (durable vs ephemeral) is clean. The 10 GB
default is reasonable for a VPS.

**What doesn't work:**
- No eviction for durable envelopes. If an app publishes durable
  data forever, the store grows forever. The 10 GB cap triggers
  a warning but doesn't reject new data.
- No topic-based storage specialization. Every node stores
  everything it receives. At scale, nodes should be able to say
  "I only store `oracle:*` topics."
- Dedup map at 10,000 entries. At 30 envelopes/sec from each of
  10 peers, that's 300/sec. The map fills in 33 seconds, then
  half-purges. This is fine for dedup (false negatives just mean
  a duplicate is stored, caught by the store's own dedup). But
  it's not great for preventing gossip loops at scale.

**Recommendation:**
- Add eviction policy for durable store. Options: LRU by topic,
  oldest-first, or quota-per-topic. Don't spec the policy — let
  nodes choose. But spec that nodes MAY evict durable envelopes
  and MUST NOT assume permanent storage. **Change needed.**
- Topic-based storage specialization aligns with interest prefixes
  (C2). If a node declares interest in `oracle:*`, it stores
  `oracle:*` envelopes. Everything else it forwards but doesn't
  store. This is a natural extension. **Future.**
- Increase dedup map size or switch to a time-windowed bloom
  filter. **Experimental** (implementation detail, not spec).

**Stability: STABLE** (dual model, LevelDB), **NEEDS CHANGE** (eviction policy), **FUTURE** (specialization)

---

### C13. API Surface

**Question:** Is the HTTP API part of the protocol?

**Current endpoints:** `/data`, `/data/subscribe`, `/overlay/*`,
`/mesh/*`, `/broadcast`, `/beef/*`

**The distinction:**
- **Node-to-node protocol** = gossip messages over WebSocket. This
  is what makes two Anvil-Mesh nodes compatible. It MUST be spec'd.
- **App-to-node API** = HTTP endpoints for apps. This is how apps
  interact with a single node. It SHOULD be documented, but a
  different implementation could expose a different API and still
  be a valid mesh node.

**Exception: BRC-22/24 endpoints.** `/overlay/submit` and
`/overlay/query` are BRC-specified. If Anvil-Mesh claims BRC-22/24
conformance, these endpoints (or equivalent) MUST exist.

**Exception: x402 challenge/response.** If x402 is a first-class
protocol element (C15), the payment negotiation endpoints are
protocol, not just API.

**Recommendation:**
- Spec the node-to-node protocol (message types, connection
  lifecycle, gossip rules). **This is the protocol.**
- Document the app-to-node API as the reference implementation's
  API. Another implementation MAY differ. **Recommendation,
  not requirement.**
- Spec BRC-22/24 endpoints as required for BRC conformance.
  **Stable.**
- Spec x402 endpoints as required if x402 is protocol-level.
  **Depends on C15.**

**Stability: N/A** (classification question, not a stability question)

---

### C14. BRC-22/24 Conformance

**Question:** Do Anvil's overlay endpoints actually conform?

**BRC-22 specifies:** `POST /submit` with BRC-8 envelope (rawTx,
inputs, mapiResponses, proof) + topics array. Response: `{status,
topics: {name: [output_indices]}}`.

**Anvil has:** `POST /overlay/submit` — need to check if the request/
response format matches BRC-22 exactly.

**BRC-24 specifies:** `POST /lookup` with `{provider, query}`.
Response: array of BRC-36 UTXOs (txid, vout, outputScript, etc.).

**Anvil has:** `POST /overlay/query` and `GET /overlay/lookup` — 
need to verify format match.

**Known gaps from the code:**
- Anvil's primary data path is `POST /data` (envelope submission),
  not `POST /submit` (BRC-22 transaction submission). These are
  different things. BRC-22 submits *transactions* to overlay topics.
  Anvil submits *envelopes* (signed data, not necessarily txs).
- The overlay endpoints exist but are secondary. Most apps use
  `/data` directly.

**This is a fundamental design question:** BRC-22 treats overlays
as *transaction processors* — they receive txs, validate them,
admit outputs to topics. Anvil treats the overlay as a *data mesh*
— it receives signed envelopes, routes them by topic, stores and
serves them. Transactions are just one type of data.

**Audit results (2026-04-03):**

BRC-22 `POST /submit` submits a BRC-8 transaction envelope with a
`topics` array and returns which outputs were admitted per topic.
Anvil has no `/submit` endpoint. Its equivalent (`POST /data`) submits
signed envelopes (not transactions). Different data model entirely.

BRC-24 `POST /lookup` with `{provider, query}` returns BRC-36 UTXO
arrays. Anvil's `GET /overlay/lookup` returns SHIP peer discovery
info (identity, domain, topic), not UTXOs.

**Conclusion:** Anvil is not BRC-22/24 non-conformant — it operates
in a space those specs don't cover. BRC-22/24 are UTXO-tracking
overlays ("which tx outputs belong to which topics?"). Anvil is a
data-envelope overlay ("signed data routed by topic"). Complementary,
not competing. Anvil's envelope model is its own contribution — could
become its own BRC if adopted. No remediation needed.

**Stability: STABLE** (Anvil extends BRC, does not implement BRC-22/24)

---

### C15. x402 as Protocol

**Question:** Should x402 be a first-class protocol element?

**What x402 does today in Anvil:**
1. App requests gated data → node returns 402 + challenge (nonce,
   payees, amount, expiry)
2. App builds BSV tx paying the challenge payees + spending the
   nonce UTXO
3. App sends proof (raw tx or BEEF) back to node
4. Node verifies: nonce binding, payee amounts, script signatures,
   optionally ARC mempool acceptance
5. Node delivers the data

**This is a protocol.** It has message types (challenge, proof),
a negotiation flow, verification rules, and economic semantics.
It's currently implemented as HTTP headers and API logic, but the
*behavior* is protocol-level.

**What makes x402 special for Anvil-Mesh:**
- It's where gossip meets economics. Gossip distributes data to
  nodes (supply-side). x402 lets nodes charge for access (demand-
  side). Together they're a complete data market.
- It crosses ecosystems. x402-style "HTTP 402 payment required"
  is being explored by developers far beyond BSV. Anvil-Mesh's
  implementation is one of the few that's actually running.
- It's the adoption hook. A developer who wants to sell API
  access for micropayments cares about x402 before they care
  about SHIP or gossip or envelopes.

**What needs to be spec'd:**
- Challenge format: what fields, what's signed, what's the nonce
  binding mechanism
- Proof format: how the payment is presented (raw tx vs BEEF,
  headers vs body)
- Verification rules: what a node MUST check before delivering data
- Payment models: passthrough (app sets payee), split (node takes
  fee), token gating (pre-paid access)
- Interaction with envelope monetization field: how a publisher
  declares terms, how a serving node enforces them

**What NOT to spec (yet):**
- How the payment reaches the blockchain. Today it's ARC, tomorrow
  Arcade. That's an implementation detail behind the verification.
- Revenue sharing between nodes. If Node A gossips data to Node B,
  and Node B charges an app via x402, does Node A get a cut? This
  is an economics question, not a protocol question. Premature.

**Recommendation:**
- Elevate x402 to a first-class protocol element. **Stable.**
- Spec the challenge/proof/verify flow. It's well-defined in code
  (payment_verify.go is 300+ lines of real verification logic).
- Spec the envelope monetization field as the publisher's terms.
- Don't spec revenue sharing or inter-node economics. Let the
  market figure that out.
- Lead with x402 publicly. It's the hook.

**Stability: STABLE** (flow + verification), **FUTURE** (inter-node economics)

---

### Phase 2 Summary — Stability Classification

| Element | Stability | Action |
|---------|-----------|--------|
| **Envelope core fields** (type, topic, payload, sig, pubkey, ttl, durable, timestamp) | STABLE | Lock. Spec in Phase 3. |
| **Envelope no_gossip** | EXPERIMENTAL | Consider moving to API-only in v2 |
| **Envelope monetization** | STABLE | Spec nil/omitempty digest rules precisely |
| **Envelope version field** | MISSING | Add in next format revision |
| **Gossip interest matching** (prefix-based) | STABLE | Lock. Spec in Phase 3. |
| **Gossip dedup** (content hash) | STABLE | Lock. Spec in Phase 3. |
| **Gossip fanout** (flood-to-interested) | EXPERIMENTAL | Works at 5-20 nodes. Will need structured relay later. |
| **Topic reserved prefixes** (`mesh:*`, `anvil:*`) | STABLE | Lock. Spec in Phase 3. |
| **Topic app naming** (colon-delimited convention) | RECOMMENDATION | Don't enforce. Document. |
| **SHIP gossip sync** | STABLE | Lock. Primary discovery mechanism. |
| **SHIP on-chain publish** | FUTURE | Bridge to BRC-88 ecosystem. Not blocking. |
| **tx_announce/request/response** | DEPRECATED (v1.2.0) | Accepted but silently dropped. Not spec'd. |
| **slash_warning mechanism** (multi-reporter) | STABLE | Keep gossip_spam + bad_proof. |
| **slash_warning thresholds** (3 warnings, 48h, 2 reporters) | EXPERIMENTAL | Tuning knobs. Don't spec exact numbers. |
| **Heartbeat** (`mesh:heartbeat`) | STABLE | Essential for observability. |
| **Block tip** (`mesh:blocks`) | REMOVED (v1.2.0) | No consumers. Header sync is node-internal. |
| **Catchup message format** (data_request/response) | STABLE | Lock format. |
| **Catchup topic selection** | STABLE (v1.2.0) | Generalized to interest prefixes + built-ins. |
| **Catchup pagination** | STABLE (v1.2.0) | Since cursor, HasMore, 5-round cap. |
| **Authentication** (BRC-31 over WebSocket) | STABLE | Lock. go-sdk handles it. |
| **Bond checking** | EXPERIMENTAL | Opt-in. Don't spec verification method. |
| **Rate limiting mechanism** (token bucket + escalation) | STABLE | Lock. |
| **Rate limiting values** (30/sec, burst 100) | STABLE (v1.2.0) | Exposed in config as rate_per_sec + rate_burst. |
| **Storage dual model** (durable LevelDB + ephemeral memory) | STABLE | Lock concept. |
| **Storage eviction** | STABLE (v1.2.0) | Reject when full (Option A). Periodic capacity check. |
| **Storage specialization** (topic-based) | FUTURE | Natural extension of interests. |
| **API surface** | RECOMMENDATION | Document as reference. Not protocol. |
| **BRC-22/24 endpoints** | STABLE | Audited: Anvil extends BRC, not implements. No remediation. |
| **x402 challenge/proof/verify** | STABLE | Elevate to protocol. Spec the flow. |
| **x402 inter-node economics** | FUTURE | Let the market figure it out. |

### Changes Needed Before Phase 3 — ALL DONE (v1.2.0)

1. ~~Make timestamp required~~ DONE — accepted but backfilled in Ingest after sig verify
2. ~~Add version field~~ DONE — backward-compat, appended to digest when > 0
3. ~~Generalize catchup~~ DONE — derives from non-empty interest prefixes + built-ins
4. ~~Add catchup pagination~~ DONE — Since cursor (older-than), HasMore, 5-round cap
5. ~~Expose rate limit config~~ DONE — `rate_per_sec` + `rate_burst` in config
6. ~~Add eviction policy~~ DONE — periodic capacity check, reject when full (Option A)
7. ~~Audit BRC-22/24 conformance~~ DONE — Anvil extends BRC, no remediation

### What Was Removed / Not Spec'd (v1.2.0)

1. **tx_announce/request/response** — deprecated, accepted but dropped silently
2. **Block tip publishing** — removed, no consumers
3. **Bond checking details** — opt-in, don't spec verification method
4. **Slash thresholds** — experimental, let implementations choose
5. **Specific API endpoints** — document as reference, not protocol
6. **TX mesh relay wiring** — disabled (broadcaster + mempool announcers unwired)

---

## Strategic Context — Protocol Adoption Path

**Current reality:** One operator, two nodes, zero independent implementers.

**The spectrum:**
- **Product** — Robert runs the mesh, apps build on it, they trust Robert.
  Works now. Doesn't scale trust.
- **Open protocol, reference implementation** — Stable behaviors are
  documented so someone *could* build a compatible node. Robert still
  runs the reference implementation. If a second implementation appears,
  it becomes a real protocol. ← **Target this.**
- **Open governance** — Formal change process, multiple stakeholders.
  Premature. Need multiple stakeholders first.

**What makes adoption possible:**
1. Documented stable behaviors (this document, Phase 3)
2. At least one independent node operator (02869a0a was the seed)
3. A hook that makes developers care (x402 — the widest door)
4. A foundation they trust (BRC-100 — the plumbing under x402)

**Leading with x402 vs BRC-100:**
- Lead publicly with x402 — it's where energy is, it crosses ecosystems,
  it solves a problem people recognize ("pay for data, get data")
- Build privately on BRC-100 — it's the foundation, but nobody gets
  excited about foundations until they've seen the building
- People adopt what solves their problem, then learn what it's built on

**Formal spec vs ship-and-see:**
Don't write a full spec yet. Instead, for each protocol element in Phase 2,
classify as:
- **Stable** — won't break under you, safe to build against
- **Experimental** — works but might change, build at your own risk
- **Deprecated** — exists but scheduled for removal

This gives early adopters something to build on without locking Robert
into decisions that need real-world feedback first.

**The keys problem:**
Resolves when the protocol is open. Robert holds the keys to *his nodes*.
Anyone can run *their own*. The mesh architecture already supports this —
nodes are peers, not clients of a central server. The protocol doc is
what makes that real instead of theoretical.

---

## Phase 3 — Definition (future)

After Phase 2 critique is resolved, write the formal spec:

- Message types with MUST/SHOULD/MAY
- Envelope format (canonical, versioned)
- Connection lifecycle (required handshake sequence)
- Gossip rules (forwarding, dedup, rate limiting)
- SHIP sync rules (announce, TTL, sweep)
- Topic conventions (namespacing, reserved prefixes)
- Storage requirements (what a node MUST persist vs MAY cache)
- API requirements (what endpoints a conformant node MUST expose)
- BRC conformance requirements (where Anvil-Mesh extends BRC, document the extension)

This becomes the document that lets someone build a compatible Anvil-Mesh
node without reading Go code.

---

## Parked Protocol Questions

These surfaced during the audit but need broader discussion:

- **Should the gossip protocol be versioned?** Currently no version field
  in messages. Adding a version allows protocol evolution without breaking
  existing nodes.

- **Should envelopes carry a protocol version?** Same concern. If the
  envelope format changes, how do old nodes handle new envelopes?

- **Is WebSocket the right transport long-term?** BRC-101 mentions
  alternative transports. Should the protocol be transport-agnostic?

- **Should there be a formal "peer capabilities" handshake?** Currently
  nodes only declare topic interests. What if a node wants to declare
  "I support tx relay" or "I support encrypted envelopes"?
