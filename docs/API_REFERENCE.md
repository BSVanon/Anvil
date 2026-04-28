# API Reference

## Core Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | Node health: version, header tip, sync lag, warnings |
| `/stats` | GET | No | Extended stats: envelopes, peers, recent connections, demand |
| `/data` | GET | No | Query envelopes by topic (`?since=TIMESTAMP` for incremental) |
| `/data/subscribe` | GET | No | SSE stream of new envelopes by topic (real-time push) |
| `/data` | POST | Bearer or x402 | Publish a signed envelope |
| `/data` | DELETE | Bearer | Delete a stored envelope by `topic` + `key` |
| `/broadcast` | POST | Bearer or x402 | Submit BEEF for validation; forwards to ARC if `?arc=true`. Returns derived `status` field. x402 accepted only when node sets a positive broadcast price. |
| `/messages/subscribe` | GET | Bearer (via `?token=`) | SSE stream of new BRC-33 messages in real time |
| `/mesh/status` | GET | No | Rich live health snapshot; carries `upstream_status` for wallet failover decisions |
| `/mesh/nodes` | GET | No | Authoritative federation directory (merged from SHIP + heartbeat + gossip adjacency) |

## Discovery Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/topics` | GET | No | List all topics with count and metadata |
| `/topics/{topic}` | GET | No | Topic detail: metadata, publisher, price, demand, identity |
| `/identity/{pubkey}` | GET | No | Publisher identity (from `identity:<pubkey>` envelope) |
| `/.well-known/x402` | GET | No | Machine-readable payment menu |
| `/.well-known/x402-info` | GET | No | Protocol spec (JSON or markdown) |
| `/.well-known/identity` | GET | No | Node identity public key |
| `/.well-known/anvil` | GET | No | Node metadata and capabilities |

## Messaging Endpoints (BRC-33)

Point-to-point messaging between identities.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/sendMessage` | POST | Bearer | Send a message to a recipient by pubkey |
| `/listMessages` | POST | Bearer | Retrieve messages for a recipient's message box |
| `/acknowledgeMessage` | POST | Bearer | Delete messages after receipt |

### POST /sendMessage

```json
{
  "recipient": "02abc...def",
  "messageBox": "inbox",
  "body": "hello"
}
```

Response: `{"status": "success", "messageId": "42"}`

The sender is the node's identity. Messages are forwarded across the mesh
via gossip with sender signature verification. Unacknowledged messages
expire after 7 days.

### POST /listMessages

```json
{
  "recipient": "02abc...def",
  "messageBox": "inbox"
}
```

Response: `{"status": "success", "messages": [{"messageId": "42", "sender": "02xyz...", "body": "hello", "timestamp": 1712345678}]}`

If `recipient` is omitted, defaults to the node's identity.

### POST /acknowledgeMessage

```json
{
  "recipient": "02abc...def",
  "messageIds": ["42", "43"]
}
```

Response: `{"status": "success", "acknowledged": 2}`

## Proof and Content Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/tx/{txid}/beef` | GET | No | BEEF proof for a transaction. `Accept: application/octet-stream` returns raw bytes. |
| `/headers/tip` | GET | No | Current BSV header-chain tip: `{height, hash}` |
| `/headers/range` | GET | No | N consecutive raw 80-byte block headers. Query: `from`, `count` (1..50). JSON default; `Accept: application/octet-stream` returns `count × 80` raw bytes. Used by SPV proof-builders. |
| `/content/{txid}_{vout}` | GET | No | Raw content from a transaction output |

## Node-Signed Publishing

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/node/publish` | POST | Bearer | Publish an envelope signed by the node's identity key |

Use this to publish metadata (`meta:<topic>`), identity (`identity:<pubkey>`),
and catalog entries without external signing tools. The node signs with its
identity key before storing.

## Overlay Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/overlay/lookup` | GET | No | SHIP peer discovery by topic |
| `/overlay/register` | POST | Bearer | Register a SHIP token |
| `/overlay/deregister` | POST | Bearer | Remove a SHIP peer |

## Wallet Endpoints (operator only)

All wallet endpoints require the `Authorization: Bearer <token>` header.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/wallet/outputs` | GET | List wallet UTXOs |
| `/wallet/send` | POST | Send BSV to an address |
| `/wallet/invoice` | POST | Create a payment invoice |
| `/wallet/scan` | POST | Scan for UTXOs at identity address |
| `/wallet/internalize` | POST | Import a BEEF transaction |
| `/wallet/create-action` | POST | Low-level BRC-101 action creation |
| `/wallet/sign-action` | POST | Low-level BRC-101 action signing |

## Other

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/explorer` | GET | No | Node explorer dashboard |
| `/app/{name}` | GET | No | Redirect to registered app |

## Broadcast response shape (v2.1.0+)

`POST /broadcast` returns a structured response. Wallets should read the
derived `status` field for failover decisions; power consumers can read
the individual ARC state bits for telemetry.

```json
{
  "txid": "abc123...",
  "status": "propagated" | "queued" | "rejected" | "validated-only",
  "confidence": "spv_verified" | "partially_verified" | "unconfirmed" | "invalid",
  "stored": true,
  "mempool": true,
  "arc": { "submitted": true, "tx_status": "SEEN_ON_NETWORK" },
  "message": "..."
}
```

Status derivation:

| Condition | status |
|---|---|
| `confidence == "invalid"` | `"rejected"` |
| `arc.submitted && tx_status ∈ {REJECTED, DOUBLE_SPEND_ATTEMPTED}` | `"rejected"` |
| `arc.submitted && tx_status ∈ {SEEN_ON_NETWORK, MINED}` | `"propagated"` |
| `arc.submitted && intermediate ARC state` (RECEIVED, STORED, ANNOUNCED, etc.) | `"queued"` |
| No ARC attempt OR ARC HTTP failure (`submitted=false`) | `"validated-only"` |

Query `?arc=true` to forward to miners after BEEF validation. ARC
transport failures set `arc.submitted = false` and surface the error in
`arc.error`; consumers should retry via another upstream (status will be
`"validated-only"`, not `"queued"`).

## BEEF response shape (v2.1.0+)

`GET /tx/{txid}/beef` returns a `source` field indicating where the
proof came from:

```json
{
  "txid": "abc123...",
  "beef": "hex-encoded-beef",
  "source": "cached" | "arc" | "woc",
  "confidence": "spv_verified"
}
```

Binary responses (on `Accept: application/octet-stream`) surface the
same value via the `X-BEEF-Source` header. Wallets doing multi-source
BEEF chains should prefer `"cached"` from Anvil and fall back to a
direct upstream for `"arc"`/`"woc"` (passthrough).

## Mesh status response shape (v2.1.0+)

`GET /mesh/status` is the recommended wallet failover-decision endpoint
(CORS-only, no rate limit, no x402). Poll every 30–60 seconds.

```json
{
  "node": "anvil-prime",
  "version": "2.1.0",
  "headers": { "height": 944988, "work": "0x..." },
  "identity": "02...",
  "mesh": { "peers": 2, "peer_list": [...], "started_at": "...", "uptime_secs": 3600 },
  "activity": { "envelopes_received": 100, "envelopes_sent": 42 },
  "topics": [{ "topic": "oracle:rates", "count": 100, "age_secs": 30 }],
  "overlay": { "ship_count": 7 },
  "upstream_status": {
    "broadcast": "healthy" | "degraded" | "down",
    "headers_sync_lag_secs": 12,
    "service_health": "healthy" | "degraded" | "broken"
  }
}
```

`broadcast` reflects the ARC (or Arcade, post-migration) upstream health;
`service_health` is the *host-level* health of the anvil service itself
(v2.2.0+). Values:

- `healthy` — systemd reports active with a low restart counter
- `degraded` — activating, or a small number of restarts, or sibling unit has issues
- `broken` — crash-looping service OR an orphan anvil process is detected
  on the host (holds LOCK files, prevents clean starts)

Wallet consumers can distinguish a transient ARC outage from a local
service meltdown — both bad, different remediations. The node also
auto-heals the `broken/orphan` case on the next service restart via a
systemd `ExecStartPre=anvil doctor --locks-only` hook installed by
`anvil deploy` since v2.2.0 (renamed from `--fix-locks-only` in v2.3.0;
the legacy name is still accepted for backward compatibility).

Heartbeat envelopes published on the `mesh:heartbeat` topic carry the
same `upstream_status` so federation consumers can observe node health
without direct-polling every node.

## Operator self-healing (v2.2.0+; ergonomics overhauled v2.3.0)

```
sudo anvil doctor                  # diagnose + prompt to fix each finding (default)
sudo anvil doctor --yes            # diagnose + fix without prompts (scripted)
sudo anvil doctor --no-fix         # diagnostic only (historical read-only mode)
sudo anvil doctor --locks-only     # kill orphan anvil processes, then exit 0
```

Since v2.3.0, `anvil doctor` is fix-interactive by default: every finding
shows a `[y/N]` prompt so operators get a guided walk-through without
having to remember a `--fix` flag. Legacy `--fix` and `--fix-locks-only`
flags from v2.2.x scripts are still accepted.

`anvil doctor` detects, remediates, and **verifies** the fix landed:

- **Orphan anvil processes** — a prior instance still holding LevelDB LOCK
  files, invisible to systemd. Caused the 12-day silent crash-loop before
  v2.2.0. Fix: SIGTERM then SIGKILL the orphan; verify no orphan remains.
- **Crash-looping systemd units** — `NRestarts > 5` AND `ActiveState ∈
  {activating, failed}`. Fix: `reset-failed` + `restart`; verify unit
  reaches `active/running` within 5s.
- **Stale header stores** — any `prev hash mismatch` error on the header
  sync path. Means the stored chain is reorg-incompatible with current
  BSV tip. Fix: wipe `<data_dir>/headers/*` (safe — only headers, preserves
  wallet/envelopes/overlay), restart services, verify lag drops within 45s.
- **Version skew** — running process version ≠ binary on disk. Happens
  when a shared-binary upgrade restarts only some services. Fix:
  `systemctl restart` mismatched services; verify each reaches
  `active/running`.

`doctor --locks-only` is the safe subset wired into systemd's
`ExecStartPre` — runs on every service start so a node can recover from
orphan-lock contention without operator intervention.

## Operator upgrade ergonomics (v2.2.2+)

- **`anvil upgrade` auto-adds the ExecStartPre hook** to existing unit
  files. Operators who installed on a version prior to v2.2.0 pick up
  the self-heal mechanism the next time they upgrade — no manual
  systemd surgery required.
- **`anvil deploy` replaces the binary atomically** (`.new` staging
  file + `rename` over the live path). Safe to re-run while services
  are up; no `text file busy` errors even when legacy units with
  different names still hold the old binary.

## Operator custom capabilities (v2.1.0+)

Node operators can declare capabilities in the node config TOML. These
surface in `/.well-known/anvil` under `capabilities[]`:

```toml
[[capabilities.custom]]
type = "avos-offer-oracle"
description = "MNEE ⇄ BSV oracle-attested swap"
oracle_pubkey = "02abc..."
mailbox = "avos.offer@node-identity"
access = "POST /sendMessage (messageBox: avos.offer)"
payment = "free"
```

Schema-less: any fields declared in the TOML pass through to the
manifest. Use this to advertise node-specific services (AVOS relays,
proprietary data feeds, etc.) without Anvil code changes.

### GET /messages/subscribe (v2.1.0+)

SSE push for new BRC-33 messages. EventSource cannot set custom headers,
so the auth token is passed via `?token=` query param:

```js
const url = `http://localhost:9333/messages/subscribe?messageBox=avos.offer&token=${token}`;
const source = new EventSource(url);
source.onmessage = (e) => console.log(JSON.parse(e.data));
```

Each message arrives as a `data:` event with a monotonic `id:` field.
On reconnect, use `Last-Event-ID` + `POST /listMessages` to backfill.

## Authentication

Transport auth for publishing data and sending messages:

1. **Bearer token** — operator auth, derived from WIF: `Authorization: Bearer <token>`
2. **x402 payment** — anyone can publish/query by paying the node's price

Every published envelope is also signed by the app's BSV key. The signature
proves authorship, but it does not replace bearer auth or x402 payment for
write endpoints.

Get your auth token:
```bash
sudo anvil token
```

## Real-time Subscription (SSE)

Subscribe to new envelopes on a topic via Server-Sent Events:

```bash
curl -N "http://localhost:9333/data/subscribe?topic=oracle:rates:bsv"
```

Each new envelope is pushed as a `data:` event with a monotonic `id:` field.
Paid payloads are redacted for unauthenticated clients.

On reconnect, the browser's `EventSource` sends `Last-Event-ID` automatically.
Use `GET /data?since=TIMESTAMP` to backfill any missed events.

```js
const source = new EventSource('http://localhost:9333/data/subscribe?topic=my:topic')
source.onmessage = (e) => {
  const envelope = JSON.parse(e.data)
  console.log(envelope.topic, envelope.payload)
}
```

## Incremental Polling

Use `since` to only fetch envelopes newer than a given unix timestamp:

```bash
curl "http://localhost:9333/data?topic=oracle:rates:bsv&since=1711600000"
```

## Topic Metadata Convention

Apps can describe their topics by publishing a durable envelope to `meta:<topic>`:

```bash
curl -X POST http://localhost:9333/data \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "type": "data",
    "topic": "meta:oracle:rates:bsv",
    "payload": "{\"description\":\"BSV/USD price feed\",\"update_interval\":\"60s\",\"schema\":{\"USD\":\"number\"}}",
    "durable": true,
    "ttl": 0,
    "timestamp": 1712345678,
    "signature": "...",
    "pubkey": "..."
  }'
```

The metadata is returned by `GET /topics/oracle:rates:bsv` in the `metadata` field.

## Publisher Identity Convention

Publishers can declare their identity by publishing to `identity:<pubkey>`:

```bash
curl -X POST http://localhost:9333/data \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "type": "data",
    "topic": "identity:02abc...def",
    "payload": "{\"name\":\"BSV Rates Oracle\",\"description\":\"Real-time price feeds\"}",
    "durable": true,
    "ttl": 0,
    "timestamp": 1712345678,
    "signature": "...",
    "pubkey": "02abc...def"
  }'
```

Returned by `GET /identity/02abc...def` and included in `GET /topics/{topic}`.

## Operator Commands

```bash
anvil help                  # full command reference
sudo anvil info             # identity, funding address, auth token
sudo anvil doctor           # validate config, connectivity, mesh health
sudo anvil token            # print auth token
curl -s localhost:9333/status   # node status
sudo journalctl -u anvil-a -f  # live logs
sudo systemctl restart anvil-a  # restart
```
