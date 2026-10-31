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
| `/messages/subscribe` | GET | Session or operator token (via `?token=`) | SSE stream of new BRC-33 messages in real time |
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

Point-to-point messaging between compressed secp256k1 identities. BRC-31
mutual authentication is preferred and scopes callers to their own identity;
the operator token remains a broad, node-scoped fallback.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/sendMessage` | POST | BRC-31 or operator token | Send a message to a recipient by pubkey |
| `/listMessages` | POST | BRC-31 or operator token | Retrieve messages for a recipient's message box |
| `/acknowledgeMessage` | POST | BRC-31 or operator token | Delete messages after receipt |
| `/messages/session` | POST | BRC-31 | Mint a five-minute, identity-scoped SSE token |
| `/messages/subscribe` | GET | Session or operator token | Stream newly arrived messages for one message box |

### POST /sendMessage

```json
{
  "recipient": "02abc...def",
  "messageBox": "inbox",
  "body": "hello"
}
```

Response: `{"status":"success","messageId":"7f..."}`

`messageId` is an opaque string. Newly generated IDs are 64 lowercase hex
characters, while messages received from older nodes can retain legacy IDs.
Never parse, sort, increment, or otherwise treat a message ID as a number.

The sender is the BRC-31-authenticated caller identity, or the node identity
when the operator-token fallback is used. Messages are forwarded across the
mesh via gossip. Each forward is signed by its origin node, which attests the
sender it authenticated (legacy forwards are signed by the sender), and is
verified before delivery. A mesh forward's non-empty
`OriginNode` must be a 66-character compressed secp256k1 public key. Unacknowledged
messages expire after 7 days.

### POST /listMessages

```json
{
  "recipient": "02abc...def",
  "messageBox": "inbox"
}
```

Response:

```json
{
  "status": "success",
  "messages": [{
    "messageId": "7f...",
    "sender": "02xyz...",
    "recipient": "02abc...def",
    "messageBox": "inbox",
    "body": "hello",
    "timestamp": 1712345678,
    "senderAttestedBy": "local"
  }]
}
```

Entries are returned in local arrival order. `senderAttestedBy` is one of
`"local"` (created by this node), an origin node's compressed public key (that
node attested the claimed sender after authenticating the submission),
`"sender"` (only this value means a legacy sender-signed forward), or
`"unknown"` (migrated legacy record). An origin-node attestation is not an
end-to-end sender signature. An empty box returns `"messages":[]`.

A positive `limit` is capped at 100. When `limit` is omitted, `null`, or zero,
one call returns at most 10,000 messages. Treating zero as omitted is a deliberate
back-compat divergence: the canonical server rejects zero. Every call, with or without `limit`,
returns at most 32 MiB of total body bytes, so a page can hold fewer messages
than `limit` (at least one message is returned when the box is non-empty).
Acknowledge the returned IDs and list again to drain any remainder.

For BRC-31 callers the recipient is always the caller's identity. With the
operator token, an omitted recipient defaults to the node identity. On a node
without an identity key, operator-token list and acknowledge requests must name
the recipient explicitly; otherwise they return `400 ERR_INVALID_RECIPIENT_KEY`.

### POST /acknowledgeMessage

```json
{
  "recipient": "02abc...def",
  "messageIds": ["42", "43"]
}
```

Response: `{"status": "success", "acknowledged": 2}`

Each ID must be 1–256 bytes and not whitespace-only. Duplicate IDs are
acknowledged once. If none of the valid IDs match stored messages, the
idempotent response remains HTTP 200 with `"acknowledged":0` (an intentional
divergence from the canonical server).

### Message validation, quotas, and errors

- `recipient` must be a valid 33-byte compressed secp256k1 public key encoded
  as 66 hex characters.
- `messageBox` is required and is 1–128 bytes; bytes below `0x20` and byte
  `0x7f` are rejected. Message bodies are required and are limited to 1 MiB.
- An acknowledgement accepts at most 1,000 message ID strings, each 1–256
  bytes. A list `limit` must be a non-negative integer and is capped at 100.
- Per sender/recipient storage defaults to 1,000 messages and 64 MiB. The
  node-wide defaults are 1,000,000 messages and 2 GiB. Per-inbox limits are
  disabled by default.

Validation, quota, rate-limit, and internal failures use this shape:

```json
{"status":"error","code":"ERR_...","description":"...","error":"..."}
```

Malformed JSON request bodies and authentication failures retain the simpler
`{"error":"..."}` shape.

| HTTP | Code | Meaning |
|------|------|---------|
| 400 | `ERR_INVALID_RECIPIENT_KEY` | Recipient is not a compressed secp256k1 key |
| 400 | `ERR_INVALID_MESSAGEBOX` | Message box is empty or contains a forbidden control byte |
| 400 | `ERR_MESSAGE_ID_REQUIRED` | `messageIds` is missing, null, or an empty array |
| 400 | `ERR_INVALID_MESSAGE_ID` | `messageIds` has the wrong type, or an ID is empty, whitespace-only, or exceeds 256 bytes |
| 400 | `ERR_MESSAGEBOX_TOO_LARGE` | Message box exceeds 128 bytes |
| 429 | `ERR_SENDER_QUOTA_EXCEEDED` | Sender/recipient pair quota is full |
| 429 | `ERR_INBOX_QUOTA_EXCEEDED` | Configured recipient inbox quota is full |
| 429 | `ERR_NODE_STORE_FULL` | Node-wide message store quota is full |
| 429 | `ERR_RATE_LIMITED` | Messagebox request or live-stream cap exceeded |
| 500 | `ERR_INTERNAL` | Internal messagebox operation failure; description and error are generic |

Every messagebox route, including the BRC-31 handshake and SSE endpoint, has a
separate per-client token bucket: 20 requests/second with a burst of 40. A
limited request includes `Retry-After: 1`. Live SSE streams are additionally
limited to 64 per client key, 16 per authenticated identity, and 10,000 across
the node. IPv6 clients share a client key by `/64`.

## Proof and Content Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/tx/{txid}/beef` | GET | No | BEEF proof for a transaction. `Accept: application/octet-stream` returns raw bytes. |
| `/headers/tip` | GET | No | Current BSV header-chain tip: `{height, hash}` |
| `/headers/range` | GET | No | N consecutive raw 80-byte block headers. Query: `from`, `count` (1..50). JSON default; `Accept: application/octet-stream` returns `count × 80` raw bytes. Used by SPV proof-builders. |
| `/getPresentHeight` | GET | No | Chaintracks-compatible current header height |
| `/findHeaderHexForHeight?height=N` | GET | No | Chaintracks-compatible parsed header lookup by height |
| `/findHeaderHexForBlockHash?hash=H` | GET | No | Chaintracks-compatible parsed header lookup by display-order block hash |
| `/content/{txid}_{vout}` | GET | No | Raw content from a transaction output |

For back-compatibility, a miss from `/findHeaderHexForHeight` retains its
existing response shape, unlike the canonical-shaped miss from
`/findHeaderHexForBlockHash`.

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

The request body is a BEEF (raw bytes, or `{"beef":"<hex>"}` with a JSON
content-type) — the SPV contract carries the proof with the transaction.
Query `?arc=true` to forward to miners after BEEF validation; Anvil hands
ARC the transaction in extended format (BIP-239) so a 0-conf ancestor
doesn't draw a "460 Missing input scripts". ARC transport failures set
`arc.submitted = false` and surface the error in `arc.error`; consumers
should retry via another upstream (status will be `"validated-only"`, not
`"queued"`).

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

Binary responses (on `Accept: application/octet-stream`) surface the same
value via the `X-BEEF-Source` header. Both JSON and binary responses include
`X-BEEF-Subject-Proven: true|false`; it reports whether the requested subject
transaction itself has a Merkle path, rather than only an ancestor having one.
Both headers are exposed to browser JavaScript by CORS. Wallets doing
multi-source BEEF chains should prefer `"cached"` from Anvil and fall back to a
direct upstream for `"arc"`/`"woc"` (passthrough).

On a cache miss, Anvil accepts a fetched BEEF only when its subject transaction
ID matches the requested txid and it passes local validation. When a cached
subject is still unproven, Anvil periodically attempts to refresh it. The cache
is upgraded only by a matching, subject-proven, locally SPV-verified BEEF. A
failed, mismatched, invalid, or slow refresh leaves the cached copy untouched
and serves that copy; if the refresh takes more than three seconds, it may
finish and populate the cache after the current response has returned.

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

SSE push for new BRC-33 messages. EventSource cannot perform BRC-31 or set
custom headers, so first mint an identity-scoped token with authenticated
`POST /messages/session`, then pass it via `?token=`. The operator token is
also accepted as a broad fallback:

```js
const url = `http://localhost:9333/messages/subscribe?messageBox=avos.offer&token=${token}`;
const source = new EventSource(url);
source.onmessage = (e) => console.log(JSON.parse(e.data));
```

Each message arrives as a `data:` event with a monotonic `id:` field.
SSE pushes are asynchronous and best-effort; under overload, a push can be
dropped. `POST /listMessages` is authoritative. On reconnect, use
`Last-Event-ID` + `POST /listMessages` to backfill.

## v3.4 messaging configuration

The v3.4 API limiter keys default as follows; non-positive values fall back to
these defaults. With `trust_proxy = true`, `trust_proxy_hops` selects the
forwarded-for entry that many hops from the right.

```toml
[api]
trust_proxy_hops = 1
messagebox_rate_limit = 20
messagebox_rate_burst = 40
```

Message storage defaults apply on upgrade without a config edit. Byte quotas
count message body bytes. The pair and node limits cannot be disabled: a value
less than or equal to zero uses the default. Inbox limits use zero to disable
that dimension.

```toml
[messaging]
ttl_seconds = 604800
max_pair_messages = 1000
max_pair_bytes = 67108864
max_store_messages = 1000000
max_store_bytes = 2147483648
max_inbox_messages = 0
max_inbox_bytes = 0
```

## Authentication

Transport auth for publishing data:

1. **Bearer token** — operator auth, derived from WIF: `Authorization: Bearer <token>`
2. **x402 payment** — anyone can publish/query by paying the node's price

Every published envelope is also signed by the app's BSV key. The signature
proves authorship, but it does not replace bearer auth or x402 payment for
data write endpoints. Messagebox authentication is described above and does
not use x402.

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
sudo anvil info             # identity and funding address; operator token is redacted
sudo anvil info -show-secrets # include the full operator token
sudo anvil doctor           # validate config, connectivity, mesh health
sudo anvil token            # print the full operator token directly
curl -s localhost:9333/status   # node status
sudo journalctl -u anvil-a -f  # live logs
sudo systemctl restart anvil-a  # restart
```
