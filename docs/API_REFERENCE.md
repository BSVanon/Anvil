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
| 400 | `ERR_MESSAGEBOX_TOO_LARGE` | Message box exceeds 128 bytes |
| 400 | `ERR_INVALID_MESSAGE_BODY` | Message body is invalid or missing |
| 413 | `ERR_MESSAGE_BODY_TOO_LARGE` | Message body exceeds 1,048,576 bytes |
| 400 | `ERR_INVALID_LIMIT` | `limit` is not a non-negative integer |
| 400 | `ERR_MESSAGE_ID_REQUIRED` | `messageIds` is missing, null, or an empty array |
| 400 | `ERR_INVALID_MESSAGE_ID` | `messageIds` has the wrong type, or an ID is empty, whitespace-only, or exceeds 256 bytes |
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

## Authentication and payment

Two distinct mechanisms gate write/query access, and they are not
interchangeable:

1. **Bearer token** — operator authentication, derived from WIF:
   `Authorization: Bearer <token>` (or `X-Anvil-Auth: <token>`). This is the
   only credential that identifies a caller as this node's operator.
2. **x402 payment** — a per-request toll, not authentication. Anyone can
   publish/query by paying the node's price. Paying never identifies the
   caller as the operator.

Only the operator's bearer token unlocks a `private` envelope (one marked
`"private": true`) or its metadata — on `GET /data`, on the SSE
subscription below, and on every discovery/metadata endpoint. A verified
x402 payment never unlocks one, by itself.

Every published envelope is also signed by the app's BSV key. The signature
proves authorship, but it does not replace bearer auth or x402 payment for
data write endpoints. Messagebox authentication is described above and does
not use x402.

Get your auth token:
```bash
sudo anvil token
```

### Paying a request

A priced request without payment answers 402 with an `X402-Challenge`
header. There are three ways to pay:

- **BRC-121** (`x-bsv-*` headers): any BRC-42 wallet pays the node's own
  price to a one-time key. This is how clients pay the node; see
  [Paying the node's price with BRC-121](#paying-the-nodes-price-with-brc-121).
- **`X402-Proof`** (bound to the challenge), for the node's own use: build a
  transaction that spends the challenge's nonce output and pays every payee
  the challenge names, then repeat the request with the proof in
  `X402-Proof`. One challenge pays for one request. Known limit: an external
  client cannot complete an `X402-Proof` on a production node, because the
  challenge's nonce output is locked to a key the node derives for itself,
  and the proof must spend it. Clients pay the node's price with BRC-121.
- **`X-Bsv-Payment`** (direct, no challenge), unchanged: it pays app prices
  (passthrough envelopes, a split envelope's app share) and serves x402
  clients. Send an Extended Format
  (BRC-30) transaction, as hex or base64, that pays the payees. Each input
  must carry the output it spends, so a plain raw transaction is refused, and
  Atomic BEEF is not parsed. The node checks every input's signature against
  the output it carries before it broadcasts the payment, and verifies at
  most 10 inputs: a transaction with none, with more than 10, or with an
  input that carries no output or no unlocking script is refused with 402
  and code `ERR_DIRECT_PAYMENT_UNVERIFIABLE`. A header that holds no transaction the
  node parses, Atomic BEEF included, is refused with 402 and code
  `ERR_PAYMENT_MALFORMED`.

**Direct payments need ARC.** The node broadcasts a direct payment and
accepts it only when ARC reports that the network accepted it:
`SEEN_ON_NETWORK` or `MINED`. Any other status, including
`SEEN_IN_ORPHAN_MEMPOOL`, is refused with 402 and code
`ERR_PAYMENT_NOT_ACCEPTED`; the network may still accept the transaction, so
retry the same transaction shortly rather than pay with a new one. A node
with no ARC client refuses every `X-Bsv-Payment` with 402 and code
`ERR_DIRECT_PAYMENT_UNAVAILABLE`. Such a node cannot take a payment from a
client. An `X402-Proof` whose challenge sets `require_mempool_accept` (the
operator's `require_mempool` setting, off by default) is held to the same
two statuses. A node with that setting and no ARC client cannot check them,
so it refuses every such proof with 402 and code
`ERR_MEMPOOL_CHECK_UNAVAILABLE`.

**One transaction pays for one request, on either path.** The node
remembers the txid of every payment it accepts, by `X402-Proof` or by
`X-Bsv-Payment`, in one set, for 24 hours and up to 100,000 txids. It
refuses a transaction already used on either path with 402 and code
`ERR_PAYMENT_REPLAYED`, so a transaction that answered a challenge cannot
pay again as a direct payment, or the other way round. It also refuses,
with code `ERR_PAYMENT_TOO_OLD`, a direct payment that ARC reports as mined
more than 144 blocks below the node's header tip, or mined with no block
height, or when the node has no header tip. A direct payment ARC reports as
mined more than 2 blocks above the node's header tip is refused with code
`ERR_PAYMENT_HEADERS_BEHIND`: the node's headers are behind, so it cannot
confirm how deep the payment is. A lag of 1 or 2 blocks passes, and the same
transaction can be retried once the headers catch up.

Known limits of the txid memory: it forgets a txid after 24 hours, when it
is full (the oldest first, to make room for the newest), and on a restart.
Each time it forgets a transaction, that transaction can pay once more as a
direct payment while it is still unmined, or mined at most 144 blocks deep.
A client that keeps the memory full, by cycling more than 100,000 paid
transactions through it, can therefore reuse each of them again and again;
but none pays as a direct payment once it is mined more than 144 blocks
deep. A transaction that stays unmined has no such bound.

Known limit: a direct payment is not bound to the request it pays for, so
it pays for whoever presents it first. Someone who sees a payer's
transaction, for example while the payer waits to retry it after
`ERR_PAYMENT_NOT_ACCEPTED`, can present it first, and the payer's retry then
gets `ERR_PAYMENT_REPLAYED`. In the same way, any unused transaction that
pays the node's payee script at least the price, unmined or mined at most
144 blocks deep, buys one request for whoever presents it.

**Direct-payment broadcasts are bounded.** The node waits at most 10
seconds for ARC to answer a direct payment's broadcast, and no longer than
the request itself lasts; a broadcast cut off this way refuses the payment,
and the same transaction can be sent again. At most 16 direct payments are
broadcast at once, node-wide. One more is answered 503 with code
`ERR_DIRECT_PAYMENT_BUSY` and a `Retry-After`, without being broadcast, and
the same transaction can be sent again.

**Request bodies on priced routes are read under bounds.** The node reads
a priced request's body before it checks the payment: at most 1 MiB, which
must start within 2 seconds and then arrive at 16 KiB a second or faster on
average. A body over the cap gets 413, and one too slow gets 408. The node
reads at most 32 such bodies at once; a body that finds none of those reads
free within 2 seconds gets 503. One client, counted as the rate limiter
counts it (with the same `trust_proxy` settings), may have at most 4 of its
bodies being read at once; one more is answered 503 with code
`ERR_PAYMENT_BODY_SHARE` and a `Retry-After`.

A refused payment answers 402, except where this section names 503. When
the refusal has a stable code, the body is
`{"status":"error","code":"ERR_...","description":"...","error":"..."}`.

### Paying the node's price with BRC-121

BRC-121 (Simple 402 Payments) lets any BRC-42 wallet pay the node's own
price. It pays only the node: checking or spending a payment to a derived
key takes the recipient's private key, so the node cannot take one for an
app, and it holds no app's money. App prices, both shares of a split
envelope included, are paid with `X-Bsv-Payment`.

**When the node offers it.** A 402 carries `x-bsv-sats` (the node's price
for the route) and `x-bsv-server` (the node wallet's identity key) only when
all of these hold:

- the node runs its wallet and has an ARC client;
- the request is not token-gated;
- every payee of the challenge is the node itself, at the node's own payee
  script;
- the node's price for the route is above 0.

Both headers are exposed to browsers (`Access-Control-Expose-Headers`), and
the five request headers are allowed by CORS. A route the node does not
price never makes an offer, and there the `x-bsv-*` request headers are
ignored: nothing is checked, broadcast or recorded. A node without its
wallet or ARC makes no offer either, and ignores the headers: the request
gets the plain x402 challenge.

Divergence from BRC-121: the 402 body is the x402 challenge JSON, as on
every other 402. BRC-121 asks for an empty body; its reference client reads
only the two headers.

**The paid request** repeats the request with five headers: `x-bsv-beef`
(the payment as a base64 Atomic BEEF, BRC-95), `x-bsv-sender` (the payer's
identity key), `x-bsv-nonce` (the base64 derivation prefix), `x-bsv-time`
(Unix milliseconds, as a decimal string) and `x-bsv-vout` (the payment
output's index). A request that also carries `X-Bsv-Payment` or `X402-Proof`
is answered 400 with code `ERR_BRC121_MIXED_METHODS`: pay by one method.

**The checks, in order.** Nothing is broadcast or stored before check 4
shows that the payment pays this node.

1. All five headers, in the shapes and lengths the reference middleware
   checks: a compressed public key, a canonical base64 nonce of at most 512
   characters, and unsigned integers for the time and the output index;
   `x-bsv-beef` within the 256 KiB payment header cap.
   `ERR_BRC121_MALFORMED`.
2. `x-bsv-time` within 30 seconds of the node's clock, either way.
   `ERR_BRC121_STALE`. Keep the node's clock synced (NTP): a clock that is
   off refuses honest payers.
3. An Atomic BEEF whose subject transaction is held in full. Only the
   subject and the ancestry its verification reads are kept, and unrelated
   entries are dropped. The payment may have at most 10 inputs, each backed
   by its source transaction. `ERR_BRC121_BAD_BEEF`. Output `x-bsv-vout`
   must exist and pay at least the price. `ERR_BRC121_UNDERPAID`.
4. The output is P2PKH to the key the node wallet derives for itself from
   the sender, the nonce and the time: BRC-29's protocol `3241645161d8`, key
   ID `<nonce> <base64(time)>`, invoice number
   `2-3241645161d8-<nonce> <base64(time)>`. `ERR_BRC121_WRONG_KEY`.
5. Every input's signature, checked against the output it spends, and the
   BEEF's merkle proofs, checked against the node's headers. A BEEF with no
   proof at all is refused, since the wallet could never record it.
   `ERR_BRC121_UNVERIFIABLE`.
6. The transaction has not paid before. The node checks its replay memory,
   which the other two payment paths share, then the node wallet's own
   record, which survives restarts. `ERR_BRC121_REPLAYED`.
7. ARC accepts it, under the same rules as a direct payment: `SEEN_ON_NETWORK`
   or `MINED`, the same depth bounds, the 10-second wait and the 16
   broadcasts at once. `ERR_BRC121_NOT_ACCEPTED`, or `ERR_BRC121_BUSY` (503
   with `Retry-After`).
8. The node wallet records it as a wallet payment, with fixed text that
   carries nothing from the request. `ERR_BRC121_NOT_ACCEPTED` if that
   fails.

A node wallet that cannot derive the key or read its own records answers
500 with `ERR_BRC121_WALLET_UNAVAILABLE`. One client, counted as the rate
limiter counts it, may have at most 4 BRC-121 payments in validation at
once; one more is answered 503 with `ERR_BRC121_BUSY` and a `Retry-After`.

Every other refusal answers 402 with the coded body. It repeats the offer
headers when the request's challenge would carry them. Divergence from
BRC-121, which answers 402 to every failed validation: when the node is busy
it answers 503 with a `Retry-After`, because the same payment can be sent
again shortly.

**What it unlocks.** An accepted payment is node coverage of what its output
paid, and nothing else. It unlocks unmonetized and `free`-model envelopes.
It covers a split envelope's node share but never its app share, and a
request pays by one method, so a split envelope stays redacted for a
BRC-121 payer: it is unlocked by an `X-Bsv-Payment` that pays both shares.
A BRC-121 payment never covers a passthrough envelope, never unlocks a
token-model envelope, and never unlocks a `private` envelope. As on the other paths, a price is paid per request. The node's
answer carries an `X402-Receipt`, as on the other paths.

**Unclaimed payments.** The payer's wallet broadcasts the payment before it
sends the request. So the node keeps every payment that passed checks 1 to
5 but was not recorded: ARC was busy, timed out, could not be reached, was
still processing it or reported it deeper than the bound, or the wallet
failed. It keeps them in a journal under `data_dir` (`brc121-journal`): at
most 4096 payments, each for at most 7 days.

Every 2 minutes, each payment kept for at least a minute is sent to ARC
again:

- **Accepted or mined:** it is recorded in the wallet.
- **Refused outright:** it is dropped. That is the status `REJECTED`,
  `DOUBLE_SPEND_ATTEMPTED`, `SEEN_IN_ORPHAN_MEMPOOL`, `INVALID` or
  `MALFORMED`, or HTTP 461 to 466 or 471 to 474.
- **Anything else:** it is kept for the next sweep.

A payment ARC refuses outright at request time is never kept. A request
whose payment was kept is not served: its payment is recorded later.
`anvil doctor` shows the journal's size and its oldest entry, and fails when
the journal is full. The operator's `/stats` view counts offers,
acceptances, refusals by code, kept, claimed and dropped payments.

**What the node wallet stores.** Spending a BRC-121 payment takes the
payer's identity key, so the wallet stores that key with the payment,
together with the nonce and the time. It stores no request path, address or
other request data.

**Proxies must allow long header lines.** A typical payment, with one input
and a mined parent, is about 1.3 KB of base64 in `x-bsv-beef`. A payment
with several inputs, unconfirmed parents or large parents is many times
that. Nginx's default `large_client_header_buffers 4 8k` refuses a header
line over 8 KiB with 400. In the server block that proxies to the node,
match the node's own cap:

```nginx
large_client_header_buffers 4 256k;
```

### What a payment or app token unlocks

Every envelope's payload is unlocked envelope by envelope, by that
envelope's own rules, on `GET /data` and on the SSE subscription alike. Where
the node charges for the route (`GET /data` or `GET /data/subscribe`), the
node's own price is one of those rules, decided for each envelope like an
app's:

- An unmonetized or `free`-model envelope is unlocked by a payment with one
  output that pays the node's own payee script at least the node's price for
  the route. A node that charges nothing there serves it unpaid.
- A split envelope needs both shares: one output that pays its own payee
  script at least its price, capped at the node's `max_app_price_sats`, and
  one that pays the node's script at least the node's price.
- A passthrough envelope needs only one output that pays its own payee script
  at least its capped price. Passthrough is the operator's choice to let that
  app's envelope take the node's price; it never extends to other envelopes on
  the topic.
- A token-model envelope is unlocked only by an `X-App-Token` validated on
  its exact topic and signed by the `auth_pubkey` that envelope names. A
  payment never unlocks one.

A BRC-121 payment (above) counts as a payment to the node's own script of
what its output paid. It never pays an app, so it never covers a
passthrough envelope or a split envelope's app share.

A price is paid per request, not per envelope: one output of at least a
price, to a payee, covers every envelope in the response that asks that
payee that price or less. One output of 100 sats to the node's script
unlocks every node-priced envelope in the response when the node's price is
100. The node never adds outputs together: two outputs of 60 to one payee do
not cover a price of 100.

Known limit: the newest public envelope on a topic prices the request, so its
rule sets the 402 challenge and the token requirement for the whole topic. A
newer envelope, one with a far-future timestamp included, can therefore hide
the topic's older envelopes: while it is the newest, honest token holders and
payers may be refused (401 or 403), or asked to pay only its payee, and every
older envelope that payment does not cover stays redacted. A request the
token rule admits free carries no payment, so it cannot unlock node-priced
envelopes either. What a newer envelope can no longer do is unlock an older
one, or take or waive the node's price for it: each older envelope is still
decided by its own rules. Closing the hiding needs topic ownership and a
bound on future timestamps.

### Topics are exact

`GET /data?topic=X` returns only topic `X`; durable topics used to match
`X:*` too. The other reads that name a topic are exact in the same way:
`GET /topics/{topic}`, `GET /identity/{pubkey}` (topic `identity:<pubkey>`),
`/app/{name}` and `/explorer` (topic `anvil:catalog`) and `/mesh/nodes`
(topic `mesh:heartbeat`). The SSE subscription was always exact. Mesh peers
still subscribe to each other by topic prefix.

## Real-time Subscription (SSE)

Subscribe to new envelopes on a topic via Server-Sent Events:

```bash
curl -N "http://localhost:9333/data/subscribe?topic=oracle:rates:bsv"
```

Each new envelope is pushed as a `data:` event with a monotonic `id:` field.
A payload is redacted unless the client's payment or app token covers that
envelope by its own rules, the node's price included, the same as `GET /data`
(see "What a payment or app token unlocks" above). The subscribe request's
payment, token and node price hold for the life of the stream. A `private`
envelope is never streamed to a client without the operator's bearer token —
a payment never unlocks one here either.

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
