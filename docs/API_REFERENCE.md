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
| `/messages/subscribe` | GET | Session ticket, or operator token in a header | SSE stream of new BRC-33 messages in real time |
| `/mesh/status` | GET | No | Rate-limited health snapshot; up to 1,000 newest topics, `upstream_status`, and peer-exchange state |
| `/mesh/nodes` | GET | No | Rate-limited federation directory; up to 500 nodes with up to 100 topics each |

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

Certificate admission is optional. `[messaging] require_sender_certificate`
gates message sends, `[gateway] allow_registration` mounts the gateway
registration routes described below, and private-home writes use the same gate.
Enabling any of those uses makes the node ask
every BRC-31 client for a certificate during the one shared handshake for this
host. The request applies to `/sendMessage`, `/listMessages`,
`/acknowledgeMessage`, `/messages/session`, `/messages/home`, and the two registration endpoints.
A client that does not present an accepted certificate is not BRC-31
authenticated on that node, so it cannot use any of those routes as an identity
or mint a ticket for `/messages/subscribe`. The operator-token fallbacks remain
available where the endpoint table says so. An authenticated sender without a
current admission receives `403 ERR_SENDER_CERTIFICATE_REQUIRED` from
`/sendMessage`.

TypeScript `@bsv/sdk` clients can present certificates during this handshake.
Clients built on Go SDK v1.7.8 can't complete it over HTTP: the node answers the
client's certificate response with an empty body, and that client's HTTP
transport treats an empty handshake reply as an error. That client also sends no
matching certificate when the requested field list is empty. Use `@bsv/sdk`
clients with a node that has either switch on.

`[certgate]` supplies the accepted compressed certifier keys and Base64
certificate type IDs, per-type revealed fields, whether an unrevocable type is
allowed, and the revocation policy. The default policy is `strict` with a
one-hour recheck. Revocable certificates are watched by their revocation
outpoint; spending it removes the admission and any gateway registrations owned
by that identity. An admission backing a live private-home claim is pinned until
that claim is released, revoked, expired, or rebound. If private homes and
certgate are both enabled, `private_home_max_members` cannot exceed the 10,000
outpoint spend-watch cap.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/sendMessage` | POST | BRC-31 or operator token | Send a message to a recipient by pubkey |
| `/listMessages` | POST | BRC-31 or operator token | Retrieve messages for a recipient's message box |
| `/acknowledgeMessage` | POST | BRC-31 or operator token | Delete messages after receipt |
| `/messages/session` | POST | BRC-31 | Mint a five-minute, identity-scoped SSE token |
| `/messages/subscribe` | GET | Session ticket or operator header | Stream newly arrived messages for one message box |
| `/messages/home` | POST | BRC-31 only | Create, renew, move, or release the caller's private homes |
| `/messages/home` | GET | BRC-31 only | Read the caller's own current private-home claim |

### Gateway registration endpoints

When `[gateway] enabled = true` and `allow_registration = true`, the shared
BRC-31 surface also mounts `POST /gateway/sites` with `{"domain":"name"}` and
`DELETE /gateway/sites/{domain}`. Both require a current certificate admission.
Registrations are stored in `<data_dir>/gateway-registrations.conf`; the daemon
never edits the operator `sites_file`. The live gateway allowlist merges both
files, but the domain's `_ordfs` TXT record still determines the origin that is
served.

An identity may own 10 registrations, with 1,000 total. A caller can delete
only its own registrations. Domains in the operator file cannot be registered
or deleted through these endpoints and return HTTP 409 with
`ERR_OPERATOR_DOMAIN`. Certificate revocation removes only that identity's
registrations. `anvil gateway sites list` marks registered entries, and
`anvil gateway sites remove <domain>` can remove either kind. The singular
`site` command remains accepted for compatibility.

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

### GET and POST /messages/home

These routes exist only when `[messaging] private_homes = true`. Private homes
are an Anvil extension for closed networks, not canonical BRC-33. POST accepts
`{"claim": RECORD}` with a maximum 16 KiB body. It requires BRC-31 mutual
authentication as the same identity named by `record.member`; the operator
token is never accepted. GET returns only that authenticated caller's current
claim and never accepts a recipient override. In the route classification,
`/messages/home`, `GET /messages/home`, and `POST /messages/home` are all
identity-authenticated, messagebox-rate-limited, bounded-body routes, like the
other BRC-31 messagebox endpoints.

A claim response is
`{"status":"success","homes":[...],"expiresAt":N}`. A release response is
`{"status":"success","released":true}`. GET returns
`{"status":"success","claim":RECORD}` or `404 ERR_NO_CLAIM`. When certgate
is configured, POST also requires a current admission and otherwise returns
`403 ERR_CERTIFICATE_REQUIRED`. If its revocation watch cannot be retained,
POST stores no claim and returns `503 ERR_CERTIFICATE_WATCH_UNAVAILABLE`. A connected named gateway that has not
negotiated private-home support causes `409 ERR_HOME_INCOMPATIBLE`; disconnected
homes are checked on reconnect and are not selected until they acknowledge the
claim version.

`private_homes` requires a non-empty `[mesh] allowed_peers`. The defaults are
`private_home_max_members = 10000` (valid range 1–1,000,000, or at most 10,000
when certgate is configured) and
`private_home_max_ttl = 2592000` seconds (valid range 3,600–7,776,000). Claims,
releases, revocations, acknowledgements, and capability status travel only over
an allowed identity's retained, admitted primary mesh socket. Pending or
unbound sockets, duplicate losers, and rejected sockets cannot dispatch these
frames. Peer exchange may discover an allowed identity's address, but its
heartbeat and candidate state never contain private-home records and do not
bypass admission, capability negotiation, or per-claim acknowledgement. A
relay-only send with no ready target returns `503 ERR_MESSAGE_UNDELIVERED`.
Trusted revocation cutoffs are stored separately from live claims and are
accepted even when the live registry is full. The cutoff store has the same
configured member cap; while it is full, new claims are refused fail closed.

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
| 400 | `ERR_INVALID_CLAIM` | Private-home record shape, bounds, policy, expiry, or signature is invalid |
| 403 | `ERR_CLAIM_MEMBER_MISMATCH` | Authenticated identity differs from `claim.member` |
| 403 | `ERR_CLAIM_LIMIT` | The live member cap is full, or the cutoff store is full and new claims are fail-closed |
| 403 | `ERR_CERTIFICATE_REQUIRED` | A private-home write lacks a current certgate admission |
| 404 | `ERR_NO_CLAIM` | The caller has no current, unexpired private-home claim |
| 409 | `ERR_CLAIM_STALE` | `issuedAt` is not newer than the stored claim or release |
| 409 | `ERR_HOME_INCOMPATIBLE` | A connected named gateway has not negotiated private-home support |
| 503 | `ERR_CERTIFICATE_WATCH_UNAVAILABLE` | A private-home claim's certificate revocation watch cannot be retained |
| 500 | `ERR_CLAIM_STORE` | Private-home persistence failed |
| 429 | `ERR_SENDER_QUOTA_EXCEEDED` | Sender/recipient pair quota is full |
| 429 | `ERR_INBOX_QUOTA_EXCEEDED` | Configured recipient inbox quota is full |
| 429 | `ERR_NODE_STORE_FULL` | Node-wide message store quota is full |
| 429 | `ERR_RATE_LIMITED` | Messagebox request or live-stream cap exceeded |
| 503 | `ERR_MESSAGE_UNDELIVERED` | A send landed nowhere: not stored at this node, and not forwarded to any peer |
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
| `/content/{origin}?seq=N` | GET | No | Tracked origin spend sequence (`0` origin, every later location including plain transfers, `-1` current location) |
| `/content/{outpoint}:N` | GET | No | Tracked spend sequence relative to the outpoint in the path |

For a sequence location without an inscription, the response body is the most
recent inscription at or before that location. `X-Outpoint` still names the
sequence location. The `:N` path form and its relative numbering follow
ORDFS; the query form remains supported. For an origin outpoint, `:N` and
`?seq=N` resolve identically.

`seq=-1` sends `Cache-Control: no-store`. An explicit sequence sends
`public, max-age=31536000, immutable` only when its location is mined and has
at least six confirmations on this node's best chain. Pending, shallow, or
not-provably-deep locations use the configured short max-age. This is a safety
divergence from ORDFS's all-explicit-sequences policy: a shallow mapping can
still be rolled back by a reorganization.

Every sequence response sends `X-Ord-Seq`, counted from the tracked origin,
including when the path starts at a later outpoint.

The ordinary `/content` route keeps its content cache policy when no read-token
gate applies. When a read-token gate is configured for the request, the answer
is credential-dependent and uses `Cache-Control: private, no-store`.

Every raw transaction fetched to serve `/content` is decoded and its bytes are
hashed before use. A transaction whose computed txid does not match the
requested txid is rejected.

For back-compatibility, a miss from `/findHeaderHexForHeight` retains its
existing response shape, unlike the canonical-shaped miss from
`/findHeaderHexForBlockHash`.

### Chaintracks v2

The public `/chaintracks/v2` route set provides `/network`, `/height`, `/tip`,
`/header/height/{height}`, `/header/hash/{hash}`, `/headers`, `/tip/stream`, and
`/reorg/stream`. Header and tip routes also have raw 80-byte `.bin` forms; the
range form is `/headers.bin?height=N&count=M`. Range requests are silently
truncated to the local tip and to 2,000 headers, returning HTTP 200 even when
the result is empty. The `.bin` range response reports the actual range in
`X-Start-Height` and `X-Header-Count`.

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
| `/lookup` | POST | No | Canonical lookup query |
| `/overlay/query` | POST | No | Legacy lookup query |
| `/overlay/lookup` | GET | No | SHIP peer discovery by topic |
| `/overlay/register` | POST | Bearer | Register a SHIP token |
| `/overlay/deregister` | POST | Bearer | Remove a SHIP peer |

### Lookup pages

`POST /lookup` and `POST /overlay/query` return up to 10,000 outputs and no
more than 8 MiB of encoded response data per page. A request without an
`X-Overlay-Cursor` header always receives the first page. Send the
`X-Overlay-Cursor` value from a truncated response to continue at the next
output.

`X-Overlay-Truncated: true` means another page is available. The accompanying
`X-Overlay-Cursor` response header is the offset for that next request.
`X-Overlay-Omitted` is the number of outputs skipped because one output could
not fit in the 8 MiB response allowance. It may be present with either a final
or a truncated page.

`POST /submit` also accepts a SHIP advertisement in the TypeScript off-chain
framing: with `x-includes-off-chain-values: true`, the body is a Bitcoin varint
containing the BEEF byte length, followed by that BEEF and the off-chain values.
The earlier Anvil ordering remains accepted for compatibility.

### UHRP advertisements

The `tm_uhrp` topic admits canonical BRC-26 PushDrop advertisements only after
checking the five content fields, signature and identity-key linkage, HTTPS
location, content hash, expiry, and size. `ls_uhrp` accepts `uhrpUrl` in the
forms `uhrp:<base58>`, `uhrp://<base58>`, `web+uhrp:<base58>`,
`web+uhrp://<base58>`, `//<base58>`, or bare Base58Check; scheme matching is
case-insensitive.

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

When inscription tracking is enabled, a verified spend of a currently tracked
tip can authorize its own broadcast without a bearer token or payment. The node
reserves the still-current tip, and checks the pending-link cap, before it
broadcasts. A failed broadcast releases the reservation; a successful one
records the link. `broadcast_tip_credential_used` counts only recorded links.

This free path accepts the token-forward output plus at most four other
outputs. Each non-token output locking script is limited to 200 bytes. The
token-forward output is not subject to that script limit because it carries the
new version's content. The normal paid and token paths retain their existing
transaction limits.

Tip-credential fall-through is not timing-padded. Response time can therefore
show whether an input names a tip tracked by this node. Tracked tips are also
announced publicly on the `ordtip:v1` gossip topic.

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
(CORS and rate-limited, no x402). Poll every 30–60 seconds.

```json
{
  "node": "anvil-prime",
  "version": "2.1.0",
  "headers": { "height": 944988, "work": "0x..." },
  "identity": "02...",
  "mesh": { "peers": 2, "peer_list": [...], "started_at": "...", "uptime_secs": 3600 },
  "peer_exchange": {
    "enabled": true,
    "advertised_url": "wss://anvil-prime.example/mesh",
    "advertise_state": "verified",
    "candidates": 12,
    "exchange_peers": 4
  },
  "activity": { "envelopes_received": 100, "envelopes_sent": 42 },
  "topics": [{ "topic": "oracle:rates", "count": 100, "age_secs": 30 }],
  "topics_total": 1,
  "topics_truncated": false,
  "overlay": { "ship_count": 7 },
  "upstream_status": {
    "broadcast": "healthy" | "degraded" | "down",
    "headers_sync_lag_secs": 12,
    "service_health": "healthy" | "degraded" | "broken"
  }
}
```

`topics` contains at most 1,000 public topics, ordered by `latest_at` newest
first and then topic name. `topics_total` is the number of public topics before
that cap, and `topics_truncated` reports whether the cap removed entries.

`peer_exchange.advertise_state` is `verified` for a derived address that passed
the self-handshake, `configured` for an explicit operator URL, `unverified`
while no derived candidate currently passes, `none` when no address can be
derived, or `off` when peer exchange is disabled. `candidates` is the bounded
signed-advertisement table size; `exchange_peers` counts only live connections
opened by peer exchange, not configured seeds or inbound connections.

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
without direct-polling every node. When peer exchange has a configured or
verified address, the payload also carries `"mesh_url": "wss://..."`. The
envelope signature authenticates that address to its publisher identity;
the field is omitted while advertising is off, unavailable, or unverified.
Private-home claims and acknowledgements are never included in this heartbeat
payload or in the peer-exchange status counters.

## Mesh nodes response shape

`GET /mesh/nodes` returns at most 500 nodes. `count` is the number returned,
`total` is the number before the cap, and `truncated` reports whether nodes
were omitted. Nodes remain ordered by source rank (self, direct peer,
heartbeat, overlay) and then name. Each node contains at most 100 topics. The
self node's topics are sorted by name; heartbeat topics keep their heartbeat
order. When a node's topics are capped, its optional `topics_total` gives the
number before that cap.

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
- **Payment readiness** — priced routes must appear in live x402 discovery;
  ARC must be enabled for BRC-121 and `X-Bsv-Payment`. The doctor reports the
  deprecated proof-only configuration separately and checks the BRC-121
  journal's size and oldest entry.
- **Gateway readiness** — mode and sites-file parsing, `_ordfs` TXT answers,
  listeners on ports 80 and 443, ACME terms, certificate cache state and
  permissions, closed-network peer settings, and replication connectivity.

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
- **`anvil upgrade` health-checks restarted units** at their configured
  `GET /status` endpoint and normally restores the previous binary after a
  failed check. Automatic rollback is suppressed once a migration starts. If
  the pre-start migration marker cannot be read, the units still start, but a
  later health failure also suppresses rollback because a startup migration
  cannot be ruled out.

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
`POST /messages/session`, then pass that scoped ticket via `?token=`. The
node-wide operator token is never accepted in a URL. Operator tooling must use
a streaming client that sends `X-Anvil-Auth` or `Authorization: Bearer`:

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

New gateway configs created with `anvil deploy --mode gateway` set
`[messaging] operator_reads_all_boxes = false`; existing configs keep their
configured value on upgrade.

## Authentication and payment

See [Authentication and payment](PAYMENTS.md) for bearer authentication, x402, BRC-121, direct payments, limits, and refusal handling.

## Private envelopes

Only this node's operator token, sent as `X-Anvil-Auth` or
`Authorization: Bearer`, can read a `private` envelope. A payment—including BRC-121,
`X-Bsv-Payment`, or the deprecated proof path—and an `X-App-Token` never unlock
one. Credential-dependent reads are uncacheable: they use `Cache-Control:
private, no-store` and vary on both operator-token headers.

Without the operator token, exact `/data` reads use the public-only index and
peer catch-up uses the public prefix index. Private envelopes are also omitted
from `/topics`, topic details and identity lookups, `/stats`, `/mesh/status`,
and `/mesh/nodes`; a topic containing only private envelopes is omitted from
public topic lists. Private-only topics are not announced as heartbeat topics
and do not contribute heartbeat demand.

On SSE routes the operator token is read from a header only, never from a URL
query parameter. `/data/subscribe` consequently omits private envelopes unless
its streaming client sends the operator header; `/messages/subscribe` uses its
identity-scoped session ticket or an operator header as described above.

## Real-time Subscription (SSE)

Subscribe to new envelopes on a topic via Server-Sent Events:

```bash
curl -N "http://localhost:9333/data/subscribe?topic=oracle:rates:bsv"
```

Each new envelope is pushed as a `data:` event with a monotonic `id:` field.
A payload is redacted unless the client's payment or app token covers that
envelope by its own rules, the node's price included, the same as `GET /data`
(see [Authentication and payment](PAYMENTS.md)). The subscribe request's
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

## Release response headers

These response headers are part of the public API contract:

| Header | Meaning |
|---|---|
| `X-Origin`, `X-Outpoint`, `X-Ord-Seq` | Origin, served location, and sequence position for versioned content. |
| `X-Overlay-Cursor`, `X-Overlay-Truncated`, `X-Overlay-Omitted` | Overlay lookup pagination and bounded-result metadata. |
| `X-Overlay-Gasp-Enabled`, `X-Overlay-Gasp-Initial-Sync-Done`, `X-Overlay-Gasp-Interval-Secs`, `X-Overlay-Gasp-Last-Sync-Unix` | Overlay federation readiness and last-sync state. |
| `X-BEEF-Source`, `X-BEEF-Subject-Proven` | Source and proof state of a returned BEEF. |
| `X-Block-Height`, `X-Start-Height`, `X-Header-Count` | Height and range metadata on binary header responses. |
| `x-bsv-sats`, `x-bsv-server`, `X402-Receipt` | Payment offer and receipt metadata. |
| `X-Accel-Buffering` | Set to `no` on SSE responses so reverse proxies stream immediately. |
| `X-Content-Type-Options` | Set to `nosniff` on gateway site responses. |

## Error code index

In addition to the payment and messagebox codes described at their endpoints,
clients may receive the following stable codes:

- Request parsing and validation: `ERR_BAD_CONTENT_TYPE`, `ERR_BAD_REQUEST`,
  `ERR_EMPTY_BODY`, `ERR_INVALID_PARAMS`, `ERR_INVALID_SENDER`,
  `ERR_INVALID_TRANSACTION`, `ERR_MALFORMED_SCRIPT`, `ERR_MISSING_TXID`,
  `ERR_READ_BODY`, `ERR_VALIDATION_BUDGET`, `ERR_BEEF_TOO_COMPLEX`.
- Topic and submission handling: `ERR_BAD_TOPICS`, `ERR_EMPTY_TOPICS`,
  `ERR_MISSING_TOPICS`, `ERR_UNKNOWN_TOPIC`, `ERR_SUBMIT_FAILED`,
  `ERR_ARC_INGEST_FAILED`.
- Authentication and certificates: `ERR_AUTH_FAILED`, `ERR_BRC31_REQUIRED`,
  `ERR_CERTIFICATE_REQUIRED`, `ERR_RESPONSE_SIGNING_FAILED`.
- Gateway registration: `ERR_INVALID_DOMAIN`, `ERR_DOMAIN_LIMIT`,
  `ERR_DOMAIN_REGISTERED`, `ERR_NOT_REGISTRATION_OWNER`,
  `ERR_REGISTRATION_NOT_FOUND`, `ERR_REGISTRATION_WRITE`, `ERR_SITE_LIMIT`.
- Payment state: `ERR_PAYMENT_HEADERS_BEHIND`, `ERR_REPLAYED_NONCE`.
