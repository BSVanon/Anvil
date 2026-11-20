# Operator Guide — Messaging Privacy

This explains what a node stores and relays for the BRC-31/33 point-to-point messaging
feature (`/sendMessage`, `/listMessages`, `/acknowledgeMessage`, `GET /messages/subscribe`),
who can see what, how long it's kept, and the `[messaging]` config keys that control all of
this.

## The three ways a node relates to a message's recipient

Every recipient identity key can advertise one or more hosts via a canonical `tm_messagebox`
record (BRC-33) — the same mechanism `ls_messagebox` answers lookups against. A node checks
the recipient's current adverts and classifies itself as exactly one of:

- **Home** — the recipient has advertised this node (one of this node's own hosts, see
  below) as a place to deliver its messages.
- **Elsewhere** — the recipient has advertised a host, but it isn't this node.
- **Unadvertised** — the recipient has no current, qualifying advert at all (including the
  case where this node doesn't host `tm_messagebox`/`ls_messagebox` itself).

"This node's own hosts" is `[node] public_url` plus any extra hosts listed in
`[messaging] home_hosts`. A recipient picks its home host the same way it picks any overlay
advert: it builds and broadcasts a `tm_messagebox` PushDrop output naming the host it wants
mail delivered to. Nothing about this is Anvil-specific — any canonical BRC-33 client can
anoint a host this way, and any canonical BRC-33 client can resolve it via `ls_messagebox`.

Only `https://` hosts count, and a handful of placeholder/loopback hosts never qualify as
anyone's home: `localhost`, `127.0.0.1`, `0.0.0.0`, `::1`, and anything ending in `.local`,
`.example.com`, `.test`, `.invalid`, or `.localhost`. An advert naming one of those is treated
the same as no advert at all.

## What gets stored, for how long, and whether it's relayed

| You received this message because of | Recipient's state | Stored? | Retention | Relayed onward? |
|---|---|---|---|---|
| A client called `/sendMessage` on this node | Home | yes | `ttl_seconds` | no — this node already is the destination |
| A client called `/sendMessage` on this node | Unadvertised | yes | `ttl_seconds` | yes, to connected mesh peers (unchanged from pre-privacy behavior) |
| A client called `/sendMessage` on this node | Elsewhere | only if `forward_copy_ttl > 0` | `forward_copy_ttl` | yes |
| A mesh peer forwarded it to this node | Home | yes | `ttl_seconds` | only if the recipient's adverts ALSO name a host other than this node |
| A mesh peer forwarded it to this node | Unadvertised or Elsewhere | only if `forward_copy_ttl > 0` | `forward_copy_ttl` | yes |

The practical read: a message only sits in long-term storage (`ttl_seconds`, 7 days by
default) on a node the recipient actually calls home. Every other node that merely sees the
message in transit keeps, at most, a short-lived forwarding copy and then relays it onward —
or, with `forward_copy_ttl = 0`, never stores a copy of it at all, just relays.

**Behavior change from earlier releases:** before this feature, a node relaying mail for a
recipient who wasn't its own identity kept a full `ttl_seconds` copy, same as a Home message.
Forwarded copies are now kept for `forward_copy_ttl` instead — 24 hours by default, down from
7 days. If you relied on the old 7-day retention for in-transit copies, set
`forward_copy_ttl` back up to (just under) your `ttl_seconds`.

A relay of a message this node has no fresh copy of to fall back on — the `forward_copy_ttl
= 0` case, and a stored node's quota-rejection fallback — still goes through the existing
mesh-wide relay budget, so an attacker can't use "never gets stored" traffic to flood a
node's outbound bandwidth for free. A Home recipient with no other advertised host is a
different case, not a budget one: such a message is never relayed at all, because there is
no other node for it to reach.

## What a relay actually sees

Regardless of whether a hop stores a copy, every hop a message passes through sees the
sender's and recipient's identity keys and the message's size and timing — that's inherent to
how the mesh routes mail to the right home node. What a relay does NOT get for free is the
message body: Anvil stores and forwards whatever bytes the client handed it, and never
inspects or requires a particular body format. If your client end-to-end encrypts the body
(most BRC-33 clients encrypt to the recipient's identity key before calling `/sendMessage`),
every hop other than the recipient only ever sees ciphertext. Anvil does not add this
encryption itself — it's a client-side choice, same as before this feature existed.

## Config reference

```toml
[messaging]
# ttl_seconds = 604800              # default 7 days — Home / direct-send retention
# forward_copy_ttl = 86400          # default 24h — forwarded/in-transit copy retention; 0 = never store, only relay
# home_hosts = ["https://my-anvil.example.org"]   # extra hosts this node is Home for, beyond [node] public_url
# forward_peers = ["<hex identity key>", ...]     # restrict forwarding to only these peers; unset = every connected peer
# operator_reads_all_boxes = true   # false restricts the operator API token to this node's own identity box
```

`forward_copy_ttl` is clamped below `ttl_seconds` if you set it equal or higher — a forwarded
copy should never outlive what a Home copy on the same node would.

### `forward_peers`: scoping who a message gets forwarded to

By default, a node forwards (and relays) mesh messages to every peer it's connected to, same
as before this feature. Setting `forward_peers` to a list of hex identity keys restricts
forwarding to only those peers — anyone else connected to this node still gossips normal mesh
traffic, but never receives a message forward or relay.

### `operator_reads_all_boxes`: scoping what the node operator's own API token can read

The REST API distinguishes a per-recipient *scoped* token (one issued for, and restricted to,
a single identity's inbox) from the node operator's own *unscoped* token. By default
(`operator_reads_all_boxes = true`), the operator token can list and acknowledge messages in
any recipient's box on this node — useful for running your own dashboard or support tooling
across every box the node is Home for. Setting this to `false` restricts the operator token
to this node's own identity box only; `/listMessages` or `/acknowledgeMessage` naming any
other recipient then returns `403 ERR_OPERATOR_BOX_RESTRICTED`. `/sendMessage` is unaffected
either way — sending was never gated by recipient identity, only reading and acknowledging
are. The same switch also gates the `recipient` override on `GET /messages/subscribe`.

### Running a closed messaging network

Combine three independent switches to run a mesh that only ever carries, stores, or relays
messages among a known set of peers, with no copy of in-transit traffic lingering anywhere
but the recipient's actual home node:

1. `[mesh] allowed_peers` — refuse any mesh connection whose authenticated identity isn't on
   the list, at the handshake, before any message is processed.
2. `[messaging] forward_peers` — restrict forwarding/relaying to that same (or a narrower)
   set of peers.
3. `[messaging] forward_copy_ttl = 0` — never keep a copy of a message this node is only
   relaying, only the Home copies it's actually the destination for.

With `forward_copy_ttl = 0`, a recipient needs a `tm_messagebox` advert naming one of the
closed network's nodes as their home, or nothing in the mesh ever stores their mail for
them. An Unadvertised recipient's message is still stored in full, at `ttl_seconds`, on
whichever node the `/sendMessage` call originated from (decision 3's Unadvertised row
always stores, independent of `forward_copy_ttl`) — but it goes no further than that one
node; it is never relayed-and-stored anywhere else. Advertise a home node for every
recipient who needs their mail to land somewhere they can reliably poll.

Every relay this mode performs is unstored — there is no local copy to fall back on if the
relay itself fails — so it draws from the same manager-wide budget every other unstored
relay shares: 10 messages/second with a burst of 50 (`internal/gossip/relay_budget.go`).
That is one allowance for the whole node, not per-sender or per-recipient; see "Known
limits" below.

## Known limits

- **A revoked advert can be replayed.** Nothing stops a third party from re-broadcasting an
  identity's own, previously-valid-but-now-revoked `tm_messagebox` advert transaction — the
  signature is still valid, and BRC-33 doesn't bind an advert to a one-time nonce. This is
  inherited from the canonical admission rules, not something Anvil's Home Rule introduces:
  under deterministic signing (RFC 6979), a genuine re-anointment of the same host is
  byte-identical to a replay of the old transaction, so there is no way to tell them apart.
  Because of this, Anvil never forwards on an API `/sendMessage` Home-row send — a Home
  recipient's message is only ever stored locally, never relayed — and canonical BRC-33
  clients already poll the union of every host ever seen advertised for an identity, not
  just the current one, so a Home delivery still reaches them even under a replay.
- **The non-Home relay budget (10 msg/s, burst 50) is one allowance for the whole node**,
  shared across every sender/recipient pair that needs an unstored relay. A node under heavy
  unstored-relay load from many different senders gets no bigger a budget than one being hit
  from a single source — there is no per-peer or per-recipient fairness within it.
- **A stored copy's expiry is fixed at write time.** Changing `ttl_seconds` or
  `forward_copy_ttl` in your config only affects messages stored after the change; a copy
  already on disk keeps counting down against whichever TTL was in force when it arrived.

## Defaults if you set nothing

Everything above behaves almost exactly as it did before this feature. The differences:

- **Any non-Home copy's retention drops from 7 days to 24 hours.** This covers both
  non-Home rows in the table above: a copy this node relays onward for an
  Unadvertised-or-Elsewhere recipient after receiving it from a peer, AND the origin's own
  copy when a client calls `/sendMessage` on THIS node for a recipient who resolves
  Elsewhere. That second case is not a "forward" in the receive sense, but it still uses
  `forward_copy_ttl`, not `ttl_seconds` — only a Home copy, on either path, keeps the full
  `ttl_seconds`.
- **Every node not running the closed-network `[overlay] named_peers` mode now mints its
  own `tm_messagebox`/`ls_messagebox` SHIP and SLAP adverts from its node wallet**, so other
  operators' nodes can discover that this node hosts messaging. If the wallet can't cover
  the cost (a few sats isn't enough), nothing crashes or retries in a tight loop: the node
  logs the shortfall clearly and tries again on its normal advertise interval (default 30
  minutes).
- **It also GASP-syncs `tm_messagebox` adverts from public overlays it discovers through
  SHIP**, when `[overlay] enable_gasp_sync` is on (the default) — so a node's own
  `ls_messagebox` index is not guaranteed to hold only locally-originated adverts, even on a
  node that never calls `/sendMessage` itself.

Otherwise every node remains reachable for every recipient by default — `forward_peers`
unset forwards to every peer, `operator_reads_all_boxes` defaults to `true` (this only ever
gates the node operator's own unscoped API token; it never restricts a recipient-scoped
token or `/sendMessage` itself), and a node with no `home_hosts` configured still becomes
Home for any recipient whose advert names its `[node] public_url`.
