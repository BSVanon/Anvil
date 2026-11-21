# Authentication and payment

Two distinct mechanisms gate write/query access, and they are not
interchangeable:

1. **Bearer token** — operator authentication, derived from WIF:
   `Authorization: Bearer <token>` (or `X-Anvil-Auth: <token>`). This is the
   only credential that identifies a caller as this node's operator.
2. **x402 payment** — a per-request toll, not authentication. Anyone can
   publish/query by paying the node's price. Paying never identifies the
   caller as the operator.

Only the operator's bearer token unlocks a `private` envelope (one marked
`"private": true`) or its metadata — on `GET /data`, on an SSE
subscription, and on every discovery/metadata endpoint. A verified
x402 payment never unlocks one, by itself.

Every published envelope is also signed by the app's BSV key. The signature
proves authorship, but it does not replace bearer auth or x402 payment for
data write endpoints. [Messagebox authentication](API_REFERENCE.md#messaging-endpoints-brc-33)
does not use x402.

Get your auth token:
```bash
sudo anvil token
```

## Paying a request

A production node offers two payment paths for a priced request:

- **BRC-121** (`x-bsv-*` headers): any BRC-42 wallet pays the node's own
  price to a one-time key. This is how clients pay the node; see
  [Paying the node's price with BRC-121](#paying-the-nodes-price-with-brc-121).
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

`X402-Proof` is deprecated, development-only, and off by default. A node
offers it only when `[api] x402_proof_scheme = true`. When it is off, an
unpaid request receives a proof-free direct offer with `ERR_PAYMENT_REQUIRED`
and no challenge coin is minted. An `X402-Proof` is not verified and receives
`ERR_PROOF_PAYMENT_UNAVAILABLE` with the same direct offer. When the switch is
on, the node mints challenge coins and accepts proofs as before. The scheme is
unsuitable for outside payers because the challenge output is locked to a key
derived by the node, while the payer is expected to spend it.

The proof-free 402 body has this shape:

```json
{
  "amount_sats": 100,
  "payee_locking_script_hex": "76a9...88ac",
  "payees": [
    {"role":"infrastructure","locking_script_hex":"76a9...88ac","amount_sats":60},
    {"role":"content","locking_script_hex":"76a9...88ac","amount_sats":40}
  ],
  "accepts": ["X-Bsv-Payment"],
  "code": "ERR_PAYMENT_REQUIRED",
  "description": "..."
}
```

`amount_sats` is the total. A one-payee offer omits `payees` and makes
`payee_locking_script_hex` that payee's script; a multi-payee offer includes
the itemized list. `description` is omitted for the ordinary unpaid response.
An attempted `X402-Proof` while the scheme is off returns the same fields with
code `ERR_PROOF_PAYMENT_UNAVAILABLE` and a description.

When a 402 offers BRC-121 it carries no `X402-Challenge`: the node does not
mint a nonce coin that the advertised payment path does not need.

**Direct payments need ARC.** The node broadcasts a direct payment and
accepts it only when ARC reports that the network accepted it:
`SEEN_ON_NETWORK` or `MINED`. `REJECTED` is an outright refusal with 402 and
code `ERR_PAYMENT_NOT_ACCEPTED`. Every other ARC transaction status, including
`SEEN_IN_ORPHAN_MEMPOOL`, may still transition to acceptance and is answered
503 with `ERR_PAYMENT_SUBMIT_UNCERTAIN`, no new offer, and instructions to
retry the same transaction. A node
with no ARC client refuses every `X-Bsv-Payment` with 402 and code
`ERR_DIRECT_PAYMENT_UNAVAILABLE`. Such a node cannot take a payment from a
client. When the deprecated proof scheme is enabled, a proof whose challenge
sets `require_mempool_accept` is held to the same two statuses. A node with
that setting and no ARC client refuses the proof with 402 and code
`ERR_MEMPOOL_CHECK_UNAVAILABLE`.

Discovery does not filter its method list by ARC availability. With
`[arc] enabled = false`, `/.well-known/x402` still lists BRC-121 and
`X-Bsv-Payment`, plus the deprecated proof method when its switch is on. A
proof-off 402 also advertises `X-Bsv-Payment` even though submitting it gets
`ERR_DIRECT_PAYMENT_UNAVAILABLE`; BRC-121 offer headers are absent because that
path could not be started. If the proof method is enabled without its mempool
requirement it remains usable; with the requirement it is refused as described
above. `anvil doctor` warns for both ARC-disabled configurations.

The ARC answer must name the submitted txid. A mismatched answer is ambiguous.
A `MINED` answer is final only
when its BRC-74 merkle path proves that txid against the node's own header at
the reported height, and its block hash names that header. A missing or
unverifiable proof is answered 503 without a new offer until the node can
verify it. A transport,
server or response failure after submission is ambiguous: ARC may already
have accepted the transaction. It answers 503 with
`ERR_PAYMENT_SUBMIT_UNCERTAIN`, no new payment offer, and tells the client to
retry the same transaction.

**One transaction pays for one request.** The node remembers the txid of every
direct payment it accepts for 24 hours and up to 100,000 txids. When the
deprecated proof scheme is enabled, accepted proofs share that same set. It
refuses a reused transaction with 402 and code `ERR_PAYMENT_REPLAYED`. When
the set is full,
it evicts nothing: a new payment is refused with 503
`ERR_PAYMENT_REPLAY_FULL` and no new offer until an entry expires. It also
refuses with code `ERR_PAYMENT_TOO_OLD` a payment mined more than 144 blocks
below the node's header tip.

Known limits of the txid memory: the direct-payment replay set lives only in
memory. It forgets a txid after 24 hours and on a restart. An unconfirmed
direct payment, or one mined no more than 144 blocks below the current tip, can
therefore pay for one more request after restart. The capacity rule does not
make an accepted transaction replayable to admit a new one. BRC-121 has
restart protection: the node checks the wallet's durable record, and writes an
ambiguous accepted payment to the journal under `data_dir` before contacting
ARC.

Known limit: a direct payment is not bound to the request it pays for, so
it pays for whoever presents it first. Someone who sees a payer's
transaction, for example while the payer waits to retry it after
`ERR_PAYMENT_NOT_ACCEPTED`, can present it first, and the payer's retry then
gets `ERR_PAYMENT_REPLAYED`. In the same way, any unused transaction that
pays the node's payee script at least the price, unmined or mined at most
144 blocks deep, buys one request for whoever presents it.

**Payment broadcasts are bounded.** The node waits at most 10 seconds for ARC
to answer a direct payment, or a proof-path broadcast when that scheme is
enabled, and no longer than the request itself lasts. A broadcast cut off this way has an ambiguous result,
so the same transaction—not a new payment—must be retried. Direct payments
take one of the 16 process-wide slots before any header decoding or
verification; enabled proof-path ARC submits share those slots. One more is answered
503 with code
`ERR_DIRECT_PAYMENT_BUSY` and a `Retry-After`, without being broadcast, and
the same transaction can be sent again.

**Proof-bound request bodies are read under bounds.** When the deprecated
proof scheme is enabled, the node reads a priced request's body before it
checks the payment: at most 1 MiB, which
must start within 2 seconds and then arrive at 16 KiB a second or faster on
average. The read ends within 60 seconds and no later than its challenge
expires. A body over the cap gets 413, and one too slow gets 408. The node
reads at most 32 such bodies at once; a body that finds none of those reads
free within 2 seconds gets 503. One client, counted as the rate limiter
counts it (with the same `trust_proxy` settings), may have at most 4 of its
bodies being read at once; one more is answered 503 with code
`ERR_PAYMENT_BODY_SHARE` and a `Retry-After`. Global and per-client capacity
is released when the body completes, fails, or reaches challenge expiry.

A refused payment answers 402, except where this section names 503. When
the refusal has a stable code, the body is
`{"status":"error","code":"ERR_...","description":"...","error":"..."}`.

## Paying the node's price with BRC-121

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
- the node's price for the route is above 0;
- that node payee is not a fallback for a disabled passthrough or split
  model; and
- the stored header tip is no older than `bsv.header_stale_after_secs`
  (30 minutes by default).

Both headers are exposed to browsers (`Access-Control-Expose-Headers`), and
the five request headers are allowed by CORS. A route the node does not
price never makes an offer, and there the `x-bsv-*` request headers are
ignored: nothing is checked, broadcast or recorded. A node without its
wallet or ARC makes no offer either, and ignores the headers.

The BRC-121 402 has an empty body and no `X402-Challenge`. It therefore mints
no proof-path nonce coin. If BRC-121 is unavailable, the response advertises
`X-Bsv-Payment` with the required amount and payees. A proof challenge is a
fallback only when the deprecated development switch is on.

**The paid request** repeats the request with five headers: `x-bsv-beef`
(the payment as a canonical-base64 Atomic BEEF, BRC-95), `x-bsv-sender`
(the payer's identity key), `x-bsv-nonce` (the base64 derivation prefix), `x-bsv-time`
(Unix milliseconds, as a decimal string) and `x-bsv-vout` (the payment
output's index). A request that also carries `X-Bsv-Payment` or `X402-Proof`
is answered 400 with code `ERR_BRC121_MIXED_METHODS`: pay by one method.

**The checks, in order.** Nothing is broadcast or stored before check 5
shows that the payment is valid and pays this node.

1. All five headers, in the shapes and lengths the reference middleware
   checks: a compressed public key, canonical base64 for both the BEEF and a
   nonce of at most 512 characters, and unsigned integers for the time and the output index;
   `x-bsv-beef` within the 256 KiB payment header cap.
   `ERR_BRC121_MALFORMED`.
2. `x-bsv-time` within 30 seconds of the node's clock, either way.
   `ERR_BRC121_STALE`. Keep the node's clock synced (NTP): a clock that is
   off refuses honest payers.
3. An Atomic BEEF whose subject transaction is held in full, with no bytes
   following the BEEF. Only the
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
   then durably journals the payment, then checks the node wallet's own
   record, which survives restarts. An already-used payment gets
   `ERR_BRC121_REPLAYED`. The journal has a 64-entry live cap per client,
   held under one-way client hashes rather than addresses.
7. ARC accepts it, under the same rules as a direct payment: unconfirmed
   ancestors are submitted in dependency order before the payment, under
   one 10-second bound and one of the 16 shared slots. The payment must reach
   `SEEN_ON_NETWORK` or `MINED` and pass the same depth bounds. A conclusive
   refusal gets `ERR_BRC121_NOT_ACCEPTED`.
8. The node wallet records it as a wallet payment, with fixed text that
   carries nothing from the request. A failure leaves the journal entry for
   the sweep.

A node wallet that cannot derive the key answers 500 with
`ERR_BRC121_WALLET_UNAVAILABLE`. A payment the journal holds but ARC or the
wallet has not conclusively handled answers 503 `PAYMENT_KEPT`; a journal
that is full, fails to write, or has reached the client's 64-entry cap
answers 503 `PAYMENT_UNRECORDED`. Both carry `Retry-After`, no BRC-121 offer,
and tell the caller not to pay again but to retry the same request.

One client, counted as the rate limiter counts it, may have 4 BRC-121
payments in validation and up to 32 waiting for a place. A fifth waits for
up to 15 seconds and proceeds when a place frees. A thirty-seventh gets 503
`ERR_BRC121_BUSY`, no offer, and is not journaled. The same 503, with no new
offer, is returned when the shared payment replay set is full. An ambiguous
network or wallet outcome remains 503 `PAYMENT_KEPT`, also with no new offer.

Only a conclusive refusal or an already-used payment answers 402 with the
offer headers. An ambiguous failure answers 503 without inviting another
payment. This differs from BRC-121's rule that every failed validation
answers 402.

**What it unlocks.** An accepted payment is node coverage of what its output
paid, and nothing else. It unlocks unmonetized and `free`-model envelopes.
It covers a split envelope's node share but never its app share, and a
request pays by one method, so a split envelope stays redacted for a
BRC-121 payer: it is unlocked by an `X-Bsv-Payment` that pays both shares.
A BRC-121 payment never covers a passthrough envelope, never unlocks a
token-model envelope, and never unlocks a `private` envelope. As on the other
paths, a price is paid per request. The node's answer carries an
`X402-Receipt`, as on the other paths.

**Unclaimed payments.** The payer's wallet broadcasts the payment before it
sends the request. After checks 1 to 5, the node therefore writes the payment
to its journal before contacting ARC. It deletes the entry only after the
wallet records the payment or ARC conclusively refuses it. ARC busy,
timeouts, unreachable or still-processing answers, non-final statuses,
depth failures, wallet-record reads and wallet-record writes all leave it
kept. The journal is under `data_dir` (`brc121-journal`), holds at most 4096
payments and keeps each for at most 7 days.

Every 2 minutes, each payment kept for at least a minute is sent to ARC
again:

- **Accepted or mined:** it is recorded in the wallet.
- **Refused outright:** it is dropped. ARC's documented final transaction
  status is `REJECTED`; documented transaction-validation HTTP responses
  461 to 466 and 471 to 474 are also conclusive.
- **Anything else:** it is kept for the next sweep.

`SEEN_IN_ORPHAN_MEMPOOL` and `DOUBLE_SPEND_ATTEMPTED` are non-final and stay
for another sweep. The sweep has one ARC slot reserved outside the 16 slots
used by requests.

A payment ARC refuses outright at request time is never kept. A request
whose payment was kept is not served: its payment is recorded later.
`anvil doctor` shows the journal's size and its oldest entry, and fails when
the journal is full. The operator's `/stats` view counts offers,
acceptances, refusals by code, kept, claimed and dropped payments.

**What the node wallet stores.** Spending a BRC-121 payment takes the
payer's identity key, so the wallet stores that key with the payment,
together with the nonce and the time. It stores no request path, address or
other request data.

**A refusal can still cost money.** The payer broadcasts before the node
answers. A malformed, stale, underpaid, wrong-key, unverifiable or replayed
request; a conclusive ARC refusal; a stale-header proof failure; the
thirty-seventh concurrent payment; or a journal that is full, unwritable or
over its per-client cap can therefore be refused even though the transaction
later pays the node. `PAYMENT_KEPT` is different: do not create a second
payment; retry that same request while the node finishes the kept payment.

Known divergences: payer inputs are limited to P2PKH; `x-bsv-beef` is capped
at 256 KiB; and the wallet's pre-check and its eventual merge result can
disagree. Like the reference middleware, the in-memory replay set fails
closed at capacity.

**Proxies must allow long header lines.** A typical payment, with one input
and a mined parent, is about 1.3 KB of base64 in `x-bsv-beef`. A payment
with several inputs, unconfirmed parents or large parents is many times
that. Nginx's default `large_client_header_buffers 4 8k` refuses a header
line over 8 KiB with 400. In the server block that proxies to the node,
allow headroom above the node's 256 KiB value cap for the header name, colon,
spaces, line ending and proxy bookkeeping:

```nginx
large_client_header_buffers 4 260k;
```

## What a payment or app token unlocks

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

## Topics are exact

`GET /data?topic=X` returns only topic `X`; durable topics used to match
`X:*` too. The other reads that name a topic are exact in the same way:
`GET /topics/{topic}`, `GET /identity/{pubkey}` (topic `identity:<pubkey>`),
`/app/{name}` and `/explorer` (topic `anvil:catalog`) and `/mesh/nodes`
(topic `mesh:heartbeat`). The SSE subscription was always exact. Mesh peers
still subscribe to each other by topic prefix.

