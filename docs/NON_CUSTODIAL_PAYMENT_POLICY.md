# Non-Custodial Payment Policy for Anvil Nodes

**Date:** 2026-03-18
**Author:** Robert + Claude
**Status:** Policy draft — to be implemented before any app monetization goes live
**Origin:** Design conversation in SendBSV-Rates workspace while planning oracle feed monetization on the Foundry mesh

---

## The Problem

Anvil nodes will host data from third-party apps (oracles, attestation services, session providers). Those apps may want to charge consumers for their data. The node operator may also want to charge for infrastructure.

If not handled carefully, the node becomes a payment intermediary — receiving funds on behalf of apps and forwarding them. That's money transmission. It carries regulatory burden that no node operator wants, and it undermines the non-custodial design of the entire system.

**This policy must be solved generically.** Every non-free app or service on every node in the Foundry mesh will face this question. The answer must be baked into the protocol, not left to per-app negotiation.

---

## The Bright Line

**A node must never receive funds destined for another party.**

This means:
- No forwarding payments from consumers to apps
- No holding funds in escrow on behalf of apps
- No revenue sharing that involves receiving then splitting
- No acting as payment agent for any third party
- No holding or using another party's wallet keys

If funds enter the node's wallet, they belong to the node operator. Period.

---

## Allowed Monetization Models

### Model 1: Node as Merchant

The node operator charges consumers for access to data in its store. Revenue is 100% the node operator's. Apps publish data to the node for free (via bearer auth) or the node pays apps separately for their feed via an independent commercial arrangement.

**Payment flow:**
```
Consumer ──pays──► Node (node's payee script via x402)
Node ──pays──► App (separate transaction, node's own funds, node's own decision)
```

**Why it's clean:** Two independent transactions. The node earned money selling access. The node spent money buying a data feed. No intermediary relationship.

**Implementation:** This is what x402 does today. `payment_satoshis > 0` in config, payee script derived from `identity.wif`.

**Use case:** Node operator runs infrastructure, charges for API access, and subscribes to oracle feeds as a cost of doing business. The resale markup is the node operator's margin.

---

### Model 2: App as Direct Merchant (x402 passthrough)

The app embeds its own payee locking script in the envelope metadata. When a consumer queries that topic, Anvil's x402 challenge uses the **app's payee script**, not the node's. Payment goes directly from consumer to app on-chain. The node verifies the TX structure but never touches the funds.

**Payment flow:**
```
Consumer ──pays──► App (app's payee script, embedded in envelope)
Node = verification only, zero fund contact
```

**Why it's clean:** The node is a payment terminal, not a payment processor. It checks that the right script was paid — it doesn't receive, hold, or forward anything. Like a vending machine that verifies the coin went into the manufacturer's slot.

**Implementation (new):**
- Envelope metadata gains optional fields: `payee_locking_script_hex`, `price_sats`
- x402 middleware checks: if the topic's envelopes carry a payee script, use it instead of the node's
- All other verification is identical (nonce UTXO, amount, request binding)
- Node's wallet is not involved in the payment output — only in nonce UTXO minting

**Use case:** An oracle publishes rates and wants to charge per-query. The oracle controls its own keys and receives payment directly. The node operator provides infrastructure for free or charges separately (see Model 3).

---

### Model 3: Split Output (atomic dual-pay)

A single consumer TX contains two outputs: one to the node (infrastructure fee) and one to the app (data fee). Both parties set their own prices independently. The node verifies both outputs are present before serving the response.

**Payment flow:**
```
Consumer ──pays──► Node + App (one TX, two outputs, each party's own script)
```

**Why it's clean:** Funds never pool. Each party receives directly from the consumer in the same atomic transaction. No custodial relationship exists at any point. This is a marketplace fee model enforced on-chain.

**Implementation (new):**
- x402 challenge includes both payee scripts and both prices:
  ```json
  {
    "payees": [
      { "role": "infrastructure", "locking_script_hex": "76a914<node>88ac", "amount_sats": 10 },
      { "role": "content",        "locking_script_hex": "76a914<app>88ac",  "amount_sats": 50 }
    ],
    "nonce_utxo": { ... }
  }
  ```
- Verification checks that the TX has outputs paying each script >= each amount
- Node's wallet mints the nonce UTXO (1 sat overhead, same as today)
- App's price and script come from envelope metadata

**Use case:** Node charges 10 sats for serving the request (bandwidth, storage, infrastructure). Oracle charges 50 sats for the data itself. Consumer pays 60 sats total in one transaction, each party receives directly.

---

### Model 4: License/Token Gating (no payment through node)

The app sells access credentials independently — signed tokens, on-chain tokens, whatever mechanism the app chooses. The consumer presents the credential when querying the Anvil node. The node verifies the credential's signature but handles zero payment.

**Payment flow:**
```
Consumer ──pays──► App (any rail, completely outside Anvil)
Consumer ──presents credential──► Node (verification only)
```

**Why it's clean:** No funds flow through the node at all. The node only verifies a cryptographic credential.

**Implementation (new):**
- Envelope metadata includes `auth_pubkey` (the app's signing key for credentials)
- Node checks for a credential header (e.g., `X-App-Token`) on gated topics
- Credential verification: signature check against the declared pubkey
- No x402 involvement — this is pure auth, not payment

**Use case:** App with its own billing system (subscriptions, invoicing, etc.) that doesn't want per-request micropayments.

---

### Model 5: Free Feed + Premium Direct

App publishes a basic feed to the mesh for free. Consumers who want premium data (higher frequency, more pairs, historical lookups) go to the app's own API and pay there. Anvil is just distribution infrastructure.

**Payment flow:**
```
Consumer ──reads──► Node (free)
Consumer ──pays──► App (app's own API, outside Anvil entirely)
```

**Why it's clean:** Anvil is a CDN. No monetization involvement whatsoever.

**Implementation:** Nothing to build. This is the default behavior today.

---

## What Is Categorically Prohibited

These patterns must be rejected at the protocol level, not just by policy:

| Pattern | Why it's prohibited |
|---|---|
| Node receives payment and forwards to app | Money transmission |
| Node holds app's private keys | Custodial |
| Node collects revenue and splits it periodically | Escrow / clearing |
| Node acts as payment agent for any third party | Money transmission |
| Revenue sharing via intermediary wallet | Money transmission |
| App's funds pass through node's wallet at any point | Custodial |

---

## Envelope Metadata Extension

To support Models 2, 3, and 4, the data envelope format gains optional monetization fields:

```json
{
  "type": "data",
  "topic": "oracle:rates:bsv",
  "payload": "{...}",
  "signature": "...",
  "pubkey": "...",
  "ttl": 30,
  "durable": false,
  "timestamp": 1710000000,

  "monetization": {
    "model": "passthrough | split | token | free",
    "payee_locking_script_hex": "76a914<app-address>88ac",
    "price_sats": 50,
    "auth_pubkey": "02ab..."
  }
}
```

| Field | Required | Description |
|---|---|---|
| `model` | Yes (if monetization present) | Which payment model applies |
| `payee_locking_script_hex` | For passthrough/split | App's receiving script |
| `price_sats` | For passthrough/split | App's price per query |
| `auth_pubkey` | For token model | Pubkey to verify access credentials |

When `monetization` is absent, the node's own x402 config applies (Model 1) or the data is free.

---

## Node Config Extension

```toml
[api]
payment_satoshis = 10                    # Node's infrastructure fee (0 = free)

[api.app_payments]
allow_passthrough = true                 # Allow apps to set their own payee scripts
allow_split = true                       # Allow dual-output (node + app) payments
allow_token_gating = true                # Allow apps to gate via signed credentials
max_app_price_sats = 10000              # Cap on app-declared prices (prevent abuse)

# NEVER configurable — these are hardcoded prohibitions:
# - receive_and_forward = PROHIBITED
# - hold_on_behalf = PROHIBITED
# - revenue_share_via_wallet = PROHIBITED
```

The prohibitions are not config options. They are not toggleable. They are enforced in the verification code path — the node physically cannot perform these operations because no code path exists to do so.

---

## x402 Middleware Changes

The existing x402 middleware (`payment.go`) needs these extensions:

### Challenge generation
1. Check if the requested topic has envelopes with `monetization` metadata
2. If `model: "passthrough"` → use app's payee script, app's price
3. If `model: "split"` → include both node's and app's payee scripts and prices
4. If `model: "token"` → skip x402, check for credential header instead
5. If no monetization → use node's payee script and node's price (today's behavior)

### Proof verification
1. For passthrough: verify TX output pays app's script >= app's price
2. For split: verify TX has outputs paying BOTH scripts >= BOTH prices
3. Nonce UTXO verification is unchanged (always node-minted)

### Key invariant
**The node's wallet is only ever used for nonce UTXO minting.** Payment outputs go to whoever the challenge specified — node, app, or both. The node never receives-and-forwards.

---

## Implementation Order

1. **Envelope metadata extension** — Add optional `monetization` field to envelope format. Validate on ingest. Store and gossip as-is.
2. **Passthrough (Model 2)** — Extend x402 challenge to use app's payee script when present. Extend verification to check app's script.
3. **Split output (Model 3)** — Extend challenge to include multiple payees. Extend verification to check all outputs.
4. **Token gating (Model 4)** — Add credential verification middleware, separate from x402.
5. **Config + guardrails** — Add `[api.app_payments]` config section. Hardcode prohibitions.

---

## Why This Matters Beyond Rates

This isn't just about one oracle. Every app on the Foundry mesh will face this:
- Session providers charging for encrypted storage
- Attestation services charging for identity verification
- Data feeds charging for real-time signals
- AI agents paying for tool access

If the first app (Rates) connects with a clean non-custodial model, every subsequent app follows the same pattern. If the first app hacks something together, every subsequent app inherits the mess.

The policy is: **direct payment only, enforced at the protocol level, no exceptions.**
