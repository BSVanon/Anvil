# Anvil Launch — Twitter Announcement Script

## Already Posted

**Tweet 1 — The Hook** (posted)
What if your data didn't need a platform? ... One binary. 30-second sync. You're a node.

**Tweet 2 — SPV Payments + App Mesh** (posted)
Anvil is a lightweight SPV node anyone can spin up and connect with...

**Tweet 3 — The Vision** (posted)
Many Apps have been developed, Many Claws have been made...

---

## Remaining Posts

### Post 4 — HTTP 402: The Machine Economy

The web has a built-in payment status code that nobody uses: HTTP 402 — Payment Required.

Reserved in 1997. Waiting for digital cash.

Anvil uses it. Any endpoint can require payment. An AI agent reads the price, pays in BSV, gets the data. No invoice. No billing cycle. No human in the loop.

Sub-cent. Per-request. Instant settlement. Non-custodial — the node never touches your funds.

Try it yourself:
https://anvil.sendbsv.com/.well-known/x402

Every Anvil node publishes what it sells and what it costs. Machines read it, pay, consume. Zero onboarding.

---

### Post 5 — The Developer Hook

```
npm install anvil-mesh
```

5 lines to publish signed data to the mesh. 3 lines to query it.

No database to run. No infra to manage. No vendor to negotiate with.

Your app signs an envelope, POSTs it to any node. Every node gossips it to every other node. Done.

Any consumer reads it from any node. The signature proves who published it. The mesh proves it wasn't tampered with.

SDK: https://www.npmjs.com/package/anvil-mesh
GitHub: https://github.com/BSVanon/Anvil

---

### Post 6 — We Inscribed Our Dashboard on Bitcoin

The Anvil Explorer isn't hosted anywhere. It's inscribed on BSV — every byte of HTML, CSS, and JavaScript is a Bitcoin transaction.

Any Anvil node serves it from the chain. No CDN. No hosting provider. No domain that can be seized or expire.

https://anvil.sendbsv.com/explorer — that's one node serving it.
http://212.56.43.191:9334/explorer — that's another. Same content. Different node.

The content is identical because it comes from the same Bitcoin transaction. Not because we copied files. Not because they sync a database. Because Bitcoin IS the database.

No hosting bills. No renewal. No "this site has been suspended."

---

### Post 7 — The Invitation

Anvil is live and public. Run your own node:

```
go build -o anvil ./cmd/anvil
./anvil -config anvil.toml
```

30 seconds to sync. Zero dependencies. One binary.

Publish data. Get paid per request. Let machines find your service automatically.

Explorer: https://anvil.sendbsv.com
GitHub: https://github.com/BSVanon/Anvil
SDK: https://www.npmjs.com/package/anvil-mesh

What would you build on a mesh where every node can serve every app?

---

## Key Messages (pick what resonates)

**For builders:**
- 5 lines to publish, 3 to query. npm install anvil-mesh.
- Non-custodial payments built in. Your app gets paid per request without touching funds.
- No database, no infra, no vendor lock-in.

**For BSV community:**
- SPV works. 30-second header sync, no blockchain download.
- HTTP 402 is real and live. Machines pay machines in BSV.
- The Explorer is permanently on-chain. Any node serves it.

**For AI/agent builders:**
- Every Anvil node publishes /.well-known/x402 — a machine-readable menu.
- AI agents discover services, read prices, pay, consume. Zero onboarding.
- Sub-cent per-request. No API keys. No accounts.

**For skeptics:**
- It's running right now. Click the link.
- The code is public. Read it.
- Two nodes, live mesh, real data flowing. Not a whitepaper.

## Tone

- No hype words: no "revolutionary", "game-changing", "web3"
- Show, don't claim: every post has a working URL
- Confidence without arrogance: "we built this" not "we solved everything"
- Let the URLs do the talking: every claim is verifiable right now

## URLs (use HTTPS where possible)

- Explorer: https://anvil.sendbsv.com
- GitHub: https://github.com/BSVanon/Anvil
- SDK: https://www.npmjs.com/package/anvil-mesh
- x402 discovery: https://anvil.sendbsv.com/.well-known/x402
- Direct IP (proves decentralization): http://212.56.43.191:9334/explorer
