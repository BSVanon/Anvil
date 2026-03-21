# Anvil Launch — Twitter Announcement Script

## Narrative Arc

**Thread structure:** 5-part series over 2-3 days. Each post stands alone but builds on the last. Start with the problem, end with the invitation.

---

## Post 1 — The Hook (Day 1, morning)

**Format:** Long-form post

**Title:** What if your data didn't need a platform?

---

Every API you use today works the same way: sign up, get a key, agree to terms, hope they don't change the rules.

Your app depends on their uptime. Their pricing. Their permission.

We built something different.

Anvil is a mesh of nodes that publish, verify, and sell data — with no platform in the middle.

- No API keys. No accounts. No sign-up.
- Any node can serve any data.
- Payments are sub-cent, instant, and non-custodial.
- Machines discover services and pay automatically.

One binary. 30-second sync. You're a node.

This isn't a pitch deck. It's running right now:
http://212.56.43.191:9333/explorer

That dashboard? It's not hosted on a server. It's inscribed on Bitcoin SV — permanently. Every node in the mesh can serve it. There's no single point of failure to take down.

More coming this week. The code is public:
https://github.com/BSVanon/Anvil

---

## Post 2 — The Machine Economy (Day 1, afternoon/evening)

**Format:** Short post with image/screenshot of x402 response

---

The web has a built-in payment status code that nobody uses: HTTP 402 — Payment Required.

It was reserved in 1997. Waiting for digital cash.

Anvil uses it. Any endpoint can require payment. An AI agent reads the price, pays in BSV, gets the data. No invoice. No billing cycle. No human in the loop.

```
GET /.well-known/x402
→ endpoints, prices, payment models
```

Sub-cent. Per-request. Instant settlement. Non-custodial — the node never touches your funds.

Try it: http://212.56.43.191:9333/.well-known/x402

---

## Post 3 — The Developer Story (Day 2, morning)

**Format:** Short post

---

```
npm install anvil-mesh
```

5 lines to publish signed data to the mesh. 3 lines to query it. Every node gossips it to every other node.

No database to run. No infra to manage. No vendor to negotiate with.

Your app signs an envelope, POSTs it to any node. Done.

```js
const anvil = new AnvilClient({ wif: yourKey, nodeUrl: 'http://any-node' })
await anvil.publish('my-app:events', { hello: 'world' }, 3600)
```

Any consumer reads it from any node. The signature proves who published it. The mesh proves it wasn't tampered with.

SDK: https://www.npmjs.com/package/anvil-mesh
Docs: https://github.com/BSVanon/Anvil

---

## Post 4 — The Permanence Story (Day 2, afternoon)

**Format:** Long-form post

**Title:** We inscribed our dashboard on Bitcoin

---

The Anvil Explorer isn't hosted anywhere. It's inscribed on BSV — every byte of HTML, CSS, and JavaScript is in a Bitcoin transaction.

Any Anvil node serves it from the chain. No CDN. No hosting provider. No domain that can be seized or expire.

http://212.56.43.191:9333/explorer — that's node one serving it.
http://212.56.43.191:9334/explorer — that's node two. Same content. Different node.

The content is identical because it comes from the same Bitcoin transaction. Not because we copied files. Not because they sync a database. Because Bitcoin IS the database.

When you deploy an app to the Anvil mesh:
1. Each file becomes a Bitcoin transaction
2. The HTML is rewritten to reference on-chain content
3. Every node can serve it — forever

No hosting bills. No renewal. No "this site has been suspended."

This is what building on Bitcoin looks like.

---

## Post 5 — The Invitation (Day 3)

**Format:** Short post

---

Anvil is live and public.

Run your own node:
```
go build -o anvil ./cmd/anvil
./anvil -config anvil.toml
```

30 seconds to sync. Zero dependencies. One binary.

Publish data. Get paid per request. Let machines find your service automatically.

GitHub: https://github.com/BSVanon/Anvil
Explorer: http://212.56.43.191:9333/explorer
SDK: https://www.npmjs.com/package/anvil-mesh

What would you build on a mesh where every node can serve every app?

---

## Tone Guidelines

- **No hype words**: no "revolutionary", "game-changing", "web3"
- **Show, don't claim**: every post has a working URL or code snippet
- **Respect the reader**: assume technical audience, don't over-explain BSV
- **Confidence without arrogance**: "we built this" not "we solved everything"
- **Let the URLs do the talking**: every claim is verifiable right now

## Hashtags (use sparingly, 1-2 per post max)

- #BuildOnBSV
- #HTTP402
- @SendBSV (your handle)

## Supporting Media

- Screenshot of Explorer (Network tab with 3D mesh)
- Screenshot of /.well-known/x402 JSON response
- Screenshot of `npm install anvil-mesh` terminal
- GIF of Explorer loading from /explorer redirect

## Timing

- Post 1: Launch day, morning — sets the narrative
- Post 2: Same day, 4-6 hours later — the money angle
- Post 3: Next morning — developer hook
- Post 4: Next afternoon — the permanence differentiator
- Post 5: Day 3 — call to action
