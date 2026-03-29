# Add Your App To The Mesh

Fast path: get an app publishing to Anvil in a few minutes.

## What you need

- A node URL, for example `http://localhost:9333` or `https://your-node.example.com`
- Either:
  - the node auth token from `sudo anvil token`
  - or an x402-enabled node you can pay per request
- A BSV WIF for the app publisher

## 1. Install the SDK

```bash
npm install anvil-mesh
```

## 2. Publish your first envelope

```ts
import { AnvilClient } from 'anvil-mesh'

const client = new AnvilClient({
  nodeUrl: 'http://localhost:9333',
  wif: process.env.APP_WIF!,
  authToken: process.env.ANVIL_TOKEN,
})

await client.publish('demo:hello', {
  message: 'hello from my app',
  ts: Date.now(),
})
```

That writes a signed envelope to `POST /data`, stores it on the node, and gossips it across the mesh.

## 3. Read it back

```ts
const result = await client.query('demo:hello')
console.log(result.envelopes[0]?.payload)
```

Or with curl:

```bash
curl "http://localhost:9333/data?topic=demo:hello&limit=10"
```

## 4. If your app is a web app, list it in the mesh catalog

Publish a durable envelope on topic `anvil:catalog` with a payload like:

```json
{
  "name": "My App",
  "description": "What it does",
  "content_origin": "your_txid_vout",
  "topics": ["demo:hello"],
  "pricing": "free"
}
```

Use `ttl: 0` and `durable: true` so the catalog entry survives restarts and gossip churn.

## 5. Update or remove a catalog entry

Every `POST /data` response returns a `key`. Keep it.

Delete an old entry:

```bash
TOKEN=$(sudo anvil token)
curl -X DELETE "http://localhost:9333/data?topic=anvil:catalog&key=TOPIC_KEY" \
  -H "Authorization: Bearer $TOKEN"
```

Then publish the new durable version.

## Common operator checks

```bash
curl -s http://localhost:9333/status
curl -s http://localhost:9333/mesh/status
sudo anvil doctor
```

If the node has `0` peers, check:

- `mesh.seeds` is set in `/etc/anvil/node-a.toml`
- outbound `wss://` traffic is allowed
- inbound ports `8333` and `9333` are open if you want full participation

## Next docs

- [App Integration](APP_INTEGRATION.md)
- [API Reference](API_REFERENCE.md)
- [Payment Policy](NON_CUSTODIAL_PAYMENT_POLICY.md)
