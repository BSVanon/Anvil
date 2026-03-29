# API Reference

## Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | Node health: version, header tip, sync lag, SPV status, warnings |
| `/stats` | GET | No | Extended stats: envelopes, peers, recent connections, SPV counters |
| `/tx/{txid}/beef` | GET | No | BEEF proof for a transaction |
| `/content/{txid}_{vout}` | GET | No | Raw content from a transaction output |
| `/data` | GET | No | Query envelopes by topic (`?since=TIMESTAMP` for incremental) |
| `/data/subscribe` | GET | No | SSE stream of new envelopes by topic (real-time push) |
| `/data` | POST | Bearer, x402, or signed | Publish an envelope |
| `/data` | DELETE | Bearer | Delete a stored envelope by `topic` + `key` |
| `/broadcast` | POST | Bearer | Broadcast a raw transaction |
| `/explorer` | GET | No | Node explorer dashboard |
| `/mesh/status` | GET | No | Live mesh activity, peers, recent connection events |
| `/.well-known/x402` | GET | No | Machine-readable payment menu |
| `/.well-known/x402-info` | GET | No | Protocol spec (JSON or markdown) |
| `/.well-known/identity` | GET | No | Node identity public key |
| `/.well-known/anvil` | GET | No | Node metadata |
| `/app/{name}` | GET | No | Redirect to registered app |

## Overlay endpoints (BRC-22/24)

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/overlay/topics` | GET | No | List registered topic managers |
| `/overlay/services` | GET | No | List registered lookup services |
| `/overlay/submit` | POST | No | Submit TaggedBEEF to overlay engine |
| `/overlay/lookup` | GET | No | Query a lookup service |
| `/overlay/query` | POST | No | Complex lookup query |

## Wallet endpoints (operator only)

All wallet endpoints require the `Authorization: Bearer <token>` or `X-Anvil-Auth: <token>` header.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/wallet/outputs` | GET | List wallet UTXOs |
| `/wallet/send` | POST | Send BSV to an address |
| `/wallet/invoice` | POST | Create a payment invoice |
| `/wallet/scan` | POST | Scan for UTXOs at identity address |
| `/wallet/internalize` | POST | Import a BEEF transaction |
| `/wallet/create-action` | POST | Low-level BRC-101 action creation |
| `/wallet/sign-action` | POST | Low-level BRC-101 action signing |

## Authentication

Transport auth for publishing data:

1. **Bearer token** — operator auth, derived from WIF: `Authorization: Bearer <token>`
2. **x402 payment** — anyone can publish by paying the node's price

Every published envelope is also signed by the app's BSV key. The signature proves authorship, but it does not replace bearer auth or x402 payment for `POST /data`.

Get your auth token:
```bash
sudo anvil token
```

Delete an old envelope:

```bash
TOKEN=$(sudo anvil token)
curl -X DELETE "http://localhost:9333/data?topic=anvil:catalog&key=TOPIC_KEY" \
  -H "Authorization: Bearer $TOKEN"
```

## Real-time subscription (SSE)

Subscribe to new envelopes on a topic via Server-Sent Events:

```bash
curl -N "http://localhost:9333/data/subscribe?topic=oracle:rates:bsv"
```

Each new envelope is pushed as a `data:` event with a monotonic `id:` field. Paid payloads are redacted for unauthenticated clients, matching `GET /data` behavior.

On reconnect, the browser's `EventSource` sends `Last-Event-ID` automatically. The server sends a gap warning comment — use `GET /data?since=TIMESTAMP` to backfill any missed events.

```js
const source = new EventSource('http://localhost:9333/data/subscribe?topic=my:topic')
source.onmessage = (e) => {
  const envelope = JSON.parse(e.data)
  console.log(envelope.topic, envelope.payload)
}
```

## Incremental polling

Use `since` to only fetch envelopes newer than a given unix timestamp:

```bash
curl "http://localhost:9333/data?topic=oracle:rates:bsv&since=1711600000"
```

## Operator commands

```bash
anvil help                  # full command reference
sudo anvil info             # identity, funding address, auth token
sudo anvil doctor           # validate config, connectivity, mesh health
sudo anvil token            # print auth token
curl -s localhost:9333/status   # node status
sudo journalctl -u anvil-a -f  # live logs
sudo systemctl restart anvil-a  # restart
```
