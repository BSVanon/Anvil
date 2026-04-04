# API Reference

## Core Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | Node health: version, header tip, sync lag, SPV status, warnings |
| `/stats` | GET | No | Extended stats: envelopes, peers, recent connections, demand |
| `/data` | GET | No | Query envelopes by topic (`?since=TIMESTAMP` for incremental) |
| `/data/subscribe` | GET | No | SSE stream of new envelopes by topic (real-time push) |
| `/data` | POST | Bearer, x402, or signed | Publish an envelope |
| `/data` | DELETE | Bearer | Delete a stored envelope by `topic` + `key` |
| `/broadcast` | POST | Bearer | Broadcast a raw transaction |

## Discovery Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/topics` | GET | No | List all topics with count, metadata, demand |
| `/topics/{topic}` | GET | No | Topic detail: metadata, publisher, price, demand, identity |
| `/identity/{pubkey}` | GET | No | Publisher identity (from `identity:<pubkey>` envelope) |
| `/.well-known/x402` | GET | No | Machine-readable payment menu |
| `/.well-known/x402-info` | GET | No | Protocol spec (JSON or markdown) |
| `/.well-known/identity` | GET | No | Node identity public key |
| `/.well-known/anvil` | GET | No | Node metadata and capabilities |

## Messaging Endpoints (BRC-33)

Point-to-point messaging between identities.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/sendMessage` | POST | Bearer | Send a message to a recipient by pubkey |
| `/listMessages` | POST | Bearer | Retrieve messages for a recipient's message box |
| `/acknowledgeMessage` | POST | Bearer | Delete messages after receipt |

### POST /sendMessage

```json
{
  "recipient": "02abc...def",
  "messageBox": "inbox",
  "body": "hello"
}
```

Response: `{"status": "success", "messageId": "42"}`

The sender is the node's identity. Messages are forwarded across the mesh
via gossip with sender signature verification. Unacknowledged messages
expire after 7 days.

### POST /listMessages

```json
{
  "recipient": "02abc...def",
  "messageBox": "inbox"
}
```

Response: `{"status": "success", "messages": [{"messageId": "42", "sender": "02xyz...", "body": "hello", "timestamp": 1712345678}]}`

If `recipient` is omitted, defaults to the node's identity.

### POST /acknowledgeMessage

```json
{
  "recipient": "02abc...def",
  "messageIds": ["42", "43"]
}
```

Response: `{"status": "success", "acknowledged": 2}`

## Proof and Content Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/tx/{txid}/beef` | GET | No | BEEF proof for a transaction |
| `/content/{txid}_{vout}` | GET | No | Raw content from a transaction output |

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
| `/mesh/status` | GET | No | Live mesh peers, connections, activity |
| `/app/{name}` | GET | No | Redirect to registered app |

## Authentication

Transport auth for publishing data and sending messages:

1. **Bearer token** — operator auth, derived from WIF: `Authorization: Bearer <token>`
2. **x402 payment** — anyone can publish/query by paying the node's price

Every published envelope is also signed by the app's BSV key. The signature
proves authorship, but it does not replace bearer auth or x402 payment for
write endpoints.

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
sudo anvil info             # identity, funding address, auth token
sudo anvil doctor           # validate config, connectivity, mesh health
sudo anvil token            # print auth token
curl -s localhost:9333/status   # node status
sudo journalctl -u anvil-a -f  # live logs
sudo systemctl restart anvil-a  # restart
```
