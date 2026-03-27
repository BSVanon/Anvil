# API Reference

## Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | Node health: height, version, work |
| `/stats` | GET | No | Envelope counts, peer count, uptime |
| `/tx/{txid}/beef` | GET | No | BEEF proof for a transaction |
| `/content/{txid}_{vout}` | GET | No | Raw content from a transaction output |
| `/data` | GET | No | Query envelopes by topic |
| `/data` | POST | Bearer, x402, or signed | Publish an envelope |
| `/broadcast` | POST | Bearer | Broadcast a raw transaction |
| `/explorer` | GET | No | Node explorer dashboard |
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

Three methods for publishing data:

1. **Bearer token** — operator auth, derived from WIF: `Authorization: Bearer <token>`
2. **x402 payment** — anyone can publish by paying the node's price
3. **Signed envelope** — anyone with a BSV key signs the envelope; no token or payment needed

Get your auth token:
```bash
sudo anvil token
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
