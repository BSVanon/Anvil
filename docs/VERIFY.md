# Verify

Validate any BSV transaction without downloading the blockchain. Used
internally for x402 payment verification.

---

## What it does

Anvil syncs ~940,000 block headers from a BSV seed peer (~30 seconds, ~40MB). With that header chain, it can verify any BEEF (BRC-95) transaction proof — confirming that a transaction was mined in a real block with valid proof-of-work.

This is SPV (Simplified Payment Verification) as described in the Bitcoin whitepaper, Section 8.

## Install

```bash
git clone https://github.com/BSVanon/Anvil.git
cd Anvil
go build -o anvil ./cmd/anvil
```

## Configure

```bash
cp anvil.example.toml anvil.toml
```

Generate or provide a BSV private key (WIF format):

```bash
export ANVIL_IDENTITY_WIF="your-wif-here"
```

The WIF is the node's identity. It derives the API auth token, wallet address, and mesh peer identity. Set it as an environment variable — never put it in a config file.

## Run

```bash
./anvil -config anvil.toml
```

Output:
```
anvil node "anvil" starting
  data_dir:   ./data
  api:        0.0.0.0:9333
synced headers count=2000 tip=2000
...
header sync complete height=940965
REST API listening on 0.0.0.0:9333
```

## Verify a transaction

Submit a BEEF transaction for SPV verification + broadcast:

```bash
curl -X POST http://localhost:9333/broadcast \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @transaction.beef
```

Add `?arc=true` to forward to miners after validation. The response
includes a derived `status` field (`propagated`, `queued`, `rejected`,
or `validated-only`) alongside the full ARC state for telemetry —
wallets use `status` for failover decisions without reading the
individual bits. See [API_REFERENCE.md](API_REFERENCE.md#broadcast-response-shape-v210) for the
derivation table.

`/broadcast` accepts a bearer token OR x402 payment (when the operator
has set a broadcast price). Zero-priced broadcast endpoints stay
auth-required.

Query a previously seen transaction's proof:

```bash
curl http://localhost:9333/tx/855fb8cd.../beef
```

The response includes a `source` field: `"cached"` (served from the
local ProofStore), `"arc"`, or `"woc"` (fetched on demand from the
named upstream). Multi-source consumers should prefer `"cached"`
results from Anvil and fall back to a direct upstream when Anvil
returns a passthrough — otherwise they inherit the same single-upstream
failure mode they were trying to escape.

## Check node health

```bash
curl http://localhost:9333/status
# → basic: {"node":"anvil","version":"2.1.0","headers":{"height":940965}}

curl http://localhost:9333/mesh/status
# → rich: adds upstream_status.broadcast (healthy|degraded|down) and
#         headers_sync_lag_secs. Recommended for wallet failover polling.
```

## Production deploy

For production, use the built-in deploy tool:

```bash
sudo ./anvil deploy --nodes a
```

This creates the `anvil` system user, data directories, systemd service, and runs a health check. See `anvil deploy --help` for options.

Validate your setup at any time:

```bash
sudo anvil doctor
```

## Configuration reference

| Setting | Default | Description |
|---------|---------|-------------|
| `node.data_dir` | `./data` | Where headers, envelopes, and wallet are stored |
| `node.api_listen` | `0.0.0.0:9333` | REST API address |
| `bsv.nodes` | `["seed.bitcoinsv.io:8333"]` | BSV peers for header sync |
| `arc.enabled` | `true` | Enable transaction broadcast via ARC |
| `arc.url` | `https://arc.gorillapool.io` | ARC endpoint |

## Next: publish data

Once your node is running, you can publish signed data to the mesh.

**[Publish →](PUBLISH.md)**
