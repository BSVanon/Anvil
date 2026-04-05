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

Query a previously seen transaction's proof:

```bash
curl http://localhost:9333/tx/855fb8cd.../beef
```

## Check node health

```bash
curl http://localhost:9333/status
# → {"node":"anvil","version":"0.1.0","headers":{"height":940965}}
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
