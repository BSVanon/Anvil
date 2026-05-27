# Anvil v3.0.0 — Canonical Engine Adoption

**Release date:** TBD (pending Robert's approval — this doc is staged for the eventual `gh release create` body).

**Headline:** Anvil migrates from its independent overlay implementation to `bsv-blockchain/go-overlay-services` v1.3.1 as the canonical engine, adds canonical BRC-88 SHIP/SLAP federation via go-sdk's `LookupResolver` and `DEFAULT_SLAP_TRACKERS`, and ports the canonical UMP + Identity topic primitives so BRC-100 wallets (Babbage MetaNet, SendBSV-Wallet) can resolve user-recovery anchors and identity certificates directly against any Anvil node.

This is a major release because the overlay engine swap is non-trivial and operators must run a one-time migration step. The on-disk LevelDB format is compatible — the new engine reads the same files — but the canonical engine uses a new key family (`ovl3:` etc.) and the migration step populates that family from the legacy `ovl:` entries.

## Read first

- **[Operator migration guide](overlay-migration.md)** — step-by-step playbook
- **Mandatory one-time step**: `anvil overlay-migrate` after upgrading the binary, before starting the daemon
- **App migrations**: 3 Anvil-consuming apps need updates (Anvil-Swap, SendBSV-Foundry, SendBSV-Wallet)

## What's new

### Canonical overlay engine

The overlay engine is now `bsv-blockchain/go-overlay-services` v1.3.1. Anvil's previous in-process engine (~5K LOC across `internal/overlay/engine.go` + handlers) has been replaced with adapter shims that translate Anvil's bespoke topic-manager interface into the canonical `engine.TopicManager` contract. All four pre-existing app-layer topics (UHRP, DEX-swap, OrdLock listings, OrdLock-buy) continue to admit on the canonical engine identically to v2.x.x.

The new HTTP routes are at the canonical paths:

- `POST /submit` — canonical with `x-includes-off-chain-values` and `x-aggregation` headers
- `POST /lookup` — canonical with `output-list` BEEF responses + optional `x-aggregation` binary aggregator
- `GET /listTopicManagers`
- `GET /listLookupServiceProviders`
- `POST /arc-ingest`
- `POST /requestSyncResponse`, `POST /requestForeignGASPNode` (canonical BRC-88 federation; see below)

The legacy `/overlay/submit` / `/overlay/query` / `/overlay/topics` / `/overlay/services` routes are preserved indefinitely via a thin compat shim (Lens 2 = 2c per `OVERLAY_PROTOCOL_ALIGNMENT_PLAN.md`). Existing apps that haven't migrated to canonical routes continue to work unchanged.

### Canonical BRC-88 SHIP/SLAP federation

v3.0.0 enables canonical federation by default. Every Anvil node now:

1. Publishes SHIP+SLAP advertisement transactions on-chain for every hosted topic, via `bsv-blockchain/go-sdk`'s `admin-token` PushDrop template + the node's operator wallet.
2. Discovers federation peers via the canonical `LookupResolver` configured with `DEFAULT_SLAP_TRACKERS` (Babbage's `overlay-us-1.bsvb.tech`, `overlay-eu-1.bsvb.tech`, `overlay-ap-1.bsvb.tech`, plus `users.bapp.dev`).
3. Runs periodic GASP sync (5-minute cadence) against discovered peers to pull their state for each subscribed topic.
4. Re-advertises on-chain every 30 minutes to maintain freshness.

Federation participation is opt-out via `cfg.Overlay.EnableGASPSync = false` for operators running single-node deployments.

The bespoke JungleBus-based federation path that powered v2.x.x's mesh discovery has been **retired**. The `[junglebus]` section in `anvil.toml` is still accepted by the parser for backwards compatibility but has no runtime effect.

The boot log includes a one-line federation summary when GASP sync is enabled:

```
v3 federation wired: 6 topics syncable via canonical SHIP/SLAP (trackers=4)
```

### Canonical UMP topic (`tm_users`)

v3.0.0 hosts the canonical User Management Protocol topic for BRC-100 cross-device passkey recovery. BRC-100 wallets (Babbage MetaNet, SendBSV-Wallet) publish 12-field UMP PushDrop tokens carrying encrypted recovery primaries; Anvil indexes the `presentationHash` (field 6) and `recoveryHash` (field 7) for fast resolution.

Supported queries on `ls_users`:

- `{presentationHash: <hex>}` — returning-user same-passkey rehydrate
- `{recoveryHash: <hex>}` — lost-passkey + recovery-key restore
- `{outpoint: "<txid>.<vout>"}` — republish / health check

v3 KDF validation (argon2id or pbkdf2-sha512, positive iterations) is enforced at admission per the canonical `UMPTopicManager.ts` reference. Anvil never decrypts UMP token fields — that stays strictly client-side per the BRC-100 transport/wallet boundary.

### Canonical Identity topic (`tm_identity`)

v3.0.0 hosts canonical BRC-52 verifiable identity certificate publication. Wallets publish JSON-encoded `Certificate` structs as PushDrop output field[0]; Anvil validates the signature chain via go-sdk's canonical `Certificate.Verify(ctx)` (which uses the canonical anyone-wallet protocol internally) and admits if valid.

Supported queries on `ls_identity`:

- `{identityKey: <hex>}` — resolve cert by subject's compressed pubkey (full support)
- `{certifierKey: <hex>}` — Anvil extension: scope queries to a trusted certifier (full support)
- `{outpoint: "<txid>.<vout>"}` — republish / health check (full support)
- `{attributes: {handle, domain}}` — paymail handle resolution; **deferred (W-11)** — still unscheduled (v3.1.0 shipped tm_kvstore, not this path)

The `attributes` query path returns an explicit Freeform answer with `{deferred:true, use:"identityKey"}` so wallets can immediately fall back to the two-step paymail protocol (`.well-known/bsvalias` HTTP gateway → identityKey → `ls_identity` by identityKey). The two-step works fully in v3.0.0; only the overlay-native one-step path is deferred.

See `docs/internal/SENDBSV_USERS_TOPIC_REQUEST.md` § "Identity attributes deferral (W-11)" for the rationale and the resolution options.

### LevelDB sub-prefix layout

The canonical engine adds these LevelDB key families:

| Prefix | Purpose |
|---|---|
| `ovl3:` | Per-output admitted record (v3 replacement for v2's `ovl:`) |
| `txi3:` | Per-txid index family |
| `topi3:` | Per-topic recency index |
| `mst3:` | Per-topic MerkleState index |
| `beef3:` | BEEF sidecar storage |
| `anci3:` | Ancillary BEEF storage |
| `txco3:` | Transaction-consumption index |
| `cons3:` | Consumed-by reference index |
| `appl3:` | Applied-transactions ledger |
| `peer3:` | Per-peer GASP last-interaction timestamps |
| `lk_uhrp:` / `lk_dexswap:` / `lk_ordlock:` / `lk_ordlockbuy:` | Per-lookup-service index (4 existing topics) |
| `lk_users:` / `lk_identity:` | Per-lookup-service index (new UMP/Identity topics) |
| `lk_ship:rec:` / `lk_slap:rec:` | Per-lookup-service index for canonical BRC-88 federation |

All families share Anvil's existing overlay LevelDB. No new database is required.

## Behavioural changes

- `cfg.JungleBus.Enabled` defaults to `false` (was `true`). The section is still accepted but no longer wired to anything.
- `cfg.Overlay.EnableGASPSync` is a new field, defaulting to `true`.
- `cfg.Overlay.SHIPTrackers` and `cfg.Overlay.SLAPTrackers` are new optional fields; blank defaults to go-sdk's canonical defaults.
- The CORS `Access-Control-Allow-Headers` allow-list now includes `X-BSV-Topic` (for canonical GASP routes).

## Operator-visible diagnostics

- **Boot-warning banner** if legacy `ovl:` keys are present without matching `ovl3:` records — fires on every restart until `anvil overlay-migrate` runs (cannot be silenced; see the migration guide).
- **Federation summary log line** at boot when `EnableGASPSync=true`.
- **CORS allow-list** test pinned in `internal/api/cors_canonical_test.go` so future surface changes can't silently drop required headers.

## App-layer migrations

| App | Effort | Status |
|---|---|---|
| Anvil-Swap | 1-2 days | Pending |
| SendBSV-Foundry | 2-4 hours (no changes required if using legacy `/overlay/*` shim) | Pending |
| SendBSV-Wallet | 1 day (paymail via two-step path) | Pending |

The internal migration tracker for these apps is at `docs/internal/APP_MIGRATION_TODO.md` (not shipped in the binary).

## Codex review trail

v3.0.0 closed 9 Codex review cycles clean during development:

`14a2d703` · `4e45ac06` · `c62abe3d` · `16624e3045f4f808` · `8b025722ece11767` · `93c0fe5a44610be1` · `077b962a02931dce` · `51bd511ccdb6f022` · `5741981d5028ea7c` · `86b6c0b969f87286` · `d671fa17fe5cc746` · `fe9707876f5618ca` · `2968609c62a2eb51` · `3a9624c1312037f8` · `f9addfb917695695` · `09ddf00c90061eac` · `9730ed97b8e75d6c` · `6daa58cb1a6f43e4` · `18af38d602483289` · `eea841a080448a49` · `c0de9d28e77cf578` · `af6f0eb413563048` · `cb6ce43d5e579dcf`

Notable W-10 (federation) finds: per-tx revocation strategy instead of concatenated InputBEEF, SDKBroadcaster admission semantics (local-mempool-admit = success, ARC = best-effort), BEEF-empty hydration preserves TopicOrService via local SHIP/SLAP record lookup.

## Test coverage

~144 real-engine production-path tests across federation, GASP routes, storage adapter, lookup services, and admission paths. All 12 W-10-affected packages race-clean under `go test -race -count=1`.

Conformance suite holds at PASS:38/80 (identical to W-6 baseline) — fixture-driven, not engine-driven; the "PASS surge" workstream that would register ts-stack topic managers + run against the live engine is explicitly out of v3.0.0 scope.

## Build

- Go toolchain: 1.26.3
- `bsv-blockchain/go-overlay-services` v1.3.1
- `bsv-blockchain/go-overlay-discovery-services` v0.3.4
- `bsv-blockchain/go-sdk` v1.2.23

Cross-compile (set via `make build` or the equivalent shell loop):

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -o dist/anvil-linux-amd64 ./cmd/anvil
GOOS=linux GOARCH=arm64 CGO_ENABLED=1 go build -o dist/anvil-linux-arm64 ./cmd/anvil
```

## Known limitations

1. **BEEF-empty post-migration**: legacy admissions migrated by `anvil overlay-migrate` end up with empty BEEF in `beef3:`. `/lookup` drops these results at hydrate time. Either re-submit the affected txs or wait for the future BEEF-fetch workstream. See migration guide § "Known limitation".
2. **Identity attributes query deferred**: `{attributes: {handle, domain}}` returns a deferred-flag Freeform answer. Wallets use the two-step paymail protocol instead. See `docs/internal/SENDBSV_USERS_TOPIC_REQUEST.md` § "Identity attributes deferral (W-11)".
3. **Upstream go-sdk Q16 race**: `go-sdk@v1.2.23/auth/peer.go:976 handleGeneralMessage` has a known race vs `peer.go:285 ToPeer` that manifests under `go test -race` in `internal/gossip`. Pre-existing since v1.2.20, ACCEPTED in every audit, not a v3.0.0 blocker.
4. **Topic ports placement**: UMP + Identity Go implementations live in `internal/overlay/topics/` as transitional placement. Long-term home is upstream `bsv-blockchain/go-overlay-discovery-services` when that repo gains a topic-impl partition.

## Acknowledgements

Federation + canonical adoption work was MCP-driven throughout: brc100-mcp's `docs_catalog` + `read_file` surfaced `go-overlay-discovery-services` (which avoided ~500 LOC of bespoke implementation), and the satoshi-mcp + tools-mcp checkpoints kept the Codex review loop honest. The four MCP servers — brc100-mcp, satoshi-mcp, tools-mcp, mempalace — are not shipped with Anvil but are the reason this release is canonical-aligned rather than canonical-flavored.
