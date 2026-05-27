# Operator Migration Guide — v2.3.x → v3.0.0

This is the one-time operator playbook for upgrading an existing Anvil node from any v2.x release to v3.0.0. v3.0.0 is the first release built on the canonical `bsv-blockchain/go-overlay-services` engine, with canonical BRC-88 SHIP/SLAP federation enabled out of the box.

If you are running a fresh v3.0.0 install (no existing v2 LevelDB on disk), most of this guide does not apply — jump to [§ "Fresh install"](#fresh-install).

## TL;DR

1. **Stop the daemon.**
2. **Take a snapshot** of the overlay data directory.
3. **Install the v3.0.0 binary.**
4. **Run `anvil overlay-migrate`** (one-time, idempotent).
5. **Restart the daemon.**
6. **Verify** federation is healthy.

The migration is reversible up until step 5 (you can keep the snapshot and roll back). Once the v3 daemon writes new admissions, the LevelDB has v3-shaped data and a clean rollback requires restoring the snapshot.

## Why a migration is needed

v2.x.x stored admitted overlay outputs under the LevelDB key family `ovl:`. v3.0.0's canonical engine uses `ovl3:` (plus sidecar families: `txi3:`, `topi3:`, `mst3:`, `beef3:`, `anci3:`, `txco3:`, `cons3:`, `appl3:`, `peer3:`). The v3 engine does NOT auto-discover legacy keys at boot — it would not be safe to silently rewrite operator data.

Instead, the v3 binary ships with a dedicated `overlay-migrate` subcommand that walks every `ovl:` entry and writes the equivalent `ovl3:` records plus the lookup-service indexes (`lk_uhrp:`, `lk_dexswap:`, `lk_ordlock:`, `lk_ordlockbuy:`). The original `ovl:` keys are NOT removed — they stay in place so a rollback to v2 still works if anything goes wrong.

v3.0.0 also adds a boot-warning that scans for `ovl:` keys at startup and emits a loud banner if any are present without matching `ovl3:` records. Operators who skip the migrate step will see this banner on every restart until they run it.

## Before you upgrade — read this first

### Known limitation: BEEF-empty post-migration

The v2 engine never persisted BEEF after parsing each admission. The migration reconstructs the `ovl3:` records + lookup indexes from the legacy metadata, but the BEEF sidecar (`beef3:`) is left empty for migrated records.

Practical effect: a migrated record is visible to the engine for re-admission safety (the engine won't accept a duplicate admit of the same outpoint) AND visible in the per-service lookup index (so `/lookup` knows the record exists). But the engine's hydration pipeline at `engine.Lookup` drops formulas whose `output.Beef == nil`, so `/lookup` and `/overlay/query` will NOT surface migrated records until BEEF arrives.

BEEF arrives via:
- The operator re-submitting the original transaction (any wallet with the tx can do this against `/submit`).
- A future "BEEF-fetch" workstream (likely a JungleBus integration) that backfills `beef3:` for legacy txids — out of v3.0.0 scope.

If you have important UTXOs in your legacy data, plan to re-submit them after migration. Most operators do not need to: app-layer wallets re-publish their outputs continuously, and the records become queryable as soon as the next admission arrives.

### Stop the daemon FIRST

The migrate command opens the same LevelDB the daemon uses. If you run it against a live daemon, the daemon will keep writing legacy `ovl:` keys that the migrator doesn't see, and the migration will be incomplete.

Always: `systemctl stop anvil`, then `anvil overlay-migrate`, then restart.

### JungleBus is now backwards-compat-only

v2.x.x used JungleBus to subscribe to on-chain SHIP/SLAP admin tokens for federation discovery. v3.0.0 retires that path in favor of canonical BRC-88 SHIP/SLAP via go-sdk's `LookupResolver` (with `DEFAULT_SLAP_TRACKERS` — Project Babbage's `overlay-us-1.bsvb.tech`, `overlay-eu-1.bsvb.tech`, `overlay-ap-1.bsvb.tech`, and `users.bapp.dev`).

Your existing `[junglebus]` section in `anvil.toml` is still accepted by the parser but has no runtime effect. Safe to leave it; safer to delete it the next time you edit the file.

### v3.0.0 adds new `[overlay]` config

The example config (`anvil.example.toml`) shows the new fields:

```toml
[overlay]
enabled = true
topics = ["anvil:mainnet"]
enable_gasp_sync = true              # canonical BRC-88 federation; default true
# ship_trackers = ["https://overlay-us-1.bsvb.tech"]   # blank → use go-sdk defaults
# slap_trackers = ["https://overlay-us-1.bsvb.tech"]   # blank → use go-sdk defaults
```

You don't need to change anything to opt in. `enable_gasp_sync` defaults to `true`, and the tracker lists default to canonical BSV-A + Babbage endpoints when left blank.

To opt OUT of federation (run as a single-node operator), set `enable_gasp_sync = false`. The GASP HTTP routes (`/requestSyncResponse`, `/requestForeignGASPNode`) remain served either way — the flag only controls outbound advertising + peer sync.

## Step-by-step upgrade

### 1. Stop the daemon

```bash
sudo systemctl stop anvil
```

Verify it's actually stopped:

```bash
systemctl status anvil
ps aux | grep anvil
```

### 2. Snapshot the data directory

Anvil's overlay LevelDB lives at `$cfg.Node.DataDir/overlay/` (typically `/var/lib/anvil/overlay/`).

```bash
sudo cp -r /var/lib/anvil/overlay /var/lib/anvil/overlay-pre-v3-snapshot
```

This snapshot is your rollback safety net. Keep it until you've validated v3 in production for a few days.

### 3. Install the v3.0.0 binary

```bash
anvil upgrade  # if you're using anvil's self-upgrade
```

Or manually:

```bash
curl -L https://github.com/BSVanon/Anvil/releases/download/v3.0.0/anvil-linux-amd64 -o /tmp/anvil
sudo install -m 755 /tmp/anvil /usr/local/bin/anvil
anvil --version  # should print v3.0.0
```

### 4. Run the migration

```bash
sudo -u anvil anvil overlay-migrate
```

The command is idempotent — safe to run multiple times. It prints a summary like:

```
=== overlay-migrate summary ===
  LegacyKeysSeen:    4218
  Migrated:          4218
  AlreadyMigrated:   0   (idempotent skips)
  UnparseableLegacy: 0   (corrupt JSON values)
  UnparseableKey:    0   (key didn't fit ovl:<topic>:<txid>:<vout>)
  LookupBackfilled:  4218 (canonical lk_* index entries written)
  LookupBackfillErr: 0   (lookup-side errors; non-fatal)

Known limitation: migrated records have no BEEF in storage (legacy
engine never stored BEEF after parsing). Canonical /lookup hydrates
each result via Storage.FindOutput(...includeBEEF=true) and drops
entries where output.Beef is nil — so migrated records are present
in ovl3 + lk_* indexes but NOT surfaced via /lookup or /overlay/query
until BEEF arrives (re-submit, JungleBus sync, or a future fetch
command). The migration preserves them for re-admission safety +
for when BEEF eventually shows up.
```

Pre-flight check the run without writing:

```bash
sudo -u anvil anvil overlay-migrate -dry-run
```

If you see `UnparseableLegacy` or `UnparseableKey` non-zero, the migration exits with status 1. Inspect the verbose log:

```bash
sudo -u anvil anvil overlay-migrate -v
```

### 5. Restart the daemon

```bash
sudo systemctl start anvil
sudo journalctl -u anvil -f
```

You should see:

- `overlay directory opened (topics=[anvil:mainnet])`
- `v3 canonical engine wired (9 topics, 9 lookup services)` — UHRP, DEX-swap, OrdLock, OrdLock-buy, tm_ship, tm_slap, tm_users, tm_identity, tm_kvstore (tm_kvstore/ls_kvstore added in v3.1.0; pre-v3.1.0 builds report 8/8).
- `v3 federation wired: N topics syncable via canonical SHIP/SLAP (trackers=4)` — confirms canonical BRC-88 federation is up
- NO `ANVIL v3 LEGACY DATA DETECTED` banner — if you see this, the migration didn't run or didn't complete

### 6. Verify

Quick health check:

```bash
curl http://localhost:9333/health
curl http://localhost:9333/listTopicManagers
curl http://localhost:9333/listLookupServiceProviders
```

The `/listTopicManagers` response should include `tm_users` and `tm_identity` alongside the existing 4 + canonical 2 (`tm_ship`, `tm_slap`).

Federation health (verify our SHIP/SLAP ads propagated to the canonical trackers):

```bash
curl -X POST https://overlay-us-1.bsvb.tech/lookup \
  -H "Content-Type: application/json" \
  -d '{"service":"ls_ship","query":{"domain":"https://your-anvil-public-url"}}'
```

Empty result means propagation is still pending — give it 30 minutes (the `SyncAdvertisements` cadence) and try again. A populated result means you're discoverable to the wider BSV ecosystem.

## Rollback (if anything goes wrong)

```bash
sudo systemctl stop anvil
sudo rm -rf /var/lib/anvil/overlay
sudo cp -r /var/lib/anvil/overlay-pre-v3-snapshot /var/lib/anvil/overlay
sudo install -m 755 /opt/anvil/anvil-v2.3.2 /usr/local/bin/anvil   # restore old binary
sudo systemctl start anvil
```

This restores both the data and the binary. If you've been writing v3 data for a while, you'll lose those writes — that's why the snapshot matters.

## Fresh install

A fresh install (no `/var/lib/anvil/overlay` exists) does NOT need to run `anvil overlay-migrate`. The boot-warning scan only fires when legacy `ovl:` keys exist without matching `ovl3:` records. On a fresh install, neither family is populated, the warning stays silent, and the engine boots cleanly into v3 native mode.

You may still want to set `[overlay] enable_gasp_sync = true` (the default) so your node participates in canonical federation from boot.

## v3.0.0 application-layer migrations

Three Anvil-consuming apps need their own one-time updates when their host Anvil node moves to v3:

| App | Estimated work | Notes |
|---|---|---|
| Anvil-Swap | 1-2 days | DEX swap broker, uses the canonical `/lookup` route with the new `output-list` BEEF wire format. |
| SendBSV-Foundry | 2-4 hours | Coin tracking, uses `/overlay/lookup` legacy shim (unchanged through v3.0.0 under Lens 2 = 2c — no app changes required). |
| SendBSV-Wallet | 1 day | Paymail handle resolution; v3.0.0 supports `identityKey` queries fully. Wallet uses two-step paymail (`.well-known/bsvalias` HTTP gateway → identityKey → `ls_identity`). Overlay-native `{attributes}` query remains deferred (W-11) — not delivered in v3.1.0 (which shipped tm_kvstore instead); still unscheduled. |

The apps' migration trackers live at `docs/internal/APP_MIGRATION_TODO.md` (internal — not shipped in the v3 binary).

## Support

If anything goes wrong during the upgrade, the relevant logs are:

- `journalctl -u anvil --since "1 hour ago"` — daemon boot + runtime
- `anvil overlay-migrate -v` — verbose migration trace
- `anvil doctor` — diagnostic snapshot

Report issues at https://github.com/BSVanon/Anvil/issues with the binary version (`anvil --version`), the migrate summary output, and the relevant journalctl output.
