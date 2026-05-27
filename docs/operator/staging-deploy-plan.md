# Staging Deploy Plan — v3.0.0

Purpose: pre-flight validation of the v3.0.0 binary against the two failure modes a real ship cares about — (1) does the v2 → v3 upgrade migrate cleanly on a real LevelDB with non-zero data, and (2) does canonical BRC-88 SHIP/SLAP federation actually discover other Anvil nodes via `DEFAULT_SLAP_TRACKERS`?

Anvil's production runs on **anvil-a + anvil-b** (dual-node mesh), both currently on v2.3.2. This plan validates v3.0.0 on a separate staging VPS first, then performs an in-place upgrade on production.

## Two-phase plan

Robert and I discussed the trade-off earlier:

- **Phase A — Fresh staging deploy** validates that canonical SHIP/SLAP discovers a brand-new node via `DEFAULT_SLAP_TRACKERS`. This is the federation surface that's new in v3.0.0.
- **Phase B — In-place upgrade on anvil-a + anvil-b** validates that the v2 → v3 migration runs cleanly on real production-shaped data + that the upgraded nodes find each other on the dual-node mesh via canonical federation.

Both phases use the SAME v3.0.0 binary. Phase A confirms federation. Phase B confirms migration. Order matters: Phase A first means we don't risk production until federation is proven.

## Phase A — Fresh staging deploy

### Prerequisites

- A staging VPS with public IPv4 + DNS pointing at it (`anvil-staging.your-domain.example` or similar)
- A funded BSV WIF for the operator wallet (small balance, < 1k sats sufficient for SHIP/SLAP advertisement transactions during testing)
- Outbound HTTPS to `overlay-us-1.bsvb.tech`, `overlay-eu-1.bsvb.tech`, `overlay-ap-1.bsvb.tech`, `users.bapp.dev`, plus ARC endpoint (`arc.gorillapool.io` or your configured ARC)

### Steps

1. **Build the v3.0.0 binary** with the Go 1.26.3 toolchain:

   ```bash
   cd /home/robert/Documents/Anvil
   CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o dist/anvil-linux-amd64 ./cmd/anvil
   ./dist/anvil-linux-amd64 --version  # should print v3.0.0-rc (until tag)
   ```

2. **Transfer binary + example config to staging VPS — SFTP only**:

   `scp` is blocked by VPS network policy. Use the tarball-staging convention from `BUG_HUNTS/README.md` § "File transfers to the VPS — SFTP only".

   Local — bundle the artifacts into a tarball under the SFTP staging dir:

   ```bash
   mkdir -p /tmp/anvil-v3-staging
   cp dist/anvil-linux-amd64 /tmp/anvil-v3-staging/anvil
   cp anvil.example.toml /tmp/anvil-v3-staging/anvil.toml
   tar -czf /home/robert/SFTP_trnsfrs/anvil-v3.0.0-staging-$(date +%Y%m%d).tar.gz \
       -C /tmp/anvil-v3-staging .
   ```

   Robert (local terminal) — SFTP the tarball to the VPS landing dir:

   ```bash
   sftp <vps-user>@<staging-vps-host>
   sftp> cd /home/<vps-user>
   sftp> put anvil-v3.0.0-staging-YYYYMMDD.tar.gz
   sftp> bye
   ```

   Robert (VPS via ssh) — extract + install:

   ```bash
   ssh <vps-user>@<staging-vps-host>
   mkdir -p ~/v3-extract && tar -xzf anvil-v3.0.0-staging-YYYYMMDD.tar.gz -C ~/v3-extract
   sudo install -m 755 ~/v3-extract/anvil /usr/local/bin/anvil
   sudo mkdir -p /etc/anvil && sudo cp ~/v3-extract/anvil.toml /etc/anvil/anvil.toml
   sudo chown -R anvil:anvil /etc/anvil
   ```

   Then edit `/etc/anvil/anvil.toml` on staging — set `cfg.Identity.WIF`, `cfg.Node.PublicURL = "https://anvil-staging.your-domain.example"`, leave `[overlay] enable_gasp_sync = true` (the default).

3. **Boot the staging daemon**:

   ```bash
   systemctl daemon-reload
   systemctl start anvil
   journalctl -u anvil -f
   ```

4. **Check the boot log lines**:

   - `overlay directory opened (topics=...)`
   - `v3 canonical engine wired (N topics, N lookup services)`
   - `v3 federation wired: N topics syncable via canonical SHIP/SLAP (trackers=4)`
   - No `ANVIL v3 LEGACY DATA DETECTED` banner (this is a fresh install)
   - `wallet initialized`

5. **Wait for first SyncAdvertisements pass** (boot-immediate + 30-minute cadence). The log line `initial SyncAdvertisements failed` would indicate a wallet or broadcaster wiring issue; absence of any error in the first 5 minutes means the publish succeeded.

6. **Verify discovery via canonical trackers**:

   ```bash
   curl -X POST https://overlay-us-1.bsvb.tech/lookup \
     -H "Content-Type: application/json" \
     -d '{"service":"ls_ship","query":{"domain":"https://anvil-staging.your-domain.example"}}'
   ```

   Result should be a `output-list` with one or more entries (the SHIP advertisements our node published, one per active topic — UHRP, DEX-swap, OrdLock, OrdLock-buy, tm_users, tm_identity, tm_kvstore, tm_ship, tm_slap = 9 entries as of v3.1.0; pre-v3.1.0 builds publish 8).

   If empty: wait another 30 minutes (one more SyncAdvertisements cycle) and retry. If still empty after an hour, check the SyncAdvertisements log lines for ARC submit failures.

7. **Verify the GASP routes serve inbound requests**:

   ```bash
   curl -X POST https://anvil-staging.your-domain.example/requestSyncResponse \
     -H "Content-Type: application/json" \
     -H "X-BSV-Topic: tm_uhrp" \
     -d '{"version":1,"since":0}'
   ```

   Should return `{"UTXOList":[],"since":0}` for a fresh node with no admissions.

### Phase A acceptance

Phase A passes when:

- [ ] Daemon boots clean with v3 federation summary line
- [ ] First SyncAdvertisements pass succeeds (no error log)
- [ ] Our node's domain is discoverable via at least one canonical SLAP tracker
- [ ] GASP routes return canonical `{UTXOList:[], since:0}` for empty topics
- [ ] No panics or fatal errors in the first 24 hours of runtime

If any item fails, **do NOT proceed to Phase B**. Investigate, fix, and re-run Phase A.

## Phase B — In-place upgrade on anvil-a + anvil-b

### Prerequisites

- Phase A passed and was stable for at least 24 hours
- A 1-hour maintenance window for each production node
- Backup of `/var/lib/anvil/overlay` on both anvil-a and anvil-b (we will create one during the upgrade anyway, but a pre-existing operational snapshot is best practice)

### Sequence

Upgrade anvil-a first, validate, then anvil-b. Never both simultaneously — the mesh keeps at least one node serving traffic at all times.

For each node:

1. **Stop the daemon**:

   ```bash
   sudo systemctl stop anvil
   ```

2. **Snapshot the overlay directory** (the migration guide's step 2):

   ```bash
   sudo cp -r /var/lib/anvil/overlay /var/lib/anvil/overlay-pre-v3-snapshot
   ```

3. **Transfer + replace the binary**. Same SFTP-only convention as Phase A — `scp` is blocked. If Phase A already transferred a tarball to this VPS, skip the local + SFTP steps and jump to the extract step.

   Local (only if anvil-a/anvil-b aren't already on the same VPS as staging):

   ```bash
   mkdir -p /tmp/anvil-v3-prod
   cp dist/anvil-linux-amd64 /tmp/anvil-v3-prod/anvil
   tar -czf /home/robert/SFTP_trnsfrs/anvil-v3.0.0-prod-$(date +%Y%m%d).tar.gz \
       -C /tmp/anvil-v3-prod .
   ```

   Robert (local) — SFTP push (one per production VPS):

   ```bash
   sftp <vps-user>@anvil-a-host
   sftp> cd /home/<vps-user>
   sftp> put anvil-v3.0.0-prod-YYYYMMDD.tar.gz
   sftp> bye
   # Repeat for anvil-b-host
   ```

   Robert (VPS via ssh) — extract + install:

   ```bash
   ssh <vps-user>@anvil-a-host
   mkdir -p ~/v3-extract && tar -xzf anvil-v3.0.0-prod-YYYYMMDD.tar.gz -C ~/v3-extract
   sudo install -m 755 ~/v3-extract/anvil /usr/local/bin/anvil
   anvil --version  # should print v3.0.0
   ```

4. **Update the config** if needed (the canonical defaults should work, but operators with custom `[overlay]` settings should review):

   ```bash
   sudo -u anvil anvil overlay-migrate -dry-run  # pre-flight count check
   ```

   Look for non-zero `Migrated`, `UnparseableLegacy=0`, `UnparseableKey=0`. If unparseable counts are non-zero, investigate before running the real migration.

5. **Run the migration**:

   ```bash
   sudo -u anvil anvil overlay-migrate
   ```

   Confirm `Migrated` matches the dry-run count.

6. **Start the daemon**:

   ```bash
   sudo systemctl start anvil
   sudo journalctl -u anvil -f
   ```

7. **Validate** (same boot-log checks as Phase A § step 4):

   - No legacy-key banner
   - Federation summary line
   - `wallet initialized`
   - SyncAdvertisements + StartGASPSync goroutines started

8. **Cross-mesh discovery check** — verify anvil-a sees anvil-b (and vice versa) via canonical SHIP/SLAP:

   On anvil-a:

   ```bash
   curl -X POST http://localhost:9333/lookup \
     -H "Content-Type: application/json" \
     -H "x-topics: [\"ls_ship\"]" \
     -d '{"service":"ls_ship","query":{"domain":"https://anvil-b.your-domain.example"}}'
   ```

   Result: `output-list` with at least one entry (anvil-b's SHIP ads).

   If empty after the first SyncAdvertisements cycle (give it 30 min after anvil-b is upgraded too): canonical discovery has a latency tail because both nodes need to publish and the trackers need to index. Worst-case wait: ~60 min after both nodes are up.

9. **Repeat for anvil-b**.

### Phase B acceptance

- [ ] Both anvil-a and anvil-b boot clean on v3.0.0
- [ ] Migration count matches dry-run (`Migrated` = legacy-key count, no unparseable entries)
- [ ] Each node sees the other via canonical SLAP discovery within 60 minutes of the second node coming up
- [ ] No regression in `/listTopicManagers` count (should be 9 topic managers as of v3.1.0: 7 Anvil topics + tm_ship + tm_slap)
- [ ] Existing apps using `/overlay/*` legacy routes still work (Anvil-Swap + SendBSV-Foundry haven't migrated yet; the Lens 2 = 2c shim handles them)
- [ ] 24-hour stability — no panics, no continual error logs, no memory leak signs

## Rollback plan

If Phase B fails on anvil-a, restore from snapshot + revert binary on that one node:

```bash
sudo systemctl stop anvil
sudo rm -rf /var/lib/anvil/overlay
sudo cp -r /var/lib/anvil/overlay-pre-v3-snapshot /var/lib/anvil/overlay
sudo install -m 755 /opt/anvil/anvil-v2.3.2 /usr/local/bin/anvil
sudo systemctl start anvil
```

Do NOT upgrade anvil-b until you understand why anvil-a failed.

If Phase B fails on anvil-b after anvil-a is already on v3: roll BACK anvil-b first (per the rollback above), leave anvil-a on v3. The mesh continues to function in mixed mode because the legacy `/overlay/*` shim on v3 anvil-a accepts traffic from v2 anvil-b unchanged.

## What this plan does NOT cover

- **Disaster recovery from corruption**: if the LevelDB itself gets corrupted during the migration (extremely unlikely; the migration is single-pass + uses per-record atomic batches), restore from the snapshot.
- **Performance benchmarking**: v3 should perform comparably to v2 for the same workload, but neither this plan nor the test suite measures throughput. Add a follow-up benchmark if performance is a concern in your operating context.
- **App-side smoke testing**: Anvil-Swap, SendBSV-Foundry, and SendBSV-Wallet need their own smoke plans against v3. Those live in the respective repos, not here.

## Sign-off

Phase A + Phase B both pass → notify Robert and queue the W-8.5 `git tag v3.0.0` + `gh release create` step. Tagging happens only with Robert's explicit approval per the `feedback_no_push_without_consent` standing rule.
