# Releasing Anvil

How to cut a release with verified install. Every release must follow this process so the one-liner install stays secure.

## Supply chain security model

The install script (`scripts/install.sh`) is served from GitHub, not from a VPS. This means:

- **Compromising the VPS does not compromise the installer.** The script URL points at `raw.githubusercontent.com` at a specific tag, which is immutable.
- **The binary is verified.** The install script downloads both the binary and `checksums.txt` from the same GitHub Release, then verifies SHA256 before executing.
- **All source is public.** Anyone can audit the script, build from source, and verify the binary matches.

An attacker would need to compromise GitHub (or the repo owner's credentials) to tamper with the install. This is a much higher bar than compromising a VPS.

## Release steps

### 1. Bump version

Edit `internal/version/version.go`:

```go
const Version = "X.Y.Z"
```

### 2. Build release binaries + checksums

```bash
make release
```

This produces:
- `dist/anvil-linux-amd64`
- `dist/anvil-linux-arm64`
- `dist/checksums.txt` (SHA256 hashes of both binaries)

### 3. Verify checksums match

```bash
cd dist && sha256sum -c checksums.txt
```

### 4. Update every hardcoded version/install pin

The `Version` constant from step 1 is the single source of truth for the
running binary, but these files separately hardcode the release tag as a
literal string and are not derived from it. Find them with
`git grep -n "<previous version, e.g. 3.4.0>"` and update each by hand so all
three point at the same new `vX.Y.Z` tag:

- **`README.md`** — the one-liner install command in the "Install" section:
  ```bash
  curl -fsSL https://raw.githubusercontent.com/BSVanon/Anvil/vX.Y.Z/scripts/install.sh | sudo bash
  ```
- **`scripts/install.sh`** — the same one-liner, in the "Secure install" comment near the top of the file.
- **`RELEASING.md`** (this file) — the "For operators who want maximum security" section below hardcodes a pinned curl one-liner and a `git checkout` example; both must track the release you're cutting, not stay on the previous one.

Steps 5–7 below keep the `vX.Y.Z` placeholder because they describe the release process itself, not a specific file to edit.

### 5. Commit, tag, push

```bash
git add -A
git commit -m "Bump version to X.Y.Z"
git tag -a vX.Y.Z -m "vX.Y.Z: <summary>"
git push origin main --tags
```

### 6. Create GitHub Release

```bash
gh release create vX.Y.Z dist/anvil-linux-amd64 dist/anvil-linux-arm64 dist/checksums.txt \
  --title "vX.Y.Z" \
  --notes "Release notes here"
```

Upload all three files: both binaries and `checksums.txt`.

### 7. Verify the install works

On a clean machine (or VM):

```bash
curl -fsSL https://raw.githubusercontent.com/BSVanon/Anvil/vX.Y.Z/scripts/install.sh | sudo bash
```

The installer should show `✓ SHA256 verified` during step 1.

## What the install script does

1. Detects architecture (amd64 or arm64)
2. Downloads binary from `github.com/BSVanon/Anvil/releases/download/vX.Y.Z/anvil-linux-{arch}`
3. Downloads `checksums.txt` from the same release
4. Extracts expected SHA256 for the architecture, computes actual SHA256, compares
5. Aborts with error if mismatch (possible tampering)
6. If verified, installs binary, runs `anvil deploy`, starts systemd service

## For operators who want maximum security

Pin to a specific tag (immutable on GitHub):

```bash
curl -fsSL https://raw.githubusercontent.com/BSVanon/Anvil/v3.5.0/scripts/install.sh | sudo bash
```

Or clone and build from source:

```bash
git clone https://github.com/BSVanon/Anvil.git
cd Anvil
git checkout v3.5.0
make build
sudo ./anvil deploy --nodes a --seed wss://anvil.sendbsv.com/mesh
```
