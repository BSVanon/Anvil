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

### 4. Update install URL in README

Update the one-liner in `README.md` to point at the new tag:

```bash
curl -fsSL https://raw.githubusercontent.com/BSVanon/Anvil/vX.Y.Z/scripts/install.sh | sudo bash
```

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
curl -fsSL https://raw.githubusercontent.com/BSVanon/Anvil/v1.0.2/scripts/install.sh | sudo bash
```

Or clone and build from source:

```bash
git clone https://github.com/BSVanon/Anvil.git
cd Anvil
git checkout v1.0.2
make build
sudo ./anvil deploy --nodes a --seed wss://anvil.sendbsv.com/mesh
```
