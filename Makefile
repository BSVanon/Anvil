# Anvil build targets
# CGO_ENABLED=1 is REQUIRED — go-sqlite3 (used by wallet-toolbox) needs it.
# Building with CGO_ENABLED=0 produces a binary that silently disables
# the wallet and mesh, which breaks everything.

VERSION := $(shell grep 'const Version' internal/version/version.go | cut -d'"' -f2)
LDFLAGS := -s -w

.PHONY: build release-amd64 release-arm64 release checksums test vet clean

build:
	CGO_ENABLED=1 go build -ldflags="$(LDFLAGS)" -o anvil ./cmd/anvil

release-amd64:
	CGO_ENABLED=1 CC=x86_64-linux-gnu-gcc GOOS=linux GOARCH=amd64 \
		go build -ldflags="$(LDFLAGS)" -o dist/anvil-linux-amd64 ./cmd/anvil

release-arm64:
	CGO_ENABLED=1 CC=aarch64-linux-gnu-gcc GOOS=linux GOARCH=arm64 \
		go build -ldflags="$(LDFLAGS)" -o dist/anvil-linux-arm64 ./cmd/anvil

# Generate SHA256 checksums for release binaries.
# Upload dist/checksums.txt alongside binaries in GitHub Releases.
checksums:
	cd dist && sha256sum anvil-linux-amd64 anvil-linux-arm64 > checksums.txt
	@echo "Checksums written to dist/checksums.txt"
	@cat dist/checksums.txt

release: release-amd64 release-arm64 checksums
	@echo "Built v$(VERSION): dist/anvil-linux-amd64 dist/anvil-linux-arm64 dist/checksums.txt"

test:
	go test -count=1 -timeout 120s ./...

vet:
	go vet ./...

clean:
	rm -f anvil dist/anvil-linux-* dist/checksums.txt
