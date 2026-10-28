# lys-secrets dev tasks.

# List all recipes with their descriptions.
default:
    @just --list

# Run every release gate in order: vet, lint, test, race, build.
check: vet lint test race build

# Static analysis of every package with go vet.
vet:
    go vet ./...

# Lint without changing anything: formatting and golangci-lint
# (settings in .golangci.yml).
lint:
    golangci-lint fmt --diff
    golangci-lint run

# Run the test suite in a random order, so a test that leans on state an
# earlier one left behind fails instead of passing by declaration order.
test *args:
    go test -shuffle=on ./... {{args}}

# Run the test suite under the race detector, which needs cgo.
race:
    CGO_ENABLED=1 go test -race -shuffle=on ./...

# Compile-check every package; the output is discarded.
build:
    go build -o /dev/null ./...

# Build the release binary into dist/: static and stripped, as the
# archive and the Debian and RPM packages ship it.
dist:
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o dist/ ./cmd/lys-secrets

# Format every Go source in place (gofumpt and gci via golangci-lint).
fmt:
    golangci-lint fmt

# Recompute nix/package.nix's vendorHash after a go.mod change: the
# vendor derivation is fixed-output, so a stale hash reuses the old
# module set instead of reporting the new one.
vendor-hash:
    #!/usr/bin/env bash
    set -euo pipefail
    file=nix/package.nix
    sed -i 's|vendorHash = "sha256-[^"]*";|vendorHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";|' "$file"
    got=$( (nix build .#default --no-link 2>&1 || true) | sed -n 's/^ *got: *\(sha256-[^ ]*\).*/\1/p' | head -1)
    if [ -z "$got" ]; then echo "no hash reported" >&2; exit 1; fi
    sed -i "s|vendorHash = \"sha256-[^\"]*\";|vendorHash = \"$got\";|" "$file"
    echo "vendorHash = $got"
