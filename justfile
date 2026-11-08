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
    go test ${LYS_TEST_ARGS--shuffle=on} ./... {{args}}

# Run the test suite under the race detector, which needs cgo.
race:
    CGO_ENABLED=1 go test -race ${LYS_TEST_ARGS--shuffle=on} ./...

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

# Set nix/package.nix's vendorHash to the hash of the modules go.sum pins.
vendor-hash:
    nix run github:stubbedev/lys-ci#vendor-hash -- nix/package.nix .#default.goModules

# Tag the current commit as the next release and push it, refusing anything but
# a clean default branch whose CI succeeded.
release-patch:
    nix run github:stubbedev/lys-ci#release -- patch

release-minor:
    nix run github:stubbedev/lys-ci#release -- minor

release-major:
    nix run github:stubbedev/lys-ci#release -- major

# Move every lys module and flake input to its head, then the vendor hash.
bump-lys:
    nix run github:stubbedev/lys-ci#bump-lys
