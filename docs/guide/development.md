# Development

## Go packages

| Package | Contents | Used by |
| --- | --- | --- |
| `vault` | `dev.stubbe.lys.Vault1` contract, daemon and client | lys-shell's vault widget, launcher mode and network agent |
| `client` | Secret Service client: lookup, store, delete, browse collections and items, `ChangeLock`; plain (`Open`) or DH (`OpenEncrypted`) session | lys-shell's Secret portal, lys-settings' passwords page, the vault's session store |
| `control` | Unlock socket client (`Unlock`, `Rekey`) and server | lys-login |
| `transport` | The `plain` and DH secret transports | `client`, the service |
| `secretstest` | The real Secret Service on a test bus, with scripted password prompts | Consumers' tests |

Everything else is under `internal/`.

## Recipes

| Recipe | Effect |
| --- | --- |
| `just check` | `vet`, `lint`, `test`, `race`, `build` in order |
| `just vet` | `go vet ./...` |
| `just lint` | `golangci-lint fmt --diff` and `golangci-lint run` (`.golangci.yml`) |
| `just test` | `go test -shuffle=on ./...` |
| `just race` | Tests under the race detector |
| `just build` | Compile every package |
| `just dist` | Static, stripped release binary in `dist/` |
| `just fmt` | Format all Go sources |
| `just vendor-hash` | Update `vendorHash` in `nix/package.nix` |
| `just release-patch` / `-minor` / `-major` | Tag and push the next release from a clean default branch with green CI |

`nix develop` (or `direnv allow`) provides the pinned Go toolchain, the lint
tools, dbus for the tests' private buses, and the clients tested against
(secret-tool, python-secretstorage, Chromium, git's libsecret helper).

`nix flake check` builds the package, evaluates both modules and boots a NixOS VM
that checks D-Bus activation under dbus-broker.

## CI and releases

| Workflow | Runs |
| --- | --- |
| `ci.yml` | `just check`, `nix flake check`, and builds and smoke-tests the archive, `.deb` and `.rpm` (`package.yml`, `scripts/ci/`, `packaging/`) |
| `release.yml` | On tag `vX.Y.Z`: packages, `SHA256SUMS` and a GitHub release |
| `security.yml` | CodeQL (Go, Actions), Grype, govulncheck; dependency review on pull requests |
| `vendor-hash.yml` | On pull requests changing `go.mod` or `go.sum`, updates `vendorHash` |
| `docs.yml` | Publishes this site |

Dependabot updates Go modules and workflows.
