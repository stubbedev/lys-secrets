# Development

## Go packages

| Package | What it is | Who uses it |
| --- | --- | --- |
| `vault` | The Bitwarden vault's D-Bus contract and client | lys-shell's vault widget, launcher mode and network agent |
| `client` | A Secret Service client | lys-shell's Secret portal, for per-app master secrets |
| `control` | The unlock socket's client and server | lys-login, to unlock the `login` collection |
| `secretstest` | The real Secret Service on a test's private bus, with scripted password prompts | Consumers' tests |

Everything else is `internal/`.

## Recipes

| Recipe | What it does |
| --- | --- |
| `just check` | Every release gate in order: vet, lint, test, race, build |
| `just vet` | Static analysis with `go vet` |
| `just lint` | Formatting and `golangci-lint run` against `.golangci.yml` |
| `just test` | `go test -shuffle=on ./...` |
| `just race` | The suite under the race detector |
| `just build` | Compile-check every package |
| `just dist` | The release binary in `dist/`, static and stripped |
| `just fmt` | Format every Go source in place |
| `just vendor-hash` | Recompute `nix/package.nix`'s `vendorHash` after a go.mod change |

The dev shell (`nix develop`, or `direnv allow`) pins the Go toolchain go.mod names
and carries the lint stack, dbus for the tests' private session buses, and the
Secret Service clients the service is checked against: secret-tool,
python-secretstorage, Chromium and git's libsecret credential helper.

`nix flake check` builds the package, evaluates the NixOS and home-manager modules,
and boots a NixOS VM that checks D-Bus activation under dbus-broker.

## CI and releases

`.github/workflows/ci.yml` runs `just check` and `nix flake check`, and builds the
archive, the `.deb` and the `.rpm` the way a release does (`package.yml`, with
`scripts/ci/` and `packaging/`), installing each package to smoke-test it, so a
packaging break shows before a tag. Pushing a tag `vX.Y.Z` runs `release.yml`: the
same packages at that version, their `SHA256SUMS`, and a GitHub release with
generated notes.

`.github/workflows/security.yml` runs CodeQL (Go and GitHub Actions), Grype and
govulncheck, uploading findings to code scanning; dependency review gates pull
requests. Dependabot keeps the module and the workflows current.

`.github/workflows/docs.yml` publishes this site.
