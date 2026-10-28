# lys-secrets

lys-secrets is the lys desktop's freedesktop Secret Service
(`org.freedesktop.secrets`): collections encrypted at rest, unlocked at
login by lys-login, with prompts through lys-shell's dialogs. It moves
here from lys-shell.

The implementation is tracked in the repository's issues.

## Recipes

| Recipe | What it does |
| --- | --- |
| `just check` | Every release gate in order: vet, lint, test, build |
| `just vet` | Static analysis with `go vet` |
| `just lint` | `golangci-lint run` against the strict config in `.golangci.yml` |
| `just test` | `go test ./...` |
| `just build` | Compile-check every package |
| `just fmt` | Format every Go source in place |

Every dev tool (Go toolchain pinned to the version go.mod declares, gopls,
golangci-lint, delve, just, git, gh) comes from the flake: `direnv allow`
on entry, or `nix develop` explicitly. `GOTOOLCHAIN=local` keeps the compiler
from downloading itself.

## Nix

- `nix build` builds the package (`nix/package.nix`; the dev shell is
  `nix/shell.nix`, both imported by `flake.nix`; add a `vendorHash`
  once go.mod grows dependencies)
- `nix run` runs it
- `nix fmt` formats the nix files with alejandra

## CI

`.github/workflows/security.yml` runs CodeQL (Go and GitHub Actions), Grype and
govulncheck, uploading findings to code scanning; dependency review gates
pull requests. Dependabot keeps the module and the workflows current.

## Linting

`.golangci.yml` starts from the standard linter set and layers on bodyclose,
copyloopvar, errorlint, gosec, intrange, misspell, modernize, nolintlint,
perfsprint, revive, unconvert, unparam, usestdlibvars and whitespace, with
gofumpt and gci as formatters. No issue caps: every finding fails the build.
