# lys-secrets

lys-secrets is the lys desktop's freedesktop
[Secret Service](https://specifications.freedesktop.org/secret-service-spec/latest/)
(`org.freedesktop.secrets`), so a lys desktop needs no gnome-keyring,
KeePassXC or KWallet for app secrets. libsecret (`secret-tool`), Chromium and
Electron apps, git's `git-credential-libsecret`, python-secretstorage and the
portal's per-app secrets for sandboxed apps all keep their secrets in it.

It is a small process of its own, separate from the shell: it links no UI
and asks for passwords through the desktop's dialogs (lys-lib's
`dev.stubbe.lys.PortalDialogs1`, served by lys-shell).

## Enabling it

Only one program can own `org.freedesktop.secrets`. When another provider
already owns it, `lys-secrets` logs which one and exits, so it never takes
the name from gnome-keyring.

The flake's package installs the binary, the user unit
(`lib/systemd/user/lys-secrets.service`) and the D-Bus activation file
(`share/dbus-1/services/org.freedesktop.secrets.lys-secrets.service`); the
modules wire them up:

- **NixOS:** import `lys-secrets.nixosModules.default` and set
  `services.lys-secrets.enable = true;`. It hands the activation file to
  D-Bus and starts the user unit with the graphical session. It cannot be
  combined with `services.gnome.gnome-keyring.enable` (evaluation fails with a
  message).
- **home-manager:** import `lys-secrets.homeManagerModules.default` and set
  `services.lys-secrets.enable = true;` to do the same at the user level. Do
  not run gnome-keyring's secrets component as well.
- **Debian, Ubuntu and Fedora:** each
  [release](https://github.com/stubbedev/lys-secrets/releases) carries a
  `.deb` and an `.rpm` (x86_64) with `/usr/bin/lys-secrets`, the user unit
  and the activation file as a reference copy under `/usr/share/lys-secrets/`.
  Installing one enables nothing. Disable gnome-keyring's secrets component,
  then `systemctl --user enable --now lys-secrets`. To have clients start it
  on demand too, copy
  `/usr/share/lys-secrets/org.freedesktop.secrets.lys-secrets.service` to
  `~/.local/share/dbus-1/services/`.
- **Other distributions:** the release's
  `lys-secrets-<version>-x86_64-linux.tar.gz` holds the static binary, the
  unit and the activation file. Put the binary at `/usr/bin/lys-secrets`,
  the unit in `/usr/lib/systemd/user/` (or `~/.config/systemd/user/`), and
  continue as above.

## Unlocking

The `login` collection is encrypted with your session password:

- **lys-login's lock screen** hands the password it just verified to `lys-secrets`
  over a socket only your user can connect to
  (`$XDG_RUNTIME_DIR/lys-secrets/control`), never over D-Bus. The first
  unlock creates the `login` collection with that password and makes it the
  default.
- **lys-login's greeter** passes it at login instead:
  `lys-secrets --unlock-fd N` reads the password from an inherited descriptor.
- **Anything else** (a restart, another collection, a locked keyring) asks
  through the desktop's password dialog when an app needs a secret. A wrong
  password asks again; cancelling leaves the collection locked.

If `lys-secrets` is not running, the lock screen unlocks a running
gnome-keyring instead, as before.

Changing your login password does not re-encrypt the collection: a
`ChangeLock` request (for example from Seahorse) asks for the new password.

## Access

Every program running as you on your session bus may read an unlocked
collection, as with gnome-keyring. Sandboxed (Flatpak) apps get their secret
through the portal, which identifies them, and their master secrets live in
the `login` collection too.

## Storage

Each collection is one file, `$XDG_DATA_HOME/lys-secrets/<id>.keyring`
(mode 0600), written atomically. Its key is derived from the password with
Argon2id (3 passes over 64 MiB), and the contents are encrypted with
XChaCha20-Poly1305. Only the item ids and SHA-256 hashes of their attributes
are readable without the password, so a locked collection can tell a client
that a matching item exists and needs an unlock; labels, attribute values
and secrets are encrypted. While a collection is unlocked, each secret stays
encrypted in memory and is decrypted only for the request that reads it. The
key lives outside the Go heap, locked against swap where the memlock limit
allows, and the process is not dumpable. The format is described in
`internal/keyring/collection.go`.

Existing gnome-keyring keyrings are not imported.

## Go packages

- `client`: a Secret Service client (lys-shell's Secret portal keeps the
  per-app master secrets through it).
- `control`: the unlock socket's client and server (lys-login unlocks the
  login collection through it).
- `secretstest`: the real Secret Service on a test's private bus, with
  scripted password prompts, for consumers' tests.

Everything else is `internal/`.

## Development

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

The dev shell (`nix develop`, or `direnv allow`) pins the Go toolchain go.mod
names and carries the lint stack, dbus for the tests' private session buses,
and the Secret Service clients the service is checked against (secret-tool,
python-secretstorage, Chromium, git's libsecret credential helper).
`nix flake check` builds the package and evaluates the NixOS and home-manager
modules.

## CI and releases

`.github/workflows/ci.yml` runs `just check` and `nix flake check`, and builds
the archive, the `.deb` and the `.rpm` the way a release does
(`package.yml`, with `scripts/ci/` and `packaging/`), so a packaging break
shows before a tag. Pushing a tag `vX.Y.Z` runs `release.yml`: the same
packages at that version, their `SHA256SUMS`, and a GitHub release with
generated notes.

`.github/workflows/security.yml` runs CodeQL (Go and GitHub Actions), Grype and
govulncheck, uploading findings to code scanning; dependency review gates
pull requests. Dependabot keeps the module and the workflows current.
