# Getting started

lys-secrets serves two D-Bus names:

- `org.freedesktop.secrets`, the
  [Secret Service API](https://specifications.freedesktop.org/secret-service-spec/latest/),
  for libsecret (`secret-tool`), Chromium and Electron apps,
  `git-credential-libsecret`, python-secretstorage and lys-shell's Secret portal.
- `dev.stubbe.lys.Vault1`, your Bitwarden vault, for lys-shell.

## Requirements

- A D-Bus session bus and a systemd user session.
- No other owner of `org.freedesktop.secrets`. If another provider holds it,
  lys-secrets serves only the vault; see
  [Bus names](/guide/how-it-works#bus-names). Existing gnome-keyring keyrings are
  not imported.
- A dialog host serving `dev.stubbe.lys.PortalDialogs1` (lys-shell) for password
  prompts. Without one, a prompt fails, is logged, and the client sees it as
  dismissed. Unlocking through lys-login or `--unlock-fd` needs no dialog.

## Install

Every route installs the `lys-secrets` binary, the user unit
`lys-secrets.service` (`Type=dbus`, wanted by `graphical-session.target`) and
D-Bus activation files for both names.

### NixOS

```nix
{
  inputs.lys-secrets.url = "github:stubbedev/lys-secrets";

  outputs = { nixpkgs, lys-secrets, ... }: {
    nixosConfigurations.example = nixpkgs.lib.nixosSystem {
      modules = [
        lys-secrets.nixosModules.default
        { services.lys-secrets.enable = true; }
      ];
    };
  };
}
```

Evaluation fails if `services.gnome.gnome-keyring.enable` is also set, or if
`sshAgent.enable` and `programs.ssh.startAgent` are both set.

### home-manager

Import `lys-secrets.homeManagerModules.default` and set
`services.lys-secrets.enable = true;`. It installs the unit, activation files and
a drop-in with the configured flags. It does not check for gnome-keyring.

Options for both modules: [Nix options](/guide/configuration#nix-options).

### Debian, Ubuntu, Fedora

Each [release](https://github.com/stubbedev/lys-secrets/releases) has a `.deb`
and `.rpm` for x86_64 and aarch64, and `SHA256SUMS`:

```sh
sha256sum --check --ignore-missing SHA256SUMS
sudo apt install ./lys-secrets_<version>_amd64.deb      # arm64: _arm64.deb
sudo dnf install ./lys-secrets-<version>-1.<dist>.x86_64.rpm  # .aarch64.rpm
systemctl --user enable --now lys-secrets
```

A package installs `/usr/bin/lys-secrets`, the `/usr/bin/pinentry-lys` link, the
user unit, and the activation files under `/usr/share/lys-secrets/`. It enables
nothing. For on-demand activation, copy the activation files:

```sh
install -D -m 0644 -t ~/.local/share/dbus-1/services/ \
  /usr/share/lys-secrets/org.freedesktop.secrets.service \
  /usr/share/lys-secrets/dev.stubbe.lys.Vault1.service
```

### Other distributions

`lys-secrets-<version>-<arch>-linux.tar.gz` (`x86_64` or `aarch64`) holds the
static binary, licence, unit and activation files. The unit and activation files
expect `/usr/bin/lys-secrets`:

```sh
tar xzf lys-secrets-<version>-<arch>-linux.tar.gz
cd lys-secrets-<version>-<arch>-linux
sudo install -m 0755 lys-secrets /usr/bin/lys-secrets
sudo install -m 0644 lys-secrets.service /usr/lib/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now lys-secrets
```

The unit may go in `~/.config/systemd/user/` instead. Copy the activation files
as above. The archive has no `pinentry-lys` link; use `lys-secrets pinentry` or
create the link.

## Check it

```sh
busctl --user call org.freedesktop.secrets /org/freedesktop/secrets org.freedesktop.DBus.Peer Ping
journalctl --user -u lys-secrets -b
```

The log says `serving org.freedesktop.secrets and dev.stubbe.lys.Vault1`, or
`org.freedesktop.secrets is already served by <owner>` when another provider
holds the name.

## First secret

Log in through lys-login or unlock at its lock screen. This creates the `login`
collection with your session password and points `default` at it if `default` is
unset.

```sh
secret-tool store --label='An example' app example
secret-tool lookup app example
secret-tool clear app example
```

If a client creates the default collection before `login` exists, lys-secrets
asks for a new password for it. The session password does not open that
collection, and a later `login` collection does not take over `default`.

## Bitwarden

Log in from lys-shell's
[bitwarden module](https://stubbedev.github.io/lys-shell/config/modules/bitwarden).
lys-secrets has no login command. To expose one vault folder to libsecret clients,
set [`--vault-collection-folder`](/guide/configuration#flags).
