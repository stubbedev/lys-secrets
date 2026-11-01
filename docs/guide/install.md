# Install

Every route gives you the same three things: the `lys-secrets` binary, the user
unit `lys-secrets.service`, and two D-Bus activation files, one for
`org.freedesktop.secrets` and one for `dev.stubbe.lys.Vault1`, which start the
unit when a client calls.

Disable any other Secret Service first; see
[Sharing the name](/guide/how-it-works#sharing-the-name). Existing gnome-keyring
keyrings are not imported.

## NixOS

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

The module hands the package to D-Bus and systemd and starts the user unit with
the graphical session. Evaluation fails with a message if
`services.gnome.gnome-keyring.enable` is also set.

## home-manager

Import `lys-secrets.homeManagerModules.default` and set:

```nix
services.lys-secrets.enable = true;
```

This does the same at the user level. It does not check for gnome-keyring, so
do not run gnome-keyring's secrets component as well.

The options of both modules are under [Configuration](/guide/configuration#nix-options).

## Debian, Ubuntu and Fedora

Each [release](https://github.com/stubbedev/lys-secrets/releases) carries an
x86_64 `.deb` and `.rpm` and a `SHA256SUMS` file:

```sh
sha256sum --check --ignore-missing SHA256SUMS
sudo apt install ./lys-secrets_<version>_amd64.deb
sudo dnf install ./lys-secrets-<version>-1.<dist>.x86_64.rpm
```

A package installs `/usr/bin/lys-secrets`, the user unit, and reference copies
of the activation files under `/usr/share/lys-secrets/`. Installing one enables
nothing, since gnome-keyring may claim the same name. Disable gnome-keyring's
secrets component, then:

```sh
systemctl --user enable --now lys-secrets
```

To have clients start it on demand too, copy the activation files:

```sh
install -D -m 0644 -t ~/.local/share/dbus-1/services/ \
  /usr/share/lys-secrets/org.freedesktop.secrets.service \
  /usr/share/lys-secrets/dev.stubbe.lys.Vault1.service
```

## Other distributions

The release's `lys-secrets-<version>-x86_64-linux.tar.gz` holds the static
binary, the licence, the unit and both activation files. The unit and the
activation files name `/usr/bin/lys-secrets`, so the binary goes there:

```sh
tar xzf lys-secrets-<version>-x86_64-linux.tar.gz
cd lys-secrets-<version>-x86_64-linux
sudo install -m 0755 lys-secrets /usr/bin/lys-secrets
sudo install -m 0644 lys-secrets.service /usr/lib/systemd/user/
```

The unit can go in `~/.config/systemd/user/` instead. Then run
`systemctl --user daemon-reload` and continue with `systemctl --user enable --now
lys-secrets` as above, copying the activation files from the unpacked archive.

## Check it

[Getting started](/guide/getting-started#install-and-start-it) shows how to see
that it answers.
