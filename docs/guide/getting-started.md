# Getting started

lys-secrets is the lys desktop's freedesktop
[Secret Service](https://specifications.freedesktop.org/secret-service-spec/latest/)
(`org.freedesktop.secrets`). Applications store secrets through it the way they
would through gnome-keyring, KeePassXC or KWallet: libsecret (`secret-tool`),
Chromium and Electron apps, git's `git-credential-libsecret`,
python-secretstorage and the portal's per-app secrets for sandboxed apps.

It also holds your Bitwarden vault, which lys-shell shows and uses.

## What you need

- A D-Bus session bus and a systemd user session. The packaged unit is a user
  unit of `Type=dbus`.
- No other provider of `org.freedesktop.secrets`. Only one program can own the
  name; see [Sharing the name](/guide/how-it-works#sharing-the-name).
- A dialog host for password prompts. lys-secrets draws no UI of its own and
  asks through `dev.stubbe.lys.PortalDialogs1`, which lys-shell serves. Without
  one, a prompt fails, the log says so, and the client sees it as dismissed.
  Unlocking through [lys-login](https://github.com/stubbedev/lys-login) or
  [`--unlock-fd`](/guide/configuration#command-line-flags) needs no dialog.

## Install and start it

Follow [Install](/guide/install) for NixOS, home-manager, Debian, Ubuntu, Fedora
or a plain archive. Then check who answers:

```sh
busctl --user call org.freedesktop.secrets /org/freedesktop/secrets org.freedesktop.DBus.Peer Ping
journalctl --user -u lys-secrets -b
```

The log should say `serving org.freedesktop.secrets and dev.stubbe.lys.Vault1`.
If it says `org.freedesktop.secrets is already served by` someone, another
provider got there first and lys-secrets serves the vault alone.

## Your first secret

Log in through lys-login or unlock the session at its lock screen first. The
`login` collection is then created with your session password and becomes the
default collection, so it opens by itself from then on.

```sh
secret-tool store --label='An example' app example
secret-tool lookup app example
secret-tool clear app example
```

`secret-tool store` reads the secret from the terminal.

If a client stores a secret before any default collection exists, lys-secrets
asks for a new password through the dialog and creates a default collection
with it. The session password does not open that one, and a `login` collection
made later does not replace it as the default. See
[Unlocking](/guide/how-it-works#unlocking).

## Your Bitwarden vault

Log in from lys-shell's
[bitwarden module](https://stubbedev.github.io/lys-shell/config/modules/bitwarden).
lys-secrets itself has no login command. To let libsecret clients read one vault
folder, set [`--vault-collection-folder`](/guide/configuration#command-line-flags).

## Read next

- [Configuration](/guide/configuration): the flags, the Nix options and the
  files lys-secrets keeps.
- [How secrets are protected](/guide/security): what the encryption covers, and
  what it does not.
