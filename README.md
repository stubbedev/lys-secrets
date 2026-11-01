<p align="center">
  <img src="docs/public/lys-secrets.svg" width="160" alt="lys-secrets">
</p>

<h1 align="center">lys-secrets</h1>

<p align="center">
  The lys desktop's freedesktop
  <a href="https://specifications.freedesktop.org/secret-service-spec/latest/">Secret Service</a>,
  so a lys desktop needs no gnome-keyring, KeePassXC or KWallet for app secrets.
</p>

<p align="center">
  <a href="https://github.com/stubbedev/lys-secrets/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/stubbedev/lys-secrets/ci.yml?branch=main&style=for-the-badge&label=CI" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=for-the-badge" alt="MIT license"></a>
  <a href="https://stubbedev.github.io/lys-secrets/"><img src="https://img.shields.io/badge/docs-stubbedev.github.io-informational?style=for-the-badge" alt="Documentation"></a>
</p>

libsecret (`secret-tool`), Chromium and Electron apps, git's
`git-credential-libsecret`, python-secretstorage and the portal's per-app secrets
for sandboxed apps all keep their secrets in it, encrypted at rest. It also holds
your Bitwarden vault for lys-shell. It is a small process of its own, separate from
the shell, and asks for passwords through the desktop's dialogs.

As with gnome-keyring, every program running as you can read an unlocked
collection. The site says
[how secrets are protected](https://stubbedev.github.io/lys-secrets/guide/security),
and where that stops.

## Install

Only one program can own `org.freedesktop.secrets`, so disable any other provider
first.

- **NixOS or home-manager:** import `lys-secrets.nixosModules.default` or
  `lys-secrets.homeManagerModules.default` from this flake and set
  `services.lys-secrets.enable = true;`.
- **Debian, Ubuntu and Fedora:** install the `.deb` or `.rpm` from a
  [release](https://github.com/stubbedev/lys-secrets/releases), then run
  `systemctl --user enable --now lys-secrets`.
- **Other distributions:** see
  [Install](https://stubbedev.github.io/lys-secrets/guide/install).

## Usage

Log in through lys-login or unlock the session at its lock screen, which unlocks
the `login` collection with your session password. Then any Secret Service client
works:

```sh
secret-tool store --label='An example' app example
secret-tool lookup app example
```

## Documentation

**<https://stubbedev.github.io/lys-secrets/>** has
[getting started](https://stubbedev.github.io/lys-secrets/guide/getting-started),
[configuration](https://stubbedev.github.io/lys-secrets/guide/configuration),
[how it works](https://stubbedev.github.io/lys-secrets/guide/how-it-works) and
[development](https://stubbedev.github.io/lys-secrets/guide/development).

## The lys family

lys-secrets is part of the lys desktop, with
[lys-shell](https://github.com/stubbedev/lys-shell),
[lys-wm](https://github.com/stubbedev/lys-wm),
[lys-ui](https://github.com/stubbedev/lys-ui),
[lys-lib](https://github.com/stubbedev/lys-lib),
[lys-login](https://github.com/stubbedev/lys-login),
[lys-splash](https://github.com/stubbedev/lys-splash) and
[lys-polkit](https://github.com/stubbedev/lys-polkit).
