<p align="center">
  <img src="docs/public/lys-secrets.svg" width="160" alt="lys-secrets">
</p>

<h1 align="center">lys-secrets</h1>

<p align="center">
  The lys desktop's freedesktop
  <a href="https://specifications.freedesktop.org/secret-service-spec/latest/">Secret Service</a>
  and Bitwarden vault.
</p>

<p align="center">
  <a href="https://github.com/stubbedev/lys-secrets/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/stubbedev/lys-secrets/ci.yml?branch=main&style=for-the-badge&label=CI" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=for-the-badge" alt="MIT license"></a>
  <a href="https://stubbedev.github.io/lys-secrets/"><img src="https://img.shields.io/badge/docs-stubbedev.github.io-informational?style=for-the-badge" alt="Documentation"></a>
</p>

lys-secrets serves `org.freedesktop.secrets` for libsecret (`secret-tool`),
Chromium and Electron apps, `git-credential-libsecret`, python-secretstorage and
the Secret portal, with collections encrypted at rest. It also serves your
Bitwarden vault (`dev.stubbe.lys.Vault1`) to lys-shell, and can act as SSH agent
and GnuPG pinentry. Password prompts use the desktop's dialogs.

Any program running as you can read an unlocked collection; see
[How secrets are protected](https://stubbedev.github.io/lys-secrets/guide/security).

## Install

Disable any other Secret Service provider first.

- **NixOS / home-manager:** import `lys-secrets.nixosModules.default` or
  `lys-secrets.homeManagerModules.default` and set
  `services.lys-secrets.enable = true;`.
- **Debian, Ubuntu, Fedora:** install the `.deb` or `.rpm` from a
  [release](https://github.com/stubbedev/lys-secrets/releases), then
  `systemctl --user enable --now lys-secrets`.
- **Others:** see
  [Getting started](https://stubbedev.github.io/lys-secrets/guide/getting-started).

## Usage

Log in through lys-login, or unlock at its lock screen, to unlock the `login`
collection. Then:

```sh
secret-tool store --label='An example' app example
secret-tool lookup app example
```

## Documentation

<https://stubbedev.github.io/lys-secrets/>

## The lys family

[lys-shell](https://github.com/stubbedev/lys-shell),
[lys-wm](https://github.com/stubbedev/lys-wm),
[lys-ui](https://github.com/stubbedev/lys-ui),
[lys-lib](https://github.com/stubbedev/lys-lib),
[lys-login](https://github.com/stubbedev/lys-login),
[lys-splash](https://github.com/stubbedev/lys-splash),
[lys-polkit](https://github.com/stubbedev/lys-polkit).
