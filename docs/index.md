---
layout: home

hero:
  name: lys-secrets
  text: The Secret Service for a lys desktop
  tagline: One small process serves org.freedesktop.secrets, so libsecret, Chromium, git and sandboxed apps keep their secrets without gnome-keyring, KeePassXC or KWallet. It holds your Bitwarden vault too.
  image:
    src: /lys-secrets.svg
    alt: lys-secrets
  actions:
    - theme: brand
      text: Get started
      link: /guide/getting-started
    - theme: alt
      text: How secrets are protected
      link: /guide/security
    - theme: alt
      text: GitHub
      link: https://github.com/stubbedev/lys-secrets

features:
  - title: A drop-in provider
    details: secret-tool, python-secretstorage, Chromium and git's libsecret credential helper are checked against the real service in the test suite. It never takes the name from another provider.
  - title: Encrypted at rest
    details: Each collection is one file, its key derived with Argon2id and its contents sealed with XChaCha20-Poly1305. Labels, attribute values and secrets need the password.
  - title: Unlocks with your session
    details: lys-login hands over the password it just verified through a socket only your user can connect to. Everything else asks through the desktop's own password dialog.
  - title: Your Bitwarden vault
    details: The one process holding the vault's keys. lys-shell's dropdown, launcher and network agent are views over it, and one folder can show as a read-only collection.
---
