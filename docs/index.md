---
layout: home

hero:
  name: lys-secrets
  text: The Secret Service for a lys desktop
  tagline: Serves org.freedesktop.secrets and your Bitwarden vault from one small process.
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
  - title: Drop-in provider
    details: Tested against secret-tool, python-secretstorage, Chromium and git's libsecret credential helper.
  - title: Encrypted at rest
    details: One file per collection, Argon2id key, XChaCha20-Poly1305 body.
  - title: Unlocks with your session
    details: lys-login hands over the verified password through a user-only socket.
  - title: Bitwarden vault
    details: Holds the vault's keys for lys-shell; one folder can appear as a read-only collection.
---
