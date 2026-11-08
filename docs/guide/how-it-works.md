# How it works

lys-secrets is a separate process with no UI code. It serves
`org.freedesktop.secrets` and `dev.stubbe.lys.Vault1`, the unlock socket, and
optionally an SSH agent. `lys-secrets pinentry` is a GnuPG pinentry.

## Bus names

It claims `dev.stubbe.lys.Vault1` first, then `org.freedesktop.secrets`. It never
queues for or replaces an owner.

| Already owned | Result |
| --- | --- |
| `dev.stubbe.lys.Vault1` (another lys-secrets) | Logs the owner and exits |
| `org.freedesktop.secrets` (another provider) | Logs the owner and serves only the vault: no unlock socket, no SSH agent |

The unit stops with the graphical session. Exiting locks every collection and the
vault.

## Collections and aliases

A collection holds items, each with a label, attributes and a secret, and has its
own password and [file](/guide/security#at-rest). Searching by attributes works on
locked collections too.

An alias names a collection; clients use `default`. `login` is the collection your
session password opens.

A client-created collection asks for a new password, typed twice. Its id, used for
the object path and file name, is the label lowercased with runs of other
characters turned into `_` (up to 48 characters, `collection` if empty, `_2`, `_3`…
if taken).

## Unlocking

| Source | Behaviour |
| --- | --- |
| lys-login (greeter and lock screen) | Sends the verified password over the [unlock socket](/guide/security#unlock-socket). The first time, creates `login` with it and points `default` at it if unset |
| `--unlock-fd N` | Same, from an inherited descriptor, for a launcher that has the password |
| Anything else | Asks through the desktop's password dialog. Wrong password asks again; cancel leaves it locked |

A change is replied to and signalled only after it is on disk. A collection locked
while a change is being written stays locked and holds the change.

### Login password changes

When lys-login sends a password that does not open `login`, lys-secrets keeps it in
locked memory and asks once for the previous password:

- **Update** opens `login` with the previous password and re-encrypts it under the
  new one. A wrong previous password asks again.
- **Keep the old password** leaves the file unchanged; `login` then asks for its
  own password when needed.

The kept password is zeroed when the dialog closes. A newer password replaces it
while the dialog is open; one that opens `login` closes the dialog.

With both passwords known, `control.Rekey(path, old, new)` re-encrypts `login`
without a dialog. It is idempotent and does nothing if `login` does not exist.

Other collections change password through `ChangeLock` and the prompt it returns:

```sh
busctl --user call org.freedesktop.secrets /org/freedesktop/secrets \
  org.freedesktop.Secret.Service ChangeLock o /org/freedesktop/secrets/collection/<id>
busctl --user call org.freedesktop.secrets <prompt path> \
  org.freedesktop.Secret.Prompt Prompt s ""
```

The dialog asks for the old password if the collection is locked, then the new one
twice.

## Locking

| Trigger | Locks |
| --- | --- |
| `Lock` | The given collections; on `bitwarden`, the vault |
| `LockService` | Every collection and the vault |
| `--collection-lock-after` | An idle collection; reading a secret or changing anything resets the timer, listing and searching do not |
| `--collection-lock-on-screen-lock` | Every collection when the session locks |
| `--vault-lock-after` | The idle vault; reading a field through `Field` or a password through `bitwarden` resets the timer, listing and `NetworkLogin` do not |
| Process exit | Everything |

Without the two collection flags, collections stay unlocked until one of the other
triggers.

## SSH agent

With `--ssh-agent`, lys-secrets serves the SSH agent protocol on
`$XDG_RUNTIME_DIR/lys-secrets/ssh`. It sets `SSH_AUTH_SOCK` in the systemd user
manager and D-Bus activation environments and unsets it in systemd on exit. The Nix
modules also export it for login shells.

- **Keys:** each `~/.ssh/id_*` with a matching `.pub` (listed from the `.pub`), plus
  keys added with `ssh-add`. Added keys live in memory only and honour `ssh-add -t`
  and `-c` (confirmation dialog per signature). `ssh-add -x`/`-X` lock and unlock
  the agent.
- **Encrypted keys** are opened on first signature, using a passphrase remembered
  in `login` if unlocked, else asking through the dialog with **Remember in the
  login keyring** ticked. Remembered passphrases are `login` items with schema
  `dev.stubbe.lys.SshKey` and attributes `fingerprint` and `path`.
- **Locking `login`** drops every `~/.ssh` key the agent opened. `ssh-add` keys
  stay until removed or expired.

## GnuPG pinentry

`pinentry-lys` (or `lys-secrets pinentry`) speaks the Assuan pinentry protocol on
stdin/stdout and asks through the desktop's dialog. In `~/.gnupg/gpg-agent.conf`:

```
pinentry-program /usr/bin/pinentry-lys
```

then `gpgconf --kill gpg-agent`. The Nix option `pinentry.enable` does this.

- When gpg-agent allows external caching, the dialog offers **Remember in the
  login keyring** (ticked). Remembered passphrases are `login` items with
  pinentry-gnome3's schema `org.gnupg.Passphrase` and a `keygrip` attribute, so
  passphrases gnome-keyring stored are found. Unticking forgets it.
- A passphrase gpg-agent reports as wrong is asked again with the reason, never
  read from the keyring.
- New passphrases are asked twice; confirmations show gpg-agent's buttons.
- Without a session bus or dialog host it answers `GPG_ERR_NO_PIN_ENTRY` at once.

## Clients

The test suite runs the real service against `secret-tool`, python-secretstorage
(DH session), Chromium's password store and git's libsecret credential helper.
Flatpak apps go through the Secret portal; lys-shell's portal stores their per-app
master secrets in the default collection.

## Bitwarden vault

lys-secrets logs in to bitwarden.com, bitwarden.eu, a self-hosted server or
Vaultwarden. lys-shell's vault dropdown, launcher mode and NetworkManager secret
agent use it over `dev.stubbe.lys.Vault1`.

It keeps only the session: the account on disk and the renewing credential (refresh
token, or the API key for API-key logins) in the default collection; see
[Bitwarden vault security](/guide/security#bitwarden-vault). After a restart the
vault is locked and opens with the master password alone. Every unlock syncs from
the server, so the vault cannot open offline.

### `dev.stubbe.lys.Vault1`

Object `/dev/stubbe/lys/Vault`. The Go package `vault` defines the contract and a
client.

| Method | Effect |
| --- | --- |
| `Status` | State, account, sync in progress, last sync, item count, last error |
| `Items` | Lists items: names, usernames, URIs, available fields; no secrets |
| `Field` | One field of one item: username, password, verification code, card number, card code, email or notes |
| `Login` | Logs in with the master password, optional second factor or new-device code |
| `SendLoginEmail` | Asks the server to email the new-device code |
| `LoginAPIKey` | Logs in with a personal API key and unlocks with the master password |
| `Unlock` | Opens the vault with the master password |
| `Lock` | Wipes the keys |
| `Logout` | Locks, forgets the session and [asks the server to revoke it](/guide/security#bitwarden-vault) |
| `Sync` | Refetches the vault |
| `NetworkLogin` | The login in a folder matching a network connection's name, for the secret agent |
| `CreateLogin` | Adds a login to a named folder, encrypted locally |
| `FindLogin` | Looks up a login by exact name, optionally within one folder |
| `Sends`, `CreateTextSend`, `DeleteSend` | Lists Sends; creates a text Send and returns its share link with key; deletes one |

Verification codes are computed locally. Signals: `Changed` (status after any
change) and `SyncFailed` (a periodic sync failed).
