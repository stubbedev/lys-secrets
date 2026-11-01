# How it works

lys-secrets is a small process of its own, separate from the shell. It links no
UI, so the code holding unlocked keys is only this. It serves two bus names:
`org.freedesktop.secrets`, the
[Secret Service API](https://specifications.freedesktop.org/secret-service-spec/latest/),
and `dev.stubbe.lys.Vault1`, your Bitwarden vault.

## Sharing the name

The process takes the vault's name first, then the Secret Service's. It never
queues for a name and never replaces an owner.

| Who already owns the name | What lys-secrets does |
| --- | --- |
| Another provider owns `org.freedesktop.secrets` | Logs which one and serves the vault alone, with no unlock socket |
| Another lys-secrets owns `dev.stubbe.lys.Vault1` | Logs that and exits |

The user unit stops with the graphical session, and every collection and the
vault lock as the process exits.

## Collections and aliases

A collection is a set of items, each with a label, attributes and a secret. It
has its own password and its own [file](/guide/security#at-rest). Clients search
by attributes, which works on a locked collection too, so a client knows to ask
for an unlock.

An alias names a collection. The one clients care about is `default`.

`login` is the collection your session password opens. A client can also create
collections of its own; lys-secrets asks for a new password, typed twice, and
makes the collection's id from its label: lowercase letters and digits, the rest
underscores. That id is the object path and the file name.

## Unlocking

- **lys-login**, both its display manager and its lock screen, hands the password
  it just verified to `lys-secrets` over a socket only your user can connect to.
  The first unlock creates the `login` collection with that password, and points
  `default` at it unless `default` is already set. Under autologin no password is
  typed at boot, so the lock screen is the first place the password appears.
- **`lys-secrets --unlock-fd N`** reads the password from an inherited descriptor,
  for whatever starts the process with the password in hand. lys-login does not
  use it.
- **Anything else**, such as a restart, another collection or a client asking for
  a locked item, asks through the desktop's password dialog. A wrong password asks
  again, and cancelling leaves the collection locked.

If `lys-secrets` is not running, lys-login unlocks a running gnome-keyring instead.

Changing your login password does not re-encrypt the collection, so your new
password does not open it. Ask for a new collection password with `ChangeLock`,
then show the prompt it returns:

```sh
busctl --user call org.freedesktop.secrets /org/freedesktop/secrets \
  org.freedesktop.Secret.Service ChangeLock o /org/freedesktop/secrets/collection/login
busctl --user call org.freedesktop.secrets <the returned prompt path> \
  org.freedesktop.Secret.Prompt Prompt s ""
```

The dialog asks for the old password if the collection is locked, then the new one
twice.

## Locking

A collection locks when a client calls the API's `Lock` or `LockService`, or when
the process stops. By default that is all: there is no idle time, and locking your
screen does not lock collections. Two settings add both, each off by default:
[`--collection-lock-after` and `--collection-lock-on-screen-lock`](/guide/configuration#command-line-flags).
The idle time restarts when a secret is read or anything in the collection changes.
Listing and searching do not restart it.

`Lock` on the `bitwarden` collection locks the vault. `LockService` locks every
collection and the vault, whether or not the vault shows as a collection.

The vault also locks after [its idle time](/guide/configuration#command-line-flags),
which restarts when a field is read through `Field` or a password through the
`bitwarden` collection. Listing items and `NetworkLogin` do not restart it.

## Clients it is checked against

The test suite runs the real service on a private bus against `secret-tool`,
python-secretstorage over a DH session, Chromium's password store and git's
libsecret credential helper. Both of the API's transports work; see
[On the bus](/guide/security#on-the-bus).

Sandboxed (Flatpak) apps get their secret through the portal, which identifies
them. lys-shell's Secret portal keeps their per-app master secrets through this
service, in the default collection.

## The Bitwarden vault

lys-secrets logs in to a Bitwarden account on bitwarden.com, bitwarden.eu, a
self-hosted server or Vaultwarden. lys-shell's vault dropdown, launcher mode and
NetworkManager secret agent are views over it, so the one process holding the
vault's keys is this one.

It keeps [only the session](/guide/security#the-bitwarden-vault) on disk. An unlock
always fetches a fresh sync from the server, so the vault cannot open offline. After
a login with a personal API key the server issues no refresh token, so a vault that
locked needs a new login.

### `dev.stubbe.lys.Vault1`

The object is `/dev/stubbe/lys/Vault`. The Go package `vault` is the contract and
its client.

| Method | What it does |
| --- | --- |
| `Status` | State, account, whether a sync runs, the last sync, the item count and the last error |
| `Items` | Lists the open vault: names, usernames, URIs, and which fields each item has; never a secret |
| `Field` | One field of one item: username, password, verification code, card number, card code, email or notes |
| `Login`, `SendLoginEmail` | Logs in with the master password, with an optional second factor or new-device code; asks the server to email that code |
| `LoginAPIKey` | Logs in with the personal API key and opens the vault with the master password |
| `Unlock`, `Lock`, `Logout`, `Sync` | Opens with the master password; wipes the keys; also forgets the session and [asks the server to revoke it](/guide/security#the-bitwarden-vault); refetches |
| `NetworkLogin` | The login answering a network connection, for the secret agent |
| `CreateLogin` | Adds a login to a folder by name, encrypted here as Bitwarden's clients do |
| `FindLogin` | Looks up a login by its exact name |
| `Sends`, `CreateTextSend`, `DeleteSend` | Lists your Bitwarden Sends; creates a text Send, encrypted here with Bitwarden's Send key derivation, and returns its share link with the key; deletes one |

Verification codes are computed here. The signals are `Changed`, the status after
any change, and `SyncFailed`, a periodic sync failing.
