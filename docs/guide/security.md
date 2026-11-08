# How secrets are protected

lys-secrets protects locked collections, files read by someone else, and secrets
from other users. It does not protect an unlocked collection from programs running
as you. [Confirming reads](#confirming-reads) slows careless exfiltration; it does
not stop a determined program.

## At rest

Each collection is `$XDG_DATA_HOME/lys-secrets/<id>.keyring`, mode 0600, in a 0700
directory. Writes go to a temporary file that is synced and renamed over the
original.

The key is Argon2id (3 passes, 64 MiB, 4 threads) over the password with a random
16-byte salt per collection. The body is XChaCha20-Poly1305 with a fresh nonce.

| Part | Contents | Readable without the password |
| --- | --- | --- |
| Header | Magic, Argon2id parameters, salt, key check (an AEAD tag over nothing) | Yes |
| Item index | Each item's numeric id and one SHA-256 hash per attribute | Yes |
| Body | Collection label and times; each item's label, attributes, content type, secret and times | No |

Header and index are authenticated with the body.

| Event | Result |
| --- | --- |
| Wrong password | Reported as wrong; the dialog asks again |
| Body or index modified | Logged as a modified file; no retry; stays locked |
| Argon2id parameters, salt or key check modified | Indistinguishable from a wrong password |

The key check costs an attacker the same Argon2id derivation as testing against the
body, so it reveals nothing new. Files in the format without a key check (magic
version 1) still open; any modification reads as a wrong password, and the first
unlock rewrites them with a key check.

Without the password, a file reveals:

- **Item count**, attributes per item, and approximate content size.
- **Guessable attribute values.** Index hashes are unkeyed, unsalted SHA-256 of
  name and value, so `username` = `ada` can be tested offline and matched across
  items and files. Keep secrets out of attributes.
- **The collection id**, derived from its label, in the file name and the
  unencrypted `aliases.json`.

A collection is only as strong as its password; no hardware key or key file is
mixed in. Changing the password re-encrypts with a fresh salt, but an older copy of
the file still opens with the old password.

## While unlocked

- The collection key is in its own anonymous mapping outside the Go heap,
  excluded from core dumps, zeroed on lock, and `mlock`ed where `RLIMIT_MEMLOCK`
  allows. If it does not, this is logged once with the limit; raise
  `LimitMEMLOCK=` or use encrypted or no swap. Each key takes one page.
- Each secret stays encrypted under that key in memory, bound to its item, and is
  decrypted only for the request reading it; the buffer is then cleared.
- The process sets itself non-dumpable at start and refuses to run otherwise. This
  blocks core dumps and same-user ptrace, not root.

Limits:

- Labels and attribute values are plain Go strings while unlocked; locking drops
  them without overwriting.
- Values sent to clients pass through D-Bus library buffers, and dialog passwords
  arrive as Go strings; neither is cleared.
- Collections stay unlocked, including under a locked screen, unless an
  [idle or screen lock](/guide/how-it-works#locking) is enabled. Locking does not
  revoke what a client already read.

## On the bus

The Secret Service API has no caller check. Any program on your session bus can,
without a prompt:

- Read every secret in an unlocked collection (unless
  [reads are confirmed](#confirming-reads)), and in `bitwarden` while the vault is
  open.
- List a locked collection's item paths and search it by attribute value.
- Change or delete items in an unlocked collection.
- **Delete an unlocked collection**, file included. Keep backups.
- Lock anything, and move aliases between unlocked collections.

Changing, deleting or re-aliasing a locked collection or its items fails with
`org.freedesktop.Secret.Error.IsLocked`, so the client must unlock first.
`CreateItem` on a locked collection instead returns the unlock prompt and stores the
item once it succeeds. Because `default` cannot move off a locked collection, a
client cannot redirect new secrets away from a locked `login` to a collection it can
read.

Secrets are only returned over a session the caller opened; its sessions close when
it leaves the bus.

### Confirming reads

With `--confirm-foreign-reads`, each item records its owners (programs that stored
or changed it, and programs always allowed) inside the encrypted body. A
non-owner sees the item as locked: searches list it as locked and reads return
nothing. Its `Unlock` prompt shows a dialog naming the program, its path, the item,
its collection and its owners:

| Answer | Effect |
| --- | --- |
| **Deny** | Prompt dismissed; nothing read |
| **Allow** | That bus connection may read the item until it disconnects or the collection locks |
| **Always allow** | The program becomes an owner and reads unasked, across restarts |

A program is identified by `/proc/<pid>/exe`, or by app id from `.flatpak-info` for
Flatpak apps. When the bus provides a pidfd (dbus-broker), the process is checked to
still be alive after identification, so a reused pid cannot impersonate. An
unidentifiable program can only be allowed per connection. An item with no owners
is claimed by its first reader without a dialog, and this is logged.

Limits:

- An interpreter is one program: allowing `python3` allows every Python script.
- A program running as you can attach to or replace an allowed program.
- Labels and attributes remain readable by any client.
- The `bitwarden` collection is not covered.
- With the flag off, reads are not checked, but stores still record owners.

Sandboxed apps should use the Secret portal; one with direct access to
`org.freedesktop.secrets` is an ordinary client.

### Transports

| Algorithm | Effect |
| --- | --- |
| `plain` | Secret sent as is |
| `dh-ietf1024-sha256-aes128-cbc-pkcs7` | AES-128-CBC under an HKDF-SHA256 key from an unauthenticated 1024-bit Diffie-Hellman exchange; fresh IV per secret |

The client chooses. Neither is a security boundary: DH keeps secrets out of bus
logs but authenticates nobody.

### Passwords on the bus

- Dialog passwords travel in the clear from the owner of
  `dev.stubbe.lys.PortalDialogs1` to lys-secrets; nothing else about that owner is
  checked. The client that triggered the prompt never sees the password.
- The Bitwarden master password travels on `Login`, `LoginAPIKey`, `Unlock` and a
  reprompted `Field`.

## Unlock socket

lys-login sends the login password over `$XDG_RUNTIME_DIR/lys-secrets/control`, not
D-Bus. The socket is in a 0700 directory and refuses peers whose `SO_PEERCRED` uid
differs. Any program running as you can connect and try passwords at one Argon2id
derivation each, with no other limit.

A password that does not open `login` is held in locked memory only while the
previous-password dialog is open. Any same-user program can trigger that dialog but
cannot read `login` through it. A re-key request needs the current (or already new)
password of `login`.

## SSH agent

The agent socket, `$XDG_RUNTIME_DIR/lys-secrets/ssh`, shares the 0700 directory and
`SO_PEERCRED` check. Any program running as you can sign with any listed key, as
with every agent; use `ssh-add -c` for per-signature confirmation.

Decrypted keys live in locked memory like collection keys. Ed25519 keys sign
directly from there with lys-secrets' own signing code, keeping derived secrets in
locked memory or on the stack. Limits:

- RSA and ECDSA keys are stored as PKCS #8 in locked memory and parsed onto the Go
  heap for each signature; their private numbers are zeroed afterwards, Go's
  internal copies are not.
- Decrypting a key file, or receiving a key from `ssh-add`, passes it through the
  SSH library's heap buffers once.
- Typed passphrases cross the session bus from the dialog host and arrive as Go
  strings.

## GnuPG pinentry

`pinentry-lys` is non-dumpable. The passphrase sent to gpg-agent is written from
buffers cleared afterwards and never logged. It crosses the session bus from the
dialog host, and a remembered one crosses it from the Secret Service over a plain
session on each use.

## Bitwarden vault

**On disk:** `$XDG_STATE_HOME/lys-secrets/bitwarden` is 0700, its files 0600. It
holds `device-id` and `session.json` (server, email, OAuth client id). No refresh
token, API key, master password, key or item.

**In the keyring:** the renewing credential is one item in the default collection
with schema `dev.stubbe.lys.Vault.Session` and server and email as attributes. It is
the refresh token, or the API key's client secret for API-key logins. Anyone who
reads it from an unlocked collection can get tokens and the server's copy of your
vault, still encrypted under your master password. The first unlock after a restart
reads it, prompting for the collection's password if locked.

**Logout** deletes the file and keyring item, then asks the server to revoke the
refresh token (RFC 7009), regardless of the answer:

| Server answer | `Logout` returns |
| --- | --- |
| 200 | Success |
| 404, 405, 501, or 400 `unsupported_token_type` | `RevocationUnsupported` |
| Anything else, or no answer | `SessionNotRevoked`, with the reason |

**Bitwarden's and Vaultwarden's servers have no revocation endpoint**, so logout
returns `RevocationUnsupported` (logged once) and the refresh token stays valid
until it expires or you use Bitwarden's "Deauthorize sessions", which logs out every
device and which lys-secrets never does for you. Do that if the token may have
leaked. API-key sessions have no refresh token; the API key works until rotated.

**In memory:** vault keys and decrypted items are on the Go heap, not `mlock`ed,
protected from dumps only by the process being non-dumpable. Locking zeroes the key
bytes and drops the access token and items; items are Go strings and are not
overwritten, and the collector may have copied keys before zeroing.

**Access:** every `dev.stubbe.lys.Vault1` call checks the caller runs as your uid.
That excludes other users, not your own programs.

- `Items` carries no secret.
- `Field` returns one value at a time. Secret fields of a reprompt item require the
  master password, checked locally; usernames and emails do not.
- `NetworkLogin` returns username, password and all custom fields without a prompt,
  but refuses reprompt items, items not fully decrypted, and names matching more
  than one login.
- The [`bitwarden` collection](/guide/configuration#the-bitwarden-collection) has no
  uid check (see [On the bus](#on-the-bus)) and omits reprompt items.

**Server:** the master password is never sent, only a hash derived from the master
key. KDF settings from the server below Bitwarden's floors are refused: PBKDF2 under
5000 iterations, Argon2id under 2 iterations, 16 MiB or 1 thread. Authenticated
items are verified with HMAC-SHA256 before decryption.

Requests use Go's standard TLS verification and a 30-second timeout. Self-hosted
URLs must be `https://`; `http://` is accepted only for `localhost` and loopback
addresses, and redirects to plain HTTP elsewhere are refused. A saved session for a
server that fails this rule is deleted at start and the vault starts logged out with
the reason as its status.
