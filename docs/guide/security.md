# How secrets are protected

lys-secrets protects secrets in a locked collection, on a disk someone else reads,
and from other users of the machine. It does not protect an unlocked collection
from programs you run: as with gnome-keyring, anything running as you can read it.

This page says what each layer does and where it stops.

## At rest

Each collection is one file, `$XDG_DATA_HOME/lys-secrets/<id>.keyring`, mode 0600,
in a directory created 0700. A change replaces the file whole: a temporary beside
it is written, synced and renamed over it.

The key is derived from the password with Argon2id (3 passes over 64 MiB, 4
threads) and a random 16-byte salt per collection. The body is encrypted with
XChaCha20-Poly1305 under a fresh nonce.

| Part of the file | Contents | Readable without the password |
| --- | --- | --- |
| Header | Format magic, Argon2id parameters, salt, and a key check: an authentication tag under the key, over nothing | Yes |
| Item index | Each item's numeric id and one SHA-256 hash per attribute | Yes |
| Body | The collection's label and times; each item's label, attributes, content type, secret and times | No |

The header and index are authenticated as part of the body, so changing them makes
the file fail to open. The key check tells the two failures apart:

| What happened | What you get |
| --- | --- |
| The password is wrong | Wrong password; the dialog asks again |
| The body or the item index changed | The file was changed: logged, no retry, and the collection stays locked |
| The Argon2id parameters, the salt or the key check changed | Wrong password. These decide what key the password gives, so a changed one finds no key and cannot be told apart |

The check gives away nothing new. Whoever holds the file can already test a password
against the body, and it costs the same Argon2id derivation.

A file from before the key check opens as it stands, and any change to it reads as
a wrong password. It is rewritten with a key check the first time it unlocks, and
older versions of lys-secrets cannot read the rewritten file.

What someone holding the file can learn without the password:

- **How many items there are**, how many attributes each has, and the rough size of
  the contents.
- **Attribute values they can guess.** The hashes are unsalted SHA-256 of the
  attribute's name and value, with no key. Someone can test a guess such as
  `username` = `ada` offline at full speed, and can see the same attribute on two
  items or in two files. Do not put anything secret in an attribute. This is what
  lets a locked collection answer a search.
- **The collection's label, nearly.** The file name and `aliases.json` carry the
  collection's id, made from its label, and `aliases.json` is not encrypted. The
  label itself and everything in the items are.

A collection is only as strong as its password. Nothing else, such as a hardware
key or a key file, goes into the derivation. Changing a password re-encrypts the
file with a fresh salt, but a copy taken earlier still opens with the old one.

## While unlocked

The collection key lives in its own anonymous memory mapping, outside the Go heap
so the collector never copies it. It is excluded from core dumps and zeroed when
the collection locks. It is locked against swap where the memlock limit allows. If
the limit does not allow it, lys-secrets logs that once, with the limit, and keeps
serving, and the key may reach swap. Each key takes one page, so the usual limit
holds many. Raise `LimitMEMLOCK=` for the unit, or use encrypted or no swap, if you
see that line.

Each secret stays encrypted in memory under that key, bound to its item so secrets
cannot be swapped between items, and is decrypted only for the request that reads
it. The buffer is cleared afterwards.

The process marks itself not dumpable at start, and refuses to run if it cannot.
That stops core dumps and another process of your user attaching to read its
memory. It does not stop root.

Where this stops:

- Labels and attribute values are plain Go strings in memory while a collection is
  unlocked. Locking drops them for the collector to reclaim; it does not overwrite
  them.
- The value handed to a client passes through the D-Bus library's buffers, which
  are not cleared. Neither is a password returned by the dialog, which arrives as a
  Go string.
- An unlocked collection [stays unlocked](/guide/how-it-works#locking) until
  something locks it, including while the screen is locked, unless you turn on its
  idle lock or its lock with the screen. Locking does not stop what a client read
  before it.

## On the bus

The Secret Service API has **no caller check**. Every program on your session bus
can do the following, with no prompt:

- Read every secret in an unlocked collection, and in the `bitwarden` collection
  while the vault is open.
- See a locked collection's item paths, and search it by attribute value.
- Change or delete items in an unlocked collection.
- **Delete a whole unlocked collection.** Its file is removed with no prompt and no
  password, so keep backups of what you cannot lose.
- Lock anything, and move aliases between unlocked collections.

A locked collection and its items cannot be changed or deleted, and an alias cannot
move off or onto one. Such a call answers `org.freedesktop.Secret.Error.IsLocked`
and leaves the files as they were, so the client has to unlock the collection first,
through the `Unlock` prompt and its password. The exception is `CreateItem`, which
returns that prompt itself and stores the item only once it succeeds.

The alias rule is stricter than gnome-keyring, which lets any client move `default`
at any time. Without it, a client could point `default` away from the locked `login`
collection at one it can already read, and the next secret an app saved would go
there.

A client can only open secrets over a session it opened itself, and its sessions
close when it leaves the bus.

An app in a sandbox should go through the portal. One allowed to talk to
`org.freedesktop.secrets` directly gets the same access as any other client.

### Transports

| Algorithm | What it does |
| --- | --- |
| `plain` | The secret travels as is |
| `dh-ietf1024-sha256-aes128-cbc-pkcs7` | AES-128-CBC under an HKDF-SHA256 key from an unauthenticated 1024-bit Diffie-Hellman exchange, with a fresh IV per secret |

These are the transports the specification names, and the client chooses.
Neither is a security boundary. The DH transport keeps a secret out of a bus log,
and does not prove who is on the other end. lys-secrets' own Go `client` package
uses `plain`.

### Passwords on the bus

- Passwords typed into a dialog cross the session bus in the clear, from the dialog
  host back to lys-secrets. Only the process owning
  `dev.stubbe.lys.PortalDialogs1` is asked, and lys-secrets checks nothing else
  about who that is. The client that triggered the prompt never receives the
  password.
- The Bitwarden master password crosses the bus on `Login`, `LoginAPIKey`, `Unlock`
  and a reprompted `Field`.

## The unlock socket

lys-login hands over the login password through
`$XDG_RUNTIME_DIR/lys-secrets/control`, so this password does not cross D-Bus. The
socket is in a 0700 directory, and the server refuses a peer whose `SO_PEERCRED` uid
is not yours. Any program running as you can still connect and try a password; a
try costs one Argon2id derivation, with no other limit.

## The Bitwarden vault

**On disk**, the vault directory `$XDG_STATE_HOME/lys-secrets/bitwarden` is created
mode 0700 and its files are 0600. It holds `device-id` and `session.json`, which holds the
server, the email, the OAuth client id and the refresh token. Never the master
password, a key or an item.

`session.json` is **not encrypted**. Whoever reads it can use the refresh token
against the server, to get a token and your vault as the server stores it, still
encrypted under your master password.

`Logout` deletes the file first, then asks the server to revoke the refresh token
through OAuth's revocation endpoint (RFC 7009). The file goes even with the server
unreachable, and a server that did not revoke the token makes `Logout` fail with
`SessionNotRevoked`, saying why. **Bitwarden's and Vaultwarden's servers have no
such endpoint today**, so expect that answer from them: the old token keeps working.
They invalidate a session only with every other one on the account, which is
Bitwarden's "Deauthorize sessions" and needs your master password. Do that if the
file may have leaked. lys-secrets does not do it for you, since it would log out
your other devices too. A session from a personal API key has no refresh token to
revoke; its access token stops working when it expires.

**In memory**, unlike a collection's key, the vault's keys and decrypted items are
on the Go heap, with no lock against swap. They are excluded from core dumps only by
the process being not dumpable. Locking zeroes the key bytes the client still holds
and drops the access token and the items. Items are Go strings: they are dropped for
the collector to reclaim, not overwritten, and the collector may have copied a key
before it was zeroed.

**Who can read it.** Each `dev.stubbe.lys.Vault1` call first checks that the caller
runs as your uid. That keeps other users out, and does not separate your own
programs from each other.

- `Items` carries no secret.
- `Field` gives out one value at a time. An item behind Bitwarden's master password
  reprompt gives its secret fields only with the master password, checked here.
  Usernames and emails are not behind it.
- `NetworkLogin` gives a login's username, password and all its custom fields
  together, with no prompt, but refuses an item behind the reprompt, one not fully
  decrypted, or a name that matches more than one login.
- The [`bitwarden` collection](/guide/configuration#the-bitwarden-collection) has no
  uid check of its own; see [On the bus](#on-the-bus). Reprompted logins are left
  out of it.

**To the server.** The password itself is never sent; the server gets a hash derived
from the master key. The account's KDF settings come from the server, so
lys-secrets refuses ones under Bitwarden's floors: PBKDF2 under 5000 iterations, or
Argon2id under 2 iterations, 16 MiB or 1 thread. Authenticated items are checked
with HMAC-SHA256 before they are decrypted.

Requests use Go's standard TLS verification and a 30-second timeout. A self-hosted
server's URL must be `https://`, because the password hash and the tokens would
otherwise travel unencrypted. `http://` is accepted only for `localhost` and
loopback addresses, and a redirect from the server to plain HTTP elsewhere is
refused. A session saved for an `http://` server from before this rule is deleted
at start, and the vault starts logged out and says why.
