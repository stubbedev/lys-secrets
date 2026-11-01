# Configuration

lys-secrets has no configuration file. Its settings are command-line flags, and
the Nix modules write those flags for you.

## Command-line flags

| Flag | Default | What it does |
| --- | --- | --- |
| `--unlock-fd N` | none | Read the login password from inherited descriptor `N` and unlock the `login` collection with it, creating the collection if there is none |
| `--collection-lock-after D` | `0` | Lock a collection once no secret was read from it and nothing in it changed for this long; `0` keeps it open until something locks it |
| `--collection-lock-on-screen-lock` | off | Lock every collection when logind says the session locked |
| `--vault-lock-after D` | `15m` | Lock the vault once no field was read from it for this long; `0` keeps it open until something locks it |
| `--vault-sync-interval D` | `30m` | Sync the open vault this often; `0` syncs only on unlock and when asked |
| `--vault-collection-folder NAME` | empty | Show the logins of this vault folder as the read-only `bitwarden` collection; empty shows none |

Durations use Go's syntax, such as `90s` or `1h30m`. A negative one is refused at
start. The idle locks and the vault's sync interval act on time and count time the
machine was suspended, acting within 30 seconds of it waking.

`--collection-lock-on-screen-lock` watches the logind session on the system bus: its
`Lock` signal and its `LockedHint` turning true, which lys-login's lock screen sets.
Unlocking through lys-login's lock screen reopens `login`; other collections ask for
their password when next used. If logind cannot be reached, lys-secrets keeps serving
and logs that collections will not lock with the screen. It does not touch the vault,
which keeps to `--vault-lock-after`.

`--unlock-fd` reads the whole descriptor, at most 4096 bytes, and drops one
trailing newline. A password that does not open the collection is logged and
leaves it locked; lys-secrets keeps running.

`--vault-collection-folder` refuses to start if a keyring collection with the id
`bitwarden` already exists. The error names the file to rename.

### Passing flags to the packaged unit

On Debian, Ubuntu, Fedora or from the archive, override `ExecStart` in a drop-in,
`~/.config/systemd/user/lys-secrets.service.d/vault.conf`:

```ini
[Service]
ExecStart=
ExecStart=/usr/bin/lys-secrets --vault-lock-after=30m --vault-collection-folder=Desktop
```

Then run `systemctl --user daemon-reload` and
`systemctl --user restart lys-secrets`. A restart locks every collection and the
vault.

## Nix options

Both the NixOS and the home-manager module take these, under
`services.lys-secrets`:

| Option | Default | Flag it sets |
| --- | --- | --- |
| `enable` | `false` | |
| `package` | the flake's package | |
| `collections.lockAfter` | `0` (minutes) | `--collection-lock-after` |
| `collections.lockOnScreenLock` | `false` | `--collection-lock-on-screen-lock` |
| `vault.lockAfter` | `15` (minutes) | `--vault-lock-after` |
| `vault.syncInterval` | `30` (minutes) | `--vault-sync-interval` |
| `vault.collectionFolder` | `""` | `--vault-collection-folder` |

## The `bitwarden` collection

With a folder set, libsecret clients find its logins while the vault is open:

```sh
secret-tool lookup username ada
```

Each item's secret is the password. Its attributes are `xdg:schema`
(`dev.stubbe.lys.Bitwarden.Login`), `bitwarden:id`, `name`, and the `username`,
`uri` (the first one) and `folder` it has.

A login shows only if it has a password, is fully decrypted, and is not behind
Bitwarden's master password reprompt. While the vault is locked the collection is
locked and has no items, so a search finds nothing and does not prompt. A client
that unlocks the collection is asked for the master password through the dialog.
The collection is read-only: creating, changing or deleting in it is refused.

## Files

`$XDG_DATA_HOME` and `$XDG_STATE_HOME` fall back to their usual places under
`$HOME`. `$XDG_RUNTIME_DIR` must be set to an absolute path, or lys-secrets exits.

| Path | What it holds |
| --- | --- |
| `$XDG_DATA_HOME/lys-secrets/<id>.keyring` | One collection |
| `$XDG_DATA_HOME/lys-secrets/aliases.json` | Which collection each alias, such as `default`, points at |
| `$XDG_STATE_HOME/lys-secrets/bitwarden/session.json` | The Bitwarden session |
| `$XDG_STATE_HOME/lys-secrets/bitwarden/device-id` | The device id the Bitwarden server knows this client by |
| `$XDG_RUNTIME_DIR/lys-secrets/control` | The unlock socket |

[How secrets are protected](/guide/security) says what is in them and who can
read them.
