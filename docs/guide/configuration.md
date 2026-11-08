# Configuration

There is no configuration file. Settings are command-line flags; the Nix modules
write them.

## Flags

```
lys-secrets [flags]
lys-secrets pinentry        # or pinentry-lys; see GnuPG pinentry
```

| Flag | Default | Effect |
| --- | --- | --- |
| `--unlock-fd N` | none | Read the login password from inherited descriptor `N` and unlock `login`, creating it if absent |
| `--collection-lock-after D` | `0` | Lock a collection after no secret was read from it and nothing in it changed for `D`; `0` never |
| `--collection-lock-on-screen-lock` | off | Lock every collection when logind reports the session locked |
| `--confirm-foreign-reads` | off | Ask before a program reads an item another program stored; see [Confirming reads](/guide/security#confirming-reads) |
| `--ssh-agent` | off | Serve an SSH agent on `$XDG_RUNTIME_DIR/lys-secrets/ssh`; see [SSH agent](/guide/how-it-works#ssh-agent) |
| `--vault-lock-after D` | `15m` | Lock the vault after no field was read for `D`; `0` never |
| `--vault-sync-interval D` | `30m` | Sync the open vault this often; `0` only on unlock and on request |
| `--vault-collection-folder NAME` | empty | Show this vault folder's logins as the read-only `bitwarden` collection; empty shows none |

- Durations use Go syntax (`90s`, `1h30m`). Negative values are refused. Idle locks
  and the sync interval count suspended time and act within 30 seconds of resume.
- `--unlock-fd` reads the whole descriptor and drops one trailing newline. An
  empty password or one over 4096 bytes is a startup error. A password that does
  not open `login` is logged and leaves it locked.
- `--collection-lock-on-screen-lock` watches the logind session's `Lock` signal
  and `LockedHint` on the system bus. If logind is unreachable, this is logged
  and the service keeps running. The vault is not affected.
- `--vault-collection-folder` refuses to start if a keyring collection with id
  `bitwarden` exists, naming the file to rename.

### Flags for the packaged unit

Override `ExecStart` in `~/.config/systemd/user/lys-secrets.service.d/override.conf`:

```ini
[Service]
ExecStart=
ExecStart=/usr/bin/lys-secrets --vault-lock-after=30m --vault-collection-folder=Desktop
```

Then `systemctl --user daemon-reload && systemctl --user restart lys-secrets`. A
restart locks every collection and the vault.

## Nix options

Under `services.lys-secrets`, for both the NixOS and home-manager module:

| Option | Default | Effect |
| --- | --- | --- |
| `enable` | `false` | Install and start the service |
| `package` | the flake's package | Package to run |
| `collections.lockAfter` | `0` (minutes) | `--collection-lock-after` |
| `collections.lockOnScreenLock` | `false` | `--collection-lock-on-screen-lock` |
| `collections.confirmForeignReads` | `false` | `--confirm-foreign-reads` |
| `sshAgent.enable` | `false` | `--ssh-agent`, and `SSH_AUTH_SOCK` for login shells |
| `pinentry.enable` | `false` | Makes `pinentry-lys` gpg-agent's pinentry (home-manager `services.gpg-agent.pinentry.package`, NixOS `programs.gnupg.agent.pinentryPackage`) |
| `vault.lockAfter` | `15` (minutes) | `--vault-lock-after` |
| `vault.syncInterval` | `30` (minutes) | `--vault-sync-interval` |
| `vault.collectionFolder` | `""` | `--vault-collection-folder` |

## The `bitwarden` collection

With a folder set, libsecret clients see its logins while the vault is open:

```sh
secret-tool lookup username ada
```

- Secret: the password.
- Attributes: `xdg:schema` (`dev.stubbe.lys.Bitwarden.Login`), `bitwarden:id`,
  `name`, and where present `username`, `uri` (the first) and `folder`.
- Only logins that have a password, decrypted fully, and are not behind
  Bitwarden's master password reprompt are shown.
- While the vault is locked the collection is locked and empty; searches find
  nothing and do not prompt. Unlocking it asks for the master password.
- Creating, changing or deleting items is refused.

## Files

`$XDG_DATA_HOME` and `$XDG_STATE_HOME` default to their usual places under
`$HOME`. `$XDG_RUNTIME_DIR` must be an absolute path, or lys-secrets exits.

| Path | Contents |
| --- | --- |
| `$XDG_DATA_HOME/lys-secrets/<id>.keyring` | One collection |
| `$XDG_DATA_HOME/lys-secrets/aliases.json` | Alias to collection id |
| `$XDG_STATE_HOME/lys-secrets/bitwarden/session.json` | Bitwarden server, email, client id |
| `$XDG_STATE_HOME/lys-secrets/bitwarden/device-id` | Device id known to the Bitwarden server |
| `$XDG_RUNTIME_DIR/lys-secrets/control` | Unlock socket |
| `$XDG_RUNTIME_DIR/lys-secrets/ssh` | SSH agent socket (`--ssh-agent`) |
