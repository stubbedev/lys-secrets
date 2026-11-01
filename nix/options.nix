self: {
  lib,
  pkgs,
  ...
}: {
  enable = lib.mkEnableOption ''
    lys-secrets as the session's Secret Service (`org.freedesktop.secrets`):
    libsecret, Chromium and Electron apps, git's libsecret credential helper
    and the xdg-desktop-portal's per-app secrets keep their secrets in
    collections encrypted at rest under `$XDG_DATA_HOME/lys-secrets`. The
    lock screen and lys-login unlock the login collection with the session
    password. It also holds the Bitwarden vault (`dev.stubbe.lys.Vault1`)
    that lys-shell's vault widget, launcher and network agent use. Only one
    provider can own `org.freedesktop.secrets`: do not run gnome-keyring's
    secrets component as well (lys-secrets logs the other owner and serves
    the vault alone)'';

  collections = {
    lockAfter = lib.mkOption {
      type = lib.types.ints.unsigned;
      default = 0;
      description = ''
        Lock a collection after this many minutes with no secret read from it
        and nothing in it changed. 0 keeps it open until something locks it.
      '';
    };
    lockOnScreenLock = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Lock every collection when logind says the session locked. lys-login's
        lock screen reopens the login collection as it unlocks; other collections
        ask for their password when next used. The Bitwarden vault keeps to
        `vault.lockAfter`.
      '';
    };
  };

  vault = {
    lockAfter = lib.mkOption {
      type = lib.types.ints.unsigned;
      default = 15;
      description = ''
        Lock the Bitwarden vault after it went this many minutes without a
        copy. 0 keeps it open until locked by hand or with the session.
      '';
    };
    collectionFolder = lib.mkOption {
      type = lib.types.str;
      default = "";
      example = "Desktop";
      description = ''
        Show the logins of this Bitwarden folder as the Secret Service's
        read-only `bitwarden` collection, so libsecret clients find them while
        the vault is open; a locked vault is a locked collection that unlocks
        with the master password. Logins behind the master password reprompt
        are left out. Empty shows no collection.
      '';
    };
    syncInterval = lib.mkOption {
      type = lib.types.ints.unsigned;
      default = 30;
      description = ''
        Sync the open Bitwarden vault every this many minutes. 0 syncs only
        on unlock and when asked.
      '';
    };
  };

  package = lib.mkOption {
    type = lib.types.package;
    default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
    defaultText = lib.literalExpression "lys-secrets.packages.\${system}.default";
    description = "The lys-secrets package.";
  };
}
