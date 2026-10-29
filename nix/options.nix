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

  vault = {
    lockAfter = lib.mkOption {
      type = lib.types.ints.unsigned;
      default = 15;
      description = ''
        Lock the Bitwarden vault after it went this many minutes without a
        copy. 0 keeps it open until locked by hand or with the session.
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
