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
    password. Only one provider can own the name: do not run gnome-keyring's
    secrets component as well (lys-secrets logs the other owner and stays
    off)'';

  package = lib.mkOption {
    type = lib.types.package;
    default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
    defaultText = lib.literalExpression "lys-secrets.packages.\${system}.default";
    description = "The lys-secrets package.";
  };
}
