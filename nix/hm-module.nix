self: {
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.lys-secrets;
  activation = "dbus-1/services/org.freedesktop.secrets.lys-secrets.service";
  unit = "${cfg.package}/lib/systemd/user/lys-secrets.service";
in {
  options.services.lys-secrets = import ./options.nix self {inherit lib pkgs;};

  config = lib.mkIf cfg.enable {
    # The activation file clients start lys-secrets through, handing them
    # to the packaged user unit, which every graphical session also starts.
    xdg.dataFile.${activation}.source = "${cfg.package}/share/${activation}";
    xdg.configFile = {
      "systemd/user/lys-secrets.service".source = unit;
      "systemd/user/graphical-session.target.wants/lys-secrets.service".source = unit;
    };
  };
}
