self: {
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.lys-secrets;
in {
  options.services.lys-secrets = import ./options.nix self {inherit lib pkgs;};

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = !config.services.gnome.gnome-keyring.enable;
        message = ''
          services.lys-secrets.enable and services.gnome.gnome-keyring.enable
          both provide org.freedesktop.secrets; enable one of them.
        '';
      }
    ];
    # The activation files clients start lys-secrets through, and the user
    # unit it hands them to, started with every graphical session under
    # the vault policy.
    services.dbus.packages = [cfg.package];
    systemd.packages = [cfg.package];
    systemd.user.services.lys-secrets = {
      wantedBy = ["graphical-session.target"];
      serviceConfig.ExecStart = ["" (import ./exec.nix cfg)];
    };
  };
}
