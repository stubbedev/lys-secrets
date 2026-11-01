self: {
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.lys-secrets;
  activations = map (name: "dbus-1/services/${name}.service") ["org.freedesktop.secrets" "dev.stubbe.lys.Vault1"];
  unit = "${cfg.package}/lib/systemd/user/lys-secrets.service";
in {
  options.services.lys-secrets = import ./options.nix self {inherit lib pkgs;};

  config = lib.mkIf cfg.enable {
    # The activation files clients start lys-secrets through, handing them
    # to the packaged user unit, which every graphical session also starts,
    # its command line carrying the settings.
    xdg.dataFile = lib.genAttrs activations (path: {source = "${cfg.package}/share/${path}";});
    xdg.configFile = {
      "systemd/user/lys-secrets.service".source = unit;
      "systemd/user/graphical-session.target.wants/lys-secrets.service".source = unit;
      "systemd/user/lys-secrets.service.d/vault.conf".text = ''
        [Service]
        ExecStart=
        ExecStart=${import ./exec.nix cfg}
      '';
    };
  };
}
