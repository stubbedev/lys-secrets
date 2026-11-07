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
      {
        assertion = !(cfg.sshAgent.enable && config.programs.ssh.startAgent);
        message = ''
          services.lys-secrets.sshAgent.enable and programs.ssh.startAgent both
          set SSH_AUTH_SOCK; enable one of them.
        '';
      }
    ];
    # Shells started outside the systemd user environment find the agent too;
    # lys-secrets hands the same path to systemd and D-Bus activation.
    environment.extraInit = lib.mkIf cfg.sshAgent.enable ''
      export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/lys-secrets/ssh"
    '';
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
