{
  self,
  inputs,
  ...
}: {
  perSystem = {
    lib,
    pkgs,
    ...
  }: let
    pkg = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
    home =
      (inputs.home-manager.lib.homeManagerConfiguration {
        inherit pkgs;
        modules = [
          self.homeManagerModules.default
          {
            home = {
              username = "u";
              homeDirectory = "/home/u";
              stateVersion = "25.11";
            };
            services.lys-secrets = {
              enable = true;
              vault.lockAfter = 5;
            };
          }
        ];
      }).config;
    nixos =
      (inputs.nixpkgs.lib.nixosSystem {
        inherit (pkgs.stdenv.hostPlatform) system;
        modules = [
          self.nixosModules.default
          {
            services.lys-secrets.enable = true;
            boot.loader.grub.enable = false;
            fileSystems."/" = {
              device = "none";
              fsType = "tmpfs";
            };
            system.stateVersion = "25.11";
          }
        ];
      }).config;
    expect = name: cond:
      if cond
      then pkgs.runCommand name {} "touch $out"
      else throw "${name} failed";
  in {
    checks =
      {
        # The package installs the binary, the unit and the activation file,
        # each naming the installed binary.
        package = pkgs.runCommand "lys-secrets-package" {} ''
          test -x ${pkg}/bin/lys-secrets
          grep -qx 'ExecStart=${pkg}/bin/lys-secrets' ${pkg}/lib/systemd/user/lys-secrets.service
          grep -qx 'Exec=${pkg}/bin/lys-secrets' ${pkg}/share/dbus-1/services/org.freedesktop.secrets.service
          grep -qx 'SystemdService=lys-secrets.service' ${pkg}/share/dbus-1/services/org.freedesktop.secrets.service
          grep -qx 'Exec=${pkg}/bin/lys-secrets' ${pkg}/share/dbus-1/services/dev.stubbe.lys.Vault1.service
          grep -qx 'SystemdService=lys-secrets.service' ${pkg}/share/dbus-1/services/dev.stubbe.lys.Vault1.service
          grep -qx 'BusName=dev.stubbe.lys.Vault1' ${pkg}/lib/systemd/user/lys-secrets.service
          touch $out
        '';

        # home-manager wires D-Bus activation of both names to the packaged
        # unit, starts it with the graphical session, and hands it the vault
        # policy.
        hm-module = expect "lys-secrets-hm-module" (
          home.xdg.dataFile."dbus-1/services/org.freedesktop.secrets.service".source
          == "${pkg}/share/dbus-1/services/org.freedesktop.secrets.service"
          && home.xdg.dataFile."dbus-1/services/dev.stubbe.lys.Vault1.service".source
          == "${pkg}/share/dbus-1/services/dev.stubbe.lys.Vault1.service"
          && home.xdg.configFile."systemd/user/graphical-session.target.wants/lys-secrets.service".source
          == "${pkg}/lib/systemd/user/lys-secrets.service"
          && home.xdg.configFile."systemd/user/lys-secrets.service.d/vault.conf".text
          == "[Service]\nExecStart=\nExecStart=${pkg}/bin/lys-secrets --vault-lock-after=5m --vault-sync-interval=30m\n"
        );

        # NixOS hands the package to D-Bus and systemd and starts the unit
        # with the graphical session.
        nixos-module = expect "lys-secrets-nixos-module" (
          lib.elem pkg nixos.services.dbus.packages
          && lib.elem pkg nixos.systemd.packages
          && lib.elem "graphical-session.target" nixos.systemd.user.services.lys-secrets.wantedBy
          && nixos.systemd.user.services.lys-secrets.serviceConfig.ExecStart
          == ["" "${pkg}/bin/lys-secrets --vault-lock-after=15m --vault-sync-interval=30m"]
        );
      }
      // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
        activation-vm = pkgs.callPackage ./tests/activation-vm.nix {inherit self;};
      };
  };
}
