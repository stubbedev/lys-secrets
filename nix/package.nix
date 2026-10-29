{self, ...}: {
  perSystem = {
    lib,
    pkgs,
    ...
  }: {
    packages.default = pkgs.buildGo127Module {
      pname = "lys-secrets";
      version = "0-unstable-${self.lastModifiedDate or "0"}";

      src = lib.fileset.toSource {
        root = ../.;
        fileset = lib.fileset.difference (lib.fileset.gitTracked ../.) (
          lib.fileset.unions [
            ../flake.nix
            ../flake.lock
            ../nix
          ]
        );
      };

      # The module cache's hash; `just vendor-hash` recomputes it after a
      # go.mod change.
      vendorHash = "sha256-t+eOEw1k2f+rdIEDjWQaZ4UDZQuypyDcV0Z0FifKOlY=";

      subPackages = ["cmd/lys-secrets"];

      env.CGO_ENABLED = 0;
      ldflags = ["-s" "-w"];

      # The suite runs in `just check`: it needs private D-Bus sessions and
      # the Secret Service clients of the dev shell.
      doCheck = false;

      # The user unit and the D-Bus activation files, for the modules to
      # wire up. Installing the package alone activates neither, since
      # gnome-keyring's activation file may claim the same name.
      postInstall = ''
        install -d $out/lib/systemd/user $out/share/dbus-1/services
        substitute resources/lys-secrets.service $out/lib/systemd/user/lys-secrets.service \
          --replace-fail /usr/bin/lys-secrets "$out/bin/lys-secrets"
        for activation in org.freedesktop.secrets dev.stubbe.lys.Vault1; do
          substitute resources/$activation.service $out/share/dbus-1/services/$activation.service \
            --replace-fail /usr/bin/lys-secrets "$out/bin/lys-secrets"
        done
      '';

      meta = {
        description = "the lys desktop's freedesktop Secret Service";
        homepage = "https://github.com/stubbedev/lys-secrets";
        license = lib.licenses.mit;
        mainProgram = "lys-secrets";
        platforms = lib.platforms.linux;
      };
    };
  };
}
