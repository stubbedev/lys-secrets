# D-Bus activation on NixOS under dbus-broker (#5): a client's call to
# org.freedesktop.secrets starts lys-secrets' user unit, and the broker
# loads the activation file without the warning it logs for a file not
# named after its bus name.
#
# Build: nix build .#checks.<system>.activation-vm -L
{
  pkgs,
  self,
}: let
  user = "alice";
  uid = 1000;
  env = "XDG_RUNTIME_DIR=/run/user/${toString uid} DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${toString uid}/bus";
in
  pkgs.testers.nixosTest {
    name = "lys-secrets-activation-vm";

    nodes.machine = {
      imports = [self.nixosModules.default];
      services.lys-secrets.enable = true;
      services.dbus.implementation = "broker";
      users.users.${user} = {
        isNormalUser = true;
        inherit uid;
        linger = true;
      };
    };

    testScript = ''
      def as_user(cmd):
          return f"su - ${user} -c '${env} {cmd}'"

      machine.wait_for_unit("user@${toString uid}.service")
      machine.succeed(as_user("busctl --user call org.freedesktop.secrets /org/freedesktop/secrets org.freedesktop.DBus.Peer Ping"))
      machine.wait_until_succeeds(as_user("systemctl --user is-active lys-secrets.service"))

      journal = machine.succeed("journalctl -b --no-pager")
      assert "is not named after the D-Bus name" not in journal, "dbus-broker warned about an activation file's name"
    '';
  }
