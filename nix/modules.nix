{self, ...}: {
  flake = {
    # NixOS: `imports = [lys-secrets.nixosModules.default]; services.lys-secrets.enable = true;`
    nixosModules.default = import ./nixos-module.nix self;

    # home-manager: `imports = [lys-secrets.homeManagerModules.default]; services.lys-secrets.enable = true;`
    homeManagerModules.default = import ./hm-module.nix self;
  };
}
