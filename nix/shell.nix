{
  perSystem = {
    pkgs,
    self',
    ...
  }: {
    devShells.default = pkgs.mkShell {
      inputsFrom = [self'.packages.default];

      packages = with pkgs; [
        gopls
        golangci-lint
        delve
        just
        git
        gh
      ];

      env = {
        CGO_ENABLED = 0;
        GOTOOLCHAIN = "local";
      };
    };

    formatter = pkgs.alejandra;
  };
}
