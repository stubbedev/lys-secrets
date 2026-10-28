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

        # dbus runs the tests' private session buses (lys-lib's dbustest).
        # The Secret Service clients lys-secrets is checked against:
        # libsecret's secret-tool, python-secretstorage (DH sessions) and
        # Chromium's libsecret password store; git's libsecret credential
        # helper is GIT_CREDENTIAL_LIBSECRET below.
        dbus
        libsecret
        (python3.withPackages (ps: [ps.secretstorage]))
        chromium
      ];

      env = {
        CGO_ENABLED = 0;
        GOTOOLCHAIN = "local";
        GIT_CREDENTIAL_LIBSECRET = "${pkgs.gitFull}/libexec/git-core/git-credential-libsecret";
      };
    };

    formatter = pkgs.alejandra;
  };
}
