# pinentry-lys as a package of its own, whose main program it is, for the
# gpg-agent options that take a pinentry package.
{
  pkgs,
  cfg,
}:
pkgs.runCommand "pinentry-lys" {meta.mainProgram = "pinentry-lys";} ''
  install -d $out/bin
  ln -s ${cfg.package}/bin/pinentry-lys $out/bin/pinentry-lys
''
