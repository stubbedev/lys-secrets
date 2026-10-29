# The command line the user unit runs: the package's binary with the
# vault settings of services.lys-secrets.vault.
cfg:
"${cfg.package}/bin/lys-secrets --vault-lock-after=${toString cfg.vault.lockAfter}m --vault-sync-interval=${toString cfg.vault.syncInterval}m"
+ (
  if cfg.vault.collectionFolder == ""
  then ""
  else " --vault-collection-folder=${builtins.toJSON cfg.vault.collectionFolder}"
)
