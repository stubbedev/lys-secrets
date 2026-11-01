# The command line the user unit runs: the package's binary with the
# settings of services.lys-secrets. A collection setting left at its
# default adds nothing.
cfg:
"${cfg.package}/bin/lys-secrets --vault-lock-after=${toString cfg.vault.lockAfter}m --vault-sync-interval=${toString cfg.vault.syncInterval}m"
+ (
  if cfg.vault.collectionFolder == ""
  then ""
  else " --vault-collection-folder=${builtins.toJSON cfg.vault.collectionFolder}"
)
+ (
  if cfg.collections.lockAfter == 0
  then ""
  else " --collection-lock-after=${toString cfg.collections.lockAfter}m"
)
+ (
  if cfg.collections.lockOnScreenLock
  then " --collection-lock-on-screen-lock"
  else ""
)
