# The command line the user unit runs: the package's binary with the
# vault policy of services.lys-secrets.vault.
cfg: "${cfg.package}/bin/lys-secrets --vault-lock-after=${toString cfg.vault.lockAfter}m --vault-sync-interval=${toString cfg.vault.syncInterval}m"
