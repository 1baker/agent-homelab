# Authelia maintenance window

`agent-homelab-authelia-maintenance` applies one reviewed Authelia configuration change, such as adding OIDC clients, as a standard stopped-writer transaction. Use it inside an announced window; users may have to sign in again once.

## What it does

1. **Preflight:** the config, candidate, database and every `--key-input` are regular files, and the candidate differs from the live config.
2. **Validate:** runs `authelia validate-config` on the candidate in a one-off container of the same Compose service. Nothing is stopped yet.
3. **Stop:** stops the service, confirms it isn't running, and confirms the database, `-wal` and `-shm` files stay unchanged for `--quiet-seconds`, so no other writer is left.
4. **Back up:** cold-copies the config, database, `-wal`, `-shm` and key inputs into `<backup-root>/authelia-<UTC>/` (mode 0700, copies 0600). Each copy is checked against its SHA-256, and `manifest.json` records path, size, mode and owner. File contents are never printed.
5. **Apply:** installs the candidate atomically with the original mode and owner.
6. **Start and verify:** starts the service and polls each `--verify URL=STATUS` until it matches or `--verify-timeout` expires.
7. **Roll back** on any failure after step 3: stop, restore every protected file (and remove `-wal`/`-shm` files that didn't exist before), start, verify.

Exit codes: `0` planned or complete, `1` failed before stopping anything, `2` rolled back, `3` rollback failed (restore by hand from the backup directory).

## Example

```sh
agent-homelab-authelia-maintenance \
  --compose-file ~/edge/compose.yml \
  --config ~/edge/authelia/configuration.yml \
  --candidate ./configuration.candidate.yml \
  --database ~/edge/authelia/data/db.sqlite3 \
  --key-input ~/edge/authelia/secrets/oidc-jwks.pem \
  --backup-root ~/edge/backups \
  --verify https://auth.example.invalid/api/health=200 \
  --verify https://auth.example.invalid/.well-known/openid-configuration=200 \
  --verify https://mcp.example.invalid/mcp=401
```

Without `--apply`, this prints the plan and changes nothing. Add `--apply` only inside the window.
