# Deploying PandaPass

## The shape of it

One host, two containers, one volume. The server holds an age private key that
can unwrap every user's master key, so **do not put this on the public
internet**. Run it on a machine you control, reachable over Tailscale or a VPN,
behind a TLS-terminating proxy.

```
                    ┌──────────────┐
   browser ────────▶│  web (nginx) │  127.0.0.1:8080
                    └──────┬───────┘
                           │ /api → pandapass:8233
                    ┌──────▼───────┐
                    │   server     │  0.0.0.0:8233 (internal only)
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │  /data       │  pandapass.db + server-age.key
                    └──────────────┘
```

## Start it

```bash
cp .env.example .env      # edit before the first boot
docker compose up -d
docker compose logs -f pandapass
```

The server generates its own age identity on first boot and writes it to
`/data/server-age.key` at mode 0600.

**Back up that file.** Without it, secrets sealed to this server cannot be
unwrapped by anyone — not by you, not by a future operator. Losing the database
*and* the key together loses everything; losing only the key makes the vault
permanently unreadable for writes.

## Register the first account

Registration is closed by default. Open it for exactly as long as it takes:

```bash
# Temporarily, in .env:
PANDAPASS_ALLOW_REGISTRATION=true
docker compose up -d pandapass

# Create the account in a browser at http://localhost:8080
#   — or headless:
docker compose exec pandapass pandapass register \
  --email you@example.com --password-stdin

# Then close it again. This is not optional.
PANDAPASS_ALLOW_REGISTRATION=false
docker compose up -d pandapass
```

The first account bootstraps as admin. After that, registration is refused
regardless of the flag.

An account created here has no age key, so it cannot store secrets. Enrol one
from the CLI on the same machine:

```bash
docker compose exec pandapass pandapass keygen
# it writes to ~/.pandapass/age.key inside the container; copy it out:
docker compose cp pandapass:/root/.pandapass/age.key ./alice-age.key
chmod 600 alice-age.key
```

Keep that file off the server. It is what lets a member read secrets without the
server decrypting on their behalf.

## Point the CLI at it

```bash
pandapass login --server https://vault.internal
pandapass keygen                                  # member age identity
pandapass project create my-app my-app
pandapass env create my-app Production prod
pandapass secret set my-app prod DATABASE_URL 'postgres://…'
```

## Configuration

All server settings are environment variables. The ones that matter:

| Variable | Default | Notes |
|---|---|---|
| `PANDAPASS_DB_URL` | `sqlite://data/pandapass.db?mode=rwc` | **Three** slashes when using an absolute path. Two makes it relative and the server writes inside the container. |
| `PANDAPASS_LISTEN` | `0.0.0.0:8233` | Bind address. |
| `PANDAPASS_PUBLIC_URL` | derived from listen | Set to your `https://` URL; sets the Secure cookie flag. |
| `PANDAPASS_ALLOWED_ORIGINS` | empty | Comma-separated. Empty means same-origin only. |
| `PANDAPASS_SERVER_AGE_IDENTITY_FILE` | — | Path to the server's age private key. |
| `PANDAPASS_ALLOW_REGISTRATION` | `false` | Leave off. |
| `PANDAPASS_REQUIRE_TOTP` | `false` | Turn on for real deployments. |
| `PANDAPASS_COMMAND_ALLOWLIST` | empty | Comma-separated. Bounds what `pandapass run` can spawn. |
| `PANDAPASS_SESSION_TTL_DAYS` | `30` | |
| `RUST_LOG` | `info` | Request metadata only; never secret values. |

## Backups

The database and the age key must be backed up together, from the same moment.
A backup of one without the other is not a backup.

```bash
#!/bin/bash
# /usr/local/bin/pandapass-backup
set -euo pipefail

DEST="/backup/pandapass/$(date +%F)"
mkdir -p "$DEST"

# .backup is safe against a live database; `cp` of the file is not, because
# SQLite is in WAL mode and the pages live in a sidecar file.
docker compose exec -T pandapass sqlite3 /data/pandapass.db ".backup /tmp/b.db"
docker compose cp pandapass:/tmp/b.db "$DEST/pandapass.db"
docker compose exec -T pandapass rm -f /tmp/b.db

docker compose cp pandapass:/data/server-age.key "$DEST/server-age.key"

tar czf "$DEST.tar.gz" -C "$(dirname "$DEST")" "$(basename "$DEST")"
rm -rf "$DEST"
```

```cron
0 3 * * * /usr/local/bin/pandapass-backup >> /var/log/pandapass-backup.log 2>&1
```

Test the restore. A backup that has never been restored is a hypothesis.

## Hardening checklist

- [ ] Host disk encrypted (LUKS). The database is ciphertext, but so is your
      age key file's directory metadata, and an unencrypted disk is a free copy.
- [ ] `docker/data` mode 700.
- [ ] `PANDAPASS_REQUIRE_TOTP=true`.
- [ ] `PANDAPASS_ALLOW_REGISTRATION` unset.
- [ ] Firewall: 8233 and 8080 bound to loopback; reachable only over the VPN.
- [ ] TLS terminated in front. `PANDAPASS_COOKIE_SECURE` then follows
      `PANDAPASS_PUBLIC_URL` automatically.
- [ ] Backups running *and restored at least once*.

## Upgrading

```bash
git pull
docker compose build
docker compose up -d
```

Migrations run automatically at startup and are forward-only. Take a backup
before upgrading; there is no down-migration.

## What SQLite gets you, and where it stops

Right for a team under ~50 people writing well under 20 requests per second,
which is what a vault mostly does — humans clicking. Zero operations, and a
backup is a file copy.

It stops working when you need concurrent writers across machines, point-in-time
recovery, or row-level access control. The data layer is SQLx throughout, so the
move to Postgres is a URL change plus whatever dialect differences the queries
have — not a rewrite.
