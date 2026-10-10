# Deploying PandaPass

## The shape of it

One host, one container, one volume. nginx and the server run side by side
under s6-overlay inside a single all-in-one container. The container holds an
age private key that can unwrap every user's master key, so **do not put this
on the public internet**. Run it on a machine you control, reachable over
Tailscale or a VPN, behind a TLS-terminating proxy.

```
                      ┌──────────────────────────┐
 browser ────────────▶│   container: pandapass   │
                      │  ┌────────┐    ┌───────┐ │
                      │  │ nginx  │───▶│server │ │
                      │  │ :8080   │    │:8233  │ │
                      │  └────────┘    └───┬───┘ │
                      │                     │     │
                      │            ┌────────▼────┐│
                      │            │   /data     ││  pandapass.db + server-age.key
                      │            └─────────────┘│
                      └──────────────────────────┘
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

## Create the first account

A fresh vault has no users. Open the web UI at http://localhost:8080 and the
login page turns into a **"Create administrator account"** form — the first
visitor becomes admin. No setup token; on a brand-new installation whoever
reaches the page first owns the vault, so do this immediately after starting
the container.

There is no `pandapass register` command. The HTTP registration endpoint is
only used by this first-run form (and, if you explicitly open it, by
`PANDAPASS_ALLOW_REGISTRATION`).

The first account bootstraps as admin. After that, registration is refused
unless `PANDAPASS_ALLOW_REGISTRATION=true` is set.

The admin creates additional team accounts from the web UI (`Users` page).

An account created here has no age key, so it cannot store secrets. Enrol one
from the CLI on the same machine:

```bash
# The container runs as nonroot with no HOME, so pass --out explicitly:
docker compose exec pandapass pandapass keygen --out /tmp/alice-age.key
docker compose cp pandapass:/tmp/alice-age.key ./alice-age.key
chmod 600 alice-age.key
docker compose exec pandapass rm -f /tmp/alice-age.key
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
| `PANDAPASS_ALLOW_REGISTRATION` | `false` | Leave off. The first-run web setup creates the admin without it; this only opens later self-service signups. |
| `PANDAPASS_REQUIRE_TOTP` | `false` | Turn on for real deployments. |
| `PANDAPASS_COMMAND_ALLOWLIST` | empty | Comma-separated. Bounds what `pandapass run` can spawn. |
| `PANDAPASS_SESSION_TTL_DAYS` | `30` | |
| `RUST_LOG` | `info` | Request metadata only; never secret values. |
| `PANDAPASS_DYNAMIC_PROXY_LISTEN` | unset | Bind address for the M2 PostgreSQL proxy, e.g. `127.0.0.1:5433`. Unset disables the proxy. |
| `PANDAPASS_DYNAMIC_PROXY_UPSTREAM` | unset | Upstream PostgreSQL, e.g. `db.internal:5432`. Must be set together with LISTEN. |

### Dynamic credential proxy (M2)

When `PANDAPASS_DYNAMIC_PROXY_LISTEN` and `PANDAPASS_DYNAMIC_PROXY_UPSTREAM`
are both set, the server also speaks the PostgreSQL wire protocol on the
listen address. A client connects using a dynamic credential's username and
password (issued through the API); the proxy checks the credential against the
database — TTL, revocation, kind — before connecting to the upstream. Once
authenticated, it relays bytes without inspecting them, so queries and results
flow through unchanged.

The proxy needs `PANDAPASS_SERVER_AGE_IDENTITY` to unwrap the creator's
envelope and decrypt the stored password, so it cannot run without the server
age identity (which the container already provides via
`PANDAPASS_SERVER_AGE_IDENTITY_FILE`).

In `docker-compose.yml`, the host port `127.0.0.1:5433` is already mapped to
the container. Set `PANDAPASS_DYNAMIC_PROXY_UPSTREAM` in `.env` to point at
your PostgreSQL and the proxy starts on boot.

## Backups

The database and the age key must be backed up together, from the same moment.
A backup of one without the other is not a backup.

The image ships `sqlite3` (installed in the runtime stage of
`docker/Dockerfile`), so the backup runs entirely inside the container.

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
- [ ] `PANDAPASS_ALLOW_REGISTRATION` unset (first-run web setup needs no flag).
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
