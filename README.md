# nanoauth

Who you are: accounts, tokens and the key set every other service verifies with.

It is one of the eight first-class services. It owns the `auth_` prefix and hands a
signed identity to the rest of the platform.

## What it is

- **Accounts and credentials.** Registration, bcrypt hashes, account status and
  tier; the first account of a fresh installation becomes the administrator.
- **RS256 tokens and a JWKS.** Access tokens for every service, a refresh ticket
  that rotates, and a public key set at a stable URL.
- **Channel identities.** A person can be reachable on several chat platforms; the
  bindings live inside the account document.
- **Directory login.** LDAP and Active Directory, configured in the admin module,
  with the same credential path as a local password.
- **A login surface.** The sign-in screens are built here and served by the portal
  as the `auth` plugin.

## Where it sits

| | |
|---|---|
| Collections | `auth_users`, `auth_secrets`, `auth_refresh_tokens`, `auth_oauth_providers`, `auth_git_shortcuts` |
| Port | `8081` in the network, `14401` on the host (loopback) |
| Upstream | browsers, the gateway, the mini program, every service that validates a token |
| Downstream | `nanoadmin` — configuration (the key pair, directory settings) and the audit trail |
| Endpoints | `/auth/v1/*`, plus `/plugins/auth/` for the built front end |

## Quick start

```bash
go build ./cmd/nanoauth
NANOAUTH_MONGO_URI="mongodb://localhost:27017/nanosec" \
NANOSEC_ADMIN_URL="http://localhost:14404" \
NANOSEC_BUS_INTERNAL_TOKEN="…" \
  ./nanoauth
```

No key files to mount: the RSA key pair is generated on first boot and written into
the admin module's configuration (`admin_config`, component `auth`), so every replica
signs with the same key.

## Configuration

| Variable | Meaning |
|---|---|
| `NANOAUTH_MONGO_URI` | The platform database; falls back to `NANOSEC_BUS_DATABASE_URI` |
| `NANOAUTH_ADDR` | Listen address, default `:8081` |
| `NANOSEC_ADMIN_URL` | Where configuration and the audit trail live |
| `NANOSEC_BUS_INTERNAL_TOKEN` | Shared secret for the admin module's internal surfaces |
| `NANOAUTH_JWT_KEY_ID` | `kid` published with the key set |
| `NANOAUTH_TOKEN_TTL` / `NANOAUTH_REFRESH_TTL` | Access token and refresh ticket lifetimes, in seconds |
| `NANOAUTH_WECHAT_APP_ID` / `NANOAUTH_WECHAT_APP_SECRET` | Mini Program login |
| `NANOAUTH_UI_DIR` | Built front end to serve under `/plugins/auth/`; empty disables it |

Directory settings — host, bind DN, base DN, filters — are configuration, not
environment: they live under `ldap.*` and are edited in the console.

## API

| Endpoint | What it does |
|---|---|
| `POST /auth/v1/register` | Create an account |
| `POST /auth/v1/token` | Password or directory login → access token + refresh ticket |
| `POST /auth/v1/token/refresh` | Rotate the ticket, get a new access token |
| `POST /auth/v1/logout` | Invalidate the ticket |
| `GET /auth/v1/userinfo` | Claims for a bearer token |
| `POST /auth/v1/oauth/wechat` | Mini Program login |
| `GET /auth/v1/.well-known/jwks` | The public key set |
| `GET /healthz`, `GET /metrics` | Liveness and Prometheus |

## Design decisions

- **One write creates a person.** The account and its channel identities are a
  single `insertOne`; there is no half-onboarded user with an orphan channel row.
- **The refresh token is a ticket, not a JWT.** It is a random string stored in
  `auth_refresh_tokens`, so logout and rotation are real revocations.
- **The key pair lives in configuration.** Generated once, read by every replica,
  and rotated by replacing the value — no secret volume to mount.
- **Directory login authenticates, it does not store.** A successful bind returns an
  identity that this service maps onto an account; the directory is never written.

## Docs

- [`docs/ACCOUNT_MANAGEMENT_DESIGN.md`](https://gitee.com/kobeyoung81/nanosec/blob/master/docs/ACCOUNT_MANAGEMENT_DESIGN.md) — accounts, channels and sessions
- [`docs/ARCHITECTURE.md`](https://gitee.com/kobeyoung81/nanosec/blob/master/docs/ARCHITECTURE.md) — the platform around this module
- [`docs/README.md`](https://gitee.com/kobeyoung81/nanosec/blob/master/docs/README.md) — every document

## Status

Released as part of `v0.1.0`; the version of this module is pinned in the
super-repo's `versions.lock`.

## Contributing and security

[`CONTRIBUTING.md`](https://gitee.com/kobeyoung81/nanosec/blob/master/CONTRIBUTING.md)
for setup and commit rules; report vulnerabilities privately through
[`SECURITY.md`](https://gitee.com/kobeyoung81/nanosec/blob/master/SECURITY.md), never
in a public issue.

## License

[AGPL-3.0](./LICENSE). The name and logo are covered separately — see
[`NOTICE`](./NOTICE).
