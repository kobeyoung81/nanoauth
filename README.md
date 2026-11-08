# nanoauth

OAuth2 / OIDC authentication service for MyriadMind.

## Overview

`nanoauth` provides user registration, password hashing (bcrypt), RS256-signed JWTs,
a public JWKS endpoint for token verification, refresh-token management, and WeChat
Mini Program OAuth login. It holds **no database credentials of its own**: accounts,
refresh tickets and OAuth links all live in the bus's store, reached over the bus's
internal API.

The RSA JWT keypair is **generated automatically and stored behind the bus**
(`service_config_items`, component `auth`, keys `jwtPrivateKey` and `jwtPublicKey`)
on first boot — no key files, volumes, or secrets need to be mounted
anywhere.

The `nanobus` service proxies `/auth/v1/*` to `nanoauth`, so services and the portal
authenticate through a single endpoint.

## API Endpoints

| Method | Path                         | Purpose                                      |
|--------|------------------------------|----------------------------------------------|
| POST   | `/auth/v1/register`          | Create a user (bcrypt password)              |
| POST   | `/auth/v1/token`             | OAuth2 password grant → access + refresh token |
| POST   | `/auth/v1/token/refresh`     | Exchange a refresh token for a new pair      |
| GET    | `/auth/v1/userinfo`          | OIDC userinfo (Bearer token)                 |
| POST   | `/auth/v1/oauth/wechat`      | WeChat Mini Program login (code → token)     |
| GET    | `/auth/v1/.well-known/jwks`  | RS256 public key set for JWT verification    |

## Configuration

Loaded from environment variables (prefix: `NANOAUTH_`). Defaults are defined in
`internal/config`.

| Variable                     | Default          | Description                          |
|------------------------------|------------------|--------------------------------------|
| `NANOAUTH_ADDR`              | `:8081`          | HTTP listen address                  |
| `NANOAUTH_BUS_URL`           | `http://127.0.0.1:9000` | nanobus base URL (the store's only door) |
| `NANOSEC_BUS_INTERNAL_TOKEN` |                  | shared token presented to the bus    |
| `NANOAUTH_JWT_KEY_ID`        | `2026-08`        | JWT `kid` header                     |
| `NANOAUTH_JWT_KEY_BITS`      | `2048`           | RSA modulus size for the generated keypair |
| `NANOAUTH_WECHAT_APP_ID`     |                  | WeChat Mini Program app ID           |
| `NANOAUTH_WECHAT_APP_SECRET` |                  | WeChat Mini Program app secret       |

The RSA keypair is stored in the shared key-value config store (`service_config_items`,
component `auth`, keys `jwtPrivateKey` with `value_type=secret` and `jwtPublicKey` with
`value_type=string`) and generated on first boot, so multiple replicas share the same
signing key. **Security note:** the private key is at rest in the bus's store — restrict
access to the bus and protect its backups.

## LDAP directory login

Set `ldap.enabled=true` and users sign in with their corporate email: `nanoauth`
searches the directory for the entry matching `ldap.userFilter`, binds with the
entry's own DN and the supplied password, and then issues the platform's own JWT.
No directory password is ever stored, and the platform never writes to the
directory.

The settings are edited on the portal's **directory login page** (management
section, `/admin/directory`) or, key by key, in the config center (Configs →
`auth`); both write the same rows, so they always show one truth. The page adds
what the raw keys cannot: a five-step connection probe, a browsable tree, an
attribute analysis that suggests the filter and the identity attributes, a group
picker, and a dry run that walks a real login without creating or linking
anything (`/auth/v1/directory/*`, reachable through the portal's
`/api/admin/v1/directory/*`, verified token and management role required).

| Config key (`service_config_items`, component `auth`) | AD default | OpenLDAP |
|---|---|---|
| `ldap.enabled` | `false` | `false` |
| `ldap.url` | `ldap://127.0.0.1:389` | same |
| `ldap.startTLS` | `false` | same |
| `ldap.tlsInsecureSkipVerify` | `false` | same |
| `ldap.caCertPEM` | *(empty)* | *(empty)* |
| `ldap.timeoutSeconds` | `10` | `10` |
| `ldap.baseDN` | *(empty)* | e.g. `dc=corp,dc=local` |
| `ldap.userFilter` | `(&(objectClass=user)(mail=%s))` | `(&(objectClass=inetOrgPerson)(mail=%s))` |
| `ldap.requiredGroupDN` | *(empty)* | *(empty)* |
| `ldap.groupMatchInChain` | `false` | `false` |
| `ldap.bindDN` | *(empty = anonymous search)* | *(empty)* |
| `ldap.bindPassword` | *(empty)* | *(empty)* |
| `ldap.attrUniqueId` | `objectGUID` | `entryUUID` |
| `ldap.attrUsername` | `sAMAccountName` | `uid` |
| `ldap.attrDisplayName` | `displayName` | `cn` |
| `ldap.autoProvision` | `true` | `true` |
| `ldap.linkPolicy` | `auto` | `auto` |
| `ldap.disableOnMissing` | `false` | `false` |
| `ldap.syncDisplayName` | `false` | `false` |

`ldap.linkPolicy` decides what happens when the directory vouches for an email
that already has a platform account: `auto` links the two, `refuse` leaves the
account alone and answers 409. `ldap.disableOnMissing` suspends a
directory-linked account whose entry has disappeared from the directory (a
departed employee) instead of refusing every login with 401.
`ldap.syncDisplayName` follows a rename in the directory into the platform name
on each login.

The settings are cached for 30 seconds, so an edit in the portal takes effect
without restarting `nanoauth`.

### What happens on a login

1. An account already linked to the directory signs in through the directory
   only: its local `password_hash` is never consulted, even while the directory
   is down (which answers `503` instead of falling back).
2. An account with a local password is offered to the directory first; when the
   email is not in the directory, or the directory cannot be reached, the local
   password still works.
3. An email that exists in the directory but has no platform account yet is
   provisioned on the spot (`ldap.autoProvision=true`) and carries no local
   password.
4. An email matching an existing **normal user** account is linked to that account
   instead of creating a second one (`ldap.linkPolicy=auto`, the default), and its
   local password hash is erased in the same step: from then on the account signs
   in through the directory only. Privileged accounts
   (`admin`/`operator`/`support`/`auditor`) are never linked and never sign in with
   a directory password — editing a `mail` attribute in the directory must not hand
   out platform administration.
5. Directory groups carry no platform roles: a directory user always ends up with
   `role=user` and `tier=free`. Grant roles in the portal.

Provisioning and linking each write an `audit_log` row
(`user.ldap.provision` / `user.ldap.link`).

### Requirements

- `ldap.userFilter` **must keep its `%s` placeholder**: it is where the sign-in
  email goes. Without it every login searches for the same entry and the
  directory answers with several matches, so nobody can sign in — the config
  center accepts such a value (it validates nothing), while the directory login
  page refuses to save it.
- The attribute `ldap.userFilter` matches on must be unique in the directory: a
  duplicate match is refused (401) rather than resolved by picking one entry.
- On AD, `objectGUID` keeps the account across an OU move. Without a usable
  unique attribute the login falls back to `ldap.attrUsername` and then to the
  lowercased DN, which a move would turn into a second account.
- The search may run anonymously; set `ldap.bindDN`/`ldap.bindPassword` when the
  directory requires an authenticated read.
- `ldap.requiredGroupDN` restricts sign-in to that group;
  `ldap.groupMatchInChain` switches to AD's nested-group matching rule
  `1.2.840.113556.1.4.1941` (AD only).

## Build & Run

```bash
go build ./cmd/nanoauth

NANOAUTH_ADDR=:8081 \
NANOAUTH_BUS_URL="http://localhost:9000" \
NANOSEC_BUS_INTERNAL_TOKEN="<the deployment's shared token>" \
./nanoauth
```

## Docker

```bash
docker build -t nanoauth .
docker run -p 8081:8081 \
  -e NANOAUTH_BUS_URL=http://nanobus:9000 \
  -e NANOSEC_BUS_INTERNAL_TOKEN=... \
  nanoauth
```

In the top-level `docker-compose.yml` no keys are mounted — `nanoauth` bootstraps its
keypair through the bus.

## Scope

**Does:** User registration with bcrypt, RS256 JWT signing (DB-stored keypair), JWKS
endpoint, refresh token management, token introspection/validation, WeChat OAuth login.

**Does NOT:** Call LLMs, handle chat platform adapters, manage agent config or sessions.

## Packages

| Package | Purpose |
|---------|---------|
| `cmd/nanoauth` | Binary entry point (env-based config) |
| `internal/config` | Config struct + defaults |
| `internal/server` | HTTP server, routing, CORS |
| `internal/handler` | Auth / OAuth / JWKS handlers |
| `internal/middleware` | Bearer-token auth middleware |
| `internal/store` | Bus-backed users / refresh tokens / `service_config_items` key store |
| `internal/token` | JWT sign/verify (RS256), PEM encode/parse |
