# Authentication API

A backend-only authentication service built with FastAPI, SQLAlchemy, and Alembic. It supports email/password registration, email verification, bearer sessions, password reset, and verified Google/Apple ID-token sign-in. SQLite is used for local development; production is configured for PostgreSQL.

This README is an introduction to how the project is structured and how to run and use it. It does not replace the deployment and security requirements in the production section below.

## What happens in the application

For each API request, FastAPI:

1. Parses and validates the JSON body using a Pydantic request model.
2. Calls the matching route function under `app/`.
3. Uses `get_db()` to provide a SQLAlchemy database session.
4. Applies shared helpers for normalization, password hashing, token digests, email delivery, provider-token verification, or rate limiting as needed.
5. Commits persistent changes to the database and returns a JSON response.

The app is assembled in [`app/main.py`](./app/main.py). It mounts each feature router under `/v1/auth`. The database models and connection are defined in [`app/db.py`](./app/db.py); settings are loaded and validated in [`app/config.py`](./app/config.py).

## Project map

```text
app/
  main.py                       Create the FastAPI app, mount routers, expose health/config endpoints
  config.py                     Load settings from environment and validate production requirements
  db.py                         SQLAlchemy models, engine, session factory, and DB dependency
  security.py                   Email/phone normalization, password policy/hash, token digests, client IP
  email_service.py              Send through Resend or log a development-only email preview
  social_auth.py                Create one-time OAuth nonces and verify Google/Apple ID tokens
  registrations/router.py       Create email/password accounts and issue verification OTPs
  email_verifications/router.py Request, resend, and confirm email verification codes
  sign_in/router.py             Verify credentials and create bearer sessions
  sessions/router.py            Authenticate, inspect, and revoke bearer sessions
  password_resets/router.py     Request and consume one-time password-reset links
  rate_limiting/service.py      Apply database-backed limits to authentication requests
migrations/
  env.py                        Connect Alembic to app settings and SQLAlchemy metadata
  versions/                     Ordered database schema changes
requirements.txt                Pinned Python runtime dependencies
.env                            Local-only runtime configuration; ignored by Git
```

### Main code concepts

- **Router:** A feature module that defines HTTP paths, request/response behavior, and calls the database or helpers.
- **Model:** A SQLAlchemy class in `app/db.py` describing a database table.
- **Migration:** A versioned schema change in `migrations/versions/`. Apply migrations to change a database; do not rely on creating tables at app startup.
- **Dependency:** A FastAPI-provided function such as `get_db()` which supplies a database session to a route.
- **Digest:** A one-way HMAC value stored instead of a raw OTP, reset token, session token, or rate-limit identity.

## Requirements and local setup

- Python 3.11 or newer
- The dependencies pinned in `requirements.txt`

### Windows PowerShell

Create and configure `.env` before running these commands. It is local-only and is not included in the repository. For production, configure the required deployment settings described below. For local development, set `APP_ENV=development`, a local `APP_SECRET`, and `DATABASE_URL=sqlite:///./auth_dev.db`; leave the Resend settings blank to use development email previews. See [`app/config.py`](./app/config.py) for all settings.

Run these commands from the project directory:

```powershell
if (-not (Test-Path .venv)) { py -3 -m venv .venv }
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m app.main
```

### macOS/Linux

Run these commands from the project directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m alembic upgrade head
python -m app.main
```

The server defaults to `http://127.0.0.1:8000`. Interactive API documentation is at <http://127.0.0.1:8000/docs>; health status is at <http://127.0.0.1:8000/health>. With the default SQLite URL, local data is stored in `auth_dev.db` in the project directory. Running migrations with SQLite will create that file again.

## Email in development and production

### Local development without mail credentials

If both `RESEND_API_KEY` and `RESEND_FROM_EMAIL` are blank, development does **not** send email. Instead, it writes the full verification email or password-reset email to the server log. Registration and OTP endpoints still return generic responses to avoid revealing account state; check the server log to see the development-only preview. Password-reset responses also identify that no email was sent. Treat these logs as sensitive because they contain usable OTPs or reset links.

### Sending real email

To send mail, set both `RESEND_API_KEY` and `RESEND_FROM_EMAIL` in `.env`. The sender address must be verified with Resend. If only one value is provided, application configuration fails rather than silently pretending to send mail. Email provider errors are reported as `503`; a verification or reset token whose email delivery failed is invalidated.

### Password reset client page

This repository is an API, not a website, so it does not implement the reset form. Set `PASSWORD_RESET_URL` to the page hosted by your client application. Use HTTPS in production; the emailed URL adds `#reset_token=<token>` as a URL fragment. The client page should:

1. Read `reset_token` from the fragment.
2. Remove the fragment from the visible browser address/history after reading it.
3. Ask the user for a new password and confirmation.
4. POST the token and password fields to `/v1/auth/password-resets/confirm`.

The fragment is not sent to the web server as part of the HTTP request for the page. The client must read it in the browser and submit it in the JSON request.

## End-to-end authentication flow

### 1. Register by email and password

Send `POST /v1/auth/registrations` with an email, first name, and password. The API normalizes the email, validates the password and optional phone number, hashes the password with Argon2id, and creates a `pending` user. It also creates a six-digit OTP record and sends or previews the verification email. The response is generic (`202`) whether or not that email can be registered, so clients should tell the user to check their email.

```json
{
  "email": "person@example.com",
  "first_name": "Alex",
  "password": "Strong!234",
  "phone": "+1 415 555 2671"
}
```

`phone` is optional. When provided, it is validated and stored in E.164 format.

### 2. Verify email

The user submits the code from the message to `POST /v1/auth/email-verifications/confirm`:

```json
{
  "email": "person@example.com",
  "code": "123456"
}
```

By default, the six-digit code expires 10 minutes after delivery, can only be used once, and has at most five attempts. A wrong code returns `400` with `Wrong OTP entered.` Expired, used, or otherwise unavailable codes return a generic invalid/expired response. Resending a code invalidates the previous code and is subject to a cooldown.

### 3. Sign in

After verification, send `POST /v1/auth/sessions`:

```json
{
  "email": "person@example.com",
  "password": "Strong!234"
}
```

The response contains an opaque bearer token. The database stores only its digest. The client must store the raw token securely and send it as `Authorization: Bearer <access_token>` on authenticated requests. Do not log or expose it.

### 4. Use or revoke a session

- `GET /v1/auth/sessions/current` returns the authenticated user and session metadata.
- `DELETE /v1/auth/sessions/current` revokes the presented session.

Sessions expire after `SESSION_TTL_DAYS` (30 days by default). Invalid, expired, or revoked tokens return `401`.

### 5. Reset a password

Request a reset with `POST /v1/auth/password-resets`:

```json
{
  "email": "person@example.com"
}
```

The API gives the same generic response whether or not an eligible account exists, to reduce account enumeration. For an active, verified email/password account, it creates a one-time reset token and sends a link. The database stores only the token digest. The default expiry is 10 minutes from successful delivery. After the client submits the token and matching new passwords to `/v1/auth/password-resets/confirm`, the API consumes the token and revokes that user's existing sessions.

### 6. Google and Apple sign-in

The client uses the Google or Apple SDK to perform the provider's authorization flow and obtain an ID token. The API does not handle provider passwords or implement the provider's authorization screen.

1. Request `POST /v1/auth/social/challenges` with `{"provider":"google"}` or `{"provider":"apple"}`.
2. The response contains a short-lived `nonce` and a `provider_nonce`. Pass `provider_nonce` as the nonce when starting the provider SDK flow. For Google, it is the raw nonce; for Apple, it is its SHA-256 hash.
3. Send the resulting ID token and the original raw `nonce` to either registration or sign-in.
4. The API verifies the token's RS256 signature using the provider's published JWKS, issuer, audience, expiry, issue time, and nonce. The nonce challenge is single-use. Email registration also requires an email claim verified by the provider.

Register a new social account using `POST /v1/auth/registrations`:

```json
{
  "provider": "google",
  "id_token": "<provider-id-token>",
  "nonce": "<raw-nonce-from-challenge>"
}
```

Sign in an existing social account using `POST /v1/auth/sessions` with the same provider, ID token, and raw nonce fields. Social identities are matched by the verified provider `sub` claim, not by an email supplied by the client. A provider ID token that omits an email can sign in to an existing identity, but cannot create a new account. Configure the provider's actual client IDs in `GOOGLE_CLIENT_IDS` and `APPLE_CLIENT_IDS` (comma-separated if multiple apps/platforms are supported). The client's redirect/state handling should use the provider SDK's recommended protections; do not send provider access tokens in place of ID tokens.

## API reference

All request and response bodies are JSON, except successful session revocation (`204 No Content`). Paths below include the `/v1/auth` prefix.

| Method and path | Purpose | Important behavior |
|---|---|---|
| `POST /registrations` | Create email/password or social account | `202` generic response; email accounts become pending and receive an OTP; social accounts require a verified provider ID token and one-time nonce |
| `POST /email-verifications` | Request verification code | `202` generic response for unknown, ineligible, or eligible email; eligible pending account receives a code |
| `POST /email-verifications/resend` | Resend verification code | Previous code is invalidated; resend cooldown applies |
| `POST /email-verifications/confirm` | Confirm verification code | Wrong code reports `Wrong OTP entered.`; attempt limit applies |
| `POST /sessions` | Sign in | Email accounts require the correct password and verified active account; social accounts require a verified provider ID token and a one-time nonce |
| `POST /social/challenges` | Start Google or Apple sign-in | Returns a one-time nonce; the caller must start provider authorization using `provider_nonce` |
| `GET /sessions/current` | Get current identity | Requires a valid bearer session |
| `DELETE /sessions/current` | Revoke current session | Requires a valid bearer session; returns `204` |
| `POST /password-resets` | Request password reset | Always returns generic confirmation for unknown/ineligible accounts |
| `POST /password-resets/confirm` | Set new password with reset token | Token is single-use and expiry-limited; revokes sessions |

`GET /runtime-config` returns public password and OTP policy settings for a client. It never returns secrets. `GET /health` is a basic liveness response.

Typical status codes include `201` for social challenge creation, `202` for account/verification/reset requests, `400` for invalid/expired OTP or reset token, `401` for invalid credentials/session/provider token, `403` for an unverified or inactive account, `422` for invalid input, `429` for rate limits, and `503` for unavailable email delivery or provider key service. Signup and verification-request responses are deliberately generic to reduce account enumeration. Rate-limit responses include a `Retry-After` header.

## How data is stored

The application has one configured database per running environment. `DATABASE_URL` selects it: a SQLite file for local development or PostgreSQL for production. Account and authentication records are stored in that database, not in `.env`. Deleting the local SQLite file removes its records; running Alembic against the SQLite URL recreates an empty database schema. In production, records are stored by the PostgreSQL service named in `DATABASE_URL`. SQLAlchemy maps application objects to these tables; it is not an additional database.

| Table | What it stores |
|---|---|
| `users` | Normalized email, profile, password hash, account status, verification timestamp, and provider metadata |
| `email_verifications` | OTP digest, expiry, attempt count, and consumed timestamp |
| `auth_sessions` | Bearer-session digest, expiry, and revocation timestamp |
| `password_resets` | Password-reset digest, expiry, and consumed timestamp |
| `oauth_challenges` | Provider, nonce digest, expiry, and consumed timestamp for one-time sign-in requests |
| `rate_limits` | Digested identity/IP keys, request count, and rate-limit window |

Passwords are hashed with Argon2id; OTPs, session tokens, reset tokens, and rate-limit keys are HMAC-digested using `APP_SECRET`. Raw passwords and authentication tokens are not stored in these tables. Timestamps are stored in UTC. User-related records have foreign keys that cascade when a user is deleted directly from the database.

Expired/consumed verification and reset records and old rate-limit rows are not automatically cleaned up. This project has no account-deletion API or scheduled cleanup job.

## Configuration

Settings are loaded from `.env` or the deployment environment in [`app/config.py`](./app/config.py). No environment file is committed to Git. Never commit real credentials. Important settings groups:

| Purpose | Settings |
|---|---|
| Runtime and database | `APP_ENV`, `APP_SECRET`, `DATABASE_URL`, `SERVER_HOST`, `SERVER_PORT`, `SERVER_RELOAD`, `DB_POOL_SIZE`, `DB_MAX_OVERFLOW` |
| Email and reset links | `RESEND_API_KEY`, `RESEND_FROM_EMAIL`, `RESEND_API_URL`, `EMAIL_TIMEOUT_SECONDS`, `PASSWORD_RESET_URL` |
| Social identity verification | `GOOGLE_CLIENT_IDS`, `APPLE_CLIENT_IDS`, `SOCIAL_AUTH_NONCE_TTL_MINUTES`, `SOCIAL_CHALLENGE_RATE_LIMIT` |
| Passwords and sessions | `PASSWORD_MIN_LENGTH`, `PASSWORD_MAX_LENGTH`, `PASSWORD_REQUIRE_*`, `PASSWORD_HASH_*`, `PASSWORD_SALT_LENGTH`, `SESSION_TTL_DAYS`, `TOKEN_BYTES` |
| OTP and reset expiry | `OTP_DIGITS`, `OTP_TTL_MINUTES`, `OTP_MAX_ATTEMPTS`, `OTP_RESEND_COOLDOWN_SECONDS`, `PASSWORD_RESET_TTL_MINUTES` |
| Request limits | `AUTH_RATE_LIMIT_WINDOW_SECONDS`, `SIGNUP_RATE_LIMIT`, `SIGNIN_RATE_LIMIT`, `OTP_*_RATE_LIMIT`, `RESET_*_RATE_LIMIT` |
| User input and proxies | `FIRST_NAME_MAX_LENGTH`, `PHONE_INPUT_MAX_LENGTH`, `TRUSTED_PROXY_CIDRS` |

Production configuration is validated at application startup. It requires PostgreSQL over TLS, a unique secret, HTTPS reset URL, configured Resend credentials, both provider client ID settings, a disabled development reload, and the configured minimum password/hash requirements. Set these values directly in your deployment environment or secret store. Generate an app secret locally with `python -c "import secrets; print(secrets.token_urlsafe(48))"` and enter it directly in the secret store; do not send it to chat or commit it. Provider client IDs are public identifiers, not secrets; the Resend key and database credentials are secrets.

## Database migrations

Alembic version files in `migrations/versions/` describe schema changes in order. The Alembic environment imports the application models and uses `DATABASE_URL`. After changing models, create and review a migration before applying it. For an existing database or a fresh local database, apply the current migration chain with:

```powershell
.\.venv\Scripts\python.exe -m alembic upgrade head
```

```bash
python -m alembic upgrade head
```

Migrations are not automatically run by the API process. In production, take a backup, review the migration, apply it as a controlled deployment step, then deploy application instances.

## Social-provider boundaries

The API validates Google and Apple ID tokens, but the client is responsible for starting the OAuth/OIDC flow with the correct app configuration. This API does not implement a browser redirect/callback, provider authorization-code exchange, account linking, or MFA. Accounts are matched by provider plus the provider's stable `sub`; accounts that share an email are not automatically linked. For production, register every web/mobile client ID in the corresponding comma-separated setting, configure the same audience in the provider SDK, and validate the client app's redirect/state behavior. Use HTTPS between the client and API; do not log ID tokens, raw nonces, or session tokens.

## Common development tasks

- Add or change an endpoint: edit the appropriate router under `app/`.
- Change a database table: update the model in `app/db.py`, generate/review a migration, then apply it with Alembic.
- Change password/OTP expiry, limits, email sender, or server settings: edit local `.env` or the deployment environment.
- Explore request and response schemas: run the server and open `/docs`.
- Diagnose an email flow locally: run the server in development without Resend credentials and inspect its terminal logs; OTPs and reset links in those logs are sensitive.
