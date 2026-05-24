# bidmart-auth-be

Auth backend service for BidMart, implemented with Rust + Axum + SQLx.

## Current Scope

This service covers BidMart authentication iteration features (`WBS 1.1-1.3`):

- Register + email verification
- Login + MFA (TOTP or email)
- Forgot/reset password
- Session management (`logout`, revoke session, revoke all sessions)
- Settings panel endpoints (profile, security, MFA, notifications)
- Service-to-service auth validation (`POST /auth/validate`)

## Runtime Auth Model

- Hybrid browser auth:
  - `Authorization: Bearer <access_token>`
  - `auth_session` httpOnly cookie
- Login/MFA verify success returns access token and sets session cookie.
- `POST /auth/logout` revokes the active session and clears session cookie.

## API Surface (Current)

Base URL: `http://localhost:8080`

### Health

- `GET /health`
- `GET /ready`

### Auth

- `POST /auth/register`
- `POST /auth/verify-email`
- `POST /auth/resend-verification`
- `POST /auth/forgot-password`
- `POST /auth/reset-password`
- `POST /auth/login`
- `POST /auth/logout`
- `POST /auth/validate`

### MFA (Login Flow)

- `POST /auth/mfa/send-email`
- `POST /auth/mfa/verify-email`
- `POST /auth/mfa/verify-totp`

### Settings

- `GET /settings/profile`
- `PUT /settings/profile`
- `POST /settings/security/password`
- `GET /settings/security/sessions`
- `DELETE /settings/security/sessions/{session_id}`
- `DELETE /settings/security/sessions`
- `GET /settings/security/mfa`
- `POST /settings/security/mfa/totp/setup`
- `POST /settings/security/mfa/totp/verify`
- `POST /settings/security/mfa/email/setup`
- `POST /settings/security/mfa/email/verify`
- `POST /settings/security/mfa/disable`
- `GET /settings/notifications`
- `PUT /settings/notifications`

## Environment

Use `.env.example` as baseline:

```bash
cp .env.example .env
```

Important variables:

- `APP_DATABASE_URL`
- `APP_AUTH_JWT_SECRET` (at least 32 bytes raw key material or decoded base64)
- `APP_VERIFY_EMAIL_URL_BASE`
- `APP_PASSWORD_RESET_URL_BASE`
- `APP_CORS_ALLOWED_ORIGINS`
- `APP_AUTH_SESSION_COOKIE_*`

## Local Development

```bash
cargo run
```

Dengan default `APP_AUTO_MIGRATE_ON_STARTUP=true`, service akan menjalankan pending migrations saat startup.

## Tests

```bash
cargo test
```

## Migrations

Migrations disimpan di `migrations/`.

- Startup migrate (opsional, dikontrol env):
  - `APP_AUTO_MIGRATE_ON_STARTUP=true` -> jalankan pending migrations saat `cargo run`
  - `APP_AUTO_MIGRATE_ON_STARTUP=false` -> skip migrate saat startup
- Dedicated migration job:

```bash
cargo run --bin migrate
```

## References

- Setup and architecture notes: [`SETUP_GUIDE.md`](./SETUP_GUIDE.md)
- Validate contract for core/admin handoff: [`docs/AUTH_VALIDATE_CONTRACT.md`](./docs/AUTH_VALIDATE_CONTRACT.md)
