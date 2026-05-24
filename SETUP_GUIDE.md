# BidMart Auth BE Setup Guide

Dokumen ini adalah panduan setup `bidmart-auth-be` sesuai kondisi aktual codebase.

## Project Overview

- **Project Name**: `bidmart-auth-be`
- **Type**: Rust Axum REST API
- **Architecture**: Modular Clean Architecture
- **Database**: PostgreSQL (`sqlx`)
- **Authentication**: JWT (HS256) dengan scrypt password hashing
- **Session Mode**: Hybrid (`Authorization` bearer + `auth_session` httpOnly cookie)

## Active Modules

- `auth` — register, login, email verification, password reset, MFA (email + TOTP), `/auth/validate`, dan settings security MFA endpoints.

## Important Docs

- Service-to-service token validation contract: [`docs/AUTH_VALIDATE_CONTRACT.md`](./docs/AUTH_VALIDATE_CONTRACT.md)

## Directory Structure (top-level)

```text
bidmart-auth-be/
├── Cargo.toml
├── Dockerfile
├── .env.example
├── migrations/                 # SQLx migrations
├── docs/
├── tests/                      # Crate-level integration tests (workspace tests)
└── src/
    ├── main.rs
    ├── lib.rs
    ├── infrastructure/         # Global technical & configuration
    │   ├── config/             # Environment variables
    │   ├── database/           # DB connection pool
    │   ├── logger/             # Tracing setup
    │   └── filters/            # Global error handlers
    ├── modules/                # Feature modules (vertical slices)
    │   └── auth/
    └── shared/                 # Cross-cutting components (Result, dll)
        └── domain/
```

## Per-Module Clean Architecture

Setiap modul di `src/modules/<module>/` mengikuti pola Clean Architecture tiga-layer yang konsisten.
Struktur kanonis (semua sub-direktori opsional kecuali `domain/` dan `application/`):

```text
modules/<module>/
├── application/
│   ├── dto/                    # Request/response DTOs (+ validator)
│   └── use_cases/              # Application use cases
│       └── tests/              # (opsional) Unit tests untuk use cases
│           ├── mod.rs
│           ├── support.rs      # Shared test fixtures / fakes
│           └── <use_case>.rs   # Satu file per use case yang ditest
├── domain/
│   ├── entities/               # Domain entities (struct + behavior)
│   ├── errors/                 # Domain-level error enums
│   └── traits/                 # Repository / port interfaces
├── infrastructure/
│   ├── controllers/            # Axum handlers / route glue
│   │   └── tests.rs            # (opsional) Unit tests yang butuh akses item private
│   ├── repositories/           # Implementasi repository (Postgres, dsb.)
│   ├── services/               # (opsional) Implementasi domain services
│   ├── middleware/             # (opsional) Tower middleware modul-spesifik
│   └── tests/                  # (opsional) Contract / integration-style tests
│       ├── mod.rs
│       └── contracts.rs
└── mod.rs
```

Penerapan aktual di modul `auth`:

```text
src/modules/auth/
├── application/
│   ├── dto/
│   └── use_cases/
│       └── tests/
│           ├── mod.rs
│           ├── support.rs
│           ├── register_user_use_case.rs
│           ├── verify_email_use_case.rs
│           ├── resend_verification_use_case.rs
│           ├── password_reset_use_case.rs
│           └── auth_mfa_use_case.rs
├── domain/
│   ├── entities/
│   ├── errors/
│   └── traits/
└── infrastructure/
    ├── controllers/
    ├── repositories/
    ├── services/
    ├── tests/
    │   ├── mod.rs
    │   └── contracts.rs
    ├── auth_extractor.rs
    ├── session_cookie.rs
    └── mod.rs
```

## Test Placement Conventions

Production code dan test code dipisahkan secara konsisten. Pakai pola berikut:

1. **`src/modules/<m>/application/use_cases/tests/`**
   - Unit tests untuk use case (logika aplikasi murni).
   - Satu file per use case, plus `support.rs` untuk fixtures / in-memory fakes.
   - Didaftarkan di `use_cases/mod.rs` dengan `#[cfg(test)] pub(crate) mod tests;`.

2. **`src/modules/<m>/infrastructure/tests/`**
   - Contract / integration-style tests pada level modul (mis. HTTP contract via `tower::ServiceExt`).
   - Boleh berisi in-memory repositories, support helpers, dan beberapa file test.

3. **`src/modules/<m>/infrastructure/controllers/tests.rs`** *(sibling file)*
   - Hanya digunakan ketika test perlu akses langsung ke item private di file implementasi controller.
   - Pakai pola ini sebagai pengecualian, bukan default.

4. **`tests/` di root project**
   - Crate-level integration tests (entity tests, service-level tests, migration conflict checks, dll).

Hindari menempatkan blok `#[cfg(test)] mod tests { ... }` panjang langsung di file implementasi utama —
selalu pindahkan ke subtree `tests/` atau sibling `tests.rs` sesuai konvensi di atas.

## Configuration

Buat file `.env`:

```env
APP_SERVER_HOST=0.0.0.0
APP_SERVER_PORT=8080
APP_DATABASE_URL=postgres://postgres:password@localhost:5432/bidmart
APP_AUTO_MIGRATE_ON_STARTUP=true
APP_AUTH_JWT_SECRET=replace-with-at-least-32-bytes-of-key-material
APP_AUTH_ACCESS_TOKEN_TTL_SECONDS=3600
APP_AUTH_MFA_TICKET_TTL_SECONDS=300
APP_AUTH_EMAIL_MFA_CODE_TTL_SECONDS=30
APP_AUTH_EMAIL_MFA_COOLDOWN_SECONDS=30
APP_AUTH_TOTP_SETUP_TTL_SECONDS=600
APP_RESEND_API_KEY=re_xxxxxxxxxxxxxxxxxxxxxxxxx
APP_RESEND_FROM_EMAIL=BidMart <noreply@bidmart.bid>
APP_VERIFY_EMAIL_URL_BASE=http://localhost:5173/auth/verify-email?token=
APP_PASSWORD_RESET_URL_BASE=http://localhost:5173/auth/reset-password?token=
APP_CORS_ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
```

`APP_AUTH_JWT_SECRET` harus berisi minimal 32 byte key material mentah, atau base64 standar yang
ter-decode minimal 32 byte. JWT access tokens HS256-only dan wajib membawa klaim
`sub`, `iat`, `exp`, `jti`, `scope`, dan `mfa_satisfied`. Persisted session lookup by hashed `jti`
diperlukan untuk protected settings routes.

## Runtime Endpoints

Modul `auth` mengekspos endpoint top-level (tanpa prefix `/api/v1`):

### Public auth flow

- `POST /auth/register`
- `POST /auth/resend-verification`
- `POST /auth/verify-email`
- `POST /auth/forgot-password`
- `POST /auth/reset-password`
- `POST /auth/login`
- `POST /auth/mfa/send-email`
- `POST /auth/mfa/verify-email`
- `POST /auth/mfa/verify-totp`

### Service-to-service

- `POST /auth/validate` — lihat [`docs/AUTH_VALIDATE_CONTRACT.md`](./docs/AUTH_VALIDATE_CONTRACT.md)

### Protected settings (memerlukan recent-auth via `currentPassword`)

- `/settings/security/mfa/*` — TOTP setup, email MFA setup, MFA verification setup, dan MFA disable.

## Running

```bash
cargo build
cargo run
```

## Dev Database Utilities

Untuk environment lokal, tersedia script utilitas:

```bash
./scripts/reset-db.sh
./scripts/seed-db.sh
./scripts/reset-and-seed-db.sh
```

Catatan:

- Semua script membaca `APP_DATABASE_URL` dari environment (`.env`).
- `reset-db` hanya menghapus data aplikasi (bukan metadata migration `sqlx`).
- `seed-db` mengisi akun contoh:
  - `hakimnizami15@gmail.com` (ACTIVE, verified)
  - `hakimnizami05@gmail.com` (ACTIVE, unverified)
  - `pending.user@bidmart.dev` (PENDING_VERIFICATION, unverified)
  - `pending.verified@bidmart.dev` (PENDING_VERIFICATION, verified)
  - `disabled.user@bidmart.dev` (DISABLED, verified)
  - `disabled.unverified@bidmart.dev` (DISABLED, unverified)
  - `active.verified@bidmart.dev` (ACTIVE, verified)
  - Password semua akun seed: `Password123!`

Migrations dijalankan melalui helper `run_pending_migrations` yang membaca folder `./migrations`.

- `APP_AUTO_MIGRATE_ON_STARTUP=true` (default): pending migrations dijalankan saat startup `cargo run`.
- `APP_AUTO_MIGRATE_ON_STARTUP=false`: startup tidak menjalankan migrations.
- Jalankan migration job manual:

```bash
cargo run --bin migrate
```

Untuk menambah migration baru:

```bash
cargo install sqlx-cli --no-default-features --features postgres
cargo sqlx migrate add <description>
```

## Tests

```bash
cargo test
```

Pola yang dipakai di codebase saat ini:

- `auth`:
  - use-case unit tests di `src/modules/auth/application/use_cases/tests/`
  - contract / module-level tests di `src/modules/auth/infrastructure/tests/`
- Crate-level integration tests berada di root `tests/` (entity tests, service tests, use-case tests, migration conflict tests).

## Residual Security Notes

- TOTP menggunakan `totp-rs` (RFC 6238). Saat ini TOTP secrets disimpan plaintext di
  `users.mfa_totp_secret` dan `totp_setups.secret`. Tambahkan authenticated encryption sebelum
  rollout production.
- Current-password adalah kontrak recent-auth untuk milestone ini: TOTP setup, email MFA setup,
  MFA verification setup, dan MFA disable wajib menyertakan `currentPassword`.
