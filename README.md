# bidmart-auth-be

A Rust Axum REST API with Modular Clean Architecture for user authentication (register/login).

## Tech Stack

- **Language**: Rust
- **Web Framework**: Axum
- **Database**: PostgreSQL with SQLx
- **Authentication**: JWT + scrypt password hashing
- **Architecture**: Modular Clean Architecture

## Project Structure

```
src/
├── infrastructure/           # Global Technical & Configuration
│   ├── config/              # Environment Variables
│   ├── database/            # DB Connection Pool
│   ├── logger/              # Logger Implementation
│   └── filters/             # Global Exception Filters
│
├── modules/                 # Feature Modules (Vertical Slices)
│   └── auth/               # Auth Module
│       ├── application/    # Use Cases & DTOs
│       ├── domain/         # Entities, Errors, Repository Interfaces
│       └── infrastructure/ # Controllers & Repositories
│
└── shared/                  # Cross-cutting Components
    └── domain/             # Result Pattern, etc.
```

## Prerequisites

- Rust (latest stable)
- PostgreSQL
- Docker & Docker Compose (optional)

## Setup

### 1. Clone and Setup

```bash
# Clone the project
cd bidmart-auth-be

# Copy environment template
cp .env.example .env
```

### 2. Configure Environment

Edit `.env` file:

```env
APP_SERVER_HOST=0.0.0.0
APP_SERVER_PORT=8080
APP_DATABASE_URL=postgres://postgres:password@localhost:5432/bidmart
APP_JWT_SECRET=your-secret-key-change-in-production
APP_JWT_EXPIRATION_HOURS=24
```

### 3. Database Setup

Ensure PostgreSQL is running and create the database:

```bash
# Create database (adjust credentials as needed)
createdb -U postgres bidmart
```

Or connect to your PostgreSQL server and run:
```sql
CREATE DATABASE bidmart;
```

**Note:** Set `APP_DATABASE_URL` in `.env` to point to your PostgreSQL instance.

### 4. Run Database Migrations

Migrations run automatically on server startup. The `migrations/` folder contains SQLx migration files.

**Adding new migrations:**

```bash
# Install sqlx-cli
cargo install sqlx-cli --no-default-features --features postgres

# Create a new migration
cargo sqlx migrate add create_new_table
```

The master schema is stored in `migrations/schema.sql`.

## Run

```bash
# Development
cargo run
```

Server starts at `http://localhost:8080`

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/api/v1/auth/register` | Register new user |
| POST | `/api/v1/auth/login` | Login |

### Register

```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123",
    "username": "johndoe"
  }'
```

**Response:**

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "username": "johndoe",
    "role": "user"
  }
}
```

### Login

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }'
```

**Response:**

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "username": "johndoe",
    "role": "user"
  }
}
```

### Health Check

```bash
curl http://localhost:8080/health
```

**Response:**

```json
{
  "service": "bidmart-auth-be",
  "status": "ok"
}
```

## Build

```bash
cargo build
```

## License

MIT
