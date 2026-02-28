# Clean Architecture Axum Project Setup Guide

This document provides instructions for agents to replicate the `bidmart-auth-be` project structure.

## Project Overview

- **Project Name**: bidmart-auth-be
- **Type**: Rust Axum REST API
- **Architecture**: Modular Clean Architecture
- **Database**: PostgreSQL with SQLx
- **Authentication**: JWT with scrypt password hashing

## Directory Structure

```
<project-name> /
├── Cargo.toml
├── build.rs
├── .env.example
├── migrations/                  # SQLx migrations
│   └── YYYYMMDDHHMMSS_description.sql
└── src/
    ├── main.rs
    ├── lib.rs
    ├── infrastructure/           # Global Technical & Configuration
    │   ├── config/             # Environment Variables
    │   ├── database/           # DB Connection Pool
    │   ├── logger/             # Logger Implementation
    │   └── filters/            # Global Exception Filters
    │
    ├── modules/                 # Feature Modules (Vertical Slices)
    │   └── auth/              # Auth Module
    │       ├── application/   # Use Cases & DTOs
    │       │   ├── dto/
    │       │   └── use_cases/
    │       ├── domain/        # Entities, Errors, Repository Interfaces
    │       │   ├── entities/
    │       │   ├── errors/
    │       │   └── traits/
    │       └── infrastructure/ # Controllers, Repositories & Services
    │           ├── controllers/
    │           ├── repositories/
    │           └── services/
    │
    └── shared/                 # Cross-cutting Components
        └── domain/            # Result Pattern, etc.
```

## Step-by-Step Setup

### Step 1: Create Project

```bash
cargo new --bin <project-name>
cd <project-name>
```

### Step 2: Create Folder Structure

```bash
mkdir -p src/{infrastructure/{config,database,logger,filters},modules/auth/{application/{dto,use_cases},domain/{entities,errors,traits},infrastructure/{controllers,repositories}},shared/domain}
```

### Step 3: Update Cargo.toml

```toml
[package]
name = "<project-name>"
version = "0.1.0"
edition = "2021"
description = "Modular Clean Architecture Axum API"

[dependencies]
axum = { version = "0.7", features = ["macros"] }
tower = "0.4"
tower-http = { version = "0.5", features = ["cors", "trace"] }

tokio = { version = "1", features = ["full"] }

serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

validator = { version = "0.16", features = ["derive"] }

thiserror = "1.0"
anyhow = "1.0"

sqlx = { version = "0.8", features = ["runtime-tokio-rustls", "postgres", "chrono", "uuid", "migrate"] }

config = "0.14"
dotenv = "0.15"

tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

uuid = { version = "1.0", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
scrypt = "0.10"
rand = "0.8"
jsonwebtoken = "9.2"
async-trait = "0.1"

[dev-dependencies]
tower = { version = "0.4", features = ["util"] }
axum = "0.7"
```

### Step 4: Create Infrastructure Layer

**src/infrastructure/config/mod.rs**

```rust
use config::ConfigError;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub jwt: JwtConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub url: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct JwtConfig {
    pub secret: String,
    pub expiration_hours: i64,
}

impl AppConfig {
    pub fn new() -> Result<Self, ConfigError> {
        dotenv::dotenv().ok();
        let config = config::Config::builder()
            .add_source(config::Environment::default().prefix("APP_"))
            .build()?;
        config.try_deserialize()
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8080,
            },
            database: DatabaseConfig {
                url: "postgres://postgres:password@localhost:5432/bidmart".to_string(),
            },
            jwt: JwtConfig {
                secret: "your-secret-key-change-in-production".to_string(),
                expiration_hours: 24,
            },
        }
    }
}
```

**src/infrastructure/database/mod.rs**

```rust
pub mod connection;
pub use connection::create_pool;
```

**src/infrastructure/database/connection.rs**

```rust
use sqlx::postgres::{PgPool, PgPoolOptions};

pub async fn create_pool(database_url: &str) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await
}
```

**src/infrastructure/logger/mod.rs**

```rust
pub mod tracer;
pub use tracer::init_tracer;
```

**src/infrastructure/logger/tracer.rs**

```rust
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub fn init_tracer() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "bidmart_auth_be=debug,tower=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}
```

**src/infrastructure/filters/mod.rs**

```rust
pub mod error_handler;
```

**src/infrastructure/filters/error_handler.rs**

```rust
use axum::http::StatusCode;

#[allow(dead_code)]
pub fn handle_error<E: std::fmt::Debug>(err: E) -> (StatusCode, String) {
    tracing::error!("Error: {:?}", err);
    (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
}
```

**src/infrastructure/mod.rs**

```rust
pub mod config;
pub mod database;
pub mod logger;
pub mod filters;
```

### Step 5: Create Modules/Auth/Domain Layer

**src/modules/auth/domain/entities/user.rs**

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub username: String,
    pub role: UserRole,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum UserRole {
    Admin,
    User,
}

impl User {
    pub fn new(email: String, password_hash: String, username: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            email,
            password_hash,
            username,
            role: UserRole::User,
            created_at: now,
            updated_at: now,
        }
    }
}
```

**src/modules/auth/domain/entities/mod.rs**

```rust
pub mod user;
pub use user::*;
```

**src/modules/auth/domain/errors/mod.rs**

```rust
use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum AuthError {
    #[error("User not found")]
    UserNotFound,
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Invalid token")]
    InvalidToken,
    #[error("Token expired")]
    TokenExpired,
    #[error("Unauthorized access")]
    Unauthorized,
    #[error("Validation error: {0}")]
    ValidationError(String),
}

impl serde::Serialize for AuthError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
```

**src/modules/auth/domain/traits/mod.rs**

```rust
use crate::modules::auth::domain::entities::User;
use crate::modules::auth::domain::errors::AuthError;
use async_trait::async_trait;

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AuthError>;
    async fn create(&self, user: User) -> Result<User, AuthError>;
}
```

**src/modules/auth/domain/mod.rs**

```rust
pub mod entities;
pub mod errors;
pub mod traits;
```

### Step 6: Create Modules/Auth/Application Layer

**src/modules/auth/application/dto/mod.rs**

```rust
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Deserialize, Validate, Serialize)]
pub struct RegisterUserDto {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub password: String,
    #[validate(length(min = 3, max = 50, message = "Username must be between 3 and 50 characters"))]
    pub username: String,
}

#[derive(Debug, Deserialize, Validate, Serialize)]
pub struct LoginUserDto {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponseDto {
    pub token: String,
    pub user: UserDto,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserDto {
    pub id: uuid::Uuid,
    pub email: String,
    pub username: String,
    pub role: String,
}

impl From<crate::modules::auth::domain::entities::User> for UserDto {
    fn from(user: crate::modules::auth::domain::entities::User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            username: user.username,
            role: match user.role {
                crate::modules::auth::domain::entities::UserRole::Admin => "admin".to_string(),
                crate::modules::auth::domain::entities::UserRole::User => "user".to_string(),
            },
        }
    }
}
```

**src/modules/auth/application/use_cases/jwt_service.rs**

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct JwtConfig {
    pub secret: String,
    pub expiration_hours: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
}

pub struct JwtService {
    config: JwtConfig,
}

impl JwtService {
    pub fn new(config: JwtConfig) -> Self {
        Self { config }
    }

    pub fn generate_token(&self, subject: &str) -> Result<String, crate::modules::auth::domain::errors::AuthError> {
        let now = chrono::Utc::now();
        let expiration = now + chrono::Duration::hours(self.config.expiration_hours);

        let claims = Claims {
            sub: subject.to_string(),
            exp: expiration.timestamp(),
            iat: now.timestamp(),
        };

        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(self.config.secret.as_bytes()),
        )
        .map_err(|_| crate::modules::auth::domain::errors::AuthError::ValidationError("Failed to generate token".to_string()))?;

        Ok(token)
    }
}

impl Clone for JwtService {
    fn clone(&self) -> Self {
        Self {
            config: JwtConfig {
                secret: self.config.secret.clone(),
                expiration_hours: self.config.expiration_hours,
            },
        }
    }
}
```

**src/modules/auth/application/use_cases/register_use_case.rs**

```rust
use std::sync::Arc;
use scrypt::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Scrypt,
};
use rand::thread_rng;

use crate::modules::auth::application::dto::{RegisterUserDto, UserDto, AuthResponseDto};
use crate::modules::auth::application::use_cases::jwt_service::JwtService;
use crate::modules::auth::domain::entities::User;
use crate::modules::auth::domain::errors::AuthError;
use crate::modules::auth::domain::traits::UserRepository;

pub struct RegisterUseCase {
    user_repository: Arc<dyn UserRepository>,
    jwt_service: JwtService,
}

impl RegisterUseCase {
    pub fn new(user_repository: Arc<dyn UserRepository>, jwt_service: JwtService) -> Self {
        Self { user_repository, jwt_service }
    }

    pub async fn execute(&self, dto: RegisterUserDto) -> Result<AuthResponseDto, AuthError> {
        let existing_user = self.user_repository.find_by_email(&dto.email).await?;
        if existing_user.is_some() {
            return Err(AuthError::UserAlreadyExists);
        }

        let password_hash = hash(dto.password.as_bytes(), DEFAULT_COST)
            .map_err(|_| AuthError::ValidationError("Failed to hash password".to_string()))?;

        let user = User::new(dto.email, password_hash, dto.username);
        let created_user = self.user_repository.create(user).await?;
        let token = self.jwt_service.generate_token(&created_user.id.to_string())?;

        Ok(AuthResponseDto {
            token,
            user: UserDto::from(created_user),
        })
    }
}
```

**src/modules/auth/application/use_cases/login_use_case.rs**

```rust
use std::sync::Arc;
use scrypt::{
    password_hash::{PasswordHash, PasswordVerifier, Scrypt},
};

use crate::modules::auth::application::dto::{LoginUserDto, UserDto, AuthResponseDto};
use crate::modules::auth::application::use_cases::jwt_service::JwtService;
use crate::modules::auth::domain::errors::AuthError;
use crate::modules::auth::domain::traits::UserRepository;

pub struct LoginUseCase {
    user_repository: Arc<dyn UserRepository>,
    jwt_service: JwtService,
}

impl LoginUseCase {
    pub fn new(user_repository: Arc<dyn UserRepository>, jwt_service: JwtService) -> Self {
        Self { user_repository, jwt_service }
    }

    pub async fn execute(&self, dto: LoginUserDto) -> Result<AuthResponseDto, AuthError> {
        let user = self.user_repository.find_by_email(&dto.email).await?
            .ok_or(AuthError::InvalidCredentials)?;

        if !verify(dto.password.as_bytes(), &user.password_hash)
            .map_err(|_| AuthError::InvalidCredentials)?
        {
            return Err(AuthError::InvalidCredentials);
        }

        let token = self.jwt_service.generate_token(&user.id.to_string())?;
        Ok(AuthResponseDto {
            token,
            user: UserDto::from(user),
        })
    }
}
```

**src/modules/auth/application/use_cases/mod.rs**

```rust
pub mod jwt_service;
pub mod register_use_case;
pub mod login_use_case;

pub use jwt_service::{JwtConfig, JwtService};
pub use register_use_case::RegisterUseCase;
pub use login_use_case::LoginUseCase;
```

**src/modules/auth/application/mod.rs**

```rust
pub mod dto;
pub mod use_cases;
```

### Step 7: Create Modules/Auth/Infrastructure Layer

**src/modules/auth/infrastructure/repositories/user_repository.rs**

```rust
use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::modules::auth::domain::entities::user::{User, UserRole};
use crate::modules::auth::domain::errors::AuthError;
use crate::modules::auth::domain::traits::UserRepository;
use sqlx::{postgres::PgPool, Row};

pub struct PostgresUserRepository {
    pool: PgPool,
}

impl PostgresUserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for PostgresUserRepository {
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AuthError> {
        let row = sqlx::query(
            "SELECT id, email, password_hash, username, role, created_at, updated_at FROM users WHERE email = $1"
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| AuthError::UserNotFound)?;

        Ok(row.map(|r| Self::row_to_user(r)))
    }

    async fn create(&self, user: User) -> Result<User, AuthError> {
        let role_str = match user.role { UserRole::Admin => "admin", UserRole::User => "user" };
        let row = sqlx::query(
            "INSERT INTO users (id, email, password_hash, username, role, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING id, email, password_hash, username, role, created_at, updated_at"
        )
        .bind(user.id)
        .bind(&user.email)
        .bind(&user.password_hash)
        .bind(&user.username)
        .bind(role_str)
        .bind(user.created_at)
        .bind(user.updated_at)
        .fetch_one(&self.pool)
        .await
        .map_err(|_| AuthError::ValidationError("Failed to create user".to_string()))?;

        Ok(Self::row_to_user(row))
    }
}

impl PostgresUserRepository {
    fn row_to_user(row: sqlx::postgres::PgRow) -> User {
        let role_str: String = row.get("role");
        let role = match role_str.as_str() { "admin" => UserRole::Admin, _ => UserRole::User };

        User {
            id: row.get("id"),
            email: row.get("email"),
            password_hash: row.get("password_hash"),
            username: row.get("username"),
            role,
            created_at: row.get::<DateTime<Utc>, _>("created_at"),
            updated_at: row.get::<DateTime<Utc>, _>("updated_at"),
        }
    }
}
```

**src/modules/auth/infrastructure/repositories/mod.rs**

```rust
pub mod user_repository;
pub use user_repository::PostgresUserRepository;
```

**src/modules/auth/infrastructure/controllers/register_controller.rs**

```rust
use axum::{extract::State, http::StatusCode, response::Json};
use validator::Validate;

use crate::modules::auth::application::dto::{RegisterUserDto, AuthResponseDto};
use crate::modules::auth::infrastructure::AppState;

pub async fn register(
    State(state): State<AppState>,
    Json(dto): Json<RegisterUserDto>,
) -> Result<Json<AuthResponseDto>, (StatusCode, String)> {
    dto.validate().map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    state.register_use_case.execute(dto).await
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
}
```

**src/modules/auth/infrastructure/controllers/login_controller.rs**

```rust
use axum::{extract::State, http::StatusCode, response::Json};
use validator::Validate;

use crate::modules::auth::application::dto::{LoginUserDto, AuthResponseDto};
use crate::modules::auth::infrastructure::AppState;

pub async fn login(
    State(state): State<AppState>,
    Json(dto): Json<LoginUserDto>,
) -> Result<Json<AuthResponseDto>, (StatusCode, String)> {
    dto.validate().map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    state.login_use_case.execute(dto).await
        .map(Json)
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))
}
```

**src/modules/auth/infrastructure/controllers/mod.rs**

```rust
pub mod register_controller;
pub mod login_controller;

pub use register_controller::register;
pub use login_controller::login;
```

**src/modules/auth/infrastructure/mod.rs**

```rust
use std::sync::Arc;
use axum::{routing::{get, post}, Router};

use crate::modules::auth::application::use_cases::{LoginUseCase, RegisterUseCase};
use crate::modules::auth::infrastructure::controllers::{login, register};

pub mod controllers;
pub mod repositories;

#[derive(Clone)]
pub struct AppState {
    pub register_use_case: Arc<RegisterUseCase>,
    pub login_use_case: Arc<LoginUseCase>,
}

pub fn create_router(state: AppState) -> Router {
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/auth/register", post(register))
        .route("/api/v1/auth/login", post(login));
    app.with_state(state)
}

async fn health_check() -> axum::response::Json<serde_json::Value> {
    axum::response::Json(serde_json::json!({"status": "ok", "service": "bidmart-auth-be"}))
}
```

**src/modules/auth/mod.rs**

```rust
pub mod domain;
pub mod application;
pub mod infrastructure;
```

**src/modules/mod.rs**

```rust
pub mod auth;
```

### Step 8: Create Shared Layer

**src/shared/domain/result.rs**

```rust
#[allow(dead_code)]
pub type Result<T, E = crate::modules::auth::domain::errors::AuthError> = std::result::Result<T, E>;
```

**src/shared/domain/mod.rs**

```rust
pub mod result;
```

**src/shared/mod.rs**

```rust
pub mod domain;
```

### Step 9: Create main.rs and lib.rs

**src/lib.rs**

```rust
pub mod infrastructure;
pub mod modules;
pub mod shared;
```

**src/main.rs**

```rust
mod infrastructure;
mod modules;
mod shared;

use std::sync::Arc;
use axum::serve;
use tokio::net::TcpListener;

use infrastructure::config::AppConfig;
use infrastructure::database::create_pool;
use infrastructure::logger::init_tracer;
use modules::auth::application::use_cases::{JwtConfig, JwtService, LoginUseCase, RegisterUseCase};
use modules::auth::infrastructure::create_router;
use modules::auth::infrastructure::repositories::PostgresUserRepository;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracer();
    let config = AppConfig::new().unwrap_or_default();
    let pool = create_pool(&config.database.url).await?;

    sqlx::migrate!().run(&pool).await?;

    let user_repository = Arc::new(PostgresUserRepository::new(pool));
    let jwt_config = JwtConfig { secret: config.jwt.secret, expiration_hours: config.jwt.expiration_hours };
    let jwt_service = JwtService::new(jwt_config);

    let register_use_case = Arc::new(RegisterUseCase::new(user_repository.clone(), jwt_service.clone()));
    let login_use_case = Arc::new(LoginUseCase::new(user_repository, jwt_service));

    let app_state = modules::auth::infrastructure::AppState { register_use_case, login_use_case };
    let router = create_router(app_state);

    let address = format!("{}:{}", config.server.host, config.server.port);
    let listener = TcpListener::bind(&address).await?;
    tracing::info!("Starting server on {}", address);

    serve(listener, router).await?;
    Ok(())
}
```

### Step 10: Create Migrations and build.rs

**build.rs**
```rust
fn main() {
    println!("cargo:rerun-if-changed=migrations/");
}
```

**migrations/YYYYMMDDHHMMSS_create_users_table.sql**
```sql
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    username VARCHAR(50) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
```

Migrations run automatically on server startup via `sqlx::migrate!().run(&pool).await?` in main.rs.

**Schema File (Single Source of Truth):**

Create `migrations/schema.sql` as the master schema definition. When schema changes, run `cargo sqlx migrate add <description>` to generate new migration files.

**Adding New Migrations:**
```bash
cargo install sqlx-cli --no-default-features --features postgres
cargo sqlx migrate add create_new_table
```

### Step 11: Environment Variables

Create `.env` file:

```env
APP_SERVER_HOST=0.0.0.0
APP_SERVER_PORT=8080
APP_DATABASE_URL=postgres://postgres:password@localhost:5432/bidmart
APP_JWT_SECRET=your-secret-key-change-in-production
APP_JWT_EXPIRATION_HOURS=24
```

### Step 12: Build and Run

```bash
cargo build
cargo run
```
