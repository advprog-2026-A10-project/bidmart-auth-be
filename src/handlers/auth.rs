use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
};
use chrono::{Duration, Utc};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    auth::{
        decode_jwt, hash_password, hash_token, issue_jwt, validate_email, validate_password,
        verify_password,
    },
    error::AppError,
    models::{
        AuthResponse, LoginRequest, MessageResponse, PublicUser, RegisterRequest, UserRecord,
    },
    state::AppState,
};

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<AuthResponse>), AppError> {
    let email = validate_email(&payload.email)?;
    validate_password(&payload.password)?;
    let password_hash = hash_password(&payload.password)?;
    let expires_at = Utc::now() + Duration::minutes(state.config.jwt_expiry_minutes);

    let mut tx = state.pool.begin().await?;

    let user = sqlx::query_as::<_, UserRecord>(
        r#"
        INSERT INTO users (email, password_hash, status, mfa_enabled)
        VALUES ($1, $2, 'ACTIVE', false)
        RETURNING id, email, password_hash, status, mfa_enabled, created_at, updated_at
        "#,
    )
    .bind(email)
    .bind(password_hash)
    .fetch_one(&mut *tx)
    .await?;

    insert_profile(&mut tx, &user.id, &payload).await?;

    let token = issue_jwt(user.id, &user.email, &state.config)?;
    let token_hash = hash_token(&token);
    store_session(&mut tx, user.id, token_hash, expires_at).await?;

    tx.commit().await?;

    let response = AuthResponse {
        access_token: token,
        token_type: "Bearer",
        expires_in_minutes: state.config.jwt_expiry_minutes,
        user: user.into(),
    };

    Ok((StatusCode::CREATED, Json(response)))
}

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let email = validate_email(&payload.email)?;

    let user = sqlx::query_as::<_, UserRecord>(
        r#"
        SELECT id, email, password_hash, status, mfa_enabled, created_at, updated_at
        FROM users
        WHERE email = $1
        "#,
    )
    .bind(email)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::Unauthorized("invalid credentials".to_owned()))?;

    if !verify_password(&payload.password, &user.password_hash)? {
        return Err(AppError::Unauthorized("invalid credentials".to_owned()));
    }

    if user.status != "ACTIVE" {
        return Err(AppError::Unauthorized(
            "user is not active. verify account or contact support".to_owned(),
        ));
    }

    let token = issue_jwt(user.id, &user.email, &state.config)?;
    let token_hash = hash_token(&token);
    let expires_at = Utc::now() + Duration::minutes(state.config.jwt_expiry_minutes);

    sqlx::query(
        r#"
        INSERT INTO sessions (user_id, token_hash, ip_address, expired_at)
        VALUES ($1, $2, NULL, $3)
        "#,
    )
    .bind(user.id)
    .bind(token_hash)
    .bind(expires_at)
    .execute(&state.pool)
    .await?;

    Ok(Json(AuthResponse {
        access_token: token,
        token_type: "Bearer",
        expires_in_minutes: state.config.jwt_expiry_minutes,
        user: user.into(),
    }))
}

pub async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<PublicUser>, AppError> {
    let token = extract_bearer_token(&headers)?;
    let claims = decode_jwt(token, &state.config)?;
    ensure_session_is_active(&state.pool, claims.sub, token).await?;

    let user = fetch_user_by_id(&state.pool, claims.sub).await?;
    Ok(Json(user.into()))
}

pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<MessageResponse>, AppError> {
    let token = extract_bearer_token(&headers)?;
    let claims = decode_jwt(token, &state.config)?;
    let token_hash = hash_token(token);

    let deleted = sqlx::query(
        r#"
        DELETE FROM sessions
        WHERE user_id = $1 AND token_hash = $2
        "#,
    )
    .bind(claims.sub)
    .bind(token_hash)
    .execute(&state.pool)
    .await?;

    if deleted.rows_affected() == 0 {
        return Err(AppError::Unauthorized("session not found".to_owned()));
    }

    Ok(Json(MessageResponse {
        message: "logged out".to_owned(),
    }))
}

fn extract_bearer_token(headers: &HeaderMap) -> Result<&str, AppError> {
    let value = headers
        .get(AUTHORIZATION)
        .ok_or_else(|| AppError::Unauthorized("missing authorization header".to_owned()))?;

    let raw = value
        .to_str()
        .map_err(|_| AppError::Unauthorized("invalid authorization header".to_owned()))?;

    raw.strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Unauthorized("expected Bearer token".to_owned()))
}

async fn fetch_user_by_id(pool: &PgPool, user_id: Uuid) -> Result<UserRecord, AppError> {
    sqlx::query_as::<_, UserRecord>(
        r#"
        SELECT id, email, password_hash, status, mfa_enabled, created_at, updated_at
        FROM users
        WHERE id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::NotFound("user not found".to_owned()))
}

async fn ensure_session_is_active(
    pool: &PgPool,
    user_id: Uuid,
    token: &str,
) -> Result<(), AppError> {
    let token_hash = hash_token(token);
    let has_active_session = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS(
            SELECT 1
            FROM sessions
            WHERE user_id = $1
              AND token_hash = $2
              AND expired_at > now()
        )
        "#,
    )
    .bind(user_id)
    .bind(token_hash)
    .fetch_one(pool)
    .await?;

    if !has_active_session {
        return Err(AppError::Unauthorized(
            "session expired or not found".to_owned(),
        ));
    }

    Ok(())
}

async fn insert_profile(
    tx: &mut Transaction<'_, Postgres>,
    user_id: &Uuid,
    payload: &RegisterRequest,
) -> Result<(), AppError> {
    let should_insert = payload.first_name.is_some()
        || payload.last_name.is_some()
        || payload.address.is_some()
        || payload.postal_code.is_some()
        || payload.avatar_url.is_some();

    if !should_insert {
        return Ok(());
    }

    sqlx::query(
        r#"
        INSERT INTO user_profiles (user_id, first_name, last_name, address, postal_code, avatar_url)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(*user_id)
    .bind(payload.first_name.as_deref())
    .bind(payload.last_name.as_deref())
    .bind(payload.address.as_deref())
    .bind(payload.postal_code.as_deref())
    .bind(payload.avatar_url.as_deref())
    .execute(&mut **tx)
    .await?;

    Ok(())
}

async fn store_session(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    token_hash: String,
    expires_at: chrono::DateTime<Utc>,
) -> Result<(), AppError> {
    sqlx::query(
        r#"
        INSERT INTO sessions (user_id, token_hash, ip_address, expired_at)
        VALUES ($1, $2, NULL, $3)
        "#,
    )
    .bind(user_id)
    .bind(token_hash)
    .bind(expires_at)
    .execute(&mut **tx)
    .await?;

    Ok(())
}
