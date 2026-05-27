use async_trait::async_trait;
use sqlx::postgres::PgPool;
use uuid::Uuid;

use crate::modules::auth::domain::entities::UserAuthorization;
use crate::modules::auth::domain::errors::AuthError;
use crate::modules::auth::domain::traits::AuthorizationRepository;

use super::map_database_error;

#[derive(Clone)]
pub struct PostgresAuthorizationRepository {
    pool: PgPool,
}

impl PostgresAuthorizationRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AuthorizationRepository for PostgresAuthorizationRepository {
    async fn get_user_authorization(&self, user_id: Uuid) -> Result<UserAuthorization, AuthError> {
        let roles = sqlx::query_scalar::<_, String>(
            r#"
            SELECT DISTINCT r.name
            FROM user_roles ur
            INNER JOIN roles r ON r.id = ur.role_id
            WHERE ur.user_id = $1
            ORDER BY r.name ASC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(map_database_error)?;

        let permissions = sqlx::query_scalar::<_, String>(
            r#"
            SELECT DISTINCT p.slug
            FROM user_roles ur
            INNER JOIN role_permissions rp ON rp.role_id = ur.role_id
            INNER JOIN permissions p ON p.id = rp.permission_id
            WHERE ur.user_id = $1
            ORDER BY p.slug ASC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(map_database_error)?;

        Ok(UserAuthorization { roles, permissions })
    }

    async fn assign_role_to_user(&self, user_id: Uuid, role_name: &str) -> Result<bool, AuthError> {
        let inserted_user_id = sqlx::query_scalar::<_, Uuid>(
            r#"
            INSERT INTO user_roles (user_id, role_id)
            SELECT u.id, r.id
            FROM users u
            JOIN roles r ON UPPER(r.name) = UPPER($2)
            WHERE u.id = $1
            ON CONFLICT (user_id, role_id) DO NOTHING
            RETURNING user_id
            "#,
        )
        .bind(user_id)
        .bind(role_name)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_database_error)?;

        Ok(inserted_user_id.is_some())
    }

    async fn revoke_role_from_user(
        &self,
        user_id: Uuid,
        role_name: &str,
    ) -> Result<bool, AuthError> {
        let deleted_rows = sqlx::query(
            r#"
            DELETE FROM user_roles ur
            USING roles r
            WHERE ur.role_id = r.id
              AND ur.user_id = $1
              AND UPPER(r.name) = UPPER($2)
            "#,
        )
        .bind(user_id)
        .bind(role_name)
        .execute(&self.pool)
        .await
        .map_err(map_database_error)?
        .rows_affected();

        Ok(deleted_rows > 0)
    }

    async fn assign_permission_to_role(
        &self,
        role_name: &str,
        permission_slug: &str,
    ) -> Result<bool, AuthError> {
        let inserted_role_id = sqlx::query_scalar::<_, i32>(
            r#"
            INSERT INTO role_permissions (role_id, permission_id)
            SELECT r.id, p.id
            FROM roles r
            JOIN permissions p ON p.slug = $2
            WHERE UPPER(r.name) = UPPER($1)
            ON CONFLICT (role_id, permission_id) DO NOTHING
            RETURNING role_id
            "#,
        )
        .bind(role_name)
        .bind(permission_slug)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_database_error)?;

        Ok(inserted_role_id.is_some())
    }

    async fn revoke_permission_from_role(
        &self,
        role_name: &str,
        permission_slug: &str,
    ) -> Result<bool, AuthError> {
        let deleted_rows = sqlx::query(
            r#"
            DELETE FROM role_permissions rp
            USING roles r, permissions p
            WHERE rp.role_id = r.id
              AND rp.permission_id = p.id
              AND UPPER(r.name) = UPPER($1)
              AND p.slug = $2
            "#,
        )
        .bind(role_name)
        .bind(permission_slug)
        .execute(&self.pool)
        .await
        .map_err(map_database_error)?
        .rows_affected();

        Ok(deleted_rows > 0)
    }
}
