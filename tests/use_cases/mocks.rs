use async_trait::async_trait;
use bidmart_auth_be::modules::example::domain::entities::User;
use bidmart_auth_be::modules::example::domain::errors::AuthError;
use bidmart_auth_be::modules::example::domain::traits::UserRepository;

pub struct MockUserRepository {
    find_by_email_result: Option<Result<Option<User>, AuthError>>,
    create_result: Result<User, AuthError>,
}

impl MockUserRepository {
    pub fn new() -> Self {
        Self {
            find_by_email_result: None,
            create_result: Err(AuthError::ValidationError("Not set".to_string())),
        }
    }

    pub fn with_find_by_email(mut self, result: Result<Option<User>, AuthError>) -> Self {
        self.find_by_email_result = Some(result);
        self
    }

    pub fn with_create(mut self, result: Result<User, AuthError>) -> Self {
        self.create_result = result;
        self
    }
}

#[async_trait]
impl UserRepository for MockUserRepository {
    async fn find_by_email(&self, _email: &str) -> Result<Option<User>, AuthError> {
        self.find_by_email_result
            .as_ref()
            .map(|r| match r {
                Ok(opt) => Ok(opt.clone()),
                Err(e) => Err(e.clone()),
            })
            .unwrap_or(Err(AuthError::UserNotFound))
    }

    async fn create(&self, _user: User) -> Result<User, AuthError> {
        match &self.create_result {
            Ok(u) => Ok(u.clone()),
            Err(e) => Err(e.clone()),
        }
    }
}

pub struct MockPasswordService {
    hash_result: Result<String, AuthError>,
    verify_result: Result<bool, AuthError>,
}

impl MockPasswordService {
    pub fn new() -> Self {
        Self {
            hash_result: Err(AuthError::ValidationError("Not set".to_string())),
            verify_result: Err(AuthError::InvalidCredentials),
        }
    }

    pub fn with_hash_success(mut self, hash: String) -> Self {
        self.hash_result = Ok(hash);
        self
    }

    pub fn with_hash_error(mut self, error: AuthError) -> Self {
        self.hash_result = Err(error);
        self
    }

    pub fn with_verify_success(mut self, result: bool) -> Self {
        self.verify_result = Ok(result);
        self
    }
}

#[async_trait]
impl bidmart_auth_be::modules::example::domain::traits::PasswordService for MockPasswordService {
    async fn hash(&self, _password: &str) -> Result<String, AuthError> {
        match &self.hash_result {
            Ok(s) => Ok(s.clone()),
            Err(e) => Err(e.clone()),
        }
    }

    async fn verify(&self, _password: &str, _hash: &str) -> Result<bool, AuthError> {
        match &self.verify_result {
            Ok(b) => Ok(*b),
            Err(e) => Err(e.clone()),
        }
    }
}
