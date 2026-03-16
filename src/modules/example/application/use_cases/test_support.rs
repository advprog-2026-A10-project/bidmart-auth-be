#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use crate::modules::example::application::use_cases::{
    AuthPolicy, RegisterUserUseCase, ResendVerificationUseCase, VerifyEmailUseCase,
};
use crate::modules::example::domain::entities::{EmailVerificationToken, User};
use crate::modules::example::domain::errors::AuthError;
use crate::modules::example::domain::traits::{
    Clock, EmailVerificationTokenRepository, PasswordHasher, UserRepository,
    VerificationEmailSender, VerificationTokenGenerator, VerificationTokenHasher,
};

pub fn fixed_now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .expect("valid test timestamp")
        .with_timezone(&Utc)
}

pub fn sample_user(email: &str, now: DateTime<Utc>) -> User {
    User::new(
        Uuid::new_v4(),
        email.to_string(),
        "hashed::already".to_string(),
        now,
    )
}

pub fn sample_token(
    user_id: Uuid,
    token_hash: &str,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> EmailVerificationToken {
    EmailVerificationToken {
        id: Uuid::new_v4(),
        user_id,
        token_hash: token_hash.to_string(),
        created_at,
        expires_at,
        consumed_at: None,
        invalidated_at: None,
    }
}

#[derive(Debug, Clone, Default)]
pub struct FakeUserRepositoryState {
    pub users_by_email: HashMap<String, User>,
    pub users_by_id: HashMap<Uuid, User>,
    pub find_by_email_inputs: Vec<String>,
    pub created_users: Vec<User>,
    pub mark_email_verified_calls: Vec<(Uuid, DateTime<Utc>)>,
}

#[derive(Debug, Default)]
pub struct FakeUserRepository {
    pub state: Mutex<FakeUserRepositoryState>,
    pub find_by_email_error: Mutex<Option<AuthError>>,
    pub create_error: Mutex<Option<AuthError>>,
    pub find_by_id_error: Mutex<Option<AuthError>>,
    pub mark_verified_error: Mutex<Option<AuthError>>,
}

impl FakeUserRepository {
    pub fn snapshot(&self) -> FakeUserRepositoryState {
        self.state.lock().expect("state lock poisoned").clone()
    }

    pub fn insert_user(&self, user: User) {
        let mut state = self.state.lock().expect("state lock poisoned");
        state
            .users_by_email
            .insert(user.email.clone(), user.clone());
        state.users_by_id.insert(user.id, user);
    }
}

#[async_trait]
impl UserRepository for FakeUserRepository {
    async fn find_by_email(&self, normalized_email: &str) -> Result<Option<User>, AuthError> {
        if let Some(err) = self
            .find_by_email_error
            .lock()
            .expect("error lock poisoned")
            .clone()
        {
            return Err(err);
        }

        let mut state = self.state.lock().expect("state lock poisoned");
        state
            .find_by_email_inputs
            .push(normalized_email.to_string());
        Ok(state.users_by_email.get(normalized_email).cloned())
    }

    async fn create(&self, user: User) -> Result<User, AuthError> {
        if let Some(err) = self
            .create_error
            .lock()
            .expect("error lock poisoned")
            .clone()
        {
            return Err(err);
        }

        let mut state = self.state.lock().expect("state lock poisoned");
        state.created_users.push(user.clone());
        state
            .users_by_email
            .insert(user.email.clone(), user.clone());
        state.users_by_id.insert(user.id, user.clone());
        Ok(user)
    }

    async fn find_by_id(&self, user_id: Uuid) -> Result<Option<User>, AuthError> {
        if let Some(err) = self
            .find_by_id_error
            .lock()
            .expect("error lock poisoned")
            .clone()
        {
            return Err(err);
        }

        let state = self.state.lock().expect("state lock poisoned");
        Ok(state.users_by_id.get(&user_id).cloned())
    }

    async fn mark_email_verified(
        &self,
        user_id: Uuid,
        verified_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        if let Some(err) = self
            .mark_verified_error
            .lock()
            .expect("error lock poisoned")
            .clone()
        {
            return Err(err);
        }

        let mut state = self.state.lock().expect("state lock poisoned");
        state.mark_email_verified_calls.push((user_id, verified_at));

        let mut updated_user: Option<User> = None;
        if let Some(user) = state.users_by_id.get_mut(&user_id) {
            user.email_verified_at = Some(verified_at);
            updated_user = Some(user.clone());
        }

        if let Some(user) = updated_user {
            state.users_by_email.insert(user.email.clone(), user);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct FakeTokenRepositoryState {
    pub tokens_by_hash: HashMap<String, EmailVerificationToken>,
    pub saved_tokens: Vec<EmailVerificationToken>,
    pub find_by_hash_inputs: Vec<String>,
    pub find_latest_inputs: Vec<Uuid>,
    pub consume_calls: Vec<(Uuid, DateTime<Utc>)>,
    pub invalidate_calls: Vec<(Uuid, DateTime<Utc>)>,
}

#[derive(Debug, Default)]
pub struct FakeTokenRepository {
    pub state: Mutex<FakeTokenRepositoryState>,
    pub save_error: Mutex<Option<AuthError>>,
    pub find_by_hash_error: Mutex<Option<AuthError>>,
    pub find_latest_error: Mutex<Option<AuthError>>,
    pub consume_error: Mutex<Option<AuthError>>,
    pub invalidate_error: Mutex<Option<AuthError>>,
}

impl FakeTokenRepository {
    pub fn snapshot(&self) -> FakeTokenRepositoryState {
        self.state.lock().expect("state lock poisoned").clone()
    }

    pub fn insert_token(&self, token: EmailVerificationToken) {
        let mut state = self.state.lock().expect("state lock poisoned");
        state.tokens_by_hash.insert(token.token_hash.clone(), token);
    }
}

#[async_trait]
impl EmailVerificationTokenRepository for FakeTokenRepository {
    async fn save(&self, token: EmailVerificationToken) -> Result<(), AuthError> {
        if let Some(err) = self.save_error.lock().expect("error lock poisoned").clone() {
            return Err(err);
        }

        let mut state = self.state.lock().expect("state lock poisoned");
        state.saved_tokens.push(token.clone());
        state.tokens_by_hash.insert(token.token_hash.clone(), token);
        Ok(())
    }

    async fn find_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<EmailVerificationToken>, AuthError> {
        if let Some(err) = self
            .find_by_hash_error
            .lock()
            .expect("error lock poisoned")
            .clone()
        {
            return Err(err);
        }

        let mut state = self.state.lock().expect("state lock poisoned");
        state.find_by_hash_inputs.push(token_hash.to_string());
        Ok(state.tokens_by_hash.get(token_hash).cloned())
    }

    async fn find_latest_active_by_user_id(
        &self,
        user_id: Uuid,
    ) -> Result<Option<EmailVerificationToken>, AuthError> {
        if let Some(err) = self
            .find_latest_error
            .lock()
            .expect("error lock poisoned")
            .clone()
        {
            return Err(err);
        }

        let mut state = self.state.lock().expect("state lock poisoned");
        state.find_latest_inputs.push(user_id);

        let latest = state
            .tokens_by_hash
            .values()
            .filter(|token| {
                token.user_id == user_id
                    && token.consumed_at.is_none()
                    && token.invalidated_at.is_none()
            })
            .max_by_key(|token| token.created_at.timestamp_millis())
            .cloned();

        Ok(latest)
    }

    async fn consume(&self, token_id: Uuid, consumed_at: DateTime<Utc>) -> Result<(), AuthError> {
        if let Some(err) = self
            .consume_error
            .lock()
            .expect("error lock poisoned")
            .clone()
        {
            return Err(err);
        }

        let mut state = self.state.lock().expect("state lock poisoned");
        state.consume_calls.push((token_id, consumed_at));

        for token in state.tokens_by_hash.values_mut() {
            if token.id == token_id {
                token.consumed_at = Some(consumed_at);
            }
        }

        Ok(())
    }

    async fn invalidate_active_tokens_for_user(
        &self,
        user_id: Uuid,
        invalidated_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        if let Some(err) = self
            .invalidate_error
            .lock()
            .expect("error lock poisoned")
            .clone()
        {
            return Err(err);
        }

        let mut state = self.state.lock().expect("state lock poisoned");
        state.invalidate_calls.push((user_id, invalidated_at));

        for token in state.tokens_by_hash.values_mut() {
            if token.user_id == user_id
                && token.consumed_at.is_none()
                && token.invalidated_at.is_none()
            {
                token.invalidated_at = Some(invalidated_at);
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct FakePasswordHasherState {
    pub hash_calls: Vec<String>,
}

#[derive(Debug, Default)]
pub struct FakePasswordHasher {
    pub state: Mutex<FakePasswordHasherState>,
    pub hash_error: Mutex<Option<AuthError>>,
}

impl PasswordHasher for FakePasswordHasher {
    fn hash(&self, raw_password: &str) -> Result<String, AuthError> {
        if let Some(err) = self.hash_error.lock().expect("error lock poisoned").clone() {
            return Err(err);
        }

        let mut state = self.state.lock().expect("state lock poisoned");
        state.hash_calls.push(raw_password.to_string());
        Ok(format!("hashed::{raw_password}"))
    }
}

#[derive(Debug, Clone, Default)]
pub struct FakeTokenGeneratorState {
    pub queued_tokens: VecDeque<String>,
    pub generated_tokens: Vec<String>,
    pub generate_calls: usize,
}

#[derive(Debug, Default)]
pub struct FakeTokenGenerator {
    pub state: Mutex<FakeTokenGeneratorState>,
    pub generate_error: Mutex<Option<AuthError>>,
}

impl FakeTokenGenerator {
    pub fn push_token(&self, token: String) {
        self.state
            .lock()
            .expect("state lock poisoned")
            .queued_tokens
            .push_back(token);
    }

    pub fn snapshot(&self) -> FakeTokenGeneratorState {
        self.state.lock().expect("state lock poisoned").clone()
    }
}

impl VerificationTokenGenerator for FakeTokenGenerator {
    fn generate(&self) -> Result<String, AuthError> {
        if let Some(err) = self
            .generate_error
            .lock()
            .expect("error lock poisoned")
            .clone()
        {
            return Err(err);
        }

        let mut state = self.state.lock().expect("state lock poisoned");
        state.generate_calls += 1;

        let token = state
            .queued_tokens
            .pop_front()
            .unwrap_or_else(|| format!("token-{}", state.generate_calls));

        state.generated_tokens.push(token.clone());
        Ok(token)
    }
}

#[derive(Debug, Clone, Default)]
pub struct FakeTokenHasherState {
    pub hash_calls: Vec<String>,
}

#[derive(Debug, Default)]
pub struct FakeTokenHasher {
    pub state: Mutex<FakeTokenHasherState>,
    pub hash_error: Mutex<Option<AuthError>>,
}

impl FakeTokenHasher {
    pub fn deterministic_hash(raw_token: &str) -> String {
        format!("token-hash::{raw_token}")
    }

    pub fn snapshot(&self) -> FakeTokenHasherState {
        self.state.lock().expect("state lock poisoned").clone()
    }
}

impl VerificationTokenHasher for FakeTokenHasher {
    fn hash(&self, raw_token: &str) -> Result<String, AuthError> {
        if let Some(err) = self.hash_error.lock().expect("error lock poisoned").clone() {
            return Err(err);
        }

        let mut state = self.state.lock().expect("state lock poisoned");
        state.hash_calls.push(raw_token.to_string());
        Ok(Self::deterministic_hash(raw_token))
    }
}

#[derive(Debug, Clone, Default)]
pub struct FakeEmailSenderState {
    pub sent_messages: Vec<(String, String)>,
}

#[derive(Debug, Default)]
pub struct FakeEmailSender {
    pub state: Mutex<FakeEmailSenderState>,
    pub send_error: Mutex<Option<AuthError>>,
}

impl FakeEmailSender {
    pub fn snapshot(&self) -> FakeEmailSenderState {
        self.state.lock().expect("state lock poisoned").clone()
    }
}

#[async_trait]
impl VerificationEmailSender for FakeEmailSender {
    async fn send_verification_email(
        &self,
        to_email: &str,
        raw_token: &str,
    ) -> Result<(), AuthError> {
        if let Some(err) = self.send_error.lock().expect("error lock poisoned").clone() {
            return Err(err);
        }

        let mut state = self.state.lock().expect("state lock poisoned");
        state
            .sent_messages
            .push((to_email.to_string(), raw_token.to_string()));
        Ok(())
    }
}

#[derive(Debug)]
pub struct FixedClock {
    current: Mutex<DateTime<Utc>>,
}

impl FixedClock {
    pub fn new(now: DateTime<Utc>) -> Self {
        Self {
            current: Mutex::new(now),
        }
    }

    pub fn set_now(&self, now: DateTime<Utc>) {
        *self.current.lock().expect("clock lock poisoned") = now;
    }
}

impl Clock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        *self.current.lock().expect("clock lock poisoned")
    }
}

pub struct UseCaseTestContext {
    pub user_repository: Arc<FakeUserRepository>,
    pub token_repository: Arc<FakeTokenRepository>,
    pub password_hasher: Arc<FakePasswordHasher>,
    pub token_generator: Arc<FakeTokenGenerator>,
    pub token_hasher: Arc<FakeTokenHasher>,
    pub email_sender: Arc<FakeEmailSender>,
    pub clock: Arc<FixedClock>,
    pub policy: AuthPolicy,
}

impl UseCaseTestContext {
    pub fn new(now: DateTime<Utc>) -> Self {
        Self {
            user_repository: Arc::new(FakeUserRepository::default()),
            token_repository: Arc::new(FakeTokenRepository::default()),
            password_hasher: Arc::new(FakePasswordHasher::default()),
            token_generator: Arc::new(FakeTokenGenerator::default()),
            token_hasher: Arc::new(FakeTokenHasher::default()),
            email_sender: Arc::new(FakeEmailSender::default()),
            clock: Arc::new(FixedClock::new(now)),
            policy: AuthPolicy::default(),
        }
    }

    pub fn with_policy(mut self, policy: AuthPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn register_use_case(&self) -> RegisterUserUseCase {
        RegisterUserUseCase::new(
            self.user_repository.clone(),
            self.token_repository.clone(),
            self.password_hasher.clone(),
            self.token_generator.clone(),
            self.token_hasher.clone(),
            self.email_sender.clone(),
            self.clock.clone(),
            self.policy.clone(),
        )
    }

    pub fn verify_email_use_case(&self) -> VerifyEmailUseCase {
        VerifyEmailUseCase::new(
            self.user_repository.clone(),
            self.token_repository.clone(),
            self.token_hasher.clone(),
            self.clock.clone(),
        )
    }

    pub fn resend_verification_use_case(&self) -> ResendVerificationUseCase {
        ResendVerificationUseCase::new(
            self.user_repository.clone(),
            self.token_repository.clone(),
            self.token_generator.clone(),
            self.token_hasher.clone(),
            self.email_sender.clone(),
            self.clock.clone(),
            self.policy.clone(),
        )
    }

    pub fn seed_token_from_raw(
        &self,
        user_id: Uuid,
        raw_token: &str,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> EmailVerificationToken {
        let token_hash = FakeTokenHasher::deterministic_hash(raw_token);
        let token = sample_token(user_id, &token_hash, created_at, expires_at);
        self.token_repository.insert_token(token.clone());
        token
    }
}

impl Default for UseCaseTestContext {
    fn default() -> Self {
        Self::new(fixed_now())
    }
}

pub fn short_cooldown_policy() -> AuthPolicy {
    AuthPolicy {
        min_password_length: 8,
        verification_token_ttl: Duration::minutes(15),
        resend_cooldown: Duration::seconds(30),
    }
}
