#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use crate::modules::auth::application::dto::{AuthenticatedUserContext, IssuedAccessToken};
use crate::modules::auth::application::use_cases::auth_mfa_use_case::AuthMfaUseCase;
use crate::modules::auth::application::use_cases::policy::AuthPolicy;
use crate::modules::auth::application::use_cases::register_user_use_case::RegisterUserUseCase;
use crate::modules::auth::application::use_cases::resend_verification_use_case::ResendVerificationUseCase;
use crate::modules::auth::application::use_cases::verify_email_use_case::VerifyEmailUseCase;
use crate::modules::auth::domain::entities::{
    AuthSession, EmailMfaCode, EmailVerificationToken, MfaTicket, TotpSetup, User, UserStatus,
};
use crate::modules::auth::domain::errors::AuthError;
use crate::modules::auth::domain::traits::{
    Clock, EmailMfaCodeRepository, EmailVerificationTokenRepository, JwtService, MfaEmailSender,
    MfaTicketRepository, PasswordHasher, PasswordVerifier, SessionRepository, TotpService,
    TotpSetupRepository, UserRepository, VerificationEmailSender, VerificationTokenGenerator,
    VerificationTokenHasher,
};

pub fn fixed_now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .expect("valid test timestamp")
        .with_timezone(&Utc)
}

pub fn sample_user(name: &str, email: &str, now: DateTime<Utc>) -> User {
    User::new(
        Uuid::new_v4(),
        name,
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

pub fn sample_mfa_ticket(
    user_id: Uuid,
    ticket_hash: &str,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> MfaTicket {
    MfaTicket {
        id: Uuid::new_v4(),
        user_id,
        ticket_hash: ticket_hash.to_string(),
        created_at,
        expires_at,
        consumed_at: None,
    }
}

pub fn sample_email_mfa_code(
    user_id: Uuid,
    code_hash: &str,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> EmailMfaCode {
    EmailMfaCode {
        id: Uuid::new_v4(),
        user_id,
        code_hash: code_hash.to_string(),
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
        if state.users_by_email.contains_key(&user.email) {
            return Err(AuthError::EmailAlreadyExists);
        }
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
            user.status = UserStatus::Active;
            user.email_verified_at = Some(verified_at);
            user.updated_at = verified_at;
            updated_user = Some(user.clone());
        }

        if let Some(user) = updated_user {
            state.users_by_email.insert(user.email.clone(), user);
        }

        Ok(())
    }

    async fn update_mfa_email_enabled(
        &self,
        user_id: Uuid,
        enabled: bool,
        updated_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        let mut state = self.state.lock().expect("state lock poisoned");
        let mut updated_user: Option<User> = None;
        if let Some(user) = state.users_by_id.get_mut(&user_id) {
            user.mfa_email_enabled = enabled;
            user.updated_at = updated_at;
            updated_user = Some(user.clone());
        }
        if let Some(user) = updated_user {
            state.users_by_email.insert(user.email.clone(), user);
            Ok(())
        } else {
            Err(AuthError::UserNotFound)
        }
    }

    async fn update_mfa_totp(
        &self,
        user_id: Uuid,
        enabled: bool,
        secret: Option<String>,
        updated_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        let mut state = self.state.lock().expect("state lock poisoned");
        let mut updated_user: Option<User> = None;
        if let Some(user) = state.users_by_id.get_mut(&user_id) {
            user.mfa_totp_enabled = enabled;
            user.mfa_totp_secret = secret;
            user.updated_at = updated_at;
            updated_user = Some(user.clone());
        }
        if let Some(user) = updated_user {
            state.users_by_email.insert(user.email.clone(), user);
            Ok(())
        } else {
            Err(AuthError::UserNotFound)
        }
    }

    async fn disable_mfa(&self, user_id: Uuid, updated_at: DateTime<Utc>) -> Result<(), AuthError> {
        let mut state = self.state.lock().expect("state lock poisoned");
        let mut updated_user: Option<User> = None;
        if let Some(user) = state.users_by_id.get_mut(&user_id) {
            user.mfa_email_enabled = false;
            user.mfa_totp_enabled = false;
            user.mfa_totp_secret = None;
            user.updated_at = updated_at;
            updated_user = Some(user.clone());
        }
        if let Some(user) = updated_user {
            state.users_by_email.insert(user.email.clone(), user);
            Ok(())
        } else {
            Err(AuthError::UserNotFound)
        }
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

    async fn consume(&self, token_id: Uuid, consumed_at: DateTime<Utc>) -> Result<bool, AuthError> {
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

        let mut updated = false;
        for token in state.tokens_by_hash.values_mut() {
            if token.id == token_id && token.consumed_at.is_none() && token.invalidated_at.is_none()
            {
                token.consumed_at = Some(consumed_at);
                updated = true;
            }
        }

        Ok(updated)
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

impl FakePasswordHasher {
    pub fn snapshot(&self) -> FakePasswordHasherState {
        self.state.lock().expect("state lock poisoned").clone()
    }
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
pub struct FakePasswordVerifierState {
    pub decisions: HashMap<(String, String), bool>,
    pub verify_calls: Vec<(String, String)>,
}

#[derive(Debug, Default)]
pub struct FakePasswordVerifier {
    pub state: Mutex<FakePasswordVerifierState>,
    pub verify_error: Mutex<Option<AuthError>>,
}

impl FakePasswordVerifier {
    pub fn accept(&self, raw_password: &str, password_hash: &str) {
        self.state
            .lock()
            .expect("state lock poisoned")
            .decisions
            .insert((raw_password.to_string(), password_hash.to_string()), true);
    }

    pub fn reject(&self, raw_password: &str, password_hash: &str) {
        self.state
            .lock()
            .expect("state lock poisoned")
            .decisions
            .insert((raw_password.to_string(), password_hash.to_string()), false);
    }

    pub fn snapshot(&self) -> FakePasswordVerifierState {
        self.state.lock().expect("state lock poisoned").clone()
    }
}

impl PasswordVerifier for FakePasswordVerifier {
    fn verify(&self, raw_password: &str, password_hash: &str) -> Result<bool, AuthError> {
        if let Some(err) = self
            .verify_error
            .lock()
            .expect("error lock poisoned")
            .clone()
        {
            return Err(err);
        }

        let mut state = self.state.lock().expect("state lock poisoned");
        state
            .verify_calls
            .push((raw_password.to_string(), password_hash.to_string()));
        Ok(state
            .decisions
            .get(&(raw_password.to_string(), password_hash.to_string()))
            .copied()
            .unwrap_or(false))
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

#[async_trait]
impl MfaEmailSender for FakeEmailSender {
    async fn send_mfa_code(&self, to_email: &str, raw_code: &str) -> Result<(), AuthError> {
        if let Some(err) = self.send_error.lock().expect("error lock poisoned").clone() {
            return Err(err);
        }

        let mut state = self.state.lock().expect("state lock poisoned");
        state
            .sent_messages
            .push((to_email.to_string(), raw_code.to_string()));
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct FakeMfaTicketRepositoryState {
    pub tickets_by_hash: HashMap<String, MfaTicket>,
    pub saved_tickets: Vec<MfaTicket>,
    pub consume_calls: Vec<(Uuid, DateTime<Utc>)>,
}

#[derive(Debug, Default)]
pub struct FakeMfaTicketRepository {
    pub state: Mutex<FakeMfaTicketRepositoryState>,
}

impl FakeMfaTicketRepository {
    pub fn snapshot(&self) -> FakeMfaTicketRepositoryState {
        self.state.lock().expect("state lock poisoned").clone()
    }

    pub fn insert_ticket(&self, ticket: MfaTicket) {
        self.state
            .lock()
            .expect("state lock poisoned")
            .tickets_by_hash
            .insert(ticket.ticket_hash.clone(), ticket);
    }
}

#[async_trait]
impl MfaTicketRepository for FakeMfaTicketRepository {
    async fn save(&self, ticket: MfaTicket) -> Result<(), AuthError> {
        let mut state = self.state.lock().expect("state lock poisoned");
        state.saved_tickets.push(ticket.clone());
        state
            .tickets_by_hash
            .insert(ticket.ticket_hash.clone(), ticket);
        Ok(())
    }

    async fn find_by_ticket_hash(&self, ticket_hash: &str) -> Result<Option<MfaTicket>, AuthError> {
        let state = self.state.lock().expect("state lock poisoned");
        Ok(state.tickets_by_hash.get(ticket_hash).cloned())
    }

    async fn consume(
        &self,
        ticket_id: Uuid,
        consumed_at: DateTime<Utc>,
    ) -> Result<bool, AuthError> {
        let mut state = self.state.lock().expect("state lock poisoned");
        state.consume_calls.push((ticket_id, consumed_at));
        for ticket in state.tickets_by_hash.values_mut() {
            if ticket.id == ticket_id && ticket.consumed_at.is_none() {
                ticket.consumed_at = Some(consumed_at);
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[derive(Debug, Clone, Default)]
pub struct FakeEmailMfaCodeRepositoryState {
    pub codes_by_hash: HashMap<String, EmailMfaCode>,
    pub saved_codes: Vec<EmailMfaCode>,
    pub consume_calls: Vec<(Uuid, DateTime<Utc>)>,
    pub invalidate_calls: Vec<(Uuid, DateTime<Utc>)>,
}

#[derive(Debug, Default)]
pub struct FakeEmailMfaCodeRepository {
    pub state: Mutex<FakeEmailMfaCodeRepositoryState>,
}

impl FakeEmailMfaCodeRepository {
    pub fn snapshot(&self) -> FakeEmailMfaCodeRepositoryState {
        self.state.lock().expect("state lock poisoned").clone()
    }

    pub fn insert_code(&self, code: EmailMfaCode) {
        self.state
            .lock()
            .expect("state lock poisoned")
            .codes_by_hash
            .insert(code.code_hash.clone(), code);
    }
}

#[async_trait]
impl EmailMfaCodeRepository for FakeEmailMfaCodeRepository {
    async fn save(&self, code: EmailMfaCode) -> Result<(), AuthError> {
        let mut state = self.state.lock().expect("state lock poisoned");
        state.saved_codes.push(code.clone());
        state.codes_by_hash.insert(code.code_hash.clone(), code);
        Ok(())
    }

    async fn find_by_code_hash(&self, code_hash: &str) -> Result<Option<EmailMfaCode>, AuthError> {
        let state = self.state.lock().expect("state lock poisoned");
        Ok(state.codes_by_hash.get(code_hash).cloned())
    }

    async fn find_latest_active_by_user_id(
        &self,
        user_id: Uuid,
    ) -> Result<Option<EmailMfaCode>, AuthError> {
        let state = self.state.lock().expect("state lock poisoned");
        Ok(state
            .codes_by_hash
            .values()
            .filter(|code| {
                code.user_id == user_id
                    && code.consumed_at.is_none()
                    && code.invalidated_at.is_none()
            })
            .max_by_key(|code| code.created_at.timestamp_millis())
            .cloned())
    }

    async fn consume(&self, code_id: Uuid, consumed_at: DateTime<Utc>) -> Result<bool, AuthError> {
        let mut state = self.state.lock().expect("state lock poisoned");
        state.consume_calls.push((code_id, consumed_at));
        for code in state.codes_by_hash.values_mut() {
            if code.id == code_id && code.consumed_at.is_none() && code.invalidated_at.is_none() {
                code.consumed_at = Some(consumed_at);
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn invalidate_active_codes_for_user(
        &self,
        user_id: Uuid,
        invalidated_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        let mut state = self.state.lock().expect("state lock poisoned");
        state.invalidate_calls.push((user_id, invalidated_at));
        for code in state.codes_by_hash.values_mut() {
            if code.user_id == user_id
                && code.consumed_at.is_none()
                && code.invalidated_at.is_none()
            {
                code.invalidated_at = Some(invalidated_at);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct FakeSessionRepositoryState {
    pub sessions_by_hash: HashMap<String, AuthSession>,
    pub saved_sessions: Vec<AuthSession>,
}

#[derive(Debug, Default)]
pub struct FakeSessionRepository {
    pub state: Mutex<FakeSessionRepositoryState>,
}

impl FakeSessionRepository {
    pub fn snapshot(&self) -> FakeSessionRepositoryState {
        self.state.lock().expect("state lock poisoned").clone()
    }
}

#[async_trait]
impl SessionRepository for FakeSessionRepository {
    async fn save(&self, session: AuthSession) -> Result<(), AuthError> {
        let mut state = self.state.lock().expect("state lock poisoned");
        state.saved_sessions.push(session.clone());
        state
            .sessions_by_hash
            .insert(session.jti_hash.clone(), session);
        Ok(())
    }

    async fn find_active_by_jti_hash(
        &self,
        jti_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<AuthSession>, AuthError> {
        let state = self.state.lock().expect("state lock poisoned");
        Ok(state
            .sessions_by_hash
            .get(jti_hash)
            .filter(|session| session.expires_at > now)
            .cloned())
    }
}

#[derive(Debug, Clone, Default)]
pub struct FakeTotpSetupRepositoryState {
    pub setups_by_hash: HashMap<String, TotpSetup>,
    pub saved_setups: Vec<TotpSetup>,
}

#[derive(Debug, Default)]
pub struct FakeTotpSetupRepository {
    pub state: Mutex<FakeTotpSetupRepositoryState>,
}

impl FakeTotpSetupRepository {
    pub fn snapshot(&self) -> FakeTotpSetupRepositoryState {
        self.state.lock().expect("state lock poisoned").clone()
    }
}

#[async_trait]
impl TotpSetupRepository for FakeTotpSetupRepository {
    async fn save(&self, setup: TotpSetup) -> Result<(), AuthError> {
        let mut state = self.state.lock().expect("state lock poisoned");
        state.saved_setups.push(setup.clone());
        state
            .setups_by_hash
            .insert(setup.setup_ticket_hash.clone(), setup);
        Ok(())
    }

    async fn find_by_ticket_hash(&self, ticket_hash: &str) -> Result<Option<TotpSetup>, AuthError> {
        let state = self.state.lock().expect("state lock poisoned");
        Ok(state.setups_by_hash.get(ticket_hash).cloned())
    }

    async fn consume(&self, setup_id: Uuid, consumed_at: DateTime<Utc>) -> Result<bool, AuthError> {
        let mut state = self.state.lock().expect("state lock poisoned");
        for setup in state.setups_by_hash.values_mut() {
            if setup.id == setup_id && setup.consumed_at.is_none() {
                setup.consumed_at = Some(consumed_at);
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[derive(Debug, Clone, Default)]
pub struct FakeJwtIssuerState {
    pub queued_access_tokens: VecDeque<(String, String)>,
    pub issued_access_tokens: Vec<(Uuid, bool)>,
}

#[derive(Debug, Default)]
pub struct FakeJwtIssuer {
    pub state: Mutex<FakeJwtIssuerState>,
}

impl FakeJwtIssuer {
    pub fn queue_access_token(&self, token: String, jti: String) {
        self.state
            .lock()
            .expect("state lock poisoned")
            .queued_access_tokens
            .push_back((token, jti));
    }

    pub fn snapshot(&self) -> FakeJwtIssuerState {
        self.state.lock().expect("state lock poisoned").clone()
    }
}

impl JwtService for FakeJwtIssuer {
    fn issue_access_token(
        &self,
        user_id: Uuid,
        mfa_satisfied: bool,
        now: DateTime<Utc>,
    ) -> Result<IssuedAccessToken, AuthError> {
        let mut state = self.state.lock().expect("state lock poisoned");
        state.issued_access_tokens.push((user_id, mfa_satisfied));
        let (token, jti) = state.queued_access_tokens.pop_front().unwrap_or_else(|| {
            (
                "access.jwt".to_string(),
                format!("jti-{}", state.issued_access_tokens.len()),
            )
        });
        Ok(IssuedAccessToken {
            token,
            jti,
            expires_at: now + Duration::hours(1),
        })
    }

    fn verify_access_token(
        &self,
        token: &str,
        _now: DateTime<Utc>,
    ) -> Result<AuthenticatedUserContext, AuthError> {
        let mut parts = token.split(':');
        let user_id = parts
            .next()
            .and_then(|value| Uuid::parse_str(value).ok())
            .ok_or(AuthError::Unauthorized)?;
        let mfa_satisfied = parts.next().map(|value| value == "mfa").unwrap_or(true);
        Ok(AuthenticatedUserContext {
            user_id,
            mfa_satisfied,
            session_jti_hash: Some(FakeTokenHasher::deterministic_hash(token)),
        })
    }

    fn jti_hash(&self, jti: &str) -> Result<String, AuthError> {
        Ok(FakeTokenHasher::deterministic_hash(jti))
    }
}

#[derive(Debug, Clone, Default)]
pub struct FakeTotpServiceState {
    pub accepted: HashMap<(String, String, i64), bool>,
    pub queued_secrets: VecDeque<String>,
}

#[derive(Debug, Default)]
pub struct FakeTotpService {
    pub state: Mutex<FakeTotpServiceState>,
}

impl FakeTotpService {
    pub fn accept(&self, secret: &str, code: &str, now: DateTime<Utc>) {
        self.state
            .lock()
            .expect("state lock poisoned")
            .accepted
            .insert(
                (secret.to_string(), code.to_string(), now.timestamp()),
                true,
            );
    }
}

impl TotpService for FakeTotpService {
    fn generate_secret(&self) -> Result<String, AuthError> {
        let mut state = self.state.lock().expect("state lock poisoned");
        Ok(state
            .queued_secrets
            .pop_front()
            .unwrap_or_else(|| "generated-totp-secret".to_string()))
    }

    fn otpauth_url(&self, email: &str, secret: &str) -> Result<String, AuthError> {
        Ok(format!(
            "otpauth://totp/BidMart:{email}?secret={secret}&issuer=BidMart"
        ))
    }

    fn verify_code(&self, secret: &str, code: &str, now: DateTime<Utc>) -> Result<bool, AuthError> {
        let state = self.state.lock().expect("state lock poisoned");
        Ok(state
            .accepted
            .get(&(secret.to_string(), code.to_string(), now.timestamp()))
            .copied()
            .unwrap_or(false))
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
        verification_token_ttl: Duration::seconds(30),
        resend_cooldown: Duration::seconds(30),
        ..AuthPolicy::default()
    }
}

pub struct AuthUseCaseTestContext {
    pub user_repository: Arc<FakeUserRepository>,
    pub password_verifier: Arc<FakePasswordVerifier>,
    pub token_generator: Arc<FakeTokenGenerator>,
    pub token_hasher: Arc<FakeTokenHasher>,
    pub email_sender: Arc<FakeEmailSender>,
    pub mfa_ticket_repository: Arc<FakeMfaTicketRepository>,
    pub email_mfa_code_repository: Arc<FakeEmailMfaCodeRepository>,
    pub session_repository: Arc<FakeSessionRepository>,
    pub totp_setup_repository: Arc<FakeTotpSetupRepository>,
    pub jwt_issuer: Arc<FakeJwtIssuer>,
    pub totp_service: Arc<FakeTotpService>,
    pub clock: Arc<FixedClock>,
    pub policy: AuthPolicy,
}

impl AuthUseCaseTestContext {
    pub fn new(now: DateTime<Utc>) -> Self {
        Self {
            user_repository: Arc::new(FakeUserRepository::default()),
            password_verifier: Arc::new(FakePasswordVerifier::default()),
            token_generator: Arc::new(FakeTokenGenerator::default()),
            token_hasher: Arc::new(FakeTokenHasher::default()),
            email_sender: Arc::new(FakeEmailSender::default()),
            mfa_ticket_repository: Arc::new(FakeMfaTicketRepository::default()),
            email_mfa_code_repository: Arc::new(FakeEmailMfaCodeRepository::default()),
            session_repository: Arc::new(FakeSessionRepository::default()),
            totp_setup_repository: Arc::new(FakeTotpSetupRepository::default()),
            jwt_issuer: Arc::new(FakeJwtIssuer::default()),
            totp_service: Arc::new(FakeTotpService::default()),
            clock: Arc::new(FixedClock::new(now)),
            policy: AuthPolicy::default(),
        }
    }

    pub fn auth_mfa_use_case(&self) -> AuthMfaUseCase {
        AuthMfaUseCase::new(
            self.user_repository.clone(),
            self.mfa_ticket_repository.clone(),
            self.email_mfa_code_repository.clone(),
            self.session_repository.clone(),
            self.totp_setup_repository.clone(),
            self.password_verifier.clone(),
            self.token_generator.clone(),
            self.token_hasher.clone(),
            self.email_sender.clone(),
            self.jwt_issuer.clone(),
            self.totp_service.clone(),
            self.clock.clone(),
            self.policy.clone(),
        )
    }

    pub fn seed_mfa_ticket(
        &self,
        user_id: Uuid,
        raw_ticket: &str,
        expires_at: DateTime<Utc>,
    ) -> MfaTicket {
        let ticket_hash = FakeTokenHasher::deterministic_hash(raw_ticket);
        let ticket = sample_mfa_ticket(user_id, &ticket_hash, self.clock.now(), expires_at);
        self.mfa_ticket_repository.insert_ticket(ticket.clone());
        ticket
    }

    pub fn seed_email_mfa_code(
        &self,
        user_id: Uuid,
        raw_code: &str,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> EmailMfaCode {
        let code_hash = FakeTokenHasher::deterministic_hash(raw_code);
        let code = sample_email_mfa_code(user_id, &code_hash, created_at, expires_at);
        self.email_mfa_code_repository.insert_code(code.clone());
        code
    }
}

impl Default for AuthUseCaseTestContext {
    fn default() -> Self {
        Self::new(fixed_now())
    }
}
