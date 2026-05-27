pub mod api_error;
mod auth_controller;
mod helpers;
mod internal_authorization_controller;
mod login_controller;
mod mfa_controller;
mod settings_controller;

pub use api_error::ApiError;
pub use auth_controller::{register, resend_verification, verify_email};
pub use internal_authorization_controller::{
    assign_role_permission, assign_user_role, revoke_role_permission, revoke_user_role,
};
pub use login_controller::{forgot_password, login, logout, reset_password, validate_session};
pub use mfa_controller::{send_email_mfa, verify_email_mfa, verify_totp_mfa};
pub use settings_controller::{
    change_password, disable_mfa, get_mfa_settings, get_notification_preferences, get_profile,
    get_sessions, revoke_all_sessions, revoke_session, setup_email_mfa, setup_totp,
    update_notification_preferences, update_profile, verify_email_mfa_setup, verify_totp_setup,
};
