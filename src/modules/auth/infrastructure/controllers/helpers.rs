use axum::http::header::SET_COOKIE;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

use crate::modules::auth::infrastructure::session_cookie::{
    build_clear_session_cookie, build_session_cookie,
};
use crate::modules::auth::infrastructure::AppState;

pub use crate::modules::auth::infrastructure::services::extract_session_context;

pub fn with_session_cookie(

    state: &AppState,
    access_token: &str,
    payload: Json<impl Serialize>,
) -> Response {
    let mut response = payload.into_response();
    let cookie = build_session_cookie(
        &state.session_cookie_name,
        access_token,
        state.session_cookie_max_age_seconds,
        &state.session_cookie_same_site,
        state.session_cookie_secure,
    );
    if let Ok(value) = axum::http::HeaderValue::from_str(&cookie) {
        response.headers_mut().append(SET_COOKIE, value);
    }
    response
}

pub fn with_clear_session_cookie(state: &AppState, payload: Json<impl Serialize>) -> Response {
    let mut response = payload.into_response();
    let cookie = build_clear_session_cookie(
        &state.session_cookie_name,
        &state.session_cookie_same_site,
        state.session_cookie_secure,
    );
    if let Ok(value) = axum::http::HeaderValue::from_str(&cookie) {
        response.headers_mut().append(SET_COOKIE, value);
    }
    response
}

