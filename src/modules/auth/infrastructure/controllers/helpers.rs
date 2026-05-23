use axum::http::header::SET_COOKIE;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

use crate::modules::auth::application::dto::SessionContext;
use crate::modules::auth::infrastructure::session_cookie::{
    build_clear_session_cookie, build_session_cookie,
};
use crate::modules::auth::infrastructure::AppState;

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

pub fn extract_session_context(headers: &HeaderMap) -> SessionContext {
    let unknown = SessionContext::unknown();
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty());

    let (device, browser, os) = match user_agent {
        Some(ua) => (parse_device(ua), parse_browser(ua), parse_os(ua)),
        None => (unknown.device, unknown.browser, unknown.os),
    };

    let ip = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
        .map(ToString::to_string)
        .unwrap_or(unknown.ip);

    SessionContext {
        device,
        browser,
        os,
        ip,
        location: unknown.location,
    }
}

fn parse_browser(ua: &str) -> String {
    const CANDIDATES: &[(&str, &str)] = &[
        ("Edg/", "Edge"),
        ("OPR/", "Opera"),
        ("Opera", "Opera"),
        ("Chrome/", "Chrome"),
        ("Firefox/", "Firefox"),
        ("Safari/", "Safari"),
    ];
    for (needle, label) in CANDIDATES {
        if ua.contains(needle) {
            return (*label).to_string();
        }
    }
    "Unknown browser".to_string()
}

fn parse_os(ua: &str) -> String {
    const CANDIDATES: &[(&str, &str)] = &[
        ("Windows NT", "Windows"),
        ("Mac OS X", "macOS"),
        ("Android", "Android"),
        ("iPhone OS", "iOS"),
        ("iPad", "iPadOS"),
        ("Linux", "Linux"),
    ];
    for (needle, label) in CANDIDATES {
        if ua.contains(needle) {
            return (*label).to_string();
        }
    }
    "Unknown OS".to_string()
}

fn parse_device(ua: &str) -> String {
    if ua.contains("Mobile") || ua.contains("Android") || ua.contains("iPhone") {
        "Mobile".to_string()
    } else if ua.contains("iPad") || ua.contains("Tablet") {
        "Tablet".to_string()
    } else {
        "Desktop".to_string()
    }
}
