use axum::http::HeaderMap;

pub fn extract_token_from_headers(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    if let Some(token) = extract_bearer_token(headers) {
        return Some(token);
    }

    extract_cookie_token(headers, cookie_name)
}

pub fn build_session_cookie(
    cookie_name: &str,
    token: &str,
    max_age_seconds: i64,
    same_site: &str,
    secure: bool,
) -> String {
    let mut cookie = format!(
        "{cookie_name}={token}; Path=/; Max-Age={max_age_seconds}; HttpOnly; SameSite={same_site}"
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

pub fn build_clear_session_cookie(cookie_name: &str, same_site: &str, secure: bool) -> String {
    let mut cookie = format!("{cookie_name}=; Path=/; Max-Age=0; HttpOnly; SameSite={same_site}");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn extract_cookie_token(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    let cookie_header = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;

    cookie_header
        .split(';')
        .map(str::trim)
        .filter_map(|cookie| cookie.split_once('='))
        .find_map(|(key, value)| {
            if key == cookie_name {
                let token = value.trim();
                if token.is_empty() {
                    None
                } else {
                    Some(token.to_string())
                }
            } else {
                None
            }
        })
}
