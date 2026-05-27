use axum::extract::Request;
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;
use std::time::Instant;
use uuid::Uuid;

const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");
const MAX_REQUEST_ID_LENGTH: usize = 128;

pub async fn request_trace_middleware(request: Request, next: Next) -> Response {
    let request_id = extract_or_generate_request_id(request.headers());
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let query_keys = request
        .uri()
        .query()
        .map(extract_query_keys)
        .unwrap_or_default();
    let user_agent = request
        .headers()
        .get(axum::http::header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    tracing::info!(
        request_id = %request_id,
        method = %method,
        path = %path,
        query_keys = ?query_keys,
        user_agent = %user_agent,
        "request_started"
    );

    let started_at = Instant::now();
    let mut response = next.run(request).await;
    let elapsed_ms = started_at.elapsed().as_millis() as u64;
    let status = response.status();

    if let Ok(header_value) = HeaderValue::from_str(&request_id) {
        response
            .headers_mut()
            .insert(REQUEST_ID_HEADER, header_value);
    }

    let status_code = status.as_u16();
    if status.is_server_error() {
        tracing::error!(
            request_id = %request_id,
            method = %method,
            path = %path,
            status = status_code,
            elapsed_ms = elapsed_ms,
            "request_finished_with_server_error"
        );
    } else if status.is_client_error() {
        tracing::warn!(
            request_id = %request_id,
            method = %method,
            path = %path,
            status = status_code,
            elapsed_ms = elapsed_ms,
            "request_finished_with_client_error"
        );
    } else {
        tracing::info!(
            request_id = %request_id,
            method = %method,
            path = %path,
            status = status_code,
            elapsed_ms = elapsed_ms,
            "request_finished"
        );
    }

    response
}

fn extract_or_generate_request_id(headers: &HeaderMap) -> String {
    let request_id = headers
        .get(REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= MAX_REQUEST_ID_LENGTH)
        .map(ToString::to_string);

    match request_id {
        Some(request_id) => request_id,
        None => Uuid::new_v4().to_string(),
    }
}

fn extract_query_keys(query: &str) -> Vec<String> {
    query
        .split('&')
        .filter_map(|pair| pair.split('=').next())
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .map(ToString::to_string)
        .take(20)
        .collect::<Vec<_>>()
}
