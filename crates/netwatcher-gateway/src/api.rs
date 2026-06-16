use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use netwatcher_common::{constant_time_eq_str, validate_ingest_batch, IngestBatch, NetworkEvent};
use serde::Serialize;
use tracing::info;

use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/health", get(health))
        .route("/api/v1/ingest", post(ingest))
        .route("/api/v1/agents/register", post(register_agent))
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "netwatcher-gateway",
    })
}

#[derive(Serialize)]
struct IngestResponse {
    accepted: usize,
    total: usize,
}

#[derive(Serialize)]
struct RegisterResponse {
    agent_id: String,
    status: &'static str,
}

async fn register_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(batch): Json<IngestBatch>,
) -> Result<Json<RegisterResponse>, StatusCode> {
    if !authorize(&state, &headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if !state.rate_limiter.check() {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    validate_batch(&state, &batch).map_err(|_| StatusCode::BAD_REQUEST)?;

    info!(agent_id = %batch.agent_id, hostname = %batch.hostname, "agent registered");
    Ok(Json(RegisterResponse {
        agent_id: batch.agent_id,
        status: "registered",
    }))
}

async fn ingest(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(batch): Json<IngestBatch>,
) -> Result<Json<IngestResponse>, StatusCode> {
    if !authorize(&state, &headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if !state.rate_limiter.check() {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    validate_batch(&state, &batch).map_err(|_| StatusCode::BAD_REQUEST)?;

    let events: Vec<NetworkEvent> = batch
        .events
        .into_iter()
        .map(|e| NetworkEvent::from_ingest(&batch.agent_id, &batch.hostname, e))
        .collect();

    let total = events.len();
    let accepted = state
        .producer
        .publish_batch(&events)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    info!(
        agent_id = %batch.agent_id,
        accepted,
        total,
        "ingested batch"
    );

    Ok(Json(IngestResponse { accepted, total }))
}

fn validate_batch(state: &AppState, batch: &IngestBatch) -> Result<(), String> {
    validate_ingest_batch(
        batch,
        state.config.max_events_per_batch,
        state.config.max_raw_event_bytes,
    )
}

fn authorize(state: &AppState, headers: &HeaderMap) -> bool {
    match &state.config.api_key {
        None => !state.config.require_api_key,
        Some(expected) => headers
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|provided| constant_time_eq_str(provided, expected)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use netwatcher_common::{GatewayConfig, KafkaConfig};
    use tower::ServiceExt;

    fn test_state(api_key: Option<&str>) -> AppState {
        let config = GatewayConfig {
            bind_addr: "0.0.0.0:8080".to_string(),
            api_key: api_key.map(str::to_string),
            require_api_key: false,
            max_body_bytes: 1024 * 1024,
            max_events_per_batch: 500,
            max_raw_event_bytes: 256 * 1024,
            rate_limit_per_minute: 600,
            kafka: KafkaConfig::default(),
        };
        let producer = netwatcher_common::KafkaProducer::new(&config.kafka).unwrap();
        AppState::new(config, producer)
    }

    #[test]
    fn authorize_without_api_key_allows_all() {
        let state = test_state(None);
        let headers = HeaderMap::new();
        assert!(authorize(&state, &headers));
    }

    #[test]
    fn authorize_with_api_key_requires_header() {
        let state = test_state(Some("secret"));
        let headers = HeaderMap::new();
        assert!(!authorize(&state, &headers));

        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", "secret".parse().unwrap());
        assert!(authorize(&state, &headers));
    }

    #[test]
    fn authorize_rejects_wrong_length_key_without_panic() {
        let state = test_state(Some("secret"));
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", "not-secret".parse().unwrap());
        assert!(!authorize(&state, &headers));
    }

    #[test]
    fn require_api_key_denies_when_unconfigured() {
        let mut config = GatewayConfig::default();
        config.require_api_key = true;
        config.api_key = None;
        let producer = netwatcher_common::KafkaProducer::new(&config.kafka).unwrap();
        let state = AppState::new(config, producer);
        assert!(!authorize(&state, &HeaderMap::new()));
    }

    #[tokio::test]
    async fn health_endpoint_returns_ok() {
        let app = routes().with_state(test_state(None));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
