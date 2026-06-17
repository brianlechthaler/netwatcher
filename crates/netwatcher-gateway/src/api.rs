use axum::{
    extract::{Multipart, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use netwatcher_common::{
    constant_time_eq_str, is_complete_pcap, is_valid_pcap_magic, validate_agent_identifier,
    validate_ingest_batch, validate_pcap_filename, IngestBatch, NetworkEvent,
};
use serde::Serialize;
use tempfile::NamedTempFile;
use tracing::info;

use crate::analyzer::TrafficAnalyzer;
use crate::state::AppState;

#[derive(Serialize)]
pub struct HealthResponse {
    status: &'static str,
    service: &'static str,
}

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "netwatcher-gateway",
    })
}

#[derive(Serialize)]
pub struct IngestResponse {
    accepted: usize,
    total: usize,
}

#[derive(Serialize)]
pub struct PcapIngestResponse {
    accepted: usize,
    zeek_events: usize,
    p0f_events: usize,
    fatt_events: usize,
    filename: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    agent_id: String,
    status: &'static str,
}

pub async fn register_agent(
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

pub async fn ingest(
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

pub async fn ingest_pcap(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Json<PcapIngestResponse>, StatusCode> {
    if !authorize(&state, &headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if !state.rate_limiter.check() {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let mut agent_id = None;
    let mut hostname = None;
    let mut interface = None;
    let mut filename = None;
    let mut pcap_bytes: Option<Vec<u8>> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?
    {
        match field.name() {
            Some("agent_id") => {
                agent_id = Some(
                    field
                        .text()
                        .await
                        .map_err(|_| StatusCode::BAD_REQUEST)?
                        .to_string(),
                );
            }
            Some("hostname") => {
                hostname = Some(
                    field
                        .text()
                        .await
                        .map_err(|_| StatusCode::BAD_REQUEST)?
                        .to_string(),
                );
            }
            Some("interface") => {
                interface = Some(
                    field
                        .text()
                        .await
                        .map_err(|_| StatusCode::BAD_REQUEST)?
                        .to_string(),
                );
            }
            Some("filename") => {
                filename = Some(
                    field
                        .text()
                        .await
                        .map_err(|_| StatusCode::BAD_REQUEST)?
                        .to_string(),
                );
            }
            Some("pcap") => {
                let data = field.bytes().await.map_err(|_| StatusCode::BAD_REQUEST)?;
                if data.len() > state.config.max_pcap_bytes {
                    return Err(StatusCode::PAYLOAD_TOO_LARGE);
                }
                pcap_bytes = Some(data.to_vec());
            }
            _ => {}
        }
    }

    let agent_id = agent_id.ok_or(StatusCode::BAD_REQUEST)?;
    let hostname = hostname.ok_or(StatusCode::BAD_REQUEST)?;
    let interface = interface.unwrap_or_else(|| "unknown".to_string());
    let filename = filename.ok_or(StatusCode::BAD_REQUEST)?;
    let pcap_bytes = pcap_bytes.ok_or(StatusCode::BAD_REQUEST)?;

    validate_agent_identifier(&agent_id, "agent_id").map_err(|_| StatusCode::BAD_REQUEST)?;
    validate_agent_identifier(&hostname, "hostname").map_err(|_| StatusCode::BAD_REQUEST)?;
    validate_agent_identifier(&interface, "interface").map_err(|_| StatusCode::BAD_REQUEST)?;
    validate_pcap_filename(&filename).map_err(|_| StatusCode::BAD_REQUEST)?;

    if pcap_bytes.is_empty() || !is_valid_pcap_magic(&pcap_bytes) || !is_complete_pcap(&pcap_bytes)
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    let _permit = state
        .pcap_semaphore
        .clone()
        .try_acquire_owned()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    let temp = NamedTempFile::new().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let pcap_path = temp.path().to_path_buf();
    tokio::task::spawn_blocking(move || std::fs::write(&pcap_path, pcap_bytes))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let analyzer = TrafficAnalyzer::new(state.config.clone());
    let events = analyzer
        .analyze_pcap(&agent_id, &hostname, &interface, temp.path())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let zeek_events = events
        .iter()
        .filter(|e| e.source == netwatcher_common::EventSource::Zeek)
        .count();
    let p0f_events = events
        .iter()
        .filter(|e| e.source == netwatcher_common::EventSource::P0f)
        .count();
    let fatt_events = events
        .iter()
        .filter(|e| e.source == netwatcher_common::EventSource::Fatt)
        .count();
    let total = events.len();

    let accepted = state
        .producer
        .publish_batch(&events)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    info!(
        agent_id = %agent_id,
        filename = %filename,
        accepted,
        total,
        p0f_events,
        fatt_events,
        zeek_events,
        "ingested pcap"
    );

    Ok(Json(PcapIngestResponse {
        accepted,
        zeek_events,
        p0f_events,
        fatt_events,
        filename,
    }))
}

fn validate_batch(state: &AppState, batch: &IngestBatch) -> Result<(), String> {
    validate_ingest_batch(
        batch,
        state.config.max_events_per_batch,
        state.config.max_raw_event_bytes,
    )
}

pub(crate) fn authorize(state: &AppState, headers: &HeaderMap) -> bool {
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
    use axum::routing::{get, post};
    use axum::Router;
    use netwatcher_common::{GatewayConfig, KafkaConfig};
    use tower::ServiceExt;

    fn test_state(api_key: Option<&str>) -> AppState {
        let config = GatewayConfig {
            bind_addr: "0.0.0.0:8080".to_string(),
            api_key: api_key.map(str::to_string),
            require_api_key: false,
            max_body_bytes: 1024 * 1024,
            max_pcap_bytes: 50 * 1024 * 1024,
            max_events_per_batch: 500,
            max_raw_event_bytes: 256 * 1024,
            rate_limit_per_minute: 600,
            p0f_bin: "/usr/local/bin/p0f".to_string(),
            p0f_fp: "/opt/p0f/p0f.fp".to_string(),
            fatt_script: "/opt/fatt/fatt.py".to_string(),
            zeek_bin: "/usr/local/zeek/bin/zeek".to_string(),
            analysis_timeout_secs: 120,
            max_concurrent_pcap_analysis: 2,
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
        let app = Router::new()
            .route("/health", get(health))
            .with_state(test_state(None));
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

    #[tokio::test]
    async fn ingest_endpoint_requires_json_body() {
        let app = Router::new()
            .route("/api/v1/ingest", post(ingest))
            .with_state(test_state(None));
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/ingest")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
}
