mod api;
mod security;
mod state;

use std::net::SocketAddr;

use axum::Router;
use clap::Parser;
use netwatcher_common::{EventSource, GatewayConfig, KafkaConfig, KafkaProducer};
use tokio::net::TcpListener;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::state::AppState;

#[derive(Parser, Debug)]
#[command(name = "netwatcher-gateway", about = "NetWatcher ingest gateway")]
struct Args {
    #[arg(long, env = "GATEWAY_BIND_ADDR", default_value = "0.0.0.0:8080")]
    bind_addr: String,

    #[arg(long, env = "GATEWAY_API_KEY")]
    api_key: Option<String>,

    #[arg(long, env = "GATEWAY_REQUIRE_API_KEY", default_value_t = false)]
    require_api_key: bool,

    #[arg(long, env = "GATEWAY_MAX_BODY_BYTES", default_value_t = 10 * 1024 * 1024)]
    max_body_bytes: usize,

    #[arg(
        long,
        env = "GATEWAY_MAX_EVENTS_PER_BATCH",
        default_value_t = netwatcher_common::default_max_events_per_batch()
    )]
    max_events_per_batch: usize,

    #[arg(
        long,
        env = "GATEWAY_MAX_RAW_EVENT_BYTES",
        default_value_t = netwatcher_common::default_max_raw_event_bytes()
    )]
    max_raw_event_bytes: usize,

    #[arg(long, env = "GATEWAY_RATE_LIMIT_PER_MINUTE", default_value_t = 600)]
    rate_limit_per_minute: u32,

    #[arg(long, env = "KAFKA_BROKERS", default_value = "kafka:9092")]
    kafka_brokers: String,

    #[arg(long, env = "KAFKA_TOPIC_PREFIX", default_value = "netwatcher")]
    kafka_topic_prefix: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();
    if args.require_api_key && args.api_key.is_none() {
        anyhow::bail!("GATEWAY_REQUIRE_API_KEY is set but GATEWAY_API_KEY is missing");
    }
    if args.api_key.is_none() && !args.require_api_key {
        warn!(
            "GATEWAY_API_KEY is not set; ingest endpoints accept unauthenticated requests. \
             Set GATEWAY_API_KEY or GATEWAY_REQUIRE_API_KEY=true for production."
        );
    }

    let config = GatewayConfig {
        bind_addr: args.bind_addr,
        api_key: args.api_key,
        require_api_key: args.require_api_key,
        max_body_bytes: args.max_body_bytes,
        max_events_per_batch: args.max_events_per_batch,
        max_raw_event_bytes: args.max_raw_event_bytes,
        rate_limit_per_minute: args.rate_limit_per_minute,
        kafka: KafkaConfig {
            brokers: args.kafka_brokers,
            topic_prefix: args.kafka_topic_prefix,
            client_id: "netwatcher-gateway".to_string(),
            group_id: "netwatcher-gateway".to_string(),
        },
    };

    let producer = KafkaProducer::new(&config.kafka)?;
    producer
        .ensure_topics(&[
            EventSource::Zeek,
            EventSource::P0f,
            EventSource::Fatt,
            EventSource::Enriched,
        ])
        .await?;

    let state = AppState::new(config.clone(), producer);
    let body_limit = RequestBodyLimitLayer::new(config.max_body_bytes);

    let app = Router::new()
        .merge(api::routes())
        .layer(body_limit)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr: SocketAddr = config.bind_addr.parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "gateway listening");

    axum::serve(listener, app).await?;
    Ok(())
}
