mod api;
mod state;

use std::net::SocketAddr;

use axum::Router;
use clap::Parser;
use netwatcher_common::{EventSource, GatewayConfig, KafkaConfig, KafkaProducer};
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::state::AppState;

#[derive(Parser, Debug)]
#[command(name = "netwatcher-gateway", about = "NetWatcher ingest gateway")]
struct Args {
    #[arg(long, env = "GATEWAY_BIND_ADDR", default_value = "0.0.0.0:8080")]
    bind_addr: String,

    #[arg(long, env = "GATEWAY_API_KEY")]
    api_key: Option<String>,

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
    let config = GatewayConfig {
        bind_addr: args.bind_addr,
        api_key: args.api_key,
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

    let app = Router::new()
        .merge(api::routes())
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr: SocketAddr = config.bind_addr.parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "gateway listening");

    axum::serve(listener, app).await?;
    Ok(())
}
