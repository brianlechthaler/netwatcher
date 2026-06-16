mod enrich;
mod feed;

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use enrich::EventEnricher;
use feed::ThreatFeedUpdater;
use futures::StreamExt;
use netwatcher_common::{
    consumer_config, EventSource, KafkaConfig, KafkaProducer, NetworkEvent, ThreatFeedConfig,
};
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::Message;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Parser, Debug)]
#[command(name = "netwatcher-enricher", about = "Threat intelligence enricher")]
struct Args {
    #[arg(long, env = "KAFKA_BROKERS", default_value = "kafka:9092")]
    kafka_brokers: String,

    #[arg(long, env = "KAFKA_TOPIC_PREFIX", default_value = "netwatcher")]
    kafka_topic_prefix: String,

    #[arg(long, env = "KAFKA_GROUP_ID", default_value = "netwatcher-enricher")]
    kafka_group_id: String,

    #[arg(
        long,
        env = "ET_COMPROMISED_URL",
        default_value = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    )]
    et_compromised_url: String,

    #[arg(
        long,
        env = "ET_BOTNET_URL",
        default_value = "https://rules.emergingthreats.net/blockrules/emerging-botcc.rules"
    )]
    et_botnet_url: String,

    #[arg(long, env = "THREAT_REFRESH_SECS", default_value = "3600")]
    threat_refresh_secs: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();
    let feed_config = ThreatFeedConfig {
        et_compromised_url: args.et_compromised_url.clone(),
        et_botnet_url: args.et_botnet_url.clone(),
        refresh_interval_secs: args.threat_refresh_secs,
    };
    netwatcher_common::validate_threat_feed_url(
        &feed_config.et_compromised_url,
        netwatcher_common::default_feed_host_suffix(),
    )
    .map_err(anyhow::Error::msg)?;
    netwatcher_common::validate_threat_feed_url(
        &feed_config.et_botnet_url,
        netwatcher_common::default_feed_host_suffix(),
    )
    .map_err(anyhow::Error::msg)?;

    let kafka = KafkaConfig {
        brokers: args.kafka_brokers.clone(),
        topic_prefix: args.kafka_topic_prefix.clone(),
        client_id: "netwatcher-enricher".to_string(),
        group_id: args.kafka_group_id,
    };

    let producer = KafkaProducer::new(&kafka)?;
    producer.ensure_topics(&[EventSource::Enriched]).await?;

    let store = Arc::new(RwLock::new(netwatcher_common::ThreatStore::new()));
    let updater = ThreatFeedUpdater::new(feed_config, store.clone());
    updater.refresh().await?;
    updater.spawn_refresh_loop();

    let enricher = EventEnricher::new(store);

    let source_topics: Vec<String> = [EventSource::Zeek, EventSource::P0f, EventSource::Fatt]
        .iter()
        .map(|s| s.kafka_topic(&kafka.topic_prefix))
        .collect();

    let consumer: StreamConsumer = consumer_config(&kafka).create()?;
    consumer.subscribe(&source_topics.iter().map(String::as_str).collect::<Vec<_>>())?;
    info!(topics = ?source_topics, "enricher subscribed");

    let mut stream = consumer.stream();
    while let Some(result) = stream.next().await {
        match result {
            Ok(message) => {
                if let Some(payload) = message.payload() {
                    match serde_json::from_slice::<NetworkEvent>(payload) {
                        Ok(mut event) => {
                            enricher.enrich(&mut event).await;
                            event.source = EventSource::Enriched;
                            if let Err(e) = producer.publish(&event).await {
                                warn!(error = %e, id = %event.id, "failed to publish enriched event");
                            }
                        }
                        Err(e) => warn!(error = %e, "invalid event payload"),
                    }
                }
            }
            Err(e) => error!(error = %e, "kafka consume error"),
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    Ok(())
}
