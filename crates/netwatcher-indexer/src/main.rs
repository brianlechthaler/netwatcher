use std::time::Duration;

use clap::Parser;
use futures::StreamExt;
use netwatcher_common::{
    consumer_config, ElasticsearchConfig, EventSource, KafkaConfig, NetworkEvent,
};
use netwatcher_indexer::elasticsearch::{build_client, EsIndexer};
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::Message;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Parser, Debug)]
#[command(name = "netwatcher-indexer", about = "Kafka to Elasticsearch indexer")]
struct Args {
    #[arg(long, env = "KAFKA_BROKERS", default_value = "kafka:9092")]
    kafka_brokers: String,

    #[arg(long, env = "KAFKA_TOPIC_PREFIX", default_value = "netwatcher")]
    kafka_topic_prefix: String,

    #[arg(long, env = "KAFKA_GROUP_ID", default_value = "netwatcher-indexer")]
    kafka_group_id: String,

    #[arg(
        long,
        env = "ELASTICSEARCH_URL",
        default_value = "http://elasticsearch:9200"
    )]
    elasticsearch_url: String,

    #[arg(long, env = "ELASTICSEARCH_INDEX_PREFIX", default_value = "netwatcher")]
    elasticsearch_index_prefix: String,

    #[arg(long, env = "ELASTICSEARCH_USERNAME")]
    elasticsearch_username: Option<String>,

    #[arg(long, env = "ELASTICSEARCH_PASSWORD")]
    elasticsearch_password: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();
    let kafka = KafkaConfig {
        brokers: args.kafka_brokers,
        topic_prefix: args.kafka_topic_prefix,
        client_id: "netwatcher-indexer".to_string(),
        group_id: args.kafka_group_id,
    };
    let es_config = ElasticsearchConfig {
        url: args.elasticsearch_url,
        index_prefix: args.elasticsearch_index_prefix,
        username: args.elasticsearch_username,
        password: args.elasticsearch_password,
    };

    let es_client = build_client(&es_config)?;
    let indexer = EsIndexer::new(es_client, &es_config).await?;

    let topics: Vec<String> = [
        EventSource::Zeek,
        EventSource::P0f,
        EventSource::Fatt,
        EventSource::Enriched,
    ]
    .iter()
    .map(|s| s.kafka_topic(&kafka.topic_prefix))
    .collect();

    let consumer: StreamConsumer = consumer_config(&kafka).create()?;
    consumer.subscribe(&topics.iter().map(String::as_str).collect::<Vec<_>>())?;
    info!(topics = ?topics, "indexer subscribed");

    let mut stream = consumer.stream();
    while let Some(result) = stream.next().await {
        match result {
            Ok(message) => {
                if let Some(payload) = message.payload() {
                    match serde_json::from_slice::<NetworkEvent>(payload) {
                        Ok(event) => {
                            if let Err(e) = indexer.index_event(&event).await {
                                warn!(error = %e, id = %event.id, "index failed");
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
