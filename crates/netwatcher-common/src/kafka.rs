use std::time::Duration;

use rdkafka::admin::{AdminClient, AdminOptions, NewTopic, TopicReplication};
use rdkafka::client::DefaultClientContext;
use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::util::Timeout;
use tracing::{debug, info, warn};

use crate::{EventSource, KafkaConfig, NetworkEvent};

pub struct KafkaProducer {
    producer: FutureProducer,
    topic_prefix: String,
    brokers: String,
}

impl KafkaProducer {
    pub fn new(config: &KafkaConfig) -> anyhow::Result<Self> {
        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", &config.brokers)
            .set("client.id", &config.client_id)
            .set("message.timeout.ms", "30000")
            .set("queue.buffering.max.ms", "100")
            .create()?;

        Ok(Self {
            producer,
            topic_prefix: config.topic_prefix.clone(),
            brokers: config.brokers.clone(),
        })
    }

    pub async fn ensure_topics(&self, sources: &[EventSource]) -> anyhow::Result<()> {
        let admin: AdminClient<DefaultClientContext> = ClientConfig::new()
            .set("bootstrap.servers", &self.brokers)
            .create()?;

        let topic_names: Vec<String> = sources
            .iter()
            .map(|s| s.kafka_topic(&self.topic_prefix))
            .collect();
        let topics: Vec<NewTopic> = topic_names
            .iter()
            .map(|name| NewTopic::new(name, 3, TopicReplication::Fixed(1)))
            .collect();

        let results = admin
            .create_topics(
                &topics,
                &AdminOptions::new()
                    .operation_timeout(Some(Timeout::After(Duration::from_secs(10)))),
            )
            .await?;

        for result in results {
            match result {
                Ok(_) => {}
                Err((topic, err)) if err.to_string().contains("already exists") => {
                    debug!(topic = %topic, "topic already exists");
                }
                Err((topic, err)) => {
                    warn!(topic = %topic, error = %err, "failed to create topic");
                }
            }
        }
        info!("kafka topics ensured");
        Ok(())
    }

    pub async fn publish(&self, event: &NetworkEvent) -> anyhow::Result<()> {
        let topic = event.source.kafka_topic(&self.topic_prefix);
        let payload = serde_json::to_string(event)?;
        let key = format!("{}:{}", event.agent_id, event.id);

        self.producer
            .send(
                FutureRecord::to(&topic).key(&key).payload(&payload),
                Duration::from_secs(5),
            )
            .await
            .map_err(|(err, _)| err)?;

        debug!(topic = %topic, id = %event.id, "published event");
        Ok(())
    }

    pub async fn publish_batch(&self, events: &[NetworkEvent]) -> anyhow::Result<usize> {
        let mut published = 0;
        for event in events {
            match self.publish(event).await {
                Ok(()) => published += 1,
                Err(e) => warn!(error = %e, id = %event.id, "failed to publish event"),
            }
        }
        Ok(published)
    }
}

pub fn consumer_config(config: &KafkaConfig) -> ClientConfig {
    let mut cfg = ClientConfig::new();
    cfg.set("bootstrap.servers", &config.brokers)
        .set("group.id", &config.group_id)
        .set("enable.auto.commit", "true")
        .set("auto.offset.reset", "earliest")
        .set("session.timeout.ms", "6000");
    cfg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consumer_config_sets_expected_keys() {
        let config = KafkaConfig {
            brokers: "kafka:9092".to_string(),
            topic_prefix: "netwatcher".to_string(),
            client_id: "test".to_string(),
            group_id: "test-group".to_string(),
        };
        let cfg = consumer_config(&config);
        assert_eq!(cfg.get("bootstrap.servers"), Some("kafka:9092"));
        assert_eq!(cfg.get("group.id"), Some("test-group"));
    }
}
