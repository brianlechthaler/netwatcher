use std::sync::Arc;

use netwatcher_common::{GatewayConfig, KafkaProducer};

#[derive(Clone)]
pub struct AppState {
    pub config: GatewayConfig,
    pub producer: Arc<KafkaProducer>,
}

impl AppState {
    pub fn new(config: GatewayConfig, producer: KafkaProducer) -> Self {
        Self {
            config,
            producer: Arc::new(producer),
        }
    }
}
