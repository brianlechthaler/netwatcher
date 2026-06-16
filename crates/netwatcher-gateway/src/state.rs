use std::sync::Arc;

use netwatcher_common::{GatewayConfig, KafkaProducer};
use tokio::sync::Semaphore;

use crate::security::RateLimiter;

#[derive(Clone)]
pub struct AppState {
    pub config: GatewayConfig,
    pub producer: Arc<KafkaProducer>,
    pub rate_limiter: Arc<RateLimiter>,
    pub pcap_semaphore: Arc<Semaphore>,
}

impl AppState {
    pub fn new(config: GatewayConfig, producer: KafkaProducer) -> Self {
        let rate_limiter = Arc::new(RateLimiter::new(
            config.rate_limit_per_minute,
            std::time::Duration::from_secs(60),
        ));
        let pcap_semaphore = Arc::new(Semaphore::new(config.max_concurrent_pcap_analysis));
        Self {
            config,
            producer: Arc::new(producer),
            rate_limiter,
            pcap_semaphore,
        }
    }
}
