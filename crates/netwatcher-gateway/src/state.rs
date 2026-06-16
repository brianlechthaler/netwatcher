use std::sync::Arc;
use std::time::Duration;

use netwatcher_common::{GatewayConfig, KafkaProducer};

use crate::security::RateLimiter;

#[derive(Clone)]
pub struct AppState {
    pub config: GatewayConfig,
    pub producer: Arc<KafkaProducer>,
    pub rate_limiter: Arc<RateLimiter>,
}

impl AppState {
    pub fn new(config: GatewayConfig, producer: KafkaProducer) -> Self {
        let rate_limiter = Arc::new(RateLimiter::new(
            config.rate_limit_per_minute,
            Duration::from_secs(60),
        ));
        Self {
            config,
            producer: Arc::new(producer),
            rate_limiter,
        }
    }
}
