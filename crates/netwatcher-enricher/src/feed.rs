use std::sync::Arc;
use std::time::Duration;

use netwatcher_common::{
    parse_et_botcc_rules, parse_et_compromised_ips, ThreatFeedConfig, ThreatStore,
};
use reqwest::Client;
use tokio::sync::RwLock;
use tracing::{info, warn};

pub struct ThreatFeedUpdater {
    client: Client,
    config: ThreatFeedConfig,
    store: Arc<RwLock<ThreatStore>>,
}

impl ThreatFeedUpdater {
    pub fn new(config: ThreatFeedConfig, store: Arc<RwLock<ThreatStore>>) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .unwrap_or_default(),
            config,
            store,
        }
    }

    pub async fn refresh(&self) -> anyhow::Result<()> {
        let compromised = self.fetch(&self.config.et_compromised_url).await?;
        let botcc = self.fetch(&self.config.et_botnet_url).await?;

        let mut indicators = parse_et_compromised_ips(&compromised);
        indicators.extend(parse_et_botcc_rules(&botcc));

        let mut store = self.store.write().await;
        *store = ThreatStore::new();
        for indicator in indicators {
            store.upsert(indicator);
        }

        info!(count = store.len(), "threat feed refreshed");
        Ok(())
    }

    pub fn spawn_refresh_loop(self) {
        let interval = self.config.refresh_interval_secs;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(interval)).await;
                if let Err(e) = self.refresh().await {
                    warn!(error = %e, "threat feed refresh failed");
                }
            }
        });
    }

    async fn fetch(&self, url: &str) -> anyhow::Result<String> {
        let response = self.client.get(url).send().await?;
        if !response.status().is_success() {
            anyhow::bail!("feed fetch failed: {} {}", url, response.status());
        }
        Ok(response.text().await?)
    }
}
