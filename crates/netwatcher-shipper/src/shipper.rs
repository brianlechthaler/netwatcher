use std::collections::HashMap;
use std::time::Duration;

use netwatcher_common::{IngestBatch, ShipperConfig};
use reqwest::Client;
use tracing::{info, warn};

use crate::parser::{
    discover_log_files, parse_fatt_line, parse_p0f_line, parse_zeek_json_line, FileTailer,
};

pub struct LogShipper {
    config: ShipperConfig,
    client: Client,
    tailers: HashMap<String, FileTailer>,
}

impl LogShipper {
    pub fn new(config: ShipperConfig) -> anyhow::Result<Self> {
        let client = Client::builder().timeout(Duration::from_secs(30)).build()?;
        Ok(Self {
            config,
            client,
            tailers: HashMap::new(),
        })
    }

    pub async fn run(mut self, interval: Duration) -> anyhow::Result<()> {
        loop {
            if let Err(e) = self.poll_and_ship().await {
                warn!(error = %e, "ship cycle failed");
            }
            tokio::time::sleep(interval).await;
        }
    }

    async fn poll_and_ship(&mut self) -> anyhow::Result<()> {
        let files = discover_log_files(&self.config.watch_dirs);
        let mut events = Vec::new();

        for (path, source, zeek_type) in files {
            let key = path.to_string_lossy().to_string();
            let tailer = self
                .tailers
                .entry(key)
                .or_insert_with(|| FileTailer::new(path.clone()));

            let lines = tailer.read_new_lines()?;
            for line in lines {
                let event = match source {
                    netwatcher_common::EventSource::Zeek => {
                        parse_zeek_json_line(&line, zeek_type.as_deref().unwrap_or("other"))
                    }
                    netwatcher_common::EventSource::P0f => parse_p0f_line(&line),
                    netwatcher_common::EventSource::Fatt => parse_fatt_line(&line),
                    netwatcher_common::EventSource::Enriched => None,
                };
                if let Some(e) = event {
                    events.push(e);
                }
            }
        }

        if events.is_empty() {
            return Ok(());
        }

        let batch = IngestBatch {
            agent_id: self.config.agent_id.clone(),
            hostname: self.config.hostname.clone(),
            events,
        };

        let mut request = self
            .client
            .post(format!("{}/api/v1/ingest", self.config.gateway_url))
            .json(&batch);

        if let Some(key) = &self.config.api_key {
            request = request.header("x-api-key", key);
        }

        let response = request.send().await?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("gateway error {status}: {body}");
        }

        info!(count = batch.events.len(), "shipped events");
        Ok(())
    }
}
