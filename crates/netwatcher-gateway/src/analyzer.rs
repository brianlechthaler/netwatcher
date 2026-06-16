use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use netwatcher_common::{
    parse_fatt_line, parse_p0f_line, GatewayConfig, IngestEvent, NetworkEvent,
};
use tokio::fs;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{debug, warn};

const MAX_ANALYZER_LOG_BYTES: usize = 10 * 1024 * 1024;

pub struct TrafficAnalyzer {
    config: GatewayConfig,
}

impl TrafficAnalyzer {
    pub fn new(config: GatewayConfig) -> Self {
        Self { config }
    }

    pub async fn analyze_pcap(
        &self,
        agent_id: &str,
        hostname: &str,
        interface: &str,
        pcap_path: &Path,
    ) -> anyhow::Result<Vec<NetworkEvent>> {
        let p0f_log = pcap_path.with_extension("p0f.log");
        let fatt_log = pcap_path.with_extension("fatt.log");

        let p0f_events = self.run_p0f(pcap_path, &p0f_log).await.unwrap_or_else(|e| {
            warn!(error = %e, "p0f analysis failed");
            Vec::new()
        });

        let fatt_events = self
            .run_fatt(pcap_path, &fatt_log)
            .await
            .unwrap_or_else(|e| {
                warn!(error = %e, "fatt analysis failed");
                Vec::new()
            });

        let mut ingest_events = Vec::with_capacity(p0f_events.len() + fatt_events.len());
        ingest_events.extend(p0f_events);
        ingest_events.extend(fatt_events);

        ingest_events.truncate(self.config.max_events_per_batch);

        debug!(
            agent_id,
            hostname,
            interface,
            count = ingest_events.len(),
            "pcap analysis complete"
        );

        let events = ingest_events
            .into_iter()
            .map(|e| NetworkEvent::from_ingest(agent_id, hostname, e))
            .collect();

        let _ = fs::remove_file(&p0f_log).await;
        let _ = fs::remove_file(&fatt_log).await;

        Ok(events)
    }

    async fn run_p0f(&self, pcap: &Path, output: &Path) -> anyhow::Result<Vec<IngestEvent>> {
        let mut child = Command::new(&self.config.p0f_bin)
            .args([
                "-r",
                &pcap.to_string_lossy(),
                "-o",
                &output.to_string_lossy(),
                "-f",
                &self.config.p0f_fp,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        let timeout_secs = self.config.analysis_timeout_secs;
        let status = match timeout(Duration::from_secs(timeout_secs), child.wait()).await {
            Ok(result) => result?,
            Err(_) => {
                let _ = child.kill().await;
                anyhow::bail!("p0f timed out after {timeout_secs}s");
            }
        };

        if !status.success() {
            anyhow::bail!("p0f exited with {status}");
        }

        self.parse_log_file(output, parse_p0f_line).await
    }

    async fn run_fatt(&self, pcap: &Path, output: &Path) -> anyhow::Result<Vec<IngestEvent>> {
        let mut child = Command::new("python3")
            .args([
                &self.config.fatt_script,
                "-r",
                &pcap.to_string_lossy(),
                "-j",
                "-p",
                "-o",
                &output.to_string_lossy(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        let timeout_secs = self.config.analysis_timeout_secs;
        let status = match timeout(Duration::from_secs(timeout_secs), child.wait()).await {
            Ok(result) => result?,
            Err(_) => {
                let _ = child.kill().await;
                anyhow::bail!("fatt timed out after {timeout_secs}s");
            }
        };

        if !status.success() {
            anyhow::bail!("fatt exited with {status}");
        }

        self.parse_log_file(output, parse_fatt_line).await
    }

    async fn parse_log_file<F>(
        &self,
        path: &Path,
        parse_line: F,
    ) -> anyhow::Result<Vec<IngestEvent>>
    where
        F: Fn(&str) -> Option<IngestEvent>,
    {
        let metadata = fs::metadata(path).await?;
        if metadata.len() as usize > MAX_ANALYZER_LOG_BYTES {
            anyhow::bail!("analyzer log exceeds maximum size ({MAX_ANALYZER_LOG_BYTES} bytes)");
        }

        let content = fs::read_to_string(path).await?;
        let mut events = Vec::new();
        for line in content.lines() {
            if events.len() >= self.config.max_events_per_batch {
                break;
            }
            if let Some(mut event) = parse_line(line) {
                let raw_len = serde_json::to_string(&event.raw)
                    .map(|s| s.len())
                    .unwrap_or(0);
                if raw_len <= self.config.max_raw_event_bytes {
                    events.push(event);
                } else {
                    event.raw = serde_json::json!({
                        "truncated": true,
                        "original_bytes": raw_len
                    });
                    events.push(event);
                }
            }
        }
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyzer_constructs_with_defaults() {
        let analyzer = TrafficAnalyzer::new(GatewayConfig::default());
        assert_eq!(analyzer.config.p0f_bin, "/usr/local/bin/p0f");
    }
}
