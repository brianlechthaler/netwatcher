use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use netwatcher_common::{
    parse_fatt_line, parse_p0f_line, parse_zeek_json_line, GatewayConfig, IngestEvent, NetworkEvent,
};
use tokio::fs;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{debug, warn};

const MAX_ANALYZER_LOG_BYTES: usize = 10 * 1024 * 1024;

fn drop_analyzer_privileges(cmd: &mut Command) {
    #[cfg(unix)]
    {
        if let Some(uid) = std::env::var("ANALYZER_UID")
            .ok()
            .and_then(|v| v.parse().ok())
        {
            cmd.uid(uid);
        }
        if let Some(gid) = std::env::var("ANALYZER_GID")
            .ok()
            .and_then(|v| v.parse().ok())
        {
            cmd.gid(gid);
        }
    }
}

#[cfg(unix)]
fn chown_for_analyzer(path: &Path) {
    if let (Some(uid), Some(gid)) = (
        std::env::var("ANALYZER_UID")
            .ok()
            .and_then(|v| v.parse().ok()),
        std::env::var("ANALYZER_GID")
            .ok()
            .and_then(|v| v.parse().ok()),
    ) {
        let _ = std::os::unix::fs::chown(path, Some(uid), Some(gid));
    }
}

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
        let deadline = Instant::now() + Duration::from_secs(self.config.analysis_timeout_secs);

        let zeek_events = self
            .run_zeek(pcap_path, deadline)
            .await
            .unwrap_or_else(|e| {
                warn!(error = %e, "zeek analysis failed");
                Vec::new()
            });

        let p0f_events = self
            .run_p0f(pcap_path, &p0f_log, deadline)
            .await
            .unwrap_or_else(|e| {
                warn!(error = %e, "p0f analysis failed");
                Vec::new()
            });

        let fatt_events = self
            .run_fatt(pcap_path, &fatt_log, deadline)
            .await
            .unwrap_or_else(|e| {
                warn!(error = %e, "fatt analysis failed");
                Vec::new()
            });

        let mut ingest_events =
            Vec::with_capacity(zeek_events.len() + p0f_events.len() + fatt_events.len());
        ingest_events.extend(zeek_events);
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

    async fn run_zeek(&self, pcap: &Path, deadline: Instant) -> anyhow::Result<Vec<IngestEvent>> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            anyhow::bail!("pcap analysis budget exhausted before zeek");
        }
        let log_dir = tempfile::tempdir()?;
        let log_path = log_dir.path().to_path_buf();
        #[cfg(unix)]
        chown_for_analyzer(&log_path);

        let pcap_arg = pcap.to_string_lossy().into_owned();
        let log_dir_arg = format!("Log::default_logdir={}", log_path.to_string_lossy());
        let mut cmd = Command::new(&self.config.zeek_bin);
        cmd.args([
            "-r",
            &pcap_arg,
            "local",
            "LogAscii::use_json=T",
            &log_dir_arg,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
        drop_analyzer_privileges(&mut cmd);
        let mut child = cmd.spawn()?;

        let status = match timeout(remaining, child.wait()).await {
            Ok(result) => result?,
            Err(_) => {
                let _ = child.kill().await;
                anyhow::bail!("zeek timed out");
            }
        };

        if !status.success() {
            anyhow::bail!("zeek exited with {status}");
        }

        self.parse_zeek_logs(&log_path).await
    }

    async fn parse_zeek_logs(&self, log_dir: &Path) -> anyhow::Result<Vec<IngestEvent>> {
        let mut events = Vec::new();
        let mut entries = fs::read_dir(log_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let log_type = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("other")
                .to_string();
            let metadata = fs::metadata(&path).await?;
            if metadata.len() as usize > MAX_ANALYZER_LOG_BYTES {
                warn!(file = %path.display(), "zeek log exceeds size cap, skipping");
                continue;
            }
            let content = fs::read_to_string(&path).await?;
            for line in content.lines() {
                if events.len() >= self.config.max_events_per_batch {
                    return Ok(events);
                }
                if let Some(mut event) = parse_zeek_json_line(line, &log_type) {
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
        }
        Ok(events)
    }

    async fn run_p0f(
        &self,
        pcap: &Path,
        output: &Path,
        deadline: Instant,
    ) -> anyhow::Result<Vec<IngestEvent>> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            anyhow::bail!("pcap analysis budget exhausted before p0f");
        }
        let pcap_arg = pcap.to_string_lossy().into_owned();
        let output_arg = output.to_string_lossy().into_owned();
        let mut cmd = Command::new(&self.config.p0f_bin);
        cmd.args([
            "-r",
            &pcap_arg,
            "-o",
            &output_arg,
            "-f",
            &self.config.p0f_fp,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
        drop_analyzer_privileges(&mut cmd);
        let mut child = cmd.spawn()?;

        let status = match timeout(remaining, child.wait()).await {
            Ok(result) => result?,
            Err(_) => {
                let _ = child.kill().await;
                anyhow::bail!("p0f timed out");
            }
        };

        if !status.success() {
            anyhow::bail!("p0f exited with {status}");
        }

        self.parse_log_file(output, parse_p0f_line).await
    }

    async fn run_fatt(
        &self,
        pcap: &Path,
        output: &Path,
        deadline: Instant,
    ) -> anyhow::Result<Vec<IngestEvent>> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            anyhow::bail!("pcap analysis budget exhausted before fatt");
        }
        let pcap_arg = pcap.to_string_lossy().into_owned();
        let output_arg = output.to_string_lossy().into_owned();
        let mut cmd = Command::new("python3");
        cmd.args([
            &self.config.fatt_script,
            "-r",
            &pcap_arg,
            "-j",
            "-p",
            "-o",
            &output_arg,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
        drop_analyzer_privileges(&mut cmd);
        let mut child = cmd.spawn()?;

        let status = match timeout(remaining, child.wait()).await {
            Ok(result) => result?,
            Err(_) => {
                let _ = child.kill().await;
                anyhow::bail!("fatt timed out");
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
