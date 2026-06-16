use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Duration;

use netwatcher_common::{
    parse_fatt_line, parse_p0f_line, parse_zeek_json_line, EventSource, ShipperConfig,
};
use reqwest::multipart::{Form, Part};
use reqwest::Client;
use tracing::{info, warn};
use walkdir::WalkDir;

pub struct LogShipper {
    config: ShipperConfig,
    client: Client,
    tailers: HashMap<String, FileTailer>,
    shipped_pcaps: HashMap<String, ()>,
}

impl LogShipper {
    pub fn new(config: ShipperConfig) -> anyhow::Result<Self> {
        let client = Client::builder().timeout(Duration::from_secs(60)).build()?;
        Ok(Self {
            config,
            client,
            tailers: HashMap::new(),
            shipped_pcaps: HashMap::new(),
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
        self.ship_logs().await?;
        self.ship_pcaps().await?;
        Ok(())
    }

    async fn ship_logs(&mut self) -> anyhow::Result<()> {
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
                    EventSource::Zeek => {
                        parse_zeek_json_line(&line, zeek_type.as_deref().unwrap_or("other"))
                    }
                    EventSource::P0f => parse_p0f_line(&line),
                    EventSource::Fatt => parse_fatt_line(&line),
                    EventSource::Enriched => None,
                };
                if let Some(e) = event {
                    events.push(e);
                }
            }
        }

        if events.is_empty() {
            return Ok(());
        }

        let batch = netwatcher_common::IngestBatch {
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

        info!(count = batch.events.len(), "shipped log events");
        Ok(())
    }

    async fn ship_pcaps(&mut self) -> anyhow::Result<()> {
        let Some(pcap_dir) = &self.config.pcap_dir else {
            return Ok(());
        };

        self.shipped_pcaps
            .retain(|path, _| std::path::Path::new(path).exists());

        let ready = find_ready_pcaps(Path::new(pcap_dir), self.config.poll_interval_secs)?;
        for path in ready {
            let key = path.to_string_lossy().to_string();
            if self.shipped_pcaps.contains_key(&key) {
                continue;
            }

            match self.upload_pcap(&path).await {
                Ok(()) => {
                    self.shipped_pcaps.insert(key, ());
                    let _ = std::fs::remove_file(&path);
                    info!(file = %path.display(), "shipped pcap");
                }
                Err(e) => {
                    warn!(file = %path.display(), error = %e, "pcap upload failed");
                }
            }
        }

        Ok(())
    }

    async fn upload_pcap(&self, path: &Path) -> anyhow::Result<()> {
        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow::anyhow!("invalid pcap path"))?
            .to_string();

        let bytes = tokio::fs::read(path).await?;
        let part = Part::bytes(bytes)
            .file_name(filename.clone())
            .mime_str("application/vnd.tcpdump.pcap")?;

        let form = Form::new()
            .text("agent_id", self.config.agent_id.clone())
            .text("hostname", self.config.hostname.clone())
            .text(
                "interface",
                std::env::var("CAPTURE_INTERFACE").unwrap_or_else(|_| "auto".into()),
            )
            .text("filename", filename)
            .part("pcap", part);

        let mut request = self
            .client
            .post(format!("{}/api/v1/ingest/pcap", self.config.gateway_url))
            .multipart(form);

        if let Some(key) = &self.config.api_key {
            request = request.header("x-api-key", key);
        }

        let response = request.send().await?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("gateway pcap error {status}: {body}");
        }

        Ok(())
    }
}

pub struct FileTailer {
    path: PathBuf,
    offset: u64,
}

impl FileTailer {
    pub fn new(path: PathBuf) -> Self {
        Self { path, offset: 0 }
    }

    pub fn read_new_lines(&mut self) -> anyhow::Result<Vec<String>> {
        let mut file = File::open(&self.path)?;
        file.seek(SeekFrom::Start(self.offset))?;
        let reader = BufReader::new(file);
        let mut lines = Vec::new();
        for line in reader.lines() {
            let line = line?;
            self.offset += line.len() as u64 + 1;
            if !line.trim().is_empty() {
                lines.push(line);
            }
        }
        Ok(lines)
    }
}

pub fn discover_log_files(watch_dirs: &[String]) -> Vec<(PathBuf, EventSource, Option<String>)> {
    let mut files = Vec::new();
    for dir in watch_dirs {
        let path = Path::new(dir);
        if !path.exists() {
            continue;
        }
        let source = if dir.contains("p0f") {
            EventSource::P0f
        } else if dir.contains("fatt") {
            EventSource::Fatt
        } else {
            EventSource::Zeek
        };
        for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
            let p = entry.path();
            if p.is_file() {
                let zeek_type = p
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .map(|s| s.to_string());
                files.push((p.to_path_buf(), source, zeek_type));
            }
        }
    }
    files
}

/// Return PCAP files that are complete (not the actively-written newest file).
fn find_ready_pcaps(dir: &Path, poll_interval_secs: u64) -> anyhow::Result<Vec<PathBuf>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut pcaps: Vec<(PathBuf, std::time::SystemTime)> = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file()
            && path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e == "pcap")
        {
            if let Ok(meta) = entry.metadata() {
                if let Ok(modified) = meta.modified() {
                    pcaps.push((path, modified));
                }
            }
        }
    }

    if pcaps.len() < 2 {
        return Ok(Vec::new());
    }

    pcaps.sort_by_key(|(_, mtime)| *mtime);
    let newest_mtime = pcaps.last().map(|(_, m)| *m);
    let stale_threshold = Duration::from_secs(poll_interval_secs.saturating_mul(2).max(10));

    let ready: Vec<PathBuf> = pcaps
        .into_iter()
        .filter(|(_path, mtime)| {
            if Some(*mtime) == newest_mtime {
                return false;
            }
            mtime
                .elapsed()
                .map(|elapsed| elapsed >= stale_threshold)
                .unwrap_or(false)
        })
        .map(|(path, _)| path)
        .collect();

    Ok(ready)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn file_tailer_reads_incrementally() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("conn.log");
        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "line1").unwrap();
        writeln!(file, "line2").unwrap();

        let mut tailer = FileTailer::new(path.clone());
        let first = tailer.read_new_lines().unwrap();
        assert_eq!(first, vec!["line1", "line2"]);
    }

    #[test]
    fn find_ready_pcaps_requires_multiple_files() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("only.pcap"), b"data").unwrap();
        let ready = find_ready_pcaps(dir.path(), 5).unwrap();
        assert!(ready.is_empty());
    }
}
