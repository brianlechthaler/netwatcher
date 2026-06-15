use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use netwatcher_common::{EventSource, IngestEvent, ZeekLogType};
use serde_json::Value;
use walkdir::WalkDir;

pub fn parse_zeek_json_line(line: &str, log_type: &str) -> Option<IngestEvent> {
    let raw: Value = serde_json::from_str(line).ok()?;
    let timestamp = extract_timestamp(&raw).unwrap_or_else(Utc::now);
    Some(IngestEvent {
        source: EventSource::Zeek,
        zeek_log_type: Some(map_zeek_log_type(log_type)),
        timestamp,
        raw,
    })
}

pub fn parse_p0f_line(line: &str) -> Option<IngestEvent> {
    if line.trim().is_empty() || line.starts_with('#') {
        return None;
    }
    let parts: Vec<&str> = line.split('|').collect();
    if parts.len() < 5 {
        return None;
    }
    let raw = serde_json::json!({
        "mod": parts.first().unwrap_or(&""),
        "src_ip": parts.get(1).unwrap_or(&""),
        "dst_ip": parts.get(2).unwrap_or(&""),
        "link": parts.get(3).unwrap_or(&""),
        "detail": parts.get(4).unwrap_or(&""),
        "raw_line": line
    });
    Some(IngestEvent {
        source: EventSource::P0f,
        zeek_log_type: None,
        timestamp: Utc::now(),
        raw,
    })
}

pub fn parse_fatt_line(line: &str) -> Option<IngestEvent> {
    let raw: Value = serde_json::from_str(line).ok()?;
    let timestamp = extract_timestamp(&raw).unwrap_or_else(Utc::now);
    Some(IngestEvent {
        source: EventSource::Fatt,
        zeek_log_type: None,
        timestamp,
        raw,
    })
}

fn extract_timestamp(raw: &Value) -> Option<DateTime<Utc>> {
    for key in ["ts", "timestamp", "@timestamp"] {
        if let Some(v) = raw.get(key) {
            if let Some(f) = v.as_f64() {
                return DateTime::from_timestamp(f as i64, 0);
            }
            if let Some(s) = v.as_str() {
                if let Ok(dt) = s.parse::<DateTime<Utc>>() {
                    return Some(dt);
                }
            }
        }
    }
    None
}

fn map_zeek_log_type(name: &str) -> ZeekLogType {
    match name {
        "conn" => ZeekLogType::Conn,
        "dns" => ZeekLogType::Dns,
        "http" => ZeekLogType::Http,
        "ssl" => ZeekLogType::Ssl,
        "files" => ZeekLogType::Files,
        "weird" => ZeekLogType::Weird,
        "notice" => ZeekLogType::Notice,
        other => ZeekLogType::Other(other.to_string()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn parse_zeek_conn_line() {
        let line = r#"{"ts":1700000000.0,"id.orig_h":"10.0.0.1","id.resp_h":"1.2.3.4"}"#;
        let event = parse_zeek_json_line(line, "conn").unwrap();
        assert_eq!(event.source, EventSource::Zeek);
        assert_eq!(event.zeek_log_type, Some(ZeekLogType::Conn));
    }

    #[test]
    fn parse_zeek_invalid_returns_none() {
        assert!(parse_zeek_json_line("not-json", "conn").is_none());
    }

    #[test]
    fn parse_p0f_line_extracts_fields() {
        let line = "srv|10.0.0.1|1.2.3.4|ether|Linux 3.x";
        let event = parse_p0f_line(line).unwrap();
        assert_eq!(event.source, EventSource::P0f);
        assert_eq!(event.raw["src_ip"], "10.0.0.1");
    }

    #[test]
    fn parse_p0f_skips_comments() {
        assert!(parse_p0f_line("# comment").is_none());
        assert!(parse_p0f_line("").is_none());
    }

    #[test]
    fn parses_fatt_json_line() {
        let line = r#"{"ts":"2024-01-01T00:00:00Z","ja3":"abc","src_ip":"10.0.0.5"}"#;
        let event = parse_fatt_line(line).unwrap();
        assert_eq!(event.source, EventSource::Fatt);
        assert_eq!(event.raw["ja3"], "abc");
    }

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

        writeln!(
            std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap(),
            "line3"
        )
        .unwrap();
        let second = tailer.read_new_lines().unwrap();
        assert_eq!(second, vec!["line3"]);
    }

    #[test]
    fn discover_log_files_finds_by_directory() {
        let dir = TempDir::new().unwrap();
        let zeek = dir.path().join("zeek");
        let p0f = dir.path().join("p0f");
        std::fs::create_dir_all(&zeek).unwrap();
        std::fs::create_dir_all(&p0f).unwrap();
        std::fs::write(zeek.join("conn.log"), "{}").unwrap();
        std::fs::write(p0f.join("p0f.log"), "x").unwrap();

        let files = discover_log_files(&[
            zeek.to_string_lossy().to_string(),
            p0f.to_string_lossy().to_string(),
        ]);
        assert_eq!(files.len(), 2);
    }
}
