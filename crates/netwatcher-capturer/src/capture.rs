use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Context;
use pcap::{Capture, Linktype, Savefile};
use tracing::{debug, info, warn};

pub struct PcapCapturer {
    interface: String,
    pcap_dir: PathBuf,
    rotate_interval: Duration,
    rotate_count: usize,
    rotate_size_bytes: u64,
    snaplen: i32,
}

impl PcapCapturer {
    pub fn new(
        interface: &str,
        pcap_dir: &Path,
        rotate_interval: Duration,
        rotate_count: usize,
        rotate_size_bytes: u64,
        snaplen: i32,
    ) -> anyhow::Result<Self> {
        fs::create_dir_all(pcap_dir).with_context(|| format!("create {}", pcap_dir.display()))?;
        Ok(Self {
            interface: interface.to_string(),
            pcap_dir: pcap_dir.to_path_buf(),
            rotate_interval,
            rotate_count: rotate_count.max(2),
            rotate_size_bytes: rotate_size_bytes.max(1024),
            snaplen,
        })
    }

    pub fn run(&self) -> anyhow::Result<()> {
        let mut cap = Capture::from_device(self.interface.as_str())
            .with_context(|| format!("open device {}", self.interface))?
            .promisc(true)
            .snaplen(self.snaplen)
            .timeout(1000)
            .immediate_mode(true)
            .open()
            .with_context(|| format!("activate capture on {}", self.interface))?;

        let mut writer = RotatingWriter::new(
            &self.pcap_dir,
            self.rotate_interval,
            self.rotate_count,
            self.rotate_size_bytes,
            cap.get_datalink(),
        )?;

        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    writer.write_packet(&packet)?;
                }
                Err(pcap::Error::TimeoutExpired) => {
                    writer.maybe_rotate()?;
                }
                Err(e) => {
                    warn!(error = %e, "capture error, retrying");
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }
}

struct RotatingWriter {
    pcap_dir: PathBuf,
    rotate_interval: Duration,
    rotate_count: usize,
    rotate_size_bytes: u64,
    linktype: Linktype,
    file_index: usize,
    opened_at: Instant,
    bytes_written: u64,
    savefile: Option<Savefile>,
    active_path: Option<PathBuf>,
}

impl RotatingWriter {
    fn new(
        pcap_dir: &Path,
        rotate_interval: Duration,
        rotate_count: usize,
        rotate_size_bytes: u64,
        linktype: Linktype,
    ) -> anyhow::Result<Self> {
        let mut writer = Self {
            pcap_dir: pcap_dir.to_path_buf(),
            rotate_interval,
            rotate_count,
            rotate_size_bytes,
            linktype,
            file_index: 0,
            opened_at: Instant::now(),
            bytes_written: 0,
            savefile: None,
            active_path: None,
        };
        writer.rotate()?;
        Ok(writer)
    }

    fn write_packet(&mut self, packet: &pcap::Packet<'_>) -> anyhow::Result<()> {
        if self.should_rotate() {
            self.rotate()?;
        }
        if let Some(savefile) = self.savefile.as_mut() {
            savefile.write(packet);
            self.bytes_written += 16 + packet.header.caplen as u64;
        }
        Ok(())
    }

    fn maybe_rotate(&mut self) -> anyhow::Result<()> {
        if self.should_rotate() {
            self.rotate()?;
        }
        Ok(())
    }

    fn should_rotate(&self) -> bool {
        self.opened_at.elapsed() >= self.rotate_interval
            || self.bytes_written >= self.rotate_size_bytes
    }

    fn rotate(&mut self) -> anyhow::Result<()> {
        self.savefile = None;
        self.active_path = None;
        self.bytes_written = 0;
        self.opened_at = Instant::now();
        self.file_index = (self.file_index + 1) % self.rotate_count;

        let filename = format!("capture-{:04}.pcap", self.file_index);
        let path = self.pcap_dir.join(&filename);
        let savefile = Capture::dead(self.linktype)
            .with_context(|| format!("create dead capture for {:?}", self.linktype))?
            .savefile(&path)
            .with_context(|| format!("open pcap writer {}", path.display()))?;

        info!(file = %path.display(), "rotated pcap");
        self.savefile = Some(savefile);
        self.active_path = Some(path);
        self.prune_old_files()?;
        Ok(())
    }

    fn prune_old_files(&self) -> anyhow::Result<()> {
        let mut files: Vec<PathBuf> = Vec::new();
        for entry in fs::read_dir(&self.pcap_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file()
                && path
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e == "pcap")
            {
                files.push(path);
            }
        }
        if files.len() <= self.rotate_count {
            return Ok(());
        }
        files.sort();
        let excess = files.len().saturating_sub(self.rotate_count);
        for path in files.into_iter().take(excess) {
            if self.active_path.as_ref() == Some(&path) {
                continue;
            }
            if let Err(e) = fs::remove_file(&path) {
                debug!(file = %path.display(), error = %e, "failed to prune pcap");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn rotating_writer_module_loads() {
        assert!(true);
    }
}
