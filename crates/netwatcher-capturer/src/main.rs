mod capture;

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::capture::PcapCapturer;

#[derive(Parser, Debug)]
#[command(
    name = "netwatcher-capturer",
    about = "Lightweight rotating PCAP capture for NetWatcher agents"
)]
struct Args {
    #[arg(long, env = "CAPTURE_INTERFACE", default_value = "eth0")]
    interface: String,

    #[arg(long, env = "PCAP_DIR", default_value = "/pcap")]
    pcap_dir: PathBuf,

    #[arg(long, env = "PCAP_ROTATE_SECS", default_value_t = 30)]
    rotate_secs: u64,

    #[arg(long, env = "PCAP_ROTATE_COUNT", default_value_t = 20)]
    rotate_count: usize,

    #[arg(long, env = "PCAP_ROTATE_SIZE_MB", default_value_t = 10)]
    rotate_size_mb: u64,

    #[arg(long, env = "PCAP_SNAPLEN", default_value_t = 65535)]
    snaplen: i32,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();
    let rotate_size_bytes = args.rotate_size_mb.saturating_mul(1024 * 1024);

    info!(
        interface = %args.interface,
        dir = %args.pcap_dir.display(),
        rotate_secs = args.rotate_secs,
        rotate_count = args.rotate_count,
        rotate_size_mb = args.rotate_size_mb,
        "capturer starting"
    );

    let capturer = PcapCapturer::new(
        &args.interface,
        &args.pcap_dir,
        Duration::from_secs(args.rotate_secs),
        args.rotate_count,
        rotate_size_bytes,
        args.snaplen,
    )?;

    capturer.run()
}
