mod shipper;

use std::time::Duration;

use clap::Parser;
use netwatcher_common::ShipperConfig;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::shipper::LogShipper;

#[derive(Parser, Debug)]
#[command(
    name = "netwatcher-shipper",
    about = "Ship capture logs and pcaps to gateway"
)]
struct Args {
    #[arg(long, env = "GATEWAY_URL", default_value = "http://gateway:8080")]
    gateway_url: String,

    #[arg(long, env = "AGENT_ID", default_value = "capture-agent-1")]
    agent_id: String,

    #[arg(long, env = "HOSTNAME")]
    hostname: Option<String>,

    #[arg(long, env = "GATEWAY_API_KEY")]
    api_key: Option<String>,

    #[arg(
        long,
        env = "WATCH_DIRS",
        value_delimiter = ',',
        default_value = "/logs/zeek"
    )]
    watch_dirs: Vec<String>,

    #[arg(long, env = "PCAP_DIR")]
    pcap_dir: Option<String>,

    #[arg(long, env = "POLL_INTERVAL_SECS", default_value = "5")]
    poll_interval_secs: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();
    let poll_interval = args.poll_interval_secs;
    let config = ShipperConfig {
        gateway_url: args.gateway_url,
        agent_id: args.agent_id,
        hostname: args
            .hostname
            .or_else(|| std::env::var("HOSTNAME").ok())
            .unwrap_or_else(|| "capture-agent".to_string()),
        api_key: args.api_key,
        watch_dirs: args.watch_dirs,
        pcap_dir: args.pcap_dir.or_else(|| Some("/pcap".to_string())),
        poll_interval_secs: poll_interval,
    };

    info!(agent_id = %config.agent_id, gateway = %config.gateway_url, "shipper starting");
    let shipper = LogShipper::new(config)?;
    shipper.run(Duration::from_secs(poll_interval)).await
}
