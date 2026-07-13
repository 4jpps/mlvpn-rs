use clap::{Parser, Subcommand};
use mlvpn::config::{self, Config};
use mlvpn::error::{MlvpnError, Result};
use mlvpn::{crypto, link, privilege, tunnel};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "mlvpnd", version, about = "Multi-link VPN bonding daemon")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the daemon using the given configuration file.
    Run {
        #[arg(short, long, default_value = "/etc/mlvpn/mlvpn.toml")]
        config: PathBuf,
    },
    /// Generate a new Curve25519 static keypair and print both halves as
    /// base64. Save the private half to a 0600 file referenced by
    /// `crypto.private_key_file` in the config, and share the public half
    /// with the peer for their `crypto.peer_public_key`.
    Genkey {
        /// Write the private key to this file (mode 0600) instead of
        /// printing it to stdout.
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Genkey { out } => genkey(out),
        Command::Run { config } => {
            let cfg = Config::load(&config)?;
            init_logging(&cfg.logging.level);
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(run(cfg))
        }
    }
}

fn init_logging(level: &str) {
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn genkey(out: Option<PathBuf>) -> anyhow::Result<()> {
    let kp = crypto::StaticKeypair::generate()?;
    match out {
        Some(path) => {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)?;
            f.write_all(kp.private_base64().as_bytes())?;
            println!("private key written to {}", path.display());
            println!("public key (share with peer): {}", kp.public_base64());
        }
        None => {
            println!("private key: {}", kp.private_base64());
            println!("public key:  {}", kp.public_base64());
            eprintln!(
                "\nwarning: private key printed to stdout; prefer --out to write it \
                 straight to a 0600 file instead of letting it touch your shell history \
                 or terminal scrollback."
            );
        }
    }
    Ok(())
}

async fn run(cfg: Config) -> anyhow::Result<()> {
    tracing::info!(mode = ?cfg.mode, tunnel = %cfg.tunnel.name, "starting mlvpnd");

    // --- Privileged setup phase -------------------------------------
    let tun = open_tun(&cfg.tunnel)?;

    let mut links = Vec::with_capacity(cfg.links.len());
    for (i, link_cfg) in cfg.links.iter().enumerate() {
        let id = u8::try_from(i).map_err(|_| MlvpnError::Config("too many links (max 255)".into()))?;
        let link = link::Link::bind(id, link_cfg.clone(), cfg.scheduler.ewma_alpha).await?;
        tracing::info!(
            link = %link_cfg.name,
            interface = %link_cfg.bind_interface,
            port = link_cfg.local_port,
            "link bound"
        );
        links.push(link);
    }

    let local_private = crypto::StaticKeypair::load_private(&cfg.crypto.private_key_file)?;
    let peer_public = crypto::decode_public_key(&cfg.crypto.peer_public_key)?;

    // --- Drop privileges before touching the network further ---------
    privilege::drop_privileges(&privilege::DropTarget::default())?;
    privilege::assert_unprivileged()?;

    // The control socket exposes live link/traffic stats to `mlvpn-tui`
    // (and anything else that wants to read newline-delimited JSON off a
    // Unix socket -- see `control.rs`). `None` disables it entirely.
    let control_socket = if cfg.control.enabled {
        Some(cfg.control.socket_path.clone().map(PathBuf::from).unwrap_or_else(|| {
            PathBuf::from(format!("/run/mlvpn/{}.sock", cfg.tunnel.name))
        }))
    } else {
        None
    };

    let params = tunnel::TunnelParams {
        mode: cfg.mode,
        mtu: cfg.tunnel.mtu,
        scheduler_cfg: cfg.scheduler.clone(),
        local_private,
        peer_public,
        rekey_interval: std::time::Duration::from_secs(cfg.crypto.rekey_interval_secs),
        tunnel_name: cfg.tunnel.name.clone(),
        control_socket,
    };

    let shutdown = tokio::signal::ctrl_c();
    tokio::select! {
        result = tunnel::run(tun, links, params) => {
            result.map_err(anyhow::Error::from)
        }
        _ = shutdown => {
            tracing::info!("received shutdown signal, exiting");
            Ok(())
        }
    }
}

fn open_tun(cfg: &config::TunnelConfig) -> Result<tun_rs::AsyncDevice> {
    let (addr, prefix) = parse_cidr(&cfg.address)?;
    let dev = tun_rs::DeviceBuilder::new()
        .name(cfg.name.as_str())
        .ipv4(addr.as_str(), prefix, None)
        .mtu(cfg.mtu)
        .build_async()
        .map_err(|e| MlvpnError::Tun(format!("creating device '{}': {e}", cfg.name)))?;
    tracing::info!(name = %cfg.name, address = %cfg.address, mtu = cfg.mtu, "tun device created");
    Ok(dev)
}

fn parse_cidr(s: &str) -> Result<(String, u8)> {
    let (addr, prefix) = s
        .split_once('/')
        .ok_or_else(|| MlvpnError::Config(format!("tunnel.address '{s}' must be in CIDR form, e.g. 10.0.0.1/30")))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| MlvpnError::Config(format!("invalid prefix length in tunnel.address '{s}'")))?;
    Ok((addr.to_string(), prefix))
}
