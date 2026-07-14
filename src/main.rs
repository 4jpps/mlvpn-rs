use clap::{Parser, Subcommand};
use mlvpn::config::{self, Config};
use mlvpn::error::{MlvpnError, Result};
use mlvpn::firewall;
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
    /// Detect the active firewall backend (firewalld, ufw, nftables, or
    /// iptables) and open inbound UDP access for every [[links]] port in
    /// the given config. Always try --dry-run first: this inspects and
    /// modifies live firewall state, unlike every other subcommand here.
    FirewallSetup {
        #[arg(short, long, default_value = "/etc/mlvpn/mlvpn.toml")]
        config: PathBuf,
        /// Print the commands this would run without executing them.
        #[arg(long)]
        dry_run: bool,
        /// Close the ports instead of opening them.
        #[arg(long)]
        remove: bool,
        /// Skip auto-detection and use this backend instead: firewalld,
        /// ufw, nftables, or iptables.
        #[arg(long)]
        backend: Option<String>,
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
        Command::FirewallSetup {
            config,
            dry_run,
            remove,
            backend,
        } => {
            let cfg = Config::load(&config)?;
            let action = if remove {
                firewall::Action::Remove
            } else {
                firewall::Action::Add
            };
            firewall::run(&cfg, dry_run, action, backend.as_deref())?;
            Ok(())
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
    // Links are bound *before* the TUN device is created (deliberately
    // reversed from the more obvious ordering) so we can query each
    // bind_interface's real kernel MTU first and pick a safe effective
    // tunnel MTU -- see effective_tunnel_mtu() below -- before the TUN
    // device is ever built with a fixed value. Both still happen before
    // privileges are dropped, since both need CAP_NET_RAW/root-level
    // access on the systems that require it.
    let mut links = Vec::with_capacity(cfg.links.len());
    for (i, link_cfg) in cfg.links.iter().enumerate() {
        let id =
            u8::try_from(i).map_err(|_| MlvpnError::Config("too many links (max 255)".into()))?;
        let link = link::Link::bind(id, link_cfg.clone(), cfg.scheduler.ewma_alpha).await?;
        tracing::info!(
            link = %link_cfg.name,
            interface = %link_cfg.bind_interface,
            port = link_cfg.local_port,
            physical_mtu = ?link.physical_mtu,
            "link bound"
        );
        links.push(link);
    }

    let effective_mtu = effective_tunnel_mtu(&cfg.tunnel, &links);
    let tun = open_tun(&cfg.tunnel, effective_mtu)?;

    let local_private = crypto::StaticKeypair::load_private(&cfg.crypto.private_key_file)?;
    let peer_public = crypto::decode_public_key(&cfg.crypto.peer_public_key)?;

    // --- Drop privileges before touching the network further ---------
    privilege::drop_privileges(&privilege::DropTarget::default())?;
    privilege::assert_unprivileged()?;

    // The control socket exposes live link/traffic stats to `mlvpn-tui`
    // (and anything else that wants to read newline-delimited JSON off a
    // Unix socket -- see `control.rs`). `None` disables it entirely.
    let control_socket = if cfg.control.enabled {
        Some(
            cfg.control
                .socket_path
                .clone()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(format!("/run/mlvpn/{}.sock", cfg.tunnel.name))),
        )
    } else {
        None
    };

    let params = tunnel::TunnelParams {
        mode: cfg.mode,
        mtu: effective_mtu,
        clamp_mss: cfg.tunnel.clamp_mss,
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

/// Picks the MTU actually used for the TUN device and outgoing packet
/// sizing: the smaller of the configured `tunnel.mtu` and a safe value
/// derived from every bonded link's real physical interface MTU (see
/// `link::Link::physical_mtu`, populated via `SIOCGIFMTU` at bind time).
/// This turns the previously advisory-only startup warning (still in
/// `config.rs`'s `validate()`, checked against a generic 1500-byte
/// assumption before any link exists to ask) into a real, self-correcting
/// default: a configured `tunnel.mtu` that would actually fragment
/// against this deployment's hardware gets clamped down automatically
/// instead of just logging a warning and fragmenting anyway. Links
/// whose physical MTU couldn't be determined (non-Linux, insufficient
/// permissions, a transient ioctl failure) simply don't participate in
/// the minimum -- if *no* link's MTU is known, this falls back to
/// trusting the configured value outright rather than refusing to
/// start.
///
/// `outer_overhead` deliberately assumes the *larger* of the two
/// possible outer-transport combinations (IPv6/UDP, 48 bytes) rather
/// than IPv4/UDP (28 bytes): which one a given link actually dials over
/// depends on `remote_addr`'s address family per-link, and this
/// function has no per-link visibility into that -- one tunnel-wide MTU
/// is picked for all of them. Assuming the larger overhead errs toward
/// "possibly slightly conservative" rather than "possibly still
/// fragments on an IPv6 link," which is the correct direction to be
/// wrong in given the user asked for this to auto-adjust for
/// *throughput*, not just raw MTU size: a black-holed PMTUD stall costs
/// far more throughput than a few bytes of headroom ever would.
fn effective_tunnel_mtu(cfg: &config::TunnelConfig, links: &[link::Link]) -> u16 {
    let outer_overhead = mlvpn::protocol::HEADER_LEN as u32 + mlvpn::crypto::TAG_LEN as u32 + 48;

    let Some(detected_min) = links.iter().filter_map(|l| l.physical_mtu).min() else {
        return cfg.mtu;
    };

    let safe_mtu = detected_min
        .saturating_sub(outer_overhead)
        .min(u16::MAX as u32) as u16;

    if cfg.mtu > safe_mtu {
        // Never clamp below the config-time floor already enforced in
        // config.rs's validate() (>= 576, the IPv6 minimum-MTU
        // guarantee) -- an unusually small detected physical MTU should
        // surface as a visible problem, not silently produce a tunnel
        // MTU so small it can't carry a minimum-size IPv6 packet at
        // all.
        let clamped = safe_mtu.max(576);
        tracing::warn!(
            configured = cfg.mtu,
            detected_min_physical_mtu = detected_min,
            clamped_to = clamped,
            "tunnel.mtu exceeds what the bonded links' physical interfaces can carry \
             without fragmentation; auto-clamping down for this run (edit tunnel.mtu \
             in the config to make this permanent and silence this warning)"
        );
        clamped
    } else {
        cfg.mtu
    }
}

fn open_tun(cfg: &config::TunnelConfig, mtu: u16) -> Result<tun_rs::AsyncDevice> {
    let (addr, prefix) = parse_cidr(&cfg.address)?;
    let mut builder = tun_rs::DeviceBuilder::new()
        .name(cfg.name.as_str())
        .ipv4(addr.as_str(), prefix, None)
        .mtu(mtu);

    if let Some(address6) = &cfg.address6 {
        let (addr6, prefix6) = parse_cidr(address6)?;
        builder = builder.ipv6(addr6.as_str(), prefix6);
    }

    let dev = builder
        .build_async()
        .map_err(|e| MlvpnError::Tun(format!("creating device '{}': {e}", cfg.name)))?;
    tracing::info!(
        name = %cfg.name,
        address = %cfg.address,
        address6 = ?cfg.address6,
        mtu,
        "tun device created"
    );
    Ok(dev)
}

fn parse_cidr(s: &str) -> Result<(String, u8)> {
    let (addr, prefix) = s.split_once('/').ok_or_else(|| {
        MlvpnError::Config(format!(
            "tunnel.address '{s}' must be in CIDR form, e.g. 10.0.0.1/30"
        ))
    })?;
    let prefix: u8 = prefix.parse().map_err(|_| {
        MlvpnError::Config(format!("invalid prefix length in tunnel.address '{s}'"))
    })?;
    Ok((addr.to_string(), prefix))
}
