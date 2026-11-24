//! `mlvpn-web`: an optional dashboard and HTTP API for `mlvpnd`.
//!
//! A separate process from the daemon, so enabling it adds no listening
//! socket and no HTTP code to `mlvpnd` itself. It connects to the
//! daemon's local control socket (the same one `mlvpn-tui` reads), keeps
//! the latest snapshot plus a short rolling history and event buffer in
//! memory, and serves a dashboard plus versioned JSON under `/api/v1/`.
//! With `[web] allow_actions`, the dashboard can also turn links off and
//! on, run throughput tests and take diagnostic dumps through the
//! daemon's command socket.
//!
//! Settings come from the `[web]` table of mlvpn.toml. Constraints:
//! - Loopback by default. A non-loopback `listen` is refused unless
//!   `trusted_proxies` and `client_cert_header` are set: it is meant to sit
//!   behind a reverse proxy that verifies a client certificate. Any peer
//!   other than loopback or a trusted proxy is refused, and requests from
//!   the proxy without the certificate header (or with a name not in
//!   `allowed_subjects`) are refused.
//! - No secrets: the daemon log ring is never served (a diagnostic dump,
//!   an action, includes recent log lines), and the control socket
//!   carries no key material.
//! - Hard limits on request size, header count, request time and
//!   concurrent connections.
//!
//! The control sockets are mode 0600 owned by `mlvpn`, so run this as the
//! `mlvpn` user (see `systemd/mlvpn-web.service`).

mod actions;
mod api;
mod http;

use anyhow::Context;
use api::{Shared, UiInfo};
use clap::Parser;
use mlvpn::config::WebConfig;
use mlvpn::ipc::Snapshot;
use serde::Deserialize;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const DEFAULT_CONFIG: &str = "/etc/mlvpn/mlvpn.toml";
const MAX_CONNECTIONS: usize = 32;

#[derive(Parser)]
#[command(
    name = "mlvpn-web",
    version = env!("APP_VERSION"),
    about = "Dashboard and HTTP API for an mlvpnd tunnel (settings: [web] in mlvpn.toml)"
)]
struct Cli {
    /// mlvpn.toml to read the `[web]`, `[command]` and `[tunnel]` settings
    /// from. Missing is fine when not given explicitly: the defaults apply.
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// Path to the mlvpnd control socket. If omitted, uses the single
    /// `*.sock` file under /run/mlvpn/ (the command socket is ignored).
    #[arg(short, long)]
    socket: Option<PathBuf>,
    /// Address to listen on, overriding `[web] listen`.
    #[arg(short, long)]
    listen: Option<SocketAddr>,
}

/// Everything the server needs from mlvpn.toml.
pub struct Settings {
    pub web: WebConfig,
    pub listen: SocketAddr,
    pub tunnel_name: Option<String>,
    pub command_socket: Option<PathBuf>,
    /// `allowed_hosts` plus the listen address.
    pub hosts: Vec<String>,
}

impl Settings {
    fn new(
        web: WebConfig,
        listen: SocketAddr,
        tunnel_name: Option<String>,
        command_socket: Option<PathBuf>,
    ) -> Settings {
        let mut hosts: Vec<String> = web
            .allowed_hosts
            .iter()
            .map(|h| h.to_ascii_lowercase())
            .collect();
        if !listen.ip().is_unspecified() {
            hosts.push(listen.ip().to_string());
        }
        Settings {
            web,
            listen,
            tunnel_name,
            command_socket,
            hosts,
        }
    }

    fn title(&self) -> String {
        self.web
            .title
            .clone()
            .or_else(|| self.tunnel_name.clone())
            .unwrap_or_else(|| "mlvpn".into())
    }

    #[cfg(test)]
    pub fn for_tests() -> Settings {
        Settings::new(
            WebConfig::default(),
            "127.0.0.1:8765".parse().unwrap(),
            Some("t0".into()),
            None,
        )
    }
}

/// Only the tables mlvpn-web reads; everything else in the file is ignored
/// (it's `mlvpnd`'s to validate).
#[derive(Deserialize, Default)]
struct FileConfig {
    #[serde(default)]
    web: WebConfig,
    #[serde(default)]
    tunnel: Option<TunnelPart>,
    #[serde(default)]
    command: Option<CommandPart>,
}

#[derive(Deserialize)]
struct TunnelPart {
    name: String,
}

#[derive(Deserialize)]
struct CommandPart {
    #[serde(default)]
    socket_path: Option<String>,
}

fn load(cli: &Cli) -> anyhow::Result<Settings> {
    let path = cli
        .config
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG));
    let file: FileConfig = match std::fs::read_to_string(&path) {
        Ok(text) => toml::from_str(&text).with_context(|| format!("reading {}", path.display()))?,
        Err(e) if cli.config.is_none() && e.kind() == std::io::ErrorKind::NotFound => {
            FileConfig::default()
        }
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let listen = match cli.listen {
        Some(l) => l,
        None => file.web.listen.parse().with_context(|| {
            format!(
                "[web] listen = {:?} is not an address:port",
                file.web.listen
            )
        })?,
    };
    check(&file.web, listen)?;
    Ok(Settings::new(
        file.web,
        listen,
        file.tunnel.map(|t| t.name),
        file.command.and_then(|c| c.socket_path).map(PathBuf::from),
    ))
}

/// A non-loopback listener only behind a trusted, authenticating proxy.
fn check(web: &WebConfig, listen: SocketAddr) -> anyhow::Result<()> {
    if listen.ip().is_loopback() {
        return Ok(());
    }
    if web.trusted_proxies.is_empty() {
        anyhow::bail!(
            "refusing to listen on {listen}: a non-loopback address needs [web] trusted_proxies \
             (the reverse proxy's address) in mlvpn.toml"
        );
    }
    if web
        .client_cert_header
        .as_deref()
        .is_none_or(|h| h.trim().is_empty())
    {
        anyhow::bail!(
            "refusing to listen on {listen}: a non-loopback address needs [web] client_cert_header \
             (the header your proxy sets to the verified client certificate)"
        );
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let settings = Arc::new(load(&cli)?);
    let listener = TcpListener::bind(settings.listen)
        .with_context(|| format!("binding {}", settings.listen))?;
    eprintln!(
        "mlvpn-web: listening on http://{} ({})",
        settings.listen,
        if settings.web.allow_actions {
            "actions on"
        } else {
            "read-only"
        }
    );

    let state = Arc::new(Mutex::new(Shared::default()));
    {
        let state = state.clone();
        let socket = cli.socket;
        thread::spawn(move || reader_thread(socket, state));
    }
    run_server(listener, state, settings, MAX_CONNECTIONS);
    Ok(())
}

fn find_socket() -> Option<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(Path::new("/run/mlvpn"))
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".sock") && !n.ends_with(".command.sock"))
        })
        .collect();
    (found.len() == 1).then(|| found.remove(0))
}

/// Connects (retrying every 2 s while the daemon is down or restarting)
/// and feeds every snapshot line into the shared state.
fn reader_thread(socket: Option<PathBuf>, state: Arc<Mutex<Shared>>) {
    loop {
        if let Some(path) = socket.clone().or_else(find_socket)
            && let Ok(stream) = UnixStream::connect(&path)
        {
            state.lock().unwrap().on_connect();
            for line in BufReader::new(stream).lines() {
                let Ok(text) = line else { break };
                if let Ok(snapshot) = serde_json::from_str::<Snapshot>(&text) {
                    state.lock().unwrap().ingest(snapshot);
                }
            }
        }
        state.lock().unwrap().connected = false;
        thread::sleep(Duration::from_secs(2));
    }
}

fn run_server(
    listener: TcpListener,
    state: Arc<Mutex<Shared>>,
    settings: Arc<Settings>,
    max_connections: usize,
) {
    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        // Anyone but loopback and the trusted proxies is turned away before
        // a byte of the request is read.
        if !peer_allowed(&settings, stream.peer_addr().ok().map(|a| a.ip())) {
            continue;
        }
        if active.fetch_add(1, Ordering::SeqCst) >= max_connections {
            active.fetch_sub(1, Ordering::SeqCst);
            let _ = stream.set_write_timeout(Some(http::WRITE_TIMEOUT));
            let _ = http::write_response(
                &mut stream,
                &http::Response::error(503, "too many connections"),
                false,
            );
            continue;
        }
        let state = state.clone();
        let settings = settings.clone();
        let active_in_thread = active.clone();
        let spawned = thread::Builder::new()
            .name("mlvpn-web-conn".into())
            .spawn(move || {
                serve_connection(stream, &state, &settings);
                active_in_thread.fetch_sub(1, Ordering::SeqCst);
            });
        if spawned.is_err() {
            active.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

fn peer_allowed(settings: &Settings, peer: Option<IpAddr>) -> bool {
    let Some(ip) = peer.map(canonical) else {
        return false;
    };
    ip.is_loopback()
        || settings
            .web
            .trusted_proxies
            .iter()
            .any(|t| canonical(*t) == ip)
}

/// IPv4-mapped IPv6 (`::ffff:a.b.c.d`) as plain IPv4.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// Who is asking.
#[derive(Debug, PartialEq, Eq)]
pub enum Who {
    /// A connection from this machine that isn't a trusted proxy: may look,
    /// may not act. Any certificate header it sends is ignored (a local
    /// process could write one itself).
    Local,
    /// A certificate name, as vouched for by a trusted proxy.
    Verified(String),
}

impl Who {
    pub fn label(&self) -> &str {
        match self {
            Who::Local => "local",
            Who::Verified(name) => name,
        }
    }
}

/// The certificate header is believed only from `trusted_proxies`; there it
/// is required (and must be an allowed name). Loopback peers that aren't a
/// trusted proxy are `Local`. Anyone else never got this far (`peer_allowed`).
fn identify(settings: &Settings, peer: IpAddr, req: &http::Request) -> Result<Who, http::Response> {
    let peer = canonical(peer);
    let from_proxy = settings
        .web
        .trusted_proxies
        .iter()
        .any(|t| canonical(*t) == peer);
    let header = settings
        .web
        .client_cert_header
        .as_deref()
        .filter(|h| !h.trim().is_empty());
    match (from_proxy, header) {
        (true, Some(header)) => {
            let Some(subject) = req.header(header).map(str::trim).filter(|s| !s.is_empty()) else {
                return Err(http::Response::error(403, "client certificate required"));
            };
            if !settings.web.allowed_subjects.is_empty()
                && !settings.web.allowed_subjects.iter().any(|a| a == subject)
            {
                return Err(http::Response::error(
                    403,
                    "this certificate is not allowed here",
                ));
            }
            Ok(Who::Verified(subject.to_string()))
        }
        _ if peer.is_loopback() => Ok(Who::Local),
        _ => Err(http::Response::error(403, "client certificate required")),
    }
}

fn serve_connection(mut stream: TcpStream, state: &Mutex<Shared>, settings: &Settings) {
    let _ = stream.set_write_timeout(Some(http::WRITE_TIMEOUT));
    let peer = stream.peer_addr().map(|a| a.ip());
    let (response, head_only) = match (http::read_request(&mut stream), peer) {
        (Ok(req), Ok(peer)) => {
            let head_only = req.method == http::Method::Head;
            (respond(state, settings, peer, &req), head_only)
        }
        (Err(e), _) => (e.response(), false),
        (_, Err(_)) => return,
    };
    let _ = http::write_response(&mut stream, &response, head_only);
}

fn respond(
    state: &Mutex<Shared>,
    settings: &Settings,
    peer: IpAddr,
    req: &http::Request,
) -> http::Response {
    // Checked before routing so no data is served to a browser reaching
    // this port by a hostile name (DNS rebinding).
    let mut sensitive = vec!["host", "origin", "content-type", "x-mlvpn-action"];
    if let Some(h) = settings.web.client_cert_header.as_deref() {
        sensitive.push(h);
    }
    if sensitive.iter().any(|h| req.repeated(h)) {
        return http::Response::error(400, "repeated header");
    }
    if !http::host_allowed(req.header("host"), &settings.hosts) {
        return http::Response::error(421, "unexpected Host header");
    }
    let who = match identify(settings, peer, req) {
        Ok(w) => w,
        Err(r) => return r,
    };
    if req.method == http::Method::Post {
        return actions::handle(settings, state, req, &who);
    }
    let title = settings.title();
    let ui = UiInfo {
        title: &title,
        actions: settings.web.allow_actions && matches!(who, Who::Verified(_)),
        who: who.label(),
    };
    api::handle(&state.lock().unwrap(), req, &ui)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn web(proxies: &[&str], header: Option<&str>) -> WebConfig {
        WebConfig {
            trusted_proxies: proxies.iter().map(|p| p.parse().unwrap()).collect(),
            client_cert_header: header.map(String::from),
            ..WebConfig::default()
        }
    }

    #[test]
    fn non_loopback_needs_a_trusted_proxy_and_a_cert_header() {
        let open = web(&[], None);
        for ok in ["127.0.0.1:8765", "127.5.5.5:1", "[::1]:8765"] {
            assert!(check(&open, ok.parse().unwrap()).is_ok(), "{ok}");
        }
        for bad in ["0.0.0.0:8765", "192.168.1.5:8765", "[::]:8765"] {
            assert!(check(&open, bad.parse().unwrap()).is_err(), "{bad}");
            assert!(
                check(&web(&["10.0.0.9"], None), bad.parse().unwrap()).is_err(),
                "{bad}"
            );
            assert!(
                check(
                    &web(&[], Some("X-Client-Cert-Subject")),
                    bad.parse().unwrap()
                )
                .is_err(),
                "{bad}"
            );
            assert!(
                check(
                    &web(&["10.0.0.9"], Some("X-Client-Cert-Subject")),
                    bad.parse().unwrap()
                )
                .is_ok(),
                "{bad}"
            );
        }
    }

    #[test]
    fn the_toml_web_table_is_read_and_other_tables_ignored() {
        let text = r#"
            mode = "client"
            [tunnel]
            name = "mlvpnrs0"
            address = "10.200.0.2/30"
            [command]
            enabled = true
            [web]
            listen = "192.168.1.1:8765"
            title = "home"
            trusted_proxies = ["10.0.0.9"]
            allowed_hosts = ["mlvpn.example.net"]
            client_cert_header = "X-Client-Cert-Subject"
            allowed_subjects = ["Jeff"]
            allow_actions = true
        "#;
        let f: FileConfig = toml::from_str(text).unwrap();
        assert_eq!(f.tunnel.unwrap().name, "mlvpnrs0");
        assert!(f.web.allow_actions);
        assert_eq!(f.web.allowed_subjects, vec!["Jeff".to_string()]);
        assert!(
            toml::from_str::<FileConfig>("[web]\nlisen = \"x\"").is_err(),
            "typos are errors"
        );
    }

    fn proxied(settings_web: WebConfig) -> Settings {
        Settings::new(
            settings_web,
            "192.168.1.1:8765".parse().unwrap(),
            Some("t0".into()),
            None,
        )
    }

    fn req(headers: &[(&str, &str)]) -> http::Request {
        http::Request {
            method: http::Method::Get,
            path: "/api/v1/version".into(),
            query: String::new(),
            headers: headers
                .iter()
                .map(|(n, v)| (n.to_ascii_lowercase(), v.to_string()))
                .collect(),
            body: Vec::new(),
        }
    }

    #[test]
    fn repeated_access_headers_are_refused() {
        let state = Mutex::new(Shared::default());
        let s = proxied(web(&["10.0.0.9"], Some("X-Client-Cert-Subject")));
        let proxy: IpAddr = "10.0.0.9".parse().unwrap();
        let two_certs = req(&[
            ("Host", "192.168.1.1"),
            ("X-Client-Cert-Subject", "Jeff"),
            ("X-Client-Cert-Subject", "Mallory"),
        ]);
        assert_eq!(respond(&state, &s, proxy, &two_certs).status, 400);
        let two_hosts = req(&[
            ("Host", "192.168.1.1"),
            ("Host", "evil.example"),
            ("X-Client-Cert-Subject", "Jeff"),
        ]);
        assert_eq!(respond(&state, &s, proxy, &two_hosts).status, 400);
        let one_each = req(&[("Host", "192.168.1.1"), ("X-Client-Cert-Subject", "Jeff")]);
        assert_eq!(respond(&state, &s, proxy, &one_each).status, 200);
    }

    #[test]
    fn peers_and_identity() {
        let mut w = web(&["10.0.0.9"], Some("X-Client-Cert-Subject"));
        let s = proxied(w.clone());
        assert!(peer_allowed(&s, Some("127.0.0.1".parse().unwrap())));
        assert!(peer_allowed(&s, Some("10.0.0.9".parse().unwrap())));
        assert!(peer_allowed(&s, Some("::ffff:10.0.0.9".parse().unwrap())));
        assert!(!peer_allowed(&s, Some("10.0.0.8".parse().unwrap())));
        assert!(!peer_allowed(&s, None));

        let proxy: IpAddr = "10.0.0.9".parse().unwrap();
        // Loopback is never taken at its word: any header it sends is ignored.
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(identify(&s, lo, &req(&[])).unwrap(), Who::Local);
        assert_eq!(
            identify(&s, lo, &req(&[("X-Client-Cert-Subject", "Jeff")])).unwrap(),
            Who::Local
        );
        let plain = Settings::for_tests();
        assert_eq!(identify(&plain, lo, &req(&[])).unwrap(), Who::Local);
        // ...unless loopback is listed as the proxy (proxy on the same host).
        let mut same_host = web(&["127.0.0.1"], Some("X-Client-Cert-Subject"));
        same_host.allowed_subjects = vec!["Jeff".into()];
        let same_host = proxied(same_host);
        assert_eq!(
            identify(&same_host, lo, &req(&[("X-Client-Cert-Subject", "Jeff")])).unwrap(),
            Who::Verified("Jeff".into())
        );
        assert_eq!(identify(&same_host, lo, &req(&[])).unwrap_err().status, 403);
        assert_eq!(identify(&s, proxy, &req(&[])).unwrap_err().status, 403);
        assert_eq!(
            identify(&s, proxy, &req(&[("X-Client-Cert-Subject", " ")]))
                .unwrap_err()
                .status,
            403
        );
        assert_eq!(
            identify(&s, proxy, &req(&[("X-Client-Cert-Subject", "Jeff")])).unwrap(),
            Who::Verified("Jeff".into())
        );

        w.allowed_subjects = vec!["Jeff".into()];
        let s = proxied(w);
        assert_eq!(
            identify(&s, proxy, &req(&[("X-Client-Cert-Subject", "Jeff")])).unwrap(),
            Who::Verified("Jeff".into())
        );
        assert_eq!(
            identify(&s, proxy, &req(&[("X-Client-Cert-Subject", "Mallory")]))
                .unwrap_err()
                .status,
            403
        );
    }

    #[test]
    fn hosts_include_the_listen_address_and_configured_names() {
        let mut w = web(&["10.0.0.9"], Some("X-Client-Cert-Subject"));
        w.allowed_hosts = vec!["MLVPN.example.net".into()];
        let s = proxied(w);
        assert!(http::host_allowed(Some("mlvpn.example.net"), &s.hosts));
        assert!(http::host_allowed(Some("192.168.1.1:8765"), &s.hosts));
        assert!(!http::host_allowed(Some("evil.example"), &s.hosts));
    }

    fn start(max: usize) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(Shared::default()));
        let settings = Arc::new(Settings::for_tests());
        thread::spawn(move || run_server(listener, state, settings, max));
        addr
    }

    fn roundtrip(addr: SocketAddr, raw: &str) -> String {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(raw.as_bytes()).unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out
    }

    #[test]
    fn serves_get_and_refuses_actions_by_default_over_a_real_socket() {
        let addr = start(8);
        let ok = roundtrip(
            addr,
            "GET /api/v1/version HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        assert!(ok.starts_with("HTTP/1.1 200 OK\r\n"), "{ok}");
        assert!(ok.contains("\"api_version\":1"), "{ok}");

        let page = roundtrip(addr, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(page.starts_with("HTTP/1.1 200 OK\r\n"), "{page}");
        assert!(page.contains("Content-Type: text/html"), "{page}");

        let nodata = roundtrip(addr, "GET /api/v1/snapshot HTTP/1.1\r\n\r\n");
        assert!(nodata.starts_with("HTTP/1.1 503"), "{nodata}");

        let post = roundtrip(
            addr,
            "POST /api/v1/actions/diag HTTP/1.1\r\nX-MLVPN-Action: 1\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        );
        assert!(post.starts_with("HTTP/1.1 403"), "{post}");
        assert!(post.contains("allow_actions"), "{post}");

        let put = roundtrip(addr, "PUT /api/v1/snapshot HTTP/1.1\r\n\r\n");
        assert!(put.starts_with("HTTP/1.1 405"), "{put}");

        let rebind = roundtrip(
            addr,
            "GET /api/v1/version HTTP/1.1\r\nHost: evil.example\r\n\r\n",
        );
        assert!(rebind.starts_with("HTTP/1.1 421"), "{rebind}");

        let head = roundtrip(addr, "HEAD /api/v1/version HTTP/1.1\r\n\r\n");
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert!(head.ends_with("\r\n\r\n"), "{head}");

        let junk = roundtrip(addr, "\x16\x03\x01\x02\x00 not http\r\n\r\n");
        assert!(junk.starts_with("HTTP/1.1 400"), "{junk}");
    }

    #[test]
    fn oversized_request_is_rejected() {
        let addr = start(8);
        let big = format!("GET /{} HTTP/1.1\r\n\r\n", "a".repeat(20_000));
        let out = roundtrip(addr, &big);
        assert!(out.starts_with("HTTP/1.1 431"), "{out}");
    }

    #[test]
    fn connections_beyond_the_cap_get_503() {
        let addr = start(2);
        // Two idle connections hold both slots (the server is waiting for
        // their request bytes).
        let _a = TcpStream::connect(addr).unwrap();
        let _b = TcpStream::connect(addr).unwrap();
        thread::sleep(Duration::from_millis(300));
        let out = roundtrip(addr, "GET / HTTP/1.1\r\n\r\n");
        assert!(out.starts_with("HTTP/1.1 503"), "{out}");
    }
}
