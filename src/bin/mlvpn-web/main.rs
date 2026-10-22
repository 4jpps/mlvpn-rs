//! `mlvpn-web`: an optional, read-only HTTP telemetry API for `mlvpnd`.
//!
//! A separate process from the daemon, so enabling it adds no listening
//! socket and no HTTP code to `mlvpnd` itself. It connects to the
//! daemon's local control socket (the same one `mlvpn-tui` reads), keeps
//! the latest snapshot plus a short rolling history and event buffer in
//! memory, and serves them as versioned JSON under `/api/v1/`.
//!
//! Constraints, deliberately:
//! - GET and HEAD only; every other method is a 405.
//! - Loopback only. Binding anything else is refused: non-loopback
//!   exposure needs authentication, which does not exist yet.
//! - No secrets: the daemon log ring is never served, and the control
//!   socket carries no key material.
//! - Hard limits on request size, header count, request time and
//!   concurrent connections.
//!
//! The control socket is mode 0600 owned by `mlvpn`, so run this as the
//! `mlvpn` user (see `systemd/mlvpn-web.service`).

mod api;
mod http;

use anyhow::Context;
use api::Shared;
use clap::Parser;
use mlvpn::ipc::Snapshot;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const DEFAULT_LISTEN: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8765);
const MAX_CONNECTIONS: usize = 32;

#[derive(Parser)]
#[command(
    name = "mlvpn-web",
    version,
    about = "Read-only HTTP telemetry API for an mlvpnd tunnel (loopback only)"
)]
struct Cli {
    /// Path to the mlvpnd control socket. If omitted, uses the single
    /// `*.sock` file under /run/mlvpn/ (the command socket is ignored).
    #[arg(short, long)]
    socket: Option<PathBuf>,
    /// Address to listen on. Must be a loopback address.
    #[arg(short, long, default_value_t = DEFAULT_LISTEN)]
    listen: SocketAddr,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    ensure_loopback(cli.listen)?;
    let listener =
        TcpListener::bind(cli.listen).with_context(|| format!("binding {}", cli.listen))?;
    eprintln!("mlvpn-web: listening on http://{} (read-only)", cli.listen);

    let state = Arc::new(Mutex::new(Shared::default()));
    {
        let state = state.clone();
        let socket = cli.socket;
        thread::spawn(move || reader_thread(socket, state));
    }
    run_server(listener, state, MAX_CONNECTIONS);
    Ok(())
}

fn ensure_loopback(addr: SocketAddr) -> anyhow::Result<()> {
    if addr.ip().is_loopback() {
        Ok(())
    } else {
        anyhow::bail!(
            "refusing to listen on {addr}: only loopback addresses are allowed \
             (non-loopback exposure requires authentication, which is not implemented)"
        )
    }
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

fn run_server(listener: TcpListener, state: Arc<Mutex<Shared>>, max_connections: usize) {
    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
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
        let active_in_thread = active.clone();
        let spawned = thread::Builder::new()
            .name("mlvpn-web-conn".into())
            .spawn(move || {
                serve_connection(stream, &state);
                active_in_thread.fetch_sub(1, Ordering::SeqCst);
            });
        if spawned.is_err() {
            active.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

fn serve_connection(mut stream: TcpStream, state: &Mutex<Shared>) {
    let _ = stream.set_write_timeout(Some(http::WRITE_TIMEOUT));
    let (response, head_only) = match http::read_request(&mut stream) {
        Ok(req) => {
            let head_only = req.method == http::Method::Head;
            (api::handle(&state.lock().unwrap(), &req), head_only)
        }
        Err(e) => (e.response(), false),
    };
    let _ = http::write_response(&mut stream, &response, head_only);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn non_loopback_listen_addresses_are_refused() {
        assert!(ensure_loopback("127.0.0.1:8765".parse().unwrap()).is_ok());
        assert!(ensure_loopback("127.5.5.5:1".parse().unwrap()).is_ok());
        assert!(ensure_loopback("[::1]:8765".parse().unwrap()).is_ok());
        for bad in [
            "0.0.0.0:8765",
            "192.168.1.5:8765",
            "[::]:8765",
            "8.8.8.8:80",
        ] {
            assert!(ensure_loopback(bad.parse().unwrap()).is_err(), "{bad}");
        }
    }

    fn start(max: usize) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(Shared::default()));
        thread::spawn(move || run_server(listener, state, max));
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
    fn serves_get_rejects_writes_over_a_real_socket() {
        let addr = start(8);
        let ok = roundtrip(
            addr,
            "GET /api/v1/version HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        assert!(ok.starts_with("HTTP/1.1 200 OK\r\n"), "{ok}");
        assert!(ok.contains("\"api_version\":1"), "{ok}");

        let nodata = roundtrip(addr, "GET /api/v1/snapshot HTTP/1.1\r\n\r\n");
        assert!(nodata.starts_with("HTTP/1.1 503"), "{nodata}");

        let post = roundtrip(
            addr,
            "POST /api/v1/snapshot HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}",
        );
        assert!(post.starts_with("HTTP/1.1 405"), "{post}");
        assert!(post.contains("Allow: GET, HEAD"), "{post}");

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
