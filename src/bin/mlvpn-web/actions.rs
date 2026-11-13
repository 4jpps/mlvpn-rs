//! Dashboard actions: turn a link off or on, run a throughput test, take a
//! diagnostic dump. Each one is a single command on the daemon's command
//! socket (the same one `mlvpnd link`, `mlvpnd self-test` and
//! `mlvpnd diag-dump` use).
//!
//! Off unless `[web] allow_actions = true`. Every action is a POST with a
//! JSON body, the `X-MLVPN-Action: 1` header and, when the browser sends
//! one, an `Origin` matching the `Host`: a page on another site can't set
//! that header without a CORS preflight, which this server never grants.
//! Only one action runs at a time.

use crate::Settings;
use crate::api::Shared;
use crate::http::{Request, Response};
use mlvpn::ipc::{Command, CommandResult};
use serde::Deserialize;
use serde_json::json;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

static BUSY: AtomicBool = AtomicBool::new(false);

pub const MAX_TEST_SECS: u32 = 15;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkBody {
    link: String,
    enabled: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TestBody {
    #[serde(default)]
    link: Option<String>,
    #[serde(default = "default_secs")]
    duration_secs: u32,
    #[serde(default)]
    bidirectional: bool,
}

fn default_secs() -> u32 {
    5
}

/// Checks that apply to every action, before anything is parsed or run.
pub fn guard(settings: &Settings, req: &Request) -> Result<(), Response> {
    if !settings.web.allow_actions {
        return Err(Response::error(
            403,
            "actions are turned off ([web] allow_actions in mlvpn.toml)",
        ));
    }
    // Without a certificate check, anyone on this machine who can reach the
    // port would act with the mlvpn user's command socket, so actions need
    // `client_cert_header`; a loopback-only dashboard is view-only (root
    // has the mlvpnd CLI).
    if settings
        .web
        .client_cert_header
        .as_deref()
        .is_none_or(|h| h.trim().is_empty())
    {
        return Err(Response::error(
            403,
            "actions need [web] client_cert_header (a proxy that checks a client certificate)",
        ));
    }
    if req.header("x-mlvpn-action") != Some("1") {
        return Err(Response::error(403, "missing X-MLVPN-Action header"));
    }
    let json = req.header("content-type").is_some_and(|c| {
        c.split(';')
            .next()
            .unwrap_or("")
            .trim()
            .eq_ignore_ascii_case("application/json")
    });
    if !json {
        return Err(Response::error(415, "send JSON"));
    }
    if let Some(origin) = req.header("origin") {
        let host = req.header("host").unwrap_or("");
        let same = origin
            .strip_prefix("https://")
            .or_else(|| origin.strip_prefix("http://"))
            .is_some_and(|o| o.eq_ignore_ascii_case(host));
        if !same {
            return Err(Response::error(403, "cross-origin request refused"));
        }
    }
    Ok(())
}

pub fn handle(settings: &Settings, state: &Mutex<Shared>, req: &Request, who: &str) -> Response {
    if let Err(r) = guard(settings, req) {
        return r;
    }
    if BUSY
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Response::error(409, "another action is still running");
    }
    let response = run(settings, state, req, who);
    BUSY.store(false, Ordering::SeqCst);
    response
}

fn run(settings: &Settings, state: &Mutex<Shared>, req: &Request, who: &str) -> Response {
    match req.path.as_str() {
        "/api/v1/actions/link" => {
            let body: LinkBody = match serde_json::from_slice(&req.body) {
                Ok(b) => b,
                Err(e) => return Response::error(400, &format!("bad request body: {e}")),
            };
            if !known_link(state, &body.link) {
                return Response::error(404, "no such link");
            }
            eprintln!(
                "mlvpn-web: {who} turned link {} {}",
                body.link,
                if body.enabled { "on" } else { "off" }
            );
            let cmd = Command::SetLinkEnabled {
                link: body.link.clone(),
                enabled: body.enabled,
            };
            match send(settings, &cmd, Duration::from_secs(10)) {
                Ok(r) if r.ok => {
                    state.lock().unwrap().note_admin(&body.link, !body.enabled);
                    Response::json(200, &json!({"api": 1, "ok": true}))
                }
                Ok(r) => refused(r),
                Err(e) => Response::error(502, &e),
            }
        }
        "/api/v1/actions/selftest" => {
            let body: TestBody = match serde_json::from_slice(&req.body) {
                Ok(b) => b,
                Err(e) => return Response::error(400, &format!("bad request body: {e}")),
            };
            if !(1..=MAX_TEST_SECS).contains(&body.duration_secs) {
                return Response::error(400, &format!("duration_secs must be 1-{MAX_TEST_SECS}"));
            }
            if let Some(l) = &body.link
                && !known_link(state, l)
            {
                return Response::error(404, "no such link");
            }
            eprintln!(
                "mlvpn-web: {who} started a {} s throughput test ({})",
                body.duration_secs,
                body.link.as_deref().unwrap_or("all links")
            );
            let links = state.lock().unwrap().link_count().max(1) as u64;
            let per = body.duration_secs as u64 * if body.bidirectional { 2 } else { 1 } + 20;
            let cmd = Command::RunThroughputTest {
                link: body.link,
                duration_secs: body.duration_secs,
                bidirectional: body.bidirectional,
            };
            match send(settings, &cmd, Duration::from_secs(per * links + 10)) {
                Ok(r) if r.ok => Response::json(
                    200,
                    &json!({"api": 1, "ok": true, "results": r.throughput_results, "peer_version": r.peer_version}),
                ),
                Ok(r) => refused(r),
                Err(e) => Response::error(502, &e),
            }
        }
        "/api/v1/actions/diag" => {
            eprintln!("mlvpn-web: {who} took a diagnostic dump");
            match send(settings, &Command::DiagDump, Duration::from_secs(60)) {
                Ok(r) if r.ok => Response::json(
                    200,
                    &json!({"api": 1, "ok": true, "text": r.diag_dump.unwrap_or_default()}),
                ),
                Ok(r) => refused(r),
                Err(e) => Response::error(502, &e),
            }
        }
        _ => Response::error(404, "not found"),
    }
}

fn known_link(state: &Mutex<Shared>, name: &str) -> bool {
    state
        .lock()
        .unwrap()
        .snapshot
        .as_ref()
        .is_some_and(|s| s.links.iter().any(|l| l.name == name))
}

fn refused(r: CommandResult) -> Response {
    Response::error(
        409,
        &format!(
            "mlvpnd refused: {}",
            r.error.unwrap_or_else(|| "no reason given".into())
        ),
    )
}

/// The command socket: `[command] socket_path`, else
/// `/run/mlvpn/<tunnel.name>.command.sock`, else the only `*.command.sock`.
pub fn command_socket(settings: &Settings) -> Option<PathBuf> {
    if let Some(p) = &settings.command_socket {
        return Some(p.clone());
    }
    if let Some(name) = &settings.tunnel_name {
        return Some(PathBuf::from(format!("/run/mlvpn/{name}.command.sock")));
    }
    let mut found: Vec<PathBuf> = std::fs::read_dir("/run/mlvpn")
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".command.sock"))
        })
        .collect();
    (found.len() == 1).then(|| found.remove(0))
}

fn send(settings: &Settings, cmd: &Command, timeout: Duration) -> Result<CommandResult, String> {
    let path = command_socket(settings)
        .ok_or("no command socket found: is [command] enabled = true in mlvpn.toml?")?;
    let mut stream = UnixStream::connect(&path).map_err(|e| {
        format!(
            "can't reach mlvpnd's command socket {}: {e}",
            path.display()
        )
    })?;
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    let mut line = serde_json::to_vec(cmd).map_err(|e| e.to_string())?;
    line.push(b'\n');
    stream.write_all(&line).map_err(|e| e.to_string())?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|e| e.to_string())?;
    let mut reply = String::new();
    BufReader::new(&stream)
        .read_line(&mut reply)
        .map_err(|e| format!("no reply from mlvpnd: {e}"))?;
    serde_json::from_str(reply.trim_end()).map_err(|e| format!("bad reply from mlvpnd: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Method, Request};

    fn settings(actions: bool) -> Settings {
        let mut s = Settings::for_tests();
        s.web.allow_actions = actions;
        s.web.client_cert_header = Some("X-Client-Cert-Subject".into());
        s
    }

    #[test]
    fn actions_need_a_certificate_header_setting() {
        let mut s = Settings::for_tests();
        s.web.allow_actions = true;
        let req = post(&[
            ("X-MLVPN-Action", "1"),
            ("Content-Type", "application/json"),
        ]);
        assert_eq!(guard(&s, &req).unwrap_err().status, 403);
    }

    fn post(headers: &[(&str, &str)]) -> Request {
        Request {
            method: Method::Post,
            path: "/api/v1/actions/diag".into(),
            query: String::new(),
            headers: headers
                .iter()
                .map(|(n, v)| (n.to_ascii_lowercase(), v.to_string()))
                .collect(),
            body: b"{}".to_vec(),
        }
    }

    #[test]
    fn actions_need_the_setting_the_header_json_and_same_origin() {
        let good = [
            ("Host", "mlvpn.example.net"),
            ("X-MLVPN-Action", "1"),
            ("Content-Type", "application/json"),
            ("Origin", "https://mlvpn.example.net"),
        ];
        assert!(guard(&settings(true), &post(&good)).is_ok());
        assert_eq!(
            guard(&settings(false), &post(&good)).unwrap_err().status,
            403
        );
        assert_eq!(
            guard(&settings(true), &post(&good[..1]))
                .unwrap_err()
                .status,
            403
        );
        let text = [good[0], good[1], ("Content-Type", "text/plain"), good[3]];
        assert_eq!(
            guard(&settings(true), &post(&text)).unwrap_err().status,
            415
        );
        let cross = [
            good[0],
            good[1],
            good[2],
            ("Origin", "https://evil.example"),
        ];
        assert_eq!(
            guard(&settings(true), &post(&cross)).unwrap_err().status,
            403
        );
        // No Origin (curl on the box itself) is fine.
        assert!(guard(&settings(true), &post(&good[..3])).is_ok());
    }
}
