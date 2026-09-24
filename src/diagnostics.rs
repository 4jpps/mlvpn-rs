//! Submits diagnostic bundles (from `diag::format_dump` or the raw log
//! ring) to the shared `jpps/software-support` intake service as a
//! real, trackable support ticket -- see
//! `docs/superpowers/specs/2026-08-27-diagnostics-report-client-design.md`
//! for the full design.
//!
//! No redaction step is needed here (unlike similar clients elsewhere):
//! `config::CryptoConfig` only ever holds a *path* to the private key
//! file, never the key material itself, so nothing reaching this module
//! from `diag::format_dump` or `logbuf::LogRing` was ever secret to
//! begin with.

use serde_json::json;

const DIAGNOSTICS_URL_DEFAULT: &str = "https://software-support.jpps.us";

/// Returns the base URL to submit reports to. Reads
/// `MLVPN_DIAGNOSTICS_URL` if set (used by integration tests to point
/// at a local mock server instead of the real live service); falls
/// back to the real service otherwise.
fn diagnostics_url() -> String {
    std::env::var("MLVPN_DIAGNOSTICS_URL").unwrap_or_else(|_| DIAGNOSTICS_URL_DEFAULT.to_string())
}

fn os_info() -> String {
    std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                line.strip_prefix("PRETTY_NAME=")
                    .map(|v| v.trim_matches('"').to_string())
            })
        })
        .unwrap_or_else(|| std::env::consts::OS.to_string())
}

fn hostname() -> Option<String> {
    nix::unistd::gethostname()
        .ok()
        .map(|h| h.to_string_lossy().into_owned())
}

fn build_report_body(bundle: &str, trigger: &str, message: Option<&str>) -> serde_json::Value {
    json!({
        "product": "mlvpn-rs",
        "version": env!("CARGO_PKG_VERSION"),
        "os_info": os_info(),
        "hostname": hostname(),
        "trigger": trigger,
        "logs": bundle,
        // software-support's SubmitReport.message is a required
        // String, not Option<String> -- sending JSON `null` here (the
        // old behavior for `None`) makes axum's Json extractor fail to
        // deserialize the whole request before the handler even runs,
        // rejecting with 422 regardless of anything else in the body.
        // Confirmed live: every automatic (loss-threshold-triggered)
        // report from this daemon has been silently failing with
        // exactly this error since the intake service existed, since
        // `control.rs`'s watcher always calls this with `message:
        // None`. omnibridge's own client (the other real consumer of
        // this same endpoint) never hits this because its equivalent
        // field is typed as a plain String there too -- always a real
        // value, never optional. Match that contract: an absent
        // message is an empty string, never JSON null.
        "message": message.unwrap_or(""),
    })
}

#[derive(serde::Deserialize)]
struct SubmitResponse {
    ticket_id: String,
}

const SUBMIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Submits a diagnostic bundle to `software-support` synchronously.
/// Used from contexts with no guaranteed tokio runtime: the CLI's
/// `diag-dump --submit` path and the panic hook's spawned thread.
pub fn submit_report_blocking(
    bundle: &str,
    trigger: &str,
    message: Option<&str>,
) -> anyhow::Result<String> {
    let body = build_report_body(bundle, trigger, message);
    let client = reqwest::blocking::Client::builder()
        .timeout(SUBMIT_TIMEOUT)
        .build()?;
    let resp = client
        .post(format!("{}/api/v1/reports", diagnostics_url()))
        .json(&body)
        .send()?;
    if !resp.status().is_success() {
        anyhow::bail!("software-support returned {}", resp.status());
    }
    let parsed: SubmitResponse = resp.json()?;
    Ok(parsed.ticket_id)
}

/// Same as `submit_report_blocking`, but non-blocking -- used by
/// the automatic diagnostics watcher (`control::diagnostics_watch_loop`),
/// which already runs inside the daemon's tokio runtime.
pub async fn submit_report_async(
    bundle: &str,
    trigger: &str,
    message: Option<&str>,
) -> anyhow::Result<String> {
    let body = build_report_body(bundle, trigger, message);
    let client = reqwest::Client::builder().timeout(SUBMIT_TIMEOUT).build()?;
    let resp = client
        .post(format!("{}/api/v1/reports", diagnostics_url()))
        .json(&body)
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("software-support returned {}", resp.status());
    }
    let parsed: SubmitResponse = resp.json().await?;
    Ok(parsed.ticket_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_report_body_includes_expected_fields_and_omits_identity() {
        let body = build_report_body("some log text", "manual", Some("it broke"));
        assert_eq!(body["product"], "mlvpn-rs");
        assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(body["trigger"], "manual");
        assert_eq!(body["logs"], "some log text");
        assert_eq!(body["message"], "it broke");
        // No license_key/install_id field at all -- mlvpn-rs has no
        // licensing system, and the API treats both as optional.
        assert!(body.get("license_key").is_none());
        assert!(body.get("install_id").is_none());
    }

    // Real bug this guards against: software-support's SubmitReport.message
    // is a required String, not Option<String> -- sending JSON `null`
    // makes axum's Json extractor reject the whole request with 422
    // before the handler runs at all. Confirmed this was happening on
    // every real automatic (loss-threshold) report in production; see
    // `build_report_body`'s own doc comment for the full story.
    #[test]
    fn build_report_body_message_is_an_empty_string_not_null_when_absent() {
        let body = build_report_body("logs", "auto", None);
        assert_eq!(body["message"], "");
        assert!(!body["message"].is_null());
    }

    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Mutex;

    // Shared lock to serialize env var access across all diagnostics tests
    static ENV_LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();

    /// A minimal, single-request raw HTTP server: reads one request off
    /// the listener, ignores its content beyond finding the end of
    /// headers, and writes back a canned response. Matches this
    /// codebase's existing preference (see the veth integration tests)
    /// for testing against real local sockets rather than pulling in a
    /// mocking framework this project has never used before.
    fn spawn_mock_server(status_line: &'static str, json_body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf); // don't need to parse the request
            let response = format!(
                "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{json_body}",
                json_body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        });
        std::thread::sleep(std::time::Duration::from_millis(50)); // allow server to accept
        format!("http://{addr}")
    }

    #[test]
    fn submit_report_blocking_returns_ticket_id_on_201() {
        let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();

        let url = spawn_mock_server("HTTP/1.1 201 Created", r#"{"ticket_id":"abc-123"}"#);
        std::env::set_var("MLVPN_DIAGNOSTICS_URL", &url);
        let result = submit_report_blocking("some logs", "manual", None);
        std::env::remove_var("MLVPN_DIAGNOSTICS_URL");
        assert_eq!(result.unwrap(), "abc-123");
    }

    #[test]
    fn submit_report_blocking_errors_on_non_2xx() {
        let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();

        let url = spawn_mock_server("HTTP/1.1 422 Unprocessable Entity", r#"{"error":"bad"}"#);
        std::env::set_var("MLVPN_DIAGNOSTICS_URL", &url);
        let result = submit_report_blocking("some logs", "manual", None);
        std::env::remove_var("MLVPN_DIAGNOSTICS_URL");
        assert!(result.is_err());
    }

    /// Like `spawn_mock_server`, but hands the captured request body
    /// back to the caller via the returned channel instead of ignoring
    /// it -- lets a test assert on the actual bytes sent over the
    /// wire, not just what `build_report_body` produces as a
    /// `serde_json::Value` in-process (which is exactly what the
    /// removed `build_report_body_message_is_null_when_absent` test
    /// did, and why it never caught this bug -- it checked the value
    /// this module builds, never what a real HTTP client actually
    /// serializes and sends).
    fn spawn_mock_server_capturing_body(
        status_line: &'static str,
        json_body: &'static str,
    ) -> (String, std::sync::mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            // Read until we've seen the blank line ending the headers,
            // then keep reading exactly Content-Length more bytes --
            // good enough for this test's own small, single-request
            // client, not a general HTTP parser.
            loop {
                let n = stream.read(&mut chunk).unwrap();
                buf.extend_from_slice(&chunk[..n]);
                if let Some(header_end) = find_subslice(&buf, b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&buf[..header_end]);
                    let content_length: usize = headers
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length: ").or_else(|| l.strip_prefix("Content-Length: ")))
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                    let body_so_far = buf.len() - (header_end + 4);
                    if body_so_far >= content_length {
                        break;
                    }
                }
            }
            let header_end = find_subslice(&buf, b"\r\n\r\n").unwrap();
            let body = String::from_utf8_lossy(&buf[header_end + 4..]).into_owned();
            let _ = tx.send(body);
            let response = format!(
                "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{json_body}",
                json_body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
        (format!("http://{addr}"), rx)
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    /// The real regression test: submits with no message (the exact
    /// call shape `control.rs`'s automatic loss-threshold watcher
    /// uses) through the real `reqwest` JSON-serialization path, and
    /// asserts the literal bytes on the wire never contain `null` for
    /// message -- catches the bug even if some future change
    /// reintroduces `Option<&str>` being serialized directly again.
    #[test]
    fn submit_report_async_never_sends_a_null_message_over_the_wire() {
        let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();

        let (url, rx) = spawn_mock_server_capturing_body("HTTP/1.1 201 Created", r#"{"ticket_id":"abc-123"}"#);
        std::env::set_var("MLVPN_DIAGNOSTICS_URL", &url);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(submit_report_async("some logs", "auto", None));
        std::env::remove_var("MLVPN_DIAGNOSTICS_URL");
        assert!(result.is_ok());

        let sent_body = rx.recv_timeout(std::time::Duration::from_secs(2)).expect("mock server should have captured a request body");
        assert!(
            !sent_body.contains("\"message\":null"),
            "message must never be serialized as JSON null -- software-support's \
             SubmitReport.message is a required String, and a null here makes \
             axum's Json extractor reject the whole request with 422. Got: {sent_body}"
        );
        assert!(sent_body.contains("\"message\":\"\""), "expected an empty string for an absent message, got: {sent_body}");
    }
}
