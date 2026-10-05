//! A deliberately tiny, read-only HTTP/1.1 layer: GET and HEAD only, one
//! request per connection, hard limits on everything an unauthenticated
//! client controls. There is no HTTP server crate in this project, and
//! the surface here is small enough that hand-rolling it is safer than a
//! dependency tree of features this never uses.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

pub const MAX_REQUEST_BYTES: usize = 8 * 1024;
pub const MAX_HEADERS: usize = 64;
/// Total time allowed to receive a complete request, so a client that
/// trickles bytes cannot hold a connection slot open.
pub const REQUEST_DEADLINE: Duration = Duration::from_secs(10);
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    pub method: Method,
    pub path: String,
    pub query: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    TooLarge,
    Malformed,
    MethodNotAllowed,
    BodyNotAllowed,
    BadHost,
    Io,
}

impl ParseError {
    pub fn response(&self) -> Response {
        match self {
            ParseError::TooLarge => Response::error(431, "request too large"),
            ParseError::Malformed => Response::error(400, "malformed request"),
            ParseError::MethodNotAllowed => {
                let mut r = Response::error(405, "this API is read-only: GET and HEAD only");
                r.allow = Some("GET, HEAD");
                r
            }
            ParseError::BodyNotAllowed => Response::error(400, "request bodies are not accepted"),
            ParseError::BadHost => Response::error(421, "unexpected Host header"),
            ParseError::Io => Response::error(408, "request timeout"),
        }
    }
}

pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    pub allow: Option<&'static str>,
}

impl Response {
    pub fn json(status: u16, value: &serde_json::Value) -> Response {
        Response {
            status,
            content_type: "application/json",
            body: serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec()),
            allow: None,
        }
    }

    pub fn error(status: u16, message: &str) -> Response {
        Response::json(status, &serde_json::json!({ "api": 1, "error": message }))
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        421 => "Misdirected Request",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

pub fn write_response<W: Write>(w: &mut W, r: &Response, head_only: bool) -> std::io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Content-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\n\
         Referrer-Policy: no-referrer\r\n\
         Connection: close\r\n",
        r.status,
        reason(r.status),
        r.content_type,
        r.body.len(),
    );
    if let Some(allow) = r.allow {
        head.push_str(&format!("Allow: {allow}\r\n"));
    }
    head.push_str("\r\n");
    w.write_all(head.as_bytes())?;
    if !head_only {
        w.write_all(&r.body)?;
    }
    w.flush()
}

/// Reads until the blank line that ends the headers, within the byte and
/// time limits. Anything after the blank line is ignored: no request
/// body is ever read.
pub fn read_request(stream: &mut TcpStream) -> Result<Request, ParseError> {
    let start = Instant::now();
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(end) = find_header_end(&buf) {
            return parse_request(&buf[..end]);
        }
        if buf.len() >= MAX_REQUEST_BYTES {
            return Err(ParseError::TooLarge);
        }
        let remaining = REQUEST_DEADLINE
            .checked_sub(start.elapsed())
            .filter(|d| !d.is_zero())
            .ok_or(ParseError::Io)?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| ParseError::Io)?;
        match stream.read(&mut chunk) {
            Ok(0) => return Err(ParseError::Malformed),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return Err(ParseError::Io),
        }
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

pub fn parse_request(head: &[u8]) -> Result<Request, ParseError> {
    if head.len() > MAX_REQUEST_BYTES {
        return Err(ParseError::TooLarge);
    }
    if !head.is_ascii() {
        return Err(ParseError::Malformed);
    }
    let text = std::str::from_utf8(head).map_err(|_| ParseError::Malformed)?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or(ParseError::Malformed)?;

    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(ParseError::Malformed);
    };
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(ParseError::Malformed);
    }
    if !target.starts_with('/') || target.starts_with("//") || target.bytes().any(|b| b < 0x21) {
        return Err(ParseError::Malformed);
    }

    let method = match method {
        "GET" => Method::Get,
        "HEAD" => Method::Head,
        _ => return Err(ParseError::MethodNotAllowed),
    };

    let mut host: Option<&str> = None;
    let mut count = 0;
    for line in lines {
        if line.is_empty() {
            break;
        }
        count += 1;
        if count > MAX_HEADERS {
            return Err(ParseError::TooLarge);
        }
        let (name, value) = line.split_once(':').ok_or(ParseError::Malformed)?;
        if name.is_empty() || name.contains(' ') || name.contains('\t') {
            return Err(ParseError::Malformed);
        }
        let value = value.trim();
        match name.to_ascii_lowercase().as_str() {
            "host" => host = Some(value),
            "content-length" if value != "0" => return Err(ParseError::BodyNotAllowed),
            "transfer-encoding" => return Err(ParseError::BodyNotAllowed),
            _ => {}
        }
    }

    // Checked before routing so no data is served to a browser reaching
    // this loopback port by a hostile name (DNS rebinding).
    if let Some(h) = host {
        if !host_allowed(h) {
            return Err(ParseError::BadHost);
        }
    }

    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    Ok(Request {
        method,
        path: path.to_string(),
        query: query.to_string(),
    })
}

/// Only literal loopback names are accepted, with an optional port.
pub fn host_allowed(host: &str) -> bool {
    let name = if let Some(rest) = host.strip_prefix('[') {
        match rest.split_once(']') {
            Some((addr, tail)) if tail.is_empty() || tail.starts_with(':') => addr,
            _ => return false,
        }
    } else {
        host.rsplit_once(':').map_or(host, |(n, port)| {
            if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) {
                n
            } else {
                host
            }
        })
    };
    matches!(
        name.to_ascii_lowercase().as_str(),
        "localhost" | "127.0.0.1" | "::1"
    )
}

pub fn query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<Request, ParseError> {
        parse_request(s.as_bytes())
    }

    #[test]
    fn parses_get_with_query() {
        let r =
            parse("GET /api/v1/events?since=5&limit=10 HTTP/1.1\r\nHost: 127.0.0.1:8765\r\n\r\n")
                .unwrap();
        assert_eq!(r.method, Method::Get);
        assert_eq!(r.path, "/api/v1/events");
        assert_eq!(query_param(&r.query, "since"), Some("5"));
        assert_eq!(query_param(&r.query, "limit"), Some("10"));
        assert_eq!(query_param(&r.query, "nope"), None);
    }

    #[test]
    fn head_is_accepted_and_everything_else_is_405() {
        assert_eq!(
            parse("HEAD / HTTP/1.1\r\n\r\n").unwrap().method,
            Method::Head
        );
        for m in [
            "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "CONNECT", "get",
        ] {
            let req = format!("{m} /api/v1/snapshot HTTP/1.1\r\n\r\n");
            assert_eq!(parse(&req), Err(ParseError::MethodNotAllowed), "{m}");
        }
        let resp = ParseError::MethodNotAllowed.response();
        assert_eq!(resp.status, 405);
        assert_eq!(resp.allow, Some("GET, HEAD"));
    }

    #[test]
    fn bodies_are_rejected() {
        assert_eq!(
            parse("GET / HTTP/1.1\r\nContent-Length: 5\r\n\r\n"),
            Err(ParseError::BodyNotAllowed)
        );
        assert_eq!(
            parse("GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"),
            Err(ParseError::BodyNotAllowed)
        );
        assert!(parse("GET / HTTP/1.1\r\nContent-Length: 0\r\n\r\n").is_ok());
    }

    #[test]
    fn malformed_requests_are_rejected() {
        for bad in [
            "GET\r\n\r\n",
            "GET / \r\n\r\n",
            "GET / HTTP/2\r\n\r\n",
            "GET index HTTP/1.1\r\n\r\n",
            "GET //evil.example/ HTTP/1.1\r\n\r\n",
            "GET /a b HTTP/1.1\r\n\r\n",
            "GET / HTTP/1.1 extra\r\n\r\n",
            "GET / HTTP/1.1\r\nno-colon\r\n\r\n",
            "GET / HTTP/1.1\r\nBad Name: x\r\n\r\n",
            "GET /\u{e9} HTTP/1.1\r\n\r\n",
        ] {
            assert_eq!(parse(bad), Err(ParseError::Malformed), "{bad:?}");
        }
    }

    #[test]
    fn too_many_headers_is_rejected() {
        let mut req = String::from("GET / HTTP/1.1\r\n");
        for i in 0..=MAX_HEADERS {
            req.push_str(&format!("X-{i}: v\r\n"));
        }
        req.push_str("\r\n");
        assert_eq!(parse(&req), Err(ParseError::TooLarge));
    }

    #[test]
    fn host_header_must_be_loopback() {
        for ok in [
            "localhost",
            "LOCALHOST:8765",
            "127.0.0.1",
            "127.0.0.1:8765",
            "[::1]",
            "[::1]:8765",
        ] {
            assert!(host_allowed(ok), "{ok}");
        }
        for bad in [
            "example.com",
            "127.0.0.1.evil.example",
            "evil.example:8765",
            "10.0.0.1",
            "[::1",
            "[::1]x",
            "",
            "localhost:abc",
        ] {
            assert!(!host_allowed(bad), "{bad}");
        }
        assert_eq!(
            parse("GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n"),
            Err(ParseError::BadHost)
        );
        assert!(parse("GET / HTTP/1.0\r\n\r\n").is_ok());
    }

    #[test]
    fn response_has_security_headers_and_no_cors() {
        let mut out = Vec::new();
        write_response(&mut out, &Response::error(404, "nope"), false).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("HTTP/1.1 404 Not Found\r\n"));
        for h in [
            "Cache-Control: no-store",
            "X-Content-Type-Options: nosniff",
            "Content-Security-Policy: default-src 'none'",
            "Connection: close",
        ] {
            assert!(text.contains(h), "{h}");
        }
        assert!(!text.to_ascii_lowercase().contains("access-control-"));
    }

    #[test]
    fn head_response_omits_body_but_keeps_length() {
        let r = Response::error(200, "x");
        let mut out = Vec::new();
        write_response(&mut out, &r, true).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(&format!("Content-Length: {}", r.body.len())));
        assert!(text.ends_with("\r\n\r\n"));
    }
}
