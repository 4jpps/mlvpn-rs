//! A deliberately tiny HTTP/1.1 layer: GET, HEAD and (for dashboard actions)
//! POST with a small body, one request per connection, hard limits on
//! everything a client controls. There is no HTTP server crate in this
//! project, and the surface here is small enough that hand-rolling it is
//! safer than a dependency tree of features this never uses.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

pub const MAX_REQUEST_BYTES: usize = 8 * 1024;
pub const MAX_BODY_BYTES: usize = 4 * 1024;
pub const MAX_HEADERS: usize = 64;
/// Total time allowed to receive a complete request, so a client that
/// trickles bytes cannot hold a connection slot open.
pub const REQUEST_DEADLINE: Duration = Duration::from_secs(10);
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// For JSON and text: nothing may load or run.
pub const CSP_API: &str = "default-src 'none'; frame-ancestors 'none'";
/// For the dashboard page: its own script, style and API, nothing else.
pub const CSP_PAGE: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
     connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; \
     frame-ancestors 'none'";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Post,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    pub method: Method,
    pub path: String,
    pub query: String,
    /// Header names lower-cased, in order.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    TooLarge,
    Malformed,
    MethodNotAllowed,
    BodyNotAllowed,
    LengthRequired,
    Io,
}

impl ParseError {
    pub fn response(&self) -> Response {
        match self {
            ParseError::TooLarge => Response::error(431, "request too large"),
            ParseError::Malformed => Response::error(400, "malformed request"),
            ParseError::MethodNotAllowed => {
                let mut r = Response::error(405, "GET, HEAD and POST only");
                r.allow = Some("GET, HEAD, POST");
                r
            }
            ParseError::BodyNotAllowed => Response::error(400, "this request may not have a body"),
            ParseError::LengthRequired => Response::error(411, "Content-Length required"),
            ParseError::Io => Response::error(408, "request timeout"),
        }
    }
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    pub allow: Option<&'static str>,
    pub csp: &'static str,
}

impl Response {
    pub fn json(status: u16, value: &serde_json::Value) -> Response {
        Response {
            status,
            content_type: "application/json",
            body: serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec()),
            allow: None,
            csp: CSP_API,
        }
    }

    pub fn error(status: u16, message: &str) -> Response {
        Response::json(status, &serde_json::json!({ "api": 1, "error": message }))
    }

    /// A static dashboard file.
    pub fn asset(content_type: &'static str, body: &'static str) -> Response {
        Response {
            status: 200,
            content_type,
            body: body.as_bytes().to_vec(),
            allow: None,
            csp: CSP_PAGE,
        }
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        411 => "Length Required",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        421 => "Misdirected Request",
        431 => "Request Header Fields Too Large",
        502 => "Bad Gateway",
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
         X-Frame-Options: DENY\r\n\
         Content-Security-Policy: {}\r\n\
         Referrer-Policy: no-referrer\r\n\
         Connection: close\r\n",
        r.status,
        reason(r.status),
        r.content_type,
        r.body.len(),
        r.csp,
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

/// Reads the headers (and a POST's body) within the byte and time limits.
pub fn read_request(stream: &mut TcpStream) -> Result<Request, ParseError> {
    let start = Instant::now();
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let mut parsed: Option<(Request, usize, usize)> = None; // (request, header end, body length)
    loop {
        if parsed.is_none()
            && let Some(end) = find_header_end(&buf)
        {
            let (req, body_len) = parse_head(&buf[..end])?;
            parsed = Some((req, end, body_len));
        }
        if let Some((_, end, body_len)) = &parsed
            && buf.len() >= end + body_len
        {
            let (mut req, end, body_len) = parsed.take().unwrap();
            req.body = buf[end..end + body_len].to_vec();
            return Ok(req);
        }
        if buf.len() >= MAX_REQUEST_BYTES + MAX_BODY_BYTES
            || (parsed.is_none() && buf.len() >= MAX_REQUEST_BYTES)
        {
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

/// Parses a request with any body after the headers (tests and callers
/// that already hold the whole request).
#[cfg(test)]
pub fn parse_request(raw: &[u8]) -> Result<Request, ParseError> {
    let end = find_header_end(raw).ok_or(ParseError::Malformed)?;
    let (mut req, body_len) = parse_head(&raw[..end])?;
    if raw.len() < end + body_len {
        return Err(ParseError::Malformed);
    }
    req.body = raw[end..end + body_len].to_vec();
    Ok(req)
}

/// The request line and headers; returns the request and how many body
/// bytes follow.
fn parse_head(head: &[u8]) -> Result<(Request, usize), ParseError> {
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
        "POST" => Method::Post,
        _ => return Err(ParseError::MethodNotAllowed),
    };

    let mut headers = Vec::new();
    let mut content_length: Option<usize> = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if headers.len() >= MAX_HEADERS {
            return Err(ParseError::TooLarge);
        }
        let (name, value) = line.split_once(':').ok_or(ParseError::Malformed)?;
        if name.is_empty() || name.contains(' ') || name.contains('\t') {
            return Err(ParseError::Malformed);
        }
        let name = name.to_ascii_lowercase();
        let value = value.trim().to_string();
        match name.as_str() {
            "content-length" => {
                if content_length.is_some() {
                    return Err(ParseError::Malformed);
                }
                content_length = Some(value.parse().map_err(|_| ParseError::Malformed)?);
            }
            "transfer-encoding" => return Err(ParseError::BodyNotAllowed),
            _ => {}
        }
        headers.push((name, value));
    }

    let body_len = match (method, content_length) {
        (Method::Post, None) => return Err(ParseError::LengthRequired),
        (Method::Post, Some(n)) if n > MAX_BODY_BYTES => return Err(ParseError::TooLarge),
        (Method::Post, Some(n)) => n,
        (_, None | Some(0)) => 0,
        (_, Some(_)) => return Err(ParseError::BodyNotAllowed),
    };

    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    Ok((
        Request {
            method,
            path: path.to_string(),
            query: query.to_string(),
            headers,
            body: Vec::new(),
        },
        body_len,
    ))
}

/// The name part of a `Host` header (without the port), lower-cased; None
/// if it isn't a well-formed host.
pub fn host_name(host: &str) -> Option<String> {
    let name = if let Some(rest) = host.strip_prefix('[') {
        match rest.split_once(']') {
            Some((addr, tail)) if tail.is_empty() || tail.starts_with(':') => addr,
            _ => return None,
        }
    } else {
        match host.rsplit_once(':') {
            Some((n, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => n,
            Some(_) => return None,
            None => host,
        }
    };
    (!name.is_empty()).then(|| name.to_ascii_lowercase())
}

/// Loopback names always; `extra` (configured names and the listen
/// address) besides. A missing Host (HTTP/1.0) is allowed.
pub fn host_allowed(host: Option<&str>, extra: &[String]) -> bool {
    let Some(host) = host else { return true };
    let Some(name) = host_name(host) else {
        return false;
    };
    matches!(name.as_str(), "localhost" | "127.0.0.1" | "::1")
        || extra.iter().any(|e| e.eq_ignore_ascii_case(&name))
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
        assert_eq!(r.header("HOST"), Some("127.0.0.1:8765"));
        assert_eq!(query_param(&r.query, "since"), Some("5"));
        assert_eq!(query_param(&r.query, "limit"), Some("10"));
        assert_eq!(query_param(&r.query, "nope"), None);
    }

    #[test]
    fn get_head_post_accepted_everything_else_is_405() {
        assert_eq!(
            parse("HEAD / HTTP/1.1\r\n\r\n").unwrap().method,
            Method::Head
        );
        let post = parse("POST /x HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}").unwrap();
        assert_eq!(post.method, Method::Post);
        assert_eq!(post.body, b"{}");
        for m in ["PUT", "DELETE", "PATCH", "OPTIONS", "CONNECT", "get"] {
            let req = format!("{m} /api/v1/snapshot HTTP/1.1\r\n\r\n");
            assert_eq!(parse(&req), Err(ParseError::MethodNotAllowed), "{m}");
        }
        assert_eq!(ParseError::MethodNotAllowed.response().status, 405);
    }

    #[test]
    fn bodies_only_on_post_and_small() {
        assert_eq!(
            parse("GET / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello"),
            Err(ParseError::BodyNotAllowed)
        );
        assert_eq!(
            parse("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"),
            Err(ParseError::BodyNotAllowed)
        );
        assert_eq!(
            parse("POST / HTTP/1.1\r\n\r\n"),
            Err(ParseError::LengthRequired)
        );
        assert_eq!(
            parse(&format!(
                "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
                MAX_BODY_BYTES + 1
            )),
            Err(ParseError::TooLarge)
        );
        assert_eq!(
            parse("POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx"),
            Err(ParseError::Malformed)
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
    fn host_rules() {
        let none: Vec<String> = Vec::new();
        for ok in [
            "localhost",
            "LOCALHOST:8765",
            "127.0.0.1",
            "127.0.0.1:8765",
            "[::1]",
            "[::1]:8765",
        ] {
            assert!(host_allowed(Some(ok), &none), "{ok}");
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
            assert!(!host_allowed(Some(bad), &none), "{bad}");
        }
        assert!(host_allowed(None, &none));
        let extra = vec!["mlvpn.example.net".to_string(), "192.168.1.1".to_string()];
        assert!(host_allowed(Some("MLVPN.example.net"), &extra));
        assert!(host_allowed(Some("192.168.1.1:8765"), &extra));
        assert!(!host_allowed(Some("mlvpn.example.net.evil"), &extra));
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
