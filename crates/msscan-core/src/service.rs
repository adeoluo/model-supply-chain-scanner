//! HTTP service: POST a file, get a report. `/health`, `/ready` and `/metrics` for operations.
//!
//! The service only analyzes bytes it receives; it never opens paths or URLs supplied by a
//! client, so it cannot be used to read the server's files or reach other hosts.

use crate::finding::RULES;
use crate::scan::{Options, Report, scan_bytes};
use std::collections::BTreeMap;
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tiny_http::{Header, Method, Request, Response, Server};

const BUCKETS: [f64; 8] = [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0];

/// Counters exported at `/metrics` in the Prometheus text format.
#[derive(Default)]
pub struct Metrics {
    requests: BTreeMap<(String, u16), u64>,
    verdicts: BTreeMap<String, u64>,
    findings: BTreeMap<String, u64>,
    bytes: u64,
    buckets: [u64; BUCKETS.len()],
    seconds_sum: f64,
    seconds_count: u64,
}

impl Metrics {
    fn observe(&mut self, r: &Report, secs: f64, bytes: usize) {
        *self.verdicts.entry(r.verdict.as_str().to_string()).or_default() += 1;
        for f in &r.findings {
            *self.findings.entry(f.rule.clone()).or_default() += 1;
        }
        self.bytes += bytes as u64;
        for (i, b) in BUCKETS.iter().enumerate() {
            if secs <= *b {
                self.buckets[i] += 1;
            }
        }
        self.seconds_sum += secs;
        self.seconds_count += 1;
    }

    /// Render in the Prometheus exposition format.
    pub fn render(&self) -> String {
        let mut s = String::new();
        s.push_str(
            "# HELP msscan_requests_total HTTP requests by path and status.\n# TYPE msscan_requests_total counter\n",
        );
        for ((p, c), n) in &self.requests {
            s.push_str(&format!("msscan_requests_total{{path=\"{p}\",status=\"{c}\"}} {n}\n"));
        }
        s.push_str(
            "# HELP msscan_files_scanned_total Files scanned by verdict.\n# TYPE msscan_files_scanned_total counter\n",
        );
        for (v, n) in &self.verdicts {
            s.push_str(&format!("msscan_files_scanned_total{{verdict=\"{v}\"}} {n}\n"));
        }
        s.push_str("# HELP msscan_findings_total Findings by rule.\n# TYPE msscan_findings_total counter\n");
        for (r, n) in &self.findings {
            s.push_str(&format!("msscan_findings_total{{rule=\"{r}\"}} {n}\n"));
        }
        s.push_str(&format!(
            "# HELP msscan_bytes_scanned_total Bytes received for scanning.\n# TYPE msscan_bytes_scanned_total counter\nmsscan_bytes_scanned_total {}\n",
            self.bytes
        ));
        s.push_str("# HELP msscan_scan_seconds Scan latency.\n# TYPE msscan_scan_seconds histogram\n");
        for (i, b) in BUCKETS.iter().enumerate() {
            s.push_str(&format!(
                "msscan_scan_seconds_bucket{{le=\"{b}\"}} {}\n",
                self.buckets[i]
            ));
        }
        s.push_str(&format!(
            "msscan_scan_seconds_bucket{{le=\"+Inf\"}} {}\n",
            self.seconds_count
        ));
        s.push_str(&format!(
            "msscan_scan_seconds_sum {}\nmsscan_scan_seconds_count {}\n",
            self.seconds_sum, self.seconds_count
        ));
        s
    }
}

/// Service configuration.
#[derive(Debug, Clone)]
pub struct ServeConfig {
    pub addr: String,
    pub max_body: u64,
    pub threads: usize,
    pub opts: Options,
}

impl Default for ServeConfig {
    fn default() -> Self {
        ServeConfig {
            addr: "127.0.0.1:8080".into(),
            max_body: 512 << 20,
            threads: 4,
            opts: Options::default(),
        }
    }
}

fn json_header() -> Header {
    Header::from_bytes("Content-Type", "application/json").expect("static header")
}

fn query_param(url: &str, key: &str) -> Option<String> {
    let q = url.split_once('?')?.1;
    q.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        (k == key).then(|| percent_decode(v))
    })
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                if let Some(v) = std::str::from_utf8(&b[i + 1..i + 3])
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                {
                    out.push(v);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Handle one request and return (status, content type json?, body).
pub fn handle(
    method: &Method,
    url: &str,
    body: Option<&[u8]>,
    cfg: &ServeConfig,
    metrics: &Mutex<Metrics>,
) -> (u16, String) {
    let path = url.split('?').next().unwrap_or(url);
    match (method, path) {
        (Method::Get, "/health") => (200, r#"{"status":"ok"}"#.into()),
        (Method::Get, "/ready") => (200, format!(r#"{{"status":"ready","rules":{}}}"#, RULES.len())),
        (Method::Get, "/metrics") => (200, metrics.lock().expect("metrics lock").render()),
        (Method::Get, "/v1/rules") => (200, serde_json::to_string(RULES).expect("rules serialize")),
        (Method::Post, "/v1/scan") => {
            let Some(body) = body else {
                return (413, format!(r#"{{"error":"body larger than {} bytes"}}"#, cfg.max_body));
            };
            let name = query_param(url, "name").unwrap_or_else(|| "upload".into());
            let mut opts = cfg.opts;
            opts.declared_size = query_param(url, "declared_size").and_then(|s| s.parse().ok());
            let t0 = Instant::now();
            let r = scan_bytes(body, &name, &opts);
            metrics
                .lock()
                .expect("metrics lock")
                .observe(&r, t0.elapsed().as_secs_f64(), body.len());
            (200, serde_json::to_string(&r).expect("report serializes"))
        }
        (_, "/health" | "/ready" | "/metrics" | "/v1/rules" | "/v1/scan") => {
            (405, r#"{"error":"method not allowed"}"#.into())
        }
        _ => (404, r#"{"error":"not found"}"#.into()),
    }
}

fn respond(mut req: Request, cfg: &ServeConfig, metrics: &Mutex<Metrics>) {
    let method = req.method().clone();
    let url = req.url().to_string();
    let declared = req.body_length().map(|n| n as u64);
    let body = if method == Method::Post {
        if declared.is_some_and(|n| n > cfg.max_body) {
            None
        } else {
            let mut buf = Vec::new();
            let ok = req.as_reader().take(cfg.max_body + 1).read_to_end(&mut buf).is_ok();
            (ok && buf.len() as u64 <= cfg.max_body).then_some(buf)
        }
    } else {
        Some(Vec::new())
    };
    let (status, text) = handle(&method, &url, body.as_deref(), cfg, metrics);
    let path = url.split('?').next().unwrap_or("").to_string();
    let known = matches!(
        path.as_str(),
        "/health" | "/ready" | "/metrics" | "/v1/rules" | "/v1/scan"
    );
    *metrics
        .lock()
        .expect("metrics lock")
        .requests
        .entry((if known { path.clone() } else { "other".into() }, status))
        .or_default() += 1;
    let mut resp = Response::from_string(text).with_status_code(status);
    if path != "/metrics" {
        resp = resp.with_header(json_header());
    }
    let _ = req.respond(resp);
}

/// Bind and serve until the process exits.
pub fn serve(cfg: ServeConfig) -> std::io::Result<()> {
    let server = Arc::new(Server::http(&cfg.addr).map_err(std::io::Error::other)?);
    let metrics = Arc::new(Mutex::new(Metrics::default()));
    let cfg = Arc::new(cfg);
    let mut handles = Vec::new();
    for _ in 0..cfg.threads.max(1) {
        let (server, metrics, cfg) = (server.clone(), metrics.clone(), cfg.clone());
        handles.push(std::thread::spawn(move || {
            for req in server.incoming_requests() {
                respond(req, &cfg, &metrics);
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes() {
        let cfg = ServeConfig::default();
        let m = Mutex::new(Metrics::default());
        assert_eq!(handle(&Method::Get, "/health", None, &cfg, &m).0, 200);
        assert!(handle(&Method::Get, "/ready", None, &cfg, &m).1.contains("ready"));
        assert!(handle(&Method::Get, "/v1/rules", None, &cfg, &m).1.contains("MS101"));
        assert_eq!(handle(&Method::Get, "/nope", None, &cfg, &m).0, 404);
        assert_eq!(handle(&Method::Get, "/v1/scan", None, &cfg, &m).0, 405);
        assert_eq!(handle(&Method::Post, "/v1/scan", None, &cfg, &m).0, 413);
        let (s, body) = handle(
            &Method::Post,
            "/v1/scan?name=a%2Fm.pkl&declared_size=99",
            Some(b"\x80\x02cos\ngetcwd\n)R."),
            &cfg,
            &m,
        );
        assert_eq!(s, 200);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["verdict"], "malicious");
        assert_eq!(v["path"], "a/m.pkl");
        assert_eq!(v["size"], 99);
        let metrics = handle(&Method::Get, "/metrics", None, &cfg, &m).1;
        assert!(metrics.contains("msscan_files_scanned_total{verdict=\"malicious\"} 1"));
        assert!(metrics.contains("msscan_findings_total{rule=\"MS101\"} 1"));
        assert!(metrics.contains("msscan_scan_seconds_count 1"));
    }

    #[test]
    fn decoding() {
        assert_eq!(percent_decode("a%20b+c%zz%4"), "a b c%zz%4");
        assert_eq!(query_param("/x?a=1&b=2", "b").as_deref(), Some("2"));
        assert_eq!(query_param("/x?a", "a").as_deref(), Some(""));
        assert_eq!(query_param("/x", "a"), None);
    }

    #[test]
    fn end_to_end_over_tcp() {
        use std::io::Write;
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let cfg = ServeConfig {
            addr: format!("127.0.0.1:{port}"),
            max_body: 64,
            threads: 1,
            opts: Options::default(),
        };
        std::thread::spawn(move || serve(cfg));
        let send = |req: &[u8]| -> String {
            for _ in 0..50 {
                if let Ok(mut s) = std::net::TcpStream::connect(("127.0.0.1", port)) {
                    s.write_all(req).unwrap();
                    let mut out = String::new();
                    let _ = s.read_to_string(&mut out);
                    return out;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            panic!("server did not start");
        };
        let ok = send(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
        let body = b"\x80\x02cos\ngetcwd\n)R.";
        let mut req = format!(
            "POST /v1/scan?name=m.pkl HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        req.extend_from_slice(body);
        assert!(send(&req).contains("\"malicious\""));
        let big = format!(
            "POST /v1/scan HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: 100\r\n\r\n{}",
            "x".repeat(100)
        );
        assert!(send(big.as_bytes()).starts_with("HTTP/1.1 413"));
        let m = send(b"GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        assert!(
            m.contains("msscan_requests_total{path=\"/v1/scan\",status=\"413\"} 1"),
            "{m}"
        );
    }
}
