//! Python bindings: `msscan.msscan_rs`. Reports cross the boundary as JSON text, which the
//! Python layer turns into dataclasses.

use msscan_core::report;
use msscan_core::service::{ServeConfig, serve as run_service};
use msscan_core::{Options, RULES, Severity, scan_bytes as core_scan_bytes, scan_path as core_scan_path};
use pyo3::exceptions::{PyOSError, PyValueError};
use pyo3::prelude::*;
use std::path::PathBuf;

fn options(hash: bool, max_decompressed: u64, declared_size: Option<u64>) -> Options {
    Options {
        hash,
        max_decompressed,
        declared_size,
        ..Options::default()
    }
}

fn severity(s: &str) -> PyResult<Severity> {
    Severity::parse(s).ok_or_else(|| PyValueError::new_err(format!("unknown severity {s:?}")))
}

/// Scan a file or directory and render the reports as `json`, `sarif` or `text`.
#[pyfunction]
#[pyo3(signature = (path, hash=false, max_decompressed=1 << 30, output="json", min_severity="info"))]
fn scan_path(
    py: Python<'_>,
    path: PathBuf,
    hash: bool,
    max_decompressed: u64,
    output: &str,
    min_severity: &str,
) -> PyResult<String> {
    let min = severity(min_severity)?;
    if !matches!(output, "json" | "sarif" | "text") {
        return Err(PyValueError::new_err(format!("unknown output {output:?}")));
    }
    let opts = options(hash, max_decompressed, None);
    let output = output.to_string();
    Ok(py.detach(move || {
        let reports = core_scan_path(&path, &opts);
        match output.as_str() {
            "sarif" => serde_json::to_string(&report::sarif(&reports, env!("CARGO_PKG_VERSION"), min)).expect("sarif"),
            "text" => report::text(&reports, min),
            _ => serde_json::to_string(&reports).expect("reports serialize"),
        }
    }))
}

/// Scan bytes; `declared_size` is the real file size when only a prefix is passed.
#[pyfunction]
#[pyo3(signature = (data, name="<bytes>", hash=false, max_decompressed=1 << 30, declared_size=None))]
fn scan_bytes(
    py: Python<'_>,
    data: Vec<u8>,
    name: &str,
    hash: bool,
    max_decompressed: u64,
    declared_size: Option<u64>,
) -> String {
    let opts = options(hash, max_decompressed, declared_size);
    let name = name.to_string();
    py.detach(move || serde_json::to_string(&core_scan_bytes(&data, &name, &opts)).expect("report serializes"))
}

/// Render a JSON array of reports (as returned by `scan_path`) as `json`, `sarif` or `text`.
#[pyfunction]
#[pyo3(signature = (reports_json, output="text", min_severity="low"))]
fn render(reports_json: &str, output: &str, min_severity: &str) -> PyResult<String> {
    let min = severity(min_severity)?;
    let mut reports: Vec<msscan_core::Report> =
        serde_json::from_str(reports_json).map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(match output {
        "sarif" => {
            serde_json::to_string_pretty(&report::sarif(&reports, env!("CARGO_PKG_VERSION"), min)).expect("sarif")
                + "\n"
        }
        "text" => report::text(&reports, min),
        "json" => {
            for r in &mut reports {
                r.findings.retain(|f| f.severity >= min);
            }
            serde_json::to_string_pretty(&reports).expect("reports serialize") + "\n"
        }
        o => return Err(PyValueError::new_err(format!("unknown output {o:?}"))),
    })
}

/// The rule catalog as JSON.
#[pyfunction]
fn rules() -> String {
    serde_json::to_string(RULES).expect("rules serialize")
}

/// The rule catalog as Markdown.
#[pyfunction]
fn rules_markdown() -> String {
    report::rules_markdown()
}

/// Run the HTTP service until the process is stopped.
#[pyfunction]
#[pyo3(signature = (addr="127.0.0.1:8080", max_body=512 << 20, threads=4))]
fn serve(py: Python<'_>, addr: &str, max_body: u64, threads: usize) -> PyResult<()> {
    let addr = addr.to_string();
    let cfg = ServeConfig {
        addr,
        max_body,
        threads,
        opts: Options::default(),
    };
    py.detach(move || run_service(cfg))
        .map_err(|e| PyOSError::new_err(e.to_string()))
}

#[pymodule]
fn msscan_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(scan_path, m)?)?;
    m.add_function(wrap_pyfunction!(scan_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(render, m)?)?;
    m.add_function(wrap_pyfunction!(rules, m)?)?;
    m.add_function(wrap_pyfunction!(rules_markdown, m)?)?;
    m.add_function(wrap_pyfunction!(serve, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
