//! Format detection and the scan entry points.

use crate::compress;
use crate::finding::{ids, Finding, Severity};
use crate::numpy;
use crate::pickle::{self, Limits, Tier};
use crate::zip;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Scan options.
#[derive(Debug, Clone, Copy)]
pub struct Options {
    pub limits: Limits,
    /// Largest decompressed size accepted for one archive entry or compressed stream.
    pub max_decompressed: u64,
    /// How deep archives, compressed streams and nested files are followed.
    pub max_depth: u8,
    /// Compute the SHA-256 of each file.
    pub hash: bool,
    /// The real size of the file when only a prefix was supplied (headers-only scanning).
    pub declared_size: Option<u64>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            limits: Limits::default(),
            max_decompressed: 1 << 30,
            max_depth: 4,
            hash: false,
            declared_size: None,
        }
    }
}

/// A global imported by a pickle somewhere in the file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ImportRecord {
    pub module: String,
    pub name: String,
    pub tier: Tier,
    pub count: u32,
    pub called: bool,
    /// Archive member (or the file itself) holding the pickle.
    pub member: String,
}

/// Counters describing what was analyzed.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Stats {
    pub pickles: u64,
    pub opcodes: u64,
    pub archive_entries: u64,
    pub members_scanned: u64,
    pub joblib_arrays: u64,
    /// Set when only a prefix of the file was supplied and the header continues past it.
    #[serde(default)]
    pub prefix_incomplete: bool,
}

/// The scan result for one file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub path: String,
    pub format: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    pub verdict: Verdict,
    pub risk_score: u32,
    pub max_severity: Option<Severity>,
    pub findings: Vec<Finding>,
    pub imports: Vec<ImportRecord>,
    pub stats: Stats,
    pub elapsed_us: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Clean,
    Suspicious,
    Unsafe,
    Malicious,
    Error,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Clean => "clean",
            Verdict::Suspicious => "suspicious",
            Verdict::Unsafe => "unsafe",
            Verdict::Malicious => "malicious",
            Verdict::Error => "error",
        }
    }

    pub fn from_severity(s: Option<Severity>) -> Verdict {
        match s {
            Some(Severity::Critical) => Verdict::Malicious,
            Some(Severity::High) => Verdict::Unsafe,
            Some(Severity::Medium) => Verdict::Suspicious,
            _ => Verdict::Clean,
        }
    }
}

/// Noisy-or of finding weights, as an integer from 0 to 100.
pub fn risk_score(findings: &[Finding]) -> u32 {
    let keep: f64 = findings.iter().map(|f| 1.0 - f.severity.weight()).product();
    ((1.0 - keep) * 100.0).round() as u32
}

/// Accumulates findings while walking nested content.
pub(crate) struct Ctx {
    pub opts: Options,
    pub findings: Vec<Finding>,
    pub imports: Vec<ImportRecord>,
    pub stats: Stats,
}

impl Ctx {
    pub fn new(opts: Options) -> Self {
        Ctx {
            opts,
            findings: Vec::new(),
            imports: Vec::new(),
            stats: Stats::default(),
        }
    }

    pub fn pickle(&mut self, data: &[u8], member: &str) -> pickle::PickleReport {
        let r = pickle::analyze(data, member, self.opts.limits);
        self.stats.pickles += r.pickles as u64;
        self.stats.opcodes += r.opcodes;
        self.stats.joblib_arrays += r.joblib_arrays;
        self.findings.extend(r.findings.iter().cloned());
        for i in &r.imports {
            self.imports.push(ImportRecord {
                module: i.module.clone(),
                name: i.name.clone(),
                tier: i.tier,
                count: i.count,
                called: i.called,
                member: member.to_string(),
            });
        }
        r
    }
}

/// File extensions and the format they promise.
fn expected_format(name: &str) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase();
    let ext = lower.rsplit('.').next().unwrap_or("");
    Some(match ext {
        "safetensors" => "safetensors",
        "pb" => "savedmodel",
        "gguf" => "gguf",
        "npy" => "numpy",
        "npz" => "zip",
        "h5" | "hdf5" => "hdf5",
        "pkl" | "pickle" => "pickle",
        "keras" => "zip",
        "onnx" => "onnx",
        "json" => "json",
        _ => return None,
    })
}

fn family(format: &str) -> &str {
    match format {
        "pytorch" | "npz" | "keras" | "zip" | "torchscript" => "zip",
        "numpy" => "numpy",
        "keras-h5" | "hdf5" => "hdf5",
        "keras-metadata" => "savedmodel",
        f if f.starts_with("pickle") || f == "joblib" || f == "pytorch-legacy" => "pickle",
        f => f,
    }
}

/// Scan one in-memory buffer at `depth`, returning the detected format name.
pub(crate) fn scan_buffer(ctx: &mut Ctx, data: &[u8], member: &str, depth: u8) -> String {
    ctx.stats.members_scanned += 1;
    if depth > ctx.opts.max_depth {
        ctx.findings.push(Finding::new(
            ids::ARCHIVE_MALFORMED,
            "nesting deeper than the configured limit; not scanned",
            member,
        ));
        return "nested".into();
    }
    let format = crate::formats::dispatch(ctx, data, member, depth);
    if depth == 0 {
        if let Some(want) = expected_format(member) {
            let got = family(&format);
            let compressed_pickle = want == "pickle" && format.contains('+');
            if want != got && format != "unknown" && !(want == "json" && got == "hf-config") && !compressed_pickle {
                ctx.findings.push(Finding::new(
                    ids::FORMAT_MISMATCH,
                    format!("the name suggests {want} but the content is {format}"),
                    member,
                ));
            }
        }
    }
    format
}

/// Scan a pickle-family buffer: plain pickle, legacy PyTorch, or joblib.
pub(crate) fn scan_pickle(ctx: &mut Ctx, data: &[u8], member: &str) -> String {
    let r = ctx.pickle(data, member);
    if r.legacy_torch {
        "pytorch-legacy".into()
    } else if r.joblib_arrays > 0 {
        "joblib".into()
    } else {
        "pickle".into()
    }
}

pub(crate) fn scan_compressed(ctx: &mut Ctx, codec: compress::Codec, data: &[u8], member: &str, depth: u8) -> String {
    match compress::decompress(codec, data, ctx.opts.max_decompressed) {
        Ok(inner) => {
            let f = scan_buffer(ctx, &inner, &format!("{member}>{}", codec.name()), depth + 1);
            format!("{}+{f}", codec.name())
        }
        Err(compress::Error::TooLarge(l)) => {
            ctx.findings.push(Finding::new(
                ids::ARCHIVE_BOMB,
                format!("{} stream decompresses past {l} bytes", codec.name()),
                member,
            ));
            codec.name().into()
        }
        Err(e) => {
            ctx.findings.push(Finding::new(
                ids::ARCHIVE_MALFORMED,
                format!("{} stream: {e:?}", codec.name()),
                member,
            ));
            codec.name().into()
        }
    }
}

pub(crate) fn scan_npy(ctx: &mut Ctx, data: &[u8], member: &str) -> String {
    let c = numpy::check(data, member);
    ctx.findings.extend(c.findings);
    if let Some(off) = c.pickle_offset {
        ctx.pickle(&data[off..], &format!("{member}@{off}"));
    }
    "numpy".into()
}

/// Scan a zip archive: classify it (PyTorch, TorchScript, NumPy npz, Keras) and scan members.
pub(crate) fn scan_zip(ctx: &mut Ctx, data: &[u8], member: &str, depth: u8) -> String {
    let a = zip::read(data, member);
    ctx.findings.extend(a.findings.iter().cloned());
    ctx.stats.archive_entries += a.entries.len() as u64;
    let names: Vec<&str> = a.entries.iter().map(|e| e.name.as_str()).collect();
    let is_torch = names
        .iter()
        .any(|n| n.ends_with("data.pkl") || n.ends_with("/version") || n == &"version");
    let is_script = names.iter().any(|n| n.contains("/code/") || n.starts_with("code/"))
        && names.iter().any(|n| n.ends_with("constants.pkl"));
    let is_keras = names.contains(&"config.json")
        && names
            .iter()
            .any(|n| n.ends_with(".weights.h5") || *n == "metadata.json");
    let is_npz = !names.is_empty() && names.iter().all(|n| n.ends_with(".npy") || n.ends_with('/'));
    let format = if is_script {
        "torchscript"
    } else if is_torch {
        "pytorch"
    } else if is_keras {
        "keras"
    } else if is_npz {
        "npz"
    } else {
        "zip"
    };
    if is_script {
        let n = names
            .iter()
            .filter(|n| n.contains("code/") && n.ends_with(".py"))
            .count();
        ctx.findings.push(Finding::new(
            ids::TORCH_SCRIPT,
            format!("{n} TorchScript code file(s)"),
            member,
        ));
    }
    let size_limit = ctx.opts.max_decompressed;
    for e in &a.entries {
        if e.is_dir() {
            continue;
        }
        // An "encrypted" stored entry that is really plaintext is still read by loaders that
        // ignore the flag (PyTorch does), so scan it when its bytes parse.
        let plain;
        let e = if e.encrypted() {
            if e.method != 0 {
                continue;
            }
            plain = zip::Entry {
                flags: e.flags & !1,
                ..e.clone()
            };
            &plain
        } else {
            e
        };
        let sub = format!("{member}/{}", e.name);
        let lname = e.name.to_ascii_lowercase();
        // PyTorch tensor storages are raw numbers: never interpret them as code.
        if (format == "pytorch" || format == "torchscript")
            && (lname.contains("/data/") || lname.starts_with("data/"))
            && !lname.ends_with(".pkl")
        {
            continue;
        }
        if e.size > size_limit {
            ctx.findings.push(Finding::new(
                ids::ARCHIVE_BOMB,
                format!("entry {:?} declares {} bytes", e.name, e.size),
                &sub,
            ));
            continue;
        }
        let body = match zip::extract(data, e, size_limit) {
            Ok(b) => b,
            Err(zip::ExtractError::TooLarge(l)) => {
                ctx.findings.push(Finding::new(
                    ids::ARCHIVE_BOMB,
                    format!("entry {:?} inflates past {l} bytes", e.name),
                    &sub,
                ));
                continue;
            }
            Err(err) => {
                ctx.findings.push(Finding::new(
                    ids::ARCHIVE_MALFORMED,
                    format!("entry {:?}: {err:?}", e.name),
                    &sub,
                ));
                continue;
            }
        };
        if e.method == 8
            && e.compressed_size > 0
            && body.len() as u64 / e.compressed_size.max(1) > 1000
            && body.len() > (64 << 20)
        {
            ctx.findings.push(Finding::new(
                ids::ARCHIVE_BOMB,
                format!("entry {:?} has a compression ratio above 1000", e.name),
                &sub,
            ));
        }
        if format == "keras" && lname == "config.json" {
            ctx.stats.members_scanned += 1;
            ctx.findings.extend(crate::keras::check_config_json(&body, &sub));
            continue;
        }
        if lname.ends_with(".pkl") || lname.ends_with(".pickle") {
            ctx.stats.members_scanned += 1;
            ctx.pickle(&body, &sub);
            continue;
        }
        scan_member(ctx, &body, &sub, depth + 1);
    }
    format.into()
}

/// Scan an archive member: only formats recognized by content, so raw data stays quiet.
fn scan_member(ctx: &mut Ctx, data: &[u8], member: &str, depth: u8) {
    if crate::formats::sniff(data, member).is_some() || pickle::is_pickle(data) && strict_pickle(data, ctx) {
        scan_buffer(ctx, data, member, depth);
    }
}

fn strict_pickle(data: &[u8], ctx: &Ctx) -> bool {
    let r = pickle::analyze(data, "", ctx.opts.limits);
    r.pickles > 0 && !r.findings.iter().any(|f| f.rule == ids::PICKLE_MALFORMED)
}

fn sha256_hex(data: &[u8]) -> String {
    let d = Sha256::digest(data);
    d.iter().map(|b| format!("{b:02x}")).collect()
}

fn finish(path: &str, data: &[u8], size: u64, mut ctx: Ctx, format: String, t0: Instant) -> Report {
    ctx.findings
        .sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.rule.cmp(&b.rule)));
    let max = ctx.findings.iter().map(|f| f.severity).max();
    Report {
        path: path.to_string(),
        format,
        size,
        sha256: if ctx.opts.hash { Some(sha256_hex(data)) } else { None },
        verdict: Verdict::from_severity(max),
        risk_score: risk_score(&ctx.findings),
        max_severity: max,
        findings: ctx.findings,
        imports: ctx.imports,
        stats: ctx.stats,
        elapsed_us: t0.elapsed().as_micros() as u64,
        error: None,
    }
}

/// Scan bytes held in memory; `name` is used for locations and extension checks.
pub fn scan_bytes(data: &[u8], name: &str, opts: &Options) -> Report {
    let t0 = Instant::now();
    let mut ctx = Ctx::new(*opts);
    let format = scan_buffer(&mut ctx, data, name, 0);
    let size = opts.declared_size.unwrap_or(data.len() as u64);
    finish(name, data, size, ctx, format, t0)
}

fn error_report(path: &str, err: String) -> Report {
    Report {
        path: path.to_string(),
        format: "unknown".into(),
        size: 0,
        sha256: None,
        verdict: Verdict::Error,
        risk_score: 0,
        max_severity: None,
        findings: Vec::new(),
        imports: Vec::new(),
        stats: Stats::default(),
        elapsed_us: 0,
        error: Some(err),
    }
}

/// Scan one file, memory-mapped so that large files are read only where needed.
pub fn scan_file(path: &Path, opts: &Options) -> Report {
    let name = path.to_string_lossy().to_string();
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => return error_report(&name, e.to_string()),
    };
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    if len == 0 {
        return scan_bytes(&[], &name, opts);
    }
    // SAFETY: the map is read-only and dropped before returning; a concurrent truncation by
    // another process could fault, which is the documented trade-off of mapping files.
    let map = match unsafe { memmap2::Mmap::map(&file) } {
        Ok(m) => m,
        Err(e) => return error_report(&name, e.to_string()),
    };
    scan_bytes(&map, &name, opts)
}

/// Every regular file under `root` (or `root` itself), sorted, skipping hidden directories.
pub fn collect_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(p) = stack.pop() {
        let Ok(meta) = std::fs::symlink_metadata(&p) else {
            continue;
        };
        if meta.is_dir() {
            if p != root && p.file_name().is_some_and(|n| n.to_string_lossy().starts_with('.')) {
                continue;
            }
            if let Ok(rd) = std::fs::read_dir(&p) {
                stack.extend(rd.flatten().map(|e| e.path()));
            }
        } else if meta.is_file() {
            out.push(p);
        }
    }
    out.sort();
    out
}

/// Scan a file or a directory tree in parallel.
pub fn scan_path(root: &Path, opts: &Options) -> Vec<Report> {
    use rayon::prelude::*;
    if !root.exists() {
        return vec![error_report(
            &root.to_string_lossy(),
            "no such file or directory".into(),
        )];
    }
    collect_files(root).par_iter().map(|p| scan_file(p, opts)).collect()
}

#[cfg(test)]
mod tests;
