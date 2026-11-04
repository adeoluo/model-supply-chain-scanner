//! `msscan`: scan machine learning model files for code execution and unsafe content.

use clap::{Parser, Subcommand, ValueEnum};
use msscan_core::{scan_path, Options, Report, Severity, RULES};
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "msscan", version, about = "Scan ML model files before loading them")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scan files or directories.
    Scan {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        #[arg(short, long, value_enum, default_value_t = Format::Text)]
        format: Format,
        /// Exit with status 1 when a finding reaches this severity (or `none`).
        #[arg(long, default_value = "high")]
        fail_on: String,
        /// Hide findings below this severity in the output.
        #[arg(long, default_value = "low")]
        min_severity: String,
        /// Include SHA-256 digests.
        #[arg(long)]
        hash: bool,
    },
    /// List the rules.
    Rules,
}

fn severity_arg(s: &str) -> Result<Option<Severity>, String> {
    if s == "none" {
        return Ok(None);
    }
    Severity::parse(s)
        .map(Some)
        .ok_or_else(|| format!("unknown severity {s:?}"))
}

fn print_text(out: &mut impl Write, reports: &[Report], min: Severity) -> std::io::Result<()> {
    for r in reports {
        writeln!(
            out,
            "{}  [{}]  {}  risk {}",
            r.path,
            r.format,
            r.verdict.as_str().to_uppercase(),
            r.risk_score
        )?;
        if let Some(e) = &r.error {
            writeln!(out, "  error: {e}")?;
        }
        for f in r.findings.iter().filter(|f| f.severity >= min) {
            writeln!(out, "  {:<8} {:<7} {}  ({})", f.severity, f.rule, f.message, f.location)?;
        }
    }
    let n = reports.len();
    let flagged = reports
        .iter()
        .filter(|r| r.max_severity.is_some_and(|s| s >= Severity::High))
        .count();
    writeln!(out, "{n} file(s) scanned, {flagged} with high or critical findings")
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Rules => {
            for r in RULES {
                println!("{:<7} {:<9} {:<34} {}", r.id, r.severity, r.name, r.summary);
            }
            ExitCode::SUCCESS
        }
        Cmd::Scan {
            paths,
            format,
            fail_on,
            min_severity,
            hash,
        } => {
            let (fail_on, min) = match (severity_arg(&fail_on), severity_arg(&min_severity)) {
                (Ok(f), Ok(m)) => (f, m.unwrap_or(Severity::Info)),
                (Err(e), _) | (_, Err(e)) => {
                    eprintln!("msscan: {e}");
                    return ExitCode::from(2);
                }
            };
            let opts = Options {
                hash,
                ..Options::default()
            };
            let reports: Vec<Report> = paths.iter().flat_map(|p| scan_path(p, &opts)).collect();
            let mut out = std::io::stdout().lock();
            let res = match format {
                Format::Text => print_text(&mut out, &reports, min),
                Format::Json => serde_json::to_writer_pretty(&mut out, &reports)
                    .map_err(std::io::Error::other)
                    .and_then(|_| writeln!(out)),
            };
            if let Err(e) = res {
                eprintln!("msscan: {e}");
                return ExitCode::from(2);
            }
            if reports.iter().any(|r| r.error.is_some()) {
                return ExitCode::from(2);
            }
            let failed = fail_on.is_some_and(|t| reports.iter().any(|r| r.max_severity.is_some_and(|s| s >= t)));
            if failed {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
    }
}
