//! `msscan`: scan machine learning model files for code execution and unsafe content.

use clap::{Parser, Subcommand, ValueEnum};
use msscan_core::report;
use msscan_core::service::{serve, ServeConfig};
use msscan_core::{scan_path, Options, Report, Severity, RULES};
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "msscan",
    version,
    about = "Scan machine learning model files before loading them"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
    Sarif,
}

#[derive(Clone, Copy, ValueEnum)]
enum RulesFormat {
    Text,
    Json,
    Markdown,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scan files or directories (formats are detected by content).
    Scan {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        #[arg(short, long, value_enum, default_value_t = Format::Text)]
        format: Format,
        /// Write the report to a file instead of standard output.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Exit with status 1 when a finding reaches this severity (`none` never fails).
        #[arg(long, default_value = "high")]
        fail_on: String,
        /// Leave findings below this severity out of the report.
        #[arg(long, default_value = "low")]
        min_severity: String,
        /// Include the SHA-256 of each file.
        #[arg(long)]
        hash: bool,
        /// Largest decompressed size accepted for one archive member or stream, in bytes.
        #[arg(long, default_value_t = 1 << 30)]
        max_decompressed: u64,
    },
    /// List the rules.
    Rules {
        #[arg(short, long, value_enum, default_value_t = RulesFormat::Text)]
        format: RulesFormat,
    },
    /// Run the HTTP service (POST /v1/scan, /health, /ready, /metrics).
    Serve {
        #[arg(long, default_value = "127.0.0.1:8080")]
        addr: String,
        /// Largest accepted request body in bytes.
        #[arg(long, default_value_t = 512 << 20)]
        max_body: u64,
        #[arg(long, default_value_t = 4)]
        threads: usize,
    },
}

fn severity_arg(s: &str) -> Result<Option<Severity>, String> {
    if s == "none" {
        return Ok(None);
    }
    Severity::parse(s)
        .map(Some)
        .ok_or_else(|| format!("unknown severity {s:?} (use info, low, medium, high, critical or none)"))
}

fn render(format: Format, reports: &[Report], min: Severity) -> String {
    match format {
        Format::Text => report::text(reports, min),
        Format::Json => {
            let filtered: Vec<Report> = reports
                .iter()
                .cloned()
                .map(|mut r| {
                    r.findings.retain(|f| f.severity >= min);
                    r
                })
                .collect();
            serde_json::to_string_pretty(&filtered).expect("reports serialize") + "\n"
        }
        Format::Sarif => {
            serde_json::to_string_pretty(&report::sarif(reports, env!("CARGO_PKG_VERSION"), min)).expect("sarif") + "\n"
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Rules { format } => {
            let out = match format {
                RulesFormat::Text => RULES
                    .iter()
                    .map(|r| format!("{:<7} {:<9} {:<32} {}\n", r.id, r.severity.as_str(), r.name, r.summary))
                    .collect(),
                RulesFormat::Json => serde_json::to_string_pretty(RULES).expect("rules") + "\n",
                RulesFormat::Markdown => report::rules_markdown(),
            };
            print!("{out}");
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Serve {
            addr,
            max_body,
            threads,
        } => {
            eprintln!("msscan {} listening on http://{addr}", env!("CARGO_PKG_VERSION"));
            serve(ServeConfig {
                addr,
                max_body,
                threads,
                opts: Options::default(),
            })
            .map_err(|e| e.to_string())?;
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Scan {
            paths,
            format,
            output,
            fail_on,
            min_severity,
            hash,
            max_decompressed,
        } => {
            let fail_on = severity_arg(&fail_on)?;
            let min = severity_arg(&min_severity)?.unwrap_or(Severity::Info);
            let opts = Options {
                hash,
                max_decompressed,
                ..Options::default()
            };
            let reports: Vec<Report> = paths.iter().flat_map(|p| scan_path(p, &opts)).collect();
            let text = render(format, &reports, min);
            match output {
                Some(p) => std::fs::write(&p, text).map_err(|e| format!("{}: {e}", p.display()))?,
                None => std::io::stdout()
                    .lock()
                    .write_all(text.as_bytes())
                    .map_err(|e| e.to_string())?,
            }
            if reports.iter().any(|r| r.error.is_some()) {
                return Ok(ExitCode::from(2));
            }
            let failed = fail_on.is_some_and(|t| reports.iter().any(|r| r.max_severity.is_some_and(|s| s >= t)));
            Ok(if failed { ExitCode::from(1) } else { ExitCode::SUCCESS })
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("msscan: {e}");
            ExitCode::from(2)
        }
    }
}
