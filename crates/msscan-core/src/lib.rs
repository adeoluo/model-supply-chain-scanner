//! Static analysis of machine learning model files.
//!
//! [`scan_bytes`], [`scan_file`] and [`scan_path`] detect the format of each file by content,
//! run the matching analyzer and return a [`Report`] with findings, a verdict and a risk score.
//! Nothing in a scanned file is ever imported, deserialized into live objects or executed.

pub mod compress;
pub mod finding;
pub mod formats;
pub mod gguf;
pub mod hfjson;
pub mod jinja;
pub mod keras;
pub mod numpy;
pub mod onnx;
pub mod pickle;
pub mod protobuf;
pub mod report;
pub mod safetensors;
pub mod savedmodel;
pub mod scan;
pub mod service;
pub mod zip;

pub use finding::{Finding, RULES, Rule, Severity};
pub use scan::{Options, Report, Verdict, scan_bytes, scan_file, scan_path};
