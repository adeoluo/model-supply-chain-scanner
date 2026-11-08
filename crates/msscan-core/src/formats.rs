//! Content sniffing and dispatch to the format analyzers.

use crate::compress;
use crate::finding::{Finding, ids};
use crate::scan::{self, Ctx};
use crate::{gguf, hfjson, keras, numpy, onnx, pickle, safetensors, savedmodel, zip};

fn base_name(name: &str) -> String {
    name.rsplit(['/', '\\']).next().unwrap_or(name).to_ascii_lowercase()
}

/// Recognize a format from magic bytes or unambiguous structure (pickles are recognized
/// separately because protocol 0 has no header).
pub fn sniff(data: &[u8], name: &str) -> Option<&'static str> {
    let base = base_name(name);
    if zip::is_zip(data) {
        Some("zip")
    } else if numpy::is_npy(data) {
        Some("numpy")
    } else if gguf::is_gguf(data) {
        Some("gguf")
    } else if keras::is_hdf5(data) {
        Some("hdf5")
    } else if safetensors::is_safetensors(data) {
        Some("safetensors")
    } else if compress::detect(data).is_some() {
        Some("compressed")
    } else if base == "saved_model.pb" || savedmodel::looks_like_saved_model(data) && savedmodel::ops(data).is_ok() {
        Some("savedmodel")
    } else if base == "keras_metadata.pb" {
        Some("keras-metadata")
    } else if base.ends_with(".onnx") || onnx::looks_like_onnx(data) && onnx::parse(data).is_ok() {
        Some("onnx")
    } else if hfjson::looks_like_json(data) {
        Some("json")
    } else {
        None
    }
}

/// Detect the format of `data` and run the matching analyzer.
pub(crate) fn dispatch(ctx: &mut Ctx, data: &[u8], member: &str, depth: u8) -> String {
    let total = if depth == 0 {
        ctx.opts.declared_size.unwrap_or(data.len() as u64)
    } else {
        data.len() as u64
    };
    match sniff(data, member) {
        Some("zip") => scan::scan_zip(ctx, data, member, depth),
        Some("numpy") => scan::scan_npy(ctx, data, member),
        Some("compressed") => {
            let codec = compress::detect(data).expect("sniffed");
            scan::scan_compressed(ctx, codec, data, member, depth)
        }
        Some("gguf") => {
            let (f, info) = gguf::check(data, total, member);
            ctx.findings.extend(f);
            ctx.stats.prefix_incomplete |= info.partial;
            "gguf".into()
        }
        Some("safetensors") => {
            let (f, info) = safetensors::check(data, total, member);
            ctx.findings.extend(f);
            ctx.stats.prefix_incomplete |= info.partial;
            "safetensors".into()
        }
        Some("hdf5") => {
            let (f, n) = keras::check_embedded(data, member);
            ctx.findings.extend(f);
            if n > 0 { "keras-h5" } else { "hdf5" }.into()
        }
        Some("savedmodel") => {
            let (f, _) = savedmodel::check(data, member);
            ctx.findings.extend(f);
            // SavedModels written by Keras 2 can also embed layer configs.
            ctx.findings.extend(
                keras::check_embedded(data, member)
                    .0
                    .into_iter()
                    .filter(|f| f.rule != ids::KERAS_MALFORMED),
            );
            "savedmodel".into()
        }
        Some("keras-metadata") => {
            ctx.findings.extend(keras::check_embedded(data, member).0);
            "keras-metadata".into()
        }
        Some("onnx") => {
            let (f, _) = onnx::check(data, member);
            ctx.findings.extend(f);
            "onnx".into()
        }
        Some("json") => {
            let f = hfjson::check(data, member);
            let fmt = if f.iter().any(|x| x.rule == ids::HF_REMOTE_CODE) || base_name(member).ends_with("config.json") {
                "hf-config"
            } else {
                "json"
            };
            ctx.findings.extend(f);
            fmt.into()
        }
        _ if pickle::is_pickle(data) => scan::scan_pickle(ctx, data, member),
        // A file named .safetensors that does not even look like one: report why.
        _ if base_name(member).ends_with(".safetensors") => {
            let (f, _) = safetensors::check(data, total, member);
            ctx.findings.extend(f);
            "safetensors".into()
        }
        _ => {
            ctx.findings
                .push(Finding::new(ids::FORMAT_UNKNOWN, "format not recognized", member));
            "unknown".into()
        }
    }
}
