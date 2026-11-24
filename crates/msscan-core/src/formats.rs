//! Content sniffing and dispatch to the format analyzers.

use crate::compress;
use crate::finding::{Finding, ids};
use crate::scan::{self, Ctx};
use crate::{archive, gguf, hfjson, keras, numpy, onnx, pickle, safetensors, savedmodel, textcfg, zip};

fn base_name(name: &str) -> String {
    name.rsplit(['/', '\\']).next().unwrap_or(name).to_ascii_lowercase()
}

/// Recognize a format from magic bytes or unambiguous structure (pickles are recognized
/// separately because protocol 0 has no header).
pub fn sniff(data: &[u8], name: &str) -> Option<&'static str> {
    let base = base_name(name);
    if is_appledouble(data) {
        Some("appledouble")
    } else if zip::is_zip(data) {
        Some("zip")
    } else if archive::is_7z(data) {
        Some("7z")
    } else if archive::is_rar(data) {
        Some("rar")
    } else if archive::is_tar(data) {
        Some("tar")
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
    } else if textcfg::is_template_name(name) && textcfg::looks_like_text(data) && !pickle::is_pickle(data) {
        Some("template")
    } else if textcfg::is_yaml_name(name) && textcfg::looks_like_text(data) && !pickle::is_pickle(data) {
        Some("yaml")
    } else {
        None
    }
}

/// The AppleDouble file macOS writes next to a file on foreign volumes (`._name`): resource
/// fork metadata that takes the name and extension of the real file.
pub fn is_appledouble(data: &[u8]) -> bool {
    data.starts_with(&[0x00, 0x05, 0x16, 0x07])
}

/// Top-level directories that a link out of a model repository has no reason to reach.
const SYSTEM_ROOTS: &[&str] = &[
    "etc",
    "proc",
    "root",
    "home",
    "usr",
    "var",
    "sys",
    "dev",
    "tmp",
    "run",
    "boot",
    "bin",
    "sbin",
    "opt",
    "mnt",
    "private",
    "Users",
    "Windows",
    "ProgramData",
];

/// A symbolic link stored as a file, which is what a hub serves for a link committed to a
/// repository: the whole content is one path, absolute or climbing with `../`, that lands in a
/// system location or a home directory. Returns the path.
pub fn link_stub(data: &[u8]) -> Option<&str> {
    if data.len() < 4 || data.len() > 1024 {
        return None;
    }
    let text = std::str::from_utf8(data).ok()?;
    if text.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return None;
    }
    if text.starts_with("~/") {
        return Some(text);
    }
    let mut parts = text.split('/').peekable();
    let absolute = text.starts_with('/');
    let mut climbs = 0;
    if absolute {
        parts.next();
    }
    while parts.peek() == Some(&"..") {
        parts.next();
        climbs += 1;
    }
    let first = parts.next()?;
    ((absolute || climbs > 0) && parts.peek().is_some() && SYSTEM_ROOTS.contains(&first)).then_some(text)
}

/// The pointer file git leaves in place of a large file that was not downloaded.
pub fn is_lfs_pointer(data: &[u8]) -> bool {
    data.starts_with(b"version https://git-lfs.github.com/spec/")
}

/// Detect the format of `data` and run the matching analyzer.
pub(crate) fn dispatch(ctx: &mut Ctx, data: &[u8], member: &str, depth: u8) -> String {
    let total = if depth == 0 {
        ctx.opts.declared_size.unwrap_or(data.len() as u64)
    } else {
        data.len() as u64
    };
    if depth == 0 && is_lfs_pointer(data) {
        ctx.findings.push(Finding::new(
            ids::FORMAT_UNKNOWN,
            "Git LFS pointer: the real file was not downloaded, so there was nothing to scan",
            member,
        ));
        return "lfs-pointer".into();
    }
    if depth == 0
        && let Some(target) = link_stub(data)
    {
        ctx.findings.push(Finding::new(
            ids::LINK_LEAVES_TREE,
            format!("the whole file is the path {target}: a symbolic link stored as a file"),
            member,
        ));
        return "link".into();
    }
    match sniff(data, member) {
        Some("zip") => scan::scan_zip(ctx, data, member, depth),
        Some("appledouble") => {
            ctx.findings.push(Finding::new(
                ids::FORMAT_UNKNOWN,
                "macOS AppleDouble metadata, not a model file",
                member,
            ));
            "appledouble".into()
        }
        Some("7z") => scan::scan_container(
            ctx,
            archive::read_7z(data, ctx.opts.max_decompressed, member),
            "7z",
            member,
            depth,
        ),
        Some("tar") => scan::scan_container(
            ctx,
            archive::read_tar(data, ctx.opts.max_decompressed, member),
            "tar",
            member,
            depth,
        ),
        Some("rar") => {
            ctx.findings.push(Finding::new(
                ids::ARCHIVE_MALFORMED,
                "RAR archives are not opened; the content was not scanned",
                member,
            ));
            "rar".into()
        }
        Some("template") => {
            ctx.findings.extend(textcfg::check_template(data, member));
            "jinja-template".into()
        }
        Some("yaml") => {
            ctx.findings.extend(textcfg::check_yaml(data, member));
            "yaml".into()
        }
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
        _ if pickle::is_pickle(data) || pickle::has_pickle_extension(member) => scan::scan_pickle(ctx, data, member),
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
