//! Keras models: Lambda layers, modules outside Keras, and custom objects in model configs.
//!
//! `.keras` archives hold `config.json`. Legacy HDF5 files hold the same JSON in the
//! `model_config` attribute, and SavedModel `keras_metadata.pb` files hold it in protobuf
//! strings; both are found by locating `{"class_name"` objects in the raw bytes and parsing
//! them with a string-aware brace matcher (ADR 0005).

use crate::finding::{ids, Finding};
use crate::pickle::policy::{self, Tier};
use serde_json::Value;

pub const HDF5_MAGIC: &[u8] = b"\x89HDF\r\n\x1a\n";

/// HDF5 superblocks may follow a user block of 512, 1024, 2048 ... bytes.
pub fn is_hdf5(d: &[u8]) -> bool {
    d.starts_with(HDF5_MAGIC)
        || [512usize, 1024, 2048, 4096]
            .iter()
            .any(|&o| d.get(o..o + 8) == Some(HDF5_MAGIC))
}

const KERAS_MODULE_PREFIXES: &[&str] = &[
    "keras",
    "tf_keras",
    "tensorflow.keras",
    "keras_hub",
    "keras_nlp",
    "keras_cv",
];

/// Keras functions that read, write or download files.
const DANGEROUS_KERAS_NAMES: &[&str] = &["get_file", "load_model", "load_weights", "save_model", "save"];

/// Fragments of TFOpLambda function names that reach files or Python.
const DANGEROUS_TF_FUNCS: &[&str] = &[
    "io.",
    "gfile",
    "py_function",
    "numpy_function",
    "py_func",
    "print",
    "debugging",
];

/// Every JSON object in `d` that starts with `{"class_name"` (or `{"module"`) and parses.
pub fn embedded_configs(d: &[u8]) -> (Vec<Value>, usize) {
    let mut out = Vec::new();
    let mut failed = 0;
    let mut i = 0;
    let pats: [&[u8]; 3] = [b"{\"class_name\"", b"{\"module\"", b"{ \"class_name\""];
    while i < d.len() {
        let Some(rel) = memfind(&d[i..], b'{') else { break };
        let s = i + rel;
        if pats.iter().any(|p| d[s..].starts_with(p)) {
            if let Some(e) = matching_brace(d, s) {
                match serde_json::from_slice::<Value>(&d[s..=e]) {
                    Ok(v) => {
                        out.push(v);
                        i = e + 1;
                        continue;
                    }
                    Err(_) => failed += 1,
                }
            } else {
                failed += 1;
            }
        }
        i = s + 1;
    }
    (out, failed)
}

fn memfind(h: &[u8], b: u8) -> Option<usize> {
    h.iter().position(|&x| x == b)
}

/// Index of the brace closing the object that opens at `start`, skipping JSON strings.
fn matching_brace(d: &[u8], start: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_str = false;
    let mut esc = false;
    for (k, &c) in d[start..].iter().enumerate().take(64 << 20) {
        if in_str {
            match (esc, c) {
                (true, _) => esc = false,
                (false, b'\\') => esc = true,
                (false, b'"') => in_str = false,
                _ => {}
            }
            continue;
        }
        match c {
            b'"' => in_str = true,
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(start + k);
                }
            }
            0 => return None,
            _ => {}
        }
    }
    None
}

#[derive(Default)]
struct Walk {
    lambdas: Vec<String>,
    modules: Vec<String>,
    external: Vec<String>,
    custom: Vec<String>,
    tf_funcs: Vec<String>,
}

fn walk(v: &Value, w: &mut Walk, depth: u32, in_lambda: bool) {
    if depth > 200 {
        return;
    }
    match v {
        Value::Object(m) => {
            let class = m.get("class_name").and_then(Value::as_str).unwrap_or("");
            let cfg = m.get("config");
            let name = cfg
                .and_then(|c| c.get("name"))
                .and_then(Value::as_str)
                .unwrap_or(class)
                .to_string();
            let is_lambda = class == "Lambda" || class == "__lambda__" && !in_lambda;
            if is_lambda {
                w.lambdas.push(name.clone());
            }
            if class == "TFOpLambda" || class == "SlicingOpLambda" {
                if let Some(f) = cfg.and_then(|c| c.get("function")).and_then(Value::as_str) {
                    if DANGEROUS_TF_FUNCS.iter().any(|d| f.contains(d)) {
                        w.tf_funcs.push(f.to_string());
                    }
                }
            }
            if let Some(module) = m.get("module").and_then(Value::as_str) {
                let keras = KERAS_MODULE_PREFIXES
                    .iter()
                    .any(|p| module == *p || module.starts_with(&format!("{p}.")));
                let builtin_ok = module == "builtins"
                    && matches!(
                        class,
                        "tuple" | "list" | "dict" | "set" | "float" | "int" | "str" | "bool"
                    );
                // Functions saved by name ({"module": "builtins", "class_name": "function"}) and
                // objects from __main__ are looked up among Keras built-ins and the custom objects
                // passed by the caller; the config cannot import code through them.
                let by_name = (module == "builtins" && class == "function") || module == "__main__";
                let full = format!("{module}.{class}");
                if DANGEROUS_KERAS_NAMES.contains(&class)
                    || module.contains("file_utils")
                    || (module == "builtins" && !builtin_ok && !by_name)
                    || (!keras && policy::classify(module, class) == Tier::Dangerous)
                {
                    w.modules.push(full);
                } else if by_name {
                    let fname = cfg.and_then(Value::as_str).unwrap_or(class);
                    w.custom.push(format!("{module}.{fname}"));
                } else if !keras && !builtin_ok {
                    w.external.push(full);
                }
            }
            if let Some(r) = m.get("registered_name").and_then(Value::as_str) {
                if r.contains('>') && m.get("module").is_none_or(Value::is_null) {
                    w.custom.push(r.to_string());
                }
            }
            for x in m.values() {
                walk(x, w, depth + 1, in_lambda || is_lambda);
            }
        }
        Value::Array(a) => a.iter().for_each(|x| walk(x, w, depth + 1, in_lambda)),
        _ => {}
    }
}

fn dedup(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v.dedup();
    v
}

fn short_list(v: &[String]) -> String {
    let mut s: Vec<String> = v.iter().take(5).map(|x| format!("{x:?}")).collect();
    if v.len() > 5 {
        s.push(format!("and {} more", v.len() - 5));
    }
    s.join(", ")
}

/// Check parsed Keras configs.
pub fn check_configs(configs: &[Value], loc: &str) -> Vec<Finding> {
    let mut w = Walk::default();
    for c in configs {
        walk(c, &mut w, 0, false);
    }
    let mut out = Vec::new();
    let lambdas = dedup(w.lambdas);
    if !lambdas.is_empty() {
        out.push(Finding::new(
            ids::KERAS_LAMBDA,
            format!(
                "{} Lambda layer(s) with serialized code: {}",
                lambdas.len(),
                short_list(&lambdas)
            ),
            loc,
        ));
    }
    let modules = dedup(
        w.modules
            .into_iter()
            .chain(w.tf_funcs.into_iter().map(|f| format!("tf.{f} (TFOpLambda)")))
            .collect(),
    );
    if !modules.is_empty() {
        out.push(Finding::new(
            ids::KERAS_UNSAFE_MODULE,
            format!("deserializes {}", short_list(&modules)),
            loc,
        ));
    }
    let external = dedup(w.external);
    if !external.is_empty() {
        out.push(Finding::new(
            ids::KERAS_EXTERNAL_MODULE,
            format!("needs code from {}", short_list(&external)),
            loc,
        ));
    }
    let custom = dedup(w.custom);
    if !custom.is_empty() {
        out.push(Finding::new(
            ids::KERAS_CUSTOM_OBJECT,
            format!("custom objects {}", short_list(&custom)),
            loc,
        ));
    }
    out
}

/// `.keras` archive `config.json`.
pub fn check_config_json(d: &[u8], loc: &str) -> Vec<Finding> {
    match serde_json::from_slice::<Value>(d) {
        Ok(v) => check_configs(&[v], loc),
        Err(e) => vec![Finding::new(ids::KERAS_MALFORMED, format!("config.json: {e}"), loc)],
    }
}

/// Legacy HDF5 or `keras_metadata.pb`: configs embedded in binary data.
pub fn check_embedded(d: &[u8], loc: &str) -> (Vec<Finding>, usize) {
    let (configs, failed) = embedded_configs(d);
    let mut out = check_configs(&configs, loc);
    if configs.is_empty() && failed > 0 {
        out.push(Finding::new(
            ids::KERAS_MALFORMED,
            "a model config was found but could not be parsed",
            loc,
        ));
    }
    (out, configs.len())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub const LAMBDA_K2: &str = r#"{"class_name": "Sequential", "config": {"name": "s", "layers": [{"class_name": "Lambda", "config": {"name": "inert", "function": ["4wEAAAAA", null, null], "function_type": "lambda"}}]}}"#;
    pub const LAMBDA_K3: &str = r#"{"module": "keras", "class_name": "Sequential", "config": {"layers": [{"module": "keras.layers", "class_name": "Lambda", "config": {"name": "l", "function": {"class_name": "__lambda__", "config": {"code": "4wEA", "defaults": null, "closure": null}}}}]}}"#;
    pub const CLEAN_K3: &str = r#"{"module": "keras", "class_name": "Sequential", "config": {"layers": [{"module": "keras.layers", "class_name": "Dense", "config": {"name": "d", "units": 2, "activation": "relu"}, "registered_name": null}]}}"#;

    #[test]
    fn lambdas_in_both_versions() {
        for c in [LAMBDA_K2, LAMBDA_K3] {
            let f = check_config_json(c.as_bytes(), "config.json");
            assert_eq!(f[0].rule, ids::KERAS_LAMBDA, "{c}");
            assert!(f[0].message.starts_with("1 Lambda"), "{}", f[0].message);
        }
        assert!(check_config_json(CLEAN_K3.as_bytes(), "x").is_empty());
    }

    #[test]
    fn foreign_modules_and_custom_objects() {
        let c = r#"{"module": "keras", "class_name": "Model", "config": {"layers": [{"module": "os", "class_name": "getcwd", "config": {}}, {"module": "keras.utils", "class_name": "get_file", "config": {}}, {"module": null, "class_name": "MyLayer", "registered_name": "Custom>MyLayer", "config": {}}, {"class_name": "TFOpLambda", "config": {"function": "io.write_file"}}, {"module": "builtins", "class_name": "tuple"}]}}"#;
        let f = check_config_json(c.as_bytes(), "x");
        let rules: Vec<_> = f.iter().map(|x| x.rule.as_str()).collect();
        assert_eq!(rules, vec![ids::KERAS_UNSAFE_MODULE, ids::KERAS_CUSTOM_OBJECT]);
        assert!(
            f[0].message.contains("os.getcwd")
                && f[0].message.contains("get_file")
                && f[0].message.contains("io.write_file")
        );
        assert!(!f[0].message.contains("tuple"));
    }

    #[test]
    fn functions_by_name_and_third_party_modules() {
        let c = r#"{"module": "keras", "class_name": "Model", "config": {"layers": [{"module": "tornet.layers", "class_name": "CoordConv2D", "config": {}}], "loss": {"module": "builtins", "class_name": "function", "config": "ciou_loss", "registered_name": "function"}, "metrics": [{"module": "__main__", "class_name": "function", "config": "iou"}]}}"#;
        let f = check_config_json(c.as_bytes(), "x");
        let rules: Vec<_> = f.iter().map(|x| x.rule.as_str()).collect();
        assert_eq!(rules, vec![ids::KERAS_EXTERNAL_MODULE, ids::KERAS_CUSTOM_OBJECT]);
        assert!(f[0].message.contains("tornet.layers.CoordConv2D"));
        assert!(f[1].message.contains("builtins.ciou_loss"));
        for bad in [
            r#"{"module": "os", "class_name": "function", "config": "system"}"#,
            r#"{"module": "builtins", "class_name": "eval"}"#,
            r#"{"module": "subprocess", "class_name": "call"}"#,
        ] {
            let f = check_config_json(bad.as_bytes(), "x");
            assert_eq!(f[0].rule, ids::KERAS_UNSAFE_MODULE, "{bad}");
        }
    }

    #[test]
    fn embedded_in_binary() {
        let mut blob = b"\x89HDF\r\n\x1a\n\x00\x00garbage{not json".to_vec();
        blob.extend_from_slice(LAMBDA_K2.as_bytes());
        blob.extend_from_slice(b"\x00\x00{\"class_name\": \"Adam\", \"config\": {\"lr\": 0.1}}\x00");
        assert!(is_hdf5(&blob));
        let (f, n) = check_embedded(&blob, "m.h5");
        assert_eq!(n, 2);
        assert_eq!(f[0].rule, ids::KERAS_LAMBDA);
        let (f, n) = check_embedded(b"\x89HDF\r\n\x1a\n{\"class_name\": \"X\", \"config\": {", "m.h5");
        assert_eq!(n, 0);
        assert_eq!(f[0].rule, ids::KERAS_MALFORMED);
        assert!(check_embedded(b"\x89HDF\r\n\x1a\nweights only", "m.h5").0.is_empty());
        assert_eq!(check_config_json(b"{", "x")[0].rule, ids::KERAS_MALFORMED);
    }

    #[test]
    fn braces_inside_strings() {
        let d = br#"{"class_name": "Lambda", "config": {"name": "a}b{", "s": "q\"}"}}"#;
        let (v, _) = embedded_configs(d);
        assert_eq!(v.len(), 1);
        let mut user_block = vec![0u8; 512];
        user_block.extend_from_slice(HDF5_MAGIC);
        assert!(is_hdf5(&user_block));
        let many: Vec<String> = (0..7).map(|i| format!("l{i}")).collect();
        assert!(short_list(&many).contains("and 2 more"));
    }
}
