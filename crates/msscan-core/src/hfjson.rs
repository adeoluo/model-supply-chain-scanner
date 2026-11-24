//! Hugging Face JSON files: remote code mappings and chat templates.

use crate::finding::{Finding, ids};
use crate::jinja;
use serde_json::Value;

pub fn looks_like_json(d: &[u8]) -> bool {
    let t = d
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .map(|i| &d[i..])
        .unwrap_or(&[]);
    t.first() == Some(&b'{') && serde_json::from_slice::<Value>(d).is_ok()
}

/// Check `config.json`-style files for `auto_map`, and tokenizer configs for chat templates.
pub fn check(d: &[u8], loc: &str) -> Vec<Finding> {
    let Ok(v) = serde_json::from_slice::<Value>(d) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(m) = v.get("auto_map").and_then(Value::as_object) {
        let targets: Vec<String> = m
            .values()
            .flat_map(|x| match x {
                Value::String(s) => vec![s.clone()],
                Value::Array(a) => a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect(),
                _ => vec![],
            })
            .collect();
        out.push(Finding::new(
            ids::HF_REMOTE_CODE,
            format!("auto_map points to {}", targets.join(", ")),
            loc,
        ));
    }
    // A sharded checkpoint index maps tensor names to shard files, which must sit beside it.
    if let Some(m) = v.get("weight_map").and_then(Value::as_object) {
        let mut outside: Vec<&str> = m
            .values()
            .filter_map(Value::as_str)
            .filter(|name| leaves_directory(name))
            .collect();
        outside.sort_unstable();
        outside.dedup();
        if !outside.is_empty() {
            let shown: Vec<&str> = outside.iter().take(3).copied().collect();
            out.push(Finding::new(
                ids::SHARD_INDEX_TRAVERSAL,
                format!(
                    "weight_map names {} shard path(s) outside the model directory: {}",
                    outside.len(),
                    shown.join(", ")
                ),
                loc,
            ));
        }
    }
    let mut targets = Vec::new();
    collect_targets(&v, &mut targets, 0);
    targets.sort();
    targets.dedup();
    for t in &targets {
        out.extend(crate::textcfg::target_finding(t, loc));
    }
    match v.get("chat_template") {
        Some(Value::String(t)) => out.extend(jinja::check(t, "chat_template", loc)),
        Some(Value::Array(a)) => {
            for item in a {
                if let (Some(name), Some(t)) = (
                    item.get("name").and_then(Value::as_str),
                    item.get("template").and_then(Value::as_str),
                ) {
                    out.extend(jinja::check(t, &format!("chat_template.{name}"), loc));
                }
            }
        }
        _ => {}
    }
    out
}

/// Whether a file name given relative to the model directory points outside it: absolute, a
/// home or drive path, or any `..` component.
pub fn leaves_directory(name: &str) -> bool {
    let b = name.as_bytes();
    name.starts_with(['/', '\\', '~'])
        || (b.len() > 1 && b[0].is_ascii_alphabetic() && b[1] == b':')
        || name.split(['/', '\\']).any(|part| part == "..")
}

/// Every string value of a `_target_` key, at any depth (Hydra-style configs saved as JSON).
fn collect_targets(v: &Value, out: &mut Vec<String>, depth: u32) {
    if depth > 64 {
        return;
    }
    match v {
        Value::Object(m) => {
            if let Some(t) = m.get("_target_").and_then(Value::as_str) {
                out.push(t.to_string());
            }
            m.values().for_each(|x| collect_targets(x, out, depth + 1));
        }
        Value::Array(a) => a.iter().for_each(|x| collect_targets(x, out, depth + 1)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;

    #[test]
    fn shard_index_paths() {
        for bad in [
            "../../../../proc/self/environ",
            "/etc/passwd",
            "sub/../../x.safetensors",
            "C:\\Windows\\win.ini",
            "~/.ssh/id_rsa",
        ] {
            let c = serde_json::json!({"metadata": {"total_size": 4}, "weight_map": {"w": bad, "v": "model-00001-of-00002.safetensors"}});
            let f = check(c.to_string().as_bytes(), "model.safetensors.index.json");
            assert_eq!(f.len(), 1, "{bad}");
            assert_eq!(
                (f[0].rule.as_str(), f[0].severity),
                (ids::SHARD_INDEX_TRAVERSAL, Severity::High)
            );
            assert!(f[0].message.contains(bad));
        }
        let ok = br#"{"metadata": {}, "weight_map": {"a": "model-00001-of-00002.safetensors", "b": "shards/part..2.safetensors"}}"#;
        assert!(check(ok, "model.safetensors.index.json").is_empty());
    }

    #[test]
    fn auto_map_and_templates() {
        let c = br#"{"auto_map": {"AutoModel": "modeling_x.XModel", "AutoTokenizer": ["tok.T", null]}, "chat_template": [{"name": "default", "template": "{{ x.__class__ }}"}]}"#;
        assert!(looks_like_json(c));
        let f = check(c, "config.json");
        assert_eq!(f.len(), 2);
        assert!(
            f.iter()
                .any(|x| x.rule == ids::HF_REMOTE_CODE && x.message.contains("modeling_x.XModel"))
        );
        assert!(f.iter().any(|x| x.rule == ids::GGUF_TEMPLATE_INJECTION));
        assert!(check(br#"{"chat_template": "{{ messages }}"}"#, "t").is_empty());
        assert!(check(b"not json", "t").is_empty());
        assert!(!looks_like_json(b"[1]"));
        let t =
            br#"{"model": {"_target_": "torch.nn.Linear"}, "hooks": [{"_target_": "os.system", "_args_": ["id"]}]}"#;
        let f = check(t, "config.json");
        assert_eq!(f.len(), 1);
        assert!(f[0].rule == ids::CONFIG_TARGET && f[0].message.contains("os.system"));
    }
}
