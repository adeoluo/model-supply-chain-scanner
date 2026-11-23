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
