//! Text files that ship next to a model: YAML configs and standalone chat templates.
//!
//! YAML is read line by line, not parsed: the checks look for PyYAML object tags (which make
//! `yaml.load` construct arbitrary objects), Hydra `_target_` entries (which make `instantiate`
//! call whatever the config names) and template expressions.

use crate::finding::{Finding, Severity, ids};
use crate::jinja;
use crate::pickle::policy;

fn base_name(name: &str) -> String {
    name.rsplit(['/', '\\']).next().unwrap_or(name).to_ascii_lowercase()
}

pub fn is_template_name(name: &str) -> bool {
    let base = base_name(name);
    [".jinja", ".jinja2", ".j2", ".template"]
        .iter()
        .any(|e| base.ends_with(e))
}

pub fn is_yaml_name(name: &str) -> bool {
    let base = base_name(name);
    base.ends_with(".yaml") || base.ends_with(".yml") || base == "mlmodel"
}

/// Text without NUL bytes in its first kilobytes: what a config or template file looks like.
pub fn looks_like_text(d: &[u8]) -> bool {
    let head = &d[..d.len().min(4096)];
    !head.is_empty() && !head.contains(&0) && std::str::from_utf8(head).is_ok_and(|s| !s.trim().is_empty())
        || d.len() > 4096
            && !head.contains(&0)
            && String::from_utf8_lossy(head)
                .chars()
                .filter(|c| *c == '\u{fffd}')
                .count()
                <= 1
}

/// A standalone Jinja template file.
pub fn check_template(d: &[u8], loc: &str) -> Vec<Finding> {
    jinja::check(&String::from_utf8_lossy(d), "the template", loc)
}

fn scalar(rest: &str) -> &str {
    let rest = rest.trim_start();
    let end = rest
        .find(|c: char| c.is_whitespace() || matches!(c, ',' | '}' | ']' | '#'))
        .unwrap_or(rest.len());
    rest[..end].trim_matches(['"', '\''])
}

/// The findings for one `_target_` value (also used for JSON configs).
pub fn target_finding(target: &str, loc: &str) -> Option<Finding> {
    let (sev, why) = policy::config_target_risk(target)?;
    Some(Finding::new(ids::CONFIG_TARGET, format!("_target_ names {target}, which {why}"), loc).with_severity(sev))
}

/// A YAML config: object tags, instantiation targets and template expressions.
pub fn check_yaml(d: &[u8], loc: &str) -> Vec<Finding> {
    let text = String::from_utf8_lossy(d);
    let mut out = Vec::new();
    let mut tags: Vec<String> = Vec::new();
    let mut targets: Vec<String> = Vec::new();
    for line in text.lines() {
        if line.trim_start().starts_with('#') {
            continue;
        }
        let code = line.split(" #").next().unwrap_or(line);
        for marker in ["!!python/", "!python/"] {
            for (i, _) in code.match_indices(marker) {
                let tag = code[i..]
                    .split(|c: char| c.is_whitespace() || matches!(c, ',' | ']' | '}'))
                    .next()
                    .unwrap_or("")
                    .to_string();
                if !tags.contains(&tag) && !(marker == "!python/" && i > 0 && code.as_bytes()[i - 1] == b'!') {
                    tags.push(tag);
                }
            }
        }
        for (i, _) in code.match_indices("_target_") {
            let after = code[i + "_target_".len()..].trim_start_matches(['"', '\'']);
            if let Some(value) = after.trim_start().strip_prefix(':') {
                let v = scalar(value).to_string();
                if !v.is_empty() && !targets.contains(&v) {
                    targets.push(v);
                }
            }
        }
    }
    for tag in &tags {
        let target = tag.rsplit(':').next().unwrap_or("");
        let calls = tag.contains("/apply:") || tag.contains("/new:");
        let dangerous = target
            .rsplit_once('.')
            .is_some_and(|(m, n)| policy::classify(m, n) == policy::Tier::Dangerous);
        let sev = if calls || dangerous {
            Severity::Critical
        } else {
            Severity::High
        };
        out.push(
            Finding::new(
                ids::CONFIG_YAML_TAG,
                format!("YAML tag {tag} makes an unsafe yaml.load build a Python object"),
                loc,
            )
            .with_severity(sev),
        );
    }
    for target in &targets {
        out.extend(target_finding(target, loc));
    }
    if text.contains("{{") || text.contains("{%") {
        out.extend(
            jinja::check(&text, "a template in the config", loc)
                .into_iter()
                .filter(|f| f.rule == ids::GGUF_TEMPLATE_INJECTION),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(f: &[Finding]) -> Vec<(&str, Severity)> {
        f.iter().map(|x| (x.rule.as_str(), x.severity)).collect()
    }

    #[test]
    fn names_and_text() {
        assert!(
            is_template_name("a/chat_template.jinja") && is_template_name("X.J2") && is_template_name("t.template")
        );
        assert!(!is_template_name("model.bin"));
        assert!(is_yaml_name("conf/model_config.yaml") && is_yaml_name("x.YML") && is_yaml_name("m/MLmodel"));
        assert!(!is_yaml_name("yaml.bin"));
        assert!(looks_like_text(b"a: 1\n") && !looks_like_text(b"\x80\x04\x00") && !looks_like_text(b"  "));
    }

    #[test]
    fn yaml_object_tags() {
        let y = b"a: !!python/object/apply:os.system ['id']\nb: !!python/name:collections.OrderedDict\nc: !!python/object/apply:os.system ['again']\n";
        let f = check_yaml(y, "c.yaml");
        assert_eq!(
            rules(&f),
            vec![
                (ids::CONFIG_YAML_TAG, Severity::Critical),
                (ids::CONFIG_YAML_TAG, Severity::High)
            ]
        );
        assert!(f[0].message.contains("os.system"));
        assert!(
            check_yaml(
                b"plain: value\nlist: [1, 2]\n# !!python/object in a comment\n",
                "c.yaml"
            )
            .is_empty()
        );
    }

    #[test]
    fn hydra_targets() {
        let y = b"model:\n  _target_: torch.nn.Linear\n  in_features: 2\nhook:\n  _target_: os.system\n  _args_: ['id']\nenc: {'_target_': \"builtins.eval\", x: 1}\npath:\n  _target_: os.path.join\nload:\n  _target_: transformers.AutoModel.from_pretrained\nwrap:\n  _target_: functools.partial\nlog:\n  _target_: logging.FileHandler\nhub:\n  _target_: torch.hub.load\n";
        let f = check_yaml(y, "c.yaml");
        let got: Vec<(String, Severity)> = f
            .iter()
            .map(|x| {
                (
                    x.message
                        .split_whitespace()
                        .nth(2)
                        .unwrap()
                        .trim_end_matches(',')
                        .to_string(),
                    x.severity,
                )
            })
            .collect();
        assert_eq!(
            got,
            vec![
                ("os.system".to_string(), Severity::Critical),
                ("builtins.eval".to_string(), Severity::Critical),
                ("functools.partial".to_string(), Severity::Medium),
                ("logging.FileHandler".to_string(), Severity::High),
                ("torch.hub.load".to_string(), Severity::High),
            ]
        );
    }

    #[test]
    fn templates_in_files_and_configs() {
        let bad =
            b"{% for m in messages %}{{ m.content }}{% endfor %}\n{{ cycler.__init__.__globals__.os.system('id') }}";
        assert_eq!(check_template(bad, "t.jinja")[0].rule, ids::GGUF_TEMPLATE_INJECTION);
        assert!(
            check_template(
                b"{% for m in messages %}{{ m.role }}: {{ m.content }}{% endfor %}",
                "t.jinja"
            )
            .is_empty()
        );
        let y = b"chat_template:\n  \"{{ config.__class__.__init__.__globals__['os'].system('x') }}\"\nname: m\n";
        assert_eq!(check_yaml(y, "c.yaml")[0].rule, ids::GGUF_TEMPLATE_INJECTION);
        assert!(check_yaml(b"prompt: \"{{ question }}\"\n", "c.yaml").is_empty());
    }
}
