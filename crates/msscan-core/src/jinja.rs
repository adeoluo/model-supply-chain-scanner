//! Chat template checks: server-side template injection patterns in Jinja tags.

use crate::finding::{ids, Finding};

/// Python internals that sandbox escapes reach for.
const DUNDERS: &[&str] = &[
    "__class__",
    "__globals__",
    "__subclasses__",
    "__builtins__",
    "__import__",
    "__mro__",
    "__base__",
    "__bases__",
    "__dict__",
    "__getattribute__",
    "__code__",
    "__init__",
    "__func__",
    "__self__",
    "__reduce__",
    "__reduce_ex__",
    "__loader__",
    "__spec__",
    "func_globals",
    "mro(",
];

/// Names and calls that have no place in a chat template.
const EXEC_TOKENS: &[&str] = &[
    "os.popen",
    "os.system",
    "popen(",
    "subprocess",
    "eval(",
    "exec(",
    "import_module",
    "getattr(",
    "lipsum.",
    "cycler.",
    "joiner.",
    "self._TemplateReference",
    "_module.",
    "request.application",
    "config.__",
];

/// Substring match that does not start in the middle of an identifier.
fn contains_token(hay: &str, needle: &str) -> bool {
    let word = needle.starts_with(|c: char| c.is_ascii_alphabetic());
    hay.match_indices(needle).any(|(i, _)| {
        !word || i == 0 || !hay.as_bytes()[i - 1].is_ascii_alphanumeric() && hay.as_bytes()[i - 1] != b'_'
    })
}

/// Segments of a template that Jinja evaluates: the inside of `{{ }}` and `{% %}`.
pub fn tags(t: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let b = t.as_bytes();
    let mut i = 0;
    while i + 1 < b.len() {
        if b[i] == b'{' && (b[i + 1] == b'{' || b[i + 1] == b'%') {
            let close = if b[i + 1] == b'{' { "}}" } else { "%}" };
            let start = i + 2;
            match t[start..].find(close) {
                Some(n) => {
                    out.push(&t[start..start + n]);
                    i = start + n + 2;
                }
                None => {
                    out.push(&t[start..]);
                    break;
                }
            }
        } else {
            i += 1;
        }
    }
    out
}

/// Check one template; `key` names where it came from.
pub fn check(template: &str, key: &str, loc: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut critical = Vec::new();
    let mut suspicious = Vec::new();
    for tag in tags(template) {
        let lower = tag.to_ascii_lowercase();
        for d in DUNDERS {
            if contains_token(tag, d) && !critical.contains(d) {
                critical.push(*d);
            }
        }
        for e in EXEC_TOKENS {
            if contains_token(&lower, &e.to_ascii_lowercase()) && !critical.contains(e) {
                critical.push(*e);
            }
        }
        // Escaped underscores ("\x5f\x5f") exist only to hide dunder names from filters.
        if lower.contains("\\x5f") || lower.contains("\\u005f") || lower.contains("\\137") {
            critical.push("escaped underscore");
        }
        if lower.contains("|attr") || lower.contains("| attr") {
            suspicious.push("attr filter");
        }
        if tag.contains("'__") || tag.contains("\"__") || tag.contains("~ '_") || tag.contains("~'_") {
            suspicious.push("string building a dunder name");
        }
        if lower.contains("|map(") && lower.contains("attribute=") && lower.contains("__") {
            suspicious.push("map(attribute=) with a dunder");
        }
    }
    if !critical.is_empty() {
        critical.dedup();
        out.push(Finding::new(
            ids::GGUF_TEMPLATE_INJECTION,
            format!("{key} reaches {}", critical.join(", ")),
            loc,
        ));
    } else if !suspicious.is_empty() {
        suspicious.dedup();
        out.push(Finding::new(
            ids::GGUF_TEMPLATE_SUSPICIOUS,
            format!("{key} uses {}", suspicious.join(", ")),
            loc,
        ));
    }
    if template.len() > 64 * 1024 {
        out.push(Finding::new(
            ids::GGUF_TEMPLATE_SUSPICIOUS,
            format!("{key} is {} bytes long", template.len()),
            loc,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHATML: &str = "{% for message in messages %}{{'<|im_start|>' + message['role'] + '\\n' + message['content'] + '<|im_end|>' + '\\n'}}{% endfor %}{% if add_generation_prompt %}{{ '<|im_start|>assistant\\n' }}{% endif %}";

    #[test]
    fn benign_templates_pass() {
        assert!(check(CHATML, "tokenizer.chat_template", "x").is_empty());
        let with_text = "You can use subprocess and os.system in Python. {{ messages[0]['content'] }}";
        assert!(
            check(with_text, "t", "x").is_empty(),
            "literal text outside tags is not evaluated"
        );
        assert!(check(
            "{% set x = namespace(found=false) %}{{ raise_exception('no') }}",
            "t",
            "x"
        )
        .is_empty());
        assert!(check("{{ retrieval(docs) }}{{ x.premro(1) }}", "t", "x").is_empty());
    }

    #[test]
    fn injection_payloads_are_critical() {
        for p in [
            "{{ cycler.__init__.__globals__.os.getcwd() }}",
            "{{ ''.__class__.__mro__[1].__subclasses__() }}",
            "{% for c in [].__class__.__base__.__subclasses__() %}{% endfor %}",
            "{{ lipsum['\\x5f\\x5fglobals\\x5f\\x5f'] }}",
            "{{ self._TemplateReference__context }}",
            "{{ joiner.__init__ }}",
        ] {
            let f = check(p, "tokenizer.chat_template", "x");
            assert_eq!(f[0].rule, ids::GGUF_TEMPLATE_INJECTION, "{p}");
        }
    }

    #[test]
    fn obfuscation_is_suspicious() {
        let f = check("{{ x|attr('a' ~ 'b') }}", "t", "x");
        assert_eq!(f[0].rule, ids::GGUF_TEMPLATE_SUSPICIOUS);
        let big = format!("{}{{{{ x }}}}", "a".repeat(70_000));
        assert_eq!(check(&big, "t", "x")[0].rule, ids::GGUF_TEMPLATE_SUSPICIOUS);
    }

    #[test]
    fn tag_splitting() {
        assert_eq!(tags("a{{ b }}c{% d %}e{# f #}"), vec![" b ", " d "]);
        assert_eq!(tags("{{ open"), vec![" open"]);
        assert!(tags("no tags {").is_empty());
    }
}
