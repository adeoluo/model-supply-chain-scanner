//! Payloads stored as data: encoded blobs and code text inside string constants and metadata.
//!
//! Loading a file does not run a string. These checks exist because staged attacks keep the
//! second stage in one: a pickle or a line of Python, often base64 or hex encoded, that a later
//! step decodes and runs. Nothing here is executed; blobs are decoded and parsed.

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_value(c: u8) -> Option<u8> {
    match c {
        b'-' => Some(62),
        b'_' => Some(63),
        _ => B64.iter().position(|&x| x == c).map(|p| p as u8),
    }
}

/// Decode standard or URL-safe base64, with or without padding. `None` unless every byte fits.
pub fn base64_decode(text: &[u8]) -> Option<Vec<u8>> {
    let body: &[u8] = {
        let mut end = text.len();
        while end > 0 && text[end - 1] == b'=' {
            end -= 1;
        }
        if text.len() - end > 2 {
            return None;
        }
        &text[..end]
    };
    if body.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0u8;
    for &c in body {
        acc = (acc << 6) | u32::from(b64_value(c)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Decode a hex string (even length, hex digits only).
pub fn hex_decode(text: &[u8]) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.chunks(2)
        .map(|p| {
            let hi = (p[0] as char).to_digit(16)?;
            let lo = (p[1] as char).to_digit(16)?;
            Some((hi * 16 + lo) as u8)
        })
        .collect()
}

fn trim(text: &[u8]) -> &[u8] {
    let is_pad = |b: &u8| b.is_ascii_whitespace() || *b == b'"' || *b == b'\'';
    let start = text.iter().position(|b| !is_pad(b)).unwrap_or(text.len());
    let end = text.iter().rposition(|b| !is_pad(b)).map_or(start, |p| p + 1);
    &text[start..end]
}

/// The shortest constant worth decoding; shorter ones cannot hold a payload.
pub const MIN_CONSTANT: usize = 16;

/// Ways `text` decodes to other bytes: `(encoding, bytes)`. Raw text is not included.
pub fn decodings(text: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let t = trim(text);
    let mut out = Vec::new();
    if t.len() < MIN_CONSTANT {
        return out;
    }
    if let Some(b) = hex_decode(t) {
        out.push(("hex", b));
    } else if let Some(b) = base64_decode(t) {
        out.push(("base64", b));
    }
    out
}

/// Whether `b` starts and ends like a pickle stream, cheaply, before a real parse.
pub fn pickle_shaped(b: &[u8]) -> bool {
    let t = {
        let end = b.iter().rposition(|c| !c.is_ascii_whitespace()).map_or(0, |p| p + 1);
        &b[..end]
    };
    t.len() >= 6 && t.last() == Some(&b'.') && ((t[0] == 0x80 && t[1] <= 5) || matches!(t[0], b'c' | b'('))
}

/// Calls that run commands or code. Each is specific enough that prose rarely contains it.
const CODE_SINKS: &[&str] = &[
    "os.system(",
    "os.popen(",
    "os.execv",
    "os.execl",
    "os.spawn",
    "posix.system(",
    "subprocess.Popen(",
    "subprocess.run(",
    "subprocess.call(",
    "subprocess.check_output(",
    "subprocess.check_call(",
    "subprocess.getoutput(",
    "pty.spawn(",
    "__import__('os')",
    "__import__(\"os\")",
    "__import__('subprocess')",
    "__import__(\"subprocess\")",
    "__import__('socket')",
    "__import__(\"socket\")",
    "__import__('builtins')",
    "__import__(\"builtins\")",
    "exec(compile(",
    "eval(compile(",
    "exec(base64.",
    "eval(base64.",
    "exec(__import__",
    "eval(__import__",
    "exec(marshal.",
    "exec(zlib.",
    "exec(bytes.fromhex(",
    "exec(codecs.",
    "pickle.loads(base64.",
    "marshal.loads(base64.",
];

/// Whether the parentheses a sink leaves open are closed later in `rest`, reading Python string
/// literals (single, double and triple quoted) as opaque when `quotes` is set.
fn closes(rest: &[char], mut depth: i32, quotes: bool) -> bool {
    let mut i = 0;
    while i < rest.len() {
        let c = rest[i];
        if quotes && (c == '\'' || c == '"') {
            let triple = rest.get(i + 1) == Some(&c) && rest.get(i + 2) == Some(&c);
            let width = if triple { 3 } else { 1 };
            i += width;
            loop {
                match rest.get(i) {
                    None => return false,
                    Some('\\') => i += 2,
                    Some(&d) if d == c && (!triple || (rest.get(i + 1) == Some(&c) && rest.get(i + 2) == Some(&c))) => {
                        i += width;
                        break;
                    }
                    Some(_) => i += 1,
                }
            }
            continue;
        }
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return true;
                }
            }
            _ => {}
        }
        i += 1;
    }
    false
}

/// The first command- or code-running call that appears in `text` as a complete call: the
/// parenthesis it opens is closed again. A fragment such as `os.system("shutdown`, which is what
/// one word of a tokenizer vocabulary built from source code looks like, is not a call.
pub fn code_sink(text: &str) -> Option<&'static str> {
    // Spaces before the parenthesis or around the dot do not change what Python runs.
    let squeezed: Vec<char> = text.chars().filter(|c| !c.is_whitespace()).collect();
    CODE_SINKS
        .iter()
        .find(|s| {
            let key: Vec<char> = s.chars().filter(|c| !c.is_whitespace()).collect();
            let open =
                key.iter().filter(|&&c| c == '(').count() as i32 - key.iter().filter(|&&c| c == ')').count() as i32;
            let mut from = 0;
            while let Some(at) = squeezed[from..].windows(key.len()).position(|w| w == key.as_slice()) {
                let rest = &squeezed[from + at + key.len()..];
                // A name prefix such as `os.execv` has no parenthesis of its own: the rest of
                // the name and the call follow it.
                let (rest, depth) = if key.contains(&'(') {
                    (rest, open)
                } else {
                    let name = rest.iter().take_while(|c| c.is_alphanumeric() || **c == '_').count();
                    match rest.get(name) {
                        Some('(') => (&rest[name + 1..], 1),
                        _ => (rest, -1),
                    }
                };
                if depth == 0 || (depth > 0 && (closes(rest, depth, true) || closes(rest, depth, false))) {
                    return true;
                }
                from += at + 1;
            }
            false
        })
        .copied()
}

/// A code-running call in `text`, or in what `text` decodes to: `(sink, encoding)`.
pub fn hidden_code(text: &[u8]) -> Option<(&'static str, &'static str)> {
    if let Ok(s) = std::str::from_utf8(text)
        && let Some(sink) = code_sink(s)
    {
        return Some((sink, "plain text"));
    }
    for (encoding, bytes) in decodings(text) {
        if let Ok(s) = std::str::from_utf8(&bytes)
            && let Some(sink) = code_sink(s)
        {
            return Some((sink, encoding));
        }
    }
    None
}

/// Check one metadata or configuration string for a second-stage payload, as the pickle
/// analyzer does for its constants: an encoded pickle that makes calls, or code text.
pub fn inspect_text(text: &[u8], what: &str, loc: &str) -> Vec<crate::finding::Finding> {
    use crate::finding::{Finding, Severity, ids};
    use crate::pickle::{self, Limits, Tier};
    let mut out = Vec::new();
    if text.len() < MIN_CONSTANT {
        return out;
    }
    let mut candidates: Vec<(&'static str, Vec<u8>)> = decodings(text);
    if pickle_shaped(text) {
        candidates.push(("raw", text.to_vec()));
    }
    for (encoding, bytes) in candidates {
        if !pickle_shaped(&bytes) {
            continue;
        }
        let mut sub = pickle::analyze(&bytes, &format!("{loc}>{what}>{encoding}-pickle"), Limits::default());
        if sub.pickles == 0 || sub.findings.iter().any(|f| f.rule == ids::PICKLE_MALFORMED) {
            continue;
        }
        if sub.imports.iter().any(|i| i.called && i.tier != Tier::Safe) {
            let sev = sub.max_severity().unwrap_or(Severity::High).max(Severity::High);
            out.push(
                Finding::new(
                    ids::PICKLE_EMBEDDED_PAYLOAD,
                    format!("{what} holds a pickle ({encoding}) that makes calls"),
                    loc,
                )
                .with_severity(sev),
            );
            out.append(&mut sub.findings);
        }
        return out;
    }
    if let Some((sink, encoding)) = hidden_code(text) {
        out.push(Finding::new(
            ids::EMBEDDED_CODE,
            format!("{what} ({encoding}) contains {sink}...)"),
            loc,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_and_hex_round_trip() {
        assert_eq!(base64_decode(b"aGVsbG8gd29ybGQ=").unwrap(), b"hello world");
        assert_eq!(base64_decode(b"aGVsbG8gd29ybGQ").unwrap(), b"hello world");
        assert_eq!(base64_decode(b"_-8=").unwrap(), vec![0xff, 0xef]);
        assert!(base64_decode(b"not base64!").is_none());
        assert!(base64_decode(b"abcde").is_none());
        assert!(base64_decode(b"ab====").is_none());
        assert_eq!(hex_decode(b"80049500").unwrap(), vec![0x80, 4, 0x95, 0]);
        assert!(hex_decode(b"8004g5").is_none() && hex_decode(b"800").is_none());
    }

    #[test]
    fn decodings_need_a_minimum_length_and_a_full_match() {
        assert!(decodings(b"abcd").is_empty());
        assert_eq!(decodings(b"  '8004950000000000' ")[0].0, "hex");
        assert_eq!(decodings(b"b3Muc3lzdGVtKCdlY2hvIEFUVEFDSycp")[0].0, "base64");
        assert!(decodings(b"an ordinary sentence with spaces").is_empty());
    }

    #[test]
    fn pickle_shape() {
        assert!(pickle_shaped(b"\x80\x04\x95\x00\x00N."));
        assert!(pickle_shaped(b"cos\nsystem\n(S'x'\ntR.\n"));
        assert!(
            !pickle_shaped(b"\x80\x04\x95\x00\x00N") && !pickle_shaped(b"hello.") && !pickle_shaped(b"\x80\x09abc.")
        );
    }

    #[test]
    fn code_in_plain_and_encoded_text() {
        assert_eq!(code_sink("import os; os.system('echo hi')"), Some("os.system("));
        assert_eq!(code_sink("subprocess . run (['ls'])"), Some("subprocess.run("));
        assert_eq!(code_sink("x = __import__( 'os' ).getcwd()"), Some("__import__('os')"));
        assert!(code_sink("the operating system (os) runs subprocesses").is_none());
        assert!(code_sink("model.eval() and exec time").is_none());
        // One word of a vocabulary built from source code is a fragment, not a call.
        assert!(code_sink("os.system(\"shutdown").is_none());
        assert!(code_sink("subprocess.run([\"ls\",").is_none());
        assert!(code_sink("see os.execv and os.spawn in the manual").is_none());
        assert_eq!(code_sink("os.execvp('sh', ['sh'])"), Some("os.execv"));
        assert_eq!(code_sink("os.system('echo :) (')"), Some("os.system("));
        assert_eq!(code_sink("os.system('''echo it's (''')"), Some("os.system("));
        assert_eq!(
            code_sink("lambda x: exec('import os; os.system(\"echo pwned\")')"),
            Some("os.system(")
        );
        assert_eq!(
            hidden_code(b"b3Muc3lzdGVtKCdlY2hvIEFUVEFDSycp"),
            Some(("os.system(", "base64"))
        );
        assert_eq!(hidden_code(b"os.popen('id')"), Some(("os.popen(", "plain text")));
        assert!(hidden_code(b"aGVsbG8gd29ybGQgaGVsbG8=").is_none());
        assert!(hidden_code(&[0xff, 0xfe, 0x00]).is_none());
    }
}
