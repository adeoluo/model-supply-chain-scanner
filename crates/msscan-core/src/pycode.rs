//! Python code objects read from their `marshal` form, without running them.
//!
//! Keras Lambda layers store a function as marshalled bytecode. What the bytecode can reach is
//! limited to the names it carries: globals and attributes are looked up through `co_names`, so
//! a function that never names an import, a file, a process or a reflection helper cannot use
//! one. This reader walks the marshal stream of CPython 3.6 to 3.16, collects every name and
//! string constant (including those of nested code objects) and grades them.

use std::collections::BTreeSet;

/// What a code object refers to.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct CodeInfo {
    /// `co_names` of the function and of every code object nested in it.
    pub names: BTreeSet<String>,
    /// String constants, kept short.
    pub strings: Vec<String>,
    /// Number of code objects found (1 for a plain lambda).
    pub code_objects: usize,
}

#[derive(Debug, Clone)]
enum Value {
    Str(String),
    Bytes,
    Seq(Vec<Value>),
    Code,
    Other,
}

const MAX_DEPTH: u32 = 64;
const MAX_ITEMS: usize = 1 << 20;
const MAX_KEPT: usize = 256;

/// The three layouts of a marshalled code object.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Layout {
    /// 3.11 and later: no nlocals; names of locals merged; qualname and an exception table.
    V311,
    /// 3.8 to 3.10: posonlyargcount added.
    V38,
    /// 3.7 and earlier.
    V37,
}

struct Reader<'a> {
    d: &'a [u8],
    pos: usize,
    refs: Vec<Value>,
    layout: Layout,
    info: CodeInfo,
    items: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.d.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }

    fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn text(&mut self, n: usize) -> Option<Value> {
        let s = self.take(n)?;
        Some(Value::Str(String::from_utf8_lossy(s).into_owned()))
    }

    fn seq(&mut self, n: usize, depth: u32) -> Option<Value> {
        self.items += n;
        if self.items > MAX_ITEMS {
            return None;
        }
        let mut out = Vec::with_capacity(n.min(1024));
        for _ in 0..n {
            out.push(self.object(depth + 1)?);
        }
        Some(Value::Seq(out))
    }

    fn object(&mut self, depth: u32) -> Option<Value> {
        if depth > MAX_DEPTH {
            return None;
        }
        let byte = self.u8()?;
        let kind = byte & 0x7f;
        // CPython reserves the reference slot before reading the object's children.
        let slot = if byte & 0x80 != 0 {
            self.refs.push(Value::Other);
            Some(self.refs.len() - 1)
        } else {
            None
        };
        let value = match kind {
            b'0' | b'N' | b'F' | b'T' | b'S' | b'.' => Value::Other,
            b'i' => {
                self.take(4)?;
                Value::Other
            }
            b'I' | b'g' => {
                self.take(8)?;
                Value::Other
            }
            b'y' => {
                self.take(16)?;
                Value::Other
            }
            b'l' => {
                let n = self.u32()? as i32;
                self.take(n.unsigned_abs() as usize * 2)?;
                Value::Other
            }
            b'f' => {
                let n = self.u8()? as usize;
                self.take(n)?;
                Value::Other
            }
            b'x' => {
                for _ in 0..2 {
                    let n = self.u8()? as usize;
                    self.take(n)?;
                }
                Value::Other
            }
            b's' => {
                let n = self.u32()? as usize;
                self.take(n)?;
                Value::Bytes
            }
            b't' | b'u' | b'a' | b'A' => {
                let n = self.u32()? as usize;
                self.text(n)?
            }
            b'z' | b'Z' => {
                let n = self.u8()? as usize;
                self.text(n)?
            }
            b'(' | b'[' | b'<' | b'>' => {
                let n = self.u32()? as usize;
                self.seq(n, depth)?
            }
            b')' => {
                let n = self.u8()? as usize;
                self.seq(n, depth)?
            }
            b'{' => {
                let mut out = Vec::new();
                loop {
                    if self.d.get(self.pos) == Some(&b'0') {
                        self.pos += 1;
                        break;
                    }
                    out.push(self.object(depth + 1)?);
                    out.push(self.object(depth + 1)?);
                    self.items += 2;
                    if self.items > MAX_ITEMS {
                        return None;
                    }
                }
                Value::Seq(out)
            }
            b':' => self.seq(3, depth)?,
            b'r' => {
                let i = self.u32()? as usize;
                self.refs.get(i)?.clone()
            }
            b'c' => {
                self.code(depth)?;
                Value::Code
            }
            _ => return None,
        };
        if let Some(i) = slot {
            self.refs[i] = value.clone();
        }
        Some(value)
    }

    fn keep_strings(&mut self, v: &Value, names: bool) {
        match v {
            Value::Str(s) if names => {
                self.info.names.insert(s.clone());
            }
            Value::Str(s) => {
                if self.info.strings.len() < MAX_KEPT {
                    self.info.strings.push(s.chars().take(MAX_KEPT).collect());
                }
            }
            Value::Seq(items) => items.iter().for_each(|x| self.keep_strings(x, names)),
            _ => {}
        }
    }

    fn code(&mut self, depth: u32) -> Option<()> {
        let ints = if self.layout == Layout::V38 { 6 } else { 5 };
        self.take(4 * ints)?;
        let bytecode = self.object(depth + 1)?;
        let consts = self.object(depth + 1)?;
        let names = self.object(depth + 1)?;
        if !matches!(bytecode, Value::Bytes) || !matches!(consts, Value::Seq(_)) || !matches!(names, Value::Seq(_)) {
            return None;
        }
        match self.layout {
            Layout::V311 => {
                let locals = self.object(depth + 1)?;
                let kinds = self.object(depth + 1)?;
                if !matches!(locals, Value::Seq(_)) || !matches!(kinds, Value::Bytes) {
                    return None;
                }
                for _ in 0..3 {
                    // filename, name, qualname
                    if !matches!(self.object(depth + 1)?, Value::Str(_)) {
                        return None;
                    }
                }
                self.take(4)?;
                self.object(depth + 1)?; // line table
                self.object(depth + 1)?; // exception table
            }
            Layout::V38 | Layout::V37 => {
                for _ in 0..3 {
                    // varnames, freevars, cellvars
                    if !matches!(self.object(depth + 1)?, Value::Seq(_)) {
                        return None;
                    }
                }
                for _ in 0..2 {
                    // filename, name
                    if !matches!(self.object(depth + 1)?, Value::Str(_)) {
                        return None;
                    }
                }
                self.take(4)?;
                self.object(depth + 1)?; // line table
            }
        }
        self.info.code_objects += 1;
        self.keep_strings(&names, true);
        self.keep_strings(&consts, false);
        Some(())
    }
}

/// Read a marshalled code object. `None` when the bytes are not one in any supported layout.
pub fn parse(data: &[u8]) -> Option<CodeInfo> {
    if data.first().map(|b| b & 0x7f) != Some(b'c') {
        return None;
    }
    for layout in [Layout::V311, Layout::V38, Layout::V37] {
        let mut r = Reader {
            d: data,
            pos: 0,
            refs: Vec::new(),
            layout,
            info: CodeInfo::default(),
            items: 0,
        };
        if r.object(0).is_some() && r.pos == data.len() && r.info.code_objects > 0 {
            return Some(r.info);
        }
    }
    None
}

/// Names that let a function import, reflect, or reach files, processes or the network.
const RISKY_NAMES: &[&str] = &[
    // builtins that import, evaluate or reflect
    "__import__",
    "eval",
    "exec",
    "compile",
    "open",
    "getattr",
    "setattr",
    "delattr",
    "globals",
    "locals",
    "vars",
    "breakpoint",
    "input",
    "help",
    "exit",
    "quit",
    "memoryview",
    "__builtins__",
    "__build_class__",
    "__loader__",
    "__spec__",
    // modules a Keras utility module has in scope, or that an import statement names
    "os",
    "sys",
    "subprocess",
    "socket",
    "shutil",
    "importlib",
    "ctypes",
    "pickle",
    "cPickle",
    "_pickle",
    "dill",
    "cloudpickle",
    "marshal",
    "pty",
    "requests",
    "urllib",
    "urllib2",
    "http",
    "httplib",
    "ftplib",
    "smtplib",
    "builtins",
    "__builtin__",
    "base64",
    "codecs",
    "binascii",
    "zlib",
    "tempfile",
    "pathlib",
    "glob",
    "io",
    "gfile",
    "runpy",
    "code",
    "inspect",
    "types",
    "threading",
    "multiprocessing",
    "webbrowser",
    "platform",
    "getpass",
    "pwd",
    "ssl",
    "mmap",
    "site",
    "posix",
    "nt",
    "winreg",
    "commands",
    "asyncio",
    "zipfile",
    "tarfile",
    "pip",
    "pkg_resources",
    "sysconfig",
    "paramiko",
    "aiohttp",
    "httpx",
    // attributes that run, load or write
    "system",
    "popen",
    "Popen",
    "check_output",
    "check_call",
    "getoutput",
    "spawn",
    "spawnv",
    "execv",
    "execve",
    "fork",
    "kill",
    "urlopen",
    "urlretrieve",
    "import_module",
    "loads",
    "load",
    "write_file",
    "read_file",
    "py_function",
    "numpy_function",
    "py_func",
    "get_file",
    "load_model",
    "load_weights",
    "save",
    "remove",
    "unlink",
    "rmtree",
    "rename",
    "chmod",
    "environ",
    "getenv",
    "putenv",
    "connect",
    "sendall",
    "b64decode",
    "fromhex",
    "decode",
];

/// The risky names in `names`, plus any dunder name (the way reflection chains are written).
pub fn risky_names<'a>(names: impl IntoIterator<Item = &'a String>) -> Vec<String> {
    let mut out: Vec<String> = names
        .into_iter()
        .filter(|n| RISKY_NAMES.contains(&n.as_str()) || (n.starts_with("__") && n.ends_with("__") && n.len() > 4))
        .cloned()
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Names with a visible side effect and no way to reach the system. A function that uses one
/// is doing something a tensor transformation does not need, without being an attack.
const SIDE_EFFECT_NAMES: &[&str] = &["print", "pprint", "sleep", "warn", "display"];

/// The side-effect names in `names`.
pub fn side_effect_names<'a>(names: impl IntoIterator<Item = &'a String>) -> Vec<String> {
    let mut out: Vec<String> = names
        .into_iter()
        .filter(|n| SIDE_EFFECT_NAMES.contains(&n.as_str()))
        .cloned()
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Identifiers in Python source text, for functions stored as source instead of bytecode.
pub fn identifiers(source: &str) -> BTreeSet<String> {
    source
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty() && !w.as_bytes()[0].is_ascii_digit())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::payload::base64_decode;

    include!("pycode_samples.rs");

    fn info(sample: &str) -> CodeInfo {
        let raw = base64_decode(sample.as_bytes()).expect("base64");
        parse(&raw).unwrap_or_else(|| panic!("not parsed: {sample}"))
    }

    #[test]
    fn every_supported_version_parses() {
        assert_eq!(SAMPLES.len(), 8 * 7);
        for (version, kind, sample) in SAMPLES {
            let i = info(sample);
            let risky = risky_names(&i.names);
            match *kind {
                "math" => assert!(i.names.is_empty() && risky.is_empty(), "{version}: {i:?}"),
                "tensor" => {
                    assert!(
                        i.names.contains("tf") && i.names.contains("reduce_mean"),
                        "{version}: {i:?}"
                    );
                    assert!(risky.is_empty(), "{version}: {risky:?}");
                }
                "system" => {
                    assert_eq!(risky, vec!["__import__", "system"], "{version}");
                    assert!(i.strings.iter().any(|s| s == "os"), "{version}: {i:?}");
                    assert!(i.strings.iter().any(|s| s == "echo inert"), "{version}: {i:?}");
                }
                "getattr" => assert_eq!(risky, vec!["__builtins__", "getattr"], "{version}"),
                "nested" => {
                    assert_eq!(i.code_objects, 2, "{version}");
                    assert_eq!(risky, vec!["open"], "{version}");
                }
                "names" => {
                    assert_eq!(risky, vec!["Popen", "subprocess"], "{version}");
                    assert!(i.names.contains("shape") && i.strings.contains(&"a string const".to_string()));
                }
                "function" => assert!(risky.contains(&"os".to_string()), "{version}: {i:?}"),
                other => panic!("unknown sample kind {other}"),
            }
        }
    }

    #[test]
    fn rejects_what_is_not_a_code_object() {
        assert!(parse(b"").is_none());
        assert!(parse(b"N").is_none());
        assert!(parse(b"\xe3\x01\x00").is_none());
        assert!(parse(&[b'c'; 64]).is_none());
        let good = base64_decode(SAMPLES[0].2.as_bytes()).unwrap();
        assert!(parse(&good[..good.len() - 3]).is_none(), "truncated");
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(parse(&trailing).is_none(), "trailing bytes");
    }

    #[test]
    fn source_identifiers() {
        let ids = identifiers("lambda x: eval('print(\"t\")') + os.path.sep + x2");
        assert!(ids.contains("eval") && ids.contains("os") && ids.contains("x2") && !ids.contains("2"));
        assert_eq!(risky_names(&ids), vec!["eval", "os"]);
        assert!(risky_names(&identifiers("lambda x: tf.nn.relu(x) * 0.5")).is_empty());
        assert_eq!(
            side_effect_names(&identifiers("lambda x: print(x) or x")),
            vec!["print"]
        );
        assert!(side_effect_names(&identifiers("lambda x: x")).is_empty());
        assert_eq!(
            risky_names(&identifiers("x.__class__.__mro__")),
            vec!["__class__", "__mro__"]
        );
    }

    proptest::proptest! {
        #[test]
        fn never_panics(mut data in proptest::collection::vec(proptest::num::u8::ANY, 0..300), flip in 0usize..200) {
            let _ = parse(&data);
            let mut good = base64_decode(SAMPLES[flip % SAMPLES.len()].2.as_bytes()).unwrap();
            let at = flip % good.len();
            good[at] ^= data.first().copied().unwrap_or(0x55);
            let _ = parse(&good);
            data.insert(0, 0xe3);
            let _ = parse(&data);
        }
    }
}
