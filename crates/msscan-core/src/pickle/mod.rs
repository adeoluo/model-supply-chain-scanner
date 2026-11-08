//! A pickle virtual machine that executes opcodes symbolically.
//!
//! Nothing is imported or called. Every opcode of protocols 0 to 5 is decoded and applied to a
//! symbolic stack and memo, so the analysis knows which globals are imported, which are called
//! (REDUCE, INST, OBJ, NEWOBJ, NEWOBJ_EX), which values flow into those calls, and which
//! attributes BUILD writes. Containers keep their elements so that call arguments, BUILD state,
//! STACK_GLOBAL operands and joblib array headers can be inspected.

pub mod policy;

use crate::finding::{Finding, Severity, ids};
pub use policy::Tier;
use policy::{classify, is_nested_loader};
use serde::Serialize;
use std::collections::HashMap;

/// Limits that bound analysis time and memory.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_opcodes: u64,
    pub max_nodes: usize,
    pub max_container_items: usize,
    pub max_nested_depth: u8,
    pub max_pickles: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_opcodes: 200_000_000,
            max_nodes: 4_000_000,
            max_container_items: 4096,
            max_nested_depth: 4,
            max_pickles: 64,
        }
    }
}

/// A global seen in the stream, aggregated over all its references.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Import {
    pub module: String,
    pub name: String,
    pub tier: Tier,
    /// Number of GLOBAL, STACK_GLOBAL or INST references.
    pub count: u32,
    /// Whether the global is called or passed into a call.
    pub called: bool,
    /// Byte offset of the first reference.
    #[serde(skip)]
    pub first_offset: usize,
}

/// Result of analyzing one pickle stream (possibly several consecutive pickles).
#[derive(Debug, Clone, Default, Serialize)]
pub struct PickleReport {
    pub findings: Vec<Finding>,
    pub imports: Vec<Import>,
    pub pickles: usize,
    pub opcodes: u64,
    pub max_protocol: u8,
    pub persistent_ids: u64,
    /// Bytes consumed from the start of the input.
    pub consumed: usize,
    pub legacy_torch: bool,
    pub joblib_arrays: u64,
}

impl PickleReport {
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }
}

/// Python 2 module names that `pickle` maps to Python 3 names (subset of `_compat_pickle`).
fn normalize_module(m: &str) -> &str {
    match m {
        "__builtin__" | "exceptions" => "builtins",
        "copy_reg" => "copyreg",
        "cPickle" => "pickle",
        "commands" => "subprocess",
        "urllib2" => "urllib.request",
        "httplib" => "http.client",
        "Queue" => "queue",
        other => other,
    }
}

#[derive(Debug, Clone)]
enum Node {
    Unknown,
    None,
    Bool(bool),
    Int(i64),
    BigInt(usize, usize),
    Float,
    /// String content, or None when longer than the kept limit.
    Str(Option<Box<str>>),
    Bytes(usize, usize),
    Tuple(Vec<u32>),
    List(Vec<u32>),
    Dict(Vec<(u32, u32)>),
    Set(Vec<u32>),
    Global(u32),
    /// STACK_GLOBAL whose operands were not constant strings.
    DynamicGlobal,
    Ext(i64),
    PersId,
    Call {
        func: u32,
        args: u32,
        state: Option<u32>,
    },
}

#[derive(Debug)]
enum Stop {
    Truncated,
    BadOpcode(u8),
    Underflow,
    NoMark,
    BadMemo,
    BadValue(&'static str),
    Limit(&'static str),
}

impl Stop {
    fn describe(&self) -> String {
        match self {
            Stop::Truncated => "stream ends before STOP".into(),
            Stop::BadOpcode(op) => format!("invalid opcode 0x{op:02x}"),
            Stop::Underflow => "stack underflow".into(),
            Stop::NoMark => "MARK expected".into(),
            Stop::BadMemo => "memo key not defined".into(),
            Stop::BadValue(m) => (*m).to_string(),
            Stop::Limit(m) => (*m).to_string(),
        }
    }
}

const TORCH_MAGIC: [u8; 10] = [0x6c, 0xfc, 0x9c, 0x46, 0xf9, 0x20, 0x6a, 0xa8, 0x50, 0x19];
const MAX_KEPT_STR: usize = 4096;

/// State shared by every pickle in one stream: the import table and accumulated findings.
struct Shared<'a> {
    data: &'a [u8],
    loc: &'a str,
    limits: Limits,
    depth: u8,
    imports: Vec<Import>,
    import_index: HashMap<(String, String), u32>,
    findings: Vec<Finding>,
    opcodes: u64,
    persistent_ids: u64,
    joblib_arrays: u64,
    max_protocol: u8,
}

impl<'a> Shared<'a> {
    fn at(&self, off: usize) -> String {
        format!("{}@{}", self.loc, off)
    }

    fn import(&mut self, module: &str, name: &str, off: usize) -> u32 {
        let module = normalize_module(module.trim());
        let name = name.trim();
        let key = (module.to_string(), name.to_string());
        if let Some(&i) = self.import_index.get(&key) {
            self.imports[i as usize].count += 1;
            return i;
        }
        let i = self.imports.len() as u32;
        self.imports.push(Import {
            module: key.0.clone(),
            name: key.1.clone(),
            tier: classify(module, name),
            count: 1,
            called: false,
            first_offset: off,
        });
        self.import_index.insert(key, i);
        i
    }
}

/// One pickle: stack, mark stack, memo and node arena.
struct Vm<'s, 'a> {
    sh: &'s mut Shared<'a>,
    pos: usize,
    nodes: Vec<Node>,
    stack: Vec<u32>,
    marks: Vec<usize>,
    memo: HashMap<u64, u32>,
    root: Option<u32>,
}

const UNKNOWN: u32 = 0;

impl<'s, 'a> Vm<'s, 'a> {
    fn new(sh: &'s mut Shared<'a>, pos: usize) -> Self {
        Vm {
            sh,
            pos,
            nodes: vec![Node::Unknown],
            stack: Vec::new(),
            marks: Vec::new(),
            memo: HashMap::new(),
            root: None,
        }
    }

    fn data(&self) -> &'a [u8] {
        self.sh.data
    }

    fn alloc(&mut self, n: Node) -> u32 {
        let keep = matches!(
            n,
            Node::Global(_) | Node::DynamicGlobal | Node::Ext(_) | Node::Call { .. }
        );
        if self.nodes.len() >= self.sh.limits.max_nodes && !keep {
            return UNKNOWN;
        }
        self.nodes.push(n);
        (self.nodes.len() - 1) as u32
    }

    fn push(&mut self, n: Node) {
        let i = self.alloc(n);
        self.stack.push(i);
    }

    fn pop(&mut self) -> Result<u32, Stop> {
        if let Some(&m) = self.marks.last()
            && self.stack.len() <= m
        {
            return Err(Stop::Underflow);
        }
        self.stack.pop().ok_or(Stop::Underflow)
    }

    fn top(&self) -> Result<u32, Stop> {
        self.stack.last().copied().ok_or(Stop::Underflow)
    }

    fn pop_mark(&mut self) -> Result<Vec<u32>, Stop> {
        let m = self.marks.pop().ok_or(Stop::NoMark)?;
        if m > self.stack.len() {
            return Err(Stop::Underflow);
        }
        Ok(self.stack.split_off(m))
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Stop> {
        let d = self.data();
        let end = self.pos.checked_add(n).ok_or(Stop::Truncated)?;
        if end > d.len() {
            return Err(Stop::Truncated);
        }
        let s = &d[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, Stop> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Stop> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, Stop> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn i32(&mut self) -> Result<i32, Stop> {
        Ok(self.u32()? as i32)
    }

    fn u64(&mut self) -> Result<u64, Stop> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }

    fn line(&mut self) -> Result<&'a [u8], Stop> {
        let d = self.data();
        let rest = &d[self.pos..];
        let n = rest.iter().position(|&b| b == b'\n').ok_or(Stop::Truncated)?;
        let s = &rest[..n];
        self.pos += n + 1;
        Ok(s)
    }

    fn len_checked(&self, n: u64) -> Result<usize, Stop> {
        let n = usize::try_from(n).map_err(|_| Stop::Truncated)?;
        if self.pos.saturating_add(n) > self.data().len() {
            return Err(Stop::Truncated);
        }
        Ok(n)
    }

    fn str_node(s: &[u8]) -> Node {
        if s.len() > MAX_KEPT_STR {
            Node::Str(None)
        } else {
            Node::Str(Some(String::from_utf8_lossy(s).into_owned().into_boxed_str()))
        }
    }

    fn str_of(&self, i: u32) -> Option<&str> {
        match &self.nodes[i as usize] {
            Node::Str(Some(s)) => Some(s),
            _ => None,
        }
    }

    fn int_of(&self, i: u32) -> Option<i64> {
        match &self.nodes[i as usize] {
            Node::Int(v) => Some(*v),
            Node::Bool(b) => Some(*b as i64),
            _ => None,
        }
    }

    fn items(&self, i: u32) -> &[u32] {
        match &self.nodes[i as usize] {
            Node::Tuple(v) | Node::List(v) | Node::Set(v) => v,
            _ => &[],
        }
    }

    fn dict_get(&self, d: u32, key: &str) -> Option<u32> {
        if let Node::Dict(kv) = &self.nodes[d as usize] {
            kv.iter()
                .rev()
                .find(|(k, _)| self.str_of(*k) == Some(key))
                .map(|(_, v)| *v)
        } else {
            None
        }
    }

    fn container_push(&mut self, target: u32, item: u32) {
        let cap = self.sh.limits.max_container_items;
        match &mut self.nodes[target as usize] {
            Node::List(v) | Node::Set(v) if v.len() < cap => v.push(item),
            _ => {}
        }
    }

    fn dict_set(&mut self, target: u32, k: u32, v: u32) {
        let cap = self.sh.limits.max_container_items;
        if let Node::Dict(kv) = &mut self.nodes[target as usize]
            && kv.len() < cap
        {
            kv.push((k, v));
        }
    }

    /// Globals reachable from a value through containers, call arguments and state (bounded walk).
    fn reachable_globals(&self, root: u32, out: &mut Vec<u32>) {
        let mut todo = vec![(root, 0u8)];
        let mut steps = 0usize;
        while let Some((i, d)) = todo.pop() {
            steps += 1;
            if steps > 10_000 || d > 6 {
                continue;
            }
            match &self.nodes[i as usize] {
                Node::Global(g) => out.push(*g),
                Node::Tuple(v) | Node::List(v) | Node::Set(v) => todo.extend(v.iter().map(|&c| (c, d + 1))),
                Node::Dict(kv) => {
                    for (k, v) in kv {
                        todo.push((*k, d + 1));
                        todo.push((*v, d + 1));
                    }
                }
                Node::Call { func, args, state } => {
                    todo.push((*func, d + 1));
                    todo.push((*args, d + 1));
                    if let Some(s) = state {
                        todo.push((*s, d + 1));
                    }
                }
                _ => {}
            }
        }
    }

    fn mark_called(&mut self, value: u32) {
        let mut gs = Vec::new();
        self.reachable_globals(value, &mut gs);
        for g in gs {
            self.sh.imports[g as usize].called = true;
        }
    }

    /// Apply a call of `func` with `args` (a tuple node) at opcode offset `off`.
    fn call(&mut self, func: u32, args: u32, off: usize) -> u32 {
        // Any global passed into a call can be invoked by the callee.
        self.mark_called(args);
        match self.nodes[func as usize].clone() {
            Node::Global(g) => {
                self.sh.imports[g as usize].called = true;
                let (m, n) = {
                    let imp = &self.sh.imports[g as usize];
                    (imp.module.clone(), imp.name.clone())
                };
                if is_nested_loader(&m, &n) {
                    self.nested(&m, &n, args, off);
                }
            }
            Node::DynamicGlobal => {
                let f = Finding::new(
                    ids::PICKLE_DYNAMIC_IMPORT,
                    "a global imported with computed module or name strings is called",
                    self.sh.at(off),
                )
                .with_severity(Severity::Critical);
                self.sh.findings.push(f);
            }
            Node::Ext(code) => {
                let f = Finding::new(
                    ids::PICKLE_EXTENSION_REGISTRY,
                    format!("a global taken from the copyreg extension registry (code {code}) is called"),
                    self.sh.at(off),
                )
                .with_severity(Severity::Critical);
                self.sh.findings.push(f);
            }
            Node::Call { .. } | Node::PersId => {
                self.mark_called(func);
                self.sh.findings.push(Finding::new(
                    ids::PICKLE_INDIRECT_CALL,
                    "calls the result of another call, so the callee is computed at load time",
                    self.sh.at(off),
                ));
            }
            _ => {}
        }
        self.alloc(Node::Call {
            func,
            args,
            state: None,
        })
    }

    fn nested(&mut self, module: &str, name: &str, args: u32, off: usize) {
        let first = self.items(args).first().copied();
        let payload = first.and_then(|a| match self.nodes[a as usize] {
            Node::Bytes(s, e) => Some((s, e)),
            Node::Call { args: inner, .. } => {
                // io.BytesIO(b"...") style wrappers: look one level down.
                self.items(inner).first().and_then(|&b| match self.nodes[b as usize] {
                    Node::Bytes(s, e) => Some((s, e)),
                    _ => None,
                })
            }
            _ => None,
        });
        let at = self.sh.at(off);
        match payload {
            Some((s, e)) if self.sh.depth < self.sh.limits.max_nested_depth => {
                let sub_loc = format!("{at}>{module}.{name}");
                let mut sub = analyze_with(&self.sh.data[s..e], &sub_loc, self.sh.limits, self.sh.depth + 1);
                let worst = sub.max_severity().unwrap_or(Severity::Info);
                let sev = worst.max(Severity::High);
                self.sh.findings.push(
                    Finding::new(
                        ids::PICKLE_NESTED_LOADER,
                        format!(
                            "calls {module}.{name} on {} embedded bytes (embedded payload: {})",
                            e - s,
                            if sub.findings.is_empty() {
                                "no findings".to_string()
                            } else {
                                format!("worst severity {worst}")
                            }
                        ),
                        at,
                    )
                    .with_severity(sev),
                );
                self.sh.findings.append(&mut sub.findings);
            }
            _ => {
                self.sh.findings.push(Finding::new(
                    ids::PICKLE_NESTED_LOADER,
                    format!("calls {module}.{name}; the payload is not an embedded constant and was not scanned"),
                    at,
                ));
            }
        }
    }

    fn build(&mut self, target: u32, state: u32, off: usize) {
        let dunder = |vm: &Self, d: u32| -> Vec<String> {
            match &vm.nodes[d as usize] {
                Node::Dict(kv) => kv
                    .iter()
                    .filter_map(|(k, _)| vm.str_of(*k))
                    .filter(|k| k.starts_with("__") && k.ends_with("__") && k.len() > 4)
                    .map(|s| s.to_string())
                    .collect(),
                _ => Vec::new(),
            }
        };
        let mut keys = dunder(self, state);
        let mut slot_state = None;
        if let Node::Tuple(t) = &self.nodes[state as usize]
            && t.len() == 2
        {
            keys.extend(dunder(self, t[0]));
            keys.extend(dunder(self, t[1]));
            slot_state = Some(t[1]);
        }
        if !keys.is_empty() {
            self.mark_called(state);
            self.sh.findings.push(Finding::new(
                ids::PICKLE_ATTRIBUTE_INJECTION,
                format!("BUILD assigns {}", keys.join(", ")),
                self.sh.at(off),
            ));
        }
        if let Node::Global(g) = self.nodes[target as usize] {
            let writes_attrs = match slot_state {
                Some(s) => matches!(&self.nodes[s as usize], Node::Dict(kv) if !kv.is_empty()),
                None => matches!(&self.nodes[state as usize], Node::Dict(kv) if !kv.is_empty()),
            };
            if writes_attrs && keys.is_empty() {
                let imp = &self.sh.imports[g as usize];
                let msg = format!(
                    "BUILD sets attributes on the imported global {}.{}",
                    imp.module, imp.name
                );
                self.mark_called(state);
                self.sh
                    .findings
                    .push(Finding::new(ids::PICKLE_ATTRIBUTE_INJECTION, msg, self.sh.at(off)));
            }
        }
        if let Node::Call { state: st, .. } = &mut self.nodes[target as usize] {
            *st = Some(state);
        }
    }

    /// If `target` is a joblib NumpyArrayWrapper, skip (or scan) the array that follows BUILD.
    fn joblib_array(&mut self, target: u32, off: usize) -> Result<(), Stop> {
        let (func, state) = match self.nodes[target as usize] {
            Node::Call {
                func, state: Some(s), ..
            } => (func, s),
            _ => return Ok(()),
        };
        let g = match self.nodes[func as usize] {
            Node::Global(g) => g,
            _ => return Ok(()),
        };
        {
            let imp = &self.sh.imports[g as usize];
            if imp.name != "NumpyArrayWrapper" || !imp.module.ends_with("joblib.numpy_pickle") {
                return Ok(());
            }
        }
        self.sh.joblib_arrays += 1;
        let shape = self.dict_get(state, "shape");
        let dtype = self.dict_get(state, "dtype");
        let align = self
            .dict_get(state, "numpy_array_alignment_bytes")
            .and_then(|a| self.int_of(a));
        let item = dtype.and_then(|d| self.dtype_itemsize(d));
        let count = shape.and_then(|s| {
            let dims = self.items(s);
            if !matches!(self.nodes[s as usize], Node::Tuple(_)) {
                return None;
            }
            dims.iter().try_fold(1u64, |acc, &d| {
                self.int_of(d)
                    .and_then(|v| u64::try_from(v).ok())
                    .and_then(|v| acc.checked_mul(v))
            })
        });
        match item {
            Some(DtypeSize::Object) => {
                // joblib writes object arrays with a nested pickle.dump.
                let start = self.pos;
                let sub_loc = self.sh.loc.to_string();
                let mut sub = Shared {
                    data: self.sh.data,
                    loc: &sub_loc,
                    limits: self.sh.limits,
                    depth: self.sh.depth,
                    imports: std::mem::take(&mut self.sh.imports),
                    import_index: std::mem::take(&mut self.sh.import_index),
                    findings: Vec::new(),
                    opcodes: 0,
                    persistent_ids: 0,
                    joblib_arrays: 0,
                    max_protocol: 0,
                };
                let res = {
                    let mut vm = Vm::new(&mut sub, start);
                    let r = vm.run();
                    (r, vm.pos)
                };
                self.sh.imports = std::mem::take(&mut sub.imports);
                self.sh.import_index = std::mem::take(&mut sub.import_index);
                self.sh.findings.append(&mut sub.findings);
                self.sh.opcodes += sub.opcodes;
                self.sh.joblib_arrays += sub.joblib_arrays;
                match res {
                    (Ok(()), end) => self.pos = end,
                    (Err(e), _) => {
                        return Err(e);
                    }
                }
            }
            Some(DtypeSize::Bytes(size)) if count.is_some() => {
                if align.is_some() {
                    let pad = self.u8()? as usize;
                    self.take(pad)?;
                }
                let total = count
                    .unwrap()
                    .checked_mul(size)
                    .ok_or(Stop::BadValue("joblib array size overflows"))?;
                let n = self.len_checked(total)?;
                self.pos += n;
            }
            _ => {
                self.sh.findings.push(Finding::new(
                    ids::PICKLE_UNSCANNED_REGION,
                    "joblib array with a shape or dtype the scanner cannot size; the rest of the stream was not scanned",
                    self.sh.at(off),
                ));
                return Err(Stop::Limit("unsized joblib array"));
            }
        }
        // The wrapper is replaced by the array on the stack.
        let i = self.alloc(Node::Unknown);
        if let Some(t) = self.stack.last_mut() {
            *t = i;
        }
        Ok(())
    }

    fn dtype_itemsize(&self, d: u32) -> Option<DtypeSize> {
        let (func, args, state) = match self.nodes[d as usize] {
            Node::Call { func, args, state } => (func, args, state),
            _ => return None,
        };
        match self.nodes[func as usize] {
            Node::Global(g) if self.sh.imports[g as usize].name == "dtype" => {}
            _ => return None,
        }
        let t = self.items(args).first().and_then(|&a| self.str_of(a))?.to_string();
        if t.starts_with('O') {
            return Some(DtypeSize::Object);
        }
        let digits: String = t
            .chars()
            .skip_while(|c| !c.is_ascii_digit())
            .take_while(|c| c.is_ascii_digit())
            .collect();
        let from_state = state
            .and_then(|s| self.items(s).get(5).copied())
            .and_then(|e| self.int_of(e))
            .filter(|&e| e > 0);
        if let Some(e) = from_state {
            return Some(DtypeSize::Bytes(e as u64));
        }
        digits.parse::<u64>().ok().filter(|&v| v > 0).map(DtypeSize::Bytes)
    }

    fn run(&mut self) -> Result<(), Stop> {
        loop {
            let off = self.pos;
            self.sh.opcodes += 1;
            if self.sh.opcodes > self.sh.limits.max_opcodes {
                return Err(Stop::Limit("opcode limit reached"));
            }
            let op = self.u8()?;
            match op {
                b'.' => {
                    let v = self.pop()?;
                    self.root = Some(v);
                    return Ok(());
                }
                0x80 => {
                    let p = self.u8()?;
                    if p > 5 {
                        return Err(Stop::BadValue("unsupported pickle protocol"));
                    }
                    self.sh.max_protocol = self.sh.max_protocol.max(p);
                }
                0x95 => {
                    self.u64()?;
                }
                b'(' => self.marks.push(self.stack.len()),
                b'0' => {
                    if self.marks.last() == Some(&self.stack.len()) {
                        self.marks.pop();
                    } else {
                        self.pop()?;
                    }
                }
                b'1' => {
                    self.pop_mark()?;
                }
                b'2' => {
                    let t = self.top()?;
                    self.stack.push(t);
                }
                b'N' => self.push(Node::None),
                0x88 => self.push(Node::Bool(true)),
                0x89 => self.push(Node::Bool(false)),
                b'I' => {
                    let l = self.line()?;
                    let n = match l {
                        b"00" => Node::Bool(false),
                        b"01" => Node::Bool(true),
                        _ => parse_int_text(l)?,
                    };
                    self.push(n);
                }
                b'L' => {
                    let l = self.line()?;
                    let l = l.strip_suffix(b"L").unwrap_or(l);
                    let n = parse_int_text(l)?;
                    self.push(n);
                }
                b'J' => {
                    let v = self.i32()?;
                    self.push(Node::Int(v as i64));
                }
                b'K' => {
                    let v = self.u8()?;
                    self.push(Node::Int(v as i64));
                }
                b'M' => {
                    let v = self.u16()?;
                    self.push(Node::Int(v as i64));
                }
                0x8a => {
                    let n = self.u8()? as usize;
                    let start = self.pos;
                    let b = self.take(n)?;
                    let node = long_node(b, start);
                    self.push(node);
                }
                0x8b => {
                    let n = self.i32()?;
                    if n < 0 {
                        return Err(Stop::BadValue("LONG4 with negative length"));
                    }
                    let n = self.len_checked(n as u64)?;
                    let start = self.pos;
                    let b = self.take(n)?;
                    let node = long_node(b, start);
                    self.push(node);
                }
                b'F' => {
                    let l = self.line()?;
                    std::str::from_utf8(l)
                        .ok()
                        .and_then(|s| s.trim().parse::<f64>().ok())
                        .ok_or(Stop::BadValue("invalid FLOAT"))?;
                    self.push(Node::Float);
                }
                b'G' => {
                    self.take(8)?;
                    self.push(Node::Float);
                }
                b'S' => {
                    let l = self.line()?;
                    let s = decode_string_literal(l).ok_or(Stop::BadValue("invalid STRING literal"))?;
                    self.push(Self::str_node(&s));
                }
                b'V' => {
                    let l = self.line()?;
                    let s = decode_raw_unicode_escape(l);
                    self.push(Self::str_node(s.as_bytes()));
                }
                b'T' => {
                    let n = self.i32()?;
                    if n < 0 {
                        return Err(Stop::BadValue("BINSTRING with negative length"));
                    }
                    let n = self.len_checked(n as u64)?;
                    let b = self.take(n)?;
                    self.push(Self::str_node(b));
                }
                b'U' => {
                    let n = self.u8()? as usize;
                    let b = self.take(n)?;
                    self.push(Self::str_node(b));
                }
                b'X' => {
                    let n = self.u32()? as u64;
                    let n = self.len_checked(n)?;
                    let b = self.take(n)?;
                    self.push(Self::str_node(b));
                }
                0x8c => {
                    let n = self.u8()? as usize;
                    let b = self.take(n)?;
                    self.push(Self::str_node(b));
                }
                0x8d => {
                    let n = self.u64()?;
                    let n = self.len_checked(n)?;
                    let b = self.take(n)?;
                    self.push(Self::str_node(b));
                }
                b'B' | b'C' | 0x8e | 0x96 => {
                    let n = match op {
                        b'B' => self.u32()? as u64,
                        b'C' => self.u8()? as u64,
                        _ => self.u64()?,
                    };
                    let n = self.len_checked(n)?;
                    let start = self.pos;
                    self.take(n)?;
                    self.push(Node::Bytes(start, start + n));
                }
                0x97 => self.push(Node::Unknown),
                0x98 => {
                    self.top()?;
                }
                b')' => self.push(Node::Tuple(Vec::new())),
                b']' => self.push(Node::List(Vec::new())),
                b'}' => self.push(Node::Dict(Vec::new())),
                0x8f => self.push(Node::Set(Vec::new())),
                b't' => {
                    let items = self.pop_mark()?;
                    self.push(Node::Tuple(items));
                }
                0x85..=0x87 => {
                    let n = (op - 0x84) as usize;
                    if self.stack.len() < n || self.marks.last().is_some_and(|&m| self.stack.len() < m + n) {
                        return Err(Stop::Underflow);
                    }
                    let items = self.stack.split_off(self.stack.len() - n);
                    self.push(Node::Tuple(items));
                }
                b'l' => {
                    let items = self.pop_mark()?;
                    self.push(Node::List(items));
                }
                b'd' => {
                    let items = self.pop_mark()?;
                    if items.len() % 2 != 0 {
                        return Err(Stop::BadValue("odd number of items for DICT"));
                    }
                    let kv = items.chunks(2).map(|c| (c[0], c[1])).collect();
                    self.push(Node::Dict(kv));
                }
                0x91 => {
                    let items = self.pop_mark()?;
                    self.push(Node::Set(items));
                }
                b'a' => {
                    let v = self.pop()?;
                    let t = self.top()?;
                    self.container_push(t, v);
                }
                b'e' | 0x90 => {
                    let items = self.pop_mark()?;
                    let t = self.top()?;
                    for v in items {
                        self.container_push(t, v);
                    }
                }
                b's' => {
                    let v = self.pop()?;
                    let k = self.pop()?;
                    let t = self.top()?;
                    self.dict_set(t, k, v);
                }
                b'u' => {
                    let items = self.pop_mark()?;
                    if items.len() % 2 != 0 {
                        return Err(Stop::BadValue("odd number of items for SETITEMS"));
                    }
                    let t = self.top()?;
                    for c in items.chunks(2) {
                        self.dict_set(t, c[0], c[1]);
                    }
                }
                b'c' => {
                    let m = self.line()?;
                    let n = self.line()?;
                    let (m, n) = (
                        String::from_utf8_lossy(m).into_owned(),
                        String::from_utf8_lossy(n).into_owned(),
                    );
                    let g = self.sh.import(&m, &n, off);
                    self.push(Node::Global(g));
                }
                0x93 => {
                    let name = self.pop()?;
                    let module = self.pop()?;
                    match (
                        self.str_of(module).map(str::to_string),
                        self.str_of(name).map(str::to_string),
                    ) {
                        (Some(m), Some(n)) => {
                            let g = self.sh.import(&m, &n, off);
                            self.push(Node::Global(g));
                        }
                        _ => {
                            self.sh.findings.push(Finding::new(
                                ids::PICKLE_DYNAMIC_IMPORT,
                                "STACK_GLOBAL operands are not constant strings",
                                self.sh.at(off),
                            ));
                            self.mark_called(module);
                            self.mark_called(name);
                            self.push(Node::DynamicGlobal);
                        }
                    }
                }
                b'i' => {
                    let m = self.line()?;
                    let n = self.line()?;
                    let (m, n) = (
                        String::from_utf8_lossy(m).into_owned(),
                        String::from_utf8_lossy(n).into_owned(),
                    );
                    let args = self.pop_mark()?;
                    let g = self.sh.import(&m, &n, off);
                    let f = self.alloc(Node::Global(g));
                    let a = self.alloc(Node::Tuple(args));
                    let r = self.call(f, a, off);
                    self.stack.push(r);
                }
                b'o' => {
                    let mut items = self.pop_mark()?;
                    if items.is_empty() {
                        return Err(Stop::Underflow);
                    }
                    let cls = items.remove(0);
                    let a = self.alloc(Node::Tuple(items));
                    let r = self.call(cls, a, off);
                    self.stack.push(r);
                }
                b'R' => {
                    let args = self.pop()?;
                    let func = self.pop()?;
                    let r = self.call(func, args, off);
                    self.stack.push(r);
                }
                0x81 => {
                    let args = self.pop()?;
                    let cls = self.pop()?;
                    let r = self.call(cls, args, off);
                    self.stack.push(r);
                }
                0x92 => {
                    let kwargs = self.pop()?;
                    let args = self.pop()?;
                    let cls = self.pop()?;
                    self.mark_called(kwargs);
                    let r = self.call(cls, args, off);
                    self.stack.push(r);
                }
                b'b' => {
                    let state = self.pop()?;
                    let target = self.top()?;
                    self.build(target, state, off);
                    self.joblib_array(target, off)?;
                }
                0x82..=0x84 => {
                    let code = match op {
                        0x82 => self.u8()? as i64,
                        0x83 => self.u16()? as i64,
                        _ => self.i32()? as i64,
                    };
                    self.sh.findings.push(Finding::new(
                        ids::PICKLE_EXTENSION_REGISTRY,
                        format!("EXT opcode with code {code}"),
                        self.sh.at(off),
                    ));
                    self.push(Node::Ext(code));
                }
                b'P' => {
                    self.line()?;
                    self.sh.persistent_ids += 1;
                    self.push(Node::PersId);
                }
                b'Q' => {
                    let pid = self.pop()?;
                    self.mark_called(pid);
                    self.sh.persistent_ids += 1;
                    self.push(Node::PersId);
                }
                b'p' => {
                    let l = self.line()?;
                    let k = parse_u64_text(l).ok_or(Stop::BadValue("invalid PUT key"))?;
                    let t = self.top()?;
                    self.memo.insert(k, t);
                }
                b'q' => {
                    let k = self.u8()? as u64;
                    let t = self.top()?;
                    self.memo.insert(k, t);
                }
                b'r' => {
                    let k = self.u32()? as u64;
                    let t = self.top()?;
                    self.memo.insert(k, t);
                }
                0x94 => {
                    let k = self.memo.len() as u64;
                    let t = self.top()?;
                    self.memo.insert(k, t);
                }
                b'g' => {
                    let l = self.line()?;
                    let k = parse_u64_text(l).ok_or(Stop::BadValue("invalid GET key"))?;
                    let v = *self.memo.get(&k).ok_or(Stop::BadMemo)?;
                    self.stack.push(v);
                }
                b'h' => {
                    let k = self.u8()? as u64;
                    let v = *self.memo.get(&k).ok_or(Stop::BadMemo)?;
                    self.stack.push(v);
                }
                b'j' => {
                    let k = self.u32()? as u64;
                    let v = *self.memo.get(&k).ok_or(Stop::BadMemo)?;
                    self.stack.push(v);
                }
                other => return Err(Stop::BadOpcode(other)),
            }
        }
    }
}

enum DtypeSize {
    Object,
    Bytes(u64),
}

fn parse_u64_text(l: &[u8]) -> Option<u64> {
    std::str::from_utf8(l).ok()?.trim().parse().ok()
}

fn parse_int_text(l: &[u8]) -> Result<Node, Stop> {
    let s = std::str::from_utf8(l)
        .map_err(|_| Stop::BadValue("invalid INT"))?
        .trim();
    if let Ok(v) = s.parse::<i64>() {
        return Ok(Node::Int(v));
    }
    let digits = s.strip_prefix('-').unwrap_or(s);
    if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(Node::Unknown);
    }
    Err(Stop::BadValue("invalid INT"))
}

fn long_node(b: &[u8], start: usize) -> Node {
    if b.len() <= 8 {
        if b.is_empty() {
            return Node::Int(0);
        }
        let neg = b[b.len() - 1] & 0x80 != 0;
        let mut a = if neg { [0xffu8; 8] } else { [0u8; 8] };
        a[..b.len()].copy_from_slice(b);
        Node::Int(i64::from_le_bytes(a))
    } else {
        Node::BigInt(start, start + b.len())
    }
}

/// Decode a protocol 0 STRING argument: a quoted Python literal with backslash escapes.
fn decode_string_literal(l: &[u8]) -> Option<Vec<u8>> {
    let l = l.strip_suffix(b"\r").unwrap_or(l);
    if l.len() < 2 || l[0] != l[l.len() - 1] || (l[0] != b'\'' && l[0] != b'"') {
        return None;
    }
    let body = &l[1..l.len() - 1];
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0;
    while i < body.len() {
        let c = body[i];
        if c != b'\\' || i + 1 >= body.len() {
            out.push(c);
            i += 1;
            continue;
        }
        let e = body[i + 1];
        i += 2;
        match e {
            b'n' => out.push(b'\n'),
            b't' => out.push(b'\t'),
            b'r' => out.push(b'\r'),
            b'0'..=b'7' => {
                let mut v = (e - b'0') as u32;
                let mut k = 0;
                while k < 2 && i < body.len() && (b'0'..=b'7').contains(&body[i]) {
                    v = v * 8 + (body[i] - b'0') as u32;
                    i += 1;
                    k += 1;
                }
                out.push(v as u8);
            }
            b'x' if i + 2 <= body.len() => {
                let h = std::str::from_utf8(&body[i..i + 2])
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok())?;
                out.push(h);
                i += 2;
            }
            b'\n' => {}
            other => {
                if !matches!(other, b'\\' | b'\'' | b'"') {
                    out.push(b'\\');
                }
                out.push(other);
            }
        }
    }
    Some(out)
}

/// Decode a protocol 0 UNICODE argument (raw-unicode-escape).
fn decode_raw_unicode_escape(l: &[u8]) -> String {
    let mut out = String::with_capacity(l.len());
    let mut i = 0;
    while i < l.len() {
        if l[i] == b'\\' && i + 1 < l.len() && (l[i + 1] == b'u' || l[i + 1] == b'U') {
            let w = if l[i + 1] == b'u' { 4 } else { 8 };
            if i + 2 + w <= l.len()
                && let Some(c) = std::str::from_utf8(&l[i + 2..i + 2 + w])
                    .ok()
                    .and_then(|h| u32::from_str_radix(h, 16).ok())
                    .and_then(char::from_u32)
            {
                out.push(c);
                i += 2 + w;
                continue;
            }
        }
        out.push(l[i] as char);
        i += 1;
    }
    out
}

fn looks_like_pickle_start(b: &[u8]) -> bool {
    matches!(b, [0x80, p, ..] if *p <= 5)
}

/// Analyze a pickle stream: the first pickle, any pickles that follow it, and the legacy
/// PyTorch layout (five pickles followed by raw storage data).
pub fn analyze(data: &[u8], loc: &str, limits: Limits) -> PickleReport {
    analyze_with(data, loc, limits, 0)
}

fn analyze_with(data: &[u8], loc: &str, limits: Limits, depth: u8) -> PickleReport {
    let mut sh = Shared {
        data,
        loc,
        limits,
        depth,
        imports: Vec::new(),
        import_index: HashMap::new(),
        findings: Vec::new(),
        opcodes: 0,
        persistent_ids: 0,
        joblib_arrays: 0,
        max_protocol: 0,
    };
    let mut pos = 0usize;
    let mut pickles = 0usize;
    let mut legacy = false;
    let mut extra = 0usize;
    loop {
        let start = pos;
        let (res, end, root_magic) = {
            let mut vm = Vm::new(&mut sh, start);
            let r = vm.run();
            let magic = vm.root.is_some_and(|r| match vm.nodes[r as usize] {
                Node::BigInt(s, e) => data[s..e] == TORCH_MAGIC,
                _ => false,
            });
            (r, vm.pos, magic)
        };
        match res {
            Ok(()) => {
                pickles += 1;
                if pickles == 1 && root_magic {
                    legacy = true;
                }
                pos = end;
            }
            Err(Stop::Limit(m)) => {
                if m != "unsized joblib array" {
                    sh.findings
                        .push(Finding::new(ids::PICKLE_RESOURCE, m.to_string(), sh.at(end)));
                }
                pos = data.len();
                break;
            }
            Err(e) => {
                if pickles > 0 && !legacy {
                    // A failed trailing pickle: report as trailing data, keep its findings.
                    sh.findings.push(Finding::new(
                        ids::PICKLE_TRAILING,
                        format!(
                            "{} bytes after the last complete pickle ({})",
                            data.len() - start,
                            e.describe()
                        ),
                        sh.at(start),
                    ));
                } else {
                    sh.findings
                        .push(Finding::new(ids::PICKLE_MALFORMED, e.describe(), sh.at(end)));
                }
                pos = data.len();
                break;
            }
        }
        if legacy && pickles == 5 {
            break;
        }
        if pos >= data.len() || pickles >= limits.max_pickles {
            break;
        }
        if !legacy {
            if !looks_like_pickle_start(&data[pos..]) {
                sh.findings.push(Finding::new(
                    ids::PICKLE_TRAILING,
                    format!("{} bytes after the final STOP opcode", data.len() - pos),
                    sh.at(pos),
                ));
                break;
            }
            extra += 1;
        }
    }
    if extra > 0 {
        sh.findings.push(Finding::new(
            ids::PICKLE_TRAILING,
            format!("{extra} more pickle(s) follow the first one; all were scanned"),
            sh.at(0),
        ));
    }
    if legacy {
        sh.findings.push(Finding::new(
            ids::TORCH_LEGACY,
            "legacy PyTorch serialization (magic number pickle)",
            sh.at(0),
        ));
    }
    for imp in &sh.imports {
        let at = sh.at(imp.first_offset);
        let what = format!("{}.{}", imp.module, imp.name);
        let f = match (imp.tier, imp.called) {
            (Tier::Dangerous, true) => Some(Finding::new(ids::PICKLE_DANGEROUS_CALL, format!("calls {what}"), at)),
            (Tier::Dangerous, false) => Some(Finding::new(
                ids::PICKLE_DANGEROUS_IMPORT,
                format!("imports {what}"),
                at,
            )),
            (Tier::Unknown, true) => Some(Finding::new(ids::PICKLE_UNKNOWN_CALL, format!("calls {what}"), at)),
            (Tier::Unknown, false) => Some(Finding::new(ids::PICKLE_UNKNOWN_IMPORT, format!("imports {what}"), at)),
            (Tier::Library, true) => Some(Finding::new(ids::PICKLE_LIBRARY_CALL, format!("calls {what}"), at)),
            _ => None,
        };
        if let Some(f) = f {
            sh.findings.push(f);
        }
    }
    PickleReport {
        findings: sh.findings,
        imports: sh.imports,
        pickles,
        opcodes: sh.opcodes,
        max_protocol: sh.max_protocol,
        persistent_ids: sh.persistent_ids,
        consumed: pos.min(data.len()),
        legacy_torch: legacy,
        joblib_arrays: sh.joblib_arrays,
    }
}

/// Cheap check used by format detection: does `data` parse as at least one complete pickle?
pub fn is_pickle(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    if looks_like_pickle_start(data) {
        return true;
    }
    // Protocol 0 and 1 have no header: accept if a short prefix parses to STOP cleanly
    // and starts with an opcode that a pickler emits first.
    if !b"(c]}NIJKLSTUVX)lde".contains(&data[0]) {
        return false;
    }
    let limits = Limits {
        max_opcodes: 1_000_000,
        ..Limits::default()
    };
    let r = analyze(&data[..data.len().min(16 << 20)], "", limits);
    r.pickles > 0 && !r.findings.iter().any(|f| f.rule == ids::PICKLE_MALFORMED)
}

#[cfg(test)]
mod tests;
