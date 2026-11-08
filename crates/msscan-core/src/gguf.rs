//! GGUF headers: structural validation and chat template checks.

use crate::finding::{Finding, ids};
use crate::jinja;
use std::collections::HashSet;

pub const MAGIC: &[u8] = b"GGUF";

pub fn is_gguf(d: &[u8]) -> bool {
    d.starts_with(MAGIC)
}

/// (block size, bytes per block) for ggml tensor types, indexed by type id.
fn type_size(t: u32) -> Option<(u64, u64)> {
    Some(match t {
        0 => (1, 4),
        1 => (1, 2),
        2 => (32, 18),
        3 => (32, 20),
        6 => (32, 22),
        7 => (32, 24),
        8 => (32, 34),
        9 => (32, 36),
        10 => (256, 84),
        11 => (256, 110),
        12 => (256, 144),
        13 => (256, 176),
        14 => (256, 210),
        15 => (256, 292),
        16 => (256, 66),
        17 => (256, 74),
        18 => (256, 98),
        19 => (256, 50),
        20 => (32, 18),
        21 => (256, 110),
        22 => (256, 82),
        23 => (256, 136),
        24 => (1, 1),
        25 => (1, 2),
        26 => (1, 4),
        27 => (1, 8),
        28 => (1, 8),
        29 => (256, 56),
        30 => (1, 2),
        34 => (256, 54),
        35 => (256, 66),
        39 => (32, 17),
        _ => return None,
    })
}

#[derive(Debug, Default)]
pub struct GgufInfo {
    pub version: u32,
    pub tensor_count: u64,
    pub kv_count: u64,
    pub architecture: Option<String>,
    pub chat_templates: Vec<(String, String)>,
    /// True when only a prefix of the file was available and parsing stopped at its end.
    pub partial: bool,
    pub tensors_checked: u64,
}

enum Halt {
    /// Data ended before the declared file size: not an error in prefix mode.
    Prefix,
    Bad(String),
}

struct R<'a> {
    d: &'a [u8],
    pos: usize,
    /// Size of the whole file (may exceed `d.len()` in prefix mode).
    total: u64,
    version: u32,
}

impl<'a> R<'a> {
    fn take(&mut self, n: u64) -> Result<&'a [u8], Halt> {
        let end = (self.pos as u64)
            .checked_add(n)
            .ok_or_else(|| Halt::Bad("length overflows".into()))?;
        if end > self.total {
            return Err(Halt::Bad(format!(
                "length {n} at offset {} runs past the end of the file",
                self.pos
            )));
        }
        if end > self.d.len() as u64 {
            return Err(Halt::Prefix);
        }
        let s = &self.d[self.pos..end as usize];
        self.pos = end as usize;
        Ok(s)
    }

    fn u32(&mut self) -> Result<u32, Halt> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("4")))
    }

    fn u64(&mut self) -> Result<u64, Halt> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("8")))
    }

    fn count(&mut self) -> Result<u64, Halt> {
        if self.version == 1 {
            Ok(self.u32()? as u64)
        } else {
            self.u64()
        }
    }

    fn string(&mut self) -> Result<&'a [u8], Halt> {
        let n = self.count()?;
        self.take(n)
    }

    fn remaining(&self) -> u64 {
        self.total.saturating_sub(self.pos as u64)
    }

    /// Read (or skip) a value of `ty`; strings are returned for chat templates.
    fn value(&mut self, ty: u32, depth: u8) -> Result<Option<&'a [u8]>, Halt> {
        match ty {
            0 | 1 | 7 => {
                self.take(1)?;
            }
            2 | 3 => {
                self.take(2)?;
            }
            4..=6 => {
                self.take(4)?;
            }
            10..=12 => {
                self.take(8)?;
            }
            8 => return Ok(Some(self.string()?)),
            9 => {
                if depth > 2 {
                    return Err(Halt::Bad("arrays nested deeper than 2".into()));
                }
                let et = self.u32()?;
                let n = self.count()?;
                let min = match et {
                    0 | 1 | 7 => 1,
                    2 | 3 => 2,
                    4..=6 => 4,
                    8..=12 => 8,
                    _ => return Err(Halt::Bad(format!("invalid array element type {et}"))),
                };
                if n.saturating_mul(min) > self.remaining() {
                    return Err(Halt::Bad(format!("array of {n} elements cannot fit in the file")));
                }
                if matches!(et, 8 | 9) {
                    for _ in 0..n {
                        self.value(et, depth + 1)?;
                    }
                } else {
                    self.take(n * min)?;
                }
            }
            t => return Err(Halt::Bad(format!("invalid value type {t}"))),
        }
        Ok(None)
    }
}

/// Validate a GGUF header. `total` is the full file size (equal to `d.len()` unless only a
/// prefix was downloaded).
pub fn check(d: &[u8], total: u64, loc: &str) -> (Vec<Finding>, GgufInfo) {
    let mut out = Vec::new();
    let mut info = GgufInfo::default();
    let res = parse(d, total, loc, &mut info, &mut out);
    match res {
        Ok(()) => {}
        Err(Halt::Prefix) => info.partial = true,
        Err(Halt::Bad(m)) => out.push(Finding::new(ids::GGUF_MALFORMED, m, loc)),
    }
    for (k, t) in &info.chat_templates {
        out.extend(jinja::check(t, k, loc));
    }
    (out, info)
}

fn parse(d: &[u8], total: u64, loc: &str, info: &mut GgufInfo, out: &mut Vec<Finding>) -> Result<(), Halt> {
    let mut r = R {
        d,
        pos: 0,
        total,
        version: 3,
    };
    if r.take(4)? != MAGIC {
        return Err(Halt::Bad("missing GGUF magic".into()));
    }
    info.version = r.u32()?;
    if !(1..=3).contains(&info.version) {
        return Err(Halt::Bad(format!("unsupported version {}", info.version)));
    }
    r.version = info.version;
    info.tensor_count = r.count()?;
    info.kv_count = r.count()?;
    // Each KV pair needs at least 4 + 4 + 1 bytes and each tensor info 4 + 4 + 4 + 8.
    if info.kv_count.saturating_mul(9) > r.remaining() || info.tensor_count.saturating_mul(20) > r.remaining() {
        return Err(Halt::Bad(format!(
            "{} key-value pairs and {} tensors cannot fit in {} bytes",
            info.kv_count, info.tensor_count, total
        )));
    }
    let mut seen = HashSet::new();
    let mut alignment = 32u64;
    for _ in 0..info.kv_count {
        let key = String::from_utf8_lossy(r.string()?).into_owned();
        let ty = r.u32()?;
        let v = r.value(ty, 0)?;
        if !seen.insert(key.clone()) {
            out.push(Finding::new(ids::GGUF_MALFORMED, format!("duplicate key {key:?}"), loc));
        }
        if key == "general.alignment" {
            // stored as uint32
            let a =
                r.d.get(r.pos - 4..r.pos)
                    .map(|b| u32::from_le_bytes(b.try_into().expect("4")) as u64);
            if ty == 4 {
                alignment = a.unwrap_or(32);
            }
            if alignment == 0 || !alignment.is_power_of_two() {
                return Err(Halt::Bad(format!("alignment {alignment} is not a power of two")));
            }
        }
        if key == "general.architecture" {
            info.architecture = v.map(|b| String::from_utf8_lossy(b).into_owned());
        }
        if key.starts_with("tokenizer.chat_template")
            && let Some(b) = v
        {
            info.chat_templates.push((key, String::from_utf8_lossy(b).into_owned()));
        }
    }
    let mut tensors = Vec::with_capacity(info.tensor_count.min(1 << 16) as usize);
    for _ in 0..info.tensor_count {
        let name = String::from_utf8_lossy(r.string()?).into_owned();
        let nd = r.u32()?;
        if nd > 4 {
            return Err(Halt::Bad(format!("tensor {name:?} has {nd} dimensions (at most 4)")));
        }
        let mut elems = 1u64;
        for _ in 0..nd {
            let dim = r.u64()?;
            elems = elems
                .checked_mul(dim)
                .filter(|&e| e <= i64::MAX as u64)
                .ok_or_else(|| Halt::Bad(format!("tensor {name:?} element count overflows")))?;
        }
        let ty = r.u32()?;
        let off = r.u64()?;
        if ty >= 64 {
            return Err(Halt::Bad(format!("tensor {name:?} has invalid type {ty}")));
        }
        if !off.is_multiple_of(alignment) {
            return Err(Halt::Bad(format!(
                "tensor {name:?} offset {off} is not aligned to {alignment}"
            )));
        }
        let size = type_size(ty).map(|(bs, ts)| elems.div_ceil(bs).saturating_mul(ts));
        tensors.push((name, off, size));
    }
    let data_start = (r.pos as u64).div_ceil(alignment) * alignment;
    let data_len = total.saturating_sub(data_start);
    tensors.sort_by_key(|t| t.1);
    let mut prev_end = 0u64;
    for (name, off, size) in &tensors {
        info.tensors_checked += 1;
        if *off < prev_end {
            out.push(Finding::new(
                ids::GGUF_MALFORMED,
                format!("tensor {name:?} overlaps the previous tensor"),
                loc,
            ));
        }
        if let Some(s) = size {
            let end = off.saturating_add(*s);
            if end > data_len {
                return Err(Halt::Bad(format!(
                    "tensor {name:?} data ends at {end}, past the {data_len} bytes of tensor data"
                )));
            }
            prev_end = end;
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub struct G {
        pub kv: Vec<u8>,
        pub nkv: u64,
        pub tensors: Vec<u8>,
        pub nt: u64,
    }

    impl G {
        pub fn new() -> Self {
            G {
                kv: Vec::new(),
                nkv: 0,
                tensors: Vec::new(),
                nt: 0,
            }
        }
        fn s(buf: &mut Vec<u8>, s: &str) {
            buf.extend_from_slice(&(s.len() as u64).to_le_bytes());
            buf.extend_from_slice(s.as_bytes());
        }
        pub fn kv_str(mut self, k: &str, v: &str) -> Self {
            Self::s(&mut self.kv, k);
            self.kv.extend_from_slice(&8u32.to_le_bytes());
            Self::s(&mut self.kv, v);
            self.nkv += 1;
            self
        }
        pub fn kv_u32(mut self, k: &str, v: u32) -> Self {
            Self::s(&mut self.kv, k);
            self.kv.extend_from_slice(&4u32.to_le_bytes());
            self.kv.extend_from_slice(&v.to_le_bytes());
            self.nkv += 1;
            self
        }
        pub fn kv_str_array(mut self, k: &str, items: &[&str]) -> Self {
            Self::s(&mut self.kv, k);
            self.kv.extend_from_slice(&9u32.to_le_bytes());
            self.kv.extend_from_slice(&8u32.to_le_bytes());
            self.kv.extend_from_slice(&(items.len() as u64).to_le_bytes());
            for i in items {
                Self::s(&mut self.kv, i);
            }
            self.nkv += 1;
            self
        }
        pub fn tensor(mut self, name: &str, dims: &[u64], ty: u32, off: u64) -> Self {
            Self::s(&mut self.tensors, name);
            self.tensors.extend_from_slice(&(dims.len() as u32).to_le_bytes());
            for d in dims {
                self.tensors.extend_from_slice(&d.to_le_bytes());
            }
            self.tensors.extend_from_slice(&ty.to_le_bytes());
            self.tensors.extend_from_slice(&off.to_le_bytes());
            self.nt += 1;
            self
        }
        pub fn build(self, data: usize) -> Vec<u8> {
            let mut out = MAGIC.to_vec();
            out.extend_from_slice(&3u32.to_le_bytes());
            out.extend_from_slice(&self.nt.to_le_bytes());
            out.extend_from_slice(&self.nkv.to_le_bytes());
            out.extend(self.kv);
            out.extend(self.tensors);
            while !out.len().is_multiple_of(32) {
                out.push(0);
            }
            out.extend(std::iter::repeat_n(0u8, data));
            out
        }
    }

    fn run(d: &[u8]) -> Vec<Finding> {
        check(d, d.len() as u64, "m.gguf").0
    }

    #[test]
    fn valid_file_with_template() {
        let d = G::new()
            .kv_str("general.architecture", "llama")
            .kv_u32("general.alignment", 32)
            .kv_str_array("tokenizer.ggml.tokens", &["a", "b"])
            .kv_str("tokenizer.chat_template", "{{ messages[0]['content'] }}")
            .tensor("w", &[4, 4], 0, 0)
            .tensor("b", &[4], 0, 64)
            .build(80);
        let (f, info) = check(&d, d.len() as u64, "m.gguf");
        assert!(f.is_empty(), "{f:?}");
        assert_eq!(info.architecture.as_deref(), Some("llama"));
        assert_eq!(info.tensors_checked, 2);
        assert!(is_gguf(&d));
    }

    #[test]
    fn template_injection() {
        let d = G::new()
            .kv_str(
                "tokenizer.chat_template",
                "{{ cycler.__init__.__globals__.os.getcwd() }}",
            )
            .build(0);
        assert_eq!(run(&d)[0].rule, ids::GGUF_TEMPLATE_INJECTION);
        let d = G::new()
            .kv_str("tokenizer.chat_template.tool_use", "{{ x.__class__ }}")
            .build(0);
        assert_eq!(run(&d)[0].rule, ids::GGUF_TEMPLATE_INJECTION);
    }

    #[test]
    fn structural_problems() {
        let cases = [
            G::new().tensor("w", &[4], 0, 0).build(4),
            G::new().tensor("w", &[1, 1, 1, 1, 1], 0, 0).build(64),
            G::new().tensor("w", &[u64::MAX, 4], 0, 0).build(64),
            G::new().tensor("w", &[4], 99, 0).build(64),
            G::new().tensor("w", &[4], 0, 3).build(64),
            G::new().kv_u32("general.alignment", 3).build(0),
        ];
        for d in cases {
            assert_eq!(run(&d)[0].rule, ids::GGUF_MALFORMED);
        }
        let dup = G::new().kv_u32("a", 1).kv_u32("a", 2).build(0);
        assert!(run(&dup)[0].message.contains("duplicate"));
        let overlap = G::new().tensor("a", &[16], 0, 0).tensor("b", &[16], 0, 32).build(128);
        assert!(run(&overlap)[0].message.contains("overlaps"));
        let mut huge = MAGIC.to_vec();
        huge.extend_from_slice(&3u32.to_le_bytes());
        huge.extend_from_slice(&u64::MAX.to_le_bytes());
        huge.extend_from_slice(&0u64.to_le_bytes());
        assert!(run(&huge)[0].message.contains("cannot fit"));
        let mut v9 = MAGIC.to_vec();
        v9.extend_from_slice(&9u32.to_le_bytes());
        assert!(run(&v9)[0].message.contains("version"));
        assert!(run(b"GGUX")[0].message.contains("magic") || run(b"GGUX")[0].message.contains("past"));
    }

    #[test]
    fn bad_values() {
        let mut d = MAGIC.to_vec();
        d.extend_from_slice(&3u32.to_le_bytes());
        d.extend_from_slice(&0u64.to_le_bytes());
        d.extend_from_slice(&1u64.to_le_bytes());
        d.extend_from_slice(&1u64.to_le_bytes());
        d.push(b'k');
        d.extend_from_slice(&77u32.to_le_bytes());
        d.extend_from_slice(&[0; 16]);
        assert!(run(&d)[0].message.contains("invalid value type"));
        let arr = G::new().kv_str_array("k", &["x"]).build(0);
        let mut bad = arr.clone();
        // element type 8 -> 99
        let pos = bad.windows(4).position(|w| w == 8u32.to_le_bytes()).unwrap();
        bad[pos] = 99;
        let f = run(&bad);
        assert!(f[0].message.contains("element type"), "{f:?}");
    }

    #[test]
    fn prefix_mode_stops_quietly() {
        let d = G::new()
            .kv_str_array("tokenizer.ggml.tokens", &["a"; 100])
            .kv_str("tokenizer.chat_template", "{{ x }}")
            .tensor("w", &[4], 0, 0)
            .build(16);
        let (f, info) = check(&d[..60], d.len() as u64, "m.gguf");
        assert!(f.is_empty(), "{f:?}");
        assert!(info.partial);
        let (f, info) = check(&d[..60], 60, "m.gguf");
        assert!(!f.is_empty());
        assert!(!info.partial);
    }

    #[test]
    fn version_one_uses_32_bit_counts() {
        let mut d = MAGIC.to_vec();
        d.extend_from_slice(&1u32.to_le_bytes());
        d.extend_from_slice(&0u32.to_le_bytes());
        d.extend_from_slice(&1u32.to_le_bytes());
        d.extend_from_slice(&1u32.to_le_bytes());
        d.push(b'k');
        d.extend_from_slice(&4u32.to_le_bytes());
        d.extend_from_slice(&5u32.to_le_bytes());
        let (f, info) = check(&d, d.len() as u64, "m");
        assert!(f.is_empty(), "{f:?}");
        assert_eq!(info.kv_count, 1);
    }
}
