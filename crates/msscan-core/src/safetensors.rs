//! safetensors headers: the same checks the reference loader makes, reported instead of raised.

use crate::finding::{ids, Finding};
use serde::de::{Deserializer, MapAccess, Visitor};
use serde_json::Value;
use std::fmt;

/// The reference implementation refuses headers above 100 MB.
pub const MAX_HEADER: u64 = 100_000_000;

/// Bits per element for known dtypes.
fn dtype_bits(d: &str) -> Option<u64> {
    Some(match d {
        "BOOL" | "U8" | "I8" | "F8_E4M3" | "F8_E5M2" | "F8_E8M0" => 8,
        "I16" | "U16" | "F16" | "BF16" => 16,
        "I32" | "U32" | "F32" => 32,
        "I64" | "U64" | "F64" | "C64" => 64,
        "F4" => 4,
        "F6_E2M3" | "F6_E3M2" => 6,
        _ => return None,
    })
}

/// Header map entries in file order, keeping duplicates.
struct Pairs(Vec<(String, Value)>);

impl<'de> serde::Deserialize<'de> for Pairs {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Pairs;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Pairs, A::Error> {
                let mut v = Vec::new();
                while let Some(kv) = m.next_entry::<String, Value>()? {
                    v.push(kv);
                }
                Ok(Pairs(v))
            }
        }
        d.deserialize_map(V)
    }
}

/// Header length from the first 8 bytes, if the buffer could be a safetensors file.
pub fn header_len(d: &[u8]) -> Option<u64> {
    let n = u64::from_le_bytes(d.get(..8)?.try_into().ok()?);
    (d.get(8) == Some(&b'{')).then_some(n)
}

pub fn is_safetensors(d: &[u8]) -> bool {
    header_len(d).is_some_and(|n| n >= 2)
}

#[derive(Debug, Default)]
pub struct Info {
    pub tensors: u64,
    pub header_len: u64,
    pub metadata_keys: u64,
    /// Only part of the header was supplied (headers-only scanning with a short prefix).
    pub partial: bool,
}

/// Validate the header against `total`, the size of the whole file.
pub fn check(d: &[u8], total: u64, loc: &str) -> (Vec<Finding>, Info) {
    let mut out = Vec::new();
    let mut info = Info::default();
    let bad = |m: String| Finding::new(ids::SAFETENSORS_HEADER, m, loc);
    let Some(n) = d.get(..8).map(|b| u64::from_le_bytes(b.try_into().expect("8"))) else {
        out.push(bad("file is shorter than the 8-byte header length".into()));
        return (out, info);
    };
    info.header_len = n;
    if n > MAX_HEADER {
        out.push(bad(format!("header length {n} exceeds the 100 MB limit")));
        return (out, info);
    }
    if 8 + n > total {
        out.push(bad(format!(
            "header length {n} runs past the end of the {total}-byte file"
        )));
        return (out, info);
    }
    let Some(raw) = d.get(8..8 + n as usize) else {
        info.partial = true;
        return (out, info);
    };
    let Ok(text) = std::str::from_utf8(raw) else {
        out.push(bad("header is not valid UTF-8".into()));
        return (out, info);
    };
    if !text.starts_with('{') {
        out.push(bad("header does not start with '{'".into()));
        return (out, info);
    }
    let pairs: Pairs = match serde_json::from_str(text.trim_end_matches(' ')) {
        Ok(p) => p,
        Err(e) => {
            out.push(bad(format!("header is not a JSON object: {e}")));
            return (out, info);
        }
    };
    let mut names = std::collections::HashSet::new();
    let mut spans: Vec<(u64, u64, String)> = Vec::new();
    for (k, v) in &pairs.0 {
        if !names.insert(k.as_str()) {
            out.push(bad(format!("duplicate key {k:?}")));
        }
        if k == "__metadata__" {
            match v.as_object() {
                Some(m) => {
                    info.metadata_keys = m.len() as u64;
                    if m.values().any(|x| !x.is_string()) {
                        out.push(Finding::new(
                            ids::SAFETENSORS_METADATA,
                            "__metadata__ holds non-string values",
                            loc,
                        ));
                    }
                }
                None => out.push(Finding::new(
                    ids::SAFETENSORS_METADATA,
                    "__metadata__ is not an object",
                    loc,
                )),
            }
            continue;
        }
        info.tensors += 1;
        let dtype = v.get("dtype").and_then(Value::as_str);
        let shape: Option<Vec<u64>> = v
            .get("shape")
            .and_then(Value::as_array)
            .and_then(|a| a.iter().map(Value::as_u64).collect());
        let offs: Option<Vec<u64>> = v
            .get("data_offsets")
            .and_then(Value::as_array)
            .and_then(|a| a.iter().map(Value::as_u64).collect());
        let (Some(dtype), Some(shape), Some(offs)) = (dtype, shape, offs) else {
            out.push(bad(format!("tensor {k:?} lacks a valid dtype, shape or data_offsets")));
            continue;
        };
        if offs.len() != 2 || offs[0] > offs[1] {
            out.push(Finding::new(
                ids::SAFETENSORS_OFFSETS,
                format!("tensor {k:?} has data_offsets {offs:?}"),
                loc,
            ));
            continue;
        }
        match dtype_bits(dtype) {
            None => out.push(Finding::new(
                ids::SAFETENSORS_METADATA,
                format!("tensor {k:?} has unknown dtype {dtype}"),
                loc,
            )),
            Some(bits) => {
                let want = shape
                    .iter()
                    .try_fold(1u64, |a, &b| a.checked_mul(b))
                    .and_then(|e| e.checked_mul(bits))
                    .map(|b| b.div_ceil(8));
                if want != Some(offs[1] - offs[0]) {
                    out.push(Finding::new(
                        ids::SAFETENSORS_OFFSETS,
                        format!(
                            "tensor {k:?} spans {} bytes but shape {shape:?} of {dtype} needs {}",
                            offs[1] - offs[0],
                            want.map_or("an overflowing number of".to_string(), |w| w.to_string())
                        ),
                        loc,
                    ));
                }
            }
        }
        spans.push((offs[0], offs[1], k.clone()));
    }
    spans.sort();
    let data_len = total - 8 - n;
    let mut end = 0u64;
    for (s, e, k) in &spans {
        if *s != end {
            let what = if *s < end {
                "overlaps the previous tensor"
            } else {
                "leaves a gap before it"
            };
            out.push(Finding::new(
                ids::SAFETENSORS_OFFSETS,
                format!("tensor {k:?} {what}"),
                loc,
            ));
        }
        end = end.max(*e);
    }
    if end != data_len {
        out.push(Finding::new(
            ids::SAFETENSORS_OFFSETS,
            format!("tensors cover {end} bytes but the file holds {data_len} bytes of data"),
            loc,
        ));
    }
    (out, info)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn st(header: &str, data: usize) -> Vec<u8> {
        let mut out = (header.len() as u64).to_le_bytes().to_vec();
        out.extend_from_slice(header.as_bytes());
        out.extend(std::iter::repeat_n(0u8, data));
        out
    }

    fn run(d: &[u8]) -> Vec<Finding> {
        check(d, d.len() as u64, "m.safetensors").0
    }

    #[test]
    fn valid_files() {
        let h = r#"{"__metadata__":{"format":"pt"},"a":{"dtype":"F32","shape":[2,2],"data_offsets":[0,16]},"b":{"dtype":"BF16","shape":[3],"data_offsets":[16,22]}}  "#;
        let d = st(h, 22);
        assert!(is_safetensors(&d));
        let (f, info) = check(&d, d.len() as u64, "x");
        assert!(f.is_empty(), "{f:?}");
        assert_eq!(info.tensors, 2);
        assert_eq!(info.metadata_keys, 1);
        // prefix mode: only the header was downloaded
        let (f, _) = check(&d[..8 + h.len()], d.len() as u64, "x");
        assert!(f.is_empty());
        let (f, info) = check(&d[..20], d.len() as u64, "x");
        assert!(f.is_empty() && info.partial);
        assert!(run(&st("{}", 0)).is_empty());
    }

    #[test]
    fn header_problems() {
        assert_eq!(run(b"\x01")[0].rule, ids::SAFETENSORS_HEADER);
        let mut big = u64::MAX.to_le_bytes().to_vec();
        big.push(b'{');
        assert!(run(&big)[0].message.contains("100 MB"));
        let mut past = 50u64.to_le_bytes().to_vec();
        past.extend_from_slice(b"{}");
        assert!(run(&past)[0].message.contains("past the end"));
        assert!(run(&st("[1,2]", 0))[0].message.contains("start"));
        assert!(run(&st("{\"a\":", 0))[0].message.contains("JSON"));
        let mut bad_utf8 = st("{\"\u{e9}\":1}", 0);
        bad_utf8[11] = 0xff;
        assert!(run(&bad_utf8)[0].message.contains("UTF-8"));
        let dup = r#"{"a":{"dtype":"U8","shape":[1],"data_offsets":[0,1]},"a":{"dtype":"U8","shape":[1],"data_offsets":[1,2]}}"#;
        assert!(run(&st(dup, 2)).iter().any(|f| f.message.contains("duplicate")));
        assert!(run(&st(r#"{"a":{"dtype":"U8"}}"#, 0))[0].message.contains("lacks"));
    }

    #[test]
    fn offset_problems() {
        let overlap = r#"{"a":{"dtype":"U8","shape":[4],"data_offsets":[0,4]},"b":{"dtype":"U8","shape":[4],"data_offsets":[2,6]}}"#;
        assert!(run(&st(overlap, 6)).iter().any(|f| f.message.contains("overlaps")));
        let gap = r#"{"a":{"dtype":"U8","shape":[2],"data_offsets":[0,2]},"b":{"dtype":"U8","shape":[2],"data_offsets":[4,6]}}"#;
        assert!(run(&st(gap, 6)).iter().any(|f| f.message.contains("gap")));
        let size = r#"{"a":{"dtype":"F32","shape":[2],"data_offsets":[0,4]}}"#;
        assert!(run(&st(size, 4)).iter().any(|f| f.message.contains("needs")));
        let past = r#"{"a":{"dtype":"U8","shape":[8],"data_offsets":[0,8]}}"#;
        assert!(run(&st(past, 4)).iter().any(|f| f.message.contains("cover")));
        let rev = r#"{"a":{"dtype":"U8","shape":[1],"data_offsets":[3,1]}}"#;
        assert_eq!(run(&st(rev, 3))[0].rule, ids::SAFETENSORS_OFFSETS);
        let unk = r#"{"__metadata__":{"x":1},"a":{"dtype":"Q9","shape":[1],"data_offsets":[0,1]}}"#;
        let f = run(&st(unk, 1));
        assert_eq!(f.iter().filter(|f| f.rule == ids::SAFETENSORS_METADATA).count(), 2);
        assert_eq!(
            run(&st(r#"{"__metadata__":[1]}"#, 0))[0].rule,
            ids::SAFETENSORS_METADATA
        );
    }
}
