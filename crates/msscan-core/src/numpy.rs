//! NumPy `.npy` headers: format version, dtype, shape, and the pickle inside object arrays.

use crate::finding::{ids, Finding};

pub const MAGIC: &[u8] = b"\x93NUMPY";

#[derive(Debug, Clone, PartialEq)]
pub struct Header {
    pub version: (u8, u8),
    pub descr: String,
    pub fortran_order: bool,
    pub shape: Vec<u64>,
    /// Offset of the array data.
    pub data_offset: usize,
    pub has_object: bool,
    /// Bytes per element when the dtype is a simple string descriptor.
    pub itemsize: Option<u64>,
}

pub fn is_npy(d: &[u8]) -> bool {
    d.starts_with(MAGIC)
}

/// Parse a `.npy` header; the error is a human-readable reason.
pub fn parse(d: &[u8]) -> Result<Header, String> {
    if !is_npy(d) || d.len() < 10 {
        return Err("missing \\x93NUMPY magic".into());
    }
    let version = (d[6], d[7]);
    let (hlen, start) = match version.0 {
        1 => (u16::from_le_bytes([d[8], d[9]]) as usize, 10),
        2 | 3 => {
            let b = d.get(8..12).ok_or("truncated header length")?;
            (u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize, 12)
        }
        v => return Err(format!("unsupported format version {v}")),
    };
    let text = d
        .get(start..start + hlen)
        .ok_or("header runs past the end of the file")?;
    let text = std::str::from_utf8(text).map_err(|_| "header is not valid text")?;
    let descr_raw = dict_value(text, "descr").ok_or("header has no descr")?;
    let fortran = dict_value(text, "fortran_order").ok_or("header has no fortran_order")?;
    let shape_raw = dict_value(text, "shape").ok_or("header has no shape")?;
    let shape = parse_shape(&shape_raw).ok_or("invalid shape")?;
    let descr = unquote(&descr_raw).unwrap_or_else(|| descr_raw.clone());
    let has_object = descr_has_object(&descr_raw);
    let itemsize = unquote(&descr_raw).and_then(|s| itemsize(&s));
    Ok(Header {
        version,
        descr,
        fortran_order: fortran.trim() == "True",
        shape,
        data_offset: start + hlen,
        has_object,
        itemsize,
    })
}

/// Find the value text for `'key':` in a Python dict literal, up to the matching delimiter.
fn dict_value(text: &str, key: &str) -> Option<String> {
    let pats = [format!("'{key}'"), format!("\"{key}\"")];
    let at = pats.iter().find_map(|p| text.find(p.as_str()).map(|i| i + p.len()))?;
    let rest = text[at..].trim_start().strip_prefix(':')?.trim_start();
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    for (i, c) in rest.char_indices() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None => match c {
                '\'' | '"' => quote = Some(c),
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' if depth > 0 => depth -= 1,
                ',' | '}' if depth == 0 => return Some(rest[..i].trim().to_string()),
                _ => {}
            },
        }
    }
    None
}

fn unquote(s: &str) -> Option<String> {
    let s = s.trim();
    let q = s.chars().next()?;
    if (q == '\'' || q == '"') && s.len() >= 2 && s.ends_with(q) {
        Some(s[1..s.len() - 1].to_string())
    } else {
        None
    }
}

fn parse_shape(s: &str) -> Option<Vec<u64>> {
    let inner = s.trim().strip_prefix('(')?.strip_suffix(')')?;
    inner
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| p.trim_end_matches('L').parse::<u64>().ok())
        .collect()
}

fn descr_has_object(raw: &str) -> bool {
    // Simple descriptors ('|O') and structured ones ([('a', '|O'), ...]) both quote the type.
    raw.split(['\'', '"']).enumerate().any(|(i, part)| {
        i % 2 == 1 && {
            let t = part.trim_start_matches(['<', '>', '|', '=']);
            t.starts_with('O')
        }
    })
}

/// Element size for a simple descriptor such as `<f4`, `|b1`, `<U10` or `<M8[ns]`.
pub fn itemsize(descr: &str) -> Option<u64> {
    let t = descr.trim_start_matches(['<', '>', '|', '=']);
    let kind = t.chars().next()?;
    let digits: String = t[1..].chars().take_while(|c| c.is_ascii_digit()).collect();
    let n: u64 = digits.parse().ok()?;
    match kind {
        'U' => n.checked_mul(4),
        'b' | 'i' | 'u' | 'f' | 'c' | 'S' | 'a' | 'V' | 'M' | 'm' => Some(n),
        _ => None,
    }
}

/// Result of checking one `.npy` buffer.
pub struct NpyCheck {
    pub header: Option<Header>,
    pub findings: Vec<Finding>,
    /// Where the embedded pickle starts, for object arrays.
    pub pickle_offset: Option<usize>,
}

/// Validate the header and size; report object arrays (the caller scans the pickle).
pub fn check(d: &[u8], loc: &str) -> NpyCheck {
    let mut findings = Vec::new();
    let h = match parse(d) {
        Ok(h) => h,
        Err(e) => {
            findings.push(Finding::new(ids::NUMPY_MALFORMED, e, loc));
            return NpyCheck {
                header: None,
                findings,
                pickle_offset: None,
            };
        }
    };
    let mut pickle_offset = None;
    if h.has_object {
        findings.push(Finding::new(
            ids::NUMPY_OBJECT_ARRAY,
            format!(
                "dtype {} holds Python objects; numpy.load(allow_pickle=True) unpickles them",
                h.descr
            ),
            loc,
        ));
        pickle_offset = Some(h.data_offset);
    } else if let Some(item) = h.itemsize {
        let count = h.shape.iter().try_fold(1u64, |a, &b| a.checked_mul(b));
        let want = count.and_then(|c| c.checked_mul(item));
        let have = (d.len() - h.data_offset.min(d.len())) as u64;
        if want != Some(have) {
            findings.push(Finding::new(
                ids::NUMPY_MALFORMED,
                format!(
                    "shape {:?} with dtype {} needs {} bytes but the file holds {have}",
                    h.shape,
                    h.descr,
                    want.map(|w| w.to_string())
                        .unwrap_or_else(|| "an overflowing number of".into())
                ),
                loc,
            ));
        }
    }
    NpyCheck {
        header: Some(h),
        findings,
        pickle_offset,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn npy(descr: &str, shape: &str, body: &[u8]) -> Vec<u8> {
        let mut h = format!("{{'descr': {descr}, 'fortran_order': False, 'shape': {shape}, }}");
        while (10 + h.len() + 1) % 64 != 0 {
            h.push(' ');
        }
        h.push('\n');
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&[1, 0]);
        out.extend_from_slice(&(h.len() as u16).to_le_bytes());
        out.extend_from_slice(h.as_bytes());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn numeric_array_ok_and_size_checked() {
        let d = npy("'<f4'", "(2, 3)", &[0u8; 24]);
        let c = check(&d, "a.npy");
        assert!(c.findings.is_empty(), "{:?}", c.findings);
        let h = c.header.unwrap();
        assert_eq!(h.shape, vec![2, 3]);
        assert_eq!(h.itemsize, Some(4));
        assert!(!h.fortran_order);
        let c = check(&npy("'<f4'", "(2, 3)", &[0u8; 20]), "a.npy");
        assert_eq!(c.findings[0].rule, ids::NUMPY_MALFORMED);
        let c = check(&npy("'<f8'", "()", &[0u8; 8]), "a.npy");
        assert!(c.findings.is_empty());
        let c = check(&npy("'<U3'", "(1,)", &[0u8; 12]), "a.npy");
        assert!(c.findings.is_empty());
    }

    #[test]
    fn object_arrays_point_at_the_pickle() {
        let d = npy("'|O'", "(1,)", b"\x80\x02N.");
        let c = check(&d, "a.npy");
        assert_eq!(c.findings[0].rule, ids::NUMPY_OBJECT_ARRAY);
        assert_eq!(&d[c.pickle_offset.unwrap()..], b"\x80\x02N.");
        let s = npy("[('a', '<i4'), ('b', '|O')]", "(1,)", b"\x80\x02N.");
        assert!(check(&s, "s.npy").header.unwrap().has_object);
    }

    #[test]
    fn malformed_headers() {
        assert!(parse(b"\x93NUMPY").is_err());
        assert!(parse(b"\x93NUMPY\x09\x00\x00\x00").is_err());
        assert!(parse(b"\x93NUMPY\x01\x00\xff\x00{").is_err());
        let d = npy("'<f4'", "(a,)", b"");
        assert!(check(&d, "x").findings[0].message.contains("shape"));
        let mut v2 = MAGIC.to_vec();
        v2.extend_from_slice(&[2, 0]);
        let h = b"{'descr': '<i8', 'fortran_order': True, 'shape': (1,), }\n";
        v2.extend_from_slice(&(h.len() as u32).to_le_bytes());
        v2.extend_from_slice(h);
        v2.extend_from_slice(&[0; 8]);
        let c = check(&v2, "x");
        assert!(c.findings.is_empty());
        assert!(c.header.unwrap().fortran_order);
        assert_eq!(itemsize("|b1"), Some(1));
        assert_eq!(itemsize("<M8[ns]"), Some(8));
        assert_eq!(itemsize("O"), None);
    }
}
