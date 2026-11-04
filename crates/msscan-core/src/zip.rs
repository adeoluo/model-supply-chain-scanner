//! A zip reader that trusts nothing: it reads the central directory, cross-checks every local
//! header, and reports traversal names, encryption, unsupported methods and size limits.

use crate::finding::{ids, Finding};
use std::io::Read;

#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub name: String,
    pub method: u16,
    pub flags: u16,
    pub compressed_size: u64,
    pub size: u64,
    pub local_offset: u64,
    /// Start of the entry data (after the local header), when the local header is valid.
    pub data_offset: Option<u64>,
}

impl Entry {
    pub fn is_dir(&self) -> bool {
        self.name.ends_with('/')
    }

    pub fn encrypted(&self) -> bool {
        self.flags & 1 != 0
    }
}

#[derive(Debug, Default)]
pub struct Archive {
    pub entries: Vec<Entry>,
    pub findings: Vec<Finding>,
}

fn u16_at(d: &[u8], o: usize) -> Option<u16> {
    d.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn u64_at(d: &[u8], o: usize) -> Option<u64> {
    d.get(o..o + 8).map(|b| {
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        u64::from_le_bytes(a)
    })
}

pub fn is_zip(d: &[u8]) -> bool {
    d.starts_with(b"PK\x03\x04") || d.starts_with(b"PK\x05\x06")
}

/// Whether an entry name escapes the extraction root.
pub fn is_traversal(name: &str) -> bool {
    let n = name.replace('\\', "/");
    if n.starts_with('/') || n.as_bytes().get(1) == Some(&b':') {
        return true;
    }
    n.split('/').any(|p| p == "..")
}

fn find_eocd(d: &[u8]) -> Option<usize> {
    if d.len() < 22 {
        return None;
    }
    let lo = d.len().saturating_sub(22 + 65535);
    (lo..=d.len() - 22).rev().find(|&i| &d[i..i + 4] == b"PK\x05\x06")
}

/// Parse an archive held in memory.
pub fn read(d: &[u8], loc: &str) -> Archive {
    let mut a = Archive::default();
    let Some(eocd) = find_eocd(d) else {
        a.findings.push(Finding::new(
            ids::ARCHIVE_MALFORMED,
            "no end of central directory record; entries recovered from local headers",
            loc,
        ));
        a.entries = walk_local_headers(d);
        return a;
    };
    let mut count = u16_at(d, eocd + 10).unwrap_or(0) as u64;
    let mut cd_off = u32_at(d, eocd + 16).unwrap_or(0) as u64;
    if count == 0xffff || cd_off == 0xffff_ffff {
        // ZIP64 end of central directory locator sits right before the EOCD record.
        if eocd >= 20 && &d[eocd - 20..eocd - 16] == b"PK\x06\x07" {
            if let Some(rec) = u64_at(d, eocd - 12).and_then(|o| usize::try_from(o).ok()) {
                if d.get(rec..rec + 4) == Some(b"PK\x06\x06") {
                    count = u64_at(d, rec + 32).unwrap_or(count);
                    cd_off = u64_at(d, rec + 48).unwrap_or(cd_off);
                }
            }
        }
    }
    let mut p = cd_off as usize;
    for _ in 0..count.min(1_000_000) {
        if d.get(p..p + 4) != Some(b"PK\x01\x02") {
            a.findings.push(Finding::new(
                ids::ARCHIVE_MALFORMED,
                "central directory entry signature missing",
                format!("{loc}@{p}"),
            ));
            break;
        }
        let (Some(flags), Some(method), Some(csize), Some(usize_), Some(nlen), Some(xlen), Some(clen), Some(loff)) = (
            u16_at(d, p + 8),
            u16_at(d, p + 10),
            u32_at(d, p + 20),
            u32_at(d, p + 24),
            u16_at(d, p + 28),
            u16_at(d, p + 30),
            u16_at(d, p + 32),
            u32_at(d, p + 42),
        ) else {
            a.findings.push(Finding::new(
                ids::ARCHIVE_MALFORMED,
                "truncated central directory",
                format!("{loc}@{p}"),
            ));
            break;
        };
        let name_start = p + 46;
        let Some(name) = d.get(name_start..name_start + nlen as usize) else {
            a.findings.push(Finding::new(
                ids::ARCHIVE_MALFORMED,
                "truncated central directory",
                format!("{loc}@{p}"),
            ));
            break;
        };
        let name = String::from_utf8_lossy(name).into_owned();
        let extra = d
            .get(name_start + nlen as usize..name_start + nlen as usize + xlen as usize)
            .unwrap_or(&[]);
        let (mut size, mut compressed_size, mut local_offset) = (usize_ as u64, csize as u64, loff as u64);
        apply_zip64(extra, &mut size, &mut compressed_size, &mut local_offset);
        let mut e = Entry {
            name,
            method,
            flags,
            compressed_size,
            size,
            local_offset,
            data_offset: None,
        };
        check_local(d, &mut e, loc, &mut a.findings);
        a.entries.push(e);
        p = name_start + nlen as usize + xlen as usize + clen as usize;
    }
    for e in &a.entries {
        if is_traversal(&e.name) {
            a.findings.push(Finding::new(
                ids::ARCHIVE_TRAVERSAL,
                format!("entry name {:?}", e.name),
                loc,
            ));
        }
        if e.encrypted() {
            a.findings.push(Finding::new(
                ids::ARCHIVE_ENCRYPTED,
                format!("entry {:?} is encrypted", e.name),
                loc,
            ));
        }
    }
    a
}

fn apply_zip64(extra: &[u8], size: &mut u64, csize: &mut u64, off: &mut u64) {
    let mut i = 0;
    while i + 4 <= extra.len() {
        let id = u16::from_le_bytes([extra[i], extra[i + 1]]);
        let len = u16::from_le_bytes([extra[i + 2], extra[i + 3]]) as usize;
        let body = extra.get(i + 4..i + 4 + len).unwrap_or(&[]);
        if id == 1 {
            let mut j = 0;
            for v in [&mut *size, &mut *csize, &mut *off] {
                if *v == 0xffff_ffff {
                    if let Some(x) = u64_at(body, j) {
                        *v = x;
                        j += 8;
                    }
                }
            }
        }
        i += 4 + len;
    }
}

fn check_local(d: &[u8], e: &mut Entry, loc: &str, findings: &mut Vec<Finding>) {
    let o = match usize::try_from(e.local_offset) {
        Ok(o) if d.get(o..o + 4) == Some(b"PK\x03\x04") => o,
        _ => {
            findings.push(Finding::new(
                ids::ARCHIVE_MALFORMED,
                format!("entry {:?} points to a missing local header", e.name),
                loc,
            ));
            return;
        }
    };
    let (Some(flags), Some(method), Some(nlen), Some(xlen)) =
        (u16_at(d, o + 6), u16_at(d, o + 8), u16_at(d, o + 26), u16_at(d, o + 28))
    else {
        return;
    };
    let lname = d
        .get(o + 30..o + 30 + nlen as usize)
        .map(|n| String::from_utf8_lossy(n).into_owned());
    let mut diffs = Vec::new();
    if lname.as_deref() != Some(e.name.as_str()) {
        diffs.push(format!("name {:?} vs {:?}", lname.unwrap_or_default(), e.name));
    }
    if method != e.method {
        diffs.push(format!("method {method} vs {}", e.method));
    }
    if (flags & 1) != (e.flags & 1) {
        diffs.push("encryption flag".to_string());
    }
    if !diffs.is_empty() {
        findings.push(Finding::new(
            ids::ARCHIVE_HEADER_MISMATCH,
            format!(
                "local header disagrees with the central directory for {:?}: {}",
                e.name,
                diffs.join(", ")
            ),
            format!("{loc}@{o}"),
        ));
    }
    e.data_offset = Some((o + 30 + nlen as usize + xlen as usize) as u64);
}

fn walk_local_headers(d: &[u8]) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut o = 0usize;
    while d.get(o..o + 4) == Some(b"PK\x03\x04") && out.len() < 100_000 {
        let (Some(flags), Some(method), Some(csize), Some(size), Some(nlen), Some(xlen)) = (
            u16_at(d, o + 6),
            u16_at(d, o + 8),
            u32_at(d, o + 18),
            u32_at(d, o + 22),
            u16_at(d, o + 26),
            u16_at(d, o + 28),
        ) else {
            break;
        };
        let name = d
            .get(o + 30..o + 30 + nlen as usize)
            .map(|n| String::from_utf8_lossy(n).into_owned())
            .unwrap_or_default();
        let data = o + 30 + nlen as usize + xlen as usize;
        if flags & 8 != 0 {
            // Sizes are in a trailing data descriptor; we cannot walk past this entry reliably.
            out.push(Entry {
                name,
                method,
                flags,
                compressed_size: 0,
                size: 0,
                local_offset: o as u64,
                data_offset: Some(data as u64),
            });
            break;
        }
        out.push(Entry {
            name,
            method,
            flags,
            compressed_size: csize as u64,
            size: size as u64,
            local_offset: o as u64,
            data_offset: Some(data as u64),
        });
        o = data + csize as usize;
    }
    out
}

/// Errors when extracting an entry.
#[derive(Debug, PartialEq)]
pub enum ExtractError {
    OutOfBounds,
    Unsupported(u16),
    Encrypted,
    TooLarge(u64),
    Corrupt,
}

/// Borrow or inflate an entry's bytes, never producing more than `limit` bytes.
pub fn extract<'a>(d: &'a [u8], e: &Entry, limit: u64) -> Result<std::borrow::Cow<'a, [u8]>, ExtractError> {
    if e.encrypted() {
        return Err(ExtractError::Encrypted);
    }
    let start = e.data_offset.ok_or(ExtractError::OutOfBounds)? as usize;
    let end = start
        .checked_add(e.compressed_size as usize)
        .ok_or(ExtractError::OutOfBounds)?;
    let raw = d.get(start..end).ok_or(ExtractError::OutOfBounds)?;
    match e.method {
        0 => Ok(std::borrow::Cow::Borrowed(raw)),
        8 => {
            let mut out = Vec::new();
            let mut r = flate2::read::DeflateDecoder::new(raw).take(limit + 1);
            r.read_to_end(&mut out).map_err(|_| ExtractError::Corrupt)?;
            if out.len() as u64 > limit {
                return Err(ExtractError::TooLarge(limit));
            }
            Ok(std::borrow::Cow::Owned(out))
        }
        m => Err(ExtractError::Unsupported(m)),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;

    /// Build a zip in memory: (name, data, deflate).
    pub fn build(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
        build_with(entries, |_, _| {})
    }

    /// Same as `build`, with a hook to tamper with each local header name.
    pub fn build_with(entries: &[(&str, &[u8], bool)], tamper: impl Fn(usize, &mut Vec<u8>)) -> Vec<u8> {
        let mut out = Vec::new();
        let mut cd = Vec::new();
        for (i, (name, data, deflate)) in entries.iter().enumerate() {
            let body = if *deflate {
                let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
                enc.write_all(data).unwrap();
                enc.finish().unwrap()
            } else {
                data.to_vec()
            };
            let method: u16 = if *deflate { 8 } else { 0 };
            let off = out.len() as u32;
            let mut lname = name.as_bytes().to_vec();
            tamper(i, &mut lname);
            out.extend_from_slice(b"PK\x03\x04");
            out.extend_from_slice(&20u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&[0; 8]);
            out.extend_from_slice(&(body.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(lname.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&lname);
            out.extend_from_slice(&body);
            cd.extend_from_slice(b"PK\x01\x02");
            cd.extend_from_slice(&20u16.to_le_bytes());
            cd.extend_from_slice(&20u16.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&method.to_le_bytes());
            cd.extend_from_slice(&[0; 8]);
            cd.extend_from_slice(&(body.len() as u32).to_le_bytes());
            cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
            cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
            cd.extend_from_slice(&[0; 12]);
            cd.extend_from_slice(&off.to_le_bytes());
            cd.extend_from_slice(name.as_bytes());
        }
        let cd_off = out.len() as u32;
        out.extend_from_slice(&cd);
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(cd.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_off.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    #[test]
    fn reads_stored_and_deflated_entries() {
        let z = build(&[("a/data.pkl", b"hello", false), ("b.txt", &[7u8; 1000], true)]);
        assert!(is_zip(&z));
        let a = read(&z, "z");
        assert!(a.findings.is_empty(), "{:?}", a.findings);
        assert_eq!(a.entries.len(), 2);
        assert_eq!(&*extract(&z, &a.entries[0], 100).unwrap(), b"hello");
        assert_eq!(extract(&z, &a.entries[1], 2000).unwrap().len(), 1000);
        assert_eq!(extract(&z, &a.entries[1], 10), Err(ExtractError::TooLarge(10)));
    }

    #[test]
    fn traversal_and_mismatch() {
        let z = build_with(&[("../evil.pkl", b"x", false), ("ok.pkl", b"y", false)], |i, n| {
            if i == 1 {
                *n = b"other.pkl".to_vec();
            }
        });
        let a = read(&z, "z");
        let rules: Vec<_> = a.findings.iter().map(|f| f.rule.as_str()).collect();
        assert!(rules.contains(&ids::ARCHIVE_TRAVERSAL));
        assert!(rules.contains(&ids::ARCHIVE_HEADER_MISMATCH));
        assert!(is_traversal("/etc/x") && is_traversal("C:/x") && is_traversal("a\\..\\b"));
        assert!(!is_traversal("a/b..c"));
    }

    #[test]
    fn missing_central_directory_falls_back_to_local_headers() {
        let z = build(&[("x.pkl", b"abc", false), ("y.pkl", b"de", false)]);
        let cut = z.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        let a = read(&z[..cut], "z");
        assert_eq!(a.entries.len(), 2);
        assert_eq!(a.findings[0].rule, ids::ARCHIVE_MALFORMED);
    }

    #[test]
    fn encrypted_and_unsupported() {
        let mut z = build(&[("x.pkl", b"abc", false)]);
        // set the encryption bit in the central directory only
        let cd = z.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        z[cd + 8] |= 1;
        let a = read(&z, "z");
        let rules: Vec<_> = a.findings.iter().map(|f| f.rule.as_str()).collect();
        assert!(rules.contains(&ids::ARCHIVE_ENCRYPTED));
        assert!(rules.contains(&ids::ARCHIVE_HEADER_MISMATCH));
        assert_eq!(extract(&z, &a.entries[0], 10), Err(ExtractError::Encrypted));
        let mut e = a.entries[0].clone();
        e.flags = 0;
        e.method = 93;
        assert_eq!(extract(&z, &e, 10), Err(ExtractError::Unsupported(93)));
        e.data_offset = None;
        e.method = 0;
        assert_eq!(extract(&z, &e, 10), Err(ExtractError::OutOfBounds));
    }

    #[test]
    fn garbage_does_not_panic() {
        for n in 0..200 {
            let mut z = build(&[("x.pkl", b"abcdef", true)]);
            let i = (n * 7) % z.len();
            z[i] = z[i].wrapping_add(13);
            let a = read(&z, "z");
            for e in &a.entries {
                let _ = extract(&z, e, 1 << 20);
            }
        }
        assert!(read(b"PK\x05\x06", "z").entries.is_empty());
    }

    #[test]
    fn zip64_extra_field() {
        let mut extra = Vec::new();
        extra.extend_from_slice(&1u16.to_le_bytes());
        extra.extend_from_slice(&24u16.to_le_bytes());
        extra.extend_from_slice(&5u64.to_le_bytes());
        extra.extend_from_slice(&6u64.to_le_bytes());
        extra.extend_from_slice(&7u64.to_le_bytes());
        let (mut s, mut c, mut o) = (0xffff_ffffu64, 0xffff_ffffu64, 0xffff_ffffu64);
        apply_zip64(&extra, &mut s, &mut c, &mut o);
        assert_eq!((s, c, o), (5, 6, 7));
    }
}
