//! 7z and tar containers. Member names are checked for traversal and members are handed back
//! to the scanner; RAR is recognized and reported as not scanned.

use crate::finding::{Finding, ids};
use crate::zip::is_traversal;
use std::io::Read;

pub const SEVENZ_MAGIC: &[u8] = b"7z\xBC\xAF\x27\x1C";

pub fn is_7z(d: &[u8]) -> bool {
    d.starts_with(SEVENZ_MAGIC)
}

pub fn is_rar(d: &[u8]) -> bool {
    d.starts_with(b"Rar!\x1a\x07")
}

/// A POSIX (ustar) or GNU tar archive: the magic sits at offset 257 of the first header.
pub fn is_tar(d: &[u8]) -> bool {
    d.len() >= 512 && &d[257..262] == b"ustar"
}

/// One regular file inside a container.
pub struct Member {
    pub name: String,
    pub data: Vec<u8>,
}

/// What reading a container produced.
#[derive(Default)]
pub struct Listing {
    pub members: Vec<Member>,
    pub findings: Vec<Finding>,
    pub entries: u64,
}

fn check_name(name: &str, kind: &str, loc: &str, out: &mut Vec<Finding>) {
    if is_traversal(name) {
        out.push(Finding::new(
            ids::ARCHIVE_TRAVERSAL,
            format!("{kind} entry {name:?} is absolute or leaves the extraction directory"),
            loc,
        ));
    }
}

/// Read every file of a 7z archive, each up to `limit` bytes and `limit` bytes in total.
pub fn read_7z(d: &[u8], limit: u64, loc: &str) -> Listing {
    use sevenz_rust2::{ArchiveReader, Password};
    let mut out = Listing::default();
    let mut reader = match ArchiveReader::new_with_memory_limit(std::io::Cursor::new(d), Password::empty(), 1 << 20) {
        Ok(r) => r,
        Err(e) => {
            let text = e.to_string();
            let rule = if text.to_ascii_lowercase().contains("password") || text.contains("AES") {
                ids::ARCHIVE_ENCRYPTED
            } else {
                ids::ARCHIVE_MALFORMED
            };
            out.findings
                .push(Finding::new(rule, format!("7z archive not scanned: {text}"), loc));
            return out;
        }
    };
    let mut budget = limit;
    let mut names = Vec::new();
    let mut members = Vec::new();
    let mut too_large: Vec<String> = Vec::new();
    let res = reader.for_each_entries(|entry, r| {
        if entry.is_directory() {
            return Ok(true);
        }
        let name = entry.name().to_string();
        names.push(name.clone());
        if entry.size() > budget {
            too_large.push(name);
            return Ok(true);
        }
        let mut buf = Vec::new();
        r.take(budget + 1).read_to_end(&mut buf)?;
        if buf.len() as u64 > budget {
            too_large.push(name);
            return Ok(true);
        }
        budget -= buf.len() as u64;
        members.push(Member { name, data: buf });
        Ok(true)
    });
    out.entries = names.len() as u64;
    for name in &names {
        check_name(name, "7z", loc, &mut out.findings);
    }
    for name in too_large {
        out.findings.push(Finding::new(
            ids::ARCHIVE_BOMB,
            format!("7z entry {name:?} decompresses past the {limit}-byte limit"),
            loc,
        ));
    }
    if let Err(e) = res {
        let text = e.to_string();
        let rule = if text.to_ascii_lowercase().contains("password") || text.contains("AES") {
            ids::ARCHIVE_ENCRYPTED
        } else {
            ids::ARCHIVE_MALFORMED
        };
        out.findings.push(Finding::new(
            rule,
            format!("7z archive only partly scanned: {text}"),
            loc,
        ));
    }
    out.members = members;
    out
}

fn c_str(field: &[u8]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).trim_end().to_string()
}

/// A tar size field: octal text, or base-256 when the top bit of the first byte is set.
fn tar_size(field: &[u8]) -> Option<u64> {
    if field[0] & 0x80 != 0 {
        return field[1..]
            .iter()
            .try_fold(0u64, |acc, &b| acc.checked_mul(256).map(|v| v | u64::from(b)));
    }
    let text = c_str(field);
    let digits = text.trim();
    if digits.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(digits, 8).ok()
}

/// The `path=` record of a pax extended header, if present.
fn pax_path(data: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(data);
    text.lines()
        .filter_map(|l| l.split_once(' ').map(|(_, kv)| kv))
        .find_map(|kv| kv.strip_prefix("path=").map(str::to_string))
}

/// Read every regular file of a tar archive, each up to `limit` bytes.
pub fn read_tar(d: &[u8], limit: u64, loc: &str) -> Listing {
    let mut out = Listing::default();
    let mut off = 0usize;
    let mut long_name: Option<String> = None;
    while off + 512 <= d.len() {
        let h = &d[off..off + 512];
        if h.iter().all(|&b| b == 0) {
            break;
        }
        let Some(size) = tar_size(&h[124..136]) else {
            out.findings.push(Finding::new(
                ids::ARCHIVE_MALFORMED,
                "tar header with an unreadable size field; the rest was not scanned",
                loc,
            ));
            break;
        };
        let start = off + 512;
        let Some(end) = usize::try_from(size).ok().and_then(|s| start.checked_add(s)) else {
            break;
        };
        if end > d.len() {
            out.findings.push(Finding::new(
                ids::ARCHIVE_MALFORMED,
                "tar entry runs past the end of the file; the rest was not scanned",
                loc,
            ));
            break;
        }
        let body = &d[start..end];
        let kind = h[156];
        let mut name = c_str(&h[0..100]);
        let prefix = c_str(&h[345..500]);
        if &h[257..262] == b"ustar" && !prefix.is_empty() {
            name = format!("{prefix}/{name}");
        }
        if let Some(n) = long_name.take() {
            name = n;
        }
        match kind {
            b'L' => long_name = Some(c_str(body)),
            b'x' => long_name = pax_path(body),
            b'g' => {}
            b'0' | 0 | b'7' => {
                out.entries += 1;
                check_name(&name, "tar", loc, &mut out.findings);
                if size > limit {
                    out.findings.push(Finding::new(
                        ids::ARCHIVE_BOMB,
                        format!("tar entry {name:?} holds {size} bytes, past the limit"),
                        loc,
                    ));
                } else {
                    out.members.push(Member {
                        name,
                        data: body.to_vec(),
                    });
                }
            }
            b'1' | b'2' => {
                out.entries += 1;
                check_name(&name, "tar", loc, &mut out.findings);
                let target = c_str(&h[157..257]);
                if is_traversal(&target) {
                    out.findings.push(Finding::new(
                        ids::ARCHIVE_TRAVERSAL,
                        format!("tar link {name:?} points to {target:?}, outside the extraction directory"),
                        loc,
                    ));
                }
            }
            _ => {
                out.entries += 1;
                check_name(&name, "tar", loc, &mut out.findings);
            }
        }
        off = end.div_ceil(512) * 512;
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Build a ustar archive from `(name, type flag, link target, data)` entries.
    pub fn tar(entries: &[(&str, u8, &str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, kind, link, data) in entries {
            let mut h = [0u8; 512];
            h[..name.len().min(100)].copy_from_slice(&name.as_bytes()[..name.len().min(100)]);
            h[100..107].copy_from_slice(b"0000644");
            let size = format!("{:011o}", data.len());
            h[124..135].copy_from_slice(size.as_bytes());
            h[156] = *kind;
            h[157..157 + link.len()].copy_from_slice(link.as_bytes());
            h[257..263].copy_from_slice(b"ustar\0");
            out.extend_from_slice(&h);
            out.extend_from_slice(data);
            out.resize(out.len().div_ceil(512) * 512, 0);
        }
        out.resize(out.len() + 1024, 0);
        out
    }

    #[test]
    fn tar_members_links_and_long_names() {
        let long = "d/".repeat(70) + "model.pkl";
        let pax = format!("{} path={}\n", 9 + long.len(), long);
        let t = tar(&[
            ("a/model.pkl", b'0', "", b"hello"),
            ("../../etc/cron.d/x", b'0', "", b"x"),
            ("link", b'2', "/etc/passwd", b""),
            ("./PaxHeaders/x", b'x', "", pax.as_bytes()),
            ("short", b'0', "", b"long one"),
            ("././@LongLink", b'L', "", b"gnu/long/name.bin\0"),
            ("ignored", b'0', "", b"gnu"),
            ("dir/", b'5', "", b""),
        ]);
        assert!(is_tar(&t) && !is_7z(&t) && !is_rar(&t));
        let l = read_tar(&t, 1 << 20, "x.tar");
        let names: Vec<&str> = l.members.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["a/model.pkl", "../../etc/cron.d/x", long.as_str(), "gnu/long/name.bin"]
        );
        assert_eq!(l.members[0].data, b"hello");
        let traversal = l.findings.iter().filter(|f| f.rule == ids::ARCHIVE_TRAVERSAL).count();
        assert_eq!(traversal, 2, "{:?}", l.findings);
        assert_eq!(l.entries, 6);
    }

    #[test]
    fn tar_limits_and_damage() {
        let t = tar(&[("big.bin", b'0', "", &[7u8; 4000])]);
        let l = read_tar(&t, 100, "x.tar");
        assert!(l.members.is_empty() && l.findings[0].rule == ids::ARCHIVE_BOMB);
        let l = read_tar(&t[..1024], 1 << 20, "x.tar");
        assert_eq!(l.findings[0].rule, ids::ARCHIVE_MALFORMED);
        let mut bad = t.clone();
        bad[124..135].copy_from_slice(b"zzzzzzzzzzz");
        assert_eq!(read_tar(&bad, 1 << 20, "x").findings.len(), 1);
    }

    #[test]
    fn base256_sizes_and_bad_7z() {
        let mut field = [0u8; 12];
        field[0] = 0x80;
        field[11] = 5;
        assert_eq!(tar_size(&field), Some(5));
        assert_eq!(tar_size(b"00000000017\0"), Some(15));
        assert_eq!(tar_size(b"\0\0\0\0\0\0\0\0\0\0\0\0"), Some(0));
        let mut d = SEVENZ_MAGIC.to_vec();
        d.extend_from_slice(&[0u8; 40]);
        assert!(is_7z(&d));
        let l = read_7z(&d, 1 << 20, "x.7z");
        assert!(l.members.is_empty());
        assert_eq!(l.findings[0].rule, ids::ARCHIVE_MALFORMED);
        assert!(is_rar(b"Rar!\x1a\x07\x01\x00"));
    }
}
