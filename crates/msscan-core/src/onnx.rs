//! ONNX models: external data paths and operator domains.

use crate::finding::{Finding, ids};
use crate::protobuf::{Error, Reader, Value};
use std::collections::BTreeSet;

const STANDARD_DOMAINS: &[&str] = &[
    "",
    "ai.onnx",
    "ai.onnx.ml",
    "ai.onnx.training",
    "ai.onnx.preview.training",
    "com.microsoft",
    "com.microsoft.nchwc",
    "com.microsoft.experimental",
    "com.microsoft.mlfeaturizers",
];

#[derive(Debug, Default)]
pub struct OnnxInfo {
    pub ir_version: u64,
    pub nodes: u64,
    pub tensors: u64,
    pub external_locations: BTreeSet<String>,
    pub domains: BTreeSet<String>,
    pub function_domains: BTreeSet<String>,
}

/// Whether an external data location escapes the model directory.
pub fn unsafe_location(loc: &str) -> bool {
    let l = loc.replace('\\', "/");
    l.starts_with('/')
        || l.starts_with('~')
        || l.as_bytes().get(1) == Some(&b':')
        || l.contains("://")
        || l.split('/').any(|p| p == "..")
}

fn tensor(d: &[u8], info: &mut OnnxInfo) -> Result<(), Error> {
    info.tensors += 1;
    Reader::each(d, |f, v| {
        if let (13, Value::Bytes(entry)) = (f, v) {
            let (mut key, mut value) = (None, None);
            Reader::each(entry, |f, v| {
                match (f, v) {
                    (1, Value::Bytes(b)) => key = Some(String::from_utf8_lossy(b).into_owned()),
                    (2, Value::Bytes(b)) => value = Some(String::from_utf8_lossy(b).into_owned()),
                    _ => {}
                }
                Ok(())
            })?;
            if key.as_deref() == Some("location")
                && let Some(v) = value
            {
                info.external_locations.insert(v);
            }
        }
        Ok(())
    })
}

fn attribute(d: &[u8], info: &mut OnnxInfo, depth: u8) -> Result<(), Error> {
    Reader::each(d, |f, v| {
        match (f, v) {
            (5 | 10, Value::Bytes(t)) => tensor(t, info)?,
            (6 | 11, Value::Bytes(g)) => graph(g, info, depth + 1)?,
            _ => {}
        }
        Ok(())
    })
}

fn node(d: &[u8], info: &mut OnnxInfo, depth: u8) -> Result<(), Error> {
    info.nodes += 1;
    let mut domain = String::new();
    Reader::each(d, |f, v| {
        match (f, v) {
            (7, Value::Bytes(b)) => domain = String::from_utf8_lossy(b).into_owned(),
            (5, Value::Bytes(a)) => attribute(a, info, depth)?,
            _ => {}
        }
        Ok(())
    })?;
    info.domains.insert(domain);
    Ok(())
}

fn graph(d: &[u8], info: &mut OnnxInfo, depth: u8) -> Result<(), Error> {
    if depth > 32 {
        return Err(Error::BadField);
    }
    Reader::each(d, |f, v| {
        match (f, v) {
            (1, Value::Bytes(n)) => node(n, info, depth)?,
            (5, Value::Bytes(t)) => tensor(t, info)?,
            (15, Value::Bytes(sparse)) => {
                for t in Reader::bytes_fields(sparse, 1)?
                    .into_iter()
                    .chain(Reader::bytes_fields(sparse, 2)?)
                {
                    tensor(t, info)?;
                }
            }
            _ => {}
        }
        Ok(())
    })
}

/// Decode the parts of a ModelProto the checks need.
pub fn parse(d: &[u8]) -> Result<OnnxInfo, Error> {
    let mut info = OnnxInfo::default();
    let mut has_graph = false;
    Reader::each(d, |f, v| {
        match (f, v) {
            (1, Value::Varint(x)) => info.ir_version = x,
            (7, Value::Bytes(g)) => {
                has_graph = true;
                graph(g, &mut info, 0)?;
            }
            (25, Value::Bytes(func)) => {
                let mut dom = String::new();
                Reader::each(func, |f, v| {
                    match (f, v) {
                        (7, Value::Bytes(n)) => node(n, &mut info, 1)?,
                        (10, Value::Bytes(b)) => dom = String::from_utf8_lossy(b).into_owned(),
                        _ => {}
                    }
                    Ok(())
                })?;
                info.function_domains.insert(dom);
            }
            _ => {}
        }
        Ok(())
    })?;
    if !has_graph {
        return Err(Error::BadField);
    }
    Ok(info)
}

/// Content check: an ir_version varint first, as every ONNX writer emits.
pub fn looks_like_onnx(d: &[u8]) -> bool {
    matches!(d, [0x08, v, next, ..] if (3..=15).contains(v) && matches!(next, 0x12 | 0x1a | 0x22 | 0x2a | 0x3a | 0x42))
}

pub fn check(d: &[u8], loc: &str) -> (Vec<Finding>, Option<OnnxInfo>) {
    let mut out = Vec::new();
    let info = match parse(d) {
        Ok(i) => i,
        Err(e) => {
            out.push(Finding::new(
                ids::ONNX_MALFORMED,
                format!("ModelProto decoding failed: {e:?}"),
                loc,
            ));
            return (out, None);
        }
    };
    for l in &info.external_locations {
        if unsafe_location(l) {
            out.push(Finding::new(
                ids::ONNX_EXTERNAL_TRAVERSAL,
                format!("external data location {l:?}"),
                loc,
            ));
        }
    }
    let custom: Vec<_> = info
        .domains
        .iter()
        .filter(|d| !STANDARD_DOMAINS.contains(&d.as_str()) && !info.function_domains.contains(*d))
        .cloned()
        .collect();
    if !custom.is_empty() {
        out.push(Finding::new(
            ids::ONNX_CUSTOM_DOMAIN,
            format!("operator domains {}", custom.join(", ")),
            loc,
        ));
    }
    (out, Some(info))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::protobuf::tests::W;

    pub fn model(locations: &[&str], domains: &[&str]) -> Vec<u8> {
        let mut g = W::default();
        for d in domains {
            g = g.msg(1, W::default().str(4, "Op").str(7, d));
        }
        for l in locations {
            let t = W::default()
                .str(8, "w")
                .msg(13, W::default().str(1, "location").str(2, l))
                .msg(13, W::default().str(1, "offset").str(2, "0"))
                .varint(14, 1);
            g = g.msg(5, t);
        }
        // a subgraph attribute holding another external tensor
        let sub = W::default().msg(
            5,
            W::default().msg(13, W::default().str(1, "location").str(2, "sub.bin")),
        );
        g = g.msg(
            1,
            W::default()
                .str(4, "If")
                .msg(5, W::default().str(1, "then_branch").msg(6, sub)),
        );
        g = g.msg(15, W::default().msg(1, W::default().str(8, "s")));
        W::default().varint(1, 8).str(2, "pytorch").msg(7, g).0
    }

    #[test]
    fn traversal_and_domains() {
        let d = model(
            &["weights.bin", "../../etc/secret.bin", "/abs/x", "C:\\x"],
            &["", "com.example"],
        );
        assert!(looks_like_onnx(&d));
        let (f, info) = check(&d, "m.onnx");
        let info = info.unwrap();
        assert_eq!(info.ir_version, 8);
        assert!(info.external_locations.contains("sub.bin"));
        assert_eq!(f.iter().filter(|x| x.rule == ids::ONNX_EXTERNAL_TRAVERSAL).count(), 3);
        assert!(
            f.iter()
                .any(|x| x.rule == ids::ONNX_CUSTOM_DOMAIN && x.message.contains("com.example"))
        );
        let (f, _) = check(
            &model(&["model.onnx_data"], &["", "ai.onnx.ml", "com.microsoft"]),
            "m.onnx",
        );
        assert!(f.is_empty(), "{f:?}");
        assert!(unsafe_location("http://x/y") && unsafe_location("~/x") && !unsafe_location("a/b.bin"));
    }

    #[test]
    fn local_functions_are_not_custom_ops() {
        let func = W::default()
            .str(1, "F")
            .msg(7, W::default().str(4, "Add"))
            .str(10, "local.fns");
        let g = W::default().msg(1, W::default().str(4, "F").str(7, "local.fns"));
        let d = W::default().varint(1, 9).msg(7, g).msg(25, func).0;
        let (f, info) = check(&d, "m.onnx");
        assert!(f.is_empty(), "{f:?}");
        assert_eq!(info.unwrap().nodes, 2);
    }

    #[test]
    fn malformed_or_missing_graph() {
        let (f, _) = check(&W::default().varint(1, 8).0, "m.onnx");
        assert_eq!(f[0].rule, ids::ONNX_MALFORMED);
        let mut d = model(&[], &[""]);
        d.truncate(d.len() - 2);
        assert_eq!(check(&d, "m").0[0].rule, ids::ONNX_MALFORMED);
        assert!(!looks_like_onnx(b"\x08\x01\x12"));
    }
}
