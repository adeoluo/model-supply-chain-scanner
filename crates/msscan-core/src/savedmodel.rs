//! TensorFlow SavedModel graphs: ops that touch files or call Python.

use crate::finding::{ids, Finding, Severity};
use crate::protobuf::{Error, Reader, Value};
use std::collections::BTreeMap;

/// Ops that read, write or list files.
const FILE_OPS: &[&str] = &[
    "ReadFile",
    "WriteFile",
    "MatchingFiles",
    "MatchingFilesDataset",
    "ImmutableConst",
    "WholeFileReader",
    "WholeFileReaderV2",
    "TextLineReader",
    "TextLineReaderV2",
    "FixedLengthRecordReader",
    "FixedLengthRecordReaderV2",
    "TFRecordReader",
    "TFRecordReaderV2",
    "DatasetToTFRecord",
    "ExperimentalDatasetToTFRecord",
    "SaveDataset",
    "SaveDatasetV2",
    "LoadDataset",
];

/// Ops that call back into Python.
const PY_OPS: &[&str] = &["PyFunc", "PyFuncStateless", "EagerPyFunc"];

/// Ops with side effects outside the model.
const RISKY_OPS: &[&str] = &[
    "PrintV2",
    "DebugIdentity",
    "DebugIdentityV2",
    "DebugIdentityV3",
    "DebugNanCount",
    "DebugNumericSummary",
    "DebugNumericSummaryV2",
    "CreateSummaryFileWriter",
    "WriteSummary",
    "WriteAudioSummary",
    "WriteGraphSummary",
    "WriteHistogramSummary",
    "WriteImageSummary",
    "WriteRawProtoSummary",
    "WriteScalarSummary",
    "CreateSummaryDbWriter",
    "Mfcc",
];

fn node_op(d: &[u8]) -> Result<Option<String>, Error> {
    let mut op = None;
    Reader::each(d, |f, v| {
        if let (2, Value::Bytes(b)) = (f, v) {
            op = Some(String::from_utf8_lossy(b).into_owned());
        }
        Ok(())
    })?;
    Ok(op)
}

fn graph_ops(graph: &[u8], ops: &mut BTreeMap<String, u32>) -> Result<(), Error> {
    Reader::each(graph, |f, v| {
        match (f, v) {
            (1, Value::Bytes(node)) => {
                if let Some(op) = node_op(node)? {
                    *ops.entry(op).or_default() += 1;
                }
            }
            (2, Value::Bytes(lib)) => {
                for func in Reader::bytes_fields(lib, 1)? {
                    for node in Reader::bytes_fields(func, 3)? {
                        if let Some(op) = node_op(node)? {
                            *ops.entry(op).or_default() += 1;
                        }
                    }
                }
            }
            _ => {}
        }
        Ok(())
    })
}

/// Op names and counts across every meta graph and function in a SavedModel.
pub fn ops(d: &[u8]) -> Result<BTreeMap<String, u32>, Error> {
    let mut ops = BTreeMap::new();
    for meta in Reader::bytes_fields(d, 2)? {
        for graph in Reader::bytes_fields(meta, 2)? {
            graph_ops(graph, &mut ops)?;
        }
    }
    Ok(ops)
}

/// Content check: schema version 1 followed by a meta graph.
pub fn looks_like_saved_model(d: &[u8]) -> bool {
    d.starts_with(&[0x08, 0x01, 0x12])
}

pub fn check(d: &[u8], loc: &str) -> (Vec<Finding>, BTreeMap<String, u32>) {
    let mut out = Vec::new();
    let ops = match ops(d) {
        Ok(o) => o,
        Err(e) => {
            out.push(Finding::new(
                ids::TF_MALFORMED,
                format!("protobuf decoding failed: {e:?}"),
                loc,
            ));
            return (out, BTreeMap::new());
        }
    };
    for (op, n) in &ops {
        let (rule, sev) = if PY_OPS.contains(&op.as_str()) {
            (ids::TF_PY_FUNC, Severity::Critical)
        } else if FILE_OPS.contains(&op.as_str()) {
            (ids::TF_FILE_OP, Severity::High)
        } else if RISKY_OPS.contains(&op.as_str()) {
            (ids::TF_RISKY_OP, Severity::Medium)
        } else {
            continue;
        };
        out.push(Finding::new(rule, format!("{n} {op} op(s)"), loc).with_severity(sev));
    }
    (out, ops)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::protobuf::tests::W;

    pub fn saved_model(graph_ops: &[&str], fn_ops: &[&str]) -> Vec<u8> {
        let mut graph = W::default();
        for (i, op) in graph_ops.iter().enumerate() {
            graph = graph.msg(1, W::default().str(1, &format!("n{i}")).str(2, op));
        }
        let mut func = W::default().msg(1, W::default().str(1, "f"));
        for op in fn_ops {
            func = func.msg(3, W::default().str(1, "x").str(2, op));
        }
        graph = graph.msg(2, W::default().msg(1, func));
        W::default().varint(1, 1).msg(2, W::default().msg(2, graph)).0
    }

    #[test]
    fn finds_file_and_python_ops() {
        let d = saved_model(&["Placeholder", "ReadFile", "MatMul"], &["PyFunc", "PrintV2", "SaveV2"]);
        assert!(looks_like_saved_model(&d));
        let (f, ops) = check(&d, "saved_model.pb");
        assert_eq!(ops.len(), 6);
        let rules: Vec<_> = f.iter().map(|x| (x.rule.as_str(), x.severity)).collect();
        assert!(rules.contains(&(ids::TF_FILE_OP, Severity::High)));
        assert!(rules.contains(&(ids::TF_PY_FUNC, Severity::Critical)));
        assert!(rules.contains(&(ids::TF_RISKY_OP, Severity::Medium)));
        let (f, _) = check(&saved_model(&["Placeholder", "SaveV2", "RestoreV2"], &[]), "x");
        assert!(f.is_empty());
    }

    #[test]
    fn malformed() {
        let mut d = saved_model(&["ReadFile"], &[]);
        d.truncate(d.len() - 3);
        let (f, _) = check(&d, "x");
        assert_eq!(f[0].rule, ids::TF_MALFORMED);
    }
}
