use super::*;
use crate::numpy::tests::npy;
use crate::zip::tests::{build, build_with};
use std::io::Write;

const GETCWD: &[u8] = b"\x80\x02cos\ngetcwd\n)R.";
const BENIGN: &[u8] = b"\x80\x02ccollections\nOrderedDict\n)R.";

fn scan(data: &[u8], name: &str) -> Report {
    scan_bytes(data, name, &Options::default())
}

fn rules(r: &Report) -> Vec<&str> {
    r.findings.iter().map(|f| f.rule.as_str()).collect()
}

#[test]
fn pytorch_zip_scans_data_pkl_and_skips_storages() {
    let z = build(&[
        ("model/data.pkl", GETCWD, false),
        ("model/version", b"3\n", false),
        ("model/data/0", b"\x80\x02cos\nsystem\n)R.", false),
    ]);
    let r = scan(&z, "model.pt");
    assert_eq!(r.format, "pytorch");
    assert_eq!(r.verdict, Verdict::Malicious);
    assert_eq!(r.imports.len(), 1, "storage bytes must not be parsed: {:?}", r.imports);
    assert_eq!(r.imports[0].member, "model.pt/model/data.pkl");
    assert!(r.risk_score >= 95);
    let clean = build(&[("archive/data.pkl", BENIGN, true), ("archive/version", b"3\n", false)]);
    let r = scan(&clean, "pytorch_model.bin");
    assert_eq!(r.verdict, Verdict::Clean, "{:?}", r.findings);
    assert_eq!(r.risk_score, 0);
    assert_eq!(r.stats.archive_entries, 2);
}

#[test]
fn torchscript_is_reported() {
    let z = build(&[
        ("m/constants.pkl", BENIGN, false),
        ("m/code/__torch__/m.py", b"def forward(self): pass", false),
        ("m/data.pkl", BENIGN, false),
    ]);
    let r = scan(&z, "m.pt");
    assert_eq!(r.format, "torchscript");
    assert!(rules(&r).contains(&ids::TORCH_SCRIPT));
    assert_eq!(r.stats.pickles, 2);
}

#[test]
fn zip_header_mismatch_with_hidden_pickle() {
    let z = build_with(&[("archive/data.pkl", GETCWD, false)], |_, n| {
        *n = b"archive/other.txt".to_vec()
    });
    let r = scan(&z, "x.pt");
    assert!(rules(&r).contains(&ids::ARCHIVE_HEADER_MISMATCH));
    assert_eq!(r.verdict, Verdict::Malicious);
}

#[test]
fn pickle_inside_unusual_member_name_is_found() {
    let z = build(&[("weights.txt", GETCWD, false), ("notes.md", b"hello", false)]);
    let r = scan(&z, "bundle.zip");
    assert_eq!(r.format, "zip");
    assert_eq!(r.verdict, Verdict::Malicious);
}

#[test]
fn npy_and_npz_object_arrays() {
    let d = npy("'|O'", "(1,)", GETCWD);
    let r = scan(&d, "a.npy");
    assert_eq!(r.format, "numpy");
    assert!(rules(&r).contains(&ids::NUMPY_OBJECT_ARRAY));
    assert_eq!(r.verdict, Verdict::Malicious);
    let z = build(&[("x.npy", &npy("'<f4'", "(2,)", &[0; 8]), false), ("y.npy", &d, true)]);
    let r = scan(&z, "a.npz");
    assert_eq!(r.format, "npz");
    assert_eq!(r.verdict, Verdict::Malicious);
    let ok = build(&[("x.npy", &npy("'<f4'", "(2,)", &[0; 8]), false)]);
    assert_eq!(scan(&ok, "a.npz").verdict, Verdict::Clean);
}

#[test]
fn compressed_pickles() {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(GETCWD).unwrap();
    let gz = gz.finish().unwrap();
    let r = scan(&gz, "model.joblib");
    assert_eq!(r.format, "gzip+pickle");
    assert_eq!(r.verdict, Verdict::Malicious);
    assert!(r.findings[0].location.contains(">gzip"));
    let small = Options {
        max_decompressed: 4,
        ..Options::default()
    };
    let r = scan_bytes(&gz, "m.joblib", &small);
    assert!(rules(&r).contains(&ids::ARCHIVE_BOMB));
    let r = scan(&[0x1f, 0x8b, 8, 0, 0], "m.gz");
    assert!(rules(&r).contains(&ids::ARCHIVE_MALFORMED));
}

#[test]
fn nesting_limit() {
    let mut data = GETCWD.to_vec();
    for _ in 0..6 {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&data).unwrap();
        data = gz.finish().unwrap();
    }
    let r = scan(&data, "deep.gz");
    assert!(r.findings.iter().any(|f| f.message.contains("nesting")));
}

#[test]
fn extension_mismatch_and_unknown() {
    let r = scan(GETCWD, "model.safetensors");
    assert!(rules(&r).contains(&ids::FORMAT_MISMATCH));
    assert_eq!(r.verdict, Verdict::Malicious);
    let r = scan(b"plain text", "notes.txt");
    assert_eq!(r.format, "unknown");
    assert_eq!(r.verdict, Verdict::Clean);
    assert!(rules(&r).contains(&ids::FORMAT_UNKNOWN));
}

#[test]
fn risk_score_is_noisy_or() {
    assert_eq!(risk_score(&[]), 0);
    let f = |id| Finding::new(id, "", "");
    assert_eq!(risk_score(&[f(ids::PICKLE_UNKNOWN_CALL)]), 25);
    assert_eq!(
        risk_score(&[f(ids::PICKLE_UNKNOWN_CALL), f(ids::PICKLE_UNKNOWN_CALL)]),
        44
    );
    assert_eq!(risk_score(&[f(ids::PICKLE_DANGEROUS_CALL)]), 95);
    assert_eq!(Verdict::from_severity(None), Verdict::Clean);
    assert_eq!(Verdict::Unsafe.as_str(), "unsafe");
}

#[test]
fn files_and_directories() {
    let dir = std::env::temp_dir().join(format!("msscan-test-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::write(dir.join("sub/bad.pkl"), GETCWD).unwrap();
    std::fs::write(dir.join("good.pkl"), BENIGN).unwrap();
    std::fs::write(dir.join("empty.bin"), b"").unwrap();
    std::fs::write(dir.join(".git/x.pkl"), GETCWD).unwrap();
    let opts = Options {
        hash: true,
        ..Options::default()
    };
    let rs = scan_path(&dir, &opts);
    assert_eq!(rs.len(), 3);
    let bad = rs.iter().find(|r| r.path.ends_with("bad.pkl")).unwrap();
    assert_eq!(bad.verdict, Verdict::Malicious);
    assert_eq!(bad.sha256.as_ref().unwrap().len(), 64);
    let missing = scan_path(&dir.join("nope"), &opts);
    assert_eq!(missing[0].verdict, Verdict::Error);
    let r = scan_file(&dir.join("nope"), &opts);
    assert!(r.error.is_some());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn declared_size_is_reported() {
    let o = Options {
        declared_size: Some(1234),
        ..Options::default()
    };
    assert_eq!(scan_bytes(BENIGN, "x.pkl", &o).size, 1234);
}

#[test]
fn report_serializes() {
    let r = scan(GETCWD, "x.pkl");
    let j = serde_json::to_value(&r).unwrap();
    assert_eq!(j["verdict"], "malicious");
    assert_eq!(j["max_severity"], "critical");
    assert_eq!(j["imports"][0]["tier"], "dangerous");
    assert!(j.get("sha256").is_none());
}
