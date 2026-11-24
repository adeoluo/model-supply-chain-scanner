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
fn encrypted_flag_on_a_plaintext_pickle_is_still_scanned() {
    let mut z = build(&[("archive/data.pkl", GETCWD, false)]);
    for sig in [&b"PK\x01\x02"[..], &b"PK\x03\x04"[..]] {
        let at = z.windows(4).position(|w| w == sig).unwrap();
        let off = if sig == b"PK\x01\x02" { 8 } else { 6 };
        z[at + off] |= 1;
    }
    let r = scan(&z, "x.pt");
    assert!(rules(&r).contains(&ids::ARCHIVE_ENCRYPTED));
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
fn truncated_protocol_zero_pickle_without_stop_is_malicious() {
    // Missing final '.' STOP opcode: Python executes REDUCE (`os.system`) before raising
    // UnpicklingError. Must be caught regardless of filename extension.
    let truncated_p0 = b"cos\nsystem\n(S'echo pwned'\ntR";
    for name in ["payload.pkl", "model.pt", "unlabeled_blob"] {
        let r = scan(truncated_p0, name);
        assert_eq!(r.format, "pickle", "missed format for {name}: {r:?}");
        assert_eq!(r.verdict, Verdict::Malicious, "missed verdict for {name}: {r:?}");
        assert!(rules(&r).contains(&ids::PICKLE_DANGEROUS_CALL));
        assert!(rules(&r).contains(&ids::PICKLE_MALFORMED));
    }
    // Plain English prose starting with 'c' must still not be misclassified as a pickle.
    let prose = scan(
        b"chapter 1\nthis is plain text, not a pickle stream at all\n",
        "readme.txt",
    );
    assert_eq!(prose.format, "unknown");
    assert_eq!(prose.verdict, Verdict::Clean);
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

#[test]
fn every_format_is_dispatched() {
    use crate::gguf::tests::G;
    let g = G::new()
        .kv_str(
            "tokenizer.chat_template",
            "{{ cycler.__init__.__globals__.os.getcwd() }}",
        )
        .build(0);
    let r = scan(&g, "m.gguf");
    assert_eq!((r.format.as_str(), r.verdict), ("gguf", Verdict::Malicious));

    let st = crate::safetensors::tests::st(r#"{"a":{"dtype":"U8","shape":[4],"data_offsets":[0,4]}}"#, 4);
    assert_eq!(scan(&st, "m.safetensors").verdict, Verdict::Clean);
    // headers-only: the real file is bigger than the tensors claim
    let o = Options {
        declared_size: Some(st.len() as u64 + 10),
        ..Options::default()
    };
    let r = scan_bytes(&st[..st.len() - 4], "m.safetensors", &o);
    assert!(rules(&r).contains(&ids::SAFETENSORS_OFFSETS));

    let sm = crate::savedmodel::tests::saved_model(&["ReadFile"], &["EagerPyFunc"]);
    let r = scan(&sm, "saved_model.pb");
    assert_eq!((r.format.as_str(), r.verdict), ("savedmodel", Verdict::Malicious));
    let r = scan(&sm, "other.bin");
    assert_eq!(r.format, "savedmodel");

    let ox = crate::onnx::tests::model(&["../x.bin"], &[""]);
    let r = scan(&ox, "model.onnx");
    assert_eq!((r.format.as_str(), r.verdict), ("onnx", Verdict::Unsafe));
    assert_eq!(scan(&ox, "renamed.bin").format, "onnx");
    assert!(rules(&scan(b"\x08\x07garbage", "bad.onnx")).contains(&ids::ONNX_MALFORMED));

    let k = build(&[
        ("config.json", crate::keras::tests::LAMBDA_K3.as_bytes(), true),
        ("metadata.json", b"{}", false),
    ]);
    let r = scan(&k, "m.keras");
    assert_eq!((r.format.as_str(), r.verdict), ("keras", Verdict::Unsafe));

    let mut h5 = crate::keras::HDF5_MAGIC.to_vec();
    h5.extend_from_slice(crate::keras::tests::LAMBDA_K2.as_bytes());
    let r = scan(&h5, "m.h5");
    assert_eq!((r.format.as_str(), r.verdict), ("keras-h5", Verdict::Unsafe));
    let r = scan(crate::keras::tests::LAMBDA_K2.as_bytes(), "keras_metadata.pb");
    assert_eq!(r.format, "keras-metadata");
    assert_eq!(r.verdict, Verdict::Unsafe);

    let cfg = br#"{"auto_map": {"AutoModel": "m.M"}}"#;
    let r = scan(cfg, "config.json");
    assert_eq!((r.format.as_str(), r.verdict), ("hf-config", Verdict::Clean));
    assert!(rules(&r).contains(&ids::HF_REMOTE_CODE));
    assert_eq!(scan(b"{\"a\": 1}", "x.json").format, "json");
    assert!(rules(&scan(b"\x80\x02N.", "x.gguf")).contains(&ids::FORMAT_MISMATCH));
    assert!(rules(&scan(b"garbage!", "x.safetensors")).contains(&ids::SAFETENSORS_HEADER));
}

mod fuzz {
    use super::*;
    use proptest::prelude::*;

    fn prefixes() -> Vec<Vec<u8>> {
        vec![
            b"GGUF\x03\x00\x00\x00".to_vec(),
            b"\x20\x00\x00\x00\x00\x00\x00\x00{\"a\":".to_vec(),
            b"PK\x03\x04".to_vec(),
            b"\x93NUMPY\x01\x00".to_vec(),
            crate::keras::HDF5_MAGIC.to_vec(),
            b"\x08\x08\x3a".to_vec(),
            b"\x08\x01\x12".to_vec(),
            b"\x1f\x8b\x08".to_vec(),
            b"\x80\x04\x95".to_vec(),
            b"{\"class_name\": ".to_vec(),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(400))]
        #[test]
        fn no_format_panics(which in 0usize..10, tail in proptest::collection::vec(any::<u8>(), 0..300),
                            names in prop::sample::select(vec!["a.bin", "saved_model.pb", "m.onnx", "keras_metadata.pb", "config.json"])) {
            let mut d = prefixes()[which].clone();
            d.extend(tail);
            let r = scan_bytes(&d, names, &Options::default());
            prop_assert!(r.risk_score <= 100);
        }

        #[test]
        fn mutated_valid_files_do_not_panic(idx in 0usize..4000, byte in any::<u8>(), which in 0usize..4) {
            let mut d = match which {
                0 => crate::gguf::tests::G::new().kv_str("tokenizer.chat_template", "{{ x }}").tensor("w", &[4], 0, 0).build(16),
                1 => crate::onnx::tests::model(&["a.bin"], &["", "x"]),
                2 => crate::savedmodel::tests::saved_model(&["ReadFile"], &["PyFunc"]),
                _ => build(&[("a/data.pkl", GETCWD, true), ("a/version", b"3", false)]),
            };
            let i = idx % d.len();
            d[i] = byte;
            let _ = scan_bytes(&d, "f", &Options::default());
        }
    }
}

#[test]
fn tar_and_7z_members_are_scanned() {
    use crate::archive::tests::tar;
    let t = tar(&[
        ("model/weights.pkl", b'0', "", GETCWD),
        ("model/notes.txt", b'0', "", b"just text"),
        ("../escape.bin", b'0', "", b"x"),
    ]);
    let r = scan(&t, "model.tar");
    assert_eq!(r.format, "tar");
    assert_eq!(r.verdict, Verdict::Malicious);
    assert!(rules(&r).contains(&ids::ARCHIVE_TRAVERSAL));
    assert_eq!(r.imports[0].member, "model.tar/model/weights.pkl");
    assert_eq!(r.stats.archive_entries, 3);
    // The same archive under a name that promises something else is still read as tar.
    let r = scan(&t, "model.nemo");
    assert!(
        r.format == "tar" && !rules(&r).contains(&ids::FORMAT_MISMATCH),
        "{:?}",
        r.findings
    );
    let clean = tar(&[("a.pkl", b'0', "", BENIGN)]);
    assert_eq!(scan(&clean, "a.tar").verdict, Verdict::Clean);
    // A real 7z archive (LZMA2) holding a pickle and a traversal name.
    let seven = {
        use sevenz_rust2::{ArchiveEntry, ArchiveWriter};
        let mut w = ArchiveWriter::new(std::io::Cursor::new(Vec::new())).expect("writer");
        w.push_archive_entry(ArchiveEntry::new_file("model/data.pkl"), Some(GETCWD))
            .expect("entry");
        w.push_archive_entry(ArchiveEntry::new_file("../../up.bin"), Some(&b"x"[..]))
            .expect("entry");
        w.finish().expect("finish").into_inner()
    };
    let r = scan(&seven, "weights.7z");
    assert_eq!(r.format, "7z");
    assert_eq!(r.verdict, Verdict::Malicious, "{:?}", r.findings);
    assert!(rules(&r).contains(&ids::ARCHIVE_TRAVERSAL));
    assert_eq!(r.imports[0].member, "weights.7z/model/data.pkl");
    // A member larger than the limit is reported, not read.
    let small = Options {
        max_decompressed: 8,
        ..Options::default()
    };
    let r = scan_bytes(&seven, "weights.7z", &small);
    assert!(rules(&r).contains(&ids::ARCHIVE_BOMB), "{:?}", r.findings);
    // A damaged 7z and a RAR are reported as not scanned, never as clean.
    let mut seven = crate::archive::SEVENZ_MAGIC.to_vec();
    seven.extend_from_slice(&[0u8; 64]);
    let r = scan(&seven, "m.7z");
    assert!(
        r.format == "7z" && rules(&r) == vec![ids::ARCHIVE_MALFORMED],
        "{:?}",
        r.findings
    );
    let r = scan(b"Rar!\x1a\x07\x01\x00rest", "m.rar");
    assert!(r.format == "rar" && r.verdict == Verdict::Suspicious);
}

#[test]
fn text_configs_and_templates() {
    let r = scan(
        b"hook:\n  _target_: os.system\n  _args_: ['id']\n",
        "conf/model_config.yaml",
    );
    assert_eq!(r.format, "yaml");
    assert_eq!(r.verdict, Verdict::Malicious);
    assert_eq!(rules(&r), vec![ids::CONFIG_TARGET]);
    let r = scan(b"a: !!python/object/apply:os.system ['id']\n", "c.yml");
    assert_eq!(rules(&r), vec![ids::CONFIG_YAML_TAG]);
    assert_eq!(
        scan(b"model:\n  _target_: torch.nn.Linear\n", "c.yaml").verdict,
        Verdict::Clean
    );
    let r = scan(
        b"{{ cycler.__init__.__globals__.os.system('id') }}",
        "chat_template.jinja",
    );
    assert_eq!(r.format, "jinja-template");
    assert_eq!(r.verdict, Verdict::Malicious);
    assert_eq!(
        scan(b"{% for m in messages %}{{ m.content }}{% endfor %}", "t.j2").verdict,
        Verdict::Clean
    );
    // A pickle named like a config is still a pickle.
    let r = scan(GETCWD, "config.yaml");
    assert!(r.format == "pickle" && r.verdict == Verdict::Malicious);
    // Text without a config extension is not guessed at.
    assert_eq!(scan(b"_target_: os.system\n", "notes.txt").format, "unknown");
}

#[test]
fn macos_metadata_is_not_a_broken_model() {
    let mut d = vec![0x00, 0x05, 0x16, 0x07, 0x00, 0x02, 0x00, 0x00];
    d.extend_from_slice(b"Mac OS X        ");
    d.extend_from_slice(&[0u8; 64]);
    let r = scan(&d, "._model.safetensors");
    assert_eq!(r.format, "appledouble");
    assert_eq!(r.verdict, Verdict::Clean);
    assert_eq!(rules(&r), vec![ids::FORMAT_UNKNOWN]);
}

#[test]
fn safetensors_metadata_is_checked_for_staged_payloads() {
    let h = r#"{"__metadata__":{"format":"pt","note":"import os; os.system('echo inert')"},"a":{"dtype":"U8","shape":[4],"data_offsets":[0,4]}}"#;
    let d = crate::safetensors::tests::st(h, 4);
    let r = scan(&d, "m.safetensors");
    assert_eq!(rules(&r), vec![ids::EMBEDDED_CODE]);
    assert_eq!(r.verdict, Verdict::Unsafe);
    let ok = r#"{"__metadata__":{"format":"pt","ss_tag_frequency":"{\"img\": {\"1girl\": 3}}"},"a":{"dtype":"U8","shape":[4],"data_offsets":[0,4]}}"#;
    assert_eq!(
        scan(&crate::safetensors::tests::st(ok, 4), "m.safetensors").verdict,
        Verdict::Clean
    );
}

#[cfg(unix)]
#[test]
fn links_are_followed_inside_the_tree_and_reported_outside_it() {
    use std::os::unix::fs::symlink;
    let top = std::env::temp_dir().join(format!("msscan-links-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&top);
    // The Hugging Face cache layout: snapshots/<revision>/name -> ../../blobs/<hash>.
    let snap = top.join("models--a--b/snapshots/rev");
    std::fs::create_dir_all(&snap).unwrap();
    std::fs::create_dir_all(top.join("models--a--b/blobs")).unwrap();
    std::fs::write(top.join("models--a--b/blobs/abc"), GETCWD).unwrap();
    std::fs::write(top.join("secret.pkl"), GETCWD).unwrap();
    symlink("../../blobs/abc", snap.join("model.pkl")).unwrap();
    symlink("../../../secret.pkl", snap.join("leak.pkl")).unwrap();
    symlink("/nonexistent/msscan/target", snap.join("gone.bin")).unwrap();
    symlink("model.pkl", snap.join("zz-again.pkl")).unwrap();
    let opts = Options::default();

    let rs = scan_path(&snap, &opts);
    let by_name = |n: &str| rs.iter().find(|r| r.path.ends_with(n));
    // The blob is scanned through its link, once.
    assert_eq!(by_name("model.pkl").unwrap().verdict, Verdict::Malicious);
    assert!(by_name("zz-again.pkl").is_none());
    // Links that leave the tree are reported and their targets are not opened.
    for name in ["leak.pkl", "gone.bin"] {
        let r = by_name(name).unwrap();
        assert_eq!(r.format, "link", "{name}");
        assert_eq!(r.findings[0].rule, ids::LINK_LEAVES_TREE);
        assert!(r.imports.is_empty());
    }
    assert_eq!(rs.len(), 3);

    // Scanning the whole repository cache reads each blob once.
    let whole = scan_path(&top.join("models--a--b"), &opts);
    assert_eq!(whole.iter().filter(|r| r.format != "link").count(), 1);
    assert_eq!(whole.len(), 3);
    // A link named on the command line is followed.
    let direct = scan_path(&snap.join("leak.pkl"), &opts);
    assert_eq!(direct[0].verdict, Verdict::Malicious);
    std::fs::remove_dir_all(&top).unwrap();
}

#[test]
fn link_stubs_and_lfs_pointers() {
    let o = Options::default();
    let r = scan_bytes(b"../../../etc/hostname", "rel.safetensors", &o);
    assert_eq!(
        (r.format.as_str(), r.findings[0].rule.as_str()),
        ("link", ids::LINK_LEAVES_TREE)
    );
    assert_eq!(r.max_severity, Some(Severity::High));
    for stub in ["/etc/passwd", "~/.ssh/id_rsa", "/proc/self/environ"] {
        assert_eq!(scan_bytes(stub.as_bytes(), "x.bin", &o).format, "link", "{stub}");
    }
    // Links that stay among model files, and ordinary short text, are not stubs.
    for plain in [
        "../../model.safetensors",
        "../blobs/abc",
        "weights/model.bin",
        "/etc",
        "etc/hosts",
        "a b/../etc/x",
    ] {
        assert!(crate::formats::link_stub(plain.as_bytes()).is_none(), "{plain}");
    }
    let lfs = b"version https://git-lfs.github.com/spec/v1\noid sha256:00\nsize 12\n";
    for name in ["model.safetensors", "pytorch_model.bin"] {
        let r = scan_bytes(lfs, name, &o);
        assert_eq!(r.format, "lfs-pointer");
        assert_eq!(r.max_severity, Some(Severity::Info));
    }
    // Text under a .safetensors name is not a crafted header.
    let r = scan_bytes(b"dmVyc2lvbiBodHRwczovL2dpdC1sZnM=", "model.safetensors", &o);
    assert_eq!(r.max_severity, Some(Severity::Medium));
    let mut crafted = (u64::MAX / 2).to_le_bytes().to_vec();
    crafted.extend_from_slice(b"{}");
    assert_eq!(
        scan_bytes(&crafted, "model.safetensors", &o).max_severity,
        Some(Severity::High)
    );
}
