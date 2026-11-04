use std::process::Command;

fn msscan(args: &[&str]) -> (i32, String, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_msscan"))
        .args(args)
        .output()
        .expect("run msscan");
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

fn tmp(name: &str, data: &[u8]) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("msscan-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join(name);
    std::fs::write(&p, data).unwrap();
    p
}

#[test]
fn scan_formats_and_exit_codes() {
    let bad = tmp("bad.pkl", b"\x80\x02cos\ngetcwd\n)R.");
    let good = tmp("good.pkl", b"\x80\x02ccollections\nOrderedDict\n)R.");
    let (c, out, _) = msscan(&["scan", bad.to_str().unwrap()]);
    assert_eq!(c, 1);
    assert!(out.contains("MALICIOUS") && out.contains("MS101"));
    let (c, out, _) = msscan(&["scan", "--format", "json", good.to_str().unwrap()]);
    assert_eq!(c, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v[0]["verdict"], "clean");
    let (c, out, _) = msscan(&["scan", "-f", "sarif", "--fail-on", "none", bad.to_str().unwrap()]);
    assert_eq!(c, 0);
    assert!(out.contains("\"ruleId\": \"MS101\""));
    let (c, out, _) = msscan(&[
        "scan",
        "-f",
        "json",
        "--min-severity",
        "critical",
        "--hash",
        bad.to_str().unwrap(),
    ]);
    assert_eq!(c, 1);
    assert!(out.contains("sha256"));
    let report = bad.with_extension("sarif");
    let (c, _, _) = msscan(&[
        "scan",
        "-f",
        "sarif",
        "-o",
        report.to_str().unwrap(),
        bad.to_str().unwrap(),
    ]);
    assert_eq!(c, 1);
    assert!(std::fs::read_to_string(&report).unwrap().contains("2.1.0"));
}

#[test]
fn errors_exit_two() {
    let (c, _, _) = msscan(&["scan", "/definitely/not/here"]);
    assert_eq!(c, 2);
    let good = tmp("g2.pkl", b"\x80\x02N.");
    let (c, _, err) = msscan(&["scan", "--fail-on", "severe", good.to_str().unwrap()]);
    assert_eq!(c, 2);
    assert!(err.contains("unknown severity"));
    let (c, _, err) = msscan(&["scan", "-o", "/definitely/not/here/x.json", good.to_str().unwrap()]);
    assert_eq!(c, 2);
    assert!(!err.is_empty());
}

#[test]
fn rules_in_three_formats() {
    let (c, out, _) = msscan(&["rules"]);
    assert_eq!(c, 0);
    assert!(out.contains("MS101"));
    let (_, out, _) = msscan(&["rules", "-f", "json"]);
    assert!(
        serde_json::from_str::<serde_json::Value>(&out)
            .unwrap()
            .as_array()
            .unwrap()
            .len()
            > 30
    );
    let (_, out, _) = msscan(&["rules", "-f", "markdown"]);
    assert!(out.starts_with("# Rules"));
}
