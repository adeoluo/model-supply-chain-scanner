import msscan

for name in ["malicious_setstate.pkl", "malicious_dynamic_import.pkl", "clean_state_dict.pt"]:
    report = msscan.scan_file(f"tests/fixtures/{name}")
    print(f"{name}: {report.verdict} (risk {report.risk_score})")
    for f in report.findings:
        print(f"    {f.severity:<8} {f.rule} {f.message}")
