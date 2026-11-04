from __future__ import annotations

import json
import subprocess
import sys

import pytest

from msscan.cli import main


def test_scan_text_exit_codes(model_dir, capsys) -> None:  # type: ignore[no-untyped-def]
    assert main(["scan", str(model_dir / "bad.pkl")]) == 1
    assert "MALICIOUS" in capsys.readouterr().out
    assert main(["scan", str(model_dir / "good.pkl")]) == 0
    assert main(["scan", "--fail-on", "none", str(model_dir)]) == 0
    assert main(["scan", str(model_dir / "missing.pkl")]) == 2


def test_scan_json_sarif_and_output(model_dir, tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    capsys.readouterr()
    assert main(["scan", "-f", "json", "--min-severity", "critical", str(model_dir)]) == 1
    rows = json.loads(capsys.readouterr().out)
    assert len(rows) == 2
    out = tmp_path / "r.sarif"
    assert main(["scan", "-f", "sarif", "-o", str(out), "--hash", str(model_dir)]) == 1
    assert json.loads(out.read_text())["runs"][0]["results"]


def test_rules_formats(capsys) -> None:  # type: ignore[no-untyped-def]
    for fmt, marker in (("text", "MS101"), ("json", '"id"'), ("markdown", "# Rules")):
        assert main(["rules", "-f", fmt]) == 0
        assert marker in capsys.readouterr().out


def test_bad_arguments() -> None:
    with pytest.raises(SystemExit):
        main(["scan", "--fail-on", "severe", "x"])


def test_module_entry_point(model_dir) -> None:  # type: ignore[no-untyped-def]
    p = subprocess.run(
        [sys.executable, "-m", "msscan", "scan", str(model_dir / "bad.pkl")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert p.returncode == 1 and "MS101" in p.stdout
