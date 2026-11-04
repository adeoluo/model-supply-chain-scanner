from __future__ import annotations

import json

import pytest

import msscan
from msscan.api import severity_rank
from tests.conftest import BENIGN, GETCWD


def test_scan_bytes_malicious_and_clean() -> None:
    r = msscan.scan_bytes(GETCWD, "m.pkl")
    assert r.verdict == "malicious"
    assert r.max_severity == "critical"
    assert "MS101" in r.rules()
    assert r.flagged() and r.flagged("critical")
    assert r.imports[0].module == "posix" or r.imports[0].module == "os"
    assert r.imports[0].tier == "dangerous" and r.imports[0].called
    assert "MS101" in r.summary()
    clean = msscan.scan_bytes(BENIGN, "m.pkl")
    assert clean.verdict == "clean" and not clean.flagged("low")
    assert clean.risk_score == 0


def test_declared_size_and_hash() -> None:
    header = b'{"a":{"dtype":"U8","shape":[4],"data_offsets":[0,4]}}'
    blob = len(header).to_bytes(8, "little") + header
    r = msscan.scan_bytes(blob, "m.safetensors", declared_size=len(blob) + 4, hash=True)
    assert r.format == "safetensors" and r.verdict == "clean"
    assert r.size == len(blob) + 4
    assert r.sha256 is not None and len(r.sha256) == 64


def test_scan_path_and_file(model_dir) -> None:  # type: ignore[no-untyped-def]
    reports = msscan.scan_path(model_dir)
    assert sorted(r.verdict for r in reports) == ["clean", "malicious"]
    one = msscan.scan_file(model_dir / "bad.pkl", hash=True)
    assert one.sha256
    with pytest.raises(IsADirectoryError):
        msscan.scan_file(model_dir)
    missing = msscan.scan_path(model_dir / "nope")
    assert missing[0].verdict == "error" and missing[0].error


def test_render_formats(model_dir) -> None:  # type: ignore[no-untyped-def]
    reports = msscan.scan_path(model_dir)
    sarif = json.loads(msscan.render(reports, "sarif"))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "MS101"
    assert "MALICIOUS" in msscan.render(reports, "text")
    only_crit = json.loads(msscan.render(reports, "json", min_severity="critical"))
    assert all(f["severity"] == "critical" for r in only_crit for f in r["findings"])
    with pytest.raises(ValueError):
        msscan.render(reports, "xml")
    with pytest.raises(ValueError):
        msscan.render(reports, "text", min_severity="severe")


def test_rules_catalog() -> None:
    rules = msscan.rules()
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids)) > 30
    assert {r.severity for r in rules} <= set(msscan.SEVERITIES)
    assert severity_rank(None) == -1 and severity_rank("critical") == 4
