"""Typed wrappers around the Rust core."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from msscan import msscan_rs

SEVERITIES: tuple[str, ...] = ("info", "low", "medium", "high", "critical")


def severity_rank(severity: str | None) -> int:
    """Position of a severity in :data:`SEVERITIES`; -1 for none."""
    return SEVERITIES.index(severity) if severity in SEVERITIES else -1


@dataclass(frozen=True)
class Finding:
    rule: str
    name: str
    severity: str
    message: str
    location: str


@dataclass(frozen=True)
class ImportRecord:
    module: str
    name: str
    tier: str
    count: int
    called: bool
    member: str


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str
    cwe: str
    summary: str
    remediation: str


@dataclass(frozen=True)
class Report:
    path: str
    format: str
    size: int
    verdict: str
    risk_score: int
    max_severity: str | None
    findings: tuple[Finding, ...]
    imports: tuple[ImportRecord, ...]
    stats: dict[str, int]
    elapsed_us: int
    sha256: str | None = None
    error: str | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Report:
        return cls(
            path=d["path"],
            format=d["format"],
            size=d["size"],
            verdict=d["verdict"],
            risk_score=d["risk_score"],
            max_severity=d.get("max_severity"),
            findings=tuple(Finding(**f) for f in d["findings"]),
            imports=tuple(ImportRecord(**i) for i in d["imports"]),
            stats=dict(d["stats"]),
            elapsed_us=d["elapsed_us"],
            sha256=d.get("sha256"),
            error=d.get("error"),
            raw=d,
        )

    def flagged(self, threshold: str = "high") -> bool:
        """Whether any finding reaches ``threshold``."""
        return severity_rank(self.max_severity) >= severity_rank(threshold)

    def rules(self) -> set[str]:
        return {f.rule for f in self.findings}

    def summary(self) -> str:
        head = f"{self.path}: {self.verdict} (risk {self.risk_score}, {self.format})"
        lines = [f"  {f.severity:<8} {f.rule:<7} {f.message}" for f in self.findings]
        return "\n".join([head, *lines])


def scan_bytes(
    data: bytes,
    name: str = "<bytes>",
    *,
    hash: bool = False,
    max_decompressed: int = 1 << 30,
    declared_size: int | None = None,
) -> Report:
    """Scan an in-memory buffer. ``declared_size`` is the real file size when ``data`` is only
    a prefix (for example a safetensors or GGUF header fetched with an HTTP range request)."""
    out = msscan_rs.scan_bytes(bytes(data), name, hash, max_decompressed, declared_size)
    return Report.from_dict(json.loads(out))


def scan_path(
    path: str | os.PathLike[str], *, hash: bool = False, max_decompressed: int = 1 << 30
) -> list[Report]:
    """Scan a file or every file under a directory (in parallel)."""
    out = msscan_rs.scan_path(Path(path), hash, max_decompressed, "json", "info")
    return [Report.from_dict(d) for d in json.loads(out)]


def scan_file(path: str | os.PathLike[str], *, hash: bool = False) -> Report:
    """Scan one file."""
    p = Path(path)
    if p.is_dir():
        raise IsADirectoryError(str(p))
    return scan_path(p, hash=hash)[0]


def render(reports: list[Report], output: str = "text", *, min_severity: str = "low") -> str:
    """Render reports as ``text``, ``json`` or ``sarif`` (SARIF 2.1.0)."""
    return str(msscan_rs.render(json.dumps([r.raw for r in reports]), output, min_severity))


def rules() -> list[Rule]:
    """The rule catalog."""
    return [Rule(**r) for r in json.loads(msscan_rs.rules())]
