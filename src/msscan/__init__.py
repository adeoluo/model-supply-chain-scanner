"""Scan machine learning model files for code execution and unsafe content before loading them.

The analysis runs in a compiled Rust core (``msscan.msscan_rs``); nothing in a scanned file is
imported, unpickled or executed. Results come back as typed dataclasses::

    import msscan

    report = msscan.scan_file("pytorch_model.bin")
    if report.verdict in ("malicious", "unsafe"):
        raise SystemExit(report.summary())
"""

from __future__ import annotations

from msscan.api import (
    SEVERITIES,
    Finding,
    ImportRecord,
    Report,
    Rule,
    render,
    rules,
    scan_bytes,
    scan_file,
    scan_path,
)

__version__ = "0.1.1"

__all__ = [
    "SEVERITIES",
    "Finding",
    "ImportRecord",
    "Report",
    "Rule",
    "__version__",
    "render",
    "rules",
    "scan_bytes",
    "scan_file",
    "scan_path",
]
