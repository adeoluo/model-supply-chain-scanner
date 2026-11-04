from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
import urllib.request
from collections.abc import Iterator

import pytest

from tests.conftest import GETCWD


@pytest.fixture(scope="module")
def server() -> Iterator[str]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    proc = subprocess.Popen(
        [sys.executable, "-m", "msscan", "serve", "--addr", f"127.0.0.1:{port}", "--threads", "2"],
        stderr=subprocess.PIPE,
    )
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            urllib.request.urlopen(base + "/health", timeout=1)
            break
        except OSError:
            time.sleep(0.05)
    yield base
    proc.terminate()
    proc.wait(timeout=10)


def test_health_ready_metrics(server: str) -> None:
    assert json.load(urllib.request.urlopen(server + "/health"))["status"] == "ok"
    assert json.load(urllib.request.urlopen(server + "/ready"))["rules"] > 30
    req = urllib.request.Request(server + "/v1/scan?name=m.pkl", data=GETCWD, method="POST")
    report = json.load(urllib.request.urlopen(req))
    assert report["verdict"] == "malicious"
    metrics = urllib.request.urlopen(server + "/metrics").read().decode()
    assert 'msscan_files_scanned_total{verdict="malicious"}' in metrics
    assert "msscan_scan_seconds_bucket" in metrics
    rules = json.load(urllib.request.urlopen(server + "/v1/rules"))
    assert rules[0]["id"] == "MS101"
