"""Collect a corpus of real model files from the Hugging Face Hub, small files and headers only.

Stages (each resumable):

1. ``list``: repositories and their file names from public listing endpoints (most downloaded,
   most recently modified, most liked, and per-library listings), skipping gated and private
   repositories.
2. ``fetch``: for each candidate file, the bytes a scanner needs, using HTTP range requests:
   the pickles inside PyTorch zip checkpoints (rebuilt into a small stub archive), the JSON
   config of ``.keras`` archives, safetensors headers, GGUF headers (scanned in memory and not
   stored), and whole files up to ``--max-file-mb`` for other formats.

Repository names are kept only in the private directory. Published results use salted
pseudonyms. No token is used, nothing is uploaded, and no repository owner is contacted.

Usage: uv run --project benchmarks python benchmarks/hf/collect.py {list,fetch} --data DIR
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import random
import secrets
import struct
import sys
import threading
import time
import zipfile
import zlib
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests

API = "https://huggingface.co/api"
HUB = "https://huggingface.co"
UA = {"User-Agent": "msscan-research/0.1 (read-only corpus study)"}

PICKLE_EXT = (".bin", ".pt", ".pth", ".ckpt", ".pkl", ".pickle", ".joblib", ".npy", ".npz", ".sav")
FULL_EXT = (".onnx", ".h5", ".hdf5", ".pb")
JSON_NAMES = ("config.json", "tokenizer_config.json")


class Limiter:
    """Fixed-rate gate shared by threads (the Hub publishes per-5-minute request budgets)."""

    def __init__(self, per_second: float) -> None:
        self.gap = 1.0 / per_second
        self.next = 0.0
        self.lock = threading.Lock()

    def wait(self) -> None:
        with self.lock:
            now = time.monotonic()
            t = max(now, self.next)
            self.next = t + self.gap
        time.sleep(max(0.0, t - time.monotonic()))


API_GATE = Limiter(1.4)
RESOLVE_GATE = Limiter(8.0)
LOCAL = threading.local()


def session() -> requests.Session:
    if not hasattr(LOCAL, "s"):
        LOCAL.s = requests.Session()
        LOCAL.s.headers.update(UA)
    return LOCAL.s  # type: ignore[no-any-return]


def get(url: str, gate: Limiter | None, **kw: Any) -> requests.Response:
    for attempt in range(6):
        if gate:
            gate.wait()
        try:
            r = session().get(url, timeout=60, **kw)
        except requests.RequestException:
            time.sleep(2 + 3 * attempt)
            continue
        if r.status_code == 429:
            time.sleep(int(r.headers.get("Retry-After", "30")) + random.random())
            continue
        if r.status_code >= 500:
            time.sleep(2 + 3 * attempt)
            continue
        return r
    raise RuntimeError("giving up after retries")


# ---------------------------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------------------------

LISTINGS = [
    ("downloads", {"sort": "downloads"}, 1500),
    ("recent", {"sort": "lastModified"}, 600),
    ("likes", {"sort": "likes"}, 300),
    ("gguf", {"sort": "downloads", "filter": "gguf"}, 400),
    ("keras", {"sort": "downloads", "filter": "keras"}, 250),
    ("onnx", {"sort": "downloads", "filter": "onnx"}, 250),
    ("sklearn", {"sort": "downloads", "filter": "sklearn"}, 300),
    ("joblib", {"sort": "downloads", "filter": "joblib"}, 150),
    ("tf", {"sort": "downloads", "filter": "tf"}, 150),
]


def cmd_list(data: Path) -> None:
    out = data / "private" / "repos.jsonl"
    seen: dict[str, dict[str, Any]] = {}
    for name, params, want in LISTINGS:
        url: str | None = f"{API}/models"
        q: dict[str, Any] = {
            **params,
            "direction": -1,
            "limit": 500,
            "expand[]": ["downloads", "gated", "private", "library_name", "createdAt", "siblings"],
        }
        got = 0
        while url and got < want:
            r = get(url, API_GATE, params=q)
            r.raise_for_status()
            for m in r.json():
                if m.get("private") or m.get("gated"):
                    continue
                got += 1
                seen.setdefault(
                    m["id"],
                    {
                        "id": m["id"],
                        "listing": name,
                        "downloads": m.get("downloads", 0),
                        "library": m.get("library_name"),
                        "created": m.get("createdAt"),
                        "files": [x["rfilename"] for x in m.get("siblings", [])],
                    },
                )
                if got >= want:
                    break
            url = r.links.get("next", {}).get("url")
            q = {}
        print(f"{name}: {got} repositories ({len(seen)} unique so far)", file=sys.stderr)
    out.write_text("".join(json.dumps(v) + "\n" for v in seen.values()))
    print(f"{len(seen)} repositories")


# ---------------------------------------------------------------------------------------------
# fetch
# ---------------------------------------------------------------------------------------------


def kind_of(path: str) -> str | None:
    base = path.rsplit("/", 1)[-1].lower()
    if base in JSON_NAMES:
        return "json" if "/" not in path else None
    if base.endswith(".safetensors"):
        return "safetensors"
    if base.endswith(".gguf"):
        return "gguf"
    if base.endswith(".keras"):
        return "keras"
    if base.endswith(PICKLE_EXT):
        return "pickle"
    if base.endswith(FULL_EXT):
        if base.endswith(".pb") and base not in ("saved_model.pb", "keras_metadata.pb"):
            return None
        return "full"
    return None


def select(files: list[str], per_kind: int, rng: random.Random) -> list[dict[str, Any]]:
    by: dict[str, list[dict[str, Any]]] = {}
    for name in files:
        k = kind_of(name)
        if k:
            by.setdefault(k, []).append({"path": name, "kind": k})
    out: list[dict[str, Any]] = []
    for k, fs in sorted(by.items()):
        fs.sort(key=lambda f: f["path"])
        # GGUF repositories hold many quantizations of one model: their headers are near copies.
        n = 1 if k == "gguf" else per_kind
        out += fs if k == "json" or len(fs) <= n else rng.sample(fs, n)
    return out


class Remote:
    """Ranged reads of one Hub file; the signed CDN location is resolved once and reused."""

    def __init__(self, repo: str, path: str) -> None:
        self.url = f"{HUB}/{repo}/resolve/main/{quote(path)}"
        self.cdn: str | None = None
        self.requests = 0
        self.bytes = 0
        self.size = self._size()

    def _size(self) -> int:
        """File size: X-Linked-Size for LFS files, else the Content-Range of a 1-byte read."""
        r = get(self.url, RESOLVE_GATE, headers={"Range": "bytes=0-0"}, allow_redirects=False)
        if r.status_code in (301, 302, 307, 308):
            loc = r.headers["Location"]
            self.cdn = HUB + loc if loc.startswith("/") else loc
            if "X-Linked-Size" in r.headers:
                return int(r.headers["X-Linked-Size"])
            r = get(self.cdn, None, headers={"Range": "bytes=0-0"})
        if r.status_code not in (200, 206):
            raise PermissionError(f"HTTP {r.status_code}")
        if r.status_code == 200:
            return len(r.content)
        return int(r.headers["Content-Range"].rsplit("/", 1)[-1])

    def read(self, start: int, end: int) -> bytes:
        """Bytes [start, end) of the file."""
        end = min(end, self.size)
        if end <= start:
            return b""
        hdr = {"Range": f"bytes={start}-{end - 1}"}
        if self.cdn is None:
            r = get(self.url, RESOLVE_GATE, headers=hdr, allow_redirects=False)
            if r.status_code in (301, 302, 307, 308):
                loc = r.headers["Location"]
                self.cdn = HUB + loc if loc.startswith("/") else loc
            elif r.status_code in (200, 206):
                self.cdn = self.url
                return self._take(r, start, end)
            else:
                raise PermissionError(f"HTTP {r.status_code}")
        r = get(self.cdn, None, headers=hdr)
        if r.status_code not in (200, 206):
            raise PermissionError(f"HTTP {r.status_code}")
        return self._take(r, start, end)

    def _take(self, r: requests.Response, start: int, end: int) -> bytes:
        self.requests += 1
        body = r.content
        if r.status_code == 200:  # the server ignored the range
            body = body[start:end]
        self.bytes += len(body)
        return body


def zip_members(
    rem: Remote, want: Callable[[str], bool], max_member: int
) -> dict[str, bytes] | None:
    """Fetch selected members of a remote zip; None when the file is not a zip."""
    tail_start = max(0, rem.size - 65558)
    tail = rem.read(tail_start, rem.size)
    i = tail.rfind(b"PK\x05\x06")
    if i < 0:
        return None
    (count,) = struct.unpack_from("<H", tail, i + 10)
    cd_size, cd_off = struct.unpack_from("<II", tail, i + 12)
    if 0xFFFFFFFF in (cd_off, cd_size) or count == 0xFFFF:
        loc = tail.rfind(b"PK\x06\x07", 0, i)
        if loc < 0:
            return None
        (rec_off,) = struct.unpack_from("<Q", tail, loc + 8)
        rec = rem.read(rec_off, rec_off + 56)
        count, cd_size, cd_off = struct.unpack_from("<QQQ", rec, 32)
    if cd_off >= tail_start:
        cd = tail[cd_off - tail_start : cd_off - tail_start + cd_size]
    else:
        cd = rem.read(cd_off, cd_off + cd_size)
    out: dict[str, bytes] = {}
    p = 0
    for _ in range(count):
        if cd[p : p + 4] != b"PK\x01\x02":
            break
        (method,) = struct.unpack_from("<H", cd, p + 10)
        csize, usize = struct.unpack_from("<II", cd, p + 20)
        nlen, xlen, clen = struct.unpack_from("<HHH", cd, p + 28)
        (loff,) = struct.unpack_from("<I", cd, p + 42)
        name = cd[p + 46 : p + 46 + nlen].decode("utf-8", "replace")
        extra = cd[p + 46 + nlen : p + 46 + nlen + xlen]
        vals = [usize, csize, loff]
        j = 0
        while j + 4 <= len(extra):
            hid, hlen = struct.unpack_from("<HH", extra, j)
            if hid == 1:
                k = j + 4
                for idx in range(3):
                    if vals[idx] == 0xFFFFFFFF:
                        vals[idx] = struct.unpack_from("<Q", extra, k)[0]
                        k += 8
            j += 4 + hlen
        usize, csize, loff = vals
        p += 46 + nlen + xlen + clen
        if not want(name) or csize > max_member:
            continue
        head = rem.read(loff, loff + 30)
        lnlen, lxlen = struct.unpack_from("<HH", head, 26)
        start = loff + 30 + lnlen + lxlen
        raw = rem.read(start, start + csize)
        if method == 8:
            raw = zlib.decompress(raw, -15)
        elif method != 0:
            continue
        out[name] = raw
    return out


def stub_zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        for n, d in members.items():
            z.writestr(zipfile.ZipInfo(n, date_time=(2020, 1, 1, 0, 0, 0)), d)
    return buf.getvalue()


def torch_member(name: str) -> bool:
    return name.endswith(".pkl") or name.rsplit("/", 1)[-1] in ("version", "byteorder")


def fetch_one(repo: str, f: dict[str, Any], dest: Path, max_full: int) -> dict[str, Any]:
    import msscan

    rem = Remote(repo, f["path"])
    f["size"] = rem.size
    rec: dict[str, Any] = {"repo": repo, "path": f["path"], "kind": f["kind"], "size": rem.size}
    base = f["path"].replace("/", "__")
    k = f["kind"]
    if k in ("pickle", "keras"):
        members = None
        if base.lower().endswith((".bin", ".pt", ".pth", ".ckpt", ".keras")) and f["size"] > 22:
            if k == "keras":
                members = zip_members(rem, lambda n: n.endswith(".json"), 32 << 20)
            else:
                members = zip_members(rem, torch_member, 64 << 20)
        if members is not None:
            if not any(n.endswith((".pkl", ".json")) for n in members):
                rec["status"] = "no-pickle-member"
                return rec
            data = stub_zip(members)
            rec["mode"] = "zip-members"
        elif f["size"] <= max_full:
            data = rem.read(0, f["size"])
            rec["mode"] = "full"
        else:
            rec["status"] = "too-large"
            return rec
        (dest / base).write_bytes(data)
        rec["stored"] = base
    elif k in ("full", "json"):
        if f["size"] > max_full and base.lower().endswith((".h5", ".hdf5")):
            # Keras writes model_config before the weights: the head and tail of the file hold
            # the root group's attributes.
            data = rem.read(0, 4 << 20) + rem.read(max(4 << 20, f["size"] - (1 << 20)), f["size"])
            (dest / base).write_bytes(data)
            rec["stored"], rec["mode"] = base, "head-tail"
            rec["status"] = "ok"
            rec["requests"], rec["downloaded"] = rem.requests, rem.bytes
            return rec
        if f["size"] > max_full:
            rec["status"] = "too-large"
            return rec
        (dest / base).write_bytes(rem.read(0, f["size"]))
        rec["stored"], rec["mode"] = base, "full"
    elif k == "safetensors":
        head = rem.read(0, 1 << 17)
        n = struct.unpack_from("<Q", head)[0] if len(head) >= 8 else 0
        if 8 + n > len(head) and n < (100 << 20):
            head += rem.read(len(head), 8 + n)
        (dest / base).write_bytes(head[: 8 + n] if n < (100 << 20) else head)
        rec["stored"], rec["mode"] = base, "header"
    elif k == "gguf":
        got = b""
        step = 4 << 20
        while True:
            got += rem.read(len(got), min(f["size"], len(got) + step))
            r = msscan.scan_bytes(got, base, declared_size=f["size"])
            if not r.stats.get("prefix_incomplete") or len(got) >= min(32 << 20, f["size"]):
                break
            step *= 2
        rec["mode"] = "header-streamed"
        rec["prefix_bytes"] = len(got)
        rec["report"] = r.raw
        rec["prefix_incomplete"] = bool(r.stats.get("prefix_incomplete"))
    rec["status"] = "ok"
    rec["requests"], rec["downloaded"] = rem.requests, rem.bytes
    return rec


def pseudonym(salt: str, repo: str) -> str:
    return "r" + hashlib.sha256((salt + repo).encode()).hexdigest()[:12]


def salt_for(data: Path) -> str:
    f = data / "private" / "salt"
    if not f.exists():
        f.write_text(secrets.token_hex(16))
    return f.read_text().strip()


def cmd_fetch(
    data: Path,
    workers: int,
    per_kind: int,
    max_full_mb: int,
    budget_gb: float,
    seed: int,
    retry_large: bool = False,
) -> None:
    priv = data / "private"
    files_dir = data / "files"
    salt = salt_for(data)
    repos = [json.loads(line) for line in (priv / "repos.jsonl").open()]
    out = priv / "fetched.jsonl"
    prior = [json.loads(line) for line in out.open()] if out.exists() else []

    def retry(d: dict[str, Any]) -> bool:
        return (
            retry_large
            and d["status"] == "too-large"
            and d["path"].lower().endswith((".h5", ".hdf5"))
        )

    done = {(d["repo"], d["path"]) for d in prior if not retry(d)}
    rng = random.Random(seed)
    jobs = []
    for t in repos:
        for f in select(t["files"], per_kind, rng):
            if (t["id"], f["path"]) not in done:
                jobs.append((t["id"], f))
    rng.shuffle(jobs)
    lock = threading.Lock()
    budget = int(budget_gb * (1 << 30))
    used = (
        sum(p.stat().st_size for p in files_dir.rglob("*") if p.is_file())
        if files_dir.exists()
        else 0
    )
    state = {"used": used, "n": 0}
    print(f"{len(jobs)} files to fetch ({used / 2**20:.0f} MB stored)", file=sys.stderr)

    def one(job: tuple[str, dict[str, Any]]) -> None:
        repo, f = job
        if state["used"] > budget:
            return
        dest = files_dir / pseudonym(salt, repo)
        dest.mkdir(parents=True, exist_ok=True)
        base = {"repo": repo, "path": f["path"], "kind": f["kind"], "size": f.get("size", -1)}
        try:
            rec = fetch_one(repo, f, dest, max_full_mb << 20)
        except PermissionError as e:
            rec = {**base, "status": f"denied {e}"}
        except Exception as e:  # recorded, not fatal
            rec = {**base, "status": f"error {type(e).__name__}: {str(e)[:120]}"}
        with lock:
            if rec.get("stored"):
                state["used"] += (dest / rec["stored"]).stat().st_size
            state["n"] += 1
            with out.open("a") as fh:
                fh.write(json.dumps(rec) + "\n")
            if state["n"] % 250 == 0:
                print(
                    f"fetched {state['n']}/{len(jobs)}, {state['used'] / 2**20:.0f} MB",
                    file=sys.stderr,
                )

    with ThreadPoolExecutor(workers) as ex:
        list(ex.map(one, jobs))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("stage", choices=["list", "fetch"])
    ap.add_argument("--data", type=Path, required=True)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--per-kind", type=int, default=3, help="files of each kind per repository")
    ap.add_argument("--max-file-mb", type=int, default=20)
    ap.add_argument("--budget-gb", type=float, default=2.5)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--retry-large", action="store_true", help="retry files skipped as too large")
    a = ap.parse_args()
    os.makedirs(a.data / "private", exist_ok=True)
    if a.stage == "list":
        cmd_list(a.data)
    else:
        cmd_fetch(a.data, a.workers, a.per_kind, a.max_file_mb, a.budget_gb, a.seed, a.retry_large)


if __name__ == "__main__":
    main()
