"""Write the small, inert fixtures in tests/fixtures (deterministic; standard library only).

Every "malicious" fixture references a harmless function (os.getcwd, print) or a path that
does not exist; none of them is ever loaded by the tests. Run: python scripts/make_fixtures.py
"""

from __future__ import annotations

import io
import json
import os
import pickle
import struct
import zipfile
from collections import OrderedDict
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


class Reduce:
    def __init__(self, func: object, args: tuple[object, ...] = ()) -> None:
        self.func, self.args = func, args

    def __reduce__(self) -> tuple[object, tuple[object, ...]]:
        return (self.func, self.args)


def torch_like_zip(pkl: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        for name, data in (("archive/data.pkl", pkl), ("archive/version", b"3\n")):
            info = zipfile.ZipInfo(name, date_time=(2024, 1, 1, 0, 0, 0))
            z.writestr(info, data)
    return buf.getvalue()


def gguf(template: str) -> bytes:
    def s(x: str) -> bytes:
        b = x.encode()
        return struct.pack("<Q", len(b)) + b

    kv = s("general.architecture") + struct.pack("<I", 8) + s("llama")
    kv += s("tokenizer.chat_template") + struct.pack("<I", 8) + s(template)
    out = b"GGUF" + struct.pack("<IQQ", 3, 0, 2) + kv
    return out + b"\0" * (-len(out) % 32)


def safetensors(header: dict[str, object], data: bytes) -> bytes:
    h = json.dumps(header, separators=(",", ":")).encode()
    return struct.pack("<Q", len(h)) + h + data


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    getcwd = pickle.dumps(Reduce(os.getcwd), protocol=2)
    files = {
        "malicious_getcwd.pkl": getcwd,
        "malicious_torch.pt": torch_like_zip(getcwd),
        "malicious_template.gguf": gguf("{{ cycler.__init__.__globals__.os.getcwd() }}"),
        "clean_state_dict.pt": torch_like_zip(pickle.dumps(OrderedDict(w=[1.0, 2.0]), protocol=2)),
        "clean_chatml.gguf": gguf("{% for m in messages %}{{ m['content'] }}{% endfor %}"),
        "clean.safetensors": safetensors(
            {"w": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]}}, b"\0" * 8
        ),
        "invalid_offsets.safetensors": safetensors(
            {"w": {"dtype": "F32", "shape": [4], "data_offsets": [0, 8]}}, b"\0" * 8
        ),
    }
    for name, data in files.items():
        (OUT / name).write_bytes(data)
    print(f"wrote {len(files)} fixtures to {OUT}")


if __name__ == "__main__":
    main()
