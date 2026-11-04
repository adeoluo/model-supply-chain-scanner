"""Write the small, inert fixtures in tests/fixtures (deterministic; standard library only).

Every "malicious" fixture references a harmless function (os.getcwd, print) or a path that
does not exist; none of them is ever loaded by the tests. Run: python scripts/make_fixtures.py
"""

from __future__ import annotations

import gzip
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


def _s(v: str) -> bytes:
    b = v.encode()
    return b"\x8c" + bytes([len(b)]) + b


def pb(field: int, data: bytes) -> bytes:
    def varint(v: int) -> bytes:
        out = bytearray()
        while True:
            out.append((v & 0x7F) | (0x80 if v > 0x7F else 0))
            v >>= 7
            if not v:
                return bytes(out)

    return varint(field << 3 | 2) + varint(len(data)) + data


def onnx_traversal() -> bytes:
    entry = pb(1, b"location") + pb(2, b"../../outside/weights.bin")
    tensor = pb(8, b"W") + pb(13, entry) + b"\x70\x01"  # data_location = EXTERNAL
    node = pb(1, b"x") + pb(1, b"W") + pb(2, b"y") + pb(4, b"MatMul")
    graph = pb(1, node) + pb(5, tensor)
    return b"\x08\x08" + pb(7, graph)


def npy_object(payload: bytes) -> bytes:
    header = "{'descr': '|O', 'fortran_order': False, 'shape': (1,), }"
    header += " " * (-(10 + len(header) + 1) % 64) + "\n"
    return b"\x93NUMPY\x01\x00" + struct.pack("<H", len(header)) + header.encode() + payload


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
        "malicious_dynamic_import.pkl": b"\x80\x04"
        + _s("_codecs")
        + _s("encode")
        + b"\x93"
        + _s("bf")
        + _s("rot13")
        + b"\x86R"
        + _s("getcwd")
        + b"\x93)R.",
        "malicious_setstate.pkl": b"\x80\x02cargparse\nNamespace\n)R}"
        + _s("__setstate__")
        + b"cbuiltins\nprint\nsb"
        + _s("inert")
        + b"b.",
        "malicious_gzip.pkl.gz": gzip.compress(getcwd, mtime=0),
        "malicious_object_array.npy": npy_object(getcwd),
        "unsafe_traversal.onnx": onnx_traversal(),
        "invalid_offsets.safetensors": safetensors(
            {"w": {"dtype": "F32", "shape": [4], "data_offsets": [0, 8]}}, b"\0" * 8
        ),
    }
    for name, data in files.items():
        (OUT / name).write_bytes(data)
    print(f"wrote {len(files)} fixtures to {OUT}")


if __name__ == "__main__":
    main()
