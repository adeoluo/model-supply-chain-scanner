"""Generate the local benchmark corpus: inert malicious files for every technique, and benign
files written by the real libraries.

Every malicious payload is inert: it prints a canary string (``MSSCAN-CANARY``), returns the
current directory (``os.getcwd``) or sets a harmless attribute. Nothing deletes, writes outside
the corpus directory, opens a network connection or persists. External data paths point to
files that do not exist. Pickles are written, never loaded, by this script; ``validate.py``
loads them in a subprocess to confirm that each payload really runs under its loader.

Usage: uv run --project benchmarks python benchmarks/corpus/generate.py --out DIR
"""

from __future__ import annotations

import argparse
import base64
import code
import cProfile
import functools
import gzip
import importlib
import io
import json
import marshal
import operator
import os
import pickle
import runpy
import struct
import subprocess
import timeit
import zipfile
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

CANARY = "MSSCAN-CANARY"


class Reduce:
    """Pickles as ``func(*args)``; never called here."""

    def __init__(self, func: Any, args: tuple[Any, ...] = ()) -> None:
        self.func, self.args = func, args

    def __reduce__(self) -> tuple[Any, tuple[Any, ...]]:
        return (self.func, self.args)

    def __call__(self) -> None:  # pickle requires reduce callables to be callable
        raise RuntimeError("not to be called")


def say(tag: str) -> str:
    return f"print('{CANARY} {tag}')"


@dataclass
class Item:
    path: str
    label: str  # "malicious" or "benign"
    family: str
    technique: str
    category: str  # "code-execution", "file-access", "structure" or "benign"
    loader: str  # how validate.py loads it, or "" when not validated
    note: str = ""


class Corpus:
    def __init__(self, out: Path) -> None:
        self.out = out
        self.items: list[Item] = []

    def add(self, rel: str, data: bytes, **kw: str) -> None:
        p = self.out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        self.items.append(Item(path=rel, **kw))

    def written(self, p: Path, **kw: str) -> None:
        self.items.append(Item(path=str(p.relative_to(self.out)), **kw))

    def write_manifest(self) -> None:
        with (self.out / "manifest.jsonl").open("w") as f:
            for it in self.items:
                f.write(json.dumps(asdict(it)) + "\n")


# ---------------------------------------------------------------------------------------------
# Pickle payloads
# ---------------------------------------------------------------------------------------------


def p_reduce_getcwd(proto: int) -> bytes:
    return pickle.dumps(Reduce(os.getcwd), protocol=proto)


def p_eval(proto: int) -> bytes:
    return pickle.dumps(Reduce(eval, (say("eval"),)), protocol=proto)


def p_exec(proto: int) -> bytes:
    return pickle.dumps(Reduce(exec, (say("exec"),)), protocol=proto)


def p_runpy(proto: int) -> bytes:
    return pickle.dumps(Reduce(runpy._run_code, (say("runpy"), {})), protocol=proto)


def p_numpy_runstring(proto: int) -> bytes:
    import numpy.testing._private.utils as u

    return pickle.dumps(Reduce(u.runstring, (say("numpy-runstring"), {})), protocol=proto)


def p_timeit(proto: int) -> bytes:
    args = (say("timeit"), "pass", timeit.default_timer, 1)
    return pickle.dumps(Reduce(timeit.timeit, args), protocol=proto)


def p_methodcaller(proto: int) -> bytes:
    interp = Reduce(code.InteractiveInterpreter, ())
    caller = Reduce(operator.methodcaller, ("runsource", say("methodcaller")))
    return pickle.dumps(Reduce(caller, (interp,)), protocol=proto)


def p_getattr_import(proto: int) -> bytes:
    fn = Reduce(getattr, (Reduce(__import__, ("os",)), "getcwd"))
    return pickle.dumps(Reduce(fn, ()), protocol=proto)


def p_importlib(proto: int) -> bytes:
    fn = Reduce(getattr, (Reduce(importlib.import_module, ("os",)), "getcwd"))
    return pickle.dumps(Reduce(fn, ()), protocol=proto)


def p_partial_print(proto: int) -> bytes:
    part = Reduce(functools.partial, (print, f"{CANARY} partial"))
    return pickle.dumps(Reduce(part, ()), protocol=proto)


def p_subprocess_harmless(proto: int) -> bytes:
    return pickle.dumps(Reduce(subprocess.list2cmdline, ([CANARY, "subprocess"],)), protocol=proto)


def p_cprofile(proto: int) -> bytes:
    return pickle.dumps(Reduce(cProfile.run, (say("cprofile"),)), protocol=proto)


def p_nested_loads(proto: int) -> bytes:
    inner = pickle.dumps(Reduce(exec, (say("nested"),)), protocol=2)
    return pickle.dumps(Reduce(pickle.loads, (inner,)), protocol=proto)


def raw_marshal_function() -> bytes:
    blob = marshal.dumps(compile(say("marshal"), "<inert>", "exec"))
    return (
        b"\x80\x03ctypes\nFunctionType\ncmarshal\nloads\nB"
        + struct.pack("<I", len(blob))
        + blob
        + b"\x85R}\x86R)R."
    )


def _s(v: str) -> bytes:
    b = v.encode()
    return b"\x8c" + bytes([len(b)]) + b


RAW: dict[str, tuple[bytes, str]] = {
    "memo-stack-global": (
        b"\x80\x04"
        + _s("builtins")
        + b"\x94"
        + _s("exec")
        + b"\x94"
        + b"00h\x00h\x01\x93"
        + _s(say("memo"))
        + b"\x85R.",
        "STACK_GLOBAL operands come from the memo",
    ),
    "dynamic-stack-global": (
        b"\x80\x04"
        + _s("_codecs")
        + _s("encode")
        + b"\x93"
        + _s("bf")
        + _s("rot13")
        + b"\x86R"
        + _s("getcwd")
        + b"\x93)R.",
        "STACK_GLOBAL module name computed with _codecs.encode(..., 'rot13')",
    ),
    "inst-opcode": (
        b'(S"' + say("inst").encode() + b'"\nibuiltins\nexec\n.',
        "protocol 0 INST",
    ),
    "obj-opcode": (
        b'(cbuiltins\nexec\nS"' + say("obj").encode() + b'"\no.',
        "protocol 1 OBJ",
    ),
    "newobj-partial": (
        b"\x80\x02cfunctools\npartial\ncbuiltins\nprint\n"
        + _s(f"{CANARY} newobj")
        + b"\x86\x81)R.",
        "NEWOBJ builds functools.partial(print, ...), then REDUCE calls it",
    ),
    "setstate-injection": (
        b"\x80\x02cargparse\nNamespace\n)R}"
        + _s("__setstate__")
        + b"cbuiltins\nexec\nsb"
        + _s(say("setstate"))
        + b"b.",
        "BUILD assigns __setstate__ = exec, a second BUILD calls it",
    ),
    "dotted-attribute-path": (
        b"\x80\x04" + _s("argparse") + _s("_os.getcwd") + b"\x93)R.",
        "protocol 4 dotted name reaches os.getcwd through argparse._os",
    ),
    "marshal-function": (raw_marshal_function(), "types.FunctionType from marshalled bytecode"),
    "build-monkeypatch": (
        b"\x80\x02cargparse\nNamespace\nN}"
        + _s("msscan_canary")
        + _s(CANARY + " monkeypatch")
        + b"s\x86b.",
        "BUILD sets an attribute on an imported class (in-process tampering)",
    ),
}


PICKLE_TECHNIQUES: dict[str, tuple[Callable[[int], bytes], str]] = {
    "reduce-os-getcwd": (p_reduce_getcwd, "REDUCE of os.getcwd"),
    "builtins-eval": (p_eval, "builtins.eval of a print statement"),
    "builtins-exec": (p_exec, "builtins.exec of a print statement"),
    "runpy-run-code": (p_runpy, "runpy._run_code"),
    "numpy-runstring": (p_numpy_runstring, "numpy.testing runstring (an exec wrapper)"),
    "timeit": (p_timeit, "timeit.timeit runs a statement"),
    "methodcaller-interpreter": (p_methodcaller, "operator.methodcaller on InteractiveInterpreter"),
    "getattr-import": (p_getattr_import, "getattr(__import__('os'), 'getcwd')()"),
    "importlib-getattr": (p_importlib, "getattr(importlib.import_module('os'), 'getcwd')()"),
    "partial-print": (p_partial_print, "functools.partial(print, ...)() with library globals only"),
    "subprocess-harmless": (p_subprocess_harmless, "a harmless function from subprocess"),
    "cprofile-run": (p_cprofile, "cProfile.run executes a statement"),
    "nested-pickle-loads": (p_nested_loads, "pickle.loads of an embedded pickle"),
}


def hard_tier() -> dict[str, tuple[bytes, str]]:
    """Payloads that run code through functions outside the scanner's denylist."""
    import logging.config
    import pydoc
    import typing

    cfg = {
        "version": 1,
        "handlers": {"h": {"()": "builtins.print", "end": f"{CANARY} logging\n"}},
        "root": {"handlers": ["h"]},
    }
    fwd = Reduce(typing.ForwardRef, (f"print('{CANARY} typing')",))
    return {
        "hard-logging-dictconfig": (
            pickle.dumps(Reduce(logging.config.dictConfig, (cfg,)), protocol=4),
            "logging.config.dictConfig imports and calls a factory named by a string",
        ),
        "hard-typing-forwardref": (
            pickle.dumps(Reduce(typing._eval_type, (fwd, {}, {})), protocol=4),  # type: ignore[attr-defined]
            "typing._eval_type evaluates a ForwardRef string",
        ),
        "hard-pydoc-locate": (
            pickle.dumps(Reduce(Reduce(pydoc.locate, ("os.getcwd",)), ()), protocol=4),
            "pydoc.locate resolves os.getcwd from a string, then it is called",
        ),
    }


def gen_pickles(c: Corpus) -> None:
    kw = {
        "label": "malicious",
        "family": "pickle",
        "category": "code-execution",
        "loader": "pickle",
    }
    for tech, (fn, note) in PICKLE_TECHNIQUES.items():
        for proto in (0, 2, 4, 5):
            c.add(
                f"malicious/pickle/{tech}.p{proto}.pkl", fn(proto), technique=tech, note=note, **kw
            )
    for tech, (data, note) in {**RAW, **hard_tier()}.items():
        c.add(f"malicious/pickle/{tech}.pkl", data, technique=tech, note=note, **kw)
    c.add(
        "malicious/pickle/odd-extension.txt",
        p_exec(4),
        technique="odd-extension",
        note="pickle named .txt",
        **kw,
    )
    kw["loader"] = "pickle-gzip"
    c.add(
        "malicious/pickle/gzip-wrapped.pkl.gz",
        gzip.compress(p_exec(4), mtime=0),
        technique="gzip-wrapped",
        note="gzip-compressed pickle",
        **kw,
    )


# ---------------------------------------------------------------------------------------------
# PyTorch
# ---------------------------------------------------------------------------------------------


def torch_save(obj: Any, **kw: Any) -> bytes:
    import torch

    buf = io.BytesIO()
    torch.save(obj, buf, **kw)
    return buf.getvalue()


def tamper_zip(data: bytes, entry_suffix: str, fn: Callable[[bytearray, int], None]) -> bytes:
    """Apply ``fn(buf, local_header_offset)`` to the entry whose name ends with the suffix."""
    buf = bytearray(data)
    zf = zipfile.ZipFile(io.BytesIO(data))
    info = next(i for i in zf.infolist() if i.filename.endswith(entry_suffix))
    fn(buf, info.header_offset)
    return bytes(buf)


def legacy_split(data: bytes) -> list[bytes]:
    """Split a legacy torch file into its five pickles plus the trailing storage bytes."""
    import pickletools

    parts, pos = [], 0
    for _ in range(5):
        end = pos
        for _op, _arg, p in pickletools.genops(io.BytesIO(data[pos:])):
            end = pos + p + 1
        parts.append(data[pos:end])
        pos = end
    parts.append(data[pos:])
    return parts


def gen_torch(c: Corpus) -> None:
    import torch
    import torch.storage

    sd = OrderedDict(weight=torch.ones(2, 2), bias=torch.zeros(2))
    payload = {"state_dict": sd, "extra": Reduce(exec, (say("torch"),))}
    zipped = torch_save(payload)
    kw = {
        "label": "malicious",
        "family": "pytorch",
        "category": "code-execution",
        "loader": "torch",
    }
    c.add(
        "malicious/pytorch/zip-data-pkl.pt",
        zipped,
        technique="zip-data-pkl",
        note="payload in data.pkl",
        **kw,
    )
    c.add(
        "malicious/pytorch/pytorch_model.bin",
        zipped,
        technique="zip-as-bin",
        note="zip checkpoint named .bin",
        **kw,
    )

    def rename_local(buf: bytearray, off: int) -> None:
        nlen = struct.unpack_from("<H", buf, off + 26)[0]
        name = bytes(buf[off + 30 : off + 30 + nlen])
        buf[off + 30 : off + 30 + nlen] = name.replace(b"data.pkl", b"data.pkx")

    c.add(
        "malicious/pytorch/zip-local-name-mismatch.pt",
        tamper_zip(zipped, "data.pkl", rename_local),
        technique="zip-local-name-mismatch",
        note="local header name differs from the central directory",
        **kw,
    )

    def flag_bits(buf: bytearray, off: int) -> None:
        flags = struct.unpack_from("<H", buf, off + 6)[0]
        struct.pack_into("<H", buf, off + 6, flags | 0x1)

    c.add(
        "malicious/pytorch/zip-encrypted-flag.pt",
        tamper_zip(zipped, "data.pkl", flag_bits),
        technique="zip-encrypted-flag",
        note="encryption bit set on a stored entry",
        **kw,
    )
    legacy = torch_save(payload, _use_new_zipfile_serialization=False)
    c.add(
        "malicious/pytorch/legacy-main-pickle.pt",
        legacy,
        technique="legacy-main-pickle",
        note="legacy (pre-1.6) format",
        **kw,
    )
    parts = legacy_split(legacy)
    parts[2] = pickle.dumps(Reduce(exec, (say("legacy-sysinfo"),)), protocol=2)
    c.add(
        "malicious/pytorch/legacy-sysinfo-pickle.pt",
        b"".join(parts),
        technique="legacy-sysinfo-pickle",
        note="payload in the third pickle of a legacy file",
        **kw,
    )
    inner = torch_save({"x": Reduce(exec, (say("torch-nested"),))})
    nested = torch_save({"blob": Reduce(torch.storage._load_from_bytes, (inner,))})
    c.add(
        "malicious/pytorch/nested-load-from-bytes.pt",
        nested,
        technique="nested-load-from-bytes",
        note="torch.storage._load_from_bytes of an embedded checkpoint",
        **kw,
    )


# ---------------------------------------------------------------------------------------------
# NumPy and joblib
# ---------------------------------------------------------------------------------------------


def gen_numpy_joblib(c: Corpus) -> None:
    import joblib
    import numpy as np

    arr = np.empty(2, dtype=object)
    arr[0], arr[1] = Reduce(exec, (say("npy"),)), "ok"
    buf = io.BytesIO()
    np.save(buf, arr, allow_pickle=True)
    npy = buf.getvalue()
    kw = {"label": "malicious", "family": "numpy", "category": "code-execution"}
    c.add(
        "malicious/numpy/object-array.npy",
        npy,
        technique="object-array",
        loader="numpy",
        note="np.load(allow_pickle=True)",
        **kw,
    )
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as z:
        z.writestr("w.npy", npy)
    c.add(
        "malicious/numpy/object-array.npz",
        zbuf.getvalue(),
        technique="object-array-npz",
        loader="numpy-npz",
        note="inside .npz",
        **kw,
    )

    kw = {
        "label": "malicious",
        "family": "joblib",
        "category": "code-execution",
        "loader": "joblib",
    }
    model = {"coef": np.arange(64, dtype=np.float64), "payload": Reduce(exec, (say("joblib"),))}
    out = io.BytesIO()
    joblib.dump(model, out)
    c.add(
        "malicious/joblib/plain.joblib",
        out.getvalue(),
        technique="plain",
        note="payload object",
        **kw,
    )
    after = {"coef": np.full(64, 1.0), "z_payload": Reduce(exec, (say("joblib-after-array"),))}
    out = io.BytesIO()
    joblib.dump(after, out)
    c.add(
        "malicious/joblib/after-raw-array.joblib",
        out.getvalue(),
        technique="after-raw-array",
        note="payload after raw array bytes",
        **kw,
    )
    objarr = np.empty(1, dtype=object)
    objarr[0] = Reduce(exec, (say("joblib-object-array"),))
    out = io.BytesIO()
    joblib.dump({"a": objarr}, out)
    c.add(
        "malicious/joblib/object-array.joblib",
        out.getvalue(),
        technique="object-array",
        note="payload in an object array's nested pickle",
        **kw,
    )
    for comp in ("zlib", "gzip", "bz2", "xz", "lzma"):
        p = c.out / f"malicious/joblib/compressed-{comp}.joblib"
        p.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(model, p, compress=(comp, 3))
        c.written(p, technique=f"compressed-{comp}", note=f"joblib compress={comp}", **kw)


# ---------------------------------------------------------------------------------------------
# Keras, SavedModel, ONNX
# ---------------------------------------------------------------------------------------------


def keras_zip(config: dict[str, Any]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("config.json", json.dumps(config))
        z.writestr("metadata.json", json.dumps({"keras_version": "3.6.0"}))
    return buf.getvalue()


def pb_varint(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def pb_bytes(field: int, data: bytes) -> bytes:
    return pb_varint(field << 3 | 2) + pb_varint(len(data)) + data


def pb_int(field: int, v: int) -> bytes:
    return pb_varint(field << 3) + pb_varint(v)


def keras_metadata_pb(meta_json: str) -> bytes:
    node = (
        pb_int(2, 1)
        + pb_bytes(3, b"root.layer-0")
        + pb_bytes(4, b"_tf_keras_layer")
        + pb_bytes(5, meta_json.encode())
    )
    return pb_bytes(1, node)


def saved_model(ops: list[str]) -> bytes:
    nodes = b"".join(
        pb_bytes(1, pb_bytes(1, f"n{i}".encode()) + pb_bytes(2, op.encode()))
        for i, op in enumerate(ops)
    )
    return pb_int(1, 1) + pb_bytes(2, pb_bytes(2, nodes))


def gen_keras(c: Corpus) -> None:
    os.environ.setdefault("KERAS_BACKEND", "torch")
    import keras

    m = keras.Sequential(
        [
            keras.Input((4,)),
            keras.layers.Lambda(lambda x: (print("MSSCAN-CANARY keras-lambda"), x)[1]),
            keras.layers.Dense(2),
        ]
    )
    kw = {"label": "malicious", "family": "keras", "category": "code-execution"}
    for ext in (".keras", ".h5"):
        p = c.out / f"malicious/keras/lambda{ext}"
        p.parent.mkdir(parents=True, exist_ok=True)
        m.save(p)
        c.written(
            p,
            technique=f"lambda{ext}",
            loader="keras",
            note="Lambda layer with marshalled bytecode",
            **kw,
        )
    with zipfile.ZipFile(c.out / "malicious/keras/lambda.keras") as z:
        files = {n: z.read(n) for n in z.namelist()}
    cfg = json.loads(files["config.json"])
    cfg["config"]["layers"][1] = {
        "module": "builtins",
        "class_name": "print",
        "config": {"name": CANARY},
        "registered_name": "print",
    }
    files["config.json"] = json.dumps(cfg).encode()
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as z:
        for n, d in files.items():
            z.writestr(n, d)
    c.add(
        "malicious/keras/foreign-module.keras",
        zbuf.getvalue(),
        technique="foreign-module",
        loader="",
        note="config deserializes builtins.print (a module outside Keras)",
        **kw,
    )
    tfop = {
        "class_name": "Functional",
        "config": {
            "layers": [
                {"class_name": "TFOpLambda", "config": {"name": "w", "function": "io.write_file"}}
            ]
        },
    }
    c.add(
        "malicious/keras/tfoplambda-write-file.keras",
        keras_zip(tfop),
        label="malicious",
        family="keras",
        technique="tfoplambda-io",
        category="file-access",
        loader="",
        note="TFOpLambda calling tf.io.write_file",
    )
    code_b64 = base64.b64encode(marshal.dumps(compile(say("k"), "<inert>", "exec"))).decode()
    lam = {
        "class_name": "Lambda",
        "config": {"name": "l", "function": [code_b64, None, None], "function_type": "lambda"},
    }
    c.add(
        "malicious/keras/savedmodel/keras_metadata.pb",
        keras_metadata_pb(json.dumps(lam)),
        technique="keras-metadata-lambda",
        loader="",
        note="Lambda config inside a SavedModel's keras_metadata.pb",
        **kw,
    )


def gen_tf(c: Corpus) -> None:
    for op, cat in (
        ("ReadFile", "file-access"),
        ("WriteFile", "file-access"),
        ("MatchingFiles", "file-access"),
        ("PyFunc", "code-execution"),
        ("EagerPyFunc", "code-execution"),
    ):
        c.add(
            f"malicious/savedmodel/{op}/saved_model.pb",
            saved_model(["Placeholder", "Const", op, "Identity"]),
            label="malicious",
            family="savedmodel",
            technique=f"op-{op}",
            category=cat,
            loader="",
            note=f"graph with a {op} op",
        )


def gen_onnx(c: Corpus) -> None:
    import numpy as np
    from onnx import TensorProto, helper, numpy_helper

    def model(location: str, in_subgraph: bool = False) -> bytes:
        w = numpy_helper.from_array(np.zeros((2, 2), np.float32), "W")
        w.ClearField("raw_data")
        w.data_location = TensorProto.EXTERNAL
        for k, v in (("location", location), ("offset", "0"), ("length", "16")):
            e = w.external_data.add()
            e.key, e.value = k, v
        x = helper.make_tensor_value_info("x", TensorProto.FLOAT, [2, 2])
        y = helper.make_tensor_value_info("y", TensorProto.FLOAT, [2, 2])
        if in_subgraph:
            branch = helper.make_graph(
                [helper.make_node("Identity", ["W"], ["y"])], "b", [], [y], [w]
            )
            cond = numpy_helper.from_array(np.array(True), "c")
            node = helper.make_node("If", ["c"], ["y"], then_branch=branch, else_branch=branch)
            g = helper.make_graph([node], "g", [x], [y], [cond])
        else:
            g = helper.make_graph(
                [helper.make_node("MatMul", ["x", "W"], ["y"])], "g", [x], [y], [w]
            )
        return bytes(helper.make_model(g).SerializeToString())

    for tech, loc, sub in (
        ("relative-traversal", "../outside/msscan-canary.bin", False),
        ("absolute-path", "/nonexistent/msscan-canary.bin", False),
        ("subgraph-traversal", "../../msscan-canary.bin", True),
    ):
        c.add(
            f"malicious/onnx/{tech}.onnx",
            model(loc, sub),
            label="malicious",
            family="onnx",
            technique=tech,
            category="file-access",
            loader="",
            note=f"external data location {loc}",
        )


# ---------------------------------------------------------------------------------------------
# GGUF, safetensors, Hugging Face JSON
# ---------------------------------------------------------------------------------------------


def gstr(v: str) -> bytes:
    b = v.encode()
    return struct.pack("<Q", len(b)) + b


def gguf_bytes(
    kv: list[tuple[str, int, bytes]], tensors: list[tuple[str, list[int], int, int]], data: int
) -> bytes:
    body = b"".join(gstr(k) + struct.pack("<I", t) + v for k, t, v in kv)
    tens = b"".join(
        gstr(n)
        + struct.pack("<I", len(d))
        + b"".join(struct.pack("<Q", x) for x in d)
        + struct.pack("<IQ", ty, off)
        for n, d, ty, off in tensors
    )
    out = b"GGUF" + struct.pack("<IQQ", 3, len(tensors), len(kv)) + body + tens
    out += b"\0" * (-len(out) % 32)
    return out + b"\0" * data


SSTI = {
    "cycler-globals": "{{ cycler.__init__.__globals__.os.getcwd() }}",
    "subclasses-walk": (
        "{% for c in ''.__class__.__mro__[1].__subclasses__() %}"
        "{% if c.__name__ == 'catch_warnings' %}"
        "{{ c()._module.__builtins__['print']('" + CANARY + "') }}{% endif %}{% endfor %}"
    ),
    "escaped-underscores": "{{ lipsum['\\x5f\\x5fglobals\\x5f\\x5f']['os'].getcwd() }}",
    "attr-filter": (
        "{{ (cycler|attr('\\x5f\\x5finit\\x5f\\x5f')|attr('\\x5f\\x5fglobals\\x5f\\x5f'))"
        "['os'].getcwd() }}"
    ),
    "joiner-globals": "{{ joiner.__init__.__globals__.os.getcwd() }}",
}
BENIGN_TAIL = "{% for m in messages %}{{ m['content'] }}{% endfor %}"


def gen_gguf(c: Corpus) -> None:
    kw = {"label": "malicious", "family": "gguf", "category": "code-execution", "loader": "jinja"}
    for tech, tpl in SSTI.items():
        kv = [
            ("general.architecture", 8, gstr("llama")),
            ("tokenizer.chat_template", 8, gstr(BENIGN_TAIL + tpl)),
        ]
        c.add(
            f"malicious/gguf/template-{tech}.gguf",
            gguf_bytes(kv, [("w", [8], 0, 0)], 32),
            technique=f"template-{tech}",
            note="chat template injection",
            **kw,
        )
    kv = [
        ("tokenizer.chat_template", 8, gstr(BENIGN_TAIL)),
        ("tokenizer.chat_template.tool_use", 8, gstr(SSTI["cycler-globals"])),
    ]
    c.add(
        "malicious/gguf/template-named-tool-use.gguf",
        gguf_bytes(kv, [], 0),
        technique="template-named-tool-use",
        note="named template",
        **kw,
    )
    kw = {"label": "malicious", "family": "gguf", "category": "structure", "loader": ""}
    c.add(
        "malicious/gguf/tensor-out-of-bounds.gguf",
        gguf_bytes([], [("w", [1024, 1024], 0, 0)], 64),
        technique="tensor-out-of-bounds",
        note="tensor data runs past the end of the file",
        **kw,
    )
    huge = b"GGUF" + struct.pack("<IQQ", 3, 0, 2**40)
    c.add(
        "malicious/gguf/huge-kv-count.gguf",
        huge + b"\0" * 64,
        technique="huge-kv-count",
        note="kv count of 2^40 (allocation bomb)",
        **kw,
    )
    bad_len = b"GGUF" + struct.pack("<IQQ", 3, 0, 1) + struct.pack("<Q", 2**62) + b"key"
    c.add(
        "malicious/gguf/string-length-overflow.gguf",
        bad_len + b"\0" * 64,
        technique="string-length-overflow",
        note="key length 2^62",
        **kw,
    )
    c.add(
        "malicious/gguf/too-many-dims.gguf",
        gguf_bytes([], [("w", [1, 1, 1, 1, 1, 1, 1, 1], 0, 0)], 64),
        technique="too-many-dims",
        note="8 dimensions (ggml allows 4)",
        **kw,
    )


def st_bytes(header: dict[str, Any] | str, data: int, length: int | None = None) -> bytes:
    h = header if isinstance(header, str) else json.dumps(header)
    hb = h.encode()
    return struct.pack("<Q", len(hb) if length is None else length) + hb + b"\0" * data


def gen_safetensors(c: Corpus) -> None:
    kw = {
        "label": "malicious",
        "family": "safetensors",
        "category": "structure",
        "loader": "safetensors",
    }

    def t(off: list[int]) -> dict[str, Any]:
        return {"dtype": "F32", "shape": [2], "data_offsets": off}

    cases = {
        "header-length-past-eof": st_bytes({"a": t([0, 8])}, 8, length=10**6),
        "header-length-huge": st_bytes({"a": t([0, 8])}, 8, length=2**40),
        "overlapping-offsets": st_bytes({"a": t([0, 8]), "b": t([4, 12])}, 12),
        "offsets-past-eof": st_bytes({"a": t([0, 8]), "b": t([8, 16])}, 8),
        "size-mismatch": st_bytes({"a": {"dtype": "F32", "shape": [4], "data_offsets": [0, 8]}}, 8),
        "invalid-json": st_bytes('{"a": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]', 8),
        "duplicate-key": st_bytes(
            '{"a":{"dtype":"F32","shape":[2],"data_offsets":[0,8]},'
            '"a":{"dtype":"F32","shape":[2],"data_offsets":[8,16]}}',
            16,
        ),
        "gap-between-tensors": st_bytes({"a": t([0, 8]), "b": t([12, 20])}, 20),
    }
    for tech, data in cases.items():
        c.add(
            f"malicious/safetensors/{tech}.safetensors",
            data,
            technique=tech,
            note="invalid header",
            **kw,
        )


def gen_hf_json(c: Corpus) -> None:
    for tech in ("cycler-globals", "subclasses-walk"):
        cfg = {"tokenizer_class": "PreTrainedTokenizerFast", "chat_template": SSTI[tech]}
        c.add(
            f"malicious/hf-json/{tech}/tokenizer_config.json",
            json.dumps(cfg).encode(),
            label="malicious",
            family="hf-json",
            technique=f"tokenizer-template-{tech}",
            category="code-execution",
            loader="jinja-json",
            note="chat template in tokenizer_config.json",
        )


# ---------------------------------------------------------------------------------------------
# Benign files written by the real libraries
# ---------------------------------------------------------------------------------------------

TEMPLATES = {
    "chatml": (
        "{% for message in messages %}{{'<|im_start|>' + message['role'] + '\\n' + "
        "message['content'] + '<|im_end|>' + '\\n'}}{% endfor %}"
        "{% if add_generation_prompt %}{{ '<|im_start|>assistant\\n' }}{% endif %}"
    ),
    "llama2": (
        "{{ bos_token }}{% for message in messages %}"
        "{% if (message['role'] == 'user') != (loop.index0 % 2 == 0) %}"
        "{{ raise_exception('Conversation roles must alternate') }}{% endif %}"
        "{% if message['role'] == 'user' %}{{ '[INST] ' + message['content'] + ' [/INST]' }}"
        "{% else %}{{ message['content'] + eos_token }}{% endif %}{% endfor %}"
    ),
    "tools": (
        "{%- set ns = namespace(found=false) -%}{%- for m in messages -%}"
        "{%- if m.role == 'system' -%}{%- set ns.found = true -%}{%- endif -%}"
        "{{ m.content | trim }}{%- endfor -%}{%- if tools %}{{ tools | tojson(indent=2) }}{%- endif %}"
    ),
}


def gen_benign(c: Corpus) -> None:
    os.environ.setdefault("KERAS_BACKEND", "torch")
    import joblib
    import keras
    import numpy as np
    import onnx
    import torch
    from onnx import TensorProto, helper, numpy_helper
    from safetensors.torch import save as st_save
    from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    def add(rel: str, data: bytes, family: str, tech: str, loader: str = "") -> None:
        c.add(
            f"benign/{family}/{rel}",
            data,
            label="benign",
            family=family,
            technique=tech,
            category="benign",
            loader=loader,
        )

    def wrote(p: Path, family: str, tech: str, loader: str = "") -> None:
        c.written(
            p, label="benign", family=family, technique=tech, category="benign", loader=loader
        )

    torch.manual_seed(0)
    nets: dict[str, torch.nn.Module] = {
        "mlp": torch.nn.Sequential(torch.nn.Linear(8, 16), torch.nn.ReLU(), torch.nn.Linear(16, 2)),
        "cnn": torch.nn.Sequential(
            torch.nn.Conv2d(1, 4, 3), torch.nn.BatchNorm2d(4), torch.nn.Flatten()
        ),
        "rnn": torch.nn.LSTM(4, 8, batch_first=True),
        "transformer": torch.nn.TransformerEncoderLayer(16, 2, 32),
    }
    for name, net in nets.items():
        sd = net.state_dict()
        add(f"{name}.state_dict.pt", torch_save(sd), "pytorch", "state-dict", "torch")
        add(f"{name}.whole.pt", torch_save(net), "pytorch", "whole-module", "torch")
        add(
            f"{name}.legacy.pt",
            torch_save(sd, _use_new_zipfile_serialization=False),
            "pytorch",
            "legacy",
            "torch",
        )
        add(
            f"{name}.half.bin",
            torch_save({k: v.half() for k, v in sd.items()}),
            "pytorch",
            "state-dict-fp16",
            "torch",
        )
        add(
            f"{name}.safetensors",
            st_save({k: v.contiguous() for k, v in sd.items()}),
            "safetensors",
            "torch-safetensors",
            "safetensors",
        )
        ckpt = {
            "model": sd,
            "epoch": 3,
            "optimizer": torch.optim.Adam(net.parameters()).state_dict(),
            "args": argparse.Namespace(lr=0.1, seed=0),
        }
        add(f"{name}.checkpoint.ckpt", torch_save(ckpt), "pytorch", "training-checkpoint", "torch")
    buf = io.BytesIO()
    torch.jit.save(torch.jit.script(nets["mlp"]), buf)
    add("mlp.torchscript.pt", buf.getvalue(), "pytorch", "torchscript")

    rng = np.random.default_rng(0)
    feats, y = rng.normal(size=(200, 6)), rng.integers(0, 2, 200)
    models = {
        "logreg": LogisticRegression(max_iter=200).fit(feats, y),
        "forest": RandomForestClassifier(n_estimators=5, random_state=0).fit(feats, y),
        "gbm": GradientBoostingClassifier(n_estimators=5, random_state=0).fit(feats, y),
        "pipeline": make_pipeline(StandardScaler(), LogisticRegression()).fit(feats, y),
    }
    for name, m in models.items():
        for comp in ("raw", "zlib", "gzip", "bz2", "xz", "lzma"):
            p = c.out / f"benign/joblib/{name}.{comp}.joblib"
            p.parent.mkdir(parents=True, exist_ok=True)
            joblib.dump(m, p, compress=0 if comp == "raw" else (comp, 3))
            wrote(p, "joblib", f"sklearn-{comp}", "joblib")
        add(f"{name}.pkl", pickle.dumps(m, protocol=4), "pickle", "sklearn-pickle", "pickle")
    for proto in range(6):
        obj = {
            "vocab": {f"w{i}": i for i in range(50)},
            "shape": (3, 4),
            "lr": 0.1,
            "tags": {"a", "b"},
            "arr": np.arange(6).reshape(2, 3),
            "raw": b"\x00\x01",
            "when": None,
        }
        add(
            f"plain.p{proto}.pkl",
            pickle.dumps(obj, protocol=proto),
            "pickle",
            "plain-data",
            "pickle",
        )
    arrays = {
        "f32": rng.normal(size=(16, 8)).astype(np.float32),
        "i64": np.arange(100),
        "bool": np.ones(7, bool),
        "u": np.array(["ab", "c"]),
        "dt": np.array(["2024-01-01"], dtype="datetime64[D]"),
    }
    for name, a in arrays.items():
        b = io.BytesIO()
        np.save(b, a)
        add(f"{name}.npy", b.getvalue(), "numpy", "numeric", "numpy")
    b = io.BytesIO()
    np.savez_compressed(b, a=np.ones(10), b=np.zeros((3, 3)))
    add("arrays.npz", b.getvalue(), "numpy", "npz", "numpy-npz")

    km = keras.Sequential(
        [
            keras.Input((4,)),
            keras.layers.Dense(3, activation="relu"),
            keras.layers.Dropout(0.1),
            keras.layers.Dense(2, activation="softmax"),
        ]
    )
    for ext in (".keras", ".h5"):
        p = c.out / f"benign/keras/dense{ext}"
        p.parent.mkdir(parents=True, exist_ok=True)
        km.save(p)
        wrote(p, "keras", f"dense{ext}", "keras")
    p = c.out / "benign/keras/dense.weights.h5"
    km.save_weights(p)
    wrote(p, "keras", "weights-only")

    w = numpy_helper.from_array(np.ones((4, 4), np.float32), "W")
    g = helper.make_graph(
        [helper.make_node("MatMul", ["x", "W"], ["y"]), helper.make_node("Relu", ["y"], ["z"])],
        "g",
        [helper.make_tensor_value_info("x", TensorProto.FLOAT, [1, 4])],
        [helper.make_tensor_value_info("z", TensorProto.FLOAT, [1, 4])],
        [w],
    )
    add("matmul.onnx", bytes(helper.make_model(g).SerializeToString()), "onnx", "inline")
    p = c.out / "benign/onnx/external/model.onnx"
    p.parent.mkdir(parents=True, exist_ok=True)
    onnx.save_model(
        helper.make_model(g),
        p,
        save_as_external_data=True,
        location="model.onnx_data",
        size_threshold=0,
    )
    wrote(p, "onnx", "external-data")
    add(
        "saved_model/saved_model.pb",
        saved_model(["Placeholder", "MatMul", "SaveV2", "RestoreV2"]),
        "savedmodel",
        "plain-graph",
    )
    for name, tpl in TEMPLATES.items():
        kv = [
            ("general.architecture", 8, gstr("llama")),
            ("general.alignment", 4, struct.pack("<I", 32)),
            ("tokenizer.chat_template", 8, gstr(tpl)),
        ]
        add(
            f"{name}.gguf",
            gguf_bytes(kv, [("tok_embd", [16, 8], 0, 0), ("out", [8], 1, 512)], 544),
            "gguf",
            "chat-template",
            "jinja",
        )
        add(
            f"{name}/tokenizer_config.json",
            json.dumps({"chat_template": tpl}).encode(),
            "hf-json",
            "chat-template",
            "jinja-json",
        )
    cfg = {"architectures": ["LlamaForCausalLM"], "hidden_size": 64}
    add("config.json", json.dumps(cfg).encode(), "hf-json", "config")


# ---------------------------------------------------------------------------------------------
# Second wave: call shapes, staged payloads, containers, configs and templates
# ---------------------------------------------------------------------------------------------


def _tar(members: dict[str, bytes]) -> bytes:
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _seven_zip(members: dict[str, bytes]) -> bytes:
    import py7zr

    buf = io.BytesIO()
    with py7zr.SevenZipFile(buf, "w") as z:
        for name, data in members.items():
            z.writestr(data, name)
    return buf.getvalue()


def _lambda_config(fn: Callable[..., Any], name: str) -> dict[str, Any]:
    """A Keras 3 model config holding one Lambda layer with ``fn`` as marshalled bytecode."""
    import base64

    code = base64.b64encode(marshal.dumps(fn.__code__)).decode()
    return {
        "module": "keras",
        "class_name": "Sequential",
        "config": {
            "name": "s",
            "layers": [
                {
                    "module": "keras.layers",
                    "class_name": "Lambda",
                    "config": {
                        "name": name,
                        "function": {
                            "class_name": "__lambda__",
                            "config": {"code": code, "defaults": None, "closure": None},
                        },
                    },
                    "registered_name": None,
                }
            ],
        },
        "registered_name": None,
    }


def gen_second_wave(c: Corpus) -> None:
    import base64
    import dis
    import pprint

    import torch.jit.unsupported_tensor_ops as tensor_ops

    def mal(rel: str, data: bytes, family: str, tech: str, loader: str, note: str) -> None:
        c.add(
            f"malicious/{family}/{rel}",
            data,
            label="malicious",
            family=family,
            technique=tech,
            category="code-execution",
            loader=loader,
            note=note,
        )

    def ben(rel: str, data: bytes, family: str, tech: str) -> None:
        c.add(
            f"benign/{family}/{rel}",
            data,
            label="benign",
            family=family,
            technique=tech,
            category="benign",
            loader="",
        )

    # Calls that no denylist names, refused for their shape. Each runs its inert payload.
    shapes: dict[str, tuple[Any, str]] = {
        "stdlib-dis": (
            Reduce(dis.dis, (say("stdlib-dis"),)),
            "a standard-library function outside the reconstruction allowlist",
        ),
        "stdlib-pprint": (
            Reduce(pprint.pprint, (f"{CANARY} stdlib-pprint",)),
            "a standard-library function outside the reconstruction allowlist",
        ),
        "builtin-print": (Reduce(print, (f"{CANARY} builtin-print",)), "print called on load"),
        "library-exec-wrapper": (
            Reduce(tensor_ops.execWrapper, (say("library-exec-wrapper"), {}, {})),
            "a library function that is neither a class nor a rebuild helper",
        ),
        "method-path": (
            # The printer is built at load time: a live one holds sys.stdout and cannot pickle.
            Reduce(
                pprint.PrettyPrinter.pprint,
                (Reduce(pprint.PrettyPrinter), f"{CANARY} method-path"),
            ),
            "a method reached through an attribute path",
        ),
    }
    for tech, (obj, note) in shapes.items():
        mal(f"{tech}.pkl", pickle.dumps(obj, protocol=4), "call-shape", tech, "pickle", note)

    # Second-stage payloads kept as data. Loading the outer file does not run them.
    stage = pickle.dumps(Reduce(print, (f"{CANARY} staged",)), protocol=4)
    staged = {
        "raw-bytes": {"weights": stage},
        "base64-text": {"weights": base64.b64encode(stage).decode()},
        "hex-text": {"weights": stage.hex()},
        "two-stages": {"blob": pickle.dumps({"stage2": stage}, protocol=4)},
    }
    for tech, obj in staged.items():
        mal(
            f"{tech}.pkl",
            pickle.dumps(obj, protocol=4),
            "staged",
            f"staged-pickle-{tech}",
            "",
            "a pickle stored as a constant; runs only if a second step unpickles it",
        )
    code = "import os; os.system('echo " + CANARY + "')"
    mal(
        "code-plain.pkl",
        pickle.dumps({"postprocess": code}, protocol=4),
        "staged",
        "staged-code-plain",
        "",
        "code text stored as a constant",
    )
    mal(
        "code-base64.pkl",
        pickle.dumps({"postprocess": base64.b64encode(code.encode()).decode()}, protocol=4),
        "staged",
        "staged-code-base64",
        "",
        "base64 code text stored as a constant",
    )
    tensor = {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]}
    mal(
        "metadata-code.safetensors",
        st_bytes({"__metadata__": {"format": "pt", "init": code}, "w": tensor}, 8),
        "staged",
        "staged-code-safetensors-metadata",
        "",
        "code text in safetensors metadata",
    )

    # Containers that pickle scanners do not open.
    payload = p_reduce_getcwd(4)
    mal(
        "weights.tar",
        _tar({"model/data.pkl": payload}),
        "container",
        "tar-member",
        "",
        "pickle in a tar",
    )
    mal(
        "weights.7z",
        _seven_zip({"model/data.pkl": payload}),
        "container",
        "7z-member",
        "",
        "pickle in a 7z",
    )
    mal(
        "model.nemo",
        _tar(
            {"model_config.yaml": b"preprocessor:\n  _target_: os.system\n  _args_: ['echo x']\n"}
        ),
        "container",
        "tar-config-target",
        "",
        "a .nemo style archive whose config instantiates os.system",
    )

    # Configs and templates.
    mal(
        "hydra/config.yaml",
        b"model:\n  _target_: torch.nn.Linear\n  in_features: 2\n  out_features: 2\n"
        b'callbacks:\n  - _target_: builtins.eval\n    _args_: ["1+1"]\n',
        "config",
        "yaml-instantiate-target",
        "",
        "Hydra instantiate target that evaluates code",
    )
    mal(
        "pyyaml/config.yaml",
        b"model: !!python/object/apply:os.getcwd []\n",
        "config",
        "yaml-python-tag",
        "",
        "PyYAML object tag",
    )
    mal(
        "json/config.json",
        json.dumps({"model": {"_target_": "subprocess.check_output", "_args_": [["id"]]}}).encode(),
        "config",
        "json-instantiate-target",
        "",
        "instantiate target in a JSON config",
    )
    mal(
        "chat_template.jinja",
        (BENIGN_TAIL + SSTI["cycler-globals"]).encode(),
        "config",
        "template-file",
        "",
        "standalone chat template file",
    )

    # A Lambda whose bytecode reaches the system, next to one that is arithmetic.
    mal(
        "lambda-import.keras",
        keras_zip(_lambda_config(lambda x: __import__("os").getcwd() and x, "risky")),
        "keras",
        "lambda-bytecode-import",
        "",
        "Lambda bytecode that imports os",
    )
    ben(
        "lambda-math.keras",
        keras_zip(_lambda_config(lambda x: x * 2.0 + 1.0, "scale")),
        "keras",
        "lambda-bytecode-arithmetic",
    )

    # Benign look-alikes for every check above.
    import datetime
    import enum
    import pathlib
    import re

    class Color(enum.IntEnum):
        RED = 1

    benign_pickles: dict[str, Any] = {
        "regex-path-date": {
            "pattern": re.compile(r"\d+"),
            "path": pathlib.PurePosixPath("weights/model.bin"),
            "when": datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC),
        },
        "base64-image": {"thumbnail": base64.b64encode(bytes(range(256)) * 4).decode()},
        "hex-digest": {
            "sha256": "ab" * 32,
            "note": "weights checked with the operating system tools",
        },
        "nested-plain-pickle": {"cache": pickle.dumps({"k": [1, 2, 3]}, protocol=4)},
        "prose-about-code": {
            "readme": "Call model.eval() before inference. Do not exec untrusted code. "
            "The subprocess module is not used by this model."
        },
    }
    for tech, obj in benign_pickles.items():
        ben(f"{tech}.pkl", pickle.dumps(obj, protocol=4), "look-alike", tech)
    ben(
        "weights.tar",
        _tar({"model/data.pkl": pickle.dumps(OrderedDict(a=1), protocol=4)}),
        "container",
        "tar-member",
    )
    ben(
        "weights.7z",
        _seven_zip({"model/data.pkl": pickle.dumps(OrderedDict(a=1), protocol=4)}),
        "container",
        "7z-member",
    )
    ben(
        "hydra/config.yaml",
        b"model:\n  _target_: transformers.AutoModel.from_pretrained\n"
        b"  pretrained_model_name_or_path: bert-base-uncased\n"
        b"optimizer:\n  _target_: torch.optim.AdamW\n  lr: 0.001\n"
        b"path:\n  _target_: os.path.join\n  _args_: [a, b]\n",
        "config",
        "yaml-instantiate-target",
    )
    ben("chat_template.jinja", TEMPLATES["chatml"].encode(), "config", "template-file")
    ben(
        "padded.safetensors",
        st_bytes({"__metadata__": {"format": "pt", "tags": json.dumps({"a": 3})}, "w": tensor}, 8)
        + b"\0" * 24,
        "safetensors",
        "trailing-padding",
    )
    ben(
        "video.gguf",
        gguf_bytes([], [("patch_embedding.weight", [1, 1, 2, 2, 2], 0, 0)], 32),
        "gguf",
        "five-dimensional-tensor",
    )
    ben(
        "._model.safetensors",
        bytes([0, 5, 0x16, 7, 0, 2, 0, 0]) + b"Mac OS X        " + b"\0" * 64,
        "safetensors",
        "macos-metadata-file",
    )

    # Shapes met in the held-out Hub sample. The benign ones were false alarms there.
    import joblib
    import torch
    from sklearn.preprocessing import FunctionTransformer
    from sklearn.utils.validation import check_array

    buf = io.BytesIO()
    joblib.dump(FunctionTransformer(func=functools.partial(check_array, accept_sparse=True)), buf)
    ben("function-transformer-partial.joblib", buf.getvalue(), "joblib", "partial-library-function")
    ben(
        "methodcaller-floordiv.pkl",
        pickle.dumps(operator.methodcaller("__floordiv__", 3600), protocol=4),
        "pickle",
        "methodcaller-operator-method",
    )
    ben(
        "hparams-partial-optimizer.ckpt",
        torch_save(
            {"hyper_parameters": {"optimizer": functools.partial(torch.optim.Adam, lr=1e-3)}}
        ),
        "pytorch",
        "partial-class",
    )
    ben(
        "code-vocabulary.pkl",
        pickle.dumps({"import": 3, 'os.system("shutdown': 1, "-s": 1, '60")': 1}, protocol=4),
        "pickle",
        "vocabulary-with-code-fragment",
    )
    ben(
        "half-precision-weights.bin",
        bytes([0x84, 0xAD, 0x39, 0xAF, 0x77, 0xA7, 0x5F, 0xA4]) + bytes(range(256)) * 4,
        "pickle",
        "raw-weights-under-a-pickle-name",
    )
    ben(
        "plain-tags.yaml",
        b"model:\n  freqs_per_bands: !!python/tuple\n    - 2\n    - 4\n  name: !!python/str demo\n",
        "config",
        "yaml-plain-value-tags",
    )
    lfs = (
        b"version https://git-lfs.github.com/spec/v1\noid sha256:" + b"0" * 64 + b"\nsize 1048576\n"
    )
    ben("lfs-pointer.safetensors", lfs, "safetensors", "lfs-pointer")
    ben(
        "encoded-pointer.safetensors",
        base64.b64encode(lfs),
        "safetensors",
        "text-under-a-safetensors-name",
    )

    def lookup(special_tokens: Any) -> dict[str, Any]:
        return {
            "module": "keras",
            "class_name": "Sequential",
            "config": {
                "name": "m",
                "layers": [
                    {
                        "module": "keras_hub.src.models.whisper.whisper_tokenizer",
                        "class_name": "WhisperTokenizer",
                        "config": {
                            "name": "tok",
                            "config_file": "tokenizer.json",
                            "special_tokens": special_tokens,
                        },
                        "registered_name": "keras_hub>WhisperTokenizer",
                    }
                ],
            },
            "registered_name": None,
        }

    for rel, path in {
        "tokenizer-file-absolute.keras": "/nonexistent/msscan-corpus/special_tokens.json",
        "tokenizer-file-home.keras": "~/.msscan-corpus-nonexistent/tokens.json",
        "tokenizer-file-climbing.keras": "../../../nonexistent-msscan-corpus/tokens.json",
    }.items():
        c.add(
            f"malicious/keras/{rel}",
            keras_zip(lookup(path)),
            label="malicious",
            family="keras",
            technique="config-file-path",
            category="file-access",
            loader="",
            note="a layer config value is a path on the loading machine (the file named does not exist)",
        )
    ben(
        "tokenizer-inline.keras",
        keras_zip(lookup({"<|endoftext|>": 101})),
        "keras",
        "tokenizer-inline-tokens",
    )
    for rel, shard in {
        "climbing.safetensors.index.json": "../../../../nonexistent-msscan-corpus/environ",
        "absolute.safetensors.index.json": "/nonexistent/msscan-corpus/passwd",
    }.items():
        c.add(
            f"malicious/hf-json/{rel}",
            json.dumps({"metadata": {"total_size": 4}, "weight_map": {"w": shard}}).encode(),
            label="malicious",
            family="hf-json",
            technique="shard-index-traversal",
            category="file-access",
            loader="",
            note="a sharded checkpoint index names a shard outside the model directory",
        )
    ben(
        "model.safetensors.index.json",
        json.dumps(
            {
                "metadata": {"total_size": 8},
                "weight_map": {
                    "a": "model-00001-of-00002.safetensors",
                    "b": "model-00002-of-00002.safetensors",
                },
            }
        ).encode(),
        "hf-json",
        "shard-index",
    )
    c.add(
        "malicious/link/etc-hostname.safetensors",
        b"../../../etc/hostname",
        label="malicious",
        family="link",
        technique="link-stored-as-file",
        category="file-access",
        loader="",
        note="a symbolic link committed to a repository, as a hub serves it; a checkout recreates the link",
    )


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    c = Corpus(args.out)
    for gen in (
        gen_pickles,
        gen_torch,
        gen_numpy_joblib,
        gen_keras,
        gen_tf,
        gen_onnx,
        gen_gguf,
        gen_safetensors,
        gen_hf_json,
        gen_second_wave,
        gen_benign,
    ):
        gen(c)
    c.write_manifest()
    mal = sum(i.label == "malicious" for i in c.items)
    techs = len({(i.family, i.technique) for i in c.items if i.label == "malicious"})
    print(f"wrote {len(c.items)} files ({mal} malicious, {techs} techniques) to {args.out}")


if __name__ == "__main__":
    main()
