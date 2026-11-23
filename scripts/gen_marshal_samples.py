"""Print marshalled code objects for the bytecode reader's tests.

Run under each supported CPython and paste the rows into
crates/msscan-core/src/pycode_samples.rs:
    for v in 3.9 3.10 3.11 3.12 3.13 3.14 3.15 3.16; do
        uv run --no-project --python $v python scripts/gen_marshal_samples.py
    done
Nothing is executed apart from compiling the sample sources; the functions are never called.
"""

from __future__ import annotations

import base64
import json
import marshal
import sys

src = {
    "math": "lambda x: x * 2 + 1",
    "tensor": "lambda x: tf.reduce_mean(K.square(x), axis=-1)",
    "system": "lambda x: __import__('os').system('echo inert') or x",
    "getattr": "lambda x: getattr(__builtins__, 'ev' + 'al')('1+1')",
    "nested": "lambda x: (lambda y: open('/tmp/inert', 'w'))(x)",
    "names": "lambda x: [subprocess.Popen, x.shape, 'a string const', b'bytes', 3.5, (1, 2), None]",
}
out = {}
for k, s in src.items():
    code = eval(compile(s, "<lambda>", "eval")).__code__
    out[k] = base64.b64encode(marshal.dumps(code)).decode()


def named(x):
    import os

    return os.getcwd()


out["function"] = base64.b64encode(marshal.dumps(named.__code__)).decode()
print(json.dumps({"version": f"{sys.version_info[0]}.{sys.version_info[1]}", "samples": out}))
