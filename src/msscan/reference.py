"""A readable reference for the pickle import and call analysis, used only by parity tests.

It walks :func:`pickletools.genops` with a symbolic stack and memo and reports which globals a
pickle imports and which it calls or passes into calls, following the same rules as the Rust
virtual machine (``crates/msscan-core/src/pickle``). It covers plain pickles (protocols 0 to 5)
and stops at the first STOP; joblib arrays, nested loaders and legacy PyTorch streams are
handled only by the Rust core.
"""

from __future__ import annotations

import io
import pickletools
from dataclasses import dataclass, field
from typing import Any

_PY2 = {
    "__builtin__": "builtins",
    "exceptions": "builtins",
    "copy_reg": "copyreg",
    "cPickle": "pickle",
    "commands": "subprocess",
    "urllib2": "urllib.request",
    "httplib": "http.client",
    "Queue": "queue",
}


@dataclass
class Global:
    key: tuple[str, str]


@dataclass
class Call:
    func: Any
    args: Any
    state: Any = None


@dataclass
class Box:
    """A mutable container (list, dict as list of pairs, set, tuple)."""

    kind: str
    items: list[Any] = field(default_factory=list)


class _Mark:
    pass


MARK = _Mark()
DYNAMIC = object()
UNKNOWN = object()


@dataclass
class Result:
    imports: dict[tuple[str, str], bool]
    dynamic: bool = False
    dunder_build: bool = False


def _reachable(v: Any, out: list[Global], depth: int = 0, seen: set[int] | None = None) -> None:
    seen = seen if seen is not None else set()
    if depth > 6 or id(v) in seen:
        return
    seen.add(id(v))
    if isinstance(v, Global):
        out.append(v)
    elif isinstance(v, Box):
        for x in v.items:
            if isinstance(x, tuple) and v.kind == "dict":
                _reachable(x[0], out, depth + 1, seen)
                _reachable(x[1], out, depth + 1, seen)
            else:
                _reachable(x, out, depth + 1, seen)
    elif isinstance(v, Call):
        _reachable(v.func, out, depth + 1, seen)
        _reachable(v.args, out, depth + 1, seen)
        if v.state is not None:
            _reachable(v.state, out, depth + 1, seen)


def analyze(data: bytes) -> Result:
    """Imports (module, name) -> called, for the first pickle in ``data``."""
    stack: list[Any] = []
    marks: list[int] = []
    memo: dict[int, Any] = {}
    res = Result(imports={})

    def imp(module: str, name: str) -> Global:
        key = (_PY2.get(module.strip(), module.strip()), name.strip())
        res.imports.setdefault(key, False)
        return Global(key)

    def called(v: Any) -> None:
        gs: list[Global] = []
        _reachable(v, gs)
        for g in gs:
            res.imports[g.key] = True

    def pop_mark() -> list[Any]:
        m = marks.pop()
        items = stack[m:]
        del stack[m:]
        return items

    def call(func: Any, args: Any) -> Call:
        called(args)
        if isinstance(func, (Global, Call)):
            called(func)
        return Call(func, args)

    def keys(d: Any) -> list[str]:
        if isinstance(d, Box) and d.kind == "dict":
            return [k for k, _ in d.items if isinstance(k, str)]
        return []

    for op, raw_arg, _pos in pickletools.genops(io.BytesIO(data)):
        arg: Any = raw_arg
        n = op.name
        if n in ("PROTO", "FRAME", "READONLY_BUFFER"):
            continue
        if n == "STOP":
            break
        if n == "MARK":
            marks.append(len(stack))
        elif n == "POP":
            if marks and marks[-1] == len(stack):
                marks.pop()
            else:
                stack.pop()
        elif n == "POP_MARK":
            pop_mark()
        elif n == "DUP":
            stack.append(stack[-1])
        elif n in ("GLOBAL", "INST"):
            module, name = str(arg).split(" ", 1)
            g = imp(module, name)
            if n == "INST":
                stack.append(call(g, Box("tuple", pop_mark())))
            else:
                stack.append(g)
        elif n == "STACK_GLOBAL":
            name, module = stack.pop(), stack.pop()
            if isinstance(module, str) and isinstance(name, str):
                stack.append(imp(module, name))
            else:
                res.dynamic = True
                called(module)
                called(name)
                stack.append(DYNAMIC)
        elif n == "REDUCE" or n == "NEWOBJ":
            args, func = stack.pop(), stack.pop()
            stack.append(call(func, args))
        elif n == "NEWOBJ_EX":
            kwargs, args, func = stack.pop(), stack.pop(), stack.pop()
            called(kwargs)
            stack.append(call(func, args))
        elif n == "OBJ":
            items = pop_mark()
            stack.append(call(items[0], Box("tuple", items[1:])))
        elif n == "BUILD":
            state = stack.pop()
            target = stack[-1]
            ks = keys(state)
            slot = None
            if isinstance(state, Box) and state.kind == "tuple" and len(state.items) == 2:
                ks += keys(state.items[0]) + keys(state.items[1])
                slot = state.items[1]
            dunders = [k for k in ks if k.startswith("__") and k.endswith("__") and len(k) > 4]
            if dunders:
                res.dunder_build = True
                called(state)
            if isinstance(target, Global) and not dunders:
                writes = slot if slot is not None else state
                if isinstance(writes, Box) and writes.kind == "dict" and writes.items:
                    called(state)
            if isinstance(target, Call):
                target.state = state
        elif n in ("EMPTY_TUPLE", "EMPTY_LIST", "EMPTY_DICT", "EMPTY_SET"):
            stack.append(Box({"EMPTY_TUPLE": "tuple", "EMPTY_LIST": "list"}.get(n, n[6:].lower())))
        elif n in ("TUPLE", "LIST", "FROZENSET"):
            stack.append(Box("tuple" if n != "LIST" else "list", pop_mark()))
        elif n == "DICT":
            items = pop_mark()
            stack.append(Box("dict", list(zip(items[::2], items[1::2], strict=True))))
        elif n in ("TUPLE1", "TUPLE2", "TUPLE3"):
            k = int(n[-1])
            items = stack[-k:]
            del stack[-k:]
            stack.append(Box("tuple", items))
        elif n == "APPEND":
            v = stack.pop()
            if isinstance(stack[-1], Box):
                stack[-1].items.append(v)
        elif n in ("APPENDS", "ADDITEMS"):
            items = pop_mark()
            if isinstance(stack[-1], Box):
                stack[-1].items.extend(items)
        elif n == "SETITEM":
            v, k = stack.pop(), stack.pop()
            if isinstance(stack[-1], Box) and stack[-1].kind == "dict":
                stack[-1].items.append((k, v))
        elif n == "SETITEMS":
            items = pop_mark()
            if isinstance(stack[-1], Box) and stack[-1].kind == "dict":
                stack[-1].items.extend(zip(items[::2], items[1::2], strict=True))
        elif n in ("PUT", "BINPUT", "LONG_BINPUT"):
            memo[int(arg)] = stack[-1]
        elif n == "MEMOIZE":
            memo[len(memo)] = stack[-1]
        elif n in ("GET", "BINGET", "LONG_BINGET"):
            stack.append(memo[int(arg)])
        elif n == "BINPERSID":
            called(stack.pop())
            stack.append(UNKNOWN)
        elif n in ("EXT1", "EXT2", "EXT4", "PERSID", "NEXT_BUFFER"):
            stack.append(UNKNOWN)
        elif op.arg is None and op.stack_after and n not in ("NONE", "NEWTRUE", "NEWFALSE"):
            stack.append(UNKNOWN)  # pragma: no cover
        elif isinstance(arg, str):
            stack.append(arg)
        else:
            stack.append(arg if not isinstance(arg, bytes) else UNKNOWN)
    return res
