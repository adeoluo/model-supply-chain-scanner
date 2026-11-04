"""Parity between the Rust virtual machine and the Python reference on generated pickles."""

from __future__ import annotations

import collections
import functools
import operator
import os
import pickle
import pickletools
from typing import Any

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

import msscan
from msscan import reference
from tests.conftest import Reduce

FUNCS = [os.getcwd, collections.OrderedDict, print, operator.add, functools.partial, len, sorted]

leaves = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**70), max_value=2**70),
    st.floats(allow_nan=False),
    st.text(max_size=8),
    st.binary(max_size=8),
    st.sampled_from(FUNCS),
)


def _build(children: st.SearchStrategy[Any]) -> st.SearchStrategy[Any]:
    return st.one_of(
        st.lists(children, max_size=4),
        st.tuples(children, children),
        st.dictionaries(st.text(max_size=4), children, max_size=3),
        st.frozensets(st.integers(), max_size=3),
        st.builds(Reduce, st.sampled_from(FUNCS), st.tuples(children)),
    )


objects = st.recursive(leaves, _build, max_leaves=12)


def rust_imports(data: bytes) -> dict[tuple[str, str], bool]:
    r = msscan.scan_bytes(data, "p.pkl")
    return {(i.module, i.name): i.called for i in r.imports}


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(obj=objects, protocol=st.integers(min_value=0, max_value=5))
def test_imports_and_calls_match_reference(obj: Any, protocol: int) -> None:
    data = pickle.dumps(obj, protocol=protocol)
    ref = reference.analyze(data)
    assert rust_imports(data) == ref.imports


@settings(max_examples=100, deadline=None)
@given(obj=objects)
def test_optimized_pickles_match(obj: Any) -> None:
    data = pickletools.optimize(pickle.dumps(obj, protocol=4))
    assert rust_imports(data) == reference.analyze(data).imports


def test_reference_on_hand_written_tricks() -> None:
    dyn = (
        b"\x80\x04\x8c\x07_codecs\x8c\x06encode\x93\x8c\x02bf\x8c\x05rot13\x86R"
        b"\x8c\x06getcwd\x93)R."
    )
    ref = reference.analyze(dyn)
    assert ref.dynamic
    assert ref.imports == rust_imports(dyn)
    inject = (
        b"\x80\x02cargparse\nNamespace\n)R}\x8c\x0c__setstate__cbuiltins\nexec\nsb"
        b"\x8c\x08print(1)b."
    )
    ref = reference.analyze(inject)
    assert ref.dunder_build and ref.imports[("builtins", "exec")]
    assert ref.imports == rust_imports(inject)
    ext = b"\x80\x02\x82\x07)R."
    assert reference.analyze(ext).imports == {}
    persid = b"\x80\x02(\x8c\x01at\x94Q\x8c\x01xPid\nh\x00."
    assert reference.analyze(persid).imports == rust_imports(persid)
    inst = b"(S'print(1)'\nibuiltins\nexec\n."
    assert reference.analyze(inst).imports == rust_imports(inst) == {("builtins", "exec"): True}
    obj = b"(cos\ngetcwd\no0(lp0\nI1\naI2\na(I3\nI4\nep1\n(dp2\nS'k'\nS'v'\nsg2\n."
    assert reference.analyze(obj).imports == rust_imports(obj)
