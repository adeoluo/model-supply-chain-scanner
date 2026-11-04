from __future__ import annotations

import os
import pickle

import pytest


class Reduce:
    """Pickles as ``func(*args)`` without ever calling it (the tests never unpickle)."""

    def __init__(self, func: object, args: tuple[object, ...] = ()) -> None:
        self.func = func
        self.args = args

    def __reduce__(self) -> tuple[object, tuple[object, ...]]:
        return (self.func, self.args)


GETCWD = pickle.dumps(Reduce(os.getcwd), protocol=2)
BENIGN = pickle.dumps({"weights": [1.0, 2.0], "name": "x"}, protocol=4)


@pytest.fixture
def model_dir(tmp_path):  # type: ignore[no-untyped-def]
    (tmp_path / "bad.pkl").write_bytes(GETCWD)
    (tmp_path / "good.pkl").write_bytes(BENIGN)
    return tmp_path
