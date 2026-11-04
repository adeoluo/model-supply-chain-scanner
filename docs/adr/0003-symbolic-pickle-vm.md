# ADR-0003: A symbolic pickle virtual machine with tiered globals

- **Status:** Accepted
- **Date:** 2026-11-04

## Context
Most pickle scanners list the `GLOBAL` and `STACK_GLOBAL` imports in a stream and compare them
with a denylist. That misses imports whose module or name is computed at load time (a
`STACK_GLOBAL` fed by `_codecs.encode("bf", "rot13")`), attributes written by `BUILD`
(`__setstate__` set to `exec`, then triggered by a second `BUILD`), payloads hidden behind raw
array bytes in joblib files, callables passed as arguments rather than called directly
(`functools.partial(os.getcwd)()`), and protocol 4 dotted names that reach a module through an
innocent one (`argparse` then `_os.getcwd`).

## Decision
Execute every opcode of protocols 0 to 5 on a symbolic stack, memo and mark stack, with nodes for
constants, containers, globals, calls (`REDUCE`, `INST`, `OBJ`, `NEWOBJ`, `NEWOBJ_EX`),
persistent ids and extension codes. From that state:

- a global is *called* when it is the callee of a call, or reachable from the arguments of any
  call (the callee may invoke it), or from state written with dunder keys;
- `STACK_GLOBAL` with non-constant operands is a dynamic import (high; critical if called);
- `BUILD` with dunder keys, or with attributes on an imported global, is attribute injection;
- calls of nested loaders (`pickle.loads`, `torch.load`, `torch.storage._load_from_bytes` and
  others) on embedded bytes recurse into those bytes;
- a joblib `NumpyArrayWrapper` followed by `BUILD` skips exactly the array bytes (shape times
  item size, with alignment padding) or scans the nested pickle of an object array;
- a legacy PyTorch stream (magic number pickle) is read as exactly the five pickles that
  `torch.load` reads.

Globals fall into four tiers: an exact *safe* allowlist (115 module and name pairs from ordinary
checkpoints), a *dangerous* denylist (90 whole modules such as `os`, `subprocess`, `runpy`, plus
69 exact names such as `builtins.eval` and `torch.load`), *library* namespaces (torch, numpy,
sklearn and others, reported low), and everything else (*unknown*, medium when called).

## Alternatives considered
- **Allowlist only (fail on anything unknown).** Safest, but every whole-model checkpoint and
  sklearn pickle fails; fickling's default comes close to this and flags all 31 benign
  PyTorch and plain pickles in the synthetic corpus.
- **Denylist only.** Lowest false positives, misses everything outside the list.

## Consequences
- The VM keeps bounded state (node, container and opcode limits) and reports when it hits them.
- Functions outside the denylist that run code (`logging.config.dictConfig` with a `()` factory,
  `typing._eval_type` on a `ForwardRef`) are reported only as unknown or library calls, below the
  default failure threshold; the hard tier of the benchmark measures this gap.
