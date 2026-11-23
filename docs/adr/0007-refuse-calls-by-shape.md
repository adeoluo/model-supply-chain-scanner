# ADR-0007: Refuse pickle calls by their shape, not only by name

- **Status:** Accepted
- **Date:** 2026-11-23

## Context
Version 0.1.1 classified every global as allowlisted, denylisted, inside a trusted library
namespace, or unknown, and rated an unknown global that is called as medium and a library one
as low. Scored on the test files of other scanner projects (144 malicious files, many of them
the proof-of-concept files of published scanner bypass advisories), it rated 27 below high.
Most were a function that no list named: `uuid._get_command_stdout`,
`_aix_support._read_cmd_output`, `lib2to3.pgen2.grammar.Grammar.loads`,
`torch.jit.unsupported_tensor_ops.execWrapper`. Each of the three outside reviews of this
scanner had found the same kind of gap, and each fix had added names.

The 7,563 Hub files without an attack show what ordinary checkpoints call. They call classes.
Outside classes they call 12 distinct library functions, all of them rebuild helpers
(`_rebuild_wrapper_subclass`, `_unpickle_block`, `__pyx_unpickle_...`). They never call a method
through an attribute path, and they call nothing from the standard library outside a short list.

## Decision
A called global that is neither allowlisted nor denylisted is refused at high severity (rule
MS115) when it has one of three shapes:

1. **A standard-library callable outside a short allowlist.** The standard library is treated
   as an allowlist: a generated table of its module names (CPython 3.10 to 3.15 plus Python 2
   and removed modules), the existing exact allowlist, a few rebuild helpers (`re._compile`,
   `codecs.encode`) and the classes of plain-data modules (`datetime`, `pathlib`, `enum`).
2. **A method reached through an attribute path** (`Class.method` as the name), unless every
   component is written like a class (a nested class).
3. **A library function that is neither a class nor a rebuild helper**, inside the trusted
   library namespaces. Rebuild helpers are recognized by name markers (`rebuild`, `reconstruct`,
   `unpickle`, `_new_`, `newobj`), and a short list names lower-case classes
   (`scipy.sparse.csr_matrix`).

Two lookups whose result is known are resolved before these rules apply:
`getattr(Class, "name")`, which is how a method reference pickles, and dill's
`_load_type("set")`. The global they return is classified like any other.

## Alternatives considered
- **Keep adding names.** That is what picklescan does and what this scanner did three times. The
  advisory list keeps growing because the standard library and PyTorch hold more gadgets than
  anyone has listed.
- **Flag every global outside the allowlist** (picklescan `--strict`, fickling). It catches
  everything and flags 25% to 80% of real pickle files, because whole-model checkpoints
  legitimately construct thousands of library classes.
- **Derive a gadget catalog by static analysis of library sources.** It would also cover class
  constructors with side effects, which the shape rule does not. It needs a call-graph analysis
  per library version and is left as future work.

## Consequences
- All 94 malicious files of picklescan's own test suite are flagged, with none of its 14 benign
  files; re-classifying every global recorded from the first Hub sample changes no verdict.
- The rule was designed on the first Hub sample, so its false alarm rate is measured on a
  second sample drawn afterwards (`make hf-heldout`).
- A class in a trusted library whose constructor has a side effect is still rated as library
  code, and an unknown third-party function is still medium: the scanner cannot tell a rebuild
  helper from anything else in a package it knows nothing about.
- A pickle that calls `print` is flagged. It is harmless and it is not reconstruction.
