# ADR-0008: Measure on a sample the rules never saw, then record what it changed

- **Status:** Accepted
- **Date:** 2026-11-23

## Context
The rules of version 0.2.0 were shaped by three sets of files: the authored corpus, the test
files of four other scanner projects, and the first Hugging Face sample. A number measured on
files that shaped the rules says how well the rules fit those files. It does not say what
happens on the next file.

Two rules made this concrete. The denylist entries for `operator.methodcaller` and for
`functools.partial` (the second added after an outside review) and the call-shape rule of
ADR-0007 both assume that an ordinary model file does not carry a function to call. In the first Hub
sample that was true: no file without an attack stored one. That is a statement about 8,541
files, and both rules were kept after looking at them.

## Decision
1. **Draw a second sample and freeze the engine before scanning it.** `make hf-heldout` lists
   the most recently created model repositories on the Hub, drops every repository of the first
   sample, and fetches the same kinds of files plus YAML configs, templates and archives. The
   engine was committed before the first scan of this sample, and that scan is published as
   measured (`benchmarks/results/hf_heldout_frozen*`), false alarms included.
2. **Fix what the sample shows, and say that the sample is no longer unseen.** The results after
   the fixes are published next to the frozen ones (`hf_heldout*`). They are a regression check,
   not a second independent measurement.
3. **Each fix is a rule about what the file does, not a list of the files that tripped it:**
   - A function kept for later is not a function called now. `functools.partial(f, ...)` around
     a global that is not dangerous, and `operator.methodcaller("name", ...)` with an ordinary
     method name, are reported at medium (MS118). The wrapped function counts as called only
     when the stream calls the result or passes it to another call. A dangerous or computed
     target, or a method name that evaluates text, loads or writes, keeps the critical rating.
   - PyYAML tags for built-in values (`!!python/tuple`) build that value and nothing else: low.
   - Eight bytes of text read as a safetensors header length mean the file is not safetensors:
     medium. A binary length over the limit stays high.
   - A file whose whole content is a path into a system location is a symbolic link stored as
     a file: high (MS206), which is what it deserved instead of a header-length complaint.
   - A path on the loading machine in a Keras layer config is high (MS506). The frozen engine
     rated the one such file in the sample low, because it only knew the config named a
     custom object.
   - A shard path that leaves the model directory in a checkpoint index is high (MS1004).
     This rule was written after reading the other files of the repository that held the
     stored link; the index files themselves were not in the sample.
4. **Symbolic links are part of the tree.** Before this decision a directory walk skipped
   every link, so a Hugging Face cache snapshot, which is nothing but links into `blobs/`, was
   reported as zero files scanned. Links to files inside the scanned tree or to cache blobs are
   now scanned once; links that leave the tree are reported (MS206) and their targets are not
   opened.

## Alternatives considered
- **Report only the numbers after the fixes.** Rejected: that would present a tuned result as
  an unseen one, which is the mistake the second sample exists to avoid.
- **Allowlist `sklearn.utils.validation.check_array`.** It would have silenced the eight files
  in this sample and none of the ones in the next. The deferred-call rule covers any stored
  function and keeps the question the scanner can answer: does anything run on load.
- **Lower MS115 to medium.** It would hide the false alarms and also the 20 third-party test
  files that are caught through this rule and no older one.
- **Follow links that leave the tree.** A scanner that opens `/etc/hostname` because a model
  repository told it to is doing what the link was planted for.

## Consequences
- The frozen held-out numbers are worse than the numbers on the first sample. That is the
  expected direction and the reason to publish both.
- A stored function is below the default failure threshold. A pipeline that later calls a
  stored code-running library function that no list names is not caught on load; this is the
  same limit the bare reference to such a function already had.
- After these fixes there is no unseen sample left. The next release needs a new one.
