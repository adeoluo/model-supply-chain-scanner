# ADR-0005: Reading Keras configs from raw bytes instead of parsing HDF5

- **Status:** Accepted
- **Date:** 2026-11-04

## Context
Legacy Keras `.h5` files keep the model architecture as JSON in the `model_config` attribute of
the root group, and TensorFlow SavedModels written by Keras keep layer configs in protobuf
strings inside `keras_metadata.pb`. A full HDF5 reader (superblocks, B-trees, fractal heaps,
dense attribute storage) is a large amount of hostile-input parsing for one string.

## Decision
Find every `{"class_name"` (or `{"module"`) object in the raw bytes, match its closing brace with a
string-aware scanner, and parse it with serde_json. HDF5 stores attribute data uncompressed and
contiguously, so the JSON is present verbatim whether it sits in the object header or in dense
storage. All parsed configs go through the same checks as `.keras` `config.json`.

## Alternatives considered
- **libhdf5 bindings.** A C dependency that parses the hostile file in full.
- **A Rust HDF5 parser.** Large, and the scanner needs one attribute.

## Consequences
- A config split across non-contiguous heap blocks, or deliberately encoded differently, would
  be missed; a found but unparsable config is reported (MS504).
- Weights-only `.h5` files (most `tf_model.h5` files on the Hub) correctly yield no config.
