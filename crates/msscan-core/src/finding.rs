//! Findings, severities and the rule catalog.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Ordered severity of a finding. `Critical` means loading the file runs code chosen by its author.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const ALL: [Severity; 5] = [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn parse(s: &str) -> Option<Severity> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }

    /// Weight used by the noisy-or risk score (see ADR 0004).
    pub fn weight(self) -> f64 {
        match self {
            Severity::Info => 0.0,
            Severity::Low => 0.05,
            Severity::Medium => 0.25,
            Severity::High => 0.6,
            Severity::Critical => 0.95,
        }
    }

    /// The value GitHub code scanning reads from `security-severity`.
    pub fn sarif_score(self) -> &'static str {
        match self {
            Severity::Info => "0.0",
            Severity::Low => "3.0",
            Severity::Medium => "5.5",
            Severity::High => "8.0",
            Severity::Critical => "9.8",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One entry in the rule catalog.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Rule {
    pub id: &'static str,
    pub name: &'static str,
    pub severity: Severity,
    pub cwe: &'static str,
    pub summary: &'static str,
    pub remediation: &'static str,
}

macro_rules! rules {
    ($($konst:ident = $id:literal, $name:literal, $sev:ident, $cwe:literal, $summary:literal, $fix:literal;)*) => {
        pub mod ids {
            $(pub const $konst: &str = $id;)*
        }
        /// Every rule the scanner can report, in catalog order.
        pub const RULES: &[Rule] = &[
            $(Rule { id: $id, name: $name, severity: Severity::$sev, cwe: $cwe, summary: $summary, remediation: $fix },)*
        ];
    };
}

rules! {
    PICKLE_DANGEROUS_CALL = "MS101", "pickle-dangerous-call", Critical, "CWE-502",
        "A pickle calls a function that can run code, start processes, touch files or the network.",
        "Do not load the file. Obtain the weights in safetensors or another format without code.";
    PICKLE_DANGEROUS_IMPORT = "MS102", "pickle-dangerous-import", High, "CWE-502",
        "A pickle imports a dangerous global without an observed call; the reference alone is unusual.",
        "Do not load the file with pickle; inspect where the reference is used.";
    PICKLE_DYNAMIC_IMPORT = "MS103", "pickle-dynamic-import", High, "CWE-502",
        "STACK_GLOBAL takes a module or name that is not a constant string, so the import is chosen at load time.",
        "Treat as malicious unless the producer is known; no ordinary serializer emits this.";
    PICKLE_EXTENSION_REGISTRY = "MS104", "pickle-extension-registry", High, "CWE-502",
        "EXT1, EXT2 or EXT4 resolve a global through the copyreg extension registry, which the scanner cannot see.",
        "Load only in a process whose copyreg registry is known, or convert the file.";
    PICKLE_ATTRIBUTE_INJECTION = "MS105", "pickle-attribute-injection", Critical, "CWE-915",
        "BUILD writes a dunder attribute such as __setstate__ onto an object, so a later BUILD calls an attacker-chosen function.",
        "Do not load the file.";
    PICKLE_NESTED_LOADER = "MS106", "pickle-nested-loader", High, "CWE-502",
        "The pickle calls another deserializer (pickle.loads, torch.load, numpy.load and similar) on embedded bytes; the embedded payload is scanned and reported too.",
        "Scan the embedded payload findings; avoid loaders that deserialize nested pickles.";
    PICKLE_UNKNOWN_CALL = "MS107", "pickle-unknown-call", Medium, "CWE-502",
        "A pickle calls a global that is neither on the allowlist of known-safe constructors nor on the denylist.",
        "Check that the module is a library you trust and that it is installed from a trusted source.";
    PICKLE_UNKNOWN_IMPORT = "MS108", "pickle-unknown-import", Low, "CWE-502",
        "A pickle imports a global that is not on the allowlist; importing a module runs its top-level code.",
        "Check that the module is a library you trust.";
    PICKLE_MALFORMED = "MS109", "pickle-malformed", Medium, "CWE-20",
        "The pickle stream is truncated or invalid. Python executes every opcode before the error, so the analysis covers only the valid prefix.",
        "Re-export the file; a damaged pickle is also a common way to confuse scanners.";
    PICKLE_INDIRECT_CALL = "MS110", "pickle-indirect-call", High, "CWE-502",
        "A pickle calls the result of another call (for example getattr(...)(...)), so the final callee is computed at load time.",
        "Treat as malicious unless the producer is known.";
    PICKLE_LIBRARY_CALL = "MS111", "pickle-library-call", Low, "CWE-502",
        "A pickle calls a global from a widely used ML or standard library namespace that is not on the exact allowlist.",
        "Usually benign (whole-model checkpoints); prefer weights-only formats.";
    PICKLE_UNSCANNED_REGION = "MS112", "pickle-unscanned-region", Medium, "CWE-693",
        "Part of the stream could not be analyzed (for example a joblib array whose size is unknown), and code could hide there.",
        "Convert the file or inspect the region manually.";
    PICKLE_TRAILING = "MS113", "pickle-trailing-data", Low, "CWE-693",
        "Bytes follow the final STOP opcode. Some loaders read several pickles from one file.",
        "Check why the file has trailing data.";
    PICKLE_RESOURCE = "MS114", "pickle-resource-limit", Medium, "CWE-400",
        "The pickle exceeds an analysis limit (opcodes, nesting, memo size), which also bounds memory use when it is loaded.",
        "Inspect the file; raise the limit only for trusted producers.";
    ARCHIVE_TRAVERSAL = "MS201", "archive-path-traversal", High, "CWE-22",
        "An archive entry name is absolute or climbs out of the extraction directory.",
        "Do not extract the archive with tools that trust entry names.";
    ARCHIVE_HEADER_MISMATCH = "MS202", "archive-header-mismatch", High, "CWE-436",
        "A zip local header disagrees with the central directory (name, flags or sizes), which lets different readers see different files.",
        "Rebuild the archive; loaders and scanners may disagree about its contents.";
    ARCHIVE_BOMB = "MS203", "archive-decompression-limit", High, "CWE-409",
        "Decompressed data exceeds the size limit or the compression ratio is extreme.",
        "Do not decompress the file without limits.";
    ARCHIVE_MALFORMED = "MS204", "archive-malformed", Medium, "CWE-20",
        "The archive or compressed stream is damaged or uses an unsupported feature, so some content was not scanned.",
        "Re-create the archive.";
    ARCHIVE_ENCRYPTED = "MS205", "archive-encrypted-entry", Medium, "CWE-693",
        "An archive entry is marked encrypted and could not be scanned.",
        "Obtain an unencrypted copy.";
    NUMPY_OBJECT_ARRAY = "MS301", "numpy-object-array", Medium, "CWE-502",
        "A .npy array has an object dtype, so numpy.load(allow_pickle=True) unpickles the embedded data (scanned and reported separately).",
        "Store numeric arrays only; keep allow_pickle=False.";
    NUMPY_MALFORMED = "MS302", "numpy-malformed", Medium, "CWE-20",
        "The .npy header is invalid or its declared size does not match the file.",
        "Re-export the array.";
    TORCH_LEGACY = "MS401", "torch-legacy-format", Info, "CWE-502",
        "A PyTorch file in the legacy (pre-1.6) multi-pickle format; every pickle torch.load reads was scanned.",
        "Re-save with a current PyTorch or convert to safetensors.";
    TORCH_SCRIPT = "MS402", "torchscript-code", Low, "CWE-94",
        "A TorchScript archive contains serialized code that torch.jit.load compiles and runs.",
        "Load TorchScript only from trusted producers.";
    KERAS_LAMBDA = "MS501", "keras-lambda-layer", High, "CWE-94",
        "A Keras model contains a Lambda layer with serialized Python bytecode, which runs when the model is loaded or called (Keras 3 blocks it unless safe_mode=False; Keras 2 HDF5 loading does not).",
        "Rebuild the layer in code and load weights only.";
    KERAS_UNSAFE_MODULE = "MS502", "keras-unsafe-module", High, "CWE-470",
        "A Keras config deserializes a class or function from a module that runs code or reaches the system (os, subprocess, builtins and the pickle denylist) or a Keras file utility.",
        "Check every module named in the config; register trusted custom objects explicitly.";
    KERAS_CUSTOM_OBJECT = "MS503", "keras-custom-object", Low, "CWE-470",
        "A Keras config refers to a registered custom object or a function by name (module builtins or __main__) that Keras resolves only from objects supplied by code at load time.",
        "Make sure the custom object comes from trusted code.";
    KERAS_MALFORMED = "MS504", "keras-malformed", Medium, "CWE-20",
        "The Keras model configuration is missing or is not valid JSON.",
        "Re-export the model.";
    KERAS_EXTERNAL_MODULE = "MS505", "keras-external-module", Medium, "CWE-470",
        "A Keras config names a class or function from a third-party module, so loading needs code that is not in the file (older Keras imports the module named in the config).",
        "Install the package from a trusted source or register the objects explicitly.";
    TF_FILE_OP = "MS601", "tf-file-io-op", High, "CWE-73",
        "A TensorFlow graph contains an op that reads, writes or lists files (ReadFile, WriteFile, MatchingFiles and similar).",
        "Inspect the graph; serving a model should not need file access.";
    TF_PY_FUNC = "MS602", "tf-py-func-op", Critical, "CWE-94",
        "A TensorFlow graph contains PyFunc or EagerPyFunc, which call Python functions from the graph.",
        "Do not serve the model.";
    TF_MALFORMED = "MS603", "tf-malformed", Medium, "CWE-20",
        "The SavedModel protobuf could not be decoded.",
        "Re-export the model.";
    TF_RISKY_OP = "MS604", "tf-risky-op", Medium, "CWE-749",
        "A TensorFlow graph contains an op with side effects outside the model (printing to files, debug dumps, system information).",
        "Check that the op is intended.";
    ONNX_EXTERNAL_TRAVERSAL = "MS701", "onnx-external-data-traversal", High, "CWE-22",
        "An ONNX tensor stores its data in an external file whose path is absolute or leaves the model directory.",
        "Reject the model; external data paths must be relative and inside the model directory.";
    ONNX_CUSTOM_DOMAIN = "MS702", "onnx-custom-op-domain", Low, "CWE-829",
        "An ONNX graph uses operators from a non-standard domain, which need a custom operator library at load time.",
        "Load custom operator libraries only from trusted sources.";
    ONNX_MALFORMED = "MS703", "onnx-malformed", Medium, "CWE-20",
        "The ONNX protobuf could not be decoded.",
        "Re-export the model.";
    GGUF_TEMPLATE_INJECTION = "MS801", "gguf-chat-template-injection", Critical, "CWE-1336",
        "A GGUF chat template reaches Python internals (__class__, __globals__, __subclasses__, __import__ and similar), the pattern of server-side template injection in unsandboxed Jinja.",
        "Render chat templates only in a sandboxed Jinja environment; replace the template.";
    GGUF_TEMPLATE_SUSPICIOUS = "MS802", "gguf-chat-template-suspicious", Medium, "CWE-1336",
        "A GGUF chat template uses constructs that ordinary templates do not need (attr filters, dunder names, very long templates).",
        "Review the template.";
    GGUF_MALFORMED = "MS803", "gguf-malformed", High, "CWE-20",
        "The GGUF header is invalid: bad counts, lengths, types or tensor offsets outside the file. Parser bugs of this kind have led to memory corruption in GGUF loaders.",
        "Do not load the file with native parsers.";
    SAFETENSORS_HEADER = "MS901", "safetensors-invalid-header", High, "CWE-20",
        "The safetensors header is not valid UTF-8 JSON of the expected shape, or its length is outside the file.",
        "Do not load the file.";
    SAFETENSORS_OFFSETS = "MS902", "safetensors-invalid-offsets", High, "CWE-787",
        "Tensor data offsets overlap, leave gaps, run past the file, or disagree with shape and dtype.",
        "Do not load the file with readers that do not validate offsets.";
    SAFETENSORS_METADATA = "MS903", "safetensors-metadata", Low, "CWE-20",
        "The __metadata__ entry holds values that are not strings, or the header holds unknown dtypes.",
        "Re-export the file.";
    FORMAT_MISMATCH = "MS1001", "format-extension-mismatch", Medium, "CWE-434",
        "The file content does not match its extension (for example a pickle named .safetensors).",
        "Treat the file by its content, not its name.";
    FORMAT_UNKNOWN = "MS1002", "format-unknown", Info, "CWE-20",
        "The file format was not recognized, so nothing was checked.",
        "None.";
    HF_REMOTE_CODE = "MS1003", "hf-remote-code", Low, "CWE-829",
        "A Hugging Face config.json maps model classes to code in the repository (auto_map), so loading needs trust_remote_code=True.",
        "Review the repository code before enabling trust_remote_code.";
}

/// Look up a rule by id.
pub fn rule(id: &str) -> &'static Rule {
    RULES
        .iter()
        .find(|r| r.id == id)
        .unwrap_or_else(|| panic!("unknown rule id {id}"))
}

/// One problem found in a file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub rule: String,
    pub name: String,
    pub severity: Severity,
    pub message: String,
    /// Where in the file: an archive member and/or byte offset, for example `archive/data.pkl@123`.
    pub location: String,
}

impl Finding {
    pub fn new(rule_id: &str, message: impl Into<String>, location: impl Into<String>) -> Self {
        let r = rule(rule_id);
        Finding {
            rule: r.id.to_string(),
            name: r.name.to_string(),
            severity: r.severity,
            message: message.into(),
            location: location.into(),
        }
    }

    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_ids_are_unique_and_named() {
        let mut ids: Vec<_> = RULES.iter().map(|r| r.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), RULES.len());
        for r in RULES {
            assert!(r.id.starts_with("MS"));
            assert!(!r.summary.is_empty() && !r.remediation.is_empty());
            assert!(r.cwe.starts_with("CWE-"));
        }
    }

    #[test]
    fn severity_round_trip_and_order() {
        for s in Severity::ALL {
            assert_eq!(Severity::parse(s.as_str()), Some(s));
            assert_eq!(s.to_string(), s.as_str());
            assert!(!s.sarif_score().is_empty());
        }
        assert!(Severity::Critical > Severity::High);
        assert_eq!(Severity::parse("bogus"), None);
    }

    #[test]
    #[should_panic]
    fn unknown_rule_panics() {
        rule("MS0");
    }
}
