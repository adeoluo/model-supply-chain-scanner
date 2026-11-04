//! Classification of pickle globals: allowlist, denylist, library namespaces and nested loaders.

use serde::Serialize;

/// How a `module.name` global is classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// Exact match on the allowlist of constructors found in ordinary checkpoints.
    Safe,
    /// A widely used ML or standard library namespace, not on the exact allowlist.
    Library,
    /// Neither allowlisted nor denylisted.
    Unknown,
    /// Can run code, start processes, touch files or the network, or load nested payloads.
    Dangerous,
}

/// Exact allowlist: (module, name).
const SAFE: &[(&str, &str)] = &[
    ("collections", "OrderedDict"),
    ("collections", "defaultdict"),
    ("collections", "Counter"),
    ("collections", "deque"),
    ("builtins", "set"),
    ("builtins", "frozenset"),
    ("builtins", "slice"),
    ("builtins", "range"),
    ("builtins", "complex"),
    ("builtins", "bytearray"),
    ("builtins", "bytes"),
    ("builtins", "int"),
    ("builtins", "float"),
    ("builtins", "str"),
    ("builtins", "list"),
    ("builtins", "dict"),
    ("builtins", "tuple"),
    ("builtins", "bool"),
    ("builtins", "object"),
    ("__builtin__", "set"),
    ("__builtin__", "frozenset"),
    ("__builtin__", "slice"),
    ("__builtin__", "complex"),
    ("__builtin__", "object"),
    ("_codecs", "encode"),
    ("copyreg", "_reconstructor"),
    ("copy_reg", "_reconstructor"),
    ("copyreg", "__newobj__"),
    ("datetime", "datetime"),
    ("datetime", "date"),
    ("datetime", "time"),
    ("datetime", "timedelta"),
    ("datetime", "timezone"),
    ("decimal", "Decimal"),
    ("fractions", "Fraction"),
    ("uuid", "UUID"),
    ("argparse", "Namespace"),
    ("numpy", "ndarray"),
    ("numpy", "dtype"),
    ("numpy", "bool_"),
    ("numpy.core.multiarray", "_reconstruct"),
    ("numpy.core.multiarray", "scalar"),
    ("numpy._core.multiarray", "_reconstruct"),
    ("numpy._core.multiarray", "scalar"),
    ("numpy.core.numeric", "_frombuffer"),
    ("numpy._core.numeric", "_frombuffer"),
    ("numpy.random", "__RandomState_ctor"),
    ("numpy.random._pickle", "__randomstate_ctor"),
    ("numpy.random._pickle", "__bit_generator_ctor"),
    ("numpy.random._pickle", "__generator_ctor"),
    ("numpy.random._mt19937", "MT19937"),
    ("numpy.random._pcg64", "PCG64"),
    ("numpy.random.mtrand", "RandomState"),
    ("numpy.random.bit_generator", "__pyx_unpickle_SeedSequence"),
    ("joblib.numpy_pickle", "NumpyArrayWrapper"),
    ("joblib.numpy_pickle", "NDArrayWrapper"),
    ("sklearn.externals.joblib.numpy_pickle", "NumpyArrayWrapper"),
    ("torch._utils", "_rebuild_tensor"),
    ("torch._utils", "_rebuild_tensor_v2"),
    ("torch._utils", "_rebuild_tensor_v3"),
    ("torch._utils", "_rebuild_parameter"),
    ("torch._utils", "_rebuild_parameter_with_state"),
    ("torch._utils", "_rebuild_qtensor"),
    ("torch._utils", "_rebuild_sparse_tensor"),
    ("torch._utils", "_rebuild_meta_tensor_no_storage"),
    ("torch._utils", "_rebuild_nested_tensor"),
    ("torch._tensor", "_rebuild_from_type_v2"),
    ("torch", "Size"),
    ("torch", "device"),
    ("torch", "Tensor"),
    ("torch.nn.parameter", "Parameter"),
    ("torch", "per_tensor_affine"),
    ("torch.serialization", "_get_layout"),
    ("torch.jit._pickle", "build_intlist"),
    ("torch.jit._pickle", "build_tensorlist"),
    ("torch.jit._pickle", "build_doublelist"),
    ("torch.jit._pickle", "build_boollist"),
    ("torch.jit._pickle", "build_tensor_from_id"),
    ("torch.jit._pickle", "restore_type_tag"),
];

/// Storage and dtype attributes that appear as globals in PyTorch pickles.
const TORCH_STORAGES: &[&str] = &[
    "FloatStorage",
    "DoubleStorage",
    "HalfStorage",
    "BFloat16Storage",
    "LongStorage",
    "IntStorage",
    "ShortStorage",
    "CharStorage",
    "ByteStorage",
    "BoolStorage",
    "ComplexFloatStorage",
    "ComplexDoubleStorage",
    "QInt8Storage",
    "QUInt8Storage",
    "QInt32Storage",
    "UntypedStorage",
    "TypedStorage",
    "float32",
    "float64",
    "float16",
    "bfloat16",
    "int64",
    "int32",
    "int16",
    "int8",
    "uint8",
    "bool",
    "complex64",
    "complex128",
    "float8_e4m3fn",
    "float8_e5m2",
    "strided",
    "sparse_coo",
    "contiguous_format",
    "channels_last",
    "preserve_format",
];

/// Modules where every name is dangerous.
const DANGEROUS_MODULES: &[&str] = &[
    "os",
    "posix",
    "nt",
    "subprocess",
    "sys",
    "socket",
    "shutil",
    "pty",
    "commands",
    "platform",
    "webbrowser",
    "runpy",
    "importlib",
    "imp",
    "pickle",
    "_pickle",
    "cPickle",
    "pickletools",
    "dill",
    "cloudpickle",
    "marshal",
    "types",
    "code",
    "codeop",
    "pdb",
    "bdb",
    "cProfile",
    "profile",
    "timeit",
    "trace",
    "asyncio",
    "multiprocessing",
    "threading",
    "_thread",
    "concurrent",
    "ctypes",
    "_ctypes",
    "cffi",
    "requests",
    "httpx",
    "urllib",
    "urllib2",
    "urllib3",
    "http",
    "httplib",
    "ftplib",
    "smtplib",
    "telnetlib",
    "poplib",
    "imaplib",
    "xmlrpc",
    "socketserver",
    "tempfile",
    "glob",
    "fileinput",
    "pip",
    "setuptools",
    "distutils",
    "pkg_resources",
    "site",
    "ensurepip",
    "venv",
    "zipimport",
    "pkgutil",
    "signal",
    "resource",
    "gc",
    "inspect",
    "builtins.__dict__",
    "numpy.f2py",
    "numpy.distutils",
    "numpy.ctypeslib",
    "numpy.testing",
    "torch.hub",
    "torch.utils.cpp_extension",
    "torch.package",
    "torch._dynamo",
    "torch._inductor",
    "torch.distributed",
    "torch.ops",
    "torch._ops",
    "pandas.io.pickle",
    "keras.utils.generic_utils",
    "tensorflow.python.ops.script_ops",
    "jinja2",
    "yaml",
    "mmap",
    "linecache",
    "zipfile",
    "tarfile",
];

/// Exact dangerous names in otherwise ordinary modules.
const DANGEROUS_NAMES: &[(&str, &str)] = &[
    ("builtins", "eval"),
    ("builtins", "exec"),
    ("builtins", "execfile"),
    ("builtins", "compile"),
    ("builtins", "open"),
    ("builtins", "__import__"),
    ("builtins", "getattr"),
    ("builtins", "setattr"),
    ("builtins", "delattr"),
    ("builtins", "globals"),
    ("builtins", "locals"),
    ("builtins", "vars"),
    ("builtins", "input"),
    ("builtins", "breakpoint"),
    ("builtins", "apply"),
    ("builtins", "file"),
    ("builtins", "reload"),
    ("builtins", "type"),
    ("operator", "attrgetter"),
    ("operator", "methodcaller"),
    ("operator", "call"),
    ("_operator", "attrgetter"),
    ("_operator", "methodcaller"),
    ("_operator", "call"),
    ("functools", "reduce"),
    ("_functools", "reduce"),
    ("copyreg", "add_extension"),
    ("copyreg", "_extension_registry"),
    ("numpy", "load"),
    ("numpy", "loads"),
    ("numpy", "fromfile"),
    ("numpy", "save"),
    ("numpy", "tofile"),
    ("numpy.lib.npyio", "load"),
    ("numpy.lib._npyio_impl", "load"),
    ("numpy.lib.format", "read_array"),
    ("numpy.core.multiarray", "frombuffer_unsafe"),
    ("torch", "load"),
    ("torch", "save"),
    ("torch", "compile"),
    ("torch.serialization", "load"),
    ("torch.jit", "load"),
    ("torch.jit._serialization", "load"),
    ("torch.jit", "_load_for_lite_interpreter"),
    ("torch.jit", "script"),
    ("torch.jit", "trace"),
    ("torch.serialization", "save"),
    ("torch.serialization", "_load"),
    ("torch.serialization", "_legacy_load"),
    ("torch.storage", "_load_from_bytes"),
    ("torch._utils", "_rebuild_device_tensor_from_numpy"),
    ("torch.fx.graph_module", "reduce_graph_module"),
    ("torch.fx.graph_module", "reduce_package_graph_module"),
    ("torch.fx.graph_module", "_deserialize_graph_module"),
    ("pandas", "read_pickle"),
    ("pandas", "eval"),
    ("pandas.core.computation.eval", "eval"),
    ("joblib", "load"),
    ("joblib.numpy_pickle", "load"),
    ("sklearn.externals.joblib", "load"),
    ("io", "open"),
    ("io", "open_code"),
    ("io", "FileIO"),
    ("_io", "open"),
    ("_io", "open_code"),
    ("_io", "FileIO"),
    ("keras.models", "load_model"),
    ("keras.saving", "load_model"),
    ("tensorflow.keras.models", "load_model"),
];

/// Calls that deserialize a nested payload taken from their arguments.
const NESTED_LOADERS: &[(&str, &str)] = &[
    ("pickle", "loads"),
    ("pickle", "load"),
    ("_pickle", "loads"),
    ("_pickle", "load"),
    ("cPickle", "loads"),
    ("dill", "loads"),
    ("cloudpickle", "loads"),
    ("torch", "load"),
    ("torch.serialization", "load"),
    ("torch.storage", "_load_from_bytes"),
    ("numpy", "loads"),
    ("joblib", "load"),
    ("pandas", "read_pickle"),
];

/// Namespaces treated as known libraries (calls are reported as `Library`, not `Unknown`).
const LIBRARY_PREFIXES: &[&str] = &[
    "torch",
    // TorchScript class names, resolved by the TorchScript type system rather than imported.
    "__torch__",
    "numpy",
    "scipy",
    "sklearn",
    "pandas",
    "transformers",
    "tokenizers",
    "sentence_transformers",
    "timm",
    "torchvision",
    "torchaudio",
    "xgboost",
    "lightgbm",
    "catboost",
    "pytorch_lightning",
    "lightning",
    "lightning_fabric",
    "omegaconf",
    "collections",
    "datetime",
    "functools",
    "enum",
    "typing",
    "pathlib",
    "re",
    "_codecs",
    "codecs",
    "copyreg",
    "builtins",
    "__builtin__",
    "math",
    "fractions",
    "decimal",
    "numbers",
    "string",
    "nltk",
    "gensim",
    "spacy",
    "fastai",
    "accelerate",
    "peft",
    "diffusers",
    "huggingface_hub",
    "safetensors",
    "statsmodels",
    "keras",
    "tensorflow",
    "jax",
    "flax",
    "optax",
    "haiku",
    "einops",
    "PIL",
    "matplotlib",
    "joblib",
    "fairseq",
    "mmcv",
    "mmdet",
    "detectron2",
    "ultralytics",
    "onnx",
    "sentencepiece",
    "torchmetrics",
    "hydra",
    "yacs",
    "easydict",
    "addict",
    "bitsandbytes",
    "open_clip",
    "speechbrain",
    "nemo",
    "espnet",
    "allennlp",
    "flair",
    "stable_baselines3",
    "gym",
    "gymnasium",
];

fn in_module(module: &str, base: &str) -> bool {
    module == base || (module.len() > base.len() && module.starts_with(base) && module.as_bytes()[base.len()] == b'.')
}

/// Classify a global reference.
pub fn classify(module: &str, name: &str) -> Tier {
    let module = module.trim();
    let name = name.trim();
    if DANGEROUS_NAMES.iter().any(|(m, n)| *m == module && *n == name) {
        return Tier::Dangerous;
    }
    if (module == "__builtin__" || module == "__builtins__" || module == "_builtins")
        && DANGEROUS_NAMES.iter().any(|(m, n)| *m == "builtins" && *n == name)
    {
        return Tier::Dangerous;
    }
    if DANGEROUS_MODULES.iter().any(|m| in_module(module, m)) {
        return Tier::Dangerous;
    }
    // Attribute paths ("os.system" as a name with protocol 4 dotted lookup) are dangerous when any
    // component is: STACK_GLOBAL resolves "a.b" names by getattr chains.
    if name.contains('.') {
        let first = name.split('.').next().unwrap_or("");
        if first.starts_with("__") || name.split('.').any(|p| p.starts_with("__") && p.ends_with("__")) {
            return Tier::Dangerous;
        }
        let full = format!("{module}.{name}");
        let (m2, n2) = full.rsplit_once('.').unwrap_or((module, name));
        if classify(m2, n2) == Tier::Dangerous {
            return Tier::Dangerous;
        }
    }
    if SAFE.iter().any(|(m, n)| *m == module && *n == name) {
        return Tier::Safe;
    }
    if module == "torch" && TORCH_STORAGES.contains(&name) {
        return Tier::Safe;
    }
    if LIBRARY_PREFIXES.iter().any(|p| in_module(module, p)) {
        return Tier::Library;
    }
    Tier::Unknown
}

/// Whether calling this global deserializes a nested payload.
pub fn is_nested_loader(module: &str, name: &str) -> bool {
    NESTED_LOADERS.iter().any(|(m, n)| *m == module && *n == name)
}

/// Sizes of the lists, for documentation and tests.
pub fn catalog_sizes() -> (usize, usize, usize, usize) {
    (
        SAFE.len() + TORCH_STORAGES.len(),
        DANGEROUS_MODULES.len(),
        DANGEROUS_NAMES.len(),
        LIBRARY_PREFIXES.len(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiers() {
        assert_eq!(classify("os", "system"), Tier::Dangerous);
        assert_eq!(classify("os.path", "join"), Tier::Dangerous);
        assert_eq!(classify("osgeo", "gdal"), Tier::Unknown);
        assert_eq!(classify("posix", "getcwd"), Tier::Dangerous);
        assert_eq!(classify("builtins", "eval"), Tier::Dangerous);
        assert_eq!(classify("__builtin__", "eval"), Tier::Dangerous);
        assert_eq!(classify("__builtins__", "exec"), Tier::Dangerous);
        assert_eq!(classify("builtins", "set"), Tier::Safe);
        assert_eq!(classify("builtins", "print"), Tier::Library);
        assert_eq!(classify("collections", "OrderedDict"), Tier::Safe);
        assert_eq!(classify("torch._utils", "_rebuild_tensor_v2"), Tier::Safe);
        assert_eq!(classify("torch", "FloatStorage"), Tier::Safe);
        assert_eq!(classify("torch", "load"), Tier::Dangerous);
        assert_eq!(classify("torch.nn.modules.linear", "Linear"), Tier::Library);
        assert_eq!(classify("__main__", "Net"), Tier::Unknown);
        assert_eq!(classify("numpy.testing._private.utils", "runstring"), Tier::Dangerous);
        assert_eq!(classify(" os ", "getcwd"), Tier::Dangerous);
        assert_eq!(classify("torch.jit._pickle", "build_intlist"), Tier::Safe);
        assert_eq!(classify("torch.jit", "load"), Tier::Dangerous);
        assert_eq!(classify("__torch__.torch.nn.modules.linear", "Linear"), Tier::Library);
    }

    #[test]
    fn dotted_names_resolve_through_attributes() {
        assert_eq!(classify("builtins", "__dict__.eval"), Tier::Dangerous);
        assert_eq!(
            classify("collections", "OrderedDict.__init__.__globals__"),
            Tier::Dangerous
        );
        assert_eq!(classify("torch", "serialization.load"), Tier::Dangerous);
        assert_eq!(classify("torch", "nn.Linear"), Tier::Library);
    }

    #[test]
    fn loaders() {
        assert!(is_nested_loader("pickle", "loads"));
        assert!(is_nested_loader("torch.storage", "_load_from_bytes"));
        assert!(!is_nested_loader("os", "system"));
        let (s, m, n, l) = catalog_sizes();
        assert!(s > 50 && m > 50 && n > 50 && l > 50);
    }
}
