//! Classification of pickle globals: allowlist, denylist, library namespaces and nested loaders.

use super::stdlib;
use serde::{Deserialize, Serialize};

/// How a `module.name` global is classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
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
    "aiohttp",
    "websocket",
    "websockets",
    "paramiko",
    "pycurl",
    "httplib2",
    "boto3",
    "botocore",
    "grpc",
    "zmq",
    "pexpect",
    "sh",
    "plumbum",
    "fabric",
    "invoke",
    "psutil",
    "docker",
    "kubernetes",
    "win32api",
    "win32process",
    "winreg",
    "_winreg",
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
    "torch.utils.collect_env",
    "torch.utils.bottleneck",
    "torch.utils.benchmark",
    "torch.utils.model_zoo",
    "torch.utils.file_baton",
    "torch.package",
    "torch._dynamo",
    "torch._inductor",
    "torch.multiprocessing",
    // torch.distributed itself (process groups, send and recv) and the parts that run commands,
    // remote calls or file I/O; tensor, device mesh and placement classes stay library code.
    "torch.distributed.rpc",
    "torch.distributed.elastic",
    "torch.distributed.launch",
    "torch.distributed.launcher",
    "torch.distributed.run",
    "torch.distributed.checkpoint",
    "torch.distributed.distributed_c10d",
    "torch.ops",
    "torch._ops",
    "pandas.io.pickle",
    "pandas.io.clipboard",
    "keras.utils.generic_utils",
    "tensorflow.python.ops.script_ops",
    "tensorflow.io.gfile",
    // Loaders of code, checkpoints and remote files inside namespaces that are otherwise
    // treated as libraries. A model never needs to call these while it is being unpickled.
    "transformers.dynamic_module_utils",
    "transformers.utils.hub",
    "tensorflow.saved_model",
    "tensorflow.python.saved_model.load",
    "tensorflow.python.framework.load_library",
    "huggingface_hub.file_download",
    "huggingface_hub._snapshot_download",
    "hydra.utils",
    "hydra._internal.utils",
    "hydra._internal.instantiate",
    "omegaconf.resolvers",
    "joblib.externals",
    "PIL.ImageMath",
    "PIL.ImageShow",
    "PIL.ImageGrab",
    "scipy.weave",
    "nltk.downloader",
    "nltk.data",
    "gensim.downloader",
    "spacy.cli",
    "fastai.data.external",
    "accelerate.launchers",
    "accelerate.commands",
    "diffusers.utils.dynamic_modules_utils",
    "diffusers.pipelines.pipeline_loading_utils",
    "pytorch_lightning.utilities.imports",
    "lightning.pytorch.utilities.imports",
    "lightning_fabric.utilities.imports",
    "lightning_fabric.utilities.cloud_io",
    "mmcv.fileio",
    "ultralytics.utils.checks",
    "ultralytics.utils.downloads",
    "onnx.hub",
    "fairseq.checkpoint_utils",
    "fairseq.hub_utils",
    "speechbrain.utils.fetching",
    "allennlp.common.file_utils",
    "allennlp.models.archival",
    "flair.file_utils",
    "stable_baselines3.common.save_util",
    "timm.models._hub",
    "timm.models._builder",
    "open_clip.pretrained",
    "torchvision.datasets.utils",
    "torchaudio.utils.download",
    "peft.utils.hub_utils",
    "pydoc",
    "doctest",
    "idlelib",
    "tkinter",
    "turtle",
    "logging.config",
    "ctypes.util",
    "sysconfig",
    "_sysconfigdata",
    "uu",
    "quopri",
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
    ("functools", "partial"),
    ("functools", "partialmethod"),
    ("_functools", "reduce"),
    ("_functools", "partial"),
    ("typing", "_eval_type"),
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
    ("keras.models", "model_from_json"),
    ("keras.models", "model_from_config"),
    ("keras.models", "model_from_yaml"),
    ("tensorflow.keras.models", "model_from_json"),
    ("tensorflow.keras.models", "model_from_config"),
    ("transformers", "pipeline"),
    ("transformers.pipelines", "pipeline"),
    ("keras.saving.pickle_utils", "deserialize_model_from_bytecode"),
    ("keras.src.saving.pickle_utils", "deserialize_model_from_bytecode"),
    ("keras.src.saving.keras_saveable", "KerasSaveable._unpickle_model"),
    ("scipy.io", "loadmat"),
    ("scipy.io", "savemat"),
    ("scipy.io", "mmread"),
    ("mmcv.utils.config", "Config.fromfile"),
    ("mmengine.config", "Config.fromfile"),
    ("keras.utils", "get_file"),
    ("keras.utils", "custom_object_scope"),
    ("keras.utils", "deserialize_keras_object"),
    ("keras.layers", "deserialize"),
    ("tensorflow.keras.utils", "get_file"),
    ("tensorflow", "py_function"),
    ("tensorflow", "numpy_function"),
    ("tensorflow", "py_func"),
    ("tensorflow", "load_library"),
    ("tensorflow", "load_op_library"),
    ("tensorflow.io", "read_file"),
    ("tensorflow.io", "write_file"),
    ("huggingface_hub", "hf_hub_download"),
    ("huggingface_hub", "snapshot_download"),
    ("huggingface_hub", "cached_download"),
    ("huggingface_hub", "hf_hub_url"),
    ("pandas", "read_csv"),
    ("pandas", "read_json"),
    ("pandas", "read_html"),
    ("pandas", "read_xml"),
    ("pandas", "read_sql"),
    ("pandas", "read_sql_query"),
    ("pandas", "read_parquet"),
    ("pandas", "read_feather"),
    ("pandas", "read_hdf"),
    ("pandas", "read_excel"),
    ("pandas", "read_table"),
    ("pandas", "read_fwf"),
    ("pandas", "read_clipboard"),
    ("pandas.core.frame", "DataFrame.to_pickle"),
    ("pandas.core.frame", "DataFrame.to_csv"),
    ("pandas.core.frame", "DataFrame.query"),
    ("pandas.core.frame", "DataFrame.eval"),
    ("numpy", "genfromtxt"),
    ("numpy", "loadtxt"),
    ("numpy", "savetxt"),
    ("numpy", "savez"),
    ("numpy", "DataSource"),
    ("numpy.lib.npyio", "DataSource"),
    ("PIL.Image", "open"),
    ("PIL.Image", "Image.save"),
    ("PIL.Image", "Image.show"),
    ("xgboost", "Booster.load_model"),
    ("xgboost", "Booster.save_model"),
    ("lightgbm", "Booster.save_model"),
    ("onnx", "save"),
    ("omegaconf", "OmegaConf.register_new_resolver"),
    ("pathlib", "Path.write_text"),
    ("pathlib", "Path.write_bytes"),
    ("pathlib", "Path.read_text"),
    ("pathlib", "Path.read_bytes"),
    ("pathlib", "Path.unlink"),
    ("pathlib", "Path.rename"),
    ("pathlib", "Path.open"),
    ("pathlib", "Path.chmod"),
    ("pathlib", "Path.symlink_to"),
    ("codecs", "open"),
];

/// Final name components that load code, deserialize a second payload, fetch a remote file
/// or run a command. Inside a library namespace a callable with one of these names is treated
/// as dangerous, whatever module it lives in, so a new loader in a trusted library does not
/// pass as ordinary library code. Matched case-sensitively: classes are not named like this.
const LOADER_NAMES: &[&str] = &[
    "load",
    "loads",
    "load_model",
    "load_module",
    "load_state_dict_from_url",
    "load_checkpoint",
    "load_from_checkpoint",
    "load_from_hub",
    "load_from_disk",
    "load_library",
    "load_op_library",
    "load_url",
    "load_learner",
    "load_pickle",
    "load_object",
    "load_dataset",
    "from_pretrained",
    "from_single_file",
    "from_file",
    "from_url",
    "from_hub",
    "from_config_file",
    "read_pickle",
    "unpickle",
    "import_module",
    "import_from_string",
    "import_string",
    "import_class",
    "import_object",
    "get_class_from_dynamic_module",
    "get_cached_module_file",
    "get_class_in_module",
    "resolve_trust_remote_code",
    "custom_object_scope",
    "instantiate",
    "locate",
    "get_method",
    "get_class",
    "get_object",
    "get_obj_from_str",
    "instantiate_from_config",
    "eval",
    "exec",
    "execfile",
    "compile",
    "run",
    "main",
    "call",
    "invoke",
    "launch",
    "download",
    "download_url",
    "download_url_to_file",
    "download_file",
    "download_from_url",
    "download_and_extract_archive",
    "urlretrieve",
    "urlopen",
    "get_file",
    "cached_path",
    "cached_file",
    "cached_download",
    "hf_hub_download",
    "snapshot_download",
    "extract_archive",
    "extractall",
    "untar_data",
    "fromfile",
    "attempt_load_weights",
    "attempt_load_one_weight",
    "torch_safe_load",
    "check_requirements",
    "model_from_json",
    "model_from_config",
    "model_from_yaml",
    "deserialize_keras_object",
];

/// Keras classes that carry serialized Python and run it when the model is built, called or
/// trained. Matched only inside the Keras and TensorFlow namespaces (`torchvision.transforms`
/// also has a `Lambda`, which holds an importable callable that is classified on its own).
const CODE_CARRYING_CLASSES: &[&str] = &["Lambda", "TFOpLambda", "SlicingOpLambda", "LambdaCallback"];
const CODE_CARRYING_NAMESPACES: &[&str] = &["keras", "tf_keras", "tensorflow"];

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
    "tf_keras",
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
    if module == "torch.distributed" || DANGEROUS_MODULES.iter().any(|m| in_module(module, m)) {
        return Tier::Dangerous;
    }
    // Attribute paths ("os.system" as a name with protocol 4 dotted lookup) are dangerous when any
    // component is: STACK_GLOBAL resolves "a.b" names by getattr chains.
    if name.contains('.') {
        let first = name.split('.').next().unwrap_or("");
        if first.starts_with("__") || name.split('.').any(|p| p.starts_with("__") && p.ends_with("__")) {
            return Tier::Dangerous;
        }
        // Intermediate attributes that are private or name a dangerous module ("argparse._os",
        // "shutil.os") reach other modules through an innocent-looking import.
        let parts: Vec<&str> = name.split('.').collect();
        if parts[..parts.len() - 1]
            .iter()
            .any(|p| p.starts_with('_') || DANGEROUS_MODULES.iter().any(|m| m == p) || *p == "builtins")
        {
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
    // Helper, CLI, script, or command-runner submodules inside broad ML namespaces (e.g.
    // `torch.utils.collect_env.run`, `transformers.commands.*`) should not be downgraded to Low:
    // keep known model/tensor submodules as `Library` and flag command/exec-named callables.
    let lower_name = name.to_ascii_lowercase();
    if matches!(
        lower_name.as_str(),
        "system"
            | "popen"
            | "spawn"
            | "run_command"
            | "run_cmd"
            | "shell"
            | "check_output"
            | "check_call"
            | "getoutput"
            | "getstatusoutput"
            | "pipepager"
            | "tempfilepager"
    ) {
        return Tier::Dangerous;
    }
    if module.split('.').any(|seg| {
        matches!(
            seg,
            "cli" | "commands" | "scripts" | "testing" | "tests" | "benchmark" | "benchmarks"
        )
    }) {
        return Tier::Unknown;
    }
    if LIBRARY_PREFIXES.iter().any(|p| in_module(module, p)) {
        let last = name.rsplit('.').next().unwrap_or(name);
        if LOADER_NAMES.contains(&last)
            || (CODE_CARRYING_CLASSES.contains(&last) && CODE_CARRYING_NAMESPACES.iter().any(|p| in_module(module, p)))
        {
            return Tier::Dangerous;
        }
        return Tier::Library;
    }
    Tier::Unknown
}

/// Operator methods: what `operator.methodcaller("__floordiv__", 3600)` names when a pipeline
/// stores arithmetic on its input.
const OPERATOR_METHODS: &[&str] = &[
    "__add__",
    "__sub__",
    "__mul__",
    "__matmul__",
    "__truediv__",
    "__floordiv__",
    "__mod__",
    "__pow__",
    "__radd__",
    "__rsub__",
    "__rmul__",
    "__rmatmul__",
    "__rtruediv__",
    "__rfloordiv__",
    "__rmod__",
    "__rpow__",
    "__neg__",
    "__pos__",
    "__abs__",
    "__invert__",
    "__and__",
    "__or__",
    "__xor__",
    "__lshift__",
    "__rshift__",
    "__lt__",
    "__le__",
    "__eq__",
    "__ne__",
    "__gt__",
    "__ge__",
    "__len__",
    "__contains__",
    "__getitem__",
];

/// Method names that evaluate text, run something or touch files when called on a value the
/// pipeline receives (`DataFrame.eval`, `DataFrame.query`, `to_pickle`, ...).
const RISKY_METHODS: &[&str] = &[
    "eval",
    "query",
    "exec",
    "system",
    "popen",
    "pipe",
    "apply",
    "applymap",
    "map",
    "agg",
    "aggregate",
    "transform",
    "tofile",
    "dump",
    "dumps",
    "save",
    "savez",
    "write",
    "writelines",
    "read",
    "open",
    "unlink",
    "remove",
    "rmdir",
    "rename",
    "format",
    "format_map",
    "send",
    "connect",
    "call",
];

/// Whether `operator.methodcaller(name)` only names an ordinary method: an operator method, or
/// a public name that is not a loader, an evaluator, a writer or a `to_*` exporter.
pub fn plain_method_name(name: &str) -> bool {
    if name.starts_with('_') {
        return OPERATOR_METHODS.contains(&name);
    }
    !name.is_empty()
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !LOADER_NAMES.contains(&name)
        && !RISKY_METHODS.contains(&name)
        && !name.starts_with("to_")
        && !name.starts_with("read_")
        && !name.starts_with("load")
}

/// Standard-library callables that only rebuild plain values and are allowed to be called.
/// Everything else in the standard library is refused when a pickle calls it (see `call_risk`).
const STDLIB_CALL_OK: &[(&str, &str)] = &[
    ("re", "_compile"),
    ("codecs", "encode"),
    ("codecs", "decode"),
    ("_codecs", "decode"),
    ("copyreg", "__newobj_ex__"),
    ("copyreg", "__reduce_ex__"),
    ("copy_reg", "__newobj__"),
    ("array", "array"),
    ("array", "_array_reconstructor"),
    ("time", "struct_time"),
    ("zoneinfo", "ZoneInfo"),
    ("collections", "ChainMap"),
    ("collections", "UserDict"),
    ("collections", "UserList"),
    ("collections", "UserString"),
    ("collections.abc", "Mapping"),
    ("_collections_abc", "Mapping"),
];

/// Standard-library modules whose classes hold plain data: constructing one has no side effect.
const STDLIB_DATA_MODULES: &[&str] = &[
    "datetime",
    "decimal",
    "fractions",
    "numbers",
    "enum",
    "typing",
    "pathlib",
    "ipaddress",
    "uuid",
    "string",
    "dataclasses",
    "zoneinfo",
];

/// Function-style names that libraries use to rebuild objects from pickled state.
const REBUILD_MARKERS: &[&str] = &[
    "rebuild",
    "reconstruct",
    "unpickle",
    "_new_",
    "newobj",
    "__reduce",
    "_from_state",
    "_restore",
    "_ctor",
];

/// Lower-case names inside library namespaces that are classes, checked in the library sources.
const LOWERCASE_CLASSES: &[(&str, &str)] = &[
    ("scipy.sparse", "csr_matrix"),
    ("scipy.sparse", "csc_matrix"),
    ("scipy.sparse", "coo_matrix"),
    ("scipy.sparse", "bsr_matrix"),
    ("scipy.sparse", "dia_matrix"),
    ("scipy.sparse", "dok_matrix"),
    ("scipy.sparse", "lil_matrix"),
    ("scipy.sparse", "csr_array"),
    ("scipy.sparse", "csc_array"),
    ("scipy.sparse", "coo_array"),
    ("scipy.sparse", "bsr_array"),
    ("scipy.sparse", "dia_array"),
    ("scipy.sparse", "dok_array"),
    ("scipy.sparse", "lil_array"),
    ("sklearn.compose", "make_column_selector"),
    ("torch", "device"),
    ("torch", "dtype"),
    ("torch", "layout"),
    ("torch", "memory_format"),
    ("numpy", "generic"),
    ("numpy", "number"),
    ("numpy", "float16"),
    ("numpy", "float32"),
    ("numpy", "float64"),
    ("numpy", "int8"),
    ("numpy", "int16"),
    ("numpy", "int32"),
    ("numpy", "int64"),
    ("numpy", "uint8"),
    ("numpy", "uint16"),
    ("numpy", "uint32"),
    ("numpy", "uint64"),
    ("numpy", "complex64"),
    ("numpy", "complex128"),
    ("numpy", "str_"),
    ("numpy", "bytes_"),
    ("numpy", "object_"),
    ("numpy", "datetime64"),
    ("numpy", "timedelta64"),
    ("numpy", "longdouble"),
    ("numpy", "matrix"),
    ("numpy", "recarray"),
    ("numpy", "record"),
    ("numpy", "memmap"),
];

/// A name written like a class (`Linear`, `_Real`, `Outer.Inner`), as opposed to a function.
fn class_like(component: &str) -> bool {
    component
        .trim_start_matches('_')
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_uppercase())
}

/// Why calling a global that is neither allowlisted nor denylisted is still refused.
///
/// Ordinary checkpoints rebuild objects: they call classes and a few rebuild helpers. Across the
/// 7,563 Hub files without an attack, no pickle called a method through an attribute path, a
/// standard-library function outside the list above, or a library function that was not a
/// rebuild helper. Published scanner bypasses are almost all one of those three shapes, so the
/// shape is refused instead of listing each function after someone reports it.
pub fn call_risk(module: &str, name: &str) -> Option<&'static str> {
    let module = module.trim();
    let name = name.trim();
    match classify(module, name) {
        Tier::Safe | Tier::Dangerous => return None,
        Tier::Library | Tier::Unknown => {}
    }
    let last = name.rsplit('.').next().unwrap_or(name);
    if name.contains('.') && !name.split('.').all(class_like) {
        return Some("a method reached through an attribute path, which object reconstruction never needs");
    }
    if stdlib::is_stdlib(module) {
        if STDLIB_CALL_OK.iter().any(|(m, n)| *m == module && *n == name) {
            return None;
        }
        let top = module.split('.').next().unwrap_or(module);
        if STDLIB_DATA_MODULES.contains(&top) && class_like(last) {
            return None;
        }
        return Some("a standard-library callable outside the short list that rebuilds plain values");
    }
    if LIBRARY_PREFIXES.iter().any(|p| in_module(module, p)) && !class_like(last) {
        let lower = last.to_ascii_lowercase();
        if REBUILD_MARKERS.iter().any(|m| lower.contains(m))
            || LOWERCASE_CLASSES
                .iter()
                .any(|(m, n)| in_module(module, m) && *n == name)
        {
            return None;
        }
        return Some("a library function that is neither a class nor a rebuild helper");
    }
    None
}

/// How risky it is for a config to name `target` (a dotted path) as the callable to instantiate.
///
/// Configs name loaders and classes all the time, so library loaders are not reported here; what
/// is reported is a target that runs commands or code, or a standard-library callable that
/// builds no model object.
pub fn config_target_risk(target: &str) -> Option<(crate::finding::Severity, &'static str)> {
    use crate::finding::Severity;
    let (module, name) = target.trim().rsplit_once('.')?;
    if matches!(module, "os.path" | "posixpath" | "ntpath") {
        return None;
    }
    let top = module.split('.').next().unwrap_or(module);
    let library = !stdlib::is_stdlib(module) && LIBRARY_PREFIXES.iter().any(|p| in_module(module, p));
    let listed = DANGEROUS_NAMES.iter().any(|(m, n)| *m == module && *n == name)
        || DANGEROUS_MODULES.iter().any(|m| in_module(module, m));
    if listed {
        return Some(if matches!(top, "functools" | "operator") {
            (Severity::Medium, "wraps another callable chosen by the config")
        } else if library {
            (Severity::High, "loads code or remote files")
        } else {
            (
                Severity::Critical,
                "runs commands or code, or reaches files or the network",
            )
        });
    }
    if stdlib::is_stdlib(module) && call_risk(module, name).is_some() {
        return Some((
            Severity::High,
            "is a standard-library callable that builds no model object",
        ));
    }
    None
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

/// How many loader-style function names are refused inside library namespaces.
pub fn loader_name_count() -> usize {
    LOADER_NAMES.len()
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
        assert_eq!(classify("torch.distributed", "init_process_group"), Tier::Dangerous);
        assert_eq!(classify("torch.distributed.rpc", "rpc_sync"), Tier::Dangerous);
        assert_eq!(classify("torch.distributed.tensor", "DTensor"), Tier::Library);
        assert_eq!(classify("torch.distributed.device_mesh", "DeviceMesh"), Tier::Library);
        assert_eq!(classify("torch.utils.collect_env", "run"), Tier::Dangerous);
        assert_eq!(classify("functools", "partial"), Tier::Dangerous);
        assert_eq!(classify("_functools", "partial"), Tier::Dangerous);
        assert_eq!(classify("pydoc", "pipepager"), Tier::Dangerous);
        assert_eq!(classify("pydoc", "locate"), Tier::Dangerous);
        assert_eq!(classify("logging.config", "dictConfig"), Tier::Dangerous);
        assert_eq!(classify("typing", "_eval_type"), Tier::Dangerous);
        assert_eq!(
            classify("transformers.commands.env", "EnvironmentCommand"),
            Tier::Unknown
        );
    }

    /// Callables that load code, a second payload or a remote file must not pass as ordinary
    /// library code just because they live in a trusted namespace.
    #[test]
    fn library_namespaces_do_not_shelter_loaders() {
        for (module, name) in [
            ("transformers.dynamic_module_utils", "get_class_from_dynamic_module"),
            ("transformers.dynamic_module_utils", "get_cached_module_file"),
            ("transformers", "pipeline"),
            ("transformers", "AutoModel.from_pretrained"),
            (
                "transformers.models.auto.auto_factory",
                "_BaseAutoModelClass.from_pretrained",
            ),
            ("diffusers", "DiffusionPipeline.from_pretrained"),
            ("keras.layers", "Lambda"),
            ("keras.src.layers.core.lambda_layer", "Lambda"),
            ("tensorflow.keras.layers", "Lambda"),
            ("tf_keras.layers", "Lambda"),
            ("keras.callbacks", "LambdaCallback"),
            ("keras.models", "model_from_json"),
            ("keras.src.saving.keras_saveable", "KerasSaveable._unpickle_model"),
            ("keras.saving.pickle_utils", "deserialize_model_from_bytecode"),
            ("tensorflow", "py_function"),
            ("tensorflow.saved_model", "load"),
            ("huggingface_hub", "hf_hub_download"),
            ("huggingface_hub.file_download", "hf_hub_download"),
            ("hydra.utils", "instantiate"),
            ("hydra._internal.utils", "_locate"),
            ("fastai.learner", "load_learner"),
            ("ultralytics.nn.tasks", "attempt_load_weights"),
            ("ultralytics.utils.checks", "check_requirements"),
            ("mmcv.utils.config", "Config.fromfile"),
            ("PIL.ImageMath", "eval"),
            ("PIL.Image", "open"),
            ("pandas", "read_csv"),
            ("numpy", "genfromtxt"),
            ("scipy.io", "loadmat"),
            ("nltk.data", "load"),
            ("joblib.externals.loky.backend.popen_loky_posix", "Popen"),
            ("pathlib", "Path.write_text"),
            ("torchvision.datasets.utils", "download_url"),
            ("timm.models._hub", "load_state_dict_from_hf"),
            // The rule is by name, so a loader this catalog has never heard of is caught too.
            ("sklearn.some_future_module", "load"),
            ("torchaudio.future", "download"),
            ("peft.future", "from_pretrained"),
        ] {
            assert_eq!(classify(module, name), Tier::Dangerous, "{module}.{name}");
        }
    }

    /// The same namespaces still classify the classes real checkpoints are made of as
    /// library code, so the tightening does not raise alerts on ordinary models.
    #[test]
    fn model_classes_stay_library_code() {
        for (module, name) in [
            ("fastai.learner", "Learner"),
            ("ultralytics.nn.tasks", "DetectionModel"),
            ("mmcv.utils.config", "ConfigDict"),
            ("gym.envs.registration", "EnvSpec"),
            ("xgboost.callback", "EarlyStopping"),
            ("joblib.memory", "Memory"),
            (
                "transformers.pipelines.text_classification",
                "TextClassificationPipeline",
            ),
            ("transformers.models.bert.modeling_bert", "BertModel"),
            ("keras.src.layers.core.dense", "Dense"),
            ("torchvision.transforms.transforms", "Lambda"),
            ("sentence_transformers.util", "cos_sim"),
            ("scipy.sparse._csr", "csr_matrix"),
            ("sklearn.pipeline", "Pipeline"),
            ("sklearn.compose._column_transformer", "make_column_selector"),
            ("numpy", "float64"),
            ("pathlib", "PosixPath"),
        ] {
            assert_eq!(classify(module, name), Tier::Library, "{module}.{name}");
        }
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
        assert_eq!(classify("argparse", "_os.getcwd"), Tier::Dangerous);
        assert_eq!(classify("shutil", "os.getcwd"), Tier::Dangerous);
        assert_eq!(classify("mypkg", "Outer.Inner"), Tier::Unknown);
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
