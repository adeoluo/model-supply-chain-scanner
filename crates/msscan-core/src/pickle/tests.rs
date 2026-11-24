use super::*;
use crate::finding::ids;

fn run(data: &[u8]) -> PickleReport {
    analyze(data, "t", Limits::default())
}

fn rules(r: &PickleReport) -> Vec<&str> {
    r.findings.iter().map(|f| f.rule.as_str()).collect()
}

fn worst(r: &PickleReport) -> Severity {
    r.max_severity().unwrap_or(Severity::Info)
}

/// Small helpers that emit opcodes.
struct P(Vec<u8>);

impl P {
    fn new(proto: u8) -> Self {
        P(vec![0x80, proto])
    }
    fn raw() -> Self {
        P(Vec::new())
    }
    fn op(mut self, b: &[u8]) -> Self {
        self.0.extend_from_slice(b);
        self
    }
    fn global(self, m: &str, n: &str) -> Self {
        self.op(format!("c{m}\n{n}\n").as_bytes())
    }
    fn s(mut self, v: &str) -> Self {
        self.0.push(0x8c);
        self.0.push(v.len() as u8);
        self.0.extend_from_slice(v.as_bytes());
        self
    }
    fn bytes(mut self, v: &[u8]) -> Self {
        self.0.push(b'B');
        self.0.extend_from_slice(&(v.len() as u32).to_le_bytes());
        self.0.extend_from_slice(v);
        self
    }
    fn int(mut self, v: u8) -> Self {
        self.0.push(b'K');
        self.0.push(v);
        self
    }
    fn stack_global(self, m: &str, n: &str) -> Self {
        self.s(m).s(n).op(&[0x93])
    }
    fn stop(self) -> Vec<u8> {
        let mut v = self.0;
        v.push(b'.');
        v
    }
}

fn getcwd_reduce(proto: u8) -> Vec<u8> {
    P::new(proto).global("os", "getcwd").op(b")R").stop()
}

#[test]
fn reduce_of_dangerous_global_is_critical() {
    let r = run(&getcwd_reduce(2));
    assert!(rules(&r).contains(&ids::PICKLE_DANGEROUS_CALL));
    assert_eq!(worst(&r), Severity::Critical);
    assert_eq!(r.imports.len(), 1);
    assert!(r.imports[0].called);
    assert_eq!(r.pickles, 1);
    assert_eq!(r.max_protocol, 2);
}

#[test]
fn protocol_zero_text_pickle() {
    let data = b"cposix\ngetcwd\n(tR.";
    let r = run(data);
    assert_eq!(worst(&r), Severity::Critical);
    assert!(is_pickle(data));
}

#[test]
fn python2_module_names_are_normalized() {
    let r = run(b"c__builtin__\neval\n(S'print(1)'\ntR.");
    assert_eq!(r.imports[0].module, "builtins");
    assert_eq!(worst(&r), Severity::Critical);
}

#[test]
fn stack_global_through_memo() {
    let data = P::new(4)
        .s("builtins")
        .op(&[0x94])
        .s("exec")
        .op(&[0x94, b'0', b'0', b'h', 0, b'h', 1, 0x93])
        .s("print('x')")
        .op(&[0x85, b'R'])
        .stop();
    let r = run(&data);
    assert_eq!(r.imports[0].name, "exec");
    assert_eq!(worst(&r), Severity::Critical);
}

#[test]
fn dynamic_stack_global_is_flagged() {
    // module name computed by _codecs.encode("bf", "rot13") at load time
    let data = P::new(4)
        .stack_global("_codecs", "encode")
        .s("bf")
        .s("rot13")
        .op(&[0x86, b'R'])
        .s("getcwd")
        .op(&[0x93, b')', b'R'])
        .stop();
    let r = run(&data);
    assert!(rules(&r).contains(&ids::PICKLE_DYNAMIC_IMPORT));
    assert_eq!(worst(&r), Severity::Critical);
}

#[test]
fn inst_obj_newobj_and_newobj_ex_are_calls() {
    let inst = b"(S'print(1)'\nibuiltins\nexec\n.".to_vec();
    let obj = P::raw().op(b"(").global("os", "getcwd").op(b"o").stop();
    let newobj = P::new(2).global("pdb", "Pdb").op(b")").op(&[0x81]).stop();
    let newobj_ex = P::new(4).global("pdb", "Pdb").op(b")}").op(&[0x92]).stop();
    for d in [inst, obj, newobj, newobj_ex] {
        let r = run(&d);
        assert!(rules(&r).contains(&ids::PICKLE_DANGEROUS_CALL), "{:?}", r.findings);
    }
}

#[test]
fn import_without_call_is_high() {
    let data = P::new(2).op(b"}").s("f").global("os", "getcwd").op(b"s").stop();
    let r = run(&data);
    assert!(rules(&r).contains(&ids::PICKLE_DANGEROUS_IMPORT));
    assert_eq!(worst(&r), Severity::High);
}

#[test]
fn dangerous_global_passed_to_call_counts_as_called() {
    // functools.partial(os.getcwd)() : getcwd is only an argument, then the partial is called
    let data = P::new(2)
        .global("functools", "partial")
        .global("os", "getcwd")
        .op(&[0x85, b'R', b')', b'R'])
        .stop();
    let r = run(&data);
    assert!(rules(&r).contains(&ids::PICKLE_INDIRECT_CALL));
    assert!(rules(&r).contains(&ids::PICKLE_DANGEROUS_CALL));
}

#[test]
fn setstate_injection_via_build() {
    // argparse.Namespace() ; BUILD {"__setstate__": builtins.exec} ; BUILD "print(1)"
    let data = P::new(2)
        .global("argparse", "Namespace")
        .op(b")R}")
        .s("__setstate__")
        .global("builtins", "exec")
        .op(b"sb")
        .s("print(1)")
        .op(b"b")
        .stop();
    let r = run(&data);
    assert!(rules(&r).contains(&ids::PICKLE_ATTRIBUTE_INJECTION));
    assert_eq!(worst(&r), Severity::Critical);
}

#[test]
fn build_on_imported_global_is_monkeypatching() {
    let data = P::new(2)
        .global("torch.nn.modules.module", "Module")
        .op(b"N}")
        .s("forward")
        .global("builtins", "print")
        .op(&[b's', 0x86, b'b'])
        .stop();
    let r = run(&data);
    assert!(rules(&r).contains(&ids::PICKLE_ATTRIBUTE_INJECTION));
}

#[test]
fn extension_registry() {
    let data = P::new(2).op(&[0x82, 7, b')', b'R']).stop();
    let r = run(&data);
    assert!(rules(&r).contains(&ids::PICKLE_EXTENSION_REGISTRY));
    assert_eq!(worst(&r), Severity::Critical);
    let r = run(&P::new(2).op(&[0x83, 1, 0]).stop());
    assert_eq!(worst(&r), Severity::High);
}

#[test]
fn unused_extension_lookup_in_a_broken_stream_is_medium() {
    // Raw half-precision weights that happen to start with the EXT4 byte.
    let weights = [0x84, 0xad, 0x39, 0xaf, 0x77, 0xa7, 0x5f, 0xa4];
    let r = run(&weights);
    assert!(rules(&r).contains(&ids::PICKLE_EXTENSION_REGISTRY));
    assert_eq!(worst(&r), Severity::Medium);
    // The same lookup stays critical when it is called before the stream breaks.
    let r = run(&[0x82, 7, b')', b'R', 0xa7]);
    assert_eq!(worst(&r), Severity::Critical);
    // A lookup that follows an earlier call and is never used itself is medium too.
    let mut used_before = getcwd_reduce(2);
    used_before.pop();
    used_before.extend([0x82, 7, 0xa7]);
    let r = run(&used_before);
    let ext = r
        .findings
        .iter()
        .find(|f| f.rule == ids::PICKLE_EXTENSION_REGISTRY)
        .unwrap();
    assert_eq!(ext.severity, Severity::Medium);
}

#[test]
fn nested_pickle_loads_is_scanned() {
    let inner = getcwd_reduce(2);
    let data = P::new(3)
        .global("pickle", "loads")
        .bytes(&inner)
        .op(&[0x85, b'R'])
        .stop();
    let r = run(&data);
    assert!(rules(&r).contains(&ids::PICKLE_NESTED_LOADER));
    let nested: Vec<_> = r
        .findings
        .iter()
        .filter(|f| f.location.contains(">raw-pickle"))
        .collect();
    assert!(!nested.is_empty());
    // The constant is reported once as an embedded payload; the loader call refers to it.
    assert!(rules(&r).contains(&ids::PICKLE_EMBEDDED_PAYLOAD));
    let inner_calls = r.findings.iter().filter(|f| f.message == "calls os.getcwd").count();
    assert_eq!(inner_calls, 1, "{:?}", r.findings);
    assert_eq!(worst(&r), Severity::Critical);
}

#[test]
fn nested_loader_without_constant_payload() {
    let data = P::new(3).global("pickle", "loads").op(b"N").op(&[0x85, b'R']).stop();
    let r = run(&data);
    assert!(
        r.findings
            .iter()
            .any(|f| f.rule == ids::PICKLE_NESTED_LOADER && f.message.contains("not scanned"))
    );
}

#[test]
fn benign_torch_like_pickle_is_clean() {
    // OrderedDict with one tensor rebuilt from a persistent storage id
    let data = P::new(2)
        .global("collections", "OrderedDict")
        .op(b")R")
        .s("w")
        .global("torch._utils", "_rebuild_tensor_v2")
        .op(b"((")
        .s("storage")
        .global("torch", "FloatStorage")
        .s("0")
        .s("cpu")
        .int(4)
        .op(b"tQ")
        .int(0)
        .int(4)
        .op(&[0x85])
        .int(1)
        .op(&[0x85, 0x89])
        .global("collections", "OrderedDict")
        .op(b")R")
        .op(b"tRs")
        .stop();
    let r = run(&data);
    assert!(r.findings.is_empty(), "{:?}", r.findings);
    assert_eq!(r.persistent_ids, 1);
}

#[test]
fn library_and_unknown_calls() {
    let lib = P::new(2).global("torch.nn.modules.linear", "Linear").op(b")R").stop();
    assert_eq!(worst(&run(&lib)), Severity::Low);
    let unk = P::new(2).global("__main__", "Net").op(b")R").stop();
    assert_eq!(worst(&run(&unk)), Severity::Medium);
    let unk_ref = P::new(2).global("mypkg", "Thing").stop();
    assert_eq!(worst(&run(&unk_ref)), Severity::Low);
}

#[test]
fn truncated_and_invalid() {
    let mut d = getcwd_reduce(2);
    d.pop();
    let r = run(&d);
    assert!(rules(&r).contains(&ids::PICKLE_MALFORMED));
    // the call before the error still counts
    assert_eq!(worst(&r), Severity::Critical);
    let r = run(&[0x80, 9, b'N', b'.']);
    assert!(rules(&r).contains(&ids::PICKLE_MALFORMED));
    let r = run(&[0x80, 2, 0xff]);
    assert!(r.findings[0].message.contains("invalid opcode"));
    let r = run(&[0x80, 2, b'R']);
    assert!(r.findings[0].message.contains("underflow"));
    let r = run(&[0x80, 2, b'h', 3]);
    assert!(r.findings[0].message.contains("memo"));
    let r = run(&[0x80, 2, b't']);
    assert!(r.findings[0].message.contains("MARK"));
}

#[test]
fn trailing_bytes_and_second_pickle() {
    let mut d = P::new(2).op(b"N").stop();
    d.extend_from_slice(b"garbage");
    let r = run(&d);
    assert!(rules(&r).contains(&ids::PICKLE_TRAILING));
    assert_eq!(worst(&r), Severity::Low);

    let mut d = P::new(2).op(b"N").stop();
    d.extend(getcwd_reduce(2));
    let r = run(&d);
    assert_eq!(r.pickles, 2);
    assert_eq!(worst(&r), Severity::Critical);

    let mut d = P::new(2).op(b"N").stop();
    d.extend_from_slice(&[0x80, 2, b'K']);
    let r = run(&d);
    assert!(
        r.findings
            .iter()
            .any(|f| f.rule == ids::PICKLE_TRAILING && f.message.contains("after the last complete"))
    );
}

#[test]
fn legacy_torch_reads_five_pickles_and_ignores_storage_bytes() {
    let mut d = P::new(2).op(&[0x8a, 10]).op(&TORCH_MAGIC).stop();
    d.extend(P::new(2).int(1).op(b"").stop());
    d.extend(P::new(2).op(b"}").stop());
    d.extend(getcwd_reduce(2));
    d.extend(P::new(2).op(b"]").stop());
    d.extend_from_slice(&[0xffu8; 64]);
    let r = run(&d);
    assert!(r.legacy_torch);
    assert_eq!(r.pickles, 5);
    assert!(rules(&r).contains(&ids::TORCH_LEGACY));
    assert!(!rules(&r).contains(&ids::PICKLE_TRAILING));
    assert_eq!(worst(&r), Severity::Critical);
}

fn joblib_wrapper(p: P, shape: u8, dtype: &str, align: bool) -> P {
    let mut p = p
        .global("joblib.numpy_pickle", "NumpyArrayWrapper")
        .op(b")")
        .op(&[0x81])
        .op(b"}(")
        .s("subclass")
        .global("numpy", "ndarray")
        .s("shape")
        .int(shape)
        .op(&[0x85])
        .s("order")
        .s("C")
        .s("dtype")
        .global("numpy", "dtype")
        .s(dtype)
        .op(&[0x89, 0x88, 0x87, b'R'])
        .op(b"(")
        .int(3)
        .s("<")
        .op(b"NNN")
        .op(b"J")
        .op(&(-1i32).to_le_bytes())
        .op(b"J")
        .op(&(-1i32).to_le_bytes())
        .int(0)
        .op(b"t")
        .op(b"b")
        .s("allow_mmap")
        .op(&[0x88]);
    if align {
        p = p.s("numpy_array_alignment_bytes").int(16);
    }
    p.op(b"ub")
}

#[test]
fn joblib_array_bytes_are_skipped_and_payload_after_them_found() {
    for align in [false, true] {
        let mut p = joblib_wrapper(P::new(4).op(b"]"), 3, "f8", align);
        if align {
            p = p.op(&[2, 0xff, 0xff]);
        }
        // 3 float64 values whose bytes include opcode-like noise
        p = p.op(&[b'R'; 24]);
        let d = p.op(b"a").global("os", "getcwd").op(b")Ra").stop();
        let r = run(&d);
        assert_eq!(r.joblib_arrays, 1);
        assert_eq!(worst(&r), Severity::Critical, "{:?}", r.findings);
        assert!(!rules(&r).contains(&ids::PICKLE_MALFORMED), "{:?}", r.findings);
    }
}

#[test]
fn joblib_object_array_nested_pickle() {
    let mut p = joblib_wrapper(P::new(4).op(b"]"), 1, "O8", false);
    p = p.op(&getcwd_reduce(2));
    let d = p.op(b"a").stop();
    let r = run(&d);
    assert_eq!(worst(&r), Severity::Critical, "{:?}", r.findings);
    assert_eq!(r.pickles, 1);
}

#[test]
fn joblib_unknown_dtype_is_unscanned_region() {
    let d = joblib_wrapper(P::new(4).op(b"]"), 1, "x", false).op(b"a").stop();
    let r = run(&d);
    assert!(rules(&r).contains(&ids::PICKLE_UNSCANNED_REGION));
}

#[test]
fn text_opcodes_decode() {
    // STRING with escapes and UNICODE with \u escapes feeding STACK_GLOBAL
    let d = b"\x80\x04S'o\\x73'\nV\\u0067etcwd\n\x93)R.";
    let r = run(d);
    assert_eq!(r.imports[0].module, "os");
    assert_eq!(r.imports[0].name, "getcwd");
    assert_eq!(decode_string_literal(b"'a\\n\\t\\101\\\\'").unwrap(), b"a\n\tA\\");
    assert!(decode_string_literal(b"noquote").is_none());
    assert_eq!(decode_raw_unicode_escape(b"\\U0001F600x"), "\u{1F600}x");
}

#[test]
fn integer_and_float_opcodes() {
    let d = b"(I01\nI00\nI42\nI-7\nI123456789012345678901234567890\nL5L\nF1.5\nJ\x01\x00\x00\x00M\x02\x00G\x00\x00\x00\x00\x00\x00\x00\x00\x8a\x01\xff\x8b\x01\x00\x00\x00\x01l.";
    let r = run(d);
    assert!(r.findings.is_empty(), "{:?}", r.findings);
    assert!(run(b"I12x\n.").findings[0].rule == ids::PICKLE_MALFORMED);
    assert!(run(b"Fnan?\n.").findings[0].rule == ids::PICKLE_MALFORMED);
    assert!(run(b"\x80\x02\x8b\xff\xff\xff\xff.").findings[0].rule == ids::PICKLE_MALFORMED);
}

#[test]
fn every_container_opcode() {
    let d = P::new(4)
        .op(b"(K\x01K\x02t")
        .op(b"(K\x01K\x02l")
        .op(b"(K\x01K\x02d")
        .op(&[0x8f, b'(', b'K', 1, 0x90])
        .op(&[b'(', b'K', 1, 0x91])
        .op(b"]K\x01a(K\x02e")
        .op(b"}K\x01K\x02s(K\x03K\x04u")
        .op(&[b'K', 1, b'K', 2, b'K', 3, 0x87, 0x94])
        .op(b"200")
        .op(b"(1")
        .op(b"p7\ng7\nr\x08\x00\x00\x00j\x08\x00\x00\x00q\x09h\x09")
        .op(b"C\x02hiB\x01\x00\x00\x00x")
        .op(&[
            0x8e, 1, 0, 0, 0, 0, 0, 0, 0, b'y', 0x96, 0, 0, 0, 0, 0, 0, 0, 0, 0x97, 0x98,
        ])
        .op(&[0x8d, 1, 0, 0, 0, 0, 0, 0, 0, b'z'])
        .op(b"T\x01\x00\x00\x00aU\x01bX\x01\x00\x00\x00c")
        .op(&[0x95, 0, 0, 0, 0, 0, 0, 0, 0])
        .op(b"Pid\n")
        .op(b"N")
        .stop();
    let r = run(&d);
    assert!(r.findings.is_empty(), "{:?}", r.findings);
    assert_eq!(r.persistent_ids, 1);
    assert!(run(b"(K\x01d.").findings[0].message.contains("odd"));
    assert!(run(b"}(K\x01u.").findings[0].message.contains("odd"));
    assert!(run(b"(o.").findings[0].message.contains("underflow"));
}

#[test]
fn opcode_limit() {
    let limits = Limits {
        max_opcodes: 3,
        ..Limits::default()
    };
    let r = analyze(&P::new(2).op(b"NNNN0000").stop(), "t", limits);
    assert!(r.findings.iter().any(|f| f.rule == ids::PICKLE_RESOURCE));
}

#[test]
fn node_limit_keeps_globals() {
    let limits = Limits {
        max_nodes: 2,
        ..Limits::default()
    };
    let r = analyze(
        &P::new(2).op(b"NNN000").global("os", "getcwd").op(b")R").stop(),
        "t",
        limits,
    );
    assert_eq!(r.max_severity(), Some(Severity::Critical));
}

#[test]
fn is_pickle_detection() {
    assert!(is_pickle(&getcwd_reduce(2)));
    assert!(is_pickle(b"(lp0\n."));
    assert!(!is_pickle(b""));
    assert!(!is_pickle(b"hello world"));
    assert!(!is_pickle(b"(garbage"));
}

mod props {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]
        #[test]
        fn never_panics_on_random_bytes(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            let r = run(&data);
            prop_assert!(r.consumed <= data.len());
        }

        #[test]
        fn never_panics_on_mutated_pickles(idx in 0usize..64, byte in any::<u8>(), cut in 0usize..80) {
            let mut d = joblib_wrapper(P::new(4).op(b"]"), 2, "f4", true).op(&[0, 0, 0, 0, 0, 0, 0, 0, 0]).op(b"a").stop();
            let i = idx % d.len();
            d[i] = byte;
            d.truncate(cut.max(1).min(d.len()));
            let _ = run(&d);
        }

        #[test]
        fn dangerous_reduce_is_always_critical(m in prop::sample::select(vec!["os", "posix", "subprocess", "runpy", "builtins"]),
                                              n in "[a-z]{1,10}") {
            let name = if m == "builtins" { "eval".to_string() } else { n };
            let d = P::new(2).global(m, &name).op(b")R").stop();
            prop_assert_eq!(run(&d).max_severity(), Some(Severity::Critical));
        }
    }
}

/// REDUCE of `module.name` with one string argument, protocol 4 (so dotted names resolve).
fn call(module: &str, name: &str) -> Vec<u8> {
    P::new(4).stack_global(module, name).s("arg").op(&[0x85, b'R']).stop()
}

#[test]
fn calls_that_reconstruction_does_not_need_are_refused() {
    // Published bypass gadgets that are in no denylist here: caught by their shape.
    for (module, name, why) in [
        ("uuid", "_get_command_stdout", "standard-library"),
        ("_aix_support", "_read_cmd_output", "standard-library"),
        ("lib2to3.pgen2.grammar", "Grammar.loads", "attribute path"),
        ("logging", "FileHandler", "standard-library"),
        ("ssl", "get_server_certificate", "standard-library"),
        ("test.support.script_helper", "assert_python_ok", "standard-library"),
        ("builtins", "print", "standard-library"),
        ("torch.jit.unsupported_tensor_ops", "execWrapper", "library function"),
        (
            "torch.utils.data.datapipes.utils.decoder",
            "basichandlers",
            "library function",
        ),
        (
            "torch.utils._config_module",
            "ConfigModule.load_config",
            "attribute path",
        ),
        (
            "torch.fx.experimental.symbolic_shapes",
            "ShapeEnv.evaluate_guards_expression",
            "attribute path",
        ),
        ("some_unknown_pkg.mod", "Helper.run_it", "attribute path"),
    ] {
        let r = run(&call(module, name));
        let f = r
            .findings
            .iter()
            .find(|f| f.rule == ids::PICKLE_NON_CONSTRUCTOR_CALL)
            .unwrap_or_else(|| panic!("{module}.{name}: {:?}", r.findings));
        assert_eq!(f.severity, Severity::High);
        assert!(f.message.contains(why), "{module}.{name}: {}", f.message);
        assert!(worst(&r) >= Severity::High);
    }
    // The same shapes when the global is only referenced are not calls.
    let referenced = P::new(4).stack_global("uuid", "_get_command_stdout").stop();
    assert!(!rules(&run(&referenced)).contains(&ids::PICKLE_NON_CONSTRUCTOR_CALL));
}

#[test]
fn ordinary_reconstruction_calls_are_not_refused() {
    for (module, name) in [
        ("re", "_compile"),
        ("pathlib", "PosixPath"),
        ("datetime", "datetime"),
        ("enum", "IntFlag"),
        ("typing", "Any"),
        ("collections", "ChainMap"),
        ("pandas.core.indexes.base", "_new_Index"),
        ("pandas._libs.internals", "_unpickle_block"),
        ("torch._utils", "_rebuild_wrapper_subclass"),
        ("numpy.ma.core", "_mareconstruct"),
        ("sklearn._loss._loss", "__pyx_unpickle_CyHalfSquaredError"),
        ("sklearn.neighbors._kd_tree", "newObj"),
        ("scipy.sparse._csr", "csr_matrix"),
        ("sklearn.compose._column_transformer", "make_column_selector"),
        ("sklearn.linear_model._logistic", "LogisticRegression"),
        ("torch.nn.modules.container", "Sequential"),
        ("torch.distributions.constraints", "_Real"),
        ("transformers.models.bert.modeling_bert", "BertModel.Config"),
        ("my_project.models", "Net"),
        ("my_project.models", "build_net"),
    ] {
        assert_eq!(policy::call_risk(module, name), None, "{module}.{name}");
        let r = run(&call(module, name));
        assert!(worst(&r) < Severity::High, "{module}.{name}: {:?}", r.findings);
    }
    // Allowlisted and denylisted globals keep their own rules.
    assert_eq!(policy::call_risk("collections", "OrderedDict"), None);
    assert_eq!(policy::call_risk("os", "system"), None);
    assert!(rules(&run(&call("os", "system"))).contains(&ids::PICKLE_DANGEROUS_CALL));
}

#[test]
fn payloads_hidden_in_constants() {
    let inner = P::new(4)
        .stack_global("builtins", "print")
        .s("staged")
        .op(&[0x85, b'R'])
        .stop();
    let b64 = {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for c in inner.chunks(3) {
            let n = (u32::from(c[0]) << 16)
                | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
                | u32::from(*c.get(2).unwrap_or(&0));
            for i in 0..4 {
                if i <= c.len() {
                    out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    };
    let hex: String = inner.iter().map(|b| format!("{b:02x}")).collect();
    // A dict value that is a pickle: raw bytes, base64 text and hex text.
    for (label, constant) in [
        ("raw", P::new(4).op(b"}").s("weights").bytes(&inner).op(b"s").stop()),
        ("base64", P::new(4).op(b"}").s("weights").s(&b64).op(b"s").stop()),
        ("hex", P::new(4).op(b"}").s("weights").s(&hex).op(b"s").stop()),
    ] {
        let r = run(&constant);
        let f = r
            .findings
            .iter()
            .find(|f| f.rule == ids::PICKLE_EMBEDDED_PAYLOAD)
            .unwrap_or_else(|| panic!("{label}: {:?}", r.findings));
        assert!(
            f.severity >= Severity::High && f.message.contains(label),
            "{}",
            f.message
        );
        assert!(f.message.contains("builtins.print"));
        assert!(r.imports.is_empty(), "the outer pickle imports nothing");
    }
    // Two stages: a pickle whose constant is a pickle whose constant is the payload.
    let stage1 = P::new(4).op(b"}").s("stage2").bytes(&inner).op(b"s").stop();
    let outer = P::new(4).op(b"}").s("blob").bytes(&stage1).op(b"s").stop();
    assert!(rules(&run(&outer)).contains(&ids::PICKLE_EMBEDDED_PAYLOAD));
    // A constant that is a harmless pickle (a dict of ints) is not reported.
    let harmless = P::new(4).op(b"}").s("k").int(1).op(b"s").stop();
    let wrap = P::new(4).op(b"}").s("blob").bytes(&harmless).op(b"s").stop();
    assert!(run(&wrap).findings.is_empty(), "{:?}", run(&wrap).findings);
    // Code text, plain and base64 ("os.system('echo ATTACK')").
    for text in ["import os; os.system('echo inert')", "b3Muc3lzdGVtKCdlY2hvIEFUVEFDSycp"] {
        let r = run(&P::new(4).op(b"}").s("note").s(text).op(b"s").stop());
        assert_eq!(rules(&r), vec![ids::EMBEDDED_CODE], "{text}");
        assert_eq!(worst(&r), Severity::High);
    }
    // Ordinary long strings stay quiet.
    let prose = "The quick brown fox jumps over the lazy dog and keeps going for a while.";
    assert!(
        run(&P::new(4).op(b"}").s("doc").s(prose).op(b"s").stop())
            .findings
            .is_empty()
    );
}

#[test]
fn project_specific_dunder_attributes_are_not_injection() {
    let build = |key: &str| {
        P::new(2)
            .global("collections", "OrderedDict")
            .op(b")R}")
            .s(key)
            .int(1)
            .op(b"sb")
            .stop()
    };
    let r = run(&build("__setstate__"));
    assert_eq!(worst(&r), Severity::Critical);
    for key in ["__FILE_RESOURCE_DATA__", "__networkx_cache__"] {
        let r = run(&build(key));
        assert!(rules(&r).contains(&ids::PICKLE_ATTRIBUTE_INJECTION));
        assert_eq!(worst(&r), Severity::Low, "{key}: {:?}", r.findings);
    }
}

#[test]
fn lookups_with_a_known_result_are_resolved() {
    // getattr(Class, "method") is how a method reference pickles: a reference, not a call.
    let reference = P::new(2)
        .global("__builtin__", "getattr")
        .global("ultralytics.nn.modules.head", "Detect")
        .s("forward")
        .op(&[0x86, b'R'])
        .stop();
    let r = run(&reference);
    assert!(worst(&r) < Severity::Medium, "{:?}", r.findings);
    assert!(r.imports.iter().any(|i| i.name == "Detect.forward" && !i.called));
    // Calling the method it returns is still refused, and a dangerous target is still dangerous.
    let called = P::new(2)
        .global("builtins", "getattr")
        .global("ultralytics.nn.modules.head", "Detect")
        .s("forward")
        .op(&[0x86, b'R'])
        .op(b")R")
        .stop();
    assert!(rules(&run(&called)).contains(&ids::PICKLE_NON_CONSTRUCTOR_CALL));
    let to_os = P::new(2)
        .global("builtins", "getattr")
        .global("os", "path")
        .s("os")
        .op(&[0x86, b'R'])
        .stop();
    assert!(worst(&run(&to_os)) >= Severity::High);
    // A computed attribute name, or a target that is not a plain global, is not resolved.
    let computed = P::new(2)
        .global("builtins", "getattr")
        .global("collections", "OrderedDict")
        .global("builtins", "str")
        .op(b")R")
        .op(&[0x86, b'R'])
        .stop();
    assert_eq!(worst(&run(&computed)), Severity::Critical);
    // dill names builtin types through _load_type; only plain containers are resolved.
    let dill_set = P::new(2)
        .global("dill._dill", "_load_type")
        .s("set")
        .op(&[0x85, b'R'])
        .op(b")R")
        .stop();
    let r = run(&dill_set);
    assert!(r.findings.is_empty(), "{:?}", r.findings);
    let dill_code = P::new(2)
        .global("dill._dill", "_load_type")
        .s("CodeType")
        .op(&[0x85, b'R'])
        .stop();
    assert_eq!(worst(&run(&dill_code)), Severity::Critical);
}

#[test]
fn partial_around_a_library_function_is_a_deferred_call() {
    // FunctionTransformer(func=partial(check_array, ...)): nothing runs on load.
    let data = P::new(2)
        .global("functools", "partial")
        .global("sklearn.utils.validation", "check_array")
        .op(&[0x85, b'R'])
        .stop();
    let r = run(&data);
    assert_eq!(rules(&r), vec![ids::PICKLE_DEFERRED_CALL]);
    assert_eq!(worst(&r), Severity::Medium);
    // Both globals are reported as called (the helper is, and the function is passed to it);
    // neither runs while the file loads.
    assert!(r.imports.iter().all(|i| i.called && !i.runs_on_load));

    // The same helper around a command runner keeps its rating.
    let data = P::new(2)
        .global("functools", "partial")
        .global("os", "system")
        .op(&[0x85, b'R'])
        .stop();
    assert_eq!(worst(&run(&data)), Severity::Critical);

    // Calling what partial returned is a call of the wrapped function at load time.
    let data = P::new(2)
        .global("functools", "partial")
        .global("sklearn.utils.validation", "check_array")
        .op(&[0x85, b'R', b')', b'R'])
        .stop();
    let r = run(&data);
    assert_eq!(worst(&r), Severity::Critical);
    assert!(rules(&r).contains(&ids::PICKLE_INDIRECT_CALL));
    assert!(rules(&r).contains(&ids::PICKLE_NON_CONSTRUCTOR_CALL));

    // dill names partial through _load_type("PartialType").
    let data = P::new(2)
        .global("dill._dill", "_load_type")
        .s("PartialType")
        .op(&[0x85, b'R'])
        .global("sklearn.utils.validation", "check_array")
        .op(&[0x85, b'R'])
        .stop();
    let r = run(&data);
    assert_eq!(rules(&r), vec![ids::PICKLE_DEFERRED_CALL]);
}

#[test]
fn methodcaller_is_graded_by_the_method_it_names() {
    let caller = |method: &str| {
        P::new(2)
            .global("operator", "methodcaller")
            .s(method)
            .op(&[0x85, b'R'])
            .stop()
    };
    for plain in ["__floordiv__", "fillna", "strip", "astype"] {
        let r = run(&caller(plain));
        assert_eq!(rules(&r), vec![ids::PICKLE_DEFERRED_CALL], "{plain}");
    }
    for risky in [
        "system",
        "eval",
        "query",
        "__reduce__",
        "to_pickle",
        "load",
        "_private",
        "__class__",
    ] {
        assert_eq!(worst(&run(&caller(risky))), Severity::Critical, "{risky}");
    }
}
