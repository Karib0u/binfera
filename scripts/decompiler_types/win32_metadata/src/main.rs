//! Development-only: dump the declarations of Microsoft's Win32 metadata (`Windows.Win32.winmd`)
//! as a line-based, architecture-neutral text that `pack_win32_metadata.py` turns into prototype
//! pack entries. Nothing here runs at build time or at analysis time.
//!
//! usage: win32-metadata-dump Windows.Win32.winmd OUTPUT.tsv
//!
//! Records (tab separated; types use the grammar documented below):
//!   FN  name  dll  conv  arches  flags  ret  [param...]       param = name|type|assoc-enum|dir
//!   TD  fullname  arches  kind  ...                             see `dump_type`
//!   CN  name  type  value                                       a constant whose type is a named
//!                                                               type (`HKEY_LOCAL_MACHINE`, `n:...HKEY`)
//!
//! Type grammar: `void bool char16 i8 u8 i16 u16 i32 u32 i64 u64 f32 f64 isize usize`,
//! `p:T` (pointer), `a<N>:T` (fixed array), `n:Namespace.Name` (named type), `s` (string, unused).
use std::collections::BTreeMap;
use std::fmt::Write as _;
use windows_metadata::reader::{Index, TypeCategory};
use windows_metadata::{HasAttributes, Type, TypeAttributes, Value};

fn arches_of<'a, R: HasAttributes<'a>>(row: &R) -> i32 {
    let a = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| row.arches())).unwrap_or(0);
    if a == 0 {
        7
    } else {
        a
    }
}

fn type_name(ty: &Type, owner: &str) -> String {
    match ty {
        Type::Void => "void".into(),
        Type::Bool => "bool".into(),
        Type::Char => "char16".into(),
        Type::I8 => "i8".into(),
        Type::U8 => "u8".into(),
        Type::I16 => "i16".into(),
        Type::U16 => "u16".into(),
        Type::I32 => "i32".into(),
        Type::U32 => "u32".into(),
        Type::I64 => "i64".into(),
        Type::U64 => "u64".into(),
        Type::F32 => "f32".into(),
        Type::F64 => "f64".into(),
        Type::ISize => "isize".into(),
        Type::USize => "usize".into(),
        Type::String => "p:char16".into(),
        Type::Object => "p:void".into(),
        Type::ClassName(tn) | Type::ValueName(tn) => {
            if tn.namespace.is_empty() {
                // A nested type, named relative to the type that contains it.
                format!("n:{owner}/{}", tn.name)
            } else {
                format!("n:{}.{}", tn.namespace, tn.name)
            }
        }
        Type::Array(t) => format!("p:{}", type_name(t, owner)),
        Type::RefMut(t) | Type::RefConst(t) => format!("p:{}", type_name(t, owner)),
        Type::PtrMut(t, depth) | Type::PtrConst(t, depth) => {
            let mut s = type_name(t, owner);
            for _ in 0..(*depth).max(1) {
                s = format!("p:{s}");
            }
            s
        }
        Type::ArrayFixed(t, n) => format!("a{n}:{}", type_name(t, owner)),
        Type::Generic(..) => "p:void".into(),
    }
}

fn attr_strings(attr: &windows_metadata::reader::Attribute) -> Vec<String> {
    // The reader panics on a few exotic attribute encodings; none of those carry what is dumped.
    let Ok(values) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| attr.value())) else {
        return Vec::new();
    };
    values
        .into_iter()
        .map(|(_, v)| match v {
            Value::Utf8(s) | Value::Utf16(s) => s,
            Value::I32(i) => i.to_string(),
            Value::U32(i) => i.to_string(),
            Value::I16(i) => i.to_string(),
            Value::U16(i) => i.to_string(),
            Value::I64(i) => i.to_string(),
            Value::U64(i) => i.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::EnumValue(_, inner) => match *inner {
                Value::I32(i) => i.to_string(),
                Value::U32(i) => i.to_string(),
                other => format!("{other:?}"),
            },
            Value::TypeName(tn) => format!("{}.{}", tn.namespace, tn.name),
            other => format!("{other:?}"),
        })
        .collect()
}

fn const_value(v: &Value) -> String {
    match v {
        Value::I8(i) => i.to_string(),
        Value::U8(i) => i.to_string(),
        Value::I16(i) => i.to_string(),
        Value::U16(i) => i.to_string(),
        Value::I32(i) => i.to_string(),
        Value::U32(i) => i.to_string(),
        Value::I64(i) => i.to_string(),
        Value::U64(i) => i.to_string(),
        Value::USize(i) => i.to_string(),
        Value::ISize(i) => i.to_string(),
        Value::Bool(b) => (*b as u8).to_string(),
        _ => "0".into(),
    }
}

/// The reader panics on a function-pointer signature element; such a field is a bare pointer.
fn safe_field_type(f: &windows_metadata::reader::Field) -> Type {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f.ty())).unwrap_or(Type::PtrMut(Box::new(Type::Void), 1))
}

fn clean(s: &str) -> String {
    s.replace(['\t', '\n', '\r'], " ")
}

fn dump_type(
    out: &mut String,
    index: &Index,
    ty: windows_metadata::reader::TypeDef,
    full: &str,
    arches: i32,
) {
    let flags = ty.flags();
    match ty.category() {
        TypeCategory::Enum => {
            let underlying = ty.underlying_type().map(|t| type_name(&t, full)).unwrap_or("i32".into());
            let is_flags = ty.has_attribute("FlagsAttribute");
            let _ = write!(out, "TD\t{full}\t{arches}\tenum\t{underlying}\t{}", is_flags as u8);
            for f in ty.fields() {
                if let Some(c) = f.constant() {
                    let _ = write!(out, "\t{}={}", f.name(), const_value(&c.value()));
                }
            }
            out.push('\n');
        }
        TypeCategory::Struct => {
            let explicit = flags.contains(TypeAttributes::ExplicitLayout);
            let (pack, size) = ty
                .class_layout()
                .map(|l| (l.packing_size(), l.class_size()))
                .unwrap_or((0, 0));
            let typedef = ty.find_attribute("NativeTypedefAttribute").is_some();
            let handle = ty.has_attribute("RAIIFreeAttribute") || ty.has_attribute("InvalidHandleValueAttribute");
            let _ = write!(
                out,
                "TD\t{full}\t{arches}\t{}\t{}\t{pack}\t{size}\t{}",
                if typedef { "typedef" } else { "struct" },
                explicit as u8,
                handle as u8
            );
            for f in ty.fields() {
                if f.flags().contains(windows_metadata::FieldAttributes::Static) {
                    continue;
                }
                let mut bits = String::new();
                if let Some(a) = f.find_attribute("NativeBitfieldAttribute") {
                    let v = attr_strings(&a);
                    bits = format!("{}:{}:{}", v.first().cloned().unwrap_or_default(), v.get(1).cloned().unwrap_or_default(), v.get(2).cloned().unwrap_or_default());
                }
                let _ = write!(out, "\t{}|{}|{}", f.name(), type_name(&safe_field_type(&f), full), bits);
            }
            out.push('\n');
        }
        TypeCategory::Delegate => {
            let invoke = ty.methods().find(|m| m.name() == "Invoke");
            let Some(m) = invoke else { return };
            let sig = m.signature(&[]);
            let conv = if ty
                .find_attribute("UnmanagedFunctionPointerAttribute")
                .map(|a| attr_strings(&a).first().map(|s| s.as_str() == "2").unwrap_or(false))
                .unwrap_or(false)
            {
                "cdecl"
            } else {
                "stdcall"
            };
            let _ = write!(out, "TD\t{full}\t{arches}\tdelegate\t{conv}\t{}", type_name(&sig.return_type, full));
            let params = m.params_by_sequence(sig.types.len()).ok();
            for (i, t) in sig.types.iter().enumerate() {
                let name = params
                    .as_ref()
                    .and_then(|p| p.params().get(i).cloned().flatten())
                    .map(|p| p.name().to_string())
                    .unwrap_or_else(|| format!("param_{}", i + 1));
                let _ = write!(out, "\t{name}|{}", type_name(t, full));
            }
            out.push('\n');
        }
        TypeCategory::Interface => {
            let _ = write!(out, "TD\t{full}\t{arches}\tinterface\n");
        }
        _ => {}
    }
    for inner in index.nested(ty) {
        let inner_full = format!("{full}/{}", inner.name());
        dump_type(out, index, inner, &inner_full, arches_of(&inner));
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: win32-metadata-dump Windows.Win32.winmd OUTPUT.tsv");
        std::process::exit(2);
    }
    
    
    std::panic::set_hook(Box::new(|_| {}));
    let index = Index::read(&args[1]).expect("cannot read the winmd file");
    let mut types: BTreeMap<String, String> = BTreeMap::new();
    let mut functions: BTreeMap<String, String> = BTreeMap::new();
    let mut constants: BTreeMap<String, String> = BTreeMap::new();
    let mut const_count = 0usize;
    for (ns, name, item) in index.iter_items() {
        use windows_metadata::reader::Item;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        match item {
            Item::Fn(m) => {
                let sig = m.signature(&[]);
                let Some(map) = m.impl_map() else { return };
                let dll = map.import_scope().name().to_string();
                let cc = m.calling_convention();
                let conv = if cc == "C" { "cdecl" } else { "stdcall" };
                let variadic = sig.flags.contains(windows_metadata::MethodCallAttributes::VARARG);
                let noreturn = m.has_attribute("DoesNotReturnAttribute");
                let arches = arches_of(&m);
                let mut line = format!(
                    "FN\t{name}\t{dll}\t{conv}\t{arches}\t{}{}\t{}\t{ns}",
                    variadic as u8,
                    noreturn as u8,
                    type_name(&sig.return_type, ns)
                );
                let params = m.params_by_sequence(sig.types.len()).ok();
                for (i, t) in sig.types.iter().enumerate() {
                    let p = params.as_ref().and_then(|p| p.params().get(i).cloned().flatten());
                    let (pname, assoc) = match &p {
                        Some(p) => (
                            clean(p.name()),
                            p.find_attribute("AssociatedEnumAttribute")
                                .map(|a| attr_strings(&a).join(","))
                                .unwrap_or_default(),
                        ),
                        None => (format!("param_{}", i + 1), String::new()),
                    };
                    let _ = write!(line, "\t{pname}|{}|{assoc}", type_name(t, ns));
                }
                functions.insert(format!("{name}\t{dll}\t{arches}"), line);
            }
            Item::Type(t) => {
                let full = format!("{ns}.{name}");
                let mut s = String::new();
                dump_type(&mut s, &index, t, &full, arches_of(&t));
                if !s.is_empty() {
                    types.entry(format!("{full}\t{}", arches_of(&t))).or_default().push_str(&s);
                }
            }
            Item::Const(f) => {
                const_count += 1;
                // Only constants of a named type (handles such as HKEY): untyped `#define` values
                // belong to no parameter.
                let ty = type_name(&safe_field_type(&f), ns);
                if let (true, Some(c)) = (ty.starts_with("n:"), f.constant()) {
                    constants.insert(format!("{ty}\t{name}"), format!("CN\t{name}\t{ty}\t{}", const_value(&c.value())));
                }
            }
        }
        }));
        if result.is_err() {
            eprintln!("unreadable item {ns}.{name}");
        }
    }
    let mut out = String::new();
    for line in functions.values() {
        out.push_str(line);
        out.push('\n');
    }
    for text in types.values() {
        out.push_str(text);
    }
    for line in constants.values() {
        out.push_str(line);
        out.push('\n');
    }
    std::fs::write(&args[2], out).expect("cannot write the output");
    eprintln!("functions={} types={} constants={}", functions.len(), types.len(), const_count);
}
