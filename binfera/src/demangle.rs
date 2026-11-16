//! Rust and C++ symbol names: Microsoft (`?add@Counter@@QAEHH@Z`) and Itanium (`_ZN7Counter3addEi`)
//! decorations, demangled into the labels Ghidra shows (`Counter::add`).
//!
//! Ghidra demangles Microsoft names with its own port of `undname` (`MDMang`) and Itanium names by
//! running GNU binutils; here the `msvc-demangler` crate (a port of LLVM's Microsoft demangler) and
//! the `cpp_demangle` crate do the parsing. A label is the qualified name without parameters, with
//! Ghidra's spelling: spaces become `_` (`operator_new`), template arguments drop `class` and
//! `struct` and their spaces (`std::vector<int,std::allocator<int>>`), and the compiler's special
//! names lose their quotes (`Class::vftable`, `` Class::`scalar_deleting_destructor' `` becomes
//! `Class::scalar_deleting_destructor`).
//!
//! A Microsoft name also encodes the prototype: calling convention, `this`, return and parameter
//! types. [`Prototype`] carries it when every type is a scalar or a pointer, so the decompiler can
//! type a C++ import or export as Ghidra does. Itanium names give neither the return type nor
//! whether a member function is static. Unqualified free functions can supply parameter types
//! without guessing their return type.
//!
//! Rust's legacy and v0 names use `rustc-demangle`, without their hash/disambiguator suffixes.
//! They carry no prototype. Legacy names must have a Rust hash to avoid taking C++ data symbols.

use msvc_demangler::{CallingConv, DemangleFlags, FuncClass, Params, Type as MsType};

mod nim;

/// A demangled symbol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Demangled {
    /// The qualified label: `std::_Lockit::_Lockit`, `net::Box<int>::vftable`.
    pub name: String,
    /// The prototype a Microsoft function name encodes, when it can be expressed.
    pub prototype: Option<Prototype>,
}

/// A calling convention a Microsoft name encodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Convention {
    Cdecl,
    Stdcall,
    Fastcall,
    Thiscall,
}
impl Convention {
    /// The compiler specification's model of that name.
    pub fn model(self) -> &'static str {
        match self {
            Convention::Cdecl => "__cdecl",
            Convention::Stdcall => "__stdcall",
            Convention::Fastcall => "__fastcall",
            Convention::Thiscall => "__thiscall",
        }
    }
}

/// A parameter or return type, as far as the decompiler's signatures can express it. Anything else
/// (a structure passed by value, a member pointer) leaves the prototype out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scalar {
    Void,
    Bool,
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
    F32,
    F64,
    Pointer,
    CharPointer,
    WideCharPointer,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prototype {
    pub convention: Convention,
    /// The class of a non-static member function; `this` comes first.
    pub this_class: Option<String>,
    pub result: Scalar,
    pub parameters: Vec<Scalar>,
    pub varargs: bool,
}

/// Demangle Rust, Microsoft, Itanium or Nim initializer names. `None` for plain or malformed names.
pub fn demangle(symbol: &str) -> Option<Demangled> {
    // Bounded: a decorated name past this length is not worth parsing. The Itanium parser limits
    // its own recursion; the Microsoft one is bounded more tightly below.
    if symbol.len() > 2048 {
        return None;
    }
    if symbol.starts_with('?') {
        return microsoft(symbol);
    }
    if let Some(name) = nim::demangle(symbol) {
        return Some(Demangled {
            name,
            prototype: None,
        });
    }
    if let Some(name) = rust(symbol) {
        return Some(Demangled {
            name,
            prototype: None,
        });
    }
    // Mach-O adds an underscore; i386 ELF names may carry a versioned suffix (`@GLIBCXX_3.4`).
    let symbol = symbol
        .strip_prefix('_')
        .filter(|s| s.starts_with("_Z"))
        .unwrap_or(symbol);
    let symbol = symbol.split('@').next().unwrap_or(symbol);
    if symbol.starts_with("_Z") && !rust_legacy(symbol) {
        return itanium(symbol).map(|name| Demangled {
            name,
            prototype: None,
        });
    }
    None
}

/// Rust names, without crate disambiguators or legacy hashes. Requiring the legacy hash keeps
/// valid Itanium data symbols such as `_ZN3foo3barE` with the C++ parser.
pub fn rust(symbol: &str) -> Option<String> {
    use std::fmt::Write;
    if symbol.len() > 2048 {
        return None;
    }
    let symbol = symbol.split('@').next().unwrap_or(symbol);
    let base = symbol.trim_start_matches('_');
    if !(base.starts_with('R') || base.starts_with("ZN") && rust_legacy(symbol)) {
        return None;
    }
    let parsed = rustc_demangle::try_demangle(symbol).ok()?;
    // v0 backreferences can expand a short input many times. Stop formatting at our own limit.
    struct Bounded(String);
    impl std::fmt::Write for Bounded {
        fn write_str(&mut self, value: &str) -> std::fmt::Result {
            if self.0.len() + value.len() > 4096 {
                return Err(std::fmt::Error);
            }
            self.0.push_str(value);
            Ok(())
        }
    }
    let mut out = Bounded(String::new());
    write!(&mut out, "{parsed:#}").ok()?;
    // Formatting can diagnose invalid backreferences after the initial parse succeeded.
    if out.0.contains("{invalid syntax}") || out.0.contains("{recursion limit reached}") {
        return None;
    }
    Some(out.0)
}

/// Rust's legacy mangling borrows the Itanium form and ends with a hash component.
fn rust_legacy(symbol: &str) -> bool {
    let symbol = symbol.split(".llvm.").next().unwrap_or(symbol);
    symbol
        .strip_suffix('E')
        .and_then(|rest| rest.get(rest.len().checked_sub(19)?..))
        .and_then(|tail| tail.strip_prefix("17h"))
        .is_some_and(|hash| hash.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// The class a Microsoft RTTI type descriptor names: `.?AVTcpChannel@net@@` is `net::TcpChannel`.
pub fn type_descriptor_class(name: &str) -> Option<String> {
    let rest = name
        .strip_prefix(".?AV")
        .or_else(|| name.strip_prefix(".?AU"))?;
    // The type name is the name of a virtual function table without its decoration.
    let table = microsoft(&format!("??_7{rest}6B@"))?;
    table.name.strip_suffix("::vftable").map(str::to_owned)
}

/// The class a member belongs to: the label without its last component, if it has one.
pub fn scope_of(label: &str) -> Option<&str> {
    split_last(label).map(|(scope, _)| scope)
}

/// The last component of a label (`send` in `net::TcpChannel::send`).
pub fn member_of(label: &str) -> &str {
    split_last(label).map_or(label, |(_, member)| member)
}

fn split_last(label: &str) -> Option<(&str, &str)> {
    let bytes = label.as_bytes();
    let mut depth = 0i32;
    let mut split = None;
    let mut i = 0;
    while i + 1 < bytes.len() {
        match bytes[i] {
            b'<' => depth += 1,
            b'>' => depth = (depth - 1).max(0),
            b':' if depth == 0 && bytes[i + 1] == b':' => {
                split = Some(i);
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    split.map(|at| (&label[..at], &label[at + 2..]))
}

/// The Microsoft parser recurses once per nested type with no limit of its own: 800 characters of
/// nested pointers overflow a 256 KB stack. Real names, which compress repeats into back
/// references, stay well under this bound; a longer one in a sample is left as it is.
const MAX_MICROSOFT: usize = 1024;

fn microsoft(symbol: &str) -> Option<Demangled> {
    if symbol.len() > MAX_MICROSOFT {
        return None;
    }
    let parsed = msvc_demangler::parse(symbol).ok()?;
    let flags = DemangleFlags::NAME_ONLY | DemangleFlags::NO_CLASS_TYPE;
    let text = msvc_demangler::serialize(&parsed, flags);
    let mut name = label(&text)?;
    // A table for a base subobject names that base: `vftable'{for `Logger'}`.
    if let MsType::CXXVFTable(bases, _) | MsType::CXXVBTable(bases, _) = &parsed.symbol_type {
        if !bases.names.is_empty() {
            let full = msvc_demangler::serialize(&parsed, DemangleFlags::NO_CLASS_TYPE);
            let base = full.split_once("{for `")?.1.rsplit_once("'}")?.0;
            name = format!("{name}_for_{}", member_of(&label(base)?));
        }
    }
    let prototype = match &parsed.symbol_type {
        MsType::MemberFunction(class, convention, params, _, result) => {
            let this_class = if class.contains(FuncClass::STATIC) {
                None
            } else {
                Some(scope_of(&name)?.to_owned())
            };
            prototype(*convention, this_class, params, result)
        }
        MsType::NonMemberFunction(convention, params, _, result) => {
            prototype(*convention, None, params, result)
        }
        _ => None,
    };
    Some(Demangled { name, prototype })
}

fn prototype(
    convention: CallingConv,
    this_class: Option<String>,
    params: &Params<'_>,
    result: &MsType<'_>,
) -> Option<Prototype> {
    let convention = match convention {
        CallingConv::Cdecl => Convention::Cdecl,
        CallingConv::Stdcall => Convention::Stdcall,
        CallingConv::Fastcall => Convention::Fastcall,
        CallingConv::Thiscall => Convention::Thiscall,
        CallingConv::Pascal | CallingConv::_Regcall => return None,
    };
    // A constructor or destructor has no return type in the name; it returns nothing useful.
    let result = match result {
        MsType::None => Scalar::Void,
        other => scalar(other)?,
    };
    let mut parameters = Vec::new();
    let mut varargs = false;
    for (index, parameter) in params.types.iter().enumerate() {
        match parameter {
            MsType::VarArgs => varargs = true,
            // `(void)` is how a name spells no parameters.
            MsType::Void(_) if index == 0 && params.types.len() == 1 => {}
            other => parameters.push(scalar(other)?),
        }
    }
    // A member function's `this` comes first whatever its convention; a variadic one is cdecl.
    let convention = if this_class.is_some() && !varargs {
        Convention::Thiscall
    } else {
        convention
    };
    Some(Prototype {
        convention,
        this_class,
        result,
        parameters,
        varargs,
    })
}

fn scalar(value: &MsType<'_>) -> Option<Scalar> {
    Some(match value {
        MsType::Void(_) => Scalar::Void,
        MsType::Bool(_) => Scalar::Bool,
        MsType::Char(_) | MsType::Schar(_) => Scalar::I8,
        MsType::Uchar(_) | MsType::Char8(_) => Scalar::U8,
        MsType::Short(_) => Scalar::I16,
        MsType::Ushort(_) | MsType::Wchar(_) | MsType::Char16(_) => Scalar::U16,
        // `long` is four bytes on Windows; an enumeration is an `int`.
        MsType::Int(_) | MsType::Long(_) | MsType::Enum(..) => Scalar::I32,
        MsType::Uint(_) | MsType::Ulong(_) | MsType::Char32(_) => Scalar::U32,
        MsType::Int64(_) => Scalar::I64,
        MsType::Uint64(_) => Scalar::U64,
        MsType::Float(_) => Scalar::F32,
        MsType::Double(_) | MsType::Ldouble(_) => Scalar::F64,
        MsType::Ptr(target, _) => match target.as_ref() {
            MsType::Char(_) | MsType::Schar(_) | MsType::Uchar(_) => Scalar::CharPointer,
            MsType::Wchar(_) | MsType::Char16(_) => Scalar::WideCharPointer,
            _ => Scalar::Pointer,
        },
        // A reference is passed as a pointer; so is an array parameter.
        MsType::Ref(..) | MsType::RValueRef(..) | MsType::Array(..) | MsType::Nullptr => {
            Scalar::Pointer
        }
        _ => return None,
    })
}

fn itanium(symbol: &str) -> Option<String> {
    let parsed = cpp_demangle::Symbol::new(symbol).ok()?;
    let options = cpp_demangle::DemangleOptions::new()
        .no_params()
        .no_return_type();
    let text = parsed.demangle_with_options(&options).ok()?;
    // Special names print as `{vtable(X)}`; give them Ghidra's labels.
    if let Some(inner) = text.strip_prefix('{').and_then(|t| t.strip_suffix('}')) {
        let (kind, rest) = inner.split_once('(')?;
        let rest = rest.strip_suffix(')')?;
        let special = match kind {
            "vtable" => format!("{rest}::vtable"),
            "typeinfo" => format!("{rest}::typeinfo"),
            "typeinfo name" => format!("{rest}::typeinfo_name"),
            "virtual table table" => format!("{rest}::VTT"),
            "construction vtable" => format!("{}::construction_vtable", rest.rsplit(", ").next()?),
            // `{virtual override thunk({offset(-16)}, X::f)}`: the thunk adjusts `this` for X::f.
            _ if kind.contains("thunk") => format!("{}_thunk", rest.rsplit(", ").next()?),
            _ => return None,
        };
        return label(&special);
    }
    // A compiler clone (`f [clone .cold]`) keeps its suffix as part of the name.
    let text = match text.split_once(" [clone ") {
        Some((name, clone)) => format!("{name}{}", clone.trim_end_matches(']').replace('.', "_")),
        None => text,
    };
    label(&text)
}

/// Ghidra's spelling of a demangled name: no spaces inside template arguments, other spaces as
/// `_`, quotes of the compiler's special names dropped.
fn label(text: &str) -> Option<String> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(text.len());
    let chars: Vec<char> = text.chars().collect();
    for (index, &ch) in chars.iter().enumerate() {
        match ch {
            '`' | '\'' => {}
            ' ' => {
                let previous = out.chars().last();
                let next = chars.get(index + 1).copied();
                // `a, b` and `> >` lose the space; `operator new` and `unsigned int` keep a `_`.
                if matches!(previous, Some(',' | '<' | '>' | '*' | '&' | '(' | ':'))
                    || matches!(next, Some(',' | '>' | '*' | '&' | ')' | ':' | '<'))
                {
                    continue;
                }
                out.push('_');
            }
            _ => out.push(ch),
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(symbol: &str) -> Option<String> {
        demangle(symbol).map(|d| d.name)
    }

    #[test]
    fn microsoft_names_take_ghidra_labels() {
        assert_eq!(
            name("?add@Counter@@QAEHH@Z").as_deref(),
            Some("Counter::add")
        );
        assert_eq!(
            name("??0_Lockit@std@@QAE@H@Z").as_deref(),
            Some("std::_Lockit::_Lockit")
        );
        assert_eq!(
            name("??1_Lockit@std@@QAE@XZ").as_deref(),
            Some("std::_Lockit::~_Lockit")
        );
        assert_eq!(name("??2@YAPAXI@Z").as_deref(), Some("operator_new"));
        assert_eq!(name("??_U@YAPAXI@Z").as_deref(), Some("operator_new[]"));
        assert_eq!(name("??8@YA_NABU_GUID@@0@Z").as_deref(), Some("operator=="));
        assert_eq!(
            name("?append@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEAAV12@PBDI@Z")
                .as_deref(),
            Some("std::basic_string<char,std::char_traits<char>,std::allocator<char>>::append")
        );
        assert_eq!(
            name("??_7?$Box@H@net@@6B@").as_deref(),
            Some("net::Box<int>::vftable")
        );
        assert_eq!(
            name("??_7LoggingChannel@net@@6BLogger@1@@").as_deref(),
            Some("net::LoggingChannel::vftable_for_Logger")
        );
        assert_eq!(
            name("??_GChannel@net@@UAEPAXI@Z").as_deref(),
            Some("net::Channel::scalar_deleting_destructor")
        );
        assert_eq!(name("GetTickCount"), None);
        // Nested past the bound: refused rather than parsed (the parser would exhaust the stack).
        assert_eq!(name(&format!("?f@@YAX{}H@Z", "PA".repeat(600))), None);
        assert_eq!(name("?"), None);
    }

    #[test]
    fn microsoft_prototypes() {
        let constructor = demangle("??0_Lockit@std@@QAE@H@Z").and_then(|d| d.prototype);
        assert_eq!(
            constructor,
            Some(Prototype {
                convention: Convention::Thiscall,
                this_class: Some("std::_Lockit".into()),
                result: Scalar::Void,
                parameters: vec![Scalar::I32],
                varargs: false,
            })
        );
        let free = demangle("?_Xlength_error@std@@YAXPBD@Z").and_then(|d| d.prototype);
        assert_eq!(
            free,
            Some(Prototype {
                convention: Convention::Cdecl,
                this_class: None,
                result: Scalar::Void,
                parameters: vec![Scalar::CharPointer],
                varargs: false,
            })
        );
        // x64 member functions are spelled `__cdecl`; `this` still comes first.
        let wide = demangle("?add@Counter@@QEAAHH@Z").and_then(|d| d.prototype);
        assert_eq!(wide.map(|p| p.convention), Some(Convention::Thiscall));
        let static_member = demangle("?instance@Counter@@SAPAV1@XZ").and_then(|d| d.prototype);
        assert_eq!(
            static_member.map(|p| (p.this_class, p.parameters, p.result)),
            Some((None, vec![], Scalar::Pointer))
        );
        // A structure returned by value is not expressible.
        assert_eq!(
            demangle("?f@@YA?AU_GUID@@XZ").and_then(|d| d.prototype),
            None
        );
    }

    #[test]
    fn itanium_names_take_ghidra_labels() {
        assert_eq!(
            name("_ZN3net10TcpChannel4sendEPKci").as_deref(),
            Some("net::TcpChannel::send")
        );
        assert_eq!(
            name("_ZNSt7_LockitC1Ei").as_deref(),
            Some("std::_Lockit::_Lockit")
        );
        assert_eq!(
            name("_ZN3net7ChannelD2Ev").as_deref(),
            Some("net::Channel::~Channel")
        );
        assert_eq!(
            name("_ZTVN3net10TcpChannelE").as_deref(),
            Some("net::TcpChannel::vtable")
        );
        assert_eq!(
            name("_ZThn16_N3net14LoggingChannel3logEi").as_deref(),
            Some("net::LoggingChannel::log_thunk")
        );
        assert_eq!(
            name("_ZNKSt6vectorIiSaIiEE4sizeEv").as_deref(),
            Some("std::vector<int,std::allocator<int>>::size")
        );
        assert_eq!(name("_ZnwmPv").as_deref(), Some("operator_new"));
        assert_eq!(name("__ZN7Counter3addEi").as_deref(), Some("Counter::add"));
        assert_eq!(
            name("_ZNSsC1EPKc@GLIBCXX_3.4").as_deref(),
            Some("std::string::string")
        );
        assert_eq!(name("main"), None);
        assert_eq!(name("_Zfoo"), None);
        assert_eq!(
            name("_ZN4core3fmt5write17h0123456789abcdefE").as_deref(),
            Some("core::fmt::write")
        );
    }

    #[test]
    fn type_descriptor_names_their_class() {
        assert_eq!(
            type_descriptor_class(".?AVTcpChannel@net@@").as_deref(),
            Some("net::TcpChannel")
        );
        assert_eq!(
            type_descriptor_class(".?AU?$Box@H@net@@").as_deref(),
            Some("net::Box<int>")
        );
        assert_eq!(type_descriptor_class(".?AH"), None);
    }

    #[test]
    fn labels_split_outside_template_arguments() {
        assert_eq!(
            scope_of("std::vector<a::b>::size"),
            Some("std::vector<a::b>")
        );
        assert_eq!(member_of("std::vector<a::b>::size"), "size");
        assert_eq!(scope_of("main"), None);
    }
}

#[cfg(test)]
mod rust_tests {
    use super::*;

    #[test]
    fn rust_legacy_and_v0_names() {
        for raw in [
            "_ZN4core3fmt5write17h0123456789abcdefE",
            "__ZN4core3fmt5write17h0123456789abcdefE",
            "ZN4core3fmt5write17h0123456789abcdefE",
            "_ZN4core3fmt5write17h0123456789abcdefE.llvm.A5310EB9",
            "_RNvNtC4core3fmt5write",
        ] {
            let symbol = demangle(raw);
            assert_eq!(
                symbol.as_ref().map(|s| s.name.as_str()),
                Some("core::fmt::write"),
                "{raw}"
            );
            assert!(symbol.is_some_and(|s| s.prototype.is_none()));
        }
        assert_eq!(
            rust("_ZN4test9$LT$T$GT$17h0123456789abcdefE").as_deref(),
            Some("test::<T>")
        );
        assert_eq!(
            rust("_RINvC4test3foomE").as_deref(),
            Some("test::foo::<u32>")
        );
    }

    #[test]
    fn rejects_malformed_and_cpp_names() {
        for raw in [
            "main",
            "_ZN3foo3barE",
            "_ZN7Counter3addEi",
            "_R",
            "_Rbad",
            "_RNvB_3foo",
            "_ZN4core3fmt5write17hXXXXXXXXXXXXXXXXE",
        ] {
            assert_eq!(rust(raw), None, "{raw}");
        }
        assert_eq!(rust(&format!("_R{}", "x".repeat(2048))), None);
    }
}

/// Parameter types encoded in an unqualified Itanium function name. Qualified
/// names alone cannot distinguish static functions from methods with hidden `this`.
/// Return types are deliberately left to inference because ordinary names omit them.
pub fn itanium_parameters(symbol: &str, long_is_64: bool) -> Option<(Vec<(Scalar, String)>, bool)> {
    let symbol = symbol
        .strip_prefix('_')
        .filter(|s| s.starts_with("_Z"))
        .unwrap_or(symbol);
    let symbol = symbol.split('@').next()?;
    if symbol.len() > 2048 || !symbol.starts_with("_Z") || rust_legacy(symbol) {
        return None;
    }
    let parsed = cpp_demangle::Symbol::new(symbol).ok()?;
    let text = parsed
        .demangle_with_options(&cpp_demangle::DemangleOptions::new().no_return_type())
        .ok()?;
    let (name, rest) = text.split_once('(')?;
    if name.contains("::") || name.contains('<') || name.starts_with('{') {
        return None;
    }
    let rest = rest.strip_suffix(')')?;
    let mut parameters = Vec::new();
    let mut start = 0;
    let mut depth = 0u32;
    let mut parts = Vec::new();
    for (index, ch) in rest.char_indices() {
        match ch {
            '<' => depth += 1,
            '>' => depth = depth.checked_sub(1)?,
            ',' if depth == 0 => {
                parts.push(&rest[start..index]);
                start = index + 1;
            }
            '(' | ')' | '[' | ']' => return None,
            _ => {}
        }
    }
    if depth != 0 {
        return None;
    }
    parts.push(&rest[start..]);
    let mut varargs = false;
    for part in parts {
        let part = part.trim();
        if part.is_empty() || part == "void" {
            continue;
        }
        if part == "..." {
            varargs = true;
            continue;
        }
        if varargs || parameters.len() >= 32 {
            return None;
        }
        let pointer = part.ends_with('*') || part.ends_with('&');
        let base = if pointer {
            part.trim_end_matches(['*', '&']).trim()
        } else {
            part
        };
        let base = base.strip_suffix(" const").unwrap_or(base);
        let base = base.strip_prefix("const ").unwrap_or(base);
        if base.contains(['*', '&']) {
            return None;
        }
        let scalar = match base {
            "bool" => Scalar::Bool,
            "char" | "signed char" => Scalar::I8,
            "unsigned char" => Scalar::U8,
            "short" => Scalar::I16,
            "unsigned short" => Scalar::U16,
            "int" => Scalar::I32,
            "unsigned int" => Scalar::U32,
            "long" if !long_is_64 => Scalar::I32,
            "unsigned long" if !long_is_64 => Scalar::U32,
            "long" | "long long" => Scalar::I64,
            "unsigned long" | "unsigned long long" => Scalar::U64,
            "float" => Scalar::F32,
            "double" => Scalar::F64,
            _ if pointer => Scalar::Pointer,
            _ => return None,
        };
        if pointer {
            // Multiple indirections need a real type graph, not a flattened pointee.
            if part.trim_end_matches(['*', '&']).len() + 1 != part.len() {
                return None;
            }
            parameters.push((
                if base == "char" {
                    Scalar::CharPointer
                } else {
                    Scalar::Pointer
                },
                if scalar == Scalar::Pointer && base != "void" {
                    base.to_owned()
                } else {
                    String::new()
                },
            ));
        } else {
            parameters.push((scalar, String::new()));
        }
    }
    Some((parameters, varargs))
}

#[cfg(test)]
mod itanium_type_tests {
    use super::*;
    #[test]
    fn free_function_parameters_preserve_class_pointers_without_guessing_return() {
        assert_eq!(
            itanium_parameters("__Z11read_configPKcP10_XimConfig", true),
            Some((
                vec![
                    (Scalar::CharPointer, String::new()),
                    (Scalar::Pointer, "_XimConfig".into())
                ],
                false
            ))
        );
        assert_eq!(
            itanium_parameters("_Z3foolz", true),
            Some((vec![(Scalar::I64, String::new())], true))
        );
        assert_eq!(
            itanium_parameters("_Z3foolz", false),
            Some((vec![(Scalar::I32, String::new())], true))
        );
        assert!(itanium_parameters("_ZN7Counter3addEi", true).is_none());
        assert!(itanium_parameters("_Z3fooPFivE", true).is_none());
    }
}
