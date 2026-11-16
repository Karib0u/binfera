//! Embedded DWARF for native decompilation. No external debug files are opened.
//! Limits here are local policy for untrusted binaries, including compressed sections and DIEs.
#![allow(non_upper_case_globals)] // Match the DWARF specification's constant names.

use std::collections::BTreeMap;
use std::io::Read;

use gimli::{AttributeValue as Attr, Dwarf, EndianSlice, Reader, RunTimeEndian};
use object::{Object, ObjectSection};

use crate::extract::image::LoadedImage;

const MAX_BYTES: usize = 64 << 20;
const MAX_ENTRIES: usize = 250_000;
const MAX_NAME: usize = 1024;
const MAX_DEPTH: usize = 64;
const MAX_TYPE_SIZE: u64 = 1 << 20;
type Slice<'a> = EndianSlice<'a, RunTimeEndian>;

#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "decompiler", derive(serde::Serialize, serde::Deserialize))]
pub struct DebugInfo {
    pub functions: BTreeMap<u64, Function>,
    pub(crate) types: Vec<binfera_ghidra::DebugType>,
    pub diagnostics: Vec<String>,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "decompiler", derive(serde::Serialize, serde::Deserialize))]
pub struct Function {
    pub name: String,
    pub(crate) result: u64,
    pub(crate) parameters: Vec<binfera_ghidra::DebugParameter>,
    pub(crate) locals: Vec<Local>,
    pub(crate) frame: Option<Location>,
    pub(crate) signature: bool,
    pub(crate) model: String,
    pub(crate) varargs: bool,
    pub(crate) go: bool,
    pub(crate) multi: bool,
    pub(crate) noreturn: bool,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "decompiler", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct Local {
    pub name: String,
    pub type_id: u64,
    pub offset: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "decompiler", derive(serde::Serialize, serde::Deserialize))]
pub(crate) enum Location {
    Frame(i64),
    Register(u16),
    Cfa,
}

struct Die {
    tag: gimli::DwTag,
    name: Option<String>,
    linkage: Option<String>,
    type_id: Option<u64>,
    origin: Option<u64>,
    specification: Option<u64>,
    size: Option<u64>,
    encoding: Option<gimli::DwAte>,
    offset: Option<u64>,
    count: Option<u64>,
    bitfield: bool,
    declaration: bool,
    prototyped: bool,
    output: bool,
    noreturn: bool,
    location: Option<Location>,
    frame: Option<Location>,
    address: Option<u64>,
    children: Vec<u64>,
    language: gimli::DwLang,
    convention: Option<u8>,
}

impl Default for Die {
    fn default() -> Self {
        Self {
            tag: gimli::DwTag(0),
            name: None,
            linkage: None,
            type_id: None,
            origin: None,
            specification: None,
            size: None,
            encoding: None,
            offset: None,
            count: None,
            bitfield: false,
            declaration: false,
            prototyped: false,
            output: false,
            noreturn: false,
            location: None,
            frame: None,
            address: None,
            children: Vec::new(),
            language: gimli::DwLang(0),
            convention: None,
        }
    }
}

fn string(
    dwarf: &Dwarf<Slice<'_>>,
    unit: &gimli::Unit<Slice<'_>>,
    value: Attr<Slice<'_>>,
) -> Option<String> {
    let value = dwarf.attr_string(unit, value).ok()?;
    if value.len() > MAX_NAME {
        return None;
    }
    let value = value.to_string_lossy();
    (!value.is_empty() && !value.chars().any(char::is_control)).then(|| value.into_owned())
}

fn reference(unit: &gimli::Unit<Slice<'_>>, value: Attr<Slice<'_>>) -> Option<u64> {
    let offset = match value {
        Attr::UnitRef(offset) => offset.to_debug_info_offset(&unit.header)?.0,
        Attr::DebugInfoRef(offset) => offset.0,
        _ => return None,
    };
    (offset as u64).checked_add(1)
}

fn location(
    expression: gimli::Expression<Slice<'_>>,
    encoding: gimli::Encoding,
) -> Option<Location> {
    let mut ops = expression.operations(encoding);
    let value = match ops.next().ok()?? {
        gimli::Operation::FrameOffset { offset } => Location::Frame(offset),
        gimli::Operation::Register { register } => Location::Register(register.0),
        gimli::Operation::CallFrameCFA => Location::Cfa,
        _ => return None,
    };
    // Pieces, dereferences and computed values need an evaluator and lifetime-aware storage.
    ops.next().ok()?.is_none().then_some(value)
}

impl DebugInfo {
    /// Malformed optional metadata is reported and never prevents code recovery.
    pub fn read(bytes: &[u8], image: &LoadedImage) -> Self {
        let mut result = Self::default();
        if let Err(error) = result.read_inner(bytes, image) {
            result.diagnostics.push(format!("DWARF: {error}"));
        }
        result
    }

    fn read_inner(&mut self, bytes: &[u8], image: &LoadedImage) -> Result<(), String> {
        let object = object::File::parse(bytes).map_err(|e| e.to_string())?;
        let endian = if object.is_little_endian() {
            RunTimeEndian::Little
        } else {
            RunTimeEndian::Big
        };
        let mut remaining = MAX_BYTES;
        let sections = gimli::DwarfSections::load(|id| -> Result<Vec<u8>, String> {
            let name = id.name();
            let section = object
                .section_by_name(name)
                .or_else(|| object.section_by_name(&name.replacen(".debug_", ".zdebug_", 1)))
                .or_else(|| object.section_by_name(&name.replacen(".debug_", "__debug_", 1)))
                .or_else(|| object.section_by_name(&name.replacen(".debug_", "__zdebug_", 1)));
            let Some(section) = section else {
                return Ok(Vec::new());
            };
            let data = section
                .compressed_data()
                .map_err(|e| format!("{name}: {e}"))?;
            let size =
                usize::try_from(data.uncompressed_size).map_err(|_| "section size overflow")?;
            if size > remaining {
                return Err("debug sections exceed 64 MiB".into());
            }
            remaining -= size;
            match data.format {
                object::CompressionFormat::None => Ok(data.data.to_vec()),
                object::CompressionFormat::Zlib => {
                    let mut bytes = Vec::new();
                    flate2::read::ZlibDecoder::new(data.data)
                        .take(size as u64 + 1)
                        .read_to_end(&mut bytes)
                        .map_err(|e| format!("{name}: {e}"))?;
                    if bytes.len() != size {
                        return Err(format!("{name}: invalid decompressed size"));
                    }
                    Ok(bytes)
                }
                _ => Err(format!("{name}: unsupported compression")),
            }
        })?;
        let dwarf = sections.borrow(|section| EndianSlice::new(section, endian));
        let mut dies = BTreeMap::new();
        let mut units = dwarf.units();
        let mut strings = 0usize;
        loop {
            let header = match units.next() {
                Ok(Some(header)) => header,
                Ok(None) => break,
                Err(error) => {
                    self.diagnostics.push(format!("DWARF unit header: {error}"));
                    break;
                }
            };
            let start = header
                .offset()
                .as_debug_info_offset()
                .map_or(0, |o| o.0 as u64 + 1);
            let unit = match dwarf.unit(header) {
                Ok(unit) => unit,
                Err(error) => {
                    if self.diagnostics.len() < 16 {
                        self.diagnostics.push(format!("DWARF unit: {error}"));
                    }
                    continue;
                }
            };
            if let Err(error) = read_unit(&dwarf, &unit, image, &mut dies, &mut strings) {
                let exhausted = dies.len() >= MAX_ENTRIES || strings > MAX_BYTES;
                // Never lock a partial function's parameter list after a damaged unit.
                dies.split_off(&start);
                if self.diagnostics.len() < 16 {
                    self.diagnostics.push(format!("DWARF unit: {error}"));
                }
                if exhausted {
                    break;
                }
            }
        }
        self.convert(&dies);
        Ok(())
    }

    fn convert(&mut self, dies: &BTreeMap<u64, Die>) {
        use gimli::*;
        for (&id, die) in dies {
            let mut ty = binfera_ghidra::DebugType {
                id,
                kind: String::new(),
                name: die.name.clone().unwrap_or_else(|| format!("dwarf_{id:x}")),
                size: die.size.filter(|s| *s <= MAX_TYPE_SIZE).unwrap_or(0) as u32,
                target: die.type_id.unwrap_or(0),
                count: 0,
                fields: Vec::new(),
            };
            match die.tag {
                DW_TAG_base_type => {
                    ty.kind = match die.encoding {
                        Some(DW_ATE_signed | DW_ATE_signed_char) => "int",
                        Some(DW_ATE_unsigned | DW_ATE_unsigned_char | DW_ATE_address) => "uint",
                        Some(DW_ATE_boolean) => "bool",
                        Some(DW_ATE_float) => "float",
                        _ => continue,
                    }
                    .into();
                    if !matches!(ty.size, 1 | 2 | 4 | 8 | 16) {
                        continue;
                    }
                }
                DW_TAG_pointer_type | DW_TAG_reference_type | DW_TAG_rvalue_reference_type => {
                    ty.kind = "pointer".into()
                }
                DW_TAG_typedef | DW_TAG_const_type | DW_TAG_volatile_type
                | DW_TAG_restrict_type | DW_TAG_atomic_type => ty.kind = "alias".into(),
                DW_TAG_unspecified_type if die.name.as_deref() == Some("void") => {
                    ty.kind = "alias".into()
                }
                DW_TAG_enumeration_type => {
                    // Keep the underlying signedness; enumerator labels are not imported yet.
                    if die.type_id.is_some() {
                        ty.kind = "alias".into();
                    } else {
                        ty.kind = if die.encoding == Some(DW_ATE_unsigned) {
                            "uint"
                        } else {
                            "int"
                        }
                        .into();
                    }
                }
                DW_TAG_structure_type | DW_TAG_class_type | DW_TAG_union_type => {
                    if die.declaration || ty.size == 0 {
                        continue;
                    }
                    ty.kind = "struct".into();
                    // Union and bit-field storage stays opaque instead of inventing a layout.
                    if die.tag != DW_TAG_union_type {
                        for child in &die.children {
                            let Some(field) = dies.get(child) else {
                                continue;
                            };
                            if field.tag != DW_TAG_member || field.bitfield {
                                continue;
                            }
                            if let (Some(offset), Some(type_id)) = (field.offset, field.type_id) {
                                if offset < u64::from(ty.size) {
                                    ty.fields.push(binfera_ghidra::DebugField {
                                        name: field
                                            .name
                                            .clone()
                                            .unwrap_or_else(|| format!("field_{offset:x}")),
                                        offset: offset as u32,
                                        type_id,
                                    });
                                }
                            }
                        }
                    }
                }
                DW_TAG_array_type => {
                    let dimensions: Vec<_> = die
                        .children
                        .iter()
                        .filter_map(|id| dies.get(id))
                        .filter(|d| d.tag == DW_TAG_subrange_type)
                        .collect();
                    // Dynamic and multi-dimensional bounds stay unknown, never silently flattened.
                    if dimensions.len() != 1 {
                        continue;
                    }
                    let Some(count) = dimensions.first().and_then(|d| d.count) else {
                        continue;
                    };
                    if count == 0 || count > MAX_TYPE_SIZE {
                        continue;
                    }
                    ty.kind = "array".into();
                    ty.count = count as u32;
                }
                _ => continue,
            }
            self.types.push(ty);
        }
        let mut supported_types = BTreeMap::new();
        for (&id, die) in dies {
            if die.tag != DW_TAG_subprogram || die.declaration {
                continue;
            }
            let Some(address) = die.address else {
                continue;
            };
            let chain = inherited(dies, id);
            let Some(name) = chain
                .iter()
                .find_map(|d| d.linkage.as_ref())
                .or_else(|| chain.iter().find_map(|d| d.name.as_ref()))
            else {
                continue;
            };
            let result = chain.iter().find_map(|d| d.type_id).unwrap_or(0);
            let children = chain
                .iter()
                .find(|d| {
                    d.children.iter().any(|id| {
                        dies.get(id)
                            .is_some_and(|d| d.tag == DW_TAG_formal_parameter)
                    })
                })
                .map(|d| &d.children)
                .unwrap_or(&die.children);
            let go = die.language == DW_LANG_Go;
            let mut function = Function {
                name: name.clone(),
                result,
                parameters: Vec::new(),
                locals: Vec::new(),
                frame: die.frame,
                signature: true,
                model: String::new(),
                varargs: false,
                go,
                multi: false,
                noreturn: chain.iter().any(|d| d.noreturn),
            };
            match chain.iter().find_map(|d| d.convention) {
                None | Some(1) => (),
                Some(0xb1) => function.model = "__stdcall".into(),
                Some(0xb2) => function.model = "__fastcall".into(),
                Some(0xb3) => function.model = "__thiscall".into(),
                _ => function.signature = false,
            }
            if chain.iter().any(|d| {
                d.origin.is_some_and(|id| !dies.contains_key(&id))
                    || d.specification.is_some_and(|id| !dies.contains_key(&id))
            }) {
                function.signature = false;
            }
            let mut outputs = Vec::new();
            for child in children {
                let Some(param) = dies.get(child) else {
                    continue;
                };
                if param.tag == DW_TAG_unspecified_parameters {
                    function.varargs = true;
                }
                if param.tag != DW_TAG_formal_parameter {
                    continue;
                }
                let chain = inherited(dies, *child);
                let Some(type_id) = chain.iter().find_map(|d| d.type_id) else {
                    function.signature = false;
                    continue;
                };
                let name = chain
                    .iter()
                    .find_map(|d| d.name.clone())
                    .unwrap_or_else(|| format!("param_{}", function.parameters.len() + 1));
                // Older Go producers omit DW_AT_variable_parameter. Their
                // compiler-generated ~rN names still identify result slots.
                let unnamed_result = name
                    .strip_prefix("~r")
                    .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
                if go && (chain.iter().any(|d| d.output) || unnamed_result) {
                    if !value_supported(dies, type_id, 0, &mut supported_types) {
                        function.signature = false;
                    }
                    // Go issue 61357: some producers repeat the same result parameter.
                    if !outputs.iter().any(|(existing, _)| existing == &name) {
                        outputs.push((name, type_id));
                    }
                } else {
                    function
                        .parameters
                        .push(binfera_ghidra::DebugParameter { name, type_id });
                }
            }
            if function.parameters.len() > 32 {
                function.signature = false;
            }
            if go && !outputs.is_empty() {
                if outputs.len() == 1 {
                    function.result = outputs[0].1;
                } else {
                    // Use DWARF's result variables in source order. Native Go allocation assigns
                    // each result separately and constructs its register/stack storage layout.
                    let mut offset = 0u64;
                    let mut fields = Vec::new();
                    for (name, type_id) in outputs {
                        let Some(size) = type_size(dies, type_id, 0) else {
                            function.signature = false;
                            break;
                        };
                        fields.push(binfera_ghidra::DebugField {
                            name,
                            offset: offset as u32,
                            type_id,
                        });
                        offset += size;
                    }
                    if offset > 0 && offset <= MAX_TYPE_SIZE {
                        let type_id = u64::MAX - id;
                        self.types.push(binfera_ghidra::DebugType {
                            id: type_id,
                            kind: "struct".into(),
                            name: format!("dwarf_results_{id:x}"),
                            size: offset as u32,
                            target: 0,
                            count: 0,
                            fields,
                        });
                        function.result = type_id;
                        function.multi = true;
                    } else {
                        function.signature = false;
                    }
                }
            }
            if go {
                function.varargs = false;
            }
            // Rust can emit name-only subprogram DIEs without -g. Like Ghidra's
            // RustDWARFFunctionFixup, retain inference for these stub signatures.
            if die.language == DW_LANG_Rust && result == 0 && function.parameters.is_empty() {
                function.signature = false;
            }
            // A name-only C DIE, including an abstract inline origin, does not
            // establish an empty prototype. Keep ABI input recovery enabled.
            if !go
                && result == 0
                && function.parameters.is_empty()
                && !chain.iter().any(|d| d.prototyped)
            {
                function.signature = false;
            }
            // Rust's private aggregate ABI needs explicit storage; scalar/pointer prototypes
            // use the platform ABI. Do not lock an aggregate to an assumed C convention.
            if die.language == DW_LANG_Rust
                && (aggregate(dies, function.result, 0)
                    || function
                        .parameters
                        .iter()
                        .any(|p| aggregate(dies, p.type_id, 0)))
            {
                function.signature = false;
            }
            if !value_supported(dies, result, 0, &mut supported_types)
                || function
                    .parameters
                    .iter()
                    .any(|p| !value_supported(dies, p.type_id, 0, &mut supported_types))
            {
                function.signature = false;
            }
            collect_locals(dies, die, &mut function.locals);
            self.functions.entry(address).or_insert(function);
        }
    }
}

fn inherited(dies: &BTreeMap<u64, Die>, id: u64) -> Vec<&Die> {
    let mut result = Vec::new();
    let mut pending = vec![id];
    let mut seen = Vec::new();
    while let Some(id) = pending.pop() {
        if seen.len() >= MAX_DEPTH || seen.contains(&id) {
            continue;
        }
        seen.push(id);
        let Some(die) = dies.get(&id) else {
            continue;
        };
        result.push(die);
        if let Some(id) = die.specification {
            pending.push(id);
        }
        if let Some(id) = die.origin {
            pending.push(id);
        }
    }
    result
}

fn type_size(dies: &BTreeMap<u64, Die>, id: u64, depth: usize) -> Option<u64> {
    if depth >= MAX_DEPTH {
        return None;
    }
    let die = dies.get(&id)?;
    die.size
        .or_else(|| type_size(dies, die.type_id?, depth + 1))
        .filter(|s| *s > 0 && *s <= MAX_TYPE_SIZE)
}

fn value_supported(
    dies: &BTreeMap<u64, Die>,
    id: u64,
    depth: usize,
    cache: &mut BTreeMap<u64, bool>,
) -> bool {
    if id == 0 {
        return true;
    }
    if depth >= MAX_DEPTH {
        return false;
    }
    if let Some(supported) = cache.get(&id) {
        return *supported;
    }
    // An in-progress by-value type is a cycle. Pointers do not traverse their target.
    cache.insert(id, false);
    let Some(die) = dies.get(&id) else {
        return false;
    };
    let supported = match die.tag {
        gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type => {
            !die.declaration
                && die
                    .children
                    .iter()
                    .filter_map(|id| dies.get(id))
                    .filter(|d| d.tag == gimli::DW_TAG_member || d.tag == gimli::DW_TAG_inheritance)
                    .all(|d| {
                        d.tag != gimli::DW_TAG_inheritance
                            && !d.bitfield
                            && d.offset.is_some()
                            && d.type_id
                                .is_some_and(|id| value_supported(dies, id, depth + 1, cache))
                    })
        }
        gimli::DW_TAG_typedef
        | gimli::DW_TAG_const_type
        | gimli::DW_TAG_volatile_type
        | gimli::DW_TAG_restrict_type
        | gimli::DW_TAG_atomic_type
        | gimli::DW_TAG_array_type => die
            .type_id
            .is_some_and(|id| value_supported(dies, id, depth + 1, cache)),
        gimli::DW_TAG_base_type
        | gimli::DW_TAG_pointer_type
        | gimli::DW_TAG_reference_type
        | gimli::DW_TAG_rvalue_reference_type
        | gimli::DW_TAG_enumeration_type => true,
        _ => false,
    };
    cache.insert(id, supported);
    supported
}

fn aggregate(dies: &BTreeMap<u64, Die>, id: u64, depth: usize) -> bool {
    if id == 0 {
        return false;
    }
    if depth >= MAX_DEPTH {
        return true;
    }
    let Some(die) = dies.get(&id) else {
        return true;
    };
    match die.tag {
        gimli::DW_TAG_base_type
        | gimli::DW_TAG_pointer_type
        | gimli::DW_TAG_reference_type
        | gimli::DW_TAG_rvalue_reference_type
        | gimli::DW_TAG_enumeration_type => false,
        gimli::DW_TAG_typedef | gimli::DW_TAG_const_type | gimli::DW_TAG_volatile_type => {
            aggregate(dies, die.type_id.unwrap_or(0), depth + 1)
        }
        _ => true,
    }
}

fn collect_locals(dies: &BTreeMap<u64, Die>, die: &Die, locals: &mut Vec<Local>) {
    // Only function-scope fixed stack locations: narrower lexical scopes can reuse storage.
    for child in &die.children {
        let Some(local) = dies.get(child) else {
            continue;
        };
        if local.tag != gimli::DW_TAG_variable {
            continue;
        }
        let chain = inherited(dies, *child);
        if let (Some(Location::Frame(offset)), Some(name), Some(type_id)) = (
            local.location,
            chain.iter().find_map(|d| d.name.clone()),
            chain.iter().find_map(|d| d.type_id),
        ) {
            if locals.len() < 256 {
                locals.push(Local {
                    name,
                    type_id,
                    offset,
                });
            }
        }
    }
}

fn read_unit(
    dwarf: &Dwarf<Slice<'_>>,
    unit: &gimli::Unit<Slice<'_>>,
    image: &LoadedImage,
    dies: &mut BTreeMap<u64, Die>,
    strings: &mut usize,
) -> Result<(), String> {
    use gimli::*;
    let mut entries = unit.entries();
    let mut depth = 0isize;
    let mut parents = Vec::new();
    let mut language = DW_LANG_C;
    while let Some((delta, entry)) = entries.next_dfs().map_err(|e| e.to_string())? {
        if dies.len() >= MAX_ENTRIES || *strings > MAX_BYTES {
            return Err("debug entry budget exceeded".into());
        }
        depth += delta;
        if depth < 0 || depth as usize > MAX_DEPTH {
            return Err("debug nesting exceeds 64 levels".into());
        }
        parents.truncate(depth as usize);
        let id = entry
            .offset()
            .to_debug_info_offset(&unit.header)
            .ok_or("unsupported type unit")?
            .0 as u64
            + 1;
        let mut die = Die {
            tag: entry.tag(),
            language,
            ..Die::default()
        };
        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next().map_err(|e| e.to_string())? {
            let value = attr.value();
            match attr.name() {
                DW_AT_name => die.name = string(dwarf, unit, value),
                DW_AT_linkage_name | DW_AT_MIPS_linkage_name => {
                    die.linkage = string(dwarf, unit, value)
                }
                DW_AT_type => die.type_id = Some(reference(unit, value).unwrap_or(u64::MAX)),
                DW_AT_abstract_origin => die.origin = reference(unit, value),
                DW_AT_specification => die.specification = reference(unit, value),
                DW_AT_calling_convention => {
                    if let Attr::CallingConvention(cc) = value {
                        die.convention = Some(cc.0);
                    }
                }
                DW_AT_byte_size => die.size = value.udata_value(),
                DW_AT_encoding => {
                    if let Attr::Encoding(encoding) = value {
                        die.encoding = Some(encoding);
                    }
                }
                DW_AT_language => {
                    if let Attr::Language(lang) = value {
                        language = lang;
                        die.language = lang;
                    }
                }
                DW_AT_data_member_location => {
                    die.offset = value.udata_value();
                    if let Attr::Exprloc(expr) = value {
                        let mut ops = expr.operations(unit.encoding());
                        if let Ok(Some(Operation::PlusConstant { value })) = ops.next() {
                            if matches!(ops.next(), Ok(None)) {
                                die.offset = Some(value);
                            }
                        }
                    }
                }
                DW_AT_count => die.count = value.udata_value(),
                DW_AT_upper_bound if die.count.is_none() => {
                    die.count = value.udata_value().and_then(|v| v.checked_add(1))
                }
                DW_AT_bit_size | DW_AT_data_bit_offset | DW_AT_bit_offset => die.bitfield = true,
                DW_AT_declaration => die.declaration = value == Attr::Flag(true),
                DW_AT_prototyped => die.prototyped = value == Attr::Flag(true),
                DW_AT_variable_parameter => die.output = value == Attr::Flag(true),
                DW_AT_noreturn => die.noreturn = value == Attr::Flag(true),
                DW_AT_frame_base => {
                    if let Attr::Exprloc(expr) = value {
                        die.frame = location(expr, unit.encoding());
                    }
                }
                DW_AT_location => {
                    if let Attr::Exprloc(expr) = value {
                        die.location = location(expr, unit.encoding());
                    }
                }
                _ => (),
            }
        }
        *strings +=
            die.name.as_ref().map_or(0, String::len) + die.linkage.as_ref().map_or(0, String::len);
        if die.tag == DW_TAG_subprogram && !die.declaration {
            let mut ranges = dwarf.die_ranges(unit, entry).map_err(|e| e.to_string())?;
            // The entry is low_pc / entry_pc when supplied, otherwise the first nonempty range.
            let entry_pc = entry
                .attr_value(DW_AT_entry_pc)
                .map_err(|e| e.to_string())?
                .or(entry.attr_value(DW_AT_low_pc).map_err(|e| e.to_string())?);
            let mut start = entry_pc
                .and_then(|v| dwarf.attr_address(unit, v).ok().flatten())
                .filter(|v| *v != 0);
            for _ in 0..4096 {
                let Some(range) = ranges.next().map_err(|e| e.to_string())? else {
                    break;
                };
                if range.begin < range.end {
                    start = start.or(Some(range.begin));
                    break;
                }
            }
            die.address = start
                .filter(|a| *a != 0)
                .and_then(|a| a.checked_add(image.load_bias))
                .filter(|a| {
                    image.sections.iter().any(|s| {
                        s.permissions.execute && *a >= s.address && *a - s.address < s.file_size
                    })
                });
        }
        if let Some(parent) = parents.last().and_then(|id| dies.get_mut(id)) {
            parent.children.push(id);
        }
        dies.insert(id, die);
        parents.push(id);
    }
    Ok(())
}

/// Convert the producer's fixed frame base to Ghidra's entry-SP coordinates. Dynamic
/// expressions and nonstandard prologues are omitted instead of binding a local to a guess.
pub(crate) fn stack_frame_base(
    image: &LoadedImage,
    address: u64,
    frame: Option<Location>,
) -> Option<i64> {
    use crate::extract::image::Architecture;
    use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register};
    if !image.architecture.is_x86() {
        // ARM and MIPS keep the return address in a link register, not above the entry stack pointer.
        return (frame == Some(Location::Cfa)).then_some(0);
    }
    let wide = image.architecture == Architecture::X64;
    let word = if wide { 8i64 } else { 4i64 };
    if frame == Some(Location::Cfa) {
        return Some(word);
    }
    let Some(Location::Register(register)) = frame else {
        return None;
    };
    let (sp, bp, sp_number, bp_number) = if wide {
        (Register::RSP, Register::RBP, 7, 6)
    } else {
        (Register::ESP, Register::EBP, 4, 5)
    };
    if register != sp_number && register != bp_number {
        return None;
    }
    let bytes = image.bytes_at(address, 64)?;
    let mut decoder = Decoder::with_ip(
        if wide { 64 } else { 32 },
        bytes,
        address,
        DecoderOptions::NONE,
    );
    let mut stack = 0i64;
    let mut base = None;
    for _ in 0..16 {
        if !decoder.can_decode() {
            break;
        }
        let insn = decoder.decode();
        match insn.mnemonic() {
            Mnemonic::Push if insn.op0_kind() == OpKind::Register => {
                stack = stack.checked_sub(word)?
            }
            Mnemonic::Sub if insn.op0_register() == sp => {
                let amount = match insn.op1_kind() {
                    OpKind::Immediate8to32 => i64::from(insn.immediate8to32()),
                    OpKind::Immediate8to64 => insn.immediate8to64(),
                    OpKind::Immediate32 => i64::from(insn.immediate32()),
                    OpKind::Immediate32to64 => insn.immediate32to64(),
                    _ => return None,
                };
                stack = stack.checked_sub(amount)?;
            }
            Mnemonic::Mov if insn.op0_register() == bp && insn.op1_register() == sp => {
                base = Some(stack)
            }
            Mnemonic::Lea
                if insn.op0_register() == bp
                    && insn.memory_base() == sp
                    && insn.memory_index() == Register::None =>
            {
                base = stack.checked_add(insn.memory_displacement64() as i64);
            }
            Mnemonic::Nop | Mnemonic::Endbr64 | Mnemonic::Endbr32 => (),
            _ if insn.op0_register() == sp && register == sp_number => return None,
            _ => break,
        }
    }
    if register == sp_number {
        Some(stack)
    } else {
        base
    }
}

#[cfg(test)]
mod tests {
    use super::{DebugInfo, Die};
    use gimli::*;
    use std::collections::BTreeMap;

    #[test]
    fn old_go_result_names_are_outputs_without_the_variable_parameter_flag() -> anyhow::Result<()> {
        let mut dies = BTreeMap::from([
            (
                1,
                Die {
                    tag: DW_TAG_base_type,
                    name: Some("int64".into()),
                    size: Some(8),
                    encoding: Some(DW_ATE_signed),
                    ..Default::default()
                },
            ),
            (
                2,
                Die {
                    tag: DW_TAG_subprogram,
                    name: Some("time.Since".into()),
                    address: Some(0x1000),
                    language: DW_LANG_Go,
                    children: vec![3, 4],
                    ..Default::default()
                },
            ),
            (
                3,
                Die {
                    tag: DW_TAG_formal_parameter,
                    name: Some("t".into()),
                    type_id: Some(1),
                    ..Default::default()
                },
            ),
            (
                4,
                Die {
                    tag: DW_TAG_formal_parameter,
                    name: Some("~r1".into()),
                    type_id: Some(1),
                    ..Default::default()
                },
            ),
        ]);
        let mut debug = DebugInfo::default();
        debug.convert(&dies);
        let function = &debug.functions[&0x1000];
        assert!(function.signature);
        assert_eq!(function.result, 1);
        assert_eq!(function.parameters.len(), 1);
        assert_eq!(function.parameters[0].name, "t");
        // Ordinary parameter names with a similar prefix remain inputs.
        dies.get_mut(&4)
            .ok_or_else(|| anyhow::anyhow!("result parameter"))?
            .name = Some("~result".into());
        let mut debug = DebugInfo::default();
        debug.convert(&dies);
        assert_eq!(debug.functions[&0x1000].result, 0);
        assert_eq!(debug.functions[&0x1000].parameters.len(), 2);
        Ok(())
    }

    #[test]
    fn name_only_inline_origins_do_not_lock_an_empty_c_prototype() {
        for prototyped in [false, true] {
            let dies = BTreeMap::from([
                (
                    1,
                    Die {
                        tag: DW_TAG_subprogram,
                        name: Some("helper".into()),
                        language: DW_LANG_C99,
                        prototyped,
                        ..Default::default()
                    },
                ),
                (
                    2,
                    Die {
                        tag: DW_TAG_subprogram,
                        origin: Some(1),
                        address: Some(0x1000),
                        language: DW_LANG_C99,
                        ..Default::default()
                    },
                ),
            ]);
            let mut debug = DebugInfo::default();
            debug.convert(&dies);
            assert_eq!(debug.functions[&0x1000].signature, prototyped);
        }
    }
}
