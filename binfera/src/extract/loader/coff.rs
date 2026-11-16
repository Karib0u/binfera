//! Function names in a PE's optional COFF symbol table.
//! Layout: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-symbol-table

use std::collections::BTreeMap;

use goblin::pe::symbol::{
    Symbol, COFF_SYMBOL_SIZE, IMAGE_SYM_CLASS_EXTERNAL, IMAGE_SYM_CLASS_STATIC,
    IMAGE_SYM_DTYPE_FUNCTION, IMAGE_SYM_DTYPE_SHIFT,
};
use goblin::pe::PE;

use super::image::LoadedImage;

/// Read only defined functions in file-backed executable sections. COFF values are offsets
/// within a one-based section, not RVAs. Auxiliary records count toward the header's count
/// but are not symbols. Keep aliases in table order so choosing a primary name is deterministic.
pub(crate) fn function_symbols(
    bytes: &[u8],
    pe: &PE<'_>,
    image: &LoadedImage,
) -> Result<BTreeMap<u64, Vec<String>>, &'static str> {
    let mut names: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    let header = &pe.header.coff_header;
    let offset = header.pointer_to_symbol_table as usize;
    let count = header.number_of_symbol_table as usize;
    if offset == 0 || count == 0 {
        return Ok(names);
    }
    let end = count
        .checked_mul(COFF_SYMBOL_SIZE)
        .and_then(|size| offset.checked_add(size))
        .ok_or("symbol table size overflow")?;
    let table = bytes.get(offset..end).ok_or("truncated symbol table")?;
    let strings = bytes.get(end..).ok_or("missing string table")?;
    let size = strings
        .get(..4)
        .and_then(|size| <[u8; 4]>::try_from(size).ok())
        .map(u32::from_le_bytes)
        .ok_or("missing string table length")? as usize;
    if size < 4 {
        return Err("invalid string table length");
    }
    let strings = strings.get(..size).ok_or("truncated string table")?;
    let mut index = 0;
    while index < count {
        let (inline_name, symbol) =
            Symbol::parse(table, index * COFF_SYMBOL_SIZE).map_err(|_| "invalid symbol record")?;
        index += 1 + usize::from(symbol.number_of_aux_symbols);
        if index > count {
            return Err("auxiliary records exceed symbol table");
        }
        // The first derived type must be FUNCTION, not POINTER-to-function. Static functions
        // matter too: goblin's is_function_definition() accepts only external definitions.
        if (symbol.typ >> IMAGE_SYM_DTYPE_SHIFT) & 3 != IMAGE_SYM_DTYPE_FUNCTION
            || !matches!(
                symbol.storage_class,
                IMAGE_SYM_CLASS_EXTERNAL | IMAGE_SYM_CLASS_STATIC
            )
            || symbol.section_number <= 0
        {
            continue;
        }
        let Some(section) = pe.sections.get(symbol.section_number as usize - 1) else {
            continue;
        };
        if symbol.value >= section.virtual_size.max(section.size_of_raw_data) {
            continue;
        }
        let Some(address) = image
            .image_base
            .checked_add(u64::from(section.virtual_address))
            .and_then(|base| base.checked_add(u64::from(symbol.value)))
        else {
            continue;
        };
        if !image.is_executable_address(address) || image.va_to_file_offset(address).is_none() {
            continue;
        }
        // Read offsets ourselves: goblin's Symbol::name_offset subtracts 4 unchecked.
        let name = if symbol.name.starts_with(&[0; 4]) {
            let Some(offset) = symbol
                .name
                .get(4..)
                .and_then(|offset| <[u8; 4]>::try_from(offset).ok())
                .map(u32::from_le_bytes)
                .filter(|offset| *offset >= 4)
            else {
                continue;
            };
            let Some(rest) = strings.get(offset as usize..) else {
                continue;
            };
            rest.iter()
                .position(|byte| *byte == 0)
                .and_then(|end| rest.get(..end))
                .and_then(|name| std::str::from_utf8(name).ok())
        } else {
            inline_name
        };
        let Some(name) = name.filter(|name| !name.is_empty()) else {
            continue;
        };
        let aliases = names.entry(address).or_default();
        if !aliases.iter().any(|alias| alias == name) {
            aliases.push(name.to_owned());
        }
    }
    Ok(names)
}
