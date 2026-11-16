//! PE inspection reuses the recovery loader's mappings and import bindings.
use super::*;
use goblin::pe::{
    export::{ExportAddressTableEntry, Reexport},
    options::{ParseMode, ParseOptions},
    PE,
};

pub(super) fn inspect(bytes: &[u8]) -> Result<ImageInfo, ImageError> {
    let image = LoadedImage::parse_partial(bytes)?;
    let mut info = from_image(bytes, &image, 0);
    let managed = crate::extract::dotnet::looks_like_dotnet_pe(bytes);
    if managed {
        info.arch = Some("cil".into());
    } else if matches!(image.architecture, Architecture::X86 | Architecture::X64) {
        info.fid_arch = info.arch.clone();
    }
    let repaired = crate::extract::image::tolerate_rich_header(bytes);
    let mut options = ParseOptions::default();
    options.parse_mode = ParseMode::Permissive;
    options.parse_imports = false;
    let pe = PE::parse_with_opts(&repaired, &options).map_err(|e| ImageError::Pe(e.to_string()))?;
    for (index, export) in pe.exports.iter().enumerate() {
        let forward = export.reexport.as_ref().map(|r| match r {
            Reexport::DLLName { export, lib } => format!("{lib}.{export}"),
            Reexport::DLLOrdinal { ordinal, lib } => format!("{lib}.#{ordinal}"),
        });
        let va = if forward.is_some() {
            0
        } else {
            image
                .image_base
                .checked_add(export.rva as u64)
                .ok_or(ImageError::AddressOverflow {
                    format: image.format,
                    context: "export address",
                })?
        };
        info.exports.push(Export {
            name: export
                .name
                .map(str::to_owned)
                .unwrap_or_else(|| format!("ord_{index}")),
            va,
            forward,
        });
    }
    // Goblin's named exports omit ordinal-only entries. Keep those navigable too.
    if let Some(data) = &pe.export_data {
        let named: std::collections::BTreeSet<_> =
            data.export_ordinal_table.iter().copied().collect();
        for (index, entry) in data.export_address_table.iter().enumerate() {
            if u16::try_from(index)
                .ok()
                .is_some_and(|index| named.contains(&index))
            {
                continue;
            }
            let (rva, forwarded) = match entry {
                ExportAddressTableEntry::ExportRVA(rva) => (*rva, false),
                ExportAddressTableEntry::ForwarderRVA(rva) => (*rva, true),
            };
            if rva == 0 {
                continue;
            }
            let va = image.image_base.checked_add(u64::from(rva)).ok_or(
                ImageError::AddressOverflow {
                    format: image.format,
                    context: "ordinal export address",
                },
            )?;
            let forward = if forwarded {
                let text = image
                    .bytes_at(va, 512)
                    .ok_or_else(|| ImageError::Pe("unmapped forwarded export".into()))?;
                let end = text
                    .iter()
                    .position(|&b| b == 0)
                    .ok_or_else(|| ImageError::Pe("unterminated forwarded export".into()))?;
                Some(String::from_utf8_lossy(&text[..end]).into_owned())
            } else {
                None
            };
            let ordinal = u64::from(data.export_directory_table.ordinal_base) + index as u64;
            info.exports.push(Export {
                name: format!("ord_{ordinal}"),
                va: if forwarded { 0 } else { va },
                forward,
            });
        }
    }
    info.details = details::pe::collect(bytes, &pe);
    Ok(info)
}
