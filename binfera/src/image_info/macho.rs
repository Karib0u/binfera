//! Universal selection and address mappings use the native Mach-O loader.
use super::*;
use crate::extract::image::{select_macho_slice, Permissions};
use goblin::mach::{
    constants::{VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE},
    exports::ExportInfo,
    MachO,
};

pub(super) fn inspect(bytes: &[u8], arch: Option<&str>) -> Result<ImageInfo, ImageError> {
    let (slice, _) = select_macho_slice(bytes, arch)?;
    let offset = (slice.as_ptr() as usize - bytes.as_ptr() as usize) as u64;
    let image = LoadedImage::from_macho(slice, None)?;
    let macho = MachO::parse(slice, 0).map_err(|e| ImageError::Macho(e.to_string()))?;
    let mut info = from_image(slice, &image, offset);
    info.little_endian = macho.little_endian;
    let mut sections = Vec::new();
    for segment in &macho.segments {
        for entry in segment {
            let (s, _) = entry.map_err(|e| ImageError::Macho(e.to_string()))?;
            let zero_fill = matches!(s.flags & 0xff, 1 | 0xc | 0x12);
            let mapped = MappedSection {
                name: format!("{},{}", s.segname().unwrap_or(""), s.name().unwrap_or("")),
                address: s.addr,
                virtual_size: s.size,
                file_offset: u64::from(s.offset),
                file_size: if zero_fill { 0 } else { s.size },
                permissions: Permissions {
                    read: segment.initprot & VM_PROT_READ != 0,
                    write: segment.initprot & VM_PROT_WRITE != 0,
                    execute: segment.initprot & VM_PROT_EXECUTE != 0,
                },
            };
            sections.push(section(slice, &mapped, offset));
        }
    }
    if !sections.is_empty() {
        info.sections = sections;
    }
    let exports = match macho.exports() {
        Ok(exports) => exports,
        Err(error) => {
            info.warnings
                .push(format!("reading Mach-O exports: {error}"));
            Vec::new()
        }
    };
    for export in exports {
        let forward = if let ExportInfo::Reexport {
            lib,
            lib_symbol_name,
            ..
        } = export.info
        {
            Some(format!("{lib}.{}", lib_symbol_name.unwrap_or(&export.name)))
        } else {
            None
        };
        info.exports.push(Export {
            name: export.name.strip_prefix('_').unwrap_or(&export.name).into(),
            va: if forward.is_some() {
                0
            } else {
                image
                    .image_base
                    .checked_add(export.offset)
                    .ok_or(ImageError::AddressOverflow {
                        format: image.format,
                        context: "export address",
                    })?
            },
            forward,
        });
    }
    info.details = details::macho::collect(bytes, slice, offset, macho.little_endian);
    Ok(info)
}
