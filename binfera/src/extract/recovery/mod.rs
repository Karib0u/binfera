mod engine;
pub use engine::*;

mod arm_unwind;
mod callbacks;
mod eh_frame;
#[cfg(feature = "decompiler")]
pub(crate) fn elf_unwind_ranges(
    bytes: &[u8],
    image: &image::LoadedImage,
) -> std::collections::BTreeMap<u64, u64> {
    let mut ranges = eh_frame::ranges(bytes, image);
    for entry in arm_unwind::read(bytes, image).entries {
        ranges.entry(entry.start).or_insert(entry.end);
    }
    ranges
}
mod emucode;
pub mod flirt;
pub mod golang;
pub(crate) mod idioms;
pub mod listing;
pub mod libc_start_main;
pub mod msvcfunc;
pub mod noreturn;
mod pointers;
mod prologues;
mod switch;

pub(crate) use super::{
    aarch64_basicblock_features, aarch64_features, basicblock_features, decoder, function_features,
    image, importcalls, insn_features,
};
