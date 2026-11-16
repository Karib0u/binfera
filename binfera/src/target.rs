//! What a binary was built to run on.
//!
//! The file format says how the bytes are laid out; the target says how to read them: the
//! instruction set, the operating system's calling convention and the pointer width. Code that
//! must branch on "which platform" asks a [`TargetProfile`] instead of testing an architecture
//! or a file format, so adding a platform means adding a profile and its data.
use crate::extract::image::{Architecture, ImageFormat, LoadedImage};

/// The calling convention and system interface a binary expects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Abi {
    /// Windows: the x64 `__fastcall` model, or the x86 stdcall and cdecl family.
    Windows,
    /// System V: the AMD64 psABI as used by Linux and the BSDs, or the i386 one.
    SystemV,
    /// Darwin, including Apple's distinct AArch64 argument layout.
    Darwin,
}

/// The compiler family, where it changes the default calling convention of the code. The system
/// interface stays the platform's: a Delphi program calls Win32 like any other.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Compiler {
    /// The platform's usual compilers (Visual C, MinGW and clang on Windows; gcc and clang on
    /// System V), which share its convention.
    #[default]
    Platform,
    /// Borland Delphi and C++Builder's Pascal: `__register`, arguments in `EAX`, `EDX`, `ECX`.
    Delphi,
    /// Borland C++: a register `__fastcall` default.
    BorlandCpp,
    /// Go: its own register ABI (Go 1.17+ on amd64) or stack ABI, on every platform. Found by the
    /// function table every Go binary carries ([`crate::golang`]), not by the headers.
    Go,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TargetProfile {
    pub architecture: Architecture,
    pub abi: Abi,
    pub compiler: Compiler,
}

impl TargetProfile {
    /// The profile the image's format and architecture imply, assuming the platform's compiler.
    pub fn of(image: &LoadedImage) -> Self {
        let abi = match image.format {
            ImageFormat::Pe => Abi::Windows,
            ImageFormat::Macho => Abi::Darwin,
            _ => Abi::SystemV,
        };
        Self {
            architecture: image.architecture,
            abi,
            compiler: Compiler::Platform,
        }
    }

    /// [`Self::of`], with the compiler of a PE read from its headers (see [`pe_compiler`]).
    pub fn of_pe(image: &LoadedImage, bytes: &[u8]) -> Self {
        let mut profile = Self::of(image);
        if profile.architecture == Architecture::X86 {
            profile.compiler = pe_compiler(bytes);
        }
        profile
    }

    pub fn pointer_bits(self) -> u32 {
        self.architecture.bitness()
    }
}

/// Ghidra's opinion of which compiler built an x86-32 PE (`PeLoader.CompilerOpinion.getOpinion`,
/// Ghidra 12.1.4), reduced to the answers that select a compiler specification for x86-32 in
/// `x86.opinion`: `borland:pascal` selects `x86delphi.cspec` and `borland:c++` or
/// `borland:unknown` select `x86borland.cspec`. Visual Studio, gcc, clang and unknown all load
/// with the Windows specification. Ghidra's answer for Go is not used: a Go binary is recognized by
/// its function table instead ([`crate::golang`]), on every platform and width.
///
/// The evidence is the linker's layout: where the PE header starts, Visual C's Rich header,
/// the DOS stub's code and message (Borland prints "This program must be run under Win32"),
/// and Borland's `CODE` section. The checks run in Ghidra's order, with its fall-through.
pub fn pe_compiler(bytes: &[u8]) -> Compiler {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Opinion {
        Unknown,
        GccVs,
        Clang,
        GccVsClang,
        Pascal,
        Cpp,
        BorlandUnknown,
    }
    const BORLAND_MESSAGE: &[u8] = b"This program must be run under Win32\r\n$";
    const GCC_VS_MESSAGE: &[u8] = b"This program cannot be run in DOS mode.\r\r\n$";
    const CLANG_MESSAGE: &[u8] = b"This program cannot be run in DOS mode.$";
    const BORLAND_STUB: &[u8] = &[
        0xba, 0x10, 0x00, 0x0e, 0x1f, 0xb4, 0x09, 0xcd, 0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21, 0x90,
        0x90,
    ];
    const GCC_VS_CLANG_STUB: &[u8] = &[
        0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd, 0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21,
    ];
    let u16_at = |at: usize| {
        bytes
            .get(at..at + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
    };
    let u32_at = |at: usize| {
        bytes
            .get(at..at + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let decide = |opinion: Opinion| match opinion {
        Opinion::Pascal => Compiler::Delphi,
        Opinion::Cpp | Opinion::BorlandUnknown => Compiler::BorlandCpp,
        _ => Compiler::Platform,
    };
    let Some(e_lfanew) = u32_at(0x3c).map(|v| v as usize) else {
        return Compiler::Platform;
    };
    let section = |wanted: &[u8]| {
        let (Some(count), Some(optional)) = (u16_at(e_lfanew + 6), u16_at(e_lfanew + 20)) else {
            return false;
        };
        let table = e_lfanew + 24 + optional as usize;
        (0..count as usize).any(|i| {
            bytes
                .get(table + 40 * i..table + 40 * i + 8)
                .is_some_and(|name| {
                    let end = name.iter().position(|&b| b == 0).unwrap_or(8);
                    &name[..end] == wanted
                })
        })
    };

    let mut offset = Opinion::Unknown;
    if e_lfanew == 0x80 {
        offset = Opinion::GccVs;
    } else if e_lfanew == 0x78 {
        offset = Opinion::Clang;
    } else if e_lfanew >= 0x80 {
        let (first, second) = (u32_at(0x80).unwrap_or(0), u32_at(0x84).unwrap_or(0));
        if first != 0 && second != 0 && first ^ second == 0x536e_6144 {
            // "DanS": the Rich header Visual C's linker writes.
            return Compiler::Platform;
        }
        match e_lfanew {
            0x100 => offset = Opinion::Pascal, // or Borland C
            0x200 => offset = Opinion::Cpp,
            n if n > 0x300 => return Compiler::Platform,
            _ => {}
        }
    }

    // Ghidra reads 256 bytes after the DOS header and gives no opinion on a shorter file.
    let Some(stub) = bytes.get(0x40..0x140) else {
        return Compiler::Platform;
    };
    let mut asm = if stub.starts_with(BORLAND_STUB) {
        Opinion::BorlandUnknown
    } else if stub.starts_with(GCC_VS_CLANG_STUB) {
        Opinion::GccVsClang
    } else {
        Opinion::Unknown
    };
    let mut message = Opinion::Unknown;
    match stub.windows(4).position(|w| w == b"This") {
        None => asm = Opinion::Unknown,
        Some(at) => {
            // Ghidra's comparison needs the whole message strictly inside the 256 bytes.
            let says = |text: &[u8]| at + text.len() < stub.len() && stub[at..].starts_with(text);
            if says(BORLAND_MESSAGE) {
                if matches!(offset, Opinion::Cpp | Opinion::Pascal) {
                    return decide(offset);
                }
                message = Opinion::BorlandUnknown;
            } else if says(GCC_VS_MESSAGE) {
                message = Opinion::GccVs;
            } else if says(CLANG_MESSAGE) {
                message = Opinion::Clang;
            }
        }
    }

    if message == Opinion::GccVs && asm == Opinion::GccVsClang && e_lfanew == 0x80 {
        // Ghidra tells Go and gcc apart here (a symbol table pointer means gcc); this answer
        // keeps the Windows specification, and Go is found by its function table instead.
        if u32_at(e_lfanew + 12).is_some_and(|symbols| symbols != 0) {
            return Compiler::Platform;
        }
    } else if (offset == Opinion::Clang || message == Opinion::Clang) && asm == Opinion::GccVsClang
        // Clang, then Ghidra's unknown.
        || message == Opinion::Unknown
        || asm == Opinion::Unknown
    {
        return Compiler::Platform;
    }
    if message == Opinion::BorlandUnknown || asm == Opinion::BorlandUnknown {
        return decide(Opinion::BorlandUnknown);
    }
    if section(b"CODE") {
        return decide(Opinion::Pascal); // could also be Borland C
    }
    if section(b".bss") || !section(b".idata") {
        return Compiler::Platform;
    }
    if section(b".tls") {
        return decide(Opinion::Cpp);
    }
    Compiler::Platform
}

#[cfg(test)]
mod tests {
    use super::{pe_compiler, Compiler};

    /// A PE32 prefix: the DOS header with `e_lfanew`, the stub at 0x40, and a file header with
    /// the given section names.
    fn image(e_lfanew: usize, stub: &[u8], sections: &[&[u8]]) -> Vec<u8> {
        let mut bytes = vec![0u8; e_lfanew + 24 + 0xe0 + 40 * sections.len()];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&(e_lfanew as u32).to_le_bytes());
        bytes[0x40..0x40 + stub.len()].copy_from_slice(stub);
        bytes[e_lfanew..e_lfanew + 4].copy_from_slice(b"PE\0\0");
        bytes[e_lfanew + 6..e_lfanew + 8].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        bytes[e_lfanew + 20..e_lfanew + 22].copy_from_slice(&0xe0u16.to_le_bytes());
        for (i, name) in sections.iter().enumerate() {
            let at = e_lfanew + 24 + 0xe0 + 40 * i;
            bytes[at..at + name.len()].copy_from_slice(name);
        }
        bytes
    }

    fn borland_stub() -> Vec<u8> {
        let mut stub = vec![
            0xba, 0x10, 0x00, 0x0e, 0x1f, 0xb4, 0x09, 0xcd, 0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21,
            0x90, 0x90,
        ];
        stub.extend_from_slice(b"This program must be run under Win32\r\n$");
        stub
    }

    fn msvc_stub() -> Vec<u8> {
        let mut stub = vec![
            0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd, 0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21,
        ];
        stub.extend_from_slice(b"This program cannot be run in DOS mode.\r\r\n$");
        stub
    }

    #[test]
    fn delphi_layout_is_pascal() {
        let bytes = image(
            0x100,
            &borland_stub(),
            &[b"CODE", b"DATA", b"BSS", b".idata"],
        );
        assert_eq!(pe_compiler(&bytes), Compiler::Delphi);
    }

    #[test]
    fn borland_cpp_layout_is_cpp() {
        let bytes = image(0x200, &borland_stub(), &[b".text", b".data", b".tls"]);
        assert_eq!(pe_compiler(&bytes), Compiler::BorlandCpp);
    }

    #[test]
    fn borland_stub_without_the_offsets_is_borland_cpp() {
        let bytes = image(0x80, &borland_stub(), &[b"CODE"]);
        assert_eq!(pe_compiler(&bytes), Compiler::BorlandCpp);
    }

    #[test]
    fn rich_header_is_visual_c() {
        let mut bytes = image(0x100, &borland_stub(), &[b"CODE"]);
        bytes[0x80..0x84].copy_from_slice(&1u32.to_le_bytes());
        bytes[0x84..0x88].copy_from_slice(&(1u32 ^ 0x536e_6144).to_le_bytes());
        assert_eq!(pe_compiler(&bytes), Compiler::Platform);
    }

    #[test]
    fn visual_c_stub_is_the_platform_compiler() {
        let bytes = image(0xe8, &msvc_stub(), &[b".text", b".rdata", b".data"]);
        assert_eq!(pe_compiler(&bytes), Compiler::Platform);
    }

    #[test]
    fn a_code_section_with_a_visual_c_stub_is_pascal() {
        // Ghidra's fall-through: no Rich header, a Visual C stub, and Borland's section name.
        let bytes = image(0xe8, &msvc_stub(), &[b"CODE", b".idata"]);
        assert_eq!(pe_compiler(&bytes), Compiler::Delphi);
    }

    #[test]
    fn truncated_input_is_the_platform_compiler() {
        assert_eq!(pe_compiler(b"MZ"), Compiler::Platform);
        assert_eq!(pe_compiler(&[]), Compiler::Platform);
    }
}
