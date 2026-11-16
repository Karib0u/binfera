use std::collections::BTreeSet;

use iced_x86::{Decoder, DecoderOptions, FlowControl, Mnemonic, Register};
use serde::Serialize;

use super::{from_image, Architecture, ImageError, ImageInfo, LoadedImage};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShellcodeInfo {
    pub ambiguous: bool,
    pub x86_score: i32,
    pub x64_score: i32,
    pub os: Option<String>,
    pub evidence: Vec<String>,
}

/// Inspect entry-reachable raw code. Explicit selection also accepts code that cannot be guessed.
pub fn inspect_shellcode(bytes: &[u8], wide: Option<bool>) -> Result<ImageInfo, ImageError> {
    if bytes.is_empty() {
        return Err(ImageError::UnsupportedFormat);
    }
    let guessed = wide.is_none();
    let x86 = probe(bytes, 32);
    let x64 = probe(bytes, 64);
    if guessed
        && (x86.score().max(x64.score()) < 100
            || bytes.iter().take(4096).all(|&b| b == 0 || b == 0xff)
            || bytes
                .iter()
                .take(4096)
                .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace()))
    {
        return Err(ImageError::UnsupportedFormat);
    }
    let wide = wide.unwrap_or(x64.score() > x86.score());
    let selected = if wide { &x64 } else { &x86 };
    let ambiguous = (x64.score() - x86.score()).abs() < 100;
    let mut info = from_image(
        bytes,
        &LoadedImage::from_shellcode_at(
            bytes,
            if wide {
                Architecture::X64
            } else {
                Architecture::X86
            },
            0,
        ),
        0,
    );
    info.format = if wide { "sc64" } else { "sc32" }.into();
    info.shellcode = Some(ShellcodeInfo {
        ambiguous,
        x86_score: x86.score(),
        x64_score: x64.score(),
        os: match (selected.windows, selected.linux) {
            (true, false) => Some("windows".into()),
            (false, true) => Some("linux".into()),
            _ => None,
        },
        evidence: selected.evidence.iter().map(|s| (*s).into()).collect(),
    });
    info.warnings.push(if guessed {
        format!(
            "Possible shellcode: {} guess{}. Entry is assumed at offset 0 of the selected bytes. Architecture and calling convention can be changed.",
            if wide { "x64" } else { "x86" },
            if ambiguous { " (ambiguous decoding)" } else { "" },
        )
    } else {
        "Raw code: entry is assumed at offset 0 of the selected bytes.".into()
    });
    Ok(info)
}

#[derive(Default)]
struct Probe {
    instructions: i32,
    useful: i32,
    points: i32,
    windows: bool,
    linux: bool,
    evidence: BTreeSet<&'static str>,
}

impl Probe {
    fn score(&self) -> i32 {
        if self.useful == 0 {
            return -1000;
        }
        // Compare quality per instruction, so producing more instructions cannot win by count.
        self.points * 100 / self.instructions.max(1)
    }
}

/// At most 1024 instructions in the first 64 KiB. NOP padding is not architecture evidence.
fn probe(bytes: &[u8], bits: u32) -> Probe {
    let bytes = &bytes[..bytes.len().min(65536)];
    let mut pending = vec![0usize];
    let mut seen = BTreeSet::new();
    let mut out = Probe::default();
    while let Some(mut at) = pending.pop() {
        while at < bytes.len() && seen.len() < 1024 {
            // A long single-byte NOP sled should not consume the entire instruction budget.
            while bytes.get(at) == Some(&0x90) {
                at += 1;
            }
            if at == bytes.len() || !seen.insert(at) {
                break;
            }
            let mut decoder = Decoder::with_ip(bits, &bytes[at..], at as u64, DecoderOptions::NONE);
            let insn = decoder.decode();
            if insn.is_invalid() {
                out.points -= 16;
                break;
            }
            if insn.mnemonic() != Mnemonic::Nop {
                out.instructions += 1;
                out.useful += 1;
                out.points += 4;
            }
            if insn.is_privileged()
                || matches!(
                    insn.mnemonic(),
                    Mnemonic::Int3 | Mnemonic::Hlt | Mnemonic::In | Mnemonic::Out
                )
            {
                out.points -= 16;
                out.useful -= 1;
            }
            if bits == 64 {
                if insn.is_ip_rel_memory_operand() {
                    out.points += 6;
                    out.evidence.insert("RIP-relative addressing");
                }
                // Decoded operands include instructions with legacy prefixes before REX.
                if !matches!(
                    insn.mnemonic(),
                    Mnemonic::Push | Mnemonic::Pop | Mnemonic::Call | Mnemonic::Jmp
                ) && (0..insn.op_count()).any(|n| insn.op_register(n).is_gpr64())
                {
                    out.points += 3;
                    out.evidence.insert("64-bit registers");
                }
                if insn.op0_register() == Register::ESP
                    || (insn.op0_register() == Register::EBP
                        && insn.op1_register() == Register::ESP)
                {
                    out.points -= 12;
                }
            } else {
                if insn.memory_base() == Register::ESP || insn.memory_base() == Register::EBP {
                    out.points += 3;
                    out.evidence.insert("32-bit stack addressing");
                }
                if matches!(bytes[at], 0x40..=0x4f) {
                    out.points -= 1;
                }
            }
            if insn.mnemonic() == Mnemonic::Int && insn.immediate8() == 0x80 {
                out.linux = true;
                out.points += if bits == 32 { 8 } else { 0 };
                out.evidence.insert("Linux int 0x80");
            }
            if (insn.segment_prefix() == Register::FS && insn.memory_displacement64() == 0x30)
                || (insn.segment_prefix() == Register::GS && insn.memory_displacement64() == 0x60)
            {
                out.windows = true;
                out.points += 4;
                out.evidence.insert("Windows PEB access");
            }
            if insn.mnemonic() == Mnemonic::Syscall {
                out.points += if bits == 64 { 8 } else { -8 };
                out.evidence.insert("SYSCALL instruction");
                // SYSCALL alone does not establish Linux versus Windows.
            }
            match insn.flow_control() {
                FlowControl::ConditionalBranch
                | FlowControl::UnconditionalBranch
                | FlowControl::Call => {
                    let target = insn.near_branch_target();
                    if target < bytes.len() as u64 {
                        pending.push(target as usize);
                    } else if insn.flow_control() != FlowControl::Call {
                        out.points -= 8;
                    }
                    if insn.flow_control() == FlowControl::UnconditionalBranch {
                        break;
                    }
                }
                FlowControl::Return | FlowControl::IndirectBranch | FlowControl::Exception => break,
                _ => {}
            }
            at += insn.len();
        }
    }
    out
}
