//! Instruction decoding and compatibility policy.
use super::*;

impl LoadedImage {
    pub fn decode_at(&self, address: u64) -> Result<DecodedInstruction, ImageError> {
        self.decode_with_policy(address, false)
    }

    pub(crate) fn decode_at_compat(&self, address: u64) -> Result<DecodedInstruction, ImageError> {
        self.decode_with_policy(address, true)
    }

    fn decode_with_policy(
        &self,
        address: u64,
        compatibility: bool,
    ) -> Result<DecodedInstruction, ImageError> {
        let section = self
            .section_containing(address)
            .ok_or(ImageError::AddressNotMapped { address })?;
        if !section.permissions.execute || self.is_code_excluded(address) {
            return Err(ImageError::AddressNotExecutable { address });
        }
        if self.architecture.is_risc32() {
            return crate::extract::risc::decode(self, address);
        }
        if self.architecture == Architecture::AArch64 {
            return self.decode_at_aarch64(address);
        }
        let limit = self
            .code_exclusions
            .get(self.code_exclusions.partition_point(|r| r.end <= address))
            .map_or(MAX_INSN_LEN, |r| {
                r.start.saturating_sub(address).min(MAX_INSN_LEN as u64) as usize
            });
        let bytes = self
            .bytes_at(address, limit)
            .ok_or(ImageError::AddressNotMapped { address })?;
        // Vivisect 1.3.2 envi/archs/i386/opcode86.py maps 0x62 to BOUND,
        // including in amd64 and with register ModRM operands. Its decoder
        // has no EVEX prefix. MOV uses the same /r operand layout, so use it
        // to decode that layout with the selected architecture's addressing.
        let opcode_offset = compatibility
            .then(|| {
                bytes.iter().position(|byte| {
                    !(matches!(
                        byte,
                        0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67 | 0xf0 | 0xf2 | 0xf3
                    ) || (self.architecture == Architecture::X64 && (0x40..=0x4f).contains(byte)))
                })
            })
            .flatten();
        // envi/archs/i386/disasm.py:disasm calls getOperValue(0) for
        // INS_TRAP when platform metadata is present. INT1 has no operand,
        // so the pinned decoder rejects it. The amd64 decoder does not
        // perform this check.
        if self.architecture == Architecture::X86
            && matches!(self.format, ImageFormat::Pe | ImageFormat::Elf)
            && opcode_offset.is_some_and(|offset| bytes.get(offset) == Some(&0xf1))
        {
            return Err(ImageError::InvalidInstruction {
                address,
                reason: "INT1 has no operand for the reference i386 platform trap check".into(),
            });
        }
        // opcode86.tbl32_fpuDF_rest (also used by amd64) leaves the
        // undocumented register FFREEP/FSTP aliases undefined.
        if opcode_offset.is_some_and(|offset| {
            bytes.get(offset) == Some(&0xdf)
                && bytes
                    .get(offset + 1)
                    .is_some_and(|modrm| *modrm >= 0xc0 && !matches!(*modrm, 0xe0 | 0xe8..=0xf7))
        }) {
            return Err(ImageError::InvalidInstruction {
                address,
                reason: "undefined DF register opcode in the reference decoder".into(),
            });
        }
        // opcode64's mandatory-prefix 0F tables leave 90..9F undefined.
        // Recent decoders assign AVX-512 mask-register moves to these VEX
        // encodings, but the pinned decoder rejects them.
        let vex_opcode = opcode_offset.and_then(|offset| match bytes.get(offset)? {
            0xc5 => Some((*bytes.get(offset + 1)? & 3, *bytes.get(offset + 2)?)),
            0xc4 if bytes.get(offset + 1)? & 0x1f == 1 => {
                Some((*bytes.get(offset + 2)? & 3, *bytes.get(offset + 3)?))
            }
            _ => None,
        });
        if self.architecture == Architecture::X64
            && vex_opcode
                .is_some_and(|(prefix, opcode)| prefix != 0 && (0x90..=0x9f).contains(&opcode))
        {
            return Err(ImageError::InvalidInstruction {
                address,
                reason: "undefined prefixed VEX opcode in the reference decoder".into(),
            });
        }
        // Union of the defined opcode64 0F38/660F38/F20F38/F30F38
        // entries. The pinned tables predate several AVX2/AVX-512
        // operations accepted by iced-x86, including VPSLLVD (47).
        if self.architecture == Architecture::X64
            && opcode_offset.is_some_and(|offset| {
                bytes.get(offset) == Some(&0xc4)
                    && bytes.get(offset + 1).is_some_and(|map| map & 0x1f == 2)
                    && bytes.get(offset + 3).is_some_and(|opcode| {
                        !matches!(opcode,
                            0x00..=0x10 | 0x13..=0x1a | 0x1c..=0x1e
                            | 0x20..=0x25 | 0x28..=0x40 | 0x58..=0x5a
                            | 0x78..=0x79 | 0x80..=0x82 | 0x96..=0x9f
                            | 0xa6..=0xaf | 0xb6..=0xbf | 0xc8..=0xcd
                            | 0xdb..=0xdf | 0xf0..=0xf3 | 0xf5..=0xf7)
                    })
            })
        {
            return Err(ImageError::InvalidInstruction {
                address,
                reason: "undefined VEX 0F38 opcode in the reference decoder".into(),
            });
        }
        let bound_offset = opcode_offset.filter(|offset| bytes.get(*offset) == Some(&0x62));
        // opcode86 treats C4/C5 as LES/LDS even when ModRM selects a
        // register. It does not reinterpret these bytes as a VEX prefix.
        let far_load_offset = opcode_offset.filter(|offset| {
            self.architecture == Architecture::X86
                && matches!(bytes.get(*offset), Some(0xc4 | 0xc5))
        });
        // The pinned opcode86.tbl32_0F leaves A6/A7 undefined, including
        // VIA PadLock instructions accepted by newer decoders.
        if opcode_offset.is_some_and(|offset| {
            bytes.get(offset) == Some(&0x0f) && matches!(bytes.get(offset + 1), Some(0xa6 | 0xa7))
        }) {
            return Err(ImageError::InvalidInstruction {
                address,
                reason: "opcode is undefined in the reference 0F A6/A7 table".into(),
            });
        }
        // Vivisect 1.3.2 i386 opcode86.tbl32_0F38/660F38/F20F38/F30F38
        // and tbl32_0F3A/660F3A leave these newer SIMD encodings undefined.
        // Check the union of their entries: mandatory-prefix fallback can
        // select the unprefixed table, but cannot define an absent opcode.
        if self.architecture == Architecture::X86
            && opcode_offset.is_some_and(|offset| {
                let opcode = bytes.get(offset + 2).copied();
                bytes.get(offset) == Some(&0x0f)
                    && match bytes.get(offset + 1) {
                        Some(0x38) => opcode.is_some_and(|opcode| {
                            !matches!(opcode,
                            0x00..=0x0b | 0x10 | 0x14..=0x15 | 0x17 | 0x1c..=0x1e
                            | 0x20..=0x25 | 0x28..=0x2b | 0x30..=0x35 | 0x37..=0x3f
                            | 0xdb..=0xdf | 0xf0..=0xf1 | 0xf6)
                        }),
                        Some(0x3a) => opcode.is_some_and(|opcode| {
                            !matches!(opcode, 0x0f | 0x14 | 0x16 | 0x20 | 0x44 | 0x63 | 0xdf)
                        }),
                        _ => false,
                    }
            })
        {
            return Err(ImageError::InvalidInstruction {
                address,
                reason: "opcode is undefined in the reference three-byte SIMD tables".into(),
            });
        }
        // The same opcode table gives C6/C7 and 8F direct MOV/POP entries,
        // ignoring the ModRM extension bits that modern decoders validate.
        let alias_offset = opcode_offset.filter(|offset| {
            matches!(bytes.get(*offset), Some(0xc6 | 0xc7 | 0x8f))
                && bytes.get(offset + 1).is_some_and(|modrm| modrm & 0x38 != 0)
        });
        // opcode86.tbl32_0F uses one NOP operand for 1C..1F, ignoring the
        // ModRM extension. This also covers the older decoding of CET pads.
        let nop_offset = opcode_offset.filter(|offset| {
            bytes.get(*offset) == Some(&0x0f)
                && matches!(bytes.get(offset + 1), Some(0x1c..=0x1f))
                && bytes.get(offset + 2).is_some()
        });
        // envi/archs/i386/disasm.py:ameth_o always consumes ptrsize bytes
        // for A0..A3, even with an address-size prefix. Preserve that extent
        // and displacement by replacing 67 with the effective segment prefix.
        let moffs_offset = opcode_offset.filter(|offset| {
            matches!(bytes.get(*offset), Some(0xa0..=0xa3))
                && bytes
                    .get(..*offset)
                    .is_some_and(|prefixes| prefixes.contains(&0x67))
        });
        // opcode86.py's F20F[D6] uses P,V operands: both read ModRM.reg
        // without consuming ModRM. The amd64 table uses the normal layout.
        let movdq2q_offset = opcode_offset.filter(|offset| {
            self.architecture == Architecture::X86
                && bytes.get(*offset..offset + 2) == Some(&[0x0f, 0xd6])
                && bytes
                    .get(..*offset)
                    .is_some_and(|prefixes| prefixes.contains(&0xf2))
        });
        // opcode64's unprefixed VEX 0F[62] retains the legacy MMX operand
        // layout and adds only a mnemonic prefix. Modern decoders reject it.
        let vex_mmx_offset = opcode_offset.filter(|offset| {
            self.architecture == Architecture::X64
                && bytes.get(*offset) == Some(&0xc5)
                && vex_opcode == Some((0, 0x62))
        });
        let mut legacy_bytes = None;
        if bound_offset.is_some()
            || far_load_offset.is_some()
            || alias_offset.is_some()
            || nop_offset.is_some()
            || moffs_offset.is_some()
            || movdq2q_offset.is_some()
            || vex_mmx_offset.is_some()
        {
            let mut adjusted = bytes.to_vec();
            if let Some(modrm) = movdq2q_offset.and_then(|offset| adjusted.get_mut(offset + 2)) {
                *modrm = 0xc0 | (*modrm & 0x38) | ((*modrm >> 3) & 7);
            }
            if let Some(opcode) = bound_offset.and_then(|offset| adjusted.get_mut(offset)) {
                *opcode = 0x8b;
            }
            if let Some(opcode) = far_load_offset.and_then(|offset| adjusted.get_mut(offset)) {
                *opcode = 0x8b;
            }
            if let Some(modrm) = alias_offset.and_then(|offset| adjusted.get_mut(offset + 1)) {
                *modrm &= !0x38;
            }
            if let Some(offset) = nop_offset {
                if let Some(opcode) = adjusted.get_mut(offset + 1) {
                    *opcode = 0x1f;
                }
                if let Some(modrm) = adjusted.get_mut(offset + 2) {
                    *modrm &= !0x38;
                }
            }
            if let Some(prefixes) = moffs_offset.and_then(|offset| adjusted.get_mut(..offset)) {
                let segment = prefixes
                    .iter()
                    .rev()
                    .copied()
                    .find(|byte| matches!(byte, 0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65))
                    .unwrap_or(0x3e);
                for prefix in prefixes {
                    if *prefix == 0x67 {
                        *prefix = segment;
                    }
                }
            }
            if let Some(offset) = vex_mmx_offset {
                if let Some(prefix) = adjusted.get_mut(offset) {
                    *prefix = 0x0f;
                }
                if offset + 1 < adjusted.len() {
                    adjusted.remove(offset + 1);
                }
            }
            legacy_bytes = Some(adjusted);
        }
        let mut decoder = Decoder::with_ip(
            self.architecture.bitness(),
            legacy_bytes.as_deref().unwrap_or(bytes),
            address,
            if compatibility {
                // envi's i386/amd64 decoder records LOCK without checking
                // whether the opcode supports it (disasm.py:disasm).
                let lock = opcode_offset
                    .and_then(|offset| bytes.get(..offset))
                    .is_some_and(|prefixes| prefixes.contains(&0xf0));
                // The pinned amd64 decoder also accepts a redundant REX
                // before VEX, even though the architecture forbids it.
                let rex_vex = self.architecture == Architecture::X64
                    && opcode_offset.is_some_and(|offset| {
                        matches!(bytes.get(offset), Some(0xc4 | 0xc5))
                            && bytes.get(..offset).is_some_and(|prefixes| {
                                prefixes.iter().any(|byte| (0x40..=0x4f).contains(byte))
                            })
                    });
                DecoderOptions::NO_PAUSE
                    | if lock || rex_vex {
                        DecoderOptions::NO_INVALID_CHECK
                    } else {
                        0
                    }
            } else {
                DecoderOptions::NONE
            },
        );
        let mut instruction = decoder.decode();
        if vex_mmx_offset.is_some() && !instruction.is_invalid() {
            instruction.set_len(instruction.len() + 1);
            instruction.set_next_ip(instruction.next_ip().wrapping_add(1));
        }
        if let Some(offset) = movdq2q_offset.filter(|_| !instruction.is_invalid()) {
            instruction.set_len(offset + 2);
            instruction.set_next_ip(address.wrapping_add((offset + 2) as u64));
        }
        if compatibility
            && self.architecture == Architecture::X86
            && instruction.op0_kind() == iced_x86::OpKind::NearBranch16
        {
            // envi/archs/i386/disasm.py:i386PcRelOper.getOperValue adds the
            // signed displacement to the full instruction VA. An operand-size
            // prefix does not truncate relative targets to 16 bits.
            let offsets = decoder.get_constant_offsets(&instruction);
            let displacement = bytes
                .get(
                    offsets.immediate_offset()
                        ..offsets.immediate_offset() + offsets.immediate_size(),
                )
                .and_then(|raw| match raw {
                    [byte] => Some(i64::from(*byte as i8)),
                    [low, high] => Some(i64::from(i16::from_le_bytes([*low, *high]))),
                    _ => None,
                })
                .ok_or_else(|| ImageError::InvalidInstruction {
                    address,
                    reason: "missing relative branch displacement".into(),
                })?;
            let target = instruction.next_ip().wrapping_add_signed(displacement);
            instruction.set_op0_kind(iced_x86::OpKind::NearBranch32);
            instruction.set_near_branch32(target as u32);
        }
        if bound_offset.is_some() && !instruction.is_invalid() {
            instruction.set_code(if instruction.op0_register().size() == 2 {
                iced_x86::Code::Bound_r16_m1616
            } else {
                iced_x86::Code::Bound_r32_m3232
            });
        }
        if let Some(opcode) = far_load_offset.and_then(|offset| bytes.get(offset)) {
            if !instruction.is_invalid() {
                instruction.set_code(match (*opcode, instruction.op0_register().size()) {
                    (0xc4, 2) => iced_x86::Code::Les_r16_m1616,
                    (0xc4, _) => iced_x86::Code::Les_r32_m1632,
                    (0xc5, 2) => iced_x86::Code::Lds_r16_m1616,
                    _ => iced_x86::Code::Lds_r32_m1632,
                });
            }
        }
        let mut mnemonic_override = vex_mmx_offset.map(|_| "vpunpckldq");
        let instruction = if instruction.is_invalid() {
            let Some((carrier, mnemonic, _)) = decode_undocumented(address, bytes) else {
                return Err(ImageError::InvalidInstruction {
                    address,
                    reason: format!("{:?}", decoder.last_error()),
                });
            };
            mnemonic_override = Some(mnemonic);
            carrier
        } else {
            instruction
        };
        let length = instruction.len();
        let raw = bytes
            .get(..length)
            .ok_or_else(|| ImageError::InvalidInstruction {
                address,
                reason: "decoder consumed beyond the mapped bytes".to_string(),
            })?;
        let mut decoded =
            super::super::decoder::from_x86(address, raw, instruction, mnemonic_override);
        // A kernel trap can return. Native ELF recovery must reach a wrapper's RET
        // instead of declaring every i386 syscall wrapper non-returning. Keep the
        // reference decoder's terminal interrupts in compatibility mode.
        if !compatibility
            && self.format == ImageFormat::Elf
            && self.architecture == Architecture::X86
            && instruction.mnemonic() == iced_x86::Mnemonic::Int
            && instruction.immediate8() == 0x80
        {
            decoded.flow = super::super::decoder::Flow::Next;
        }
        // The amd64 decoder leaves INS_TRAP fallthrough intact. Only the
        // i386 decoder applies the platform-dependent interrupt restriction.
        // INT3 is INS_DEBUG and remains terminal on both architectures.
        if compatibility
            && self.architecture == Architecture::X64
            && matches!(
                instruction.mnemonic(),
                iced_x86::Mnemonic::Int | iced_x86::Mnemonic::Int1
            )
        {
            decoded.flow = super::super::decoder::Flow::Next;
        }
        Ok(decoded)
    }

    /// AArch64 is fixed-width: every instruction is exactly 4 little-endian
    /// bytes, so there is no variable-length-decode failure mode to carry a
    /// fallback for the way `decode_undocumented` does for x86 -- an
    /// unrecognized word is handled inside `decoder::from_aarch64` itself,
    /// never here.
    pub(super) fn decode_at_aarch64(&self, address: u64) -> Result<DecodedInstruction, ImageError> {
        let bytes = self
            .bytes_at(address, 4)
            .ok_or(ImageError::AddressNotMapped { address })?;
        let raw: [u8; 4] = bytes
            .get(..4)
            .and_then(|slice| slice.try_into().ok())
            .ok_or_else(|| ImageError::InvalidInstruction {
                address,
                reason: "fewer than 4 bytes mapped for an AArch64 instruction".to_string(),
            })?;
        let word = u32::from_le_bytes(raw);
        Ok(super::super::decoder::from_aarch64(address, &raw, word))
    }
}

/// `vpcext imm8, imm8` -- Virtual PC's hypercall opcode. envi decodes it
/// (`envi/archs/i386/opcode86.py:357`, the `cpu_VIRTUALPC` row, and
/// `envi/tests/test_arch_i386.py:222`'s `0F3F070B -> vpcext 7,11`); iced-x86
/// has no entry for it and reports `InvalidInstruction`, which truncates the
/// containing function at the hypercall rather than merely losing one
/// mnemonic feature.
const VPCEXT_OPCODE: [u8; 2] = [0x0f, 0x3f];
const VPCEXT_LEN: usize = 4;

/// Decode the opcodes envi knows and iced-x86 does not, so recovery does not
/// stop at them. The returned `Instruction` is a *carrier*: its `code` is
/// meaningless and only its length, `Next` flow control and operand kinds are
/// read -- the mnemonic comes from [`DecodedInstruction::mnemonic_override`].
fn decode_undocumented(address: u64, bytes: &[u8]) -> Option<(Instruction, &'static str, usize)> {
    if bytes.len() < VPCEXT_LEN || bytes[..2] != VPCEXT_OPCODE {
        return None;
    }
    // envi builds two `i386ImmOper`s from the trailing bytes, so
    // `extract_op_number_features` sees `Number(imm)`/`OperandNumber(i, imm)`
    // for both. `enter imm16, imm8` is the carrier because it is the only
    // shape iced-x86 offers that is two immediates wide with `FlowControl::Next`.
    let mut instruction = Instruction::default();
    instruction.set_code(iced_x86::Code::Enterd_imm16_imm8);
    instruction.set_op0_kind(iced_x86::OpKind::Immediate8);
    instruction.set_immediate8(bytes[2]);
    instruction.set_op1_kind(iced_x86::OpKind::Immediate8_2nd);
    instruction.set_immediate8_2nd(bytes[3]);
    instruction.set_len(VPCEXT_LEN);
    instruction.set_ip(address);
    instruction.set_next_ip(address.wrapping_add(VPCEXT_LEN as u64));
    Some((instruction, "vpcext", VPCEXT_LEN))
}

const MAX_INSN_LEN: usize = 15;
