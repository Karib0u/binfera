//! Classic MSVC C++ exception metadata (FuncInfo versions 1, 2 and 3).
//!
//! Layouts follow Ghidra 12.1.4's EHFunctionInfoModel, EHTryBlockModel,
//! EHHandlerTypeModel, EHUnwindModel and EHIPToStateModel. On x86, a frame
//! handler stub loads FuncInfo into EAX. On x64, UNWIND_INFO's language data
//! points to it with an image-relative 32-bit reference. FH4 is a different,
//! compressed format and is reported when its imported handler is recognized.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use iced_x86::{Mnemonic, OpKind};
use serde::Serialize;

use crate::extract::image::{Architecture, ImageFormat, LoadedImage};
use crate::extract::recovery::Analysis;

// Ghidra's PEExceptionAnalyzer uses 16000 entries per map. Also bound total
// work across candidates, so repeated aliases cannot multiply allocations.
const MAX_ENTRIES: u32 = 16_000;
const MAX_WORK: usize = 1_000_000;
const MAX_CANDIDATES: usize = 16_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UnwindAction {
    pub state: i32,
    pub to_state: i32,
    pub action: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CatchHandler {
    pub address: u64,
    pub adjectives: u32,
    pub type_descriptor: Option<u64>,
    /// `...` for a catch-all, a demangled class or the descriptor's encoding.
    pub catch_type: String,
    pub catch_object_displacement: i32,
    pub frame_displacement: Option<i32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TryBlock {
    pub low: i32,
    pub high: i32,
    pub catch_high: i32,
    pub handlers: Vec<CatchHandler>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IpState {
    pub address: u64,
    pub state: i32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FunctionInfo {
    pub address: u64,
    pub magic: u32,
    pub bbt_flags: u32,
    pub eh_flags: Option<u32>,
    pub unwind_help_displacement: Option<i32>,
    pub owners: BTreeSet<u64>,
    pub frame_handlers: BTreeSet<u64>,
    pub unwind: Vec<UnwindAction>,
    pub try_blocks: Vec<TryBlock>,
    pub ip_states: Vec<IpState>,
    /// Runtime-function extents, including catch funclets and chained fragments.
    pub code_ranges: Vec<Range<u64>>,
}

impl FunctionInfo {
    /// Half-open address ranges for a try block. x86 usually has only state
    /// numbers; an empty result deliberately does not invent address bounds.
    pub fn protected_ranges(&self, block: &TryBlock) -> Vec<Range<u64>> {
        let mut ranges: Vec<Range<u64>> = Vec::new();
        for extent in &self.code_ranges {
            for (index, entry) in self.ip_states.iter().enumerate() {
                if entry.state < block.low || entry.state > block.high {
                    continue;
                }
                let start = entry.address.max(extent.start);
                let end = self
                    .ip_states
                    .get(index + 1)
                    .map_or(extent.end, |next| next.address)
                    .min(extent.end);
                if start < end {
                    if let Some(previous) = ranges.last_mut().filter(|r| r.end == start) {
                        previous.end = end;
                    } else {
                        ranges.push(start..end);
                    }
                }
            }
        }
        ranges
    }

    pub fn targets(&self) -> impl Iterator<Item = u64> + '_ {
        self.frame_handlers
            .iter()
            .copied()
            .chain(self.unwind.iter().filter_map(|entry| entry.action))
            .chain(
                self.try_blocks
                    .iter()
                    .flat_map(|block| block.handlers.iter().map(|h| h.address)),
            )
    }
}

#[derive(Clone, Debug, Default)]
pub struct ExceptionInfo {
    pub functions: BTreeMap<u64, FunctionInfo>,
    pub diagnostics: Vec<String>,
    pub(crate) data_ranges: Vec<Range<u64>>,
}

impl ExceptionInfo {
    pub fn read(image: &LoadedImage) -> Self {
        if image.format != ImageFormat::Pe
            || !matches!(image.architecture, Architecture::X86 | Architecture::X64)
        {
            return Self::default();
        }
        let mut reader = Reader {
            image,
            wide: image.architecture == Architecture::X64,
            work: MAX_WORK,
            attempted: BTreeSet::new(),
            limit_reported: false,
        };
        let mut result = Self::default();
        if reader.wide {
            reader.read_x64(&mut result);
        } else {
            reader.read_x86(&mut result);
        }
        result.diagnostics.sort();
        result.diagnostics.dedup();
        result
    }

    /// Associate x86 stubs with the function installing them. x64 ownership is
    /// supplied by the exception directory. Shared funclets retain all owners.
    pub fn link_functions(&mut self, analysis: &Analysis) {
        if analysis.image.architecture != Architecture::X86 {
            return;
        }
        let stubs: BTreeMap<u64, u64> = self
            .functions
            .iter()
            .flat_map(|(address, info)| {
                info.frame_handlers
                    .iter()
                    .map(move |stub| (*stub, *address))
            })
            .collect();
        for function in analysis.functions.values() {
            for insn in function.blocks.iter().flat_map(|block| &block.insns) {
                let instruction = insn.x86_instruction();
                if !matches!(instruction.mnemonic(), Mnemonic::Push | Mnemonic::Mov) {
                    continue;
                }
                for operand in 0..instruction.op_count() {
                    if instruction.op_kind(operand) != OpKind::Immediate32 {
                        continue;
                    }
                    if let Some(info) = stubs
                        .get(&u64::from(instruction.immediate32()))
                        .and_then(|address| self.functions.get_mut(address))
                    {
                        if !info.frame_handlers.contains(&function.addr) {
                            info.owners.insert(function.addr);
                        }
                    }
                }
            }
        }
    }

    /// Stable fallback labels; callers retain names supplied by symbols/debug info.
    pub fn names(&self) -> BTreeMap<u64, String> {
        let mut names = BTreeMap::new();
        for info in self.functions.values() {
            let owner = info.owners.first().copied().unwrap_or(info.address);
            for address in &info.frame_handlers {
                names
                    .entry(*address)
                    .or_insert_with(|| format!("eh_frame_{owner:x}_{address:x}"));
            }
            for block in &info.try_blocks {
                for handler in &block.handlers {
                    names
                        .entry(handler.address)
                        .or_insert_with(|| format!("catch_{owner:x}_{:x}", handler.address));
                }
            }
            for entry in &info.unwind {
                if let Some(address) = entry.action {
                    names
                        .entry(address)
                        .or_insert_with(|| format!("unwind_{owner:x}_{address:x}"));
                }
            }
        }
        names
    }

    pub fn for_function(&self, address: u64) -> Vec<FunctionInfo> {
        self.functions
            .values()
            .filter(|info| {
                info.owners.contains(&address) || info.targets().any(|target| target == address)
            })
            .cloned()
            .collect()
    }

    /// Exception-table targets strictly inside an owner's recovered body are
    /// labels in that body. Out-of-line helpers remain functions.
    pub fn contained_funclets(&self, analysis: &Analysis) -> BTreeMap<u64, u64> {
        let mut labels = BTreeMap::new();
        for info in self.functions.values() {
            let mut targets: BTreeSet<_> = info
                .unwind
                .iter()
                .filter_map(|u| u.action)
                .chain(
                    info.try_blocks
                        .iter()
                        .flat_map(|b| b.handlers.iter().map(|h| h.address)),
                )
                .collect();
            if analysis.image.architecture == Architecture::X86 {
                for handler in info.try_blocks.iter().flat_map(|b| &b.handlers) {
                    targets.extend(catch_continuations(analysis, handler.address));
                }
            }
            for owner in &info.owners {
                let Some(function) = analysis.functions.get(owner) else {
                    continue;
                };
                let end = function
                    .blocks
                    .iter()
                    .flat_map(|b| &b.insns)
                    .map(|i| i.next_address)
                    .max()
                    .unwrap_or(*owner);
                for &target in &targets {
                    if *owner < target && target < end {
                        // A shared FuncInfo can describe several parents. Use
                        // the nearest enclosing owner, not the first table user.
                        labels
                            .entry(target)
                            .and_modify(|old: &mut u64| {
                                *old = (*old).max(*owner);
                            })
                            .or_insert(*owner);
                    }
                }
            }
        }
        labels
    }

    /// Comments preserve the table's state model without suggesting the native
    /// decompiler reconstructed C++ exceptional control-flow edges.
    pub fn comments(&self, address: u64) -> Vec<String> {
        let mut lines = Vec::new();
        for info in self.functions.values().filter(|info| {
            info.owners.contains(&address) || info.targets().any(|target| target == address)
        }) {
            let owners = info
                .owners
                .iter()
                .map(|owner| format!("{owner:#x}"))
                .collect::<Vec<_>>()
                .join(", ");
            lines.push(format!(
                "MSVC C++ EH FuncInfo {:#x}; owner(s): {}",
                info.address,
                if owners.is_empty() {
                    "unresolved"
                } else {
                    &owners
                }
            ));
            for block in &info.try_blocks {
                let ranges = info
                    .protected_ranges(block)
                    .iter()
                    .map(|range| format!("[{:#x}, {:#x})", range.start, range.end))
                    .collect::<Vec<_>>()
                    .join(", ");
                lines.push(format!(
                    "try states {}..{}; catch states through {}{}",
                    block.low,
                    block.high,
                    block.catch_high,
                    if ranges.is_empty() {
                        String::new()
                    } else {
                        format!("; protected {ranges}")
                    }
                ));
                for handler in &block.handlers {
                    // A binary's type name must not terminate a generated comment.
                    let name = handler
                        .catch_type
                        .replace("*/", "* / ")
                        .replace(['\r', '\n'], " ");
                    lines.push(format!("catch ({name}) -> {:#x}", handler.address));
                }
            }
            for action in &info.unwind {
                if let Some(target) = action.action {
                    lines.push(format!(
                        "unwind state {} -> {}: {target:#x}",
                        action.state, action.to_state
                    ));
                }
            }
        }
        lines
    }
}

/// An x86 catch returns the address where the runtime resumes its parent.
/// Only accept a literal EAX result immediately followed by RET, in bounded
/// local handler flow. Ordinary function-pointer returns are never scanned.
fn catch_continuations(analysis: &Analysis, handler: u64) -> BTreeSet<u64> {
    use crate::extract::decoder::Flow;
    use iced_x86::Register;
    let mut targets = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let mut pending = vec![handler];
    while let Some(address) = pending.pop() {
        if seen.len() >= 256 || address.abs_diff(handler) > 1024 || !seen.insert(address) {
            continue;
        }
        let Ok(insn) = analysis.image.decode_at(address) else {
            continue;
        };
        let op = insn.x86_instruction();
        if op.mnemonic() == Mnemonic::Mov
            && op.op0_register() == Register::EAX
            && op.op1_kind() == OpKind::Immediate32
            && analysis
                .image
                .decode_at(insn.next_address)
                .is_ok_and(|i| i.flow == Flow::Return)
        {
            let target = u64::from(op.immediate32());
            if analysis.image.is_executable_address(target) {
                targets.insert(target);
            }
        }
        if analysis.noreturn_calls.contains(&address) {
            continue;
        }
        match insn.flow {
            Flow::Next | Flow::Call | Flow::IndirectCall => pending.push(insn.next_address),
            Flow::ConditionalBranch => {
                pending.push(insn.next_address);
                pending.extend(insn.direct_target);
            }
            Flow::UnconditionalBranch => pending.extend(insn.direct_target),
            _ => {}
        }
    }
    targets
}

struct Reader<'a> {
    image: &'a LoadedImage,
    wide: bool,
    work: usize,
    attempted: BTreeSet<u64>,
    limit_reported: bool,
}

impl Reader<'_> {
    // Unlike bytes_at, metadata reads may not consume loader-created zero fill.
    fn bytes(&self, address: u64, size: usize) -> Option<&[u8]> {
        address.checked_add(size as u64)?;
        let section = self
            .image
            .sections
            .iter()
            .find(|section| section.contains_va(address))?;
        let offset = address.checked_sub(section.address)?;
        if offset.checked_add(size as u64)? > section.file_size {
            return None;
        }
        self.image
            .bytes_at(address, size)
            .filter(|bytes| bytes.len() == size)
    }
    fn word(&self, address: u64) -> Option<u32> {
        Some(u32::from_le_bytes(self.bytes(address, 4)?.try_into().ok()?))
    }
    fn reference(&self, address: u64) -> Option<Option<u64>> {
        let value = self.word(address)?;
        if value == 0 {
            return Some(None);
        }
        Some(Some(if self.wide {
            self.image.image_base.checked_add(u64::from(value))?
        } else {
            u64::from(value)
        }))
    }
    fn code(&self, address: u64) -> bool {
        self.image.is_primary_code_address(address) && self.bytes(address, 1).is_some()
    }
    fn table(
        &mut self,
        address: u64,
        count: u32,
        stride: usize,
        ranges: &mut Vec<Range<u64>>,
    ) -> Option<()> {
        if count > MAX_ENTRIES {
            return None;
        }
        let cost = count as usize + 1;
        if cost > self.work {
            self.work = 0;
            return None;
        }
        self.work -= cost;
        if count == 0 {
            return Some(());
        }
        let size = (count as usize).checked_mul(stride)?;
        self.bytes(address, size)?;
        ranges.push(address..address.checked_add(size as u64)?);
        Some(())
    }
    fn catch_type(&self, address: u64) -> Option<String> {
        let start = address.checked_add(if self.wide { 16 } else { 8 })?;
        let mut bytes = Vec::new();
        for offset in 0..1024 {
            let byte = *self.bytes(start.checked_add(offset)?, 1)?.first()?;
            if byte == 0 {
                let name = std::str::from_utf8(&bytes).ok()?;
                // Rust's MSVC unwinder uses an unmangled synthetic type descriptor.
                if !(name.starts_with('.') || name == "rust_panic")
                    || !name.is_ascii()
                    || name.bytes().any(|b| b.is_ascii_control())
                {
                    return None;
                }
                return Some(
                    crate::demangle::type_descriptor_class(name).unwrap_or_else(|| match name {
                        ".H" | ".?AH" => "int".into(),
                        ".I" | ".?AI" => "unsigned int".into(),
                        ".N" | ".?AN" => "double".into(),
                        _ => name.to_owned(),
                    }),
                );
            }
            bytes.push(byte);
        }
        None
    }
    fn parse(&mut self, address: u64) -> Option<(FunctionInfo, Vec<Range<u64>>)> {
        let flags = self.word(address)?;
        let magic = flags & 0x1fff_ffff;
        if !(0x1993_0520..=0x1993_0522).contains(&magic) {
            return None;
        }
        let version = magic - 0x1993_0520;
        let size = 28 + u64::from(self.wide) * 4 + u64::from(version) * 4;
        self.bytes(address, size as usize)?;
        let mut ranges = Vec::new();
        ranges.push(address..address.checked_add(size)?);
        let max_state = self.word(address + 4)?;
        let unwind_map = self.reference(address + 8)?;
        let n_try = self.word(address + 12)?;
        let try_map = self.reference(address + 16)?;
        let n_ip = self.word(address + 20)?;
        let ip_map = self.reference(address + 24)?;
        if max_state == 0 && n_try == 0 && n_ip == 0 {
            return None;
        }
        self.table(unwind_map.unwrap_or(0), max_state, 8, &mut ranges)?;
        self.table(try_map.unwrap_or(0), n_try, 20, &mut ranges)?;
        self.table(ip_map.unwrap_or(0), n_ip, 8, &mut ranges)?;
        let mut info = FunctionInfo {
            address,
            magic,
            bbt_flags: flags >> 29,
            eh_flags: if version == 2 {
                Some(self.word(address + size - 4)?)
            } else {
                None
            },
            unwind_help_displacement: if self.wide {
                Some(self.word(address + 28)? as i32)
            } else {
                None
            },
            owners: BTreeSet::new(),
            frame_handlers: BTreeSet::new(),
            unwind: Vec::new(),
            try_blocks: Vec::new(),
            ip_states: Vec::new(),
            code_ranges: Vec::new(),
        };
        for state in 0..max_state {
            let entry = unwind_map? + u64::from(state) * 8;
            let to_state = self.word(entry)? as i32;
            if to_state < -1 || to_state >= state as i32 {
                return None;
            }
            let action = self.reference(entry + 4)?;
            if action.is_some_and(|target| !self.code(target)) {
                return None;
            }
            info.unwind.push(UnwindAction {
                state: state as i32,
                to_state,
                action,
            });
        }
        for index in 0..n_try {
            let entry = try_map? + u64::from(index) * 20;
            let low = self.word(entry)? as i32;
            let high = self.word(entry + 4)? as i32;
            let catch_high = self.word(entry + 8)? as i32;
            if low < 0 || low > high || high > catch_high || catch_high >= max_state as i32 {
                return None;
            }
            let count = self.word(entry + 12)?;
            if count == 0 {
                return None;
            }
            let handlers = self.reference(entry + 16)??;
            let stride = if self.wide { 20 } else { 16 };
            self.table(handlers, count, stride, &mut ranges)?;
            let mut block = TryBlock {
                low,
                high,
                catch_high,
                handlers: Vec::new(),
            };
            for index in 0..count {
                let handler = handlers + u64::from(index) * stride as u64;
                let adjectives = self.word(handler)?;
                let descriptor = self.reference(handler + 4)?;
                let catch_type = match descriptor {
                    Some(address) => self.catch_type(address)?,
                    None => "...".into(),
                };
                if catch_type.len() > self.work {
                    self.work = 0;
                    return None;
                }
                self.work -= catch_type.len();
                let target = self.reference(handler + 12)??;
                if !self.code(target) {
                    return None;
                }
                block.handlers.push(CatchHandler {
                    address: target,
                    adjectives,
                    type_descriptor: descriptor,
                    catch_type,
                    catch_object_displacement: self.word(handler + 8)? as i32,
                    frame_displacement: if self.wide {
                        Some(self.word(handler + 16)? as i32)
                    } else {
                        None
                    },
                });
            }
            info.try_blocks.push(block);
        }
        for index in 0..n_ip {
            let entry = ip_map? + u64::from(index) * 8;
            let ip = self.reference(entry)??;
            let state = self.word(entry + 4)? as i32;
            if state < -1
                || state >= max_state as i32
                || !self.code(ip)
                || info
                    .ip_states
                    .last()
                    .is_some_and(|previous| previous.address >= ip)
            {
                return None;
            }
            info.ip_states.push(IpState { address: ip, state });
        }
        // Dynamic exception specifications use a HandlerType array too. Reject
        // a non-null list until it can be represented, rather than mislabel it.
        if version >= 1
            && self
                .reference(address + 28 + u64::from(self.wide) * 4)?
                .is_some()
        {
            return None;
        }
        if info
            .targets()
            .any(|target| ranges.iter().any(|range| range.contains(&target)))
        {
            return None;
        }
        Some((info, ranges))
    }

    fn add(&mut self, result: &mut ExceptionInfo, address: u64) -> bool {
        if result.functions.contains_key(&address) {
            return true;
        }
        if self.attempted.len() >= MAX_CANDIDATES || self.work == 0 {
            if !self.limit_reported {
                result
                    .diagnostics
                    .push("MSVC C++ exception parsing exceeded its work limit".into());
                self.limit_reported = true;
            }
            return false;
        }
        if !self.attempted.insert(address) {
            return false;
        }
        if let Some((info, ranges)) = self.parse(address) {
            result.functions.insert(address, info);
            result.data_ranges.extend(ranges);
            true
        } else {
            result.diagnostics.push(format!(
                "Invalid or unsupported MSVC C++ FuncInfo at {address:#x}"
            ));
            false
        }
    }

    fn read_x86(&mut self, result: &mut ExceptionInfo) {
        let mut candidates = 0;
        for section in &self.image.sections {
            if !self.image.is_primary_code_address(section.address) {
                continue;
            }
            let Some(bytes) = self.image.bytes_at(
                section.address,
                section.file_size.min(section.virtual_size) as usize,
            ) else {
                continue;
            };
            for (offset, window) in bytes.windows(10).enumerate() {
                if window.first() != Some(&0xb8) {
                    continue;
                }
                let Some(raw) = window.get(1..5).and_then(|b| <[u8; 4]>::try_from(b).ok()) else {
                    continue;
                };
                let address = u64::from(u32::from_le_bytes(raw));
                if !self.word(address).is_some_and(|magic| {
                    (0x1993_0520..=0x1993_0522).contains(&(magic & 0x1fff_ffff))
                }) {
                    continue;
                }
                let stub = section.address + offset as u64;
                let Ok(jump) = self.image.decode_at(stub + 5) else {
                    continue;
                };
                if jump.x86_instruction().mnemonic() != Mnemonic::Jmp
                    || !(jump.direct_target.is_some_and(|target| self.code(target))
                        || jump.memory_target.is_some_and(|target| {
                            self.image.import_locations.contains_key(&target)
                        }))
                {
                    continue;
                }
                candidates += 1;
                if candidates > MAX_CANDIDATES || self.work == 0 {
                    result
                        .diagnostics
                        .push("MSVC C++ exception parsing exceeded its work limit".into());
                    return;
                }
                if self.add(result, address) {
                    if let Some(info) = result.functions.get_mut(&address) {
                        info.frame_handlers.insert(self.x86_handler_start(stub));
                    }
                }
            }
        }
    }

    /// /GS frame handlers check a cookie before loading FuncInfo into EAX.
    /// The pointer installed by the parent names that prefix, not the later MOV.
    fn x86_handler_start(&self, stub: u64) -> u64 {
        use iced_x86::Register;
        for distance in 16..=32 {
            let Some(start) = stub.checked_sub(distance) else {
                continue;
            };
            if self.image.bytes_at(start, 4) != Some(&[0x8b, 0x54, 0x24, 0x08]) {
                continue;
            }
            let mut at = start;
            let mut instructions = Vec::new();
            for _ in 0..5 {
                let Ok(i) = self.image.decode_at(at) else {
                    break;
                };
                at = i.next_address;
                instructions.push(i);
            }
            if at != stub || instructions.len() != 5 {
                continue;
            }
            let lea = instructions[1].x86_instruction();
            let load = instructions[2].x86_instruction();
            let xor = instructions[3].x86_instruction();
            if lea.mnemonic() == Mnemonic::Lea
                && lea.op0_register() == Register::EAX
                && lea.memory_base() == Register::EDX
                && lea.memory_index() == Register::None
                && load.mnemonic() == Mnemonic::Mov
                && load.op0_register() == Register::ECX
                && load.memory_base() == Register::EDX
                && load.memory_index() == Register::None
                && xor.mnemonic() == Mnemonic::Xor
                && xor.op0_register() == Register::ECX
                && xor.op1_register() == Register::EAX
                && instructions[4].flow == crate::extract::decoder::Flow::Call
            {
                return if start >= 2 && self.image.bytes_at(start - 2, 2) == Some(&[0x90, 0x90]) {
                    start - 2
                } else {
                    start
                };
            }
        }
        stub
    }

    fn handler_name(&self, mut address: u64) -> Option<&str> {
        for _ in 0..4 {
            if let Some(name) = self.image.import_locations.get(&address) {
                return Some(name);
            }
            let insn = self.image.decode_at(address).ok()?;
            if insn.x86_instruction().mnemonic() != Mnemonic::Jmp {
                return None;
            }
            address = insn.memory_target.or(insn.direct_target)?;
        }
        None
    }

    fn read_x64(&mut self, result: &mut ExceptionInfo) {
        let Some((directory, size)) = self.image.pe_exception_directory else {
            return;
        };
        if size as usize / 12 > MAX_WORK || size % 12 != 0 {
            result
                .diagnostics
                .push("Malformed or oversized x64 exception directory".into());
            return;
        }
        let Some(entries) = self.bytes(directory, size as usize) else {
            result
                .diagnostics
                .push("Truncated x64 exception directory".into());
            return;
        };
        // Copy only the bounded directory, so the reader's work budget can mutate.
        let entries = entries.to_vec();
        for row in entries.as_chunks::<12>().0 {
            let field = |offset: usize| -> Option<u64> {
                self.image
                    .image_base
                    .checked_add(u64::from(u32::from_le_bytes(
                        row.get(offset..offset + 4)?.try_into().ok()?,
                    )))
            };
            let (Some(begin), Some(end), Some(mut unwind)) = (field(0), field(4), field(8)) else {
                continue;
            };
            if begin >= end || !self.code(begin) || !self.code(end - 1) {
                continue;
            }
            let mut owner = begin;
            // UNW_FLAG_CHAININFO stores another RUNTIME_FUNCTION. The bound also
            // stops cycles, without recursive parsing or stack growth.
            for depth in 0..32 {
                let Some(header) = self.bytes(unwind, 4) else {
                    break;
                };
                let Some((&version_flags, rest)) = header.split_first() else {
                    break;
                };
                let Some(&count) = rest.get(1) else {
                    break;
                };
                if !matches!(version_flags & 7, 1 | 2) {
                    break;
                }
                let flags = version_flags >> 3;
                let Some(tail) = unwind.checked_add(4 + u64::from(count).div_ceil(2) * 4) else {
                    break;
                };
                if flags & 4 != 0 {
                    if flags & 3 != 0 {
                        break;
                    }
                    let (Some(Some(parent)), Some(Some(next))) =
                        (self.reference(tail), self.reference(tail + 8))
                    else {
                        break;
                    };
                    owner = parent;
                    unwind = next;
                    if depth == 31 {
                        result
                            .diagnostics
                            .push(format!("Cyclic or overlong x64 unwind chain at {begin:#x}"));
                    }
                    continue;
                }
                if flags & 3 == 0 {
                    break;
                }
                let Some(Some(handler)) = self.reference(tail) else {
                    break;
                };
                let name = self.handler_name(handler).unwrap_or_default();
                if name.contains("CxxFrameHandler4") || name.contains("GSHandlerCheck_EH4") {
                    result.diagnostics.push(format!(
                        "Compressed MSVC C++ FH4 metadata at {begin:#x} is not supported"
                    ));
                    break;
                }
                let known = name.contains("CxxFrameHandler") || name.contains("GSHandlerCheck_EH");
                let Some(Some(address)) = self.reference(tail + 4) else {
                    if known {
                        result
                            .diagnostics
                            .push(format!("Missing MSVC C++ FuncInfo pointer at {begin:#x}"));
                    }
                    break;
                };
                let magic = self.word(address).is_some_and(|word| {
                    (0x1993_0520..=0x1993_0522).contains(&(word & 0x1fff_ffff))
                });
                if !magic && !known {
                    break;
                } // SEH and other language handlers.
                if !self.code(handler) || !self.code(owner) {
                    break;
                }
                if self.add(result, address) {
                    if let Some(info) = result.functions.get_mut(&address) {
                        info.owners.insert(owner);
                        info.code_ranges.push(begin..end);
                    }
                }
                break;
            }
        }
        // Catch funclets have their own RUNTIME_FUNCTION but belong to their
        // parent FuncInfo, not independent source-level functions.
        for info in result.functions.values_mut() {
            let targets: BTreeSet<_> = info.targets().collect();
            info.owners.retain(|owner| !targets.contains(owner));
            info.code_ranges
                .sort_by_key(|range| (range.start, range.end));
            info.code_ranges.dedup();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_checking_x86_handler_uses_its_installed_entry() {
        let mut bytes = vec![
            0x90, 0x90, 0x8b, 0x54, 0x24, 8, // mov edx,[esp+8]
            0x8d, 0x42, 0x0c, // lea eax,[edx+12]
            0x8b, 0x4a, 0xcc, // mov ecx,[edx-52]
            0x33, 0xc8, // xor ecx,eax
            0xe8, 0, 0, 0, 0, // cookie helper
            0xb8, 0, 0, 0, 0, // FuncInfo load
        ];
        for valid in [true, false] {
            if !valid {
                bytes[13] = 0xc0;
            } // xor eax,eax does not check that cookie
            let image = LoadedImage::from_shellcode(&bytes, Architecture::X86);
            let reader = Reader {
                image: &image,
                wide: false,
                work: MAX_WORK,
                attempted: BTreeSet::new(),
                limit_reported: false,
            };
            let stub = image.image_base + 19;
            assert_eq!(
                reader.x86_handler_start(stub),
                if valid { image.image_base } else { stub }
            );
        }
    }

    #[test]
    fn catch_resume_requires_a_literal_code_address_at_return(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let base = crate::extract::image::SHELLCODE_BASE;
        let mut bytes = vec![0xb8]; // mov eax,continuation; ret
        bytes.extend_from_slice(&(base as u32 + 16).to_le_bytes());
        bytes.push(0xc3);
        bytes.resize(16, 0xcc);
        bytes.push(0xc3);
        let analysis = crate::extract::recovery::analyze_shellcode(&bytes, Architecture::X86)?;
        assert_eq!(
            catch_continuations(&analysis, base),
            BTreeSet::from([base + 16])
        );
        bytes[1..5].copy_from_slice(&7u32.to_le_bytes());
        let analysis = crate::extract::recovery::analyze_shellcode(&bytes, Architecture::X86)?;
        assert!(catch_continuations(&analysis, base).is_empty());
        Ok(())
    }
}
