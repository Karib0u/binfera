//! Bounded, deterministic p-code emulation. Imports are recorded stubs; no host APIs execute.
//! Every request starts with fresh image memory, zero registers, and a synthetic stack.
use crate::decompiler::{ctypes::Pack, BatchOptions, CallingConvention as C, DecompilerSession};
use crate::extract::decoder::Flow;
use crate::extract::image::Architecture;
use crate::extract::recovery::Analysis;
use binfera_ghidra::{CodeRange, EmuStop, Session};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

const STACK_SIZE: u64 = 1 << 20;
const MAX_BYTES: usize = 1 << 20;
const MAX_CALLS: usize = 4096;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid emulation request: {0}")]
    Request(String),
    #[error("{0}")]
    Image(#[from] crate::decompiler::DecompileError),
    #[error("emulation bridge: {0}")]
    Native(#[from] binfera_ghidra::Error),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryInput {
    pub address: u64,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryRange {
    pub address: u64,
    pub size: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Request {
    pub address: u64,
    /// Integer/pointer ABI slots, each at most one machine word.
    pub args: Vec<u64>,
    /// Applied after ABI setup. Allows explicit segment bases, stack pointers and link registers.
    pub registers: BTreeMap<String, u64>,
    /// Initial memory, mapped on demand; changes are excluded from the write log.
    pub memory: Vec<MemoryInput>,
    pub capture: Vec<MemoryRange>,
    /// Import symbol or full import location to fixed scalar return value. Default is zero.
    pub import_returns: BTreeMap<String, u64>,
    /// Explicit callee-popped bytes for imports with unknown 32-bit Windows signatures.
    pub import_stack_pops: BTreeMap<String, u32>,
    pub max_steps: u64,
    pub timeout_ms: u32,
    pub max_calls: usize,
    pub max_write_bytes: usize,
}
impl Default for Request {
    fn default() -> Self {
        Self {
            address: 0,
            args: Vec::new(),
            registers: BTreeMap::new(),
            memory: Vec::new(),
            capture: Vec::new(),
            import_returns: BTreeMap::new(),
            import_stack_pops: BTreeMap::new(),
            max_steps: 100_000,
            timeout_ms: 1000,
            max_calls: 256,
            max_write_bytes: 65_536,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Stop {
    pub kind: String,
    pub address: u64,
    pub detail: String,
}
#[derive(Debug, Serialize)]
pub struct ImportCall {
    pub name: String,
    pub slot: u64,
    pub return_address: u64,
    /// Raw ABI slots; aggregate and floating-point arguments are not decoded.
    pub args: Vec<u64>,
    pub signature_known: bool,
    pub return_value: u64,
}
#[derive(Debug, Serialize)]
pub struct MemoryOutput {
    pub address: u64,
    pub size: u64,
    pub data: Vec<u8>,
    pub truncated: bool,
}
#[derive(Debug, Serialize)]
pub struct Result {
    pub address: u64,
    pub stop: Stop,
    pub steps: u64,
    pub return_value: u64,
    pub registers: BTreeMap<String, u64>,
    pub calls: Vec<ImportCall>,
    pub writes: Vec<MemoryOutput>,
    pub memory: Vec<MemoryOutput>,
    pub warnings: Vec<String>,
}
#[derive(Debug, Serialize)]
pub struct CallSite {
    pub caller: u64,
    pub site: u64,
    /// False if the caller did not reach this site with the supplied initial state.
    pub reached: bool,
    /// Ranges written by the call itself, after the caller reached the site. `result.writes` also
    /// holds what the caller wrote on the way, such as the buffer it passes in.
    pub call_writes: Vec<MemoryOutput>,
    pub result: Result,
}
#[derive(Debug, Serialize)]
pub struct CallSites {
    pub address: u64,
    pub total_sites: usize,
    pub truncated: bool,
    pub sites: Vec<CallSite>,
}

#[derive(Clone, Copy)]
struct Abi {
    sp: &'static str,
    result: &'static str,
    link: Option<&'static str>,
    args: &'static [&'static str],
    stack_args: u64,
}
impl Abi {
    fn of(c: C) -> std::result::Result<Self, Error> {
        let (sp, result, link, args, stack_args) = match c {
            C::WindowsX64 => ("RSP", "RAX", None, &["RCX", "RDX", "R8", "R9"][..], 40),
            C::SystemVX64 | C::DarwinX64 => (
                "RSP",
                "RAX",
                None,
                &["RDI", "RSI", "RDX", "RCX", "R8", "R9"][..],
                8,
            ),
            C::WindowsX86 | C::SystemVX86 => ("ESP", "EAX", None, &[][..], 4),
            C::WindowsAArch64 | C::SystemVAArch64 | C::DarwinAArch64 => (
                "sp",
                "x0",
                Some("x30"),
                &["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"][..],
                0,
            ),
            C::SystemVArm | C::SystemVArmSoft | C::WindowsArm => {
                ("sp", "r0", Some("lr"), &["r0", "r1", "r2", "r3"][..], 0)
            }
            C::SystemVMips | C::SystemVMipsBe => {
                ("sp", "v0", Some("ra"), &["a0", "a1", "a2", "a3"][..], 16)
            }
            _ => {
                return Err(Error::Request(format!(
                    "{c:?} argument setup is not supported"
                )))
            }
        };
        Ok(Self {
            sp,
            result,
            link,
            args,
            stack_args,
        })
    }
}

struct Import {
    slot: u64,
    name: String,
    symbol: String,
    count: Option<usize>,
    pop: Option<u32>,
}

pub struct Emulator {
    native: Session,
    analysis: Analysis,
    abi: Abi,
    imports: BTreeMap<u64, Import>,
    stack: u64,
    sentinel: u64,
}

impl Emulator {
    pub fn open(bytes: &[u8], options: &BatchOptions) -> std::result::Result<Self, Error> {
        let (session, analysis) = options.open(bytes)?;
        Self::new(session, analysis)
    }

    pub fn from_analysis(analysis: Analysis, convention: C) -> std::result::Result<Self, Error> {
        let session = DecompilerSession::from_analysis(&analysis, &BTreeMap::new(), convention)?;
        Self::new(session, analysis)
    }

    fn new(session: DecompilerSession, analysis: Analysis) -> std::result::Result<Self, Error> {
        let thunks: BTreeSet<_> = analysis
            .image
            .import_locations
            .keys()
            .copied()
            .filter(|at| session.is_import_thunk(*at))
            .collect();
        let (native, convention) = session.into_emulation_parts();
        let abi = Abi::of(convention)?;
        let pack = Pack::parse(binfera_ghidra::prototype_pack(convention.language()))
            .map_err(Error::Request)?;
        let wide = analysis.image.architecture.pointer_width() == 8;
        let stack = Self::free_region(
            &analysis,
            if wide { 0x7000_0000_0000 } else { 0x7000_0000 },
            STACK_SIZE,
            None,
        )?;
        let sentinel_size = (analysis.image.import_locations.len() as u64 + 1) * 16;
        let sentinel = Self::free_region(
            &analysis,
            if wide { 0x7100_0000_0000 } else { 0x7100_0000 },
            sentinel_size,
            Some((stack, stack + STACK_SIZE)),
        )?;
        let mut imports = BTreeMap::new();
        for (&slot, name) in &analysis.image.import_locations {
            if thunks.contains(&slot) {
                continue;
            }
            let symbol = name.rsplit('.').next().unwrap_or(name).to_string();
            let signature = pack.signature(&symbol);
            let pop = if convention == C::WindowsX86 {
                match signature.as_ref() {
                    Some((_, true, _)) => Some(0),
                    Some((_, _, Some(model))) if model == "__cdecl" => Some(0),
                    Some((_, false, Some(model))) if model == "__stdcall" => {
                        pack.stack_parameter_bytes(&symbol, 4)
                    }
                    _ => None,
                }
            } else {
                Some(0)
            };
            imports.insert(
                sentinel + (imports.len() as u64 + 1) * 16,
                Import {
                    slot,
                    name: name.clone(),
                    symbol,
                    count: signature.map(|s| s.0),
                    pop,
                },
            );
        }
        Ok(Self {
            native,
            analysis,
            abi,
            imports,
            stack,
            sentinel,
        })
    }

    fn free_region(
        analysis: &Analysis,
        mut base: u64,
        size: u64,
        reserved: Option<(u64, u64)>,
    ) -> std::result::Result<u64, Error> {
        for _ in 0..256 {
            if reserved.is_none_or(|(start, end)| base + size <= start || end <= base)
                && analysis.image.sections.iter().all(|s| {
                    base + size <= s.address || s.end_address().is_some_and(|end| end <= base)
                })
            {
                return Ok(base);
            }
            let Some(previous) = base.checked_sub(16 << 20) else {
                break;
            };
            base = previous;
        }
        Err(Error::Request(
            "cannot find a synthetic memory range".into(),
        ))
    }

    fn validate(&self, req: &Request) -> std::result::Result<(), Error> {
        if req.max_steps == 0
            || req.max_steps > 10_000_000
            || req.timeout_ms == 0
            || req.timeout_ms > 60_000
        {
            return Err(Error::Request(
                "max_steps must be 1..10000000 and timeout_ms 1..60000".into(),
            ));
        }
        if req.args.len() > 256
            || req.registers.len() > 128
            || req.memory.len() > 128
            || req.capture.len() > 128
            || req.max_calls > MAX_CALLS
            || req.max_write_bytes > MAX_BYTES
            || req.import_returns.len() > MAX_CALLS
            || req.import_stack_pops.len() > MAX_CALLS
        {
            return Err(Error::Request(
                "request exceeds argument, memory or output limits".into(),
            ));
        }
        if req.memory.iter().map(|m| m.data.len()).sum::<usize>() > MAX_BYTES
            || req.capture.iter().map(|m| u64::from(m.size)).sum::<u64>() > MAX_BYTES as u64
        {
            return Err(Error::Request(
                "initial memory and captures are limited to 1 MiB each".into(),
            ));
        }
        let sentinel_end = self.sentinel + (self.imports.len() as u64 + 1) * 16;
        for (address, size) in req
            .memory
            .iter()
            .map(|m| (m.address, m.data.len() as u64))
            .chain(req.capture.iter().map(|m| (m.address, u64::from(m.size))))
        {
            let end = address
                .checked_add(size)
                .ok_or_else(|| Error::Request("memory range overflow".into()))?;
            if size == 0 || (address < sentinel_end && self.sentinel < end) {
                return Err(Error::Request(
                    "empty memory range or overlap with import sentinels".into(),
                ));
            }
        }
        if self.analysis.image.architecture.pointer_width() == 4
            && req
                .args
                .iter()
                .chain(req.import_returns.values())
                .any(|v| *v > u32::MAX as u64)
        {
            return Err(Error::Request(
                "32-bit ABI slots must fit in 32 bits".into(),
            ));
        }
        if req
            .import_stack_pops
            .values()
            .any(|p| *p > 65536 || *p % 4 != 0)
        {
            return Err(Error::Request(
                "import stack pops must be aligned and at most 65536".into(),
            ));
        }
        Ok(())
    }

    fn word(&self) -> usize {
        self.analysis.image.architecture.pointer_width()
    }
    fn encode(&self, value: u64) -> Vec<u8> {
        if self.analysis.image.architecture.little_endian() {
            value.to_le_bytes()[..self.word()].to_vec()
        } else {
            value.to_be_bytes()[8 - self.word()..].to_vec()
        }
    }
    fn read_word(&mut self, address: u64) -> std::result::Result<u64, Error> {
        let bytes = self.native.emu_read(address, self.word() as u32)?;
        if bytes.len() != self.word() {
            return Err(Error::Request(format!(
                "ABI read from unmapped memory at {address:#x}"
            )));
        }
        Ok(if self.analysis.image.architecture.little_endian() {
            bytes
                .iter()
                .rev()
                .fold(0u64, |v, b| (v << 8) | u64::from(*b))
        } else {
            bytes.iter().fold(0u64, |v, b| (v << 8) | u64::from(*b))
        })
    }

    fn setup(&mut self, req: &Request, entry: u64) -> std::result::Result<(), Error> {
        self.native.emu_reset()?;
        self.native.emu_map(self.stack, STACK_SIZE)?;
        // At x86 entry the return address is one word below a 16-byte aligned caller SP.
        let mut sp = self.stack + STACK_SIZE - 4096;
        if self.abi.link.is_none() {
            sp -= self.word() as u64;
        }
        self.native.emu_set_register(self.abi.sp, sp)?;
        if let Some(link) = self.abi.link {
            self.native.emu_set_register(link, self.sentinel)?;
        } else {
            self.native
                .emu_write(sp, &self.encode(self.sentinel), false)?;
        }
        if matches!(
            self.analysis.image.architecture,
            Architecture::Mips | Architecture::MipsBe
        ) {
            self.native.emu_set_register("t9", entry)?;
            if let Some(gp) = self.analysis.image.global_pointer {
                self.native.emu_set_register("gp", gp)?;
            }
        }
        for (i, arg) in req.args.iter().enumerate() {
            if let Some(reg) = self.abi.args.get(i) {
                self.native.emu_set_register(reg, *arg)?;
            } else {
                let at =
                    sp + self.abi.stack_args + ((i - self.abi.args.len()) * self.word()) as u64;
                self.native.emu_write(at, &self.encode(*arg), false)?;
            }
        }
        for memory in &req.memory {
            let end = memory.address + memory.data.len() as u64;
            if self.analysis.image.sections.iter().any(|s| {
                s.permissions.execute
                    && memory.address < s.end_address().unwrap_or(u64::MAX)
                    && s.address < end
            }) {
                return Err(Error::Request(
                    "initial memory cannot patch executable sections".into(),
                ));
            }
            if !self
                .native
                .emu_mapped(memory.address, memory.data.len() as u64)?
            {
                self.native
                    .emu_map(memory.address, memory.data.len() as u64)?;
            }
            self.native.emu_write(memory.address, &memory.data, false)?;
        }
        let slots: Vec<_> = self.imports.iter().map(|(&at, i)| (at, i.slot)).collect();
        for (at, slot) in slots {
            self.native.emu_write(slot, &self.encode(at), false)?;
        }
        for (name, value) in &req.registers {
            self.native.emu_set_register(name, *value)?;
        }
        self.native.emu_clear_writes()?;
        Ok(())
    }

    /// Execute one entry until its synthetic return address, a fault, a trap, or a budget limit.
    pub fn run(&mut self, req: &Request) -> std::result::Result<Result, Error> {
        self.validate(req)?;
        let entry = if self.analysis.image.architecture == Architecture::Arm {
            req.address & !1
        } else {
            req.address
        };
        if !self.analysis.image.is_executable_address(entry) {
            return Err(Error::Request(
                "entry is not in executable image memory".into(),
            ));
        }
        self.setup(req, entry)?;
        let mut run = Run::new(req.address);
        self.execute(entry, self.sentinel, None, req, &mut run)?;
        let writes = self.native.emu_writes()?;
        self.finish(req, run, writes)
    }

    /// Run each statically recovered direct call site with a fresh caller state. The caller
    /// executes from its entry to the site, then the call executes until its fallthrough.
    /// Sites not reached with the supplied caller arguments retain their prelude stop reason.
    pub fn call_sites(
        &mut self,
        req: &Request,
        max_sites: usize,
    ) -> std::result::Result<CallSites, Error> {
        self.validate(req)?;
        if self.analysis.image.architecture.is_risc32() {
            return Err(Error::Request(
                "call-site execution currently supports x86, x64 and AArch64".into(),
            ));
        }
        if max_sites == 0 || max_sites > 128 {
            return Err(Error::Request("max_sites must be 1..128".into()));
        }
        let mut sites = BTreeSet::new();
        for (&caller, function) in &self.analysis.functions {
            for insn in function.blocks.iter().flat_map(|b| &b.insns) {
                if matches!(insn.flow, Flow::Call | Flow::IndirectCall)
                    && (insn.direct_target == Some(req.address)
                        || insn.memory_target == Some(req.address))
                {
                    sites.insert((caller, insn.address, insn.next_address));
                }
            }
        }
        let total_sites = sites.len();
        let started = Instant::now();
        let mut out = Vec::new();
        for (caller, site, next) in sites.into_iter().take(max_sites) {
            if started.elapsed().as_millis() >= u128::from(req.timeout_ms) {
                break;
            }
            self.setup(req, caller)?;
            let mut run = Run::new(req.address);
            run.started = started;
            let reached = if site == caller {
                true
            } else {
                self.execute(caller, site, None, req, &mut run)?;
                run.stop.kind == "returned" && run.stop.address == site
            };
            let mut written = self.native.emu_writes()?;
            let mut call_writes = Vec::new();
            if reached {
                // The write log restarts at the site so the call's own output can be told apart.
                self.native.emu_clear_writes()?;
                // A recursive target reaches `next` in deeper frames first; only the frame that
                // made this call, with the stack back at or above the site's, counts as returned.
                let frame = self.native.emu_get_register(self.abi.sp)?;
                self.execute(site, next, Some(frame), req, &mut run)?;
                let call = self.native.emu_writes()?;
                call_writes = self.read_ranges(&call, req.max_write_bytes)?;
                written.extend(call);
            }
            out.push(CallSite {
                caller,
                site,
                reached,
                call_writes,
                result: self.finish(req, run, merge_ranges(written))?,
            });
        }
        Ok(CallSites {
            address: req.address,
            total_sites,
            truncated: total_sites > out.len(),
            sites: out,
        })
    }

    fn execute(
        &mut self,
        mut pc: u64,
        end: u64,
        frame: Option<u64>,
        req: &Request,
        run: &mut Run,
    ) -> std::result::Result<(), Error> {
        loop {
            let remaining = req.max_steps.saturating_sub(run.steps);
            let elapsed = run.started.elapsed().as_millis();
            if remaining == 0 || elapsed >= u128::from(req.timeout_ms) {
                run.stop = Stop {
                    kind: if remaining == 0 {
                        "step_limit"
                    } else {
                        "timeout"
                    }
                    .into(),
                    address: pc,
                    detail: String::new(),
                };
                return Ok(());
            }
            let budget = req.timeout_ms - elapsed as u32;
            let mut stop = self
                .native
                .emu_run(pc, remaining, budget, &[end, self.sentinel])?;
            run.steps += stop.steps;
            run.approximated.extend(stop.approximated.iter().cloned());
            pc = stop.address;
            if pc == end && stop.kind == "breakpoint" && run.steps < req.max_steps {
                if let Some(frame) = frame {
                    if self.native.emu_get_register(self.abi.sp)? < frame {
                        // Step off the breakpoint of a nested frame without stopping on it.
                        stop = self.native.emu_run(pc, 1, budget, &[self.sentinel])?;
                        run.steps += stop.steps;
                        run.approximated.extend(stop.approximated.iter().cloned());
                        pc = stop.address;
                        if stop.kind == "step_limit" {
                            continue;
                        }
                    }
                }
            }
            if pc == end && stop.kind == "breakpoint" {
                run.stop = Stop {
                    kind: "returned".into(),
                    address: pc,
                    detail: String::new(),
                };
                return Ok(());
            }
            if pc == self.sentinel && stop.kind == "breakpoint" {
                run.stop = Stop {
                    kind: "caller_returned".into(),
                    address: pc,
                    detail: String::new(),
                };
                return Ok(());
            }
            if !self.imports.contains_key(&pc) || stop.kind != "fetch" {
                run.stop = stop.into();
                return Ok(());
            }
            if run.steps >= req.max_steps {
                run.stop = Stop {
                    kind: "step_limit".into(),
                    address: pc,
                    detail: String::new(),
                };
                return Ok(());
            }
            if run.calls.len() >= req.max_calls {
                run.stop = Stop {
                    kind: "call_limit".into(),
                    address: pc,
                    detail: String::new(),
                };
                return Ok(());
            }
            // Copy metadata before reading the mutable native state.
            let import = &self.imports[&pc];
            let (slot, name, symbol, count, default_pop) = (
                import.slot,
                import.name.clone(),
                import.symbol.clone(),
                import.count,
                import.pop,
            );
            let lookup =
                |map: &BTreeMap<String, u32>| map.get(&name).or_else(|| map.get(&symbol)).copied();
            let pop = lookup(&req.import_stack_pops).or(default_pop);
            let Some(pop) = pop else {
                run.stop = Stop {
                    kind: "unknown_import_abi".into(),
                    address: pc,
                    detail: format!("set import_stack_pops for {name}"),
                };
                return Ok(());
            };
            let sp = self.native.emu_get_register(self.abi.sp)?;
            if self.abi.link.is_none() && !self.native.emu_mapped(sp, self.word() as u64)? {
                run.stop = Stop {
                    kind: "read_fault".into(),
                    address: pc,
                    detail: format!("import return address is unmapped at {sp:#x}"),
                };
                return Ok(());
            }
            let return_address = if let Some(link) = self.abi.link {
                self.native.emu_get_register(link)?
            } else {
                self.read_word(sp)?
            };
            let mut args = Vec::new();
            let slots = count.unwrap_or(4).max(pop as usize / self.word());
            for i in 0..slots.min(32) {
                if let Some(reg) = self.abi.args.get(i) {
                    args.push(self.native.emu_get_register(reg)?);
                } else {
                    let at = sp
                        .checked_add(
                            self.abi.stack_args + ((i - self.abi.args.len()) * self.word()) as u64,
                        )
                        .ok_or_else(|| Error::Request("import argument address overflow".into()))?;
                    // Unmapped optional inspection slots are omitted, never invented as zeros.
                    if !self.native.emu_mapped(at, self.word() as u64)? {
                        break;
                    }
                    args.push(self.read_word(at)?);
                }
            }
            let value = req
                .import_returns
                .get(&name)
                .or_else(|| req.import_returns.get(&symbol))
                .copied()
                .unwrap_or(0);
            self.native.emu_set_register(self.abi.result, value)?;
            if self.abi.link.is_none() {
                let new_sp = sp
                    .checked_add(self.word() as u64 + u64::from(pop))
                    .ok_or_else(|| Error::Request("import stack overflow".into()))?;
                self.native.emu_set_register(self.abi.sp, new_sp)?;
            }
            run.calls.push(ImportCall {
                name,
                slot,
                return_address,
                args,
                signature_known: count.is_some(),
                return_value: value,
            });
            // Charge stubs too: a corrupt return address cannot create an unbounded host loop.
            run.steps += 1;
            // ARM return addresses carry the Thumb state in bit 0; the instruction doesn't.
            pc = if self.analysis.image.architecture == Architecture::Arm {
                return_address & !1
            } else {
                return_address
            };
            if pc == end || pc == self.sentinel {
                run.stop = Stop {
                    kind: if pc == end {
                        "returned"
                    } else {
                        "caller_returned"
                    }
                    .into(),
                    address: pc,
                    detail: String::new(),
                };
                return Ok(());
            }
        }
    }

    /// Reads written ranges, in order, until `budget` bytes have been returned.
    fn read_ranges(
        &mut self,
        ranges: &[CodeRange],
        budget: usize,
    ) -> std::result::Result<Vec<MemoryOutput>, Error> {
        let mut remaining = budget;
        let mut writes = Vec::new();
        for range in ranges {
            let size = range.end - range.start;
            let count = size.min(remaining as u64) as u32;
            writes.push(MemoryOutput {
                address: range.start,
                size,
                data: self.native.emu_read(range.start, count)?,
                truncated: u64::from(count) < size,
            });
            remaining -= count as usize;
        }
        Ok(writes)
    }

    fn finish(
        &mut self,
        req: &Request,
        run: Run,
        written: Vec<CodeRange>,
    ) -> std::result::Result<Result, Error> {
        let writes = self.read_ranges(&written, req.max_write_bytes)?;
        let mut memory = Vec::new();
        for range in &req.capture {
            let data = self.native.emu_read(range.address, range.size)?;
            let truncated = data.len() != range.size as usize;
            memory.push(MemoryOutput {
                address: range.address,
                size: u64::from(range.size),
                data,
                truncated,
            });
        }
        let mut registers = BTreeMap::new();
        for name in [self.abi.sp, self.abi.result]
            .into_iter()
            .chain(self.abi.args.iter().copied())
            .chain(req.registers.keys().map(String::as_str))
        {
            registers.insert(name.to_string(), self.native.emu_get_register(name)?);
        }
        let mut warnings = vec!["Imports use fixed scalar returns; host APIs, allocations and output buffers are not modeled. Integer/pointer ABI slots only; aggregate and floating-point arguments require explicit register/memory setup.".into()];
        warnings.extend(
            run.approximated
                .into_iter()
                .map(|s| format!("Approximated user operation: {s}")),
        );
        Ok(Result {
            address: req.address,
            stop: run.stop,
            steps: run.steps,
            return_value: self.native.emu_get_register(self.abi.result)?,
            registers,
            calls: run.calls,
            writes,
            memory,
            warnings,
        })
    }
}
/// Sorted union of half-open ranges; touching ranges merge, as the native write log does.
fn merge_ranges(mut ranges: Vec<CodeRange>) -> Vec<CodeRange> {
    ranges.sort_by_key(|r| (r.start, r.end));
    let mut out: Vec<CodeRange> = Vec::with_capacity(ranges.len());
    for range in ranges {
        match out.last_mut() {
            Some(last) if range.start <= last.end => last.end = last.end.max(range.end),
            _ => out.push(range),
        }
    }
    out
}

impl From<EmuStop> for Stop {
    fn from(stop: EmuStop) -> Self {
        Self {
            kind: stop.kind,
            address: stop.address,
            detail: stop.detail,
        }
    }
}
struct Run {
    started: Instant,
    steps: u64,
    stop: Stop,
    calls: Vec<ImportCall>,
    approximated: BTreeSet<String>,
}
impl Run {
    fn new(address: u64) -> Self {
        Self {
            started: Instant::now(),
            steps: 0,
            stop: Stop {
                kind: String::new(),
                address,
                detail: String::new(),
            },
            calls: Vec::new(),
            approximated: BTreeSet::new(),
        }
    }
}
