//! The native boundary. All input slices are copied before native calls return.
//! Sessions own their translator and are deliberately neither Send nor Sync.
#![cfg(feature = "native")]

// The C++ code calls zlib directly, so nothing in Rust names the crate that builds it on Windows;
// without this reference the linker never receives its library.
#[cfg(all(windows, feature = "native"))]
use libz_sys as _;
use std::{marker::PhantomData, rc::Rc};

// CXX emits explicit Clone calls for primitive fields in its generated bridge.
#[allow(clippy::too_many_arguments, clippy::clone_on_copy)]
#[cxx::bridge(namespace = "binfera")]
mod ffi {
    /// A half-open metadata interval that must remain readable but not executable.
    #[derive(Clone, Copy, Debug)]
    struct CodeRange {
        start: u64,
        end: u64,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ValueType {
        Void,
        I32,
        U32,
        I64,
        U64,
        Pointer,
        CharPointer,
        WideCharPointer,
        U32Pointer,
        PointerPointer,
        LuidPointer,
        TokenPrivilegesPointer,
        I8,
        U8,
        I16,
        U16,
        Bool,
        F32,
        F64,
    }
    /// A processor and compiler specification pair the engine can be started with.
    /// The compiler specification fixes the platform calling convention.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Language {
        ArmLinux,
        ArmLinuxSoft,
        ArmWindows,
        MipsLittle,
        MipsBig,
        AArch64Linux,
        AArch64GoLinux,
        AArch64GoWindows,
        AArch64GoApple,
        AArch64Windows,
        AArch64Apple,
        X86Apple64,
        X86GoApple64,
        /// `x86:LE:32:default:windows`
        X86Windows32,
        /// `x86:LE:64:default:windows`
        X86Windows64,
        /// `x86:LE:64:default:gcc`, the System V AMD64 convention
        X86Linux64,
        /// `x86:LE:32:default:gcc`, the System V i386 convention (cdecl, `__regparm`)
        X86Linux32,
        /// `x86:LE:32:default:borlanddelphi`: Delphi's `__register` default (`EAX`, `EDX`, `ECX`)
        X86Delphi32,
        /// `x86:LE:32:default:borlandcpp`: Borland C++'s register `__fastcall` default
        X86Borland32,
        /// `x86:LE:64:default:golang` with the Windows archive for imports
        X86GoWindows64,
        /// `x86:LE:64:default:golang` with the C library archive for imports
        X86GoLinux64,
        /// `x86:LE:32:default:golang` (Go's stack ABI) with the Windows archive for imports
        X86GoWindows32,
        /// `x86:LE:32:default:golang` with the C library archive for imports
        X86GoLinux32,
    }
    #[derive(Clone, Debug)]
    struct CppParameter {
        value: ValueType,
        pointee: String,
    }
    /// One virtual function table of a C++ class, for `add_class`.
    #[derive(Clone, Debug)]
    struct VfTable {
        /// Where the table's pointer sits in the object.
        offset: u32,
        address: u64,
        /// The table's data label (`Class::vftable`).
        label: String,
        /// The structure type laid out like the table, one function pointer per slot.
        type_name: String,
        /// The class structure's field that holds the table's pointer.
        field: String,
        /// The class `this` points to in each slot's method; empty when unknown.
        this_class: String,
        /// The slots' calling convention (`__thiscall`, or `__stdcall` for a COM interface on
        /// x86); the default model when the compiler specification has none of that name.
        model: String,
        slots: Vec<u64>,
    }
    #[derive(Clone, Debug)]
    struct DebugField {
        name: String,
        offset: u32,
        type_id: u64,
    }
    #[derive(Clone, Debug)]
    struct DebugType {
        id: u64,
        kind: String,
        name: String,
        size: u32,
        target: u64,
        count: u32,
        fields: Vec<DebugField>,
    }
    #[derive(Clone, Debug)]
    struct DebugParameter {
        name: String,
        type_id: u64,
    }
    /// A data symbol the text names, with the type the analysis settled on for it.
    struct NativeGlobal {
        name: String,
        address: u64,
        /// The size of that type, or of the symbol when the analysis gave it none.
        size: u32,
        /// `float`, `signed`, `unsigned`, `bool`, `pointer` or `unknown`.
        kind: String,
    }
    /// A stack symbol of the decompiled function.
    struct NativeStackSlot {
        name: String,
        /// The register holding a parameter passed in one, which has no offset; otherwise empty.
        register_name: String,
        /// From the stack pointer at entry.
        offset: i64,
        size: u32,
        type_name: String,
        parameter: bool,
        /// Instruction addresses, each sorted.
        reads: Vec<u64>,
        writes: Vec<u64>,
        references: Vec<u64>,
    }
    /// A named parameter of one call, and where the caller places its argument.
    struct NativeCallArgument {
        /// The call instruction.
        call: u64,
        index: u32,
        name: String,
        type_name: String,
        /// The register holding the argument, empty when it is on the stack.
        register_name: String,
        on_stack: bool,
        /// From the stack pointer at the call instruction, when on the stack.
        stack_offset: i64,
    }
    /// The bytes an x86 call's callee pops besides its return address.
    struct NativeCallPop {
        call: u64,
        bytes: i32,
    }
    struct NativeOutput {
        text: String,
        file_warnings: Vec<String>,
        /// Gaps in the analysis; any of them makes the result incomplete.
        warnings: Vec<String>,
        /// Informational: modeled effects and caveats that leave the result complete.
        notes: Vec<String>,
        incomplete: bool,
        unknown_callees: bool,
        /// The same pseudocode printed with Ghidra's token markup, empty if that print failed.
        markup: Vec<u8>,
        /// Parallel arrays: p-code op index (`opref` in the markup) and its instruction address.
        op_times: Vec<u32>,
        op_addrs: Vec<u64>,
        /// The data symbols named for this request (`DAT_`, `PTR_`, `s_`, `u_`).
        globals: Vec<NativeGlobal>,
        /// Stack symbols by offset, then register parameters; empty if collecting them failed.
        frame: Vec<NativeStackSlot>,
        /// Named call arguments; empty if collecting them failed.
        call_args: Vec<NativeCallArgument>,
        /// x86 calls with a known stack effect; empty elsewhere.
        call_pops: Vec<NativeCallPop>,
        initial_ms: f64,
        data_ms: f64,
        returns_ms: f64,
        inference_ms: f64,
        print_ms: f64,
        analysis_passes: u32,
        inference_cache_hits: u32,
        inference_cache_misses: u32,
        inference_cache_invalidations: u32,
        inference_cache_evictions: u32,
        inference_invalidation_reasons: Vec<String>,
    }
    /// Why an emulation run returned.
    #[derive(Clone, Debug)]
    struct EmuStop {
        /// `breakpoint`, `fetch` (execution reached memory that holds no image code: a
        /// sentinel, the return address or unmapped memory), `step_limit`, `timeout`,
        /// `read_fault`, `write_fault`, `trap` (syscall or software interrupt),
        /// `decode_error` or `unsupported`.
        kind: String,
        /// The address of the instruction that was about to execute.
        address: u64,
        steps: u64,
        detail: String,
        /// User-defined operations given a deterministic zero result so far.
        approximated: Vec<String>,
    }
    unsafe extern "C++" {
        include!("bridge.hh");
        fn emu_reset(self: Pin<&mut Session>) -> Result<()>;
        fn emu_map(self: Pin<&mut Session>, address: u64, size: u64) -> Result<()>;
        fn emu_mapped(self: Pin<&mut Session>, address: u64, size: u64) -> Result<bool>;
        fn emu_write(
            self: Pin<&mut Session>,
            address: u64,
            bytes: &[u8],
            record: bool,
        ) -> Result<()>;
        fn emu_read(self: Pin<&mut Session>, address: u64, size: u32) -> Result<Vec<u8>>;
        fn emu_set_register(self: Pin<&mut Session>, name: &str, value: u64) -> Result<()>;
        fn emu_get_register(self: Pin<&mut Session>, name: &str) -> Result<u64>;
        fn emu_writes(self: Pin<&mut Session>) -> Result<Vec<CodeRange>>;
        fn emu_clear_writes(self: Pin<&mut Session>) -> Result<()>;
        fn emu_run(
            self: Pin<&mut Session>,
            pc: u64,
            max_steps: u64,
            timeout_ms: u32,
            stops: &[u64],
        ) -> Result<EmuStop>;
        type Session;
        fn add_debug_types(self: Pin<&mut Session>, types: &[DebugType]) -> Result<()>;
        fn set_debug_signature(
            self: Pin<&mut Session>,
            address: u64,
            result: u64,
            model: &str,
            parameters: &[DebugParameter],
            varargs: bool,
            go: bool,
            multi: bool,
            noreturn: bool,
        ) -> Result<bool>;
        fn add_debug_local(
            self: Pin<&mut Session>,
            address: u64,
            name: &str,
            type_id: u64,
            offset: i64,
        ) -> Result<bool>;
        fn set_preserves_rax(self: Pin<&mut Session>, address: u64) -> Result<()>;
        fn set_print_work_limit(self: Pin<&mut Session>, work: u32) -> Result<()>;
        fn set_leaf_effects(
            self: Pin<&mut Session>,
            address: u64,
            zero_from: u32,
            preserves_ecx: bool,
        ) -> Result<()>;
        fn set_variadic_forwarder(
            self: Pin<&mut Session>,
            address: u64,
            fixed: u32,
            target: u64,
        ) -> Result<bool>;
        fn add_class(self: Pin<&mut Session>, name: &str, tables: &[VfTable]) -> Result<()>;
        fn set_method(self: Pin<&mut Session>, address: u64, class_name: &str) -> Result<bool>;
        fn set_method_signature(
            self: Pin<&mut Session>,
            address: u64,
            model: &str,
            this_class: &str,
            result: ValueType,
            parameters: &[ValueType],
            varargs: bool,
        ) -> Result<()>;
        fn add_label(self: Pin<&mut Session>, address: u64, name: &str, size: u32) -> Result<bool>;
        fn add_code_label(
            self: Pin<&mut Session>,
            owner: u64,
            address: u64,
            name: &str,
        ) -> Result<()>;
        fn set_cpp_parameters(
            self: Pin<&mut Session>,
            address: u64,
            parameters: &[CppParameter],
            varargs: bool,
        ) -> Result<bool>;
        fn set_function_model(self: Pin<&mut Session>, address: u64, model: &str) -> Result<bool>;
        fn set_rust_function(self: Pin<&mut Session>, address: u64) -> Result<()>;
        fn add_rust_string(
            self: Pin<&mut Session>,
            address: u64,
            length: u32,
            descriptor: u64,
        ) -> Result<bool>;
        fn set_call_fixup(self: Pin<&mut Session>, address: u64, fixup: &str) -> Result<()>;
        fn set_go_target(
            self: Pin<&mut Session>,
            os: &str,
            minor: u32,
            register_abi: bool,
            text_start: u64,
            text_end: u64,
        ) -> Result<()>;
        fn apply_go_prototype(self: Pin<&mut Session>, address: u64, name: &str) -> Result<bool>;
        fn set_go_special(self: Pin<&mut Session>, address: u64, kind: &str) -> Result<bool>;
        fn validate_go_pack(
            self: Pin<&mut Session>,
            os: &str,
            minor: u32,
            max_report: u32,
        ) -> Result<String>;
        fn set_callsite_arguments(
            self: Pin<&mut Session>,
            caller: u64,
            site: u64,
            target: u64,
            count: u32,
        ) -> Result<bool>;
        fn set_win64_stack_arguments(
            self: Pin<&mut Session>,
            targets: &[u64],
            counts: &[u32],
        ) -> Result<()>;
        fn set_message_send(
            self: Pin<&mut Session>,
            caller: u64,
            site: u64,
            count: u32,
        ) -> Result<bool>;
        fn set_go_stack_layout(
            self: Pin<&mut Session>,
            address: u64,
            inputs: u32,
            results: u32,
        ) -> Result<bool>;
        fn set_counted_strings(self: Pin<&mut Session>, enabled: bool) -> Result<()>;
        fn set_linux_syscalls(self: Pin<&mut Session>, enabled: bool) -> Result<()>;
        fn apply_prototype(self: Pin<&mut Session>, address: u64, name: &str) -> Result<bool>;
        fn validate_prototype_pack(self: Pin<&mut Session>, max_report: u32) -> Result<String>;
        fn stack_purge(self: Pin<&mut Session>, address: u64) -> Result<i32>;
        fn set_stack_purge(self: Pin<&mut Session>, address: u64, bytes: u32) -> Result<()>;
        fn add_branch(
            self: Pin<&mut Session>,
            site: u64,
            target: u64,
            length: u32,
            pop: u32,
        ) -> Result<()>;
        fn add_tail_call(
            self: Pin<&mut Session>,
            caller: u64,
            site: u64,
            target: u64,
        ) -> Result<()>;
        fn set_signature(
            self: Pin<&mut Session>,
            address: u64,
            result: ValueType,
            parameters: &[ValueType],
        ) -> Result<()>;
        fn new_session(language: Language) -> Result<UniquePtr<Session>>;
        fn prototype_pack_bytes(language: Language) -> &'static [u8];
        fn set_windows_pack(wide: bool, bytes: &[u8], present: bool);
        fn add_section(
            self: Pin<&mut Session>,
            address: u64,
            bytes: &[u8],
            executable: bool,
            readonly: bool,
        ) -> Result<()>;
        fn set_arm_mode(self: Pin<&mut Session>, start: u64, end: u64, thumb: bool) -> Result<()>;
        fn set_register_value(
            self: Pin<&mut Session>,
            start: u64,
            end: u64,
            name: &str,
            value: u64,
        ) -> Result<()>;
        fn set_code_exclusions(self: Pin<&mut Session>, ranges: &[CodeRange]) -> Result<()>;
        fn set_function_ranges(self: Pin<&mut Session>, ranges: &[CodeRange]) -> Result<()>;
        fn add_function(
            self: Pin<&mut Session>,
            address: u64,
            name: &str,
            noreturn: bool,
        ) -> Result<()>;
        fn add_import(
            self: Pin<&mut Session>,
            address: u64,
            name: &str,
            noreturn: bool,
        ) -> Result<()>;
        fn decompile(
            self: Pin<&mut Session>,
            address: u64,
            timeout_ms: u32,
            max_instructions: u32,
            max_work: u32,
            return_bytes: u32,
            use_cdecl: bool,
        ) -> Result<NativeOutput>;
    }
}

pub use cxx::Exception as Error;
pub use ffi::{
    CodeRange, CppParameter, DebugField, DebugParameter, DebugType, EmuStop, Language,
    NativeCallArgument, NativeCallPop, NativeGlobal, NativeOutput, NativeStackSlot, ValueType,
    VfTable,
};

/// The packed Ghidra type and prototype archive for one language; empty where none is bundled.
/// Format: `scripts/decompiler_types/pack_prototypes.py`.
pub fn prototype_pack(language: Language) -> &'static [u8] {
    ffi::prototype_pack_bytes(language)
}

/// Supplies the Windows API prototype archive for 64-bit (`wide`) or 32-bit x86 sessions.
///
/// Native builds embed both archives, so this only overrides them (tests use it); the
/// WebAssembly build embeds none and the host calls this before the first session for that
/// architecture. An empty `bytes` means the archive is unavailable: Windows imports then stay
/// untyped, exactly as with the empty archives of the other platforms.
pub fn set_windows_pack(wide: bool, bytes: &[u8]) {
    ffi::set_windows_pack(wide, bytes, true);
}

/// Forgets a supplied archive: native builds fall back to the embedded one, WebAssembly to none.
pub fn clear_windows_pack(wide: bool) {
    ffi::set_windows_pack(wide, &[], false);
}

// CXX shared structs cannot derive serde traits inside the bridge.
macro_rules! snapshot_struct {
    ($name:ident { $($field:ident: $ty:ty),+ $(,)? }) => {
        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serde::Serialize::serialize(&($(&self.$field,)+), serializer)
            }
        }
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let ($($field,)+) = <($($ty,)+) as serde::Deserialize>::deserialize(deserializer)?;
                Ok(Self { $($field,)+ })
            }
        }
    };
}
snapshot_struct!(DebugField {
    name: String,
    offset: u32,
    type_id: u64
});
snapshot_struct!(DebugType { id: u64, kind: String, name: String, size: u32, target: u64, count: u32, fields: Vec<DebugField> });
snapshot_struct!(DebugParameter {
    name: String,
    type_id: u64
});

pub struct Session {
    inner: cxx::UniquePtr<ffi::Session>,
    _serial: PhantomData<Rc<()>>,
}
impl Session {
    pub fn add_debug_types(&mut self, types: &[DebugType]) -> Result<(), Error> {
        self.inner.pin_mut().add_debug_types(types)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn set_debug_signature(
        &mut self,
        address: u64,
        result: u64,
        model: &str,
        parameters: &[DebugParameter],
        varargs: bool,
        go: bool,
        multi: bool,
        noreturn: bool,
    ) -> Result<bool, Error> {
        self.inner.pin_mut().set_debug_signature(
            address, result, model, parameters, varargs, go, multi, noreturn,
        )
    }
    pub fn add_debug_local(
        &mut self,
        address: u64,
        name: &str,
        type_id: u64,
        offset: i64,
    ) -> Result<bool, Error> {
        self.inner
            .pin_mut()
            .add_debug_local(address, name, type_id, offset)
    }

    /// Start (or restart) emulation with a fresh memory and register state over the mapped image.
    pub fn emu_reset(&mut self) -> Result<(), Error> {
        self.inner.pin_mut().emu_reset()
    }
    /// Map zero-filled memory for the emulator (stack, buffers, heap); it must not overlap the image.
    pub fn emu_map(&mut self, address: u64, size: u64) -> Result<(), Error> {
        self.inner.pin_mut().emu_map(address, size)
    }
    pub fn emu_mapped(&mut self, address: u64, size: u64) -> Result<bool, Error> {
        self.inner.pin_mut().emu_mapped(address, size)
    }
    /// Write emulated memory; `record` counts it among the writes made by the code (a modelled
    /// library call), otherwise it is setup.
    pub fn emu_write(&mut self, address: u64, bytes: &[u8], record: bool) -> Result<(), Error> {
        self.inner.pin_mut().emu_write(address, bytes, record)
    }
    /// Read emulated memory; empty when any byte is unmapped.
    pub fn emu_read(&mut self, address: u64, size: u32) -> Result<Vec<u8>, Error> {
        self.inner.pin_mut().emu_read(address, size)
    }
    pub fn emu_set_register(&mut self, name: &str, value: u64) -> Result<(), Error> {
        self.inner.pin_mut().emu_set_register(name, value)
    }
    pub fn emu_get_register(&mut self, name: &str) -> Result<u64, Error> {
        self.inner.pin_mut().emu_get_register(name)
    }
    /// Memory the emulated code wrote since the last [`Self::emu_clear_writes`], as merged ranges.
    pub fn emu_writes(&mut self) -> Result<Vec<CodeRange>, Error> {
        self.inner.pin_mut().emu_writes()
    }
    pub fn emu_clear_writes(&mut self) -> Result<(), Error> {
        self.inner.pin_mut().emu_clear_writes()
    }
    /// Execute from `pc` until a stop condition; see [`EmuStop`].
    pub fn emu_run(
        &mut self,
        pc: u64,
        max_steps: u64,
        timeout_ms: u32,
        stops: &[u64],
    ) -> Result<EmuStop, Error> {
        self.inner
            .pin_mut()
            .emu_run(pc, max_steps, timeout_ms, stops)
    }

    pub fn new(language: Language) -> Result<Self, Error> {
        Ok(Self {
            inner: ffi::new_session(language)?,
            _serial: PhantomData,
        })
    }
    pub fn add_section(
        &mut self,
        address: u64,
        bytes: &[u8],
        executable: bool,
        readonly: bool,
    ) -> Result<(), Error> {
        self.inner
            .pin_mut()
            .add_section(address, bytes, executable, readonly)
    }
    pub fn set_arm_mode(&mut self, start: u64, end: u64, thumb: bool) -> Result<(), Error> {
        self.inner.pin_mut().set_arm_mode(start, end, thumb)
    }
    pub fn set_register_value(
        &mut self,
        start: u64,
        end: u64,
        name: &str,
        value: u64,
    ) -> Result<(), Error> {
        self.inner
            .pin_mut()
            .set_register_value(start, end, name, value)
    }
    pub fn add_function(&mut self, address: u64, name: &str, noreturn: bool) -> Result<(), Error> {
        self.inner.pin_mut().add_function(address, name, noreturn)
    }
    /// Replace sorted, non-overlapping metadata ranges without splitting byte mappings.
    /// At most 100,000 ranges are accepted; invalid input leaves the previous set intact.
    pub fn set_code_exclusions(&mut self, ranges: &[CodeRange]) -> Result<(), Error> {
        self.inner.pin_mut().set_code_exclusions(ranges)
    }

    /// Unambiguous unwind ranges constrain speculative jump-table recovery.
    pub fn set_function_ranges(&mut self, ranges: &[CodeRange]) -> Result<(), Error> {
        self.inner.pin_mut().set_function_ranges(ranges)
    }
    pub fn add_import(&mut self, address: u64, name: &str, noreturn: bool) -> Result<(), Error> {
        self.inner.pin_mut().add_import(address, name, noreturn)
    }
    /// Known callee stack cleanup, excluding the return address; -1 means unknown.
    pub fn stack_purge(&mut self, address: u64) -> Result<i32, Error> {
        self.inner.pin_mut().stack_purge(address)
    }
    pub fn set_stack_purge(&mut self, address: u64, bytes: u32) -> Result<(), Error> {
        self.inner.pin_mut().set_stack_purge(address, bytes)
    }
    /// Replace a validated compiler idiom with a direct branch and optional stack pop.
    pub fn add_branch(
        &mut self,
        site: u64,
        target: u64,
        length: u32,
        pop: u32,
    ) -> Result<(), Error> {
        self.inner.pin_mut().add_branch(site, target, length, pop)
    }

    pub fn add_tail_call(&mut self, caller: u64, site: u64, target: u64) -> Result<(), Error> {
        self.inner.pin_mut().add_tail_call(caller, site, target)
    }
    pub fn set_signature(
        &mut self,
        address: u64,
        result: ValueType,
        parameters: &[ValueType],
    ) -> Result<(), Error> {
        self.inner
            .pin_mut()
            .set_signature(address, result, parameters)
    }
    /// Preserve explicitly populated arguments to an untyped variadic callee.
    pub fn set_callsite_arguments(
        &mut self,
        caller: u64,
        site: u64,
        target: u64,
        count: u32,
    ) -> Result<bool, Error> {
        self.inner
            .pin_mut()
            .set_callsite_arguments(caller, site, target, count)
    }

    /// Give fixed Win64 functions the stack arguments every caller writes and the body reads,
    /// counted after the four register arguments. Replaces the previous set.
    pub fn set_win64_stack_arguments(
        &mut self,
        targets: &[u64],
        counts: &[u32],
    ) -> Result<(), Error> {
        self.inner
            .pin_mut()
            .set_win64_stack_arguments(targets, counts)
    }

    /// Give one Objective-C message send its arguments: self, the selector and one per colon.
    pub fn set_message_send(&mut self, caller: u64, site: u64, count: u32) -> Result<bool, Error> {
        self.inner.pin_mut().set_message_send(caller, site, count)
    }

    /// Install a bounded ABI0 stack layout inferred from function metadata and stores.
    pub fn set_go_stack_layout(
        &mut self,
        address: u64,
        inputs: u32,
        results: u32,
    ) -> Result<bool, Error> {
        self.inner
            .pin_mut()
            .set_go_stack_layout(address, inputs, results)
    }

    /// Treat strings as counted (Go, Rust): data found by a NUL-terminated scan is named but
    /// not typed as text, since the terminator is not where such a string ends.
    pub fn set_counted_strings(&mut self, enabled: bool) -> Result<(), Error> {
        self.inner.pin_mut().set_counted_strings(enabled)
    }
    /// Enable Linux syscall resolution for Linux languages (enabled by default).
    /// Disable for a non-Linux image using the same System V calling convention.
    pub fn set_linux_syscalls(&mut self, enabled: bool) -> Result<(), Error> {
        self.inner.pin_mut().set_linux_syscalls(enabled)
    }
    /// Apply the archive prototype named `name` to a registered function or import.
    /// Returns false when the packed Ghidra data type archives do not know the name.
    pub fn apply_prototype(&mut self, address: u64, name: &str) -> Result<bool, Error> {
        self.inner.pin_mut().apply_prototype(address, name)
    }
    /// Decode every packed type and prototype; returns a summary with failures.
    #[doc(hidden)]
    pub fn validate_prototype_pack(&mut self, max_report: u32) -> Result<String, Error> {
        self.inner.pin_mut().validate_prototype_pack(max_report)
    }
    /// A C++ class: a structure named `name` holding a pointer to each of its virtual function
    /// tables, each labeled and typed as a structure of method pointers. Call after every
    /// function is registered, since the slots are named after the functions they point to.
    pub fn add_class(&mut self, name: &str, tables: &[VfTable]) -> Result<(), Error> {
        self.inner.pin_mut().add_class(name, tables)
    }
    /// Make the function at `address` a method of `class_name`: the `__thiscall` model, with
    /// `this` typed as a pointer to the class. The other parameters are still inferred. False when
    /// the language has no such model or the prototype is already locked.
    pub fn set_method(&mut self, address: u64, class_name: &str) -> Result<bool, Error> {
        self.inner.pin_mut().set_method(address, class_name)
    }
    /// Set the fixed integer inputs of a verified SysV va_list forwarder.
    /// The callee's return storage is inferred separately; explicit signatures win.
    pub fn set_variadic_forwarder(
        &mut self,
        address: u64,
        fixed: u32,
        target: u64,
    ) -> Result<bool, Error> {
        self.inner
            .pin_mut()
            .set_variadic_forwarder(address, fixed, target)
    }
    /// [`Self::set_signature`] with a named model (the default when the compiler specification has
    /// none of that name), a leading `this` pointer to `this_class` unless it is empty, and
    /// optional variadic arguments after the fixed ones.
    pub fn set_method_signature(
        &mut self,
        address: u64,
        model: &str,
        this_class: &str,
        result: ValueType,
        parameters: &[ValueType],
        varargs: bool,
    ) -> Result<(), Error> {
        self.inner
            .pin_mut()
            .set_method_signature(address, model, this_class, result, parameters, varargs)
    }
    /// A persistent label for `size` bytes of data at `address`. False when the address already
    /// has a symbol or is not mapped.
    pub fn add_label(&mut self, address: u64, name: &str, size: u32) -> Result<bool, Error> {
        self.inner.pin_mut().add_label(address, name, size)
    }

    pub fn add_code_label(&mut self, owner: u64, address: u64, name: &str) -> Result<(), Error> {
        self.inner.pin_mut().add_code_label(owner, address, name)
    }

    /// Apply encoded C++ input types without inventing an unencoded return type.
    pub fn set_cpp_parameters(
        &mut self,
        address: u64,
        parameters: &[CppParameter],
        varargs: bool,
    ) -> Result<bool, Error> {
        self.inner
            .pin_mut()
            .set_cpp_parameters(address, parameters, varargs)
    }
    /// Select an inferred model without overriding explicit prototype facts.
    pub fn set_function_model(&mut self, address: u64, model: &str) -> Result<bool, Error> {
        self.inner.pin_mut().set_function_model(address, model)
    }
    /// Select Rust's platform convention and load Ghidra's Rust helper fixups.
    pub fn set_rust_function(&mut self, address: u64) -> Result<(), Error> {
        self.inner.pin_mut().set_rust_function(address)
    }

    /// Register an exact UTF-8 slice and optionally its pointer/length descriptor (zero for none).
    pub fn add_rust_string(
        &mut self,
        address: u64,
        length: u32,
        descriptor: u64,
    ) -> Result<bool, Error> {
        self.inner
            .pin_mut()
            .add_rust_string(address, length, descriptor)
    }
    /// Explicit ABI fact, used for recognized runtime helpers only.
    pub fn set_preserves_rax(&mut self, address: u64) -> Result<(), Error> {
        self.inner.pin_mut().set_preserves_rax(address)
    }

    /// Replace the work budget of the print phase alone; 0 uses the request's budget. A request's
    /// analysis needs far more work than its printing, so a test cannot otherwise stop a print
    /// partway without depending on the clock.
    #[doc(hidden)]
    pub fn set_print_work_limit(&mut self, work: u32) -> Result<(), Error> {
        self.inner.pin_mut().set_print_work_limit(work)
    }

    /// Install byte-verified leaf facts: zero high EAX/RAX bytes and an untouched ECX/RCX.
    /// `zero_from` is the first known-zero byte; 0 leaves return bits unknown.
    pub fn set_leaf_effects(
        &mut self,
        address: u64,
        zero_from: u32,
        preserves_ecx: bool,
    ) -> Result<(), Error> {
        self.inner
            .pin_mut()
            .set_leaf_effects(address, zero_from, preserves_ecx)
    }
    /// Replace calls to the function at `address` with one of the compiler
    /// specification's `<callfixup>` p-code snippets (for example
    /// `security_check_cookie`). Unknown fixup names are an error.
    pub fn set_call_fixup(&mut self, address: u64, fixup: &str) -> Result<(), Error> {
        self.inner.pin_mut().set_call_fixup(address, fixup)
    }
    /// Go languages: the binary's operating system (`w`, `l` or `d`) and Go minor version, which
    /// select the standard library signatures and types; whether it uses the register ABI (Go 1.17+
    /// on amd64), which selects the default model; and the extent of its code, where the goroutine
    /// register R14 points at `CURRENT_G` and XMM15 is zero. Call before registering functions.
    pub fn set_go_target(
        &mut self,
        os: &str,
        minor: u32,
        register_abi: bool,
        text_start: u64,
        text_end: u64,
    ) -> Result<(), Error> {
        self.inner
            .pin_mut()
            .set_go_target(os, minor, register_abi, text_start, text_end)
    }
    /// Apply the Go signature the standard library snapshot gives `name` (in its snapshot form,
    /// `os.(*os.File).Write`), with the storage the Go ABI assigns. False when the snapshot does not
    /// have it or a type cannot be built.
    pub fn apply_go_prototype(&mut self, address: u64, name: &str) -> Result<bool, Error> {
        self.inner.pin_mut().apply_go_prototype(address, name)
    }
    /// Give a Go runtime helper its own convention: `abi0`, `duffzero`, `duffcopy`, `gcwrite_batch`,
    /// `gcwrite_batch_numbytes`, `gcwrite_buffered` or `gcwrite_buffered:<register>`. False when
    /// the language has no such model (x86-32).
    pub fn set_go_special(&mut self, address: u64, kind: &str) -> Result<bool, Error> {
        self.inner.pin_mut().set_go_special(address, kind)
    }
    /// Decode every Go pack record that applies to one operating system and Go minor version;
    /// returns a summary with failures. `unallocated` counts signatures whose Go ABI storage cannot
    /// be expressed (they are left unapplied, not wrong).
    #[doc(hidden)]
    pub fn validate_go_pack(
        &mut self,
        os: &str,
        minor: u32,
        max_report: u32,
    ) -> Result<String, Error> {
        self.inner.pin_mut().validate_go_pack(os, minor, max_report)
    }
    pub fn decompile(
        &mut self,
        address: u64,
        timeout_ms: u32,
        max_instructions: u32,
        max_work: u32,
    ) -> Result<NativeOutput, Error> {
        self.decompile_with_hints(address, timeout_ms, max_instructions, max_work, 0, false)
    }

    /// Decompile with request-local, speculative return-width and x86 cdecl hints.
    /// `return_bytes` is 0, 4 or 8; on x86-32, 1 asks to use a single locked
    /// four-byte callee return that the caller established is forwarded. On
    /// x86-64, 1 records a caller's AL use and requires Boolean partial returns
    /// in the selected function before narrowing its output.
    /// Locked signatures take precedence, and an applied hint is incomplete.
    pub fn decompile_with_hints(
        &mut self,
        address: u64,
        timeout_ms: u32,
        max_instructions: u32,
        max_work: u32,
        return_bytes: u32,
        cdecl: bool,
    ) -> Result<NativeOutput, Error> {
        self.inner.pin_mut().decompile(
            address,
            timeout_ms,
            max_instructions,
            max_work,
            return_bytes,
            cdecl,
        )
    }
}
