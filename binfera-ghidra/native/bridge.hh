#pragma once
#include "rust/cxx.h"
#include <memory>
namespace binfera {
struct NativeOutput;
struct CodeRange;
struct EmuStop;
struct VfTable;
struct DebugType;
struct DebugParameter;
struct CppParameter;
enum class ValueType : uint8_t;
enum class Language : uint8_t;
class Session {
public:
  class Impl;
private:
  std::unique_ptr<Impl> impl;
public:
  explicit Session(Language language);
  ~Session();
  void add_section(uint64_t address, rust::Slice<const uint8_t> bytes, bool executable, bool readonly);
  void set_arm_mode(uint64_t start, uint64_t end, bool thumb);
  void set_register_value(uint64_t start, uint64_t end, rust::Str name, uint64_t value);
  void set_code_exclusions(rust::Slice<const CodeRange> ranges);
  void set_function_ranges(rust::Slice<const CodeRange> ranges);
  void add_function(uint64_t address, rust::Str name, bool noreturn);
  void add_import(uint64_t address, rust::Str name, bool noreturn);
  int32_t stack_purge(uint64_t address);
  void set_stack_purge(uint64_t address, uint32_t bytes);
  void add_branch(uint64_t site, uint64_t target, uint32_t length, uint32_t pop);
  void add_tail_call(uint64_t caller, uint64_t site, uint64_t target);
  void add_debug_types(rust::Slice<const DebugType> types);
  bool set_debug_signature(uint64_t address, uint64_t result, rust::Str model, rust::Slice<const DebugParameter> parameters,
                           bool varargs, bool go, bool multi, bool noreturn);
  bool add_debug_local(uint64_t address, rust::Str name, uint64_t type_id, int64_t offset);
  void set_signature(uint64_t address, ValueType result, rust::Slice<const ValueType> parameters);
  void set_preserves_rax(uint64_t address);
  void set_print_work_limit(uint32_t work);
  void set_leaf_effects(uint64_t address, uint32_t zero_from, bool preserves_ecx);
  void add_class(rust::Str name, rust::Slice<const VfTable> tables);
  bool set_method(uint64_t address, rust::Str class_name);
  void set_method_signature(uint64_t address, rust::Str model, rust::Str this_class, ValueType result,
                            rust::Slice<const ValueType> parameters, bool varargs);
  bool set_variadic_forwarder(uint64_t address, uint32_t fixed, uint64_t target);
  bool add_label(uint64_t address, rust::Str name, uint32_t size);
  void add_code_label(uint64_t owner, uint64_t address, rust::Str name);
  bool set_cpp_parameters(uint64_t address, rust::Slice<const CppParameter> parameters, bool varargs);
  bool set_function_model(uint64_t address, rust::Str model);
  void set_rust_function(uint64_t address);
  bool add_rust_string(uint64_t address, uint32_t length, uint64_t descriptor);
  void set_call_fixup(uint64_t address, rust::Str fixup);
  void set_go_target(rust::Str os, uint32_t minor, bool register_abi, uint64_t text_start, uint64_t text_end);
  bool apply_go_prototype(uint64_t address, rust::Str name);
  bool set_go_special(uint64_t address, rust::Str kind);
  rust::String validate_go_pack(rust::Str os, uint32_t minor, uint32_t max_report);
  bool set_callsite_arguments(uint64_t caller, uint64_t site, uint64_t target, uint32_t count);
  void set_win64_stack_arguments(rust::Slice<const uint64_t> targets, rust::Slice<const uint32_t> counts);
  bool set_message_send(uint64_t caller, uint64_t site, uint32_t count);
  bool set_go_stack_layout(uint64_t address, uint32_t inputs, uint32_t results);
  void set_counted_strings(bool enabled);
  void set_linux_syscalls(bool enabled);
  bool apply_prototype(uint64_t address, rust::Str name);
  rust::String validate_prototype_pack(uint32_t max_report);
  void emu_reset();
  void emu_map(uint64_t address, uint64_t size);
  bool emu_mapped(uint64_t address, uint64_t size);
  void emu_write(uint64_t address, rust::Slice<const uint8_t> bytes, bool record);
  rust::Vec<uint8_t> emu_read(uint64_t address, uint32_t size);
  void emu_set_register(rust::Str name, uint64_t value);
  uint64_t emu_get_register(rust::Str name);
  rust::Vec<CodeRange> emu_writes();
  void emu_clear_writes();
  EmuStop emu_run(uint64_t pc, uint64_t max_steps, uint32_t timeout_ms, rust::Slice<const uint64_t> stops);
  NativeOutput decompile(uint64_t address, uint32_t timeout_ms, uint32_t max_instructions, uint32_t max_work, uint32_t return_bytes, bool use_cdecl);
};
std::unique_ptr<Session> new_session(Language language);
// The embedded prototype pack for one language, read by the Rust side to describe types and callees.
rust::Slice<const uint8_t> prototype_pack_bytes(Language language);
// Supplies (or, with `present` false, withdraws) the Windows API prototype archive of one pointer width.
void set_windows_pack(bool wide, rust::Slice<const uint8_t> bytes, bool present);
}
