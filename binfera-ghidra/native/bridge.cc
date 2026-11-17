#include "bridge.hh"
#include "binfera-ghidra/src/lib.rs.h"
#include "hooks.hh"
#include "specs.hh"
#include "sleigh_arch.hh"
#include "funcdata.hh"
#include "flow.hh"
#include "printc.hh"
#include <algorithm>
#include <chrono>
#include <cctype>
#include <iomanip>
#include <cstdio>
#include <cstring>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <limits>
#include <set>
#include <map>
#include <vector>
#include <zlib.h>

using namespace ghidra;
namespace {
std::mutex engine_mutex;
std::once_flag initialized;
struct Budget {
  bool active = false;
  /// A checkpoint ran out of budget. The exception it threw can be swallowed by the engine.
  bool exhausted = false;
  uint64_t remaining = 0;
  std::chrono::steady_clock::time_point deadline;
  const char *reason = "";
  uint32_t clock_checks = 0;
};
thread_local Budget budget;
// Cooperative limits abort one request; the session stays usable because every
// request starts by clearing the analysis state it touched.
struct BudgetExceeded : std::runtime_error {
  using std::runtime_error::runtime_error;
};
// Charge \p work units, as if the engine had spent them itself.
void charge(uint64_t work) {
  if (!budget.active) return;
  if (budget.remaining < work) { budget.remaining = 0; budget.exhausted = true; budget.reason = "native work limit exceeded"; throw BudgetExceeded(budget.reason); }
  budget.remaining -= work;
}
struct BudgetGuard {
  // \p overall caps the whole request, so phases that each get a fresh budget cannot stack
  // into minutes of wall time for one function.
  BudgetGuard(uint32_t ms, uint32_t work, std::chrono::steady_clock::time_point overall = std::chrono::steady_clock::time_point::max()) {
    const auto phase = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    budget = {true, false, work, phase < overall ? phase : overall, ""};
  }
  ~BudgetGuard() { budget.active = false; }
};
// Convert Ghidra's non-std exceptions before CXX's std::exception boundary.
template<class F> auto checked(F f) -> decltype(f()) {
  try { return f(); }
  catch (const LowlevelError &e) { throw std::runtime_error(e.explain); }
  catch (const DecoderError &e) { throw std::runtime_error(e.explain); }
  catch (const std::exception &) { throw; }
  catch (...) { throw std::runtime_error("unknown native decompiler exception"); }
}
bool informationalWarning(const std::string &text) {
  return text.find(" replaced with injection: ") != std::string::npos ||
         text.find("\": Some values do not have unique names") != std::string::npos ||
         text == "WARNING: Subroutine does not return" ||
         text.find("Removing unreachable block") != std::string::npos;
}
// Keep prototype inference conservative even though known no-return effects
// are informational to the reader. A partial path is not return-storage evidence.
bool inferenceGap(const std::string &text) {
  return text == "WARNING: Subroutine does not return" || !informationalWarning(text);
}
// docFunction clears its partial state only for LowlevelError. A limit or an output failure leaves
// queued tokens and indentation behind, which would then appear in later functions' text.
struct PrinterReset {
  PrintLanguage *print;
  std::ostream *fallback;
  bool finished = false;
  ~PrinterReset() {
    if (finished) return;
    print->clear();
    print->setMarkup(false);
    print->setOutputStream(fallback);
  }
};
class OutputBuffer : public std::streambuf {
  std::string text;
protected:
  std::streamsize xsputn(const char *data, std::streamsize count) override {
    binfera_check();
    if (count < 0 || uint64_t(count) > 4 * 1024 * 1024 - text.size())
      throw std::runtime_error("pseudocode output limit exceeded");
    text.append(data, size_t(count));
    return count;
  }
  int_type overflow(int_type ch) override {
    if (traits_type::eq_int_type(ch, traits_type::eof())) return traits_type::not_eof(ch);
    char byte = traits_type::to_char_type(ch);
    xsputn(&byte, 1);
    return ch;
  }
public:
  const std::string &str() const { return text; }
};
// One entry per supported language. Everything that differs between x86-32 and
// x86-64 (language, specs, prototype pack, pointer width, the unmapped range used for
// import targets) lives here; the rest of the bridge reads it from the session.
struct Spec {
  bool wide;
  const char *archid;
  const char *description;
  const unsigned char *sla; size_t sla_size;
  const unsigned char *pspec; size_t pspec_size;
  const unsigned char *cspec; size_t cspec_size;
  const unsigned char *pack; size_t pack_size;
  int pointer;
  uint64_t external_base;
  uint64_t address_limit;
  // Go languages only: the Go prototype pack (standard library signatures and Go types), the
  // model that C prototypes from the archive take (the Go compiler specs name System V
  // `__stdcall` and Windows `MSABI`), and where the current goroutine's `runtime.g` is placed.
  const unsigned char *go_pack = nullptr; size_t go_pack_size = 0;
  const char *import_model = nullptr;
  uint64_t go_context = 0;
  const char *default_model = nullptr;
};
const Spec &spec_for(binfera::Language language) {
  // Empty archive: x86-specific structure layouts and syscall ABIs must not leak
  // into ARM/MIPS. Function parameters come from these compiler models and DWARF.
  static const unsigned char empty_pack[] = {'C','X','P','R','O','T','O','1',0,0,0,0};
  static const Spec arm32{false, "ARM:LE:32:v7:default", "ARM32 AAPCS", sla_arm32_bytes, sizeof(sla_arm32_bytes),
    pspec_arm32_bytes, sizeof(pspec_arm32_bytes), cspec_arm32_bytes, sizeof(cspec_arm32_bytes),
    empty_pack, sizeof(empty_pack), 4, 0xffff0000ULL, 0x100000000ULL};
  static const Spec arm32soft = [] { Spec s = arm32; s.default_model = "__stdcall_softfp"; return s; }();
  static const Spec arm32win{false, "ARM:LE:32:v7:windows", "ARM32 Windows", sla_arm32_bytes, sizeof(sla_arm32_bytes),
    pspec_arm32_bytes, sizeof(pspec_arm32_bytes), cspec_arm32win_bytes, sizeof(cspec_arm32win_bytes),
    empty_pack, sizeof(empty_pack), 4, 0xffff0000ULL, 0x100000000ULL};
  static const Spec mipsle{false, "MIPS:LE:32:default:default", "MIPS32 o32 little endian", sla_mipsle_bytes, sizeof(sla_mipsle_bytes),
    pspec_mipsle_bytes, sizeof(pspec_mipsle_bytes), cspec_mipsle_bytes, sizeof(cspec_mipsle_bytes),
    empty_pack, sizeof(empty_pack), 4, 0xffff0000ULL, 0x100000000ULL};
  static const Spec mipsbe{false, "MIPS:BE:32:default:default", "MIPS32 o32 big endian", sla_mipsbe_bytes, sizeof(sla_mipsbe_bytes),
    pspec_mipsbe_bytes, sizeof(pspec_mipsbe_bytes), cspec_mipsbe_bytes, sizeof(cspec_mipsbe_bytes),
    empty_pack, sizeof(empty_pack), 4, 0xffff0000ULL, 0x100000000ULL};

  static const Spec win64{true, "x86:LE:64:default:windows", "x86-64 Windows", sla_x64_bytes, sizeof(sla_x64_bytes),
    pspec_x64_bytes, sizeof(pspec_x64_bytes), cspec_x64_bytes, sizeof(cspec_x64_bytes),
    pack_x64_bytes, sizeof(pack_x64_bytes), 8, 0xffff000000000000ULL, 0xffff000000000000ULL};
  static const Spec win32{false, "x86:LE:32:default:windows", "x86-32 Windows", sla_x86_bytes, sizeof(sla_x86_bytes),
    pspec_x86_bytes, sizeof(pspec_x86_bytes), cspec_x86_bytes, sizeof(cspec_x86_bytes),
    pack_x86_bytes, sizeof(pack_x86_bytes), 4, 0xf0000000ULL, 0xf0000000ULL};
  // The same SLEIGH language and processor context as Windows x86-64; only the compiler
  // specification (System V calling convention) and the type archive (the C library) differ.
  static const Spec linux64{true, "x86:LE:64:default:gcc", "x86-64 System V", sla_x64_bytes, sizeof(sla_x64_bytes),
    pspec_x64_bytes, sizeof(pspec_x64_bytes), cspec_x64gcc_bytes, sizeof(cspec_x64gcc_bytes),
    pack_sysv64_bytes, sizeof(pack_sysv64_bytes), 8, 0xffff000000000000ULL, 0xffff000000000000ULL};
  // The x86-32 SLEIGH language and processor context with another compiler: System V i386 has
  // its own C library archive, while Delphi and Borland C++ call the same Win32 imports as
  // Visual C, typed by the same archive.
  static const Spec linux32{false, "x86:LE:32:default:gcc", "x86-32 System V", sla_x86_bytes, sizeof(sla_x86_bytes),
    pspec_x86_bytes, sizeof(pspec_x86_bytes), cspec_x86gcc_bytes, sizeof(cspec_x86gcc_bytes),
    pack_sysv32_bytes, sizeof(pack_sysv32_bytes), 4, 0xf0000000ULL, 0xf0000000ULL};
  static const Spec delphi32{false, "x86:LE:32:default:borlanddelphi", "x86-32 Delphi", sla_x86_bytes, sizeof(sla_x86_bytes),
    pspec_x86_bytes, sizeof(pspec_x86_bytes), cspec_x86delphi_bytes, sizeof(cspec_x86delphi_bytes),
    pack_x86_bytes, sizeof(pack_x86_bytes), 4, 0xf0000000ULL, 0xf0000000ULL};
  static const Spec borland32{false, "x86:LE:32:default:borlandcpp", "x86-32 Borland C++", sla_x86_bytes, sizeof(sla_x86_bytes),
    pspec_x86_bytes, sizeof(pspec_x86_bytes), cspec_x86borland_bytes, sizeof(cspec_x86borland_bytes),
    pack_x86_bytes, sizeof(pack_x86_bytes), 4, 0xf0000000ULL, 0xf0000000ULL};
  // Go: Ghidra's Go compiler specifications (`abi-internal`, the register ABI of Go 1.17+, and
  // `abi0`, the stack ABI) with the platform's C archive for imports and the Go pack for Go's own
  // functions. The goroutine's `runtime.g` sits just below the import range, unmapped.
  static const Spec go_win64{true, "x86:LE:64:default:golang", "x86-64 Go (Windows)", sla_x64_bytes, sizeof(sla_x64_bytes),
    pspec_x64_bytes, sizeof(pspec_x64_bytes), cspec_x64go_bytes, sizeof(cspec_x64go_bytes),
    pack_x64_bytes, sizeof(pack_x64_bytes), 8, 0xffff000000000000ULL, 0xffff000000000000ULL,
    pack_go64_bytes, sizeof(pack_go64_bytes), "MSABI", 0xfffe000000000000ULL};
  static const Spec go_linux64{true, "x86:LE:64:default:golang", "x86-64 Go (System V)", sla_x64_bytes, sizeof(sla_x64_bytes),
    pspec_x64_bytes, sizeof(pspec_x64_bytes), cspec_x64go_bytes, sizeof(cspec_x64go_bytes),
    pack_sysv64_bytes, sizeof(pack_sysv64_bytes), 8, 0xffff000000000000ULL, 0xffff000000000000ULL,
    pack_go64_bytes, sizeof(pack_go64_bytes), "__stdcall", 0xfffe000000000000ULL};
  static const Spec go_win32{false, "x86:LE:32:default:golang", "x86-32 Go (Windows)", sla_x86_bytes, sizeof(sla_x86_bytes),
    pspec_x86_bytes, sizeof(pspec_x86_bytes), cspec_x86go_bytes, sizeof(cspec_x86go_bytes),
    pack_x86_bytes, sizeof(pack_x86_bytes), 4, 0xf0000000ULL, 0xf0000000ULL,
    pack_go32_bytes, sizeof(pack_go32_bytes), nullptr, 0};
  static const Spec go_linux32{false, "x86:LE:32:default:golang", "x86-32 Go (System V)", sla_x86_bytes, sizeof(sla_x86_bytes),
    pspec_x86_bytes, sizeof(pspec_x86_bytes), cspec_x86go_bytes, sizeof(cspec_x86go_bytes),
    pack_sysv32_bytes, sizeof(pack_sysv32_bytes), 4, 0xf0000000ULL, 0xf0000000ULL,
    pack_go32_bytes, sizeof(pack_go32_bytes), nullptr, 0};
  static const Spec arm_linux{true, "AARCH64:LE:64:v8A:default", "AArch64 Linux", sla_arm64_bytes, sizeof(sla_arm64_bytes),
    pspec_arm64_bytes, sizeof(pspec_arm64_bytes), cspec_arm64_bytes, sizeof(cspec_arm64_bytes),
    pack_sysv64_bytes, sizeof(pack_sysv64_bytes), 8, 0xffff000000000000ULL, 0xffff000000000000ULL};
  static const Spec arm_win{true, "AARCH64:LE:64:v8A:windows", "AArch64 Windows", sla_arm64_bytes, sizeof(sla_arm64_bytes),
    pspec_arm64_bytes, sizeof(pspec_arm64_bytes), cspec_arm64win_bytes, sizeof(cspec_arm64win_bytes),
    pack_x64_bytes, sizeof(pack_x64_bytes), 8, 0xffff000000000000ULL, 0xffff000000000000ULL};
  static const Spec arm_apple{true, "AARCH64:LE:64:v8A:apple", "AArch64 Apple", sla_arm64_bytes, sizeof(sla_arm64_bytes),
    pspec_arm64_bytes, sizeof(pspec_arm64_bytes), cspec_arm64apple_bytes, sizeof(cspec_arm64apple_bytes),
    pack_macos64_bytes, sizeof(pack_macos64_bytes), 8, 0xffff000000000000ULL, 0xffff000000000000ULL};
  static const Spec apple64{true, "x86:LE:64:default:gcc", "x86-64 Darwin", sla_x64_bytes, sizeof(sla_x64_bytes),
    pspec_x64_bytes, sizeof(pspec_x64_bytes), cspec_x64gcc_bytes, sizeof(cspec_x64gcc_bytes),
    pack_macos64_bytes, sizeof(pack_macos64_bytes), 8, 0xffff000000000000ULL, 0xffff000000000000ULL};
  static const Spec go_apple64{true, "x86:LE:64:default:golang", "x86-64 Go (Darwin)", sla_x64_bytes, sizeof(sla_x64_bytes),
    pspec_x64_bytes, sizeof(pspec_x64_bytes), cspec_x64go_bytes, sizeof(cspec_x64go_bytes),
    pack_macos64_bytes, sizeof(pack_macos64_bytes), 8, 0xffff000000000000ULL, 0xffff000000000000ULL,
    pack_go64_bytes, sizeof(pack_go64_bytes), "__stdcall", 0xfffe000000000000ULL};
  static const Spec go_arm_linux{true, "AARCH64:LE:64:v8A:golang", "AArch64 Go (Linux)", sla_arm64_bytes, sizeof(sla_arm64_bytes),
    pspec_arm64_bytes, sizeof(pspec_arm64_bytes), cspec_arm64go_bytes, sizeof(cspec_arm64go_bytes),
    pack_sysv64_bytes, sizeof(pack_sysv64_bytes), 8, 0xffff000000000000ULL, 0xffff000000000000ULL,
    pack_go64_bytes, sizeof(pack_go64_bytes), "__cdecl", 0xfffe000000000000ULL};
  static const Spec go_arm_win{true, "AARCH64:LE:64:v8A:golang", "AArch64 Go (Windows)", sla_arm64_bytes, sizeof(sla_arm64_bytes),
    pspec_arm64_bytes, sizeof(pspec_arm64_bytes), cspec_arm64gowin_bytes, sizeof(cspec_arm64gowin_bytes),
    pack_x64_bytes, sizeof(pack_x64_bytes), 8, 0xffff000000000000ULL, 0xffff000000000000ULL,
    pack_go64_bytes, sizeof(pack_go64_bytes), "__cdecl", 0xfffe000000000000ULL};
  static const Spec go_arm_apple{true, "AARCH64:LE:64:v8A:golang", "AArch64 Go (Darwin)", sla_arm64_bytes, sizeof(sla_arm64_bytes),
    pspec_arm64_bytes, sizeof(pspec_arm64_bytes), cspec_arm64goapple_bytes, sizeof(cspec_arm64goapple_bytes),
    pack_macos64_bytes, sizeof(pack_macos64_bytes), 8, 0xffff000000000000ULL, 0xffff000000000000ULL,
    pack_go64_bytes, sizeof(pack_go64_bytes), "__cdecl", 0xfffe000000000000ULL};
  switch (language) {
    case binfera::Language::ArmLinux: return arm32;
    case binfera::Language::ArmLinuxSoft: return arm32soft;
    case binfera::Language::ArmWindows: return arm32win;
    case binfera::Language::MipsLittle: return mipsle;
    case binfera::Language::MipsBig: return mipsbe;
    case binfera::Language::X86Apple64: return apple64;
    case binfera::Language::X86GoApple64: return go_apple64;
    case binfera::Language::AArch64GoLinux: return go_arm_linux;
    case binfera::Language::AArch64GoWindows: return go_arm_win;
    case binfera::Language::AArch64GoApple: return go_arm_apple;
    case binfera::Language::AArch64Linux: return arm_linux;
    case binfera::Language::AArch64Windows: return arm_win;
    case binfera::Language::AArch64Apple: return arm_apple;
    case binfera::Language::X86GoWindows64: return go_win64;
    case binfera::Language::X86GoLinux64: return go_linux64;
    case binfera::Language::X86GoWindows32: return go_win32;
    case binfera::Language::X86GoLinux32: return go_linux32;
    case binfera::Language::X86Windows32: return win32;
    case binfera::Language::X86Linux64: return linux64;
    case binfera::Language::X86Linux32: return linux32;
    case binfera::Language::X86Delphi32: return delphi32;
    case binfera::Language::X86Borland32: return borland32;
    default: return win64;
  }
}
const char *resultRegister(const Spec &spec) {
  if (spec.sla == sla_arm32_bytes) return "r0";
  if (spec.sla == sla_mipsle_bytes || spec.sla == sla_mipsbe_bytes) return "v0";
  if (spec.sla == sla_arm64_bytes) return "x0";
  return spec.wide ? "RAX" : "EAX";
}
bool linuxSpec(const Spec &spec) {
  return spec.sla != sla_arm64_bytes && (spec.pack == pack_sysv64_bytes || spec.pack == pack_sysv32_bytes);
}
// Set under engine_mutex around architecture construction, where the SLEIGH hook
// asks for the compiled specification.
const Spec *constructing_spec = nullptr;
struct Section {
  uint64_t address;
  std::vector<uint8_t> bytes;
  bool executable;
};
class Image : public LoadImage {
public:
  std::vector<Section> sections;
  std::vector<binfera::CodeRange> code_exclusions;
  std::vector<binfera::CodeRange> function_ranges;
  size_t total = 0;
  std::string arch_type;
  explicit Image(const Spec &spec)
    : LoadImage("binfera image"), arch_type(spec.archid) {}
  std::string getArchType() const override { return arch_type; }
  void adjustVma(long) override { throw LowlevelError("image relocation is unsupported"); }
  bool executable(uint64_t address, size_t size = 1) const {
    if (!size || size > UINT64_MAX - address) return false;
    const auto next = std::upper_bound(code_exclusions.begin(), code_exclusions.end(), address,
      [](uint64_t value, const binfera::CodeRange &range) { return value < range.start; });
    if (next != code_exclusions.begin() && (next - 1)->end > address) return false;
    if (next != code_exclusions.end() && next->start < address + size) return false;
    for (const auto &s : sections)
      if (address >= s.address && address - s.address < s.bytes.size())
        return s.executable && size <= s.bytes.size() - size_t(address - s.address);
    return false;
  }
  /// The mapped bytes from \p address to the end of its section, or empty.
  std::pair<const uint8_t *, size_t> bytesAt(uint64_t address) const {
    for (const auto &s : sections)
      if (address >= s.address && address - s.address < s.bytes.size())
        return {s.bytes.data() + (address - s.address), s.bytes.size() - size_t(address - s.address)};
    return {nullptr, 0};
  }
  bool mapped(uint64_t address) const { return bytesAt(address).first != nullptr; }
  void loadFill(uint1 *ptr, int4 size, const Address &address) override {
    binfera_check();
    auto current = address.getOffset();
    // Most reads fit within one section, including SLEIGH's 16-byte lookahead.
    if (size > 0 && uint64_t(size - 1) <= std::numeric_limits<uint64_t>::max() - current) {
      const auto bytes = bytesAt(current);
      if (size_t(size) <= bytes.second) {
        std::copy_n(bytes.first, size, ptr);
        return;
      }
    }
    // Ghidra requests a lookahead window even for a one-byte instruction.
    // Padding after mapped bytes is allowed, but never an unmapped start.
    for (int4 i = 0; i < size; ++i) {
      bool mapped = false;
      for (const auto &s : sections) {
        if (current >= s.address && current - s.address < s.bytes.size()) {
          ptr[i] = s.bytes.at(current - s.address);
          mapped = true;
          break;
        }
      }
      if (i == 0 && !mapped) throw DataUnavailError("read from unmapped image address");
      if (!mapped) ptr[i] = 0;
      if (current == std::numeric_limits<uint64_t>::max() && i + 1 < size)
        throw DataUnavailError("image address overflow");
      ++current;
    }
  }
};
// Data symbols. Ghidra's Java analysis labels the data a function touches:
// `DAT_<addr>` for plain data, `PTR_<target>_<addr>` for a pointer cell and
// `s_<text>_<addr>` / `u_<text>_<addr>` for narrow and wide string literals.
// The embedded engine has no program database, so the adapter derives the same
// names from the image bytes, per request (see docs/decompiler-design.md). Constants
// copied from Ghidra 12.1.4's observed labels: at most 32 characters of text,
// every character other than a letter, digit, `_`, `<` or `>` becomes `_`, trailing
// line breaks are dropped, and the address is lowercase hex padded to 8 digits.
struct StringLiteral {
  bool wide = false;
  size_t chars = 0;
  std::string label;
};
constexpr size_t kMinStringChars = 1;
constexpr size_t kMaxStringChars = 4096;
constexpr size_t kMaxLabelChars = 32;
std::string hexAddress(uint64_t address) {
  char text[24];
  std::snprintf(text, sizeof(text), "%08llx", static_cast<unsigned long long>(address));
  return text;
}
/// The engine's own default name for a global it had no symbol for, e.g. `uRam0000000140004098`.
/// mapGlobals stores these in the global scope, where they would otherwise outlive the request.
bool placeholderName(const std::string &name) {
  size_t i = 0;
  while (i < 8 && i < name.size() && std::isalpha(static_cast<unsigned char>(name[i])) && name.compare(i, 3, "Ram") != 0) ++i;
  // The address prints with two hex digits per address byte: 16 in x86-64, 8 in x86-32.
  if (name.compare(i, 3, "Ram") != 0 || (name.size() != i + 3 + 16 && name.size() != i + 3 + 8)) return false;
  for (size_t k = i + 3; k < name.size(); ++k)
    if (!((name[k] >= '0' && name[k] <= '9') || (name[k] >= 'a' && name[k] <= 'f'))) return false;
  return true;
}
std::string labelFromText(const std::string &text) {
  size_t end = text.size();
  while (end && (text[end - 1] == '\n' || text[end - 1] == '\r' || text[end - 1] == '\t')) --end;
  std::string label;
  for (size_t i = 0; i < end && i < kMaxLabelChars; ++i) {
    const unsigned char ch = static_cast<unsigned char>(text[i]);
    const bool keep = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
                      ch == '_' || ch == '<' || ch == '>';
    label += keep ? char(ch) : '_';
  }
  return label;
}
bool printable(unsigned ch) { return (ch >= 0x20 && ch < 0x7f) || ch == '\t' || ch == '\n' || ch == '\r'; }
/// A NUL-terminated printable ASCII or UTF-16LE (ASCII range) string at \p address.
bool detectString(const Image &image, uint64_t address, StringLiteral &out) {
  const auto [data, available] = image.bytesAt(address);
  if (!data) return false;
  size_t n = 0;
  while (n < available && n < kMaxStringChars && printable(data[n])) ++n;
  std::string text;
  size_t w = 0;
  while ((w + 1) * 2 + 1 < available && w < kMaxStringChars && data[2 * w + 1] == 0 && printable(data[2 * w])) {
    text += char(data[2 * w]);
    ++w;
  }
  if (w >= 2 && (w * 2 + 1) < available && data[2 * w] == 0 && data[2 * w + 1] == 0) {
    out.wide = true;
    out.chars = w;
    out.label = labelFromText(text);
    return true;
  }
  if (n >= kMinStringChars && n < available && data[n] == 0) {
    out.wide = false;
    out.chars = n;
    out.label = labelFromText(std::string(reinterpret_cast<const char *>(data), n));
    return true;
  }
  return false;
}
class ImageSleigh : public Sleigh {
  Image *image;
  const Spec &spec;
public:
  struct Branch { uint64_t target; uint32_t length, pop; };
  mutable std::map<uint64_t, Branch> branches;
  mutable std::map<uint64_t, uint32_t> return_zero_from;
  mutable uint64_t syscall_probe = 0;
  mutable bool linux_syscalls = true;
  mutable bool probe_syscalls = false;
  mutable std::set<uint64_t> syscall_sites;
  mutable std::map<uint64_t, uint64_t> syscall_targets;
  /// Set while emulating: translate the machine code exactly, without the decompiler's flow
  /// overrides, syscall rewriting or return-bit modelling.
  mutable bool raw = false;
  ImageSleigh(Image *loader, ContextDatabase *context, const Spec &s)
    : Sleigh(loader, context), image(loader), spec(s) {}
  // Probe only native Linux entry instructions. Compatibility int 0x80 in long mode has
  // a different ABI and deliberately stays untouched.
  int syscallLength(uint64_t address) const {
    if (!linux_syscalls || !linuxSpec(spec)) return 0;
    const auto bytes = image->bytesAt(address);
    if (bytes.second < 2) return 0;
    const auto *p = bytes.first;
    if (spec.wide) return p[0] == 0x0f && p[1] == 0x05 ? 2 : 0;
    if (p[0] == 0xcd && p[1] == 0x80) return 2;
    return 0;
  }
  int4 oneInstruction(PcodeEmit &emit, const Address &address) const override {
    if (!image->executable(address.getOffset())) {
      char text[80];
      std::snprintf(text, sizeof(text), "code flow left executable mapped memory at 0x%llx",
                    static_cast<unsigned long long>(address.getOffset()));
      // Ghidra's flow analysis turns this error into a warning and truncates the flow, which
      // keeps the rest of the function instead of failing the request.
      throw BadDataError(text);
    }
    if (raw) {
      const auto length = Sleigh::oneInstruction(emit, address);
      if (length <= 0 || !image->executable(address.getOffset(), size_t(length)))
        throw BadDataError("instruction crosses executable mapping boundary");
      return length;
    }
    auto branch = branches.find(address.getOffset());
    if (branch != branches.end()) {
      const auto &flow = branch->second;
      if (flow.pop) {
        VarnodeData sp = getRegister(spec.wide ? "RSP" : "ESP");
        VarnodeData args[2] = {sp, {getConstantSpace(), flow.pop, sp.size}};
        emit.dump(address, CPUI_INT_ADD, &sp, args, 2);
      }
      VarnodeData target{getDefaultCodeSpace(), flow.target, uint4(spec.pointer)};
      emit.dump(address, CPUI_BRANCH, nullptr, &target, 1);
      return flow.length;
    }
    const int syscall_length = syscallLength(address.getOffset());
    if (syscall_length && image->executable(address.getOffset(), syscall_length)) {
      auto found = syscall_targets.find(address.getOffset());
      if (!probe_syscalls && found != syscall_targets.end()) {
        VarnodeData target{getDefaultCodeSpace(), found->second, uint4(spec.pointer)};
        emit.dump(address, CPUI_CALL, nullptr, &target, 1);
        return syscall_length;
      }
      if (probe_syscalls) {
        syscall_sites.insert(address.getOffset());
        std::vector<std::string> names;
        getUserOpNames(names);
        auto id = std::find(names.begin(), names.end(), "syscall");
        VarnodeData result = getRegister(resultRegister(spec));
        VarnodeData inputs[2] = {{getConstantSpace(), uintb(id - names.begin()), 4}, result};
        // Expose the number to SSA and kill the old accumulator value. This temporary
        // operation never prints; a second pass restores unresolved instructions verbatim.
        emit.dump(address, CPUI_CALLOTHER, &result, inputs, 2);
        // CALLOTHER alone has no memory effects in Ghidra. A temporary opaque call
        // reads all six argument registers and invalidates memory that the kernel could
        // write, as well as the ABI's clobbered registers, before later numbers propagate.
        VarnodeData target{getDefaultCodeSpace(), syscall_probe, uint4(spec.pointer)};
        emit.dump(address, CPUI_CALL, nullptr, &target, 1);
        return syscall_length;
      }
    }
    // A narrow logical result does not erase physical high bits established by
    // the complete callee. Emit those zero writes after its CALL so heritage
    // keeps them separate from genuinely unknown scratch-register outputs.
    struct ReturnBits : PcodeEmit {
      PcodeEmit &sink;
      const ImageSleigh &translator;
      ReturnBits(PcodeEmit &s, const ImageSleigh &t) : sink(s), translator(t) {}
      void dump(const Address &at, OpCode op, VarnodeData *out, VarnodeData *inputs, int4 count) override {
        sink.dump(at, op, out, inputs, count);
        if (op != CPUI_CALL || count != 1 || inputs[0].space->getType() != IPTR_PROCESSOR) return;
        auto known = translator.return_zero_from.find(inputs[0].offset);
        if (known == translator.return_zero_from.end()) return;
        VarnodeData high = translator.getRegister(translator.spec.wide ? "RAX" : "EAX");
        high.offset += known->second;
        high.size -= known->second;
        VarnodeData zero{translator.getConstantSpace(), 0, high.size};
        sink.dump(at, CPUI_COPY, &high, &zero, 1);
      }
    } bits(emit, *this);
    const auto length = Sleigh::oneInstruction(bits, address);
    if (length <= 0 || !image->executable(address.getOffset(), size_t(length)))
      throw BadDataError("instruction crosses executable mapping boundary");
    return length;
  }
};
// Bounded discovery for an explicitly requested entry absent from recovery.
// Stop at any non-linear flow; only a direct jump to a supplied entry is a
// tail-call fact. All instructions are still translated by native SLEIGH.
class WrapperFlow : public PcodeEmit {
public:
  unsigned flows = 0;
  bool direct = false;
  Address target;
  void dump(const Address &, OpCode op, VarnodeData *, VarnodeData *inputs, int4 count) override {
    if (op == CPUI_BRANCH || op == CPUI_CBRANCH || op == CPUI_BRANCHIND ||
        op == CPUI_CALL || op == CPUI_CALLIND || op == CPUI_RETURN) {
      ++flows;
      if (op == CPUI_BRANCH && count == 1 && inputs[0].space->getType() == IPTR_PROCESSOR) {
        direct = true;
        target = Address(inputs[0].space, inputs[0].offset);
      }
    }
  }
};
// Prototype and type pack: Ghidra data type archive content exported offline
// (scripts/decompiler_types) in Ghidra's own decompiler marshalling. Entries are
// zlib blocks; a lookup inflates one bounded block. Serialized by engine_mutex.
class PrototypePack {
  struct Block { uint32_t offset, clength, rlength; std::string first; };
  std::vector<Block> blocks;
  const uint8_t *data = nullptr;
  size_t data_size = 0;
  std::map<size_t, std::string> cache;
  static uint32_t u32(const uint8_t *p) { return p[0] | p[1] << 8 | p[2] << 16 | uint32_t(p[3]) << 24; }
  const std::string &inflated(size_t index) {
    auto found = cache.find(index);
    if (found != cache.end()) return found->second;
    const Block &b = blocks[index];
    if (b.rlength > 4 * 1024 * 1024) throw std::runtime_error("prototype pack block too large");
    std::string raw(b.rlength, '\0');
    uLongf length = b.rlength;
    if (uncompress(reinterpret_cast<Bytef *>(&raw[0]), &length, data + b.offset, b.clength) != Z_OK || length != b.rlength)
      throw std::runtime_error("corrupt prototype pack block");
    if (cache.size() >= 16) cache.clear();
    return cache.emplace(index, std::move(raw)).first->second;
  }
public:
  PrototypePack(const unsigned char *bytes, size_t size) {
    const char magic[] = "CXPROTO1";
    if (size < 12 || memcmp(bytes, magic, 8) != 0) throw std::runtime_error("bad prototype pack header");
    const uint32_t count = u32(bytes + 8);
    size_t pos = 12;
    for (uint32_t i = 0; i < count; i++) {
      if (size - pos < 14) throw std::runtime_error("truncated prototype pack index");
      Block b{u32(bytes + pos), u32(bytes + pos + 4), u32(bytes + pos + 8), ""};
      const size_t key = bytes[pos + 12] | bytes[pos + 13] << 8;
      pos += 14;
      if (size - pos < key) throw std::runtime_error("truncated prototype pack key");
      b.first.assign(reinterpret_cast<const char *>(bytes + pos), key);
      pos += key;
      blocks.push_back(std::move(b));
    }
    data = bytes + pos;
    data_size = size - pos;
    for (const auto &b : blocks)
      if (b.offset > data_size || b.clength > data_size - b.offset) throw std::runtime_error("prototype pack block out of range");
  }
  size_t block_count() const { return blocks.size(); }
  /// Value after the first tab of the line keyed \p key.
  bool find(const std::string &key, std::string &value) {
    auto it = std::upper_bound(blocks.begin(), blocks.end(), key,
      [](const std::string &k, const Block &b) { return k < b.first; });
    if (it == blocks.begin()) return false;
    const std::string &raw = inflated(size_t(it - blocks.begin()) - 1);
    size_t pos = 0;
    while (pos < raw.size()) {
      size_t end = raw.find('\n', pos);
      if (end == std::string::npos) end = raw.size();
      const size_t tab = raw.find('\t', pos);
      if (tab != std::string::npos && tab < end && raw.compare(pos, tab - pos, key) == 0) {
        value.assign(raw, tab + 1, end - tab - 1);
        return true;
      }
      pos = end + 1;
    }
    return false;
  }
  /// Every key of every block, for validation.
  std::vector<std::string> keys() {
    std::vector<std::string> out;
    for (size_t i = 0; i < blocks.size(); i++) {
      const std::string raw = inflated(i);
      size_t pos = 0;
      while (pos < raw.size()) {
        size_t end = raw.find('\n', pos);
        if (end == std::string::npos) end = raw.size();
        const size_t tab = raw.find('\t', pos);
        if (tab != std::string::npos && tab < end) out.push_back(raw.substr(pos, tab - pos));
        pos = end + 1;
      }
    }
    return out;
  }
};
PrototypePack &pack_at(const unsigned char *bytes, size_t size) {
  // Languages that share an archive share its decoded index. Called under engine_mutex.
  static std::map<const unsigned char *, std::unique_ptr<PrototypePack>> packs;
  auto &pack = packs[bytes];
  if (!pack) pack.reset(new PrototypePack(bytes, size));
  return *pack;
}
PrototypePack &prototype_pack(const Spec &spec) { return pack_at(spec.pack, spec.pack_size); }
PrototypePack &go_pack(const Spec &spec) {
  if (!spec.go_pack) throw std::runtime_error("no Go prototype pack for this language");
  return pack_at(spec.go_pack, spec.go_pack_size);
}
/// The Go binary a session decompiles: its operating system (`w`, `l` or `d`, as in the Go pack) and
/// minor version, which select one record of each Go pack entry.
struct GoTarget {
  char os = 0;
  uint32_t minor = 0;
};
/// The payload of the record of a Go pack entry that applies to \p target (see
/// scripts/decompiler_types/pack_go_snapshots.py): records "<os>|<first>|<last>|<payload>" separated by 0x1f.
bool go_record(const std::string &value, const GoTarget &target, std::string &payload) {
  size_t pos = 0;
  while (pos < value.size()) {
    size_t end = value.find('\x1f', pos);
    if (end == std::string::npos) end = value.size();
    const size_t a = value.find('|', pos), b = a == std::string::npos ? a : value.find('|', a + 1),
                 c = b == std::string::npos ? b : value.find('|', b + 1);
    if (c == std::string::npos || c >= end) throw std::runtime_error("malformed Go pack record");
    const bool os = value.find(target.os, pos) < a;
    const unsigned long first = std::strtoul(value.c_str() + a + 1, nullptr, 10);
    const unsigned long last = std::strtoul(value.c_str() + b + 1, nullptr, 10);
    if (os && first <= target.minor && target.minor <= last) {
      payload.assign(value, c + 1, end - c - 1);
      return true;
    }
    pos = end + 1;
  }
  return false;
}
/// `Datatype::hashName` (protected): the id the engine gives a type, or a reference to one, that
/// carries a name and no id.
uint64_t name_hash(const std::string &name) {
  uint64_t res = 123;
  for (unsigned char ch : name) {
    res = (res << 8) | (res >> 56);
    res += ch;
    if ((res & 1) == 0) res ^= 0xfeabfeab;
  }
  return res | 0xC000000000000000ULL;
}
std::string type_key(uint64_t id) {
  char buffer[32];
  snprintf(buffer, sizeof buffer, "T:0x%llx", static_cast<unsigned long long>(id));
  return buffer;
}
/// Resolves named types the way Ghidra's decompiler asks its host: on demand.
class TypeFactoryPack : public TypeFactory {
  // Recursive definitions end at the stub objects the decoder creates, so
  // re-entry for an id is legitimate; bound it to protect the native stack.
  std::map<uint64_t, int> loading;
  int depth = 0;
  struct Loading {
    TypeFactoryPack &owner;
    uint64_t id;
    ~Loading() {
      owner.depth--;
      if (--owner.loading[id] == 0) owner.loading.erase(id);
    }
  };
public:
  const Spec &spec;
  GoTarget go;
  TypeFactoryPack(Architecture *g, const Spec &s) : TypeFactory(g), spec(s) {}
  Datatype *resolve(uint64_t id) { return findById("", id, 0); }
  /// A Go type by name, through the definition the binary's version has (Go pack N and D entries).
  /// Null when the pack does not describe it.
  Datatype *goType(const std::string &n) { return findById(n, name_hash(n), 0); }
  Datatype *findById(const std::string &n, uint8 id, int4 sz) override {
    Datatype *known = TypeFactory::findById(n, id, sz);
    if (known) return known;
    // Ghidra's untyped bytes; the C++ core types call them xunknown.
    if (n.size() == 10 && n.compare(0, 9, "undefined") == 0 && n[9] >= '1' && n[9] <= '8' && (n[9] == '1' || n[9] == '2' || n[9] == '4' || n[9] == '8'))
      return getBase(n[9] - '0', TYPE_UNKNOWN);
    if (id == 0 || sz > 0) return nullptr;
    std::string value;
    // Go types are referenced by name only, so their id is the name's hash; the pack maps the name
    // to the definition of the binary's release.
    if (!prototype_pack(spec).find(type_key(id), value)) {
      std::string index, definition;
      if (!spec.go_pack || !go.os || n.empty() || id != name_hash(n) || !go_pack(spec).find("N:" + n, index) ||
          !go_record(index, go, definition) || !go_pack(spec).find("D:" + definition, value))
        return nullptr;
    }
    if (depth >= 64 || loading[id] >= 3) throw LowlevelError("packed type definition nests too deeply: " + n);
    loading[id]++;
    depth++;
    Loading guard{*this, id};
    const size_t tab = value.find('\t');
    if (tab == std::string::npos) throw LowlevelError("malformed packed type: " + n);
    std::istringstream input(value.substr(tab + 1));
    DocumentStorage store;
    XmlDecode decoder(glb, store.parseDocument(input)->getRoot());
    return decodeType(decoder);
  }
};
// Unlike C strings, Rust slices carry their byte length. The synthetic terminator belongs only
// to the printer's decoded cache; it is never written into the loaded image.
class SliceStringManager : public StringManagerUnicode {
public:
  explicit SliceStringManager(Architecture *arch) : StringManagerUnicode(arch, 2048) {}
  void add(const Address &address, const uint1 *bytes, size_t length) {
    auto &data = stringMap[address];
    data.isTruncated = false;
    data.byteData.assign(bytes, bytes + length);
    data.byteData.push_back(0);
  }
};
// Render typed string addresses even when the compiler put literals in writable data.
// This changes printing only: loads and stores retain their original memory semantics.
class StringPrintC : public PrintC {
  bool pushString(Symbol *symbol, const Varnode *vn, const PcodeOp *op) {
    if (!symbol || symbol->getType()->getMetatype() != TYPE_ARRAY ||
        (symbol->getName().find("s_") != 0 && symbol->getName().find("u_") != 0)) return false;
    auto *element = static_cast<TypeArray *>(symbol->getType())->getBase();
    auto *entry = symbol->getFirstWholeMap();
    std::ostringstream literal;
    if (!entry || !element->isCharPrint() || !printCharacterConstant(literal, entry->getAddr(), element)) return false;
    writable_literals |= !(symbol->getFlags() & Varnode::readonly);
    pushAtom(Atom(literal.str(), vartoken, EmitMarkup::const_color, op, vn));
    return true;
  }
public:
  bool c_types = true;
  bool unknown_types = false;
  bool writable_literals = false;
  explicit StringPrintC(Architecture *arch) : PrintC(arch, "binfera-c") {}
  void opCast(const PcodeOp *op) override {
    // CAST preserves bits. FLOAT_INT2FLOAT and FLOAT_FLOAT2FLOAT are numeric
    // conversions and retain Ghidra's own printer. ARM soft-float moves often
    // expose casts between a double and its two integer register halves.
    const auto *input = op->getIn(0);
    const auto *output = op->getOut();
    const auto in = input->getHighTypeReadFacing(op)->getMetatype();
    const auto out = output->getHighTypeDefFacing()->getMetatype();
    const bool integer_in = in == TYPE_INT || in == TYPE_UINT || in == TYPE_UNKNOWN;
    const bool integer_out = out == TYPE_INT || out == TYPE_UINT || out == TYPE_UNKNOWN;
    if (input->getSize() == output->getSize() && (input->getSize() == 4 || input->getSize() == 8) &&
        ((in == TYPE_FLOAT && integer_out) || (out == TYPE_FLOAT && integer_in))) {
      const std::string name = std::string("BITCAST_") + (out == TYPE_FLOAT ? "F" : "U") + std::to_string(input->getSize() * 8);
      pushOp(&function_call, op);
      pushAtom(Atom(name, optoken, EmitMarkup::no_color, op));
      pushVn(input, op, mods);
      return;
    }
    PrintC::opCast(op);
  }
  void pushTypeStart(const Datatype *ct, bool noident) override {
    std::vector<const Datatype *> stack;
    buildTypeStack(ct, stack);
    const auto *base = stack.back();
    const auto &name = base->getName();
    const int size = base->getSize();
    const auto meta = base->getMetatype();
    const bool unknown = meta == TYPE_UNKNOWN &&
      (name == "xunknown" + std::to_string(size) || name == "undefined" + std::to_string(size));
    const bool integer = (meta == TYPE_INT && name == "int" + std::to_string(size)) ||
      (meta == TYPE_UINT && name == "uint" + std::to_string(size));
    if (!c_types || (!unknown && !integer) || (size != 1 && size != 2 && size != 4 && size != 8 && size != 16)) {
      PrintC::pushTypeStart(ct, noident);
      return;
    }
    unknown_types |= unknown;
    std::string type = size == 1 ? "char" : size == 2 ? "short" : size == 4 ? "int" : size == 8 ? "long long" : "__int128";
    if (meta != TYPE_INT) type = "unsigned " + type;
    else if (size == 1) type = "signed " + type;
    pushOp(noident && stack.size() == 1 ? &type_expr_nospace : &type_expr_space, nullptr);
    pushAtom(Atom(type, typetoken, EmitMarkup::type_color, base));
    for (int i = int(stack.size()) - 2; i >= 0; --i) {
      switch (stack[i]->getMetatype()) {
      case TYPE_PTR: pushOp(&ptr_expr, nullptr); break;
      case TYPE_ARRAY: pushOp(&array_expr, nullptr); break;
      case TYPE_CODE: pushOp(&function_call, nullptr); break;
      default: throw LowlevelError("Bad type expression");
      }
    }
  }
  void pushConstant(uintb value, const Datatype *type, tagtype tag, const Varnode *vn,
                    const PcodeOp *op, uint4 format) override {
    // Small UEFI addresses can remain untyped integers despite a discovered string symbol.
    // Only substitute address arguments with unknown/pointer type, never typed integer values.
    const bool call_argument = op && vn && (op->code() == CPUI_CALL || op->code() == CPUI_CALLIND) && op->getIn(0) != vn;
    if (value != 0 && op && vn && (type->getMetatype() == TYPE_PTR ||
        (call_argument && type->getMetatype() == TYPE_UNKNOWN))) {
      Address at(glb->getDefaultCodeSpace(), value);
      auto *entry = glb->symboltab->getGlobalScope()->queryContainer(at, 1, Address());
      if (entry && entry->getAddr() == at && pushString(entry->getSymbol(), vn, op)) return;
    }
    PrintC::pushConstant(value, type, tag, vn, op, format);
  }
  void opPtrsub(const PcodeOp *op) override {
    auto *base = op->getIn(0)->getTypeReadFacing(op);
    if (!(mods & (print_load_value | print_store_value)) && base->getMetatype() == TYPE_PTR &&
        static_cast<TypePointer *>(base)->getPtrTo()->getMetatype() == TYPE_SPACEBASE) {
      auto *high = op->getIn(1)->getHigh();
      if (high->getSymbolOffset() == 0 && pushString(high->getSymbol(), op->getOut(), op)) return;
    }
    PrintC::opPtrsub(op);
  }
};
/// A type as StringPrintC declares it: the same C spelling for untyped and sized integer bases.
static std::string frameTypeName(const Datatype *type) {
  switch (type->getMetatype()) {
  case TYPE_PTR:
    // A named pointer (LPCSTR) is declared by that name.
    if (!type->getName().empty()) break;
    return frameTypeName(static_cast<const TypePointer *>(type)->getPtrTo()) + " *";
  case TYPE_ARRAY: {
    if (!type->getName().empty()) break;
    const auto *array = static_cast<const TypeArray *>(type);
    return frameTypeName(array->getBase()) + "[" + std::to_string(array->numElements()) + "]";
  }
  default: break;
  }
  const auto &name = type->getName();
  if (name.empty()) return "undefined" + std::to_string(type->getSize());
  const int size = type->getSize();
  const auto meta = type->getMetatype();
  const bool unknown = meta == TYPE_UNKNOWN &&
    (name == "xunknown" + std::to_string(size) || name == "undefined" + std::to_string(size));
  const bool integer = (meta == TYPE_INT && name == "int" + std::to_string(size)) ||
    (meta == TYPE_UINT && name == "uint" + std::to_string(size));
  if ((!unknown && !integer) || (size != 1 && size != 2 && size != 4 && size != 8 && size != 16)) return name;
  std::string spelled = size == 1 ? "char" : size == 2 ? "short" : size == 4 ? "int" : size == 8 ? "long long" : "__int128";
  if (meta != TYPE_INT) return "unsigned " + spelled;
  return size == 1 ? "signed " + spelled : spelled;
}

/// The stack symbols of a finished function, by offset from the stack pointer at entry, with the
/// instructions that read, write or take the address of each.
static void collectStackFrame(Funcdata *fd, AddrSpace *stack, rust::Vec<binfera::NativeStackSlot> &frame) {
  struct Slot {
    int64_t offset;
    uint32_t size;
    std::string name, type, reg;
    bool parameter;
    std::set<uint64_t> reads, writes, references;
  };
  const int shift = 64 - int(stack->getAddrSize()) * 8;
  const auto signedOffset = [&](uintb offset) { return int64_t(uint64_t(offset) << shift) >> shift; };
  std::vector<Slot> slots;
  auto *scope = fd->getScopeLocal();
  for (MapIterator it = scope->begin(); it != scope->end(); ++it) {
    const SymbolEntry *entry = *it;
    if (entry->getAddr().getSpace() != stack) continue;
    const Symbol *symbol = entry->getSymbol();
    slots.push_back({signedOffset(entry->getAddr().getOffset()), uint32_t(entry->getSize()), symbol->getName(),
                     frameTypeName(symbol->getType()), "", symbol->getCategory() == Symbol::function_parameter, {}, {}, {}});
  }
  std::sort(slots.begin(), slots.end(), [](const Slot &a, const Slot &b) { return a.offset < b.offset; });
  // A symbol split over ranges has one entry per range at the same storage.
  slots.erase(std::unique(slots.begin(), slots.end(), [](const Slot &a, const Slot &b) {
    return a.offset == b.offset && a.name == b.name;
  }), slots.end());
  // Parameters passed in registers have no frame offset, but the signature still names them.
  std::vector<Slot> registers;
  std::vector<Address> registerStorage;
  const auto &proto = fd->getFuncProto();
  for (int4 i = 0; i < proto.numParams(); ++i) {
    const ProtoParameter *parameter = proto.getParam(i);
    const Address storage = parameter->getAddress();
    if (storage.getSpace() == stack) continue;
    std::string reg = fd->getArch()->translate->getRegisterName(storage.getSpace(), storage.getOffset(), parameter->getSize());
    if (reg.empty()) reg = "register";
    registers.push_back({0, uint32_t(parameter->getSize()), parameter->getName(), frameTypeName(parameter->getType()), reg, true, {}, {}, {}});
    registerStorage.push_back(storage);
  }
  const auto slotAt = [&](int64_t offset) -> Slot * {
    auto next = std::upper_bound(slots.begin(), slots.end(), offset, [](int64_t at, const Slot &slot) { return at < slot.offset; });
    if (next == slots.begin()) return nullptr;
    --next;
    return offset < next->offset + int64_t(next->size) ? &*next : nullptr;
  };
  for (auto it = fd->beginOpAll(); it != fd->endOpAll(); ++it) {
    const PcodeOp *op = it->second;
    const auto code = op->code();
    // Phi nodes and call side effects are not instructions touching the slot.
    if (op->isDead() || code == CPUI_MULTIEQUAL || code == CPUI_INDIRECT) continue;
    const uint64_t at = op->getAddr().getOffset();
    const Varnode *out = op->getOut();
    if (out && out->getSpace() == stack)
      if (auto *slot = slotAt(signedOffset(out->getOffset()))) slot->writes.insert(at);
    for (int4 i = 0; i < op->numInput(); ++i) {
      const Varnode *in = op->getIn(i);
      if (in->isInput())
        for (size_t r = 0; r < registers.size(); ++r)
          if (in->getAddr() == registerStorage[r]) registers[r].reads.insert(at);
      // A wide store is split into pieces of the value it just wrote: not a read of the old contents.
      if (in->getSpace() == stack && !in->isAnnotation() && !(in->isWritten() && in->getDef()->getAddr() == op->getAddr()))
        if (auto *slot = slotAt(signedOffset(in->getOffset()))) slot->reads.insert(at);
    }
    if ((code == CPUI_PTRSUB || code == CPUI_INT_ADD) && op->getIn(0)->isSpacebase() && op->getIn(1)->isConstant()) {
      auto *slot = slotAt(signedOffset(op->getIn(1)->getOffset()));
      if (!slot || !out) continue;
      // Copy propagation can leave this op at the `sub rsp` that made the frame, so what counts
      // is the instruction using the pointer, past any casts and copies of it.
      std::vector<const Varnode *> pointers{out};
      for (size_t i = 0; i < pointers.size() && i < 64; ++i) {
        for (auto use = pointers[i]->beginDescend(); use != pointers[i]->endDescend(); ++use) {
          const PcodeOp *user = *use;
          if (user->isDead() || user->code() == CPUI_MULTIEQUAL || user->code() == CPUI_INDIRECT) continue;
          if ((user->code() == CPUI_CAST || user->code() == CPUI_COPY) && user->getOut()) pointers.push_back(user->getOut());
          else slot->references.insert(user->getAddr().getOffset());
        }
      }
    }
  }
  slots.insert(slots.end(), registers.begin(), registers.end());
  for (const auto &slot : slots) {
    binfera::NativeStackSlot out;
    out.name = slot.name;
    out.register_name = slot.reg;
    out.offset = slot.offset;
    out.size = slot.size;
    out.type_name = slot.type;
    out.parameter = slot.parameter;
    for (auto at : slot.reads) out.reads.push_back(at);
    for (auto at : slot.writes) out.writes.push_back(at);
    for (auto at : slot.references) out.references.push_back(at);
    frame.push_back(std::move(out));
  }
}

class StringPrintCapability : public PrintLanguageCapability {
public:
  StringPrintCapability() { name = "binfera-c"; isdefault = false; }
  PrintLanguage *buildLanguage(Architecture *arch) override { return new StringPrintC(arch); }
};
StringPrintCapability string_print_capability;
class ArchitectureX86 : public SleighArchitecture {
  const Spec &spec;
protected:
  void buildLoader(DocumentStorage &) override { loader = new Image(spec); }
  void buildTypegrp(DocumentStorage &) override { types = new TypeFactoryPack(this, spec); }
  void buildStringManager(DocumentStorage &) override { stringManager = new SliceStringManager(this); }
  void resolveArchitecture() override { archid = spec.archid; }
  void buildSpecFile(DocumentStorage &store) override {
    for (auto pair : {std::make_pair(spec.pspec, spec.pspec_size), std::make_pair(spec.cspec, spec.cspec_size)}) {
      std::istringstream stream(std::string(reinterpret_cast<const char *>(pair.first), pair.second));
      store.registerTag(store.parseDocument(stream)->getRoot());
    }
    std::istringstream stream("<sleigh>embedded</sleigh>");
    store.registerTag(store.parseDocument(stream)->getRoot());
    if (spec.go_pack) {
      // The engine's own names would print an eight-byte integer as `int8`, which in Go is one
      // byte. Go programs get Go's names for the core types, and Ghidra's `undefinedN`.
      std::istringstream core(
        "<coretypes><void/>"
        "<type name=\"bool\" size=\"1\" metatype=\"bool\"/>"
        "<type name=\"uint8\" size=\"1\" metatype=\"uint\"/><type name=\"uint16\" size=\"2\" metatype=\"uint\"/>"
        "<type name=\"uint32\" size=\"4\" metatype=\"uint\"/><type name=\"uint64\" size=\"8\" metatype=\"uint\"/>"
        "<type name=\"int8\" size=\"1\" metatype=\"int\"/><type name=\"int16\" size=\"2\" metatype=\"int\"/>"
        "<type name=\"int32\" size=\"4\" metatype=\"int\"/><type name=\"int64\" size=\"8\" metatype=\"int\"/>"
        "<type name=\"float32\" size=\"4\" metatype=\"float\"/><type name=\"float64\" size=\"8\" metatype=\"float\"/>"
        "<type name=\"float10\" size=\"10\" metatype=\"float\"/><type name=\"float16\" size=\"16\" metatype=\"float\"/>"
        "<type name=\"undefined1\" size=\"1\" metatype=\"unknown\"/><type name=\"undefined2\" size=\"2\" metatype=\"unknown\"/>"
        "<type name=\"undefined4\" size=\"4\" metatype=\"unknown\"/><type name=\"undefined8\" size=\"8\" metatype=\"unknown\"/>"
        "<type name=\"code\" size=\"1\" metatype=\"code\"/>"
        "<type name=\"char\" size=\"1\" metatype=\"int\" char=\"true\"/>"
        "<type name=\"wchar2\" size=\"2\" metatype=\"int\" utf=\"true\"/><type name=\"wchar4\" size=\"4\" metatype=\"int\" utf=\"true\"/>"
        "</coretypes>");
      store.registerTag(store.parseDocument(core)->getRoot());
    }
  }
  Translate *buildTranslator(DocumentStorage &) override { return new ImageSleigh(static_cast<Image *>(loader), context, spec); }
  void modifySpaces(Translate *) override {}
public:
  ArchitectureX86(const Spec &s, std::ostream *errors) : SleighArchitecture("", s.archid, errors), spec(s) {
    if (!dynamic_cast<PrintC *>(print)) throw LowlevelError("C printer unavailable");
  }
  ~ArchitectureX86() override { delete translate; translate = nullptr; }
  std::string getDescription() const override { return spec.description; }
  Image &image() { return *static_cast<Image *>(loader); }
  const Spec &language() const { return spec; }
};
#include "emulator.inc"
/// A C identifier made of \p input. Go symbols keep the punctuation of their names
/// (`os.(*File).Write`), as Ghidra prints them, and so do demangled C++ names
/// (`std::vector<int>::operator[]`, `Class::~Class`); anything else becomes `_`.
std::string identifier(rust::Str input, bool go = false) {
  if (input.size() > 1024) throw std::runtime_error("symbol exceeds 1024 bytes");
  std::string result;
  for (unsigned char ch : input) {
    const bool punctuation = (go && (ch == '.' || ch == '*' || ch == '(' || ch == ')' || ch == '/' || ch == '[' || ch == ']' || ch == '-')) ||
                             (ch != 0 && std::strchr(":<>,~&=+!%^|()[]*/-", ch) != nullptr);
    result += ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
               (ch >= '0' && ch <= '9') || ch == '_' || punctuation) ? char(ch) : '_';
  }
  if (result.empty()) throw std::runtime_error("empty symbol name");
  if (result.front() >= '0' && result.front() <= '9') result.insert(0, "_");
  return result;
}
}
std::string binfera_sla() {
  if (!constructing_spec) throw std::runtime_error("no language selected for the SLEIGH specification");
  return std::string(reinterpret_cast<const char *>(constructing_spec->sla), constructing_spec->sla_size);
}
bool binfera_jump_target_valid(LoadImage *loader, uint64_t function, uint64_t target) {
  const auto *image = dynamic_cast<Image *>(loader);
  if (!image) return true;
  const auto &ranges = image->function_ranges;
  const auto containing = [&](uint64_t address) -> const binfera::CodeRange * {
    auto it = std::upper_bound(ranges.begin(), ranges.end(), address,
      [](uint64_t value, const binfera::CodeRange &range) { return value < range.start; });
    if (it == ranges.begin() || address >= (it - 1)->end) return nullptr;
    return &*(it - 1);
  };
  const auto *source = containing(function), *destination = containing(target);
  // A table can tail-call another function or enter a separate cold fragment.
  // Reject only an interior target in a different declared unwind range.
  return !source || !destination || source == destination || target == destination->start;
}
bool binfera_forwarded_return(Funcdata &fd, const PcodeOp &ret, int slot) {
  const auto *value = ret.getIn(slot);
  if (!value->isWritten() || !value->getDef()->isCall() || fd.getFuncProto().isNoReturn()) return false;
  const auto &arch = static_cast<const ArchitectureX86 &>(*fd.getArch());
  const auto &spec = arch.language();
  if (spec.go_pack) return false;
  const auto &result = arch.translate->getRegister(resultRegister(spec));
  const auto &translator = *static_cast<const ImageSleigh *>(arch.translate);
  const auto forwards = [&](const PcodeOp &exit) {
    const auto *input = exit.getIn(slot);
    if (input->getAddr() != result.getAddr() || !input->isWritten()) return false;
    const auto *def = input->getDef();
    if (def->code() != CPUI_CALL && def->code() != CPUI_CALLIND) return false;
    const auto *call = fd.getCallSpecs(def);
    if (!call || !call->isOutputLocked() || call->isNoReturn()) return false;
    const auto *output = call->getOutput();
    const auto kind = output->getType()->getMetatype();
    if (kind != TYPE_INT && kind != TYPE_UINT && kind != TYPE_BOOL && kind != TYPE_PTR && kind != TYPE_UNKNOWN)
      return false;
    if (output->getAddress() != result.getAddr() || output->getSize() != input->getSize() ||
        input->getSize() > result.size) return false;
    const auto &site = def->getAddr();
    if (site == exit.getAddr() && fd.getOverride().getFlowOverride(site) == Override::CALL_RETURN) return true;
    const auto syscall = translator.syscall_targets.find(site.getOffset());
    return syscall != translator.syscall_targets.end() && syscall->second == call->getEntryAddress().getOffset();
  };
  if (!forwards(ret)) return false;
  // Only preserve this result if it reaches every normal return. An ordinary
  // call can leave its unused result in the register of a void function.
  for (auto it = fd.beginOp(CPUI_RETURN); it != fd.endOp(CPUI_RETURN); ++it) {
    const auto *exit = *it;
    if (exit == &ret || exit->isDead() || exit->getHaltType() == PcodeOp::noreturn) continue;
    binfera_check();
    if (exit->getHaltType() != 0 || slot >= exit->numInput() || !forwards(*exit)) return false;
  }
  return true;
}
void binfera_check() {
  if (!budget.active) return;
  if (budget.remaining-- == 0) { budget.exhausted = true; budget.reason = "native work limit exceeded"; throw BudgetExceeded(budget.reason); }
  // Reading the clock crosses into the host runtime on WebAssembly. Keep exact
  // work accounting, but poll elapsed time on the first and every 64th checkpoint.
  if ((budget.clock_checks++ & 63u) == 0 && std::chrono::steady_clock::now() >= budget.deadline) {
    budget.exhausted = true;
    budget.reason = "native decompilation deadline exceeded";
    throw BudgetExceeded(budget.reason);
  }
}
// TypeFactory::setFields is private since Ghidra 12 and the public route is the
// XML decoder. Explicit instantiation may name a private member, which yields a
// member pointer without modifying the pinned headers or casting any object.
struct SetStructFieldsTag {
  using type = void (TypeFactory::*)(const vector<TypeField> &, const vector<TypeBitField> &,
                                     TypeStruct *, int4, int4, uint4);
};
SetStructFieldsTag::type access_set_struct_fields(SetStructFieldsTag);
template <typename Tag, typename Tag::type Member>
struct AccessPrivate {
  friend typename Tag::type access_set_struct_fields(Tag) { return Member; }
};
template struct AccessPrivate<SetStructFieldsTag, &TypeFactory::setFields>;
// Ghidra records an indirect-to-direct call override when it resolves a call through the import table
// (FuncCallSpecs::deindirect), so that a restart of the same analysis converts the call at once. The
// table is private and has no way to remove an entry, so reach it the same way.
struct IndirectOverrideTag {
  using type = std::map<Address, Address> Override::*;
};
IndirectOverrideTag::type access_indirect_overrides(IndirectOverrideTag);
template <typename Tag, typename Tag::type Member>
struct AccessIndirect {
  friend typename Tag::type access_indirect_overrides(Tag) { return Member; }
};
template struct AccessIndirect<IndirectOverrideTag, &Override::indirectover>;
// The same route to a prototype's parameter store, so Go parameters can be given the storage the
// Go ABI assigns rather than the one the compiler specification's model would compute.
struct ProtoStoreTag {
  using type = ProtoStore *FuncProto::*;
};
ProtoStoreTag::type access_proto_store(ProtoStoreTag);
template <typename Tag, typename Tag::type Member>
struct AccessProtoStore {
  friend typename Tag::type access_proto_store(Tag) { return Member; }
};
template struct AccessProtoStore<ProtoStoreTag, &FuncProto::store>;

// The same route to ScopeLocal::collectNameRecs, which turns name-locked symbols into the name
// and type recommendations an analysis applies. Ghidra calls it when the Java side sends a
// function's local scope; here a method's `this` is supplied directly.
struct CollectNameRecsTag {
  using type = void (ScopeLocal::*)(void);
};
CollectNameRecsTag::type access_collect_name_recs(CollectNameRecsTag);
template <typename Tag, typename Tag::type Member>
struct AccessCollectNameRecs {
  friend typename Tag::type access_collect_name_recs(Tag) { return Member; }
};
template struct AccessCollectNameRecs<CollectNameRecsTag, &ScopeLocal::collectNameRecs>;

namespace {
/// Port of Ghidra 12.1.4's `GoParamStorageAllocator`: Go's register assignment (`internal/abi`).
/// A value goes to the next free registers if all of its pieces fit (a pointer or an integer of up
/// to two words in integer registers, a float in a float register, a struct field by field, an array
/// of one element as that element), otherwise the whole value goes to the stack and the registers
/// stay free for later values. `x86-64-golang.register.info`: RAX, RBX, RCX, RDI, RSI, R8-R11 and
/// XMM0-14 from Go 1.17, nothing before; stack values start at 8 (4 in x86-32) and align to at most
/// the pointer size.
class GoAllocator {
  Architecture &arch;
  std::vector<std::string> ints, floats;
  size_t next_int = 0, next_float = 0;
  int word;
  int max_align;
  bool fill(const std::string &base, int size, std::vector<VarnodeData> &out) {
    // `getBestFitRegister`: the register's low part, halved while larger than what is left.
    VarnodeData reg = arch.translate->getRegister(base);
    int fit = int(reg.size);
    while (fit > size && fit > 1) fit /= 2;
    reg.size = uint4(fit);
    out.push_back(reg);
    return true;
  }
  bool allocate(size_t count, bool floating, int size, std::vector<VarnodeData> &out) {
    auto &list = floating ? floats : ints;
    auto &next = floating ? next_float : next_int;
    if (next + count > list.size()) return false;
    int remaining = size;
    for (size_t i = next; i < next + count; ++i) {
      fill(list[i], remaining, out);
      remaining -= int(out.back().size);
    }
    next += count;
    return true;
  }
  bool count(Datatype *type, std::vector<VarnodeData> &out) {
    const int size = type->getSize();
    if (size == 0) return false;
    switch (type->getMetatype()) {
    case TYPE_PTR:
      return allocate(1, false, size, out);
    case TYPE_INT: case TYPE_UINT: case TYPE_BOOL: case TYPE_UNKNOWN:
      return size <= 2 * word && allocate(size_t((size + word - 1) / word), false, size, out);
    case TYPE_FLOAT:
      return allocate(1, true, size, out);
    case TYPE_ARRAY: {
      auto *array = static_cast<TypeArray *>(type);
      return array->numElements() == 1 && count(array->getBase(), out);
    }
    case TYPE_STRUCT: {
      auto *structure = static_cast<TypeStruct *>(type);
      for (auto it = structure->beginField(); it != structure->endField(); ++it)
        if (!count(it->type, out)) return false;
      return true;
    }
    default:
      return false;
    }
  }
public:
  int64_t stack;
  GoAllocator(Architecture &a, bool wide, bool registers, bool arm64) : arch(a), word(wide ? 8 : 4), max_align(wide ? 8 : 4), stack(wide ? 8 : 4) {
    if (registers) {
      if (arm64) {
        for (int i = 0; i < 16; ++i) {
          ints.push_back("x" + std::to_string(i));
          floats.push_back("q" + std::to_string(i));
        }
        return;
      }
      ints = {"RAX", "RBX", "RCX", "RDI", "RSI", "R8", "R9", "R10", "R11"};
      for (int i = 0; i < 15; ++i) floats.push_back("XMM" + std::to_string(i) + "_Qa");
    }
  }
  /// Registers for \p type in allocation order, or false (and nothing used) if it goes on the stack.
  bool registers(Datatype *type, std::vector<VarnodeData> &out) {
    const auto saved_int = next_int, saved_float = next_float;
    out.clear();
    if (count(type, out) && !out.empty()) return true;
    next_int = saved_int;
    next_float = saved_float;
    out.clear();
    return false;
  }
  void reset() { next_int = next_float = 0; }
  int alignment(Datatype *type) const {
    while (type->getMetatype() == TYPE_ARRAY) type = static_cast<TypeArray *>(type)->getBase();
    const int size = type->getSize();
    const bool power = size > 0 && (size & (size - 1)) == 0;
    switch (type->getMetatype()) {
    case TYPE_INT: case TYPE_UINT: case TYPE_BOOL: case TYPE_UNKNOWN:
      return power ? std::min(max_align, size) : max_align;
    case TYPE_FLOAT:
      return std::min(max_align, size);
    default:
      return type->getName() == "complex64" ? 4 : max_align;
    }
  }
  int64_t onStack(Datatype *type) {
    const int64_t align = alignment(type);
    stack = (stack + align - 1) / align * align;
    const int64_t at = stack;
    stack += type->getSize();
    return at;
  }
  void alignStack() { stack = (stack + max_align - 1) / max_align * max_align; }
};
}

namespace binfera {
class Session::Impl {
public:
  std::ostringstream errors;
  const Spec &spec;
  ArchitectureX86 arch;
  /// Emulation state, created by emu_reset; declared after arch so it is destroyed first.
  std::unique_ptr<EmuState> emu;
  int ptr() const { return spec.pointer; }
  std::map<uint64_t, Datatype *> debug_types;
  std::set<uint64_t> debug_incomplete;
  bool poisoned = false;
  bool rust_fixups = false;
  size_t symbols = 0;
  size_t edges = 0;
  std::set<uint64_t> supplied_entries;
  TypeStruct *luid;
  TypeStruct *token_privileges;
  explicit Impl(const Spec &s) : spec(s), arch(s, &errors) {
    DocumentStorage store;
    arch.init(store);
    if (spec.default_model) arch.setDefaultModel(arch.getModel(spec.default_model));
    arch.setPrintLanguage("binfera-c");
    static_cast<StringPrintC *>(arch.print)->c_types = !spec.go_pack;
    // Windows x64 SDK layouts (winnt.h). DWORD and LONG are four bytes;
    // ANYSIZE_ARRAY is one in the declaration, not a runtime allocation bound.
    // See docs/decompiler-design.md for the declarations and provenance.
    auto *types = arch.types;
    auto set_struct_fields = access_set_struct_fields(SetStructFieldsTag());
    auto *u32 = types->getBase(4, TYPE_UINT);
    luid = types->getTypeStruct("LUID");
    (types->*set_struct_fields)({TypeField(0, 0, "LowPart", u32),
      TypeField(1, 4, "HighPart", types->getBase(4, TYPE_INT))}, {}, luid, 8, 4, 0);
    auto *attributes = types->getTypeStruct("LUID_AND_ATTRIBUTES");
    (types->*set_struct_fields)({TypeField(0, 0, "Luid", luid),
      TypeField(1, 8, "Attributes", u32)}, {}, attributes, 12, 4, 0);
    token_privileges = types->getTypeStruct("TOKEN_PRIVILEGES");
    (types->*set_struct_fields)({TypeField(0, 0, "PrivilegeCount", u32),
      TypeField(1, 4, "Privileges", types->getTypeArray(1, attributes))}, {}, token_privileges, 16, 4, 0);
  }
  /// The engine type for a supplied signature type.
  Datatype *valueType(ValueType value) {
    switch (value) {
    case ValueType::Void: return arch.types->getTypeVoid();
    case ValueType::I32: return arch.types->getBase(4, TYPE_INT);
    case ValueType::U32: return arch.types->getBase(4, TYPE_UINT);
    case ValueType::I64: return arch.types->getBase(8, TYPE_INT);
    case ValueType::U64: return arch.types->getBase(8, TYPE_UINT);
    case ValueType::Pointer: return arch.types->getTypePointer(arch.getDefaultCodeSpace()->getAddrSize(), arch.types->getTypeVoid(), 1);
    case ValueType::CharPointer: return arch.types->getTypePointer(arch.getDefaultCodeSpace()->getAddrSize(), arch.types->getTypeChar(1), 1);
    case ValueType::WideCharPointer: return arch.types->getTypePointer(arch.getDefaultCodeSpace()->getAddrSize(), arch.types->getTypeChar(2), 1);
    case ValueType::U32Pointer: return arch.types->getTypePointer(arch.getDefaultCodeSpace()->getAddrSize(), arch.types->getBase(4, TYPE_UINT), 1);
    case ValueType::PointerPointer: return arch.types->getTypePointer(arch.getDefaultCodeSpace()->getAddrSize(),
        arch.types->getTypePointer(arch.getDefaultCodeSpace()->getAddrSize(), arch.types->getTypeVoid(), 1), 1);
    case ValueType::LuidPointer: return arch.types->getTypePointer(arch.getDefaultCodeSpace()->getAddrSize(), luid, 1);
    case ValueType::TokenPrivilegesPointer: return arch.types->getTypePointer(arch.getDefaultCodeSpace()->getAddrSize(), token_privileges, 1);
    case ValueType::I8: return arch.types->getBase(1, TYPE_INT);
    case ValueType::U8: return arch.types->getBase(1, TYPE_UINT);
    case ValueType::I16: return arch.types->getBase(2, TYPE_INT);
    case ValueType::U16: return arch.types->getBase(2, TYPE_UINT);
    case ValueType::Bool: return arch.types->getBase(1, TYPE_BOOL);
    case ValueType::F32: return arch.types->getBase(4, TYPE_FLOAT);
    case ValueType::F64: return arch.types->getBase(8, TYPE_FLOAT);
    default: throw std::runtime_error("unknown signature type");
    }
  }
  Datatype *pointerTo(Datatype *type) {
    return arch.types->getTypePointer(ptr(), type, arch.getDefaultCodeSpace()->getWordSize());
  }
  /// A C++ class as a structure; created empty (incomplete) on first use, given its virtual
  /// function table pointers by add_class.
  TypeStruct *classType(rust::Str name) {
    std::string id = identifier(name);
    // A completed structure cannot be asked for by its definition again; look it up by name.
    // A name the archives already give another kind of type keeps that type and gets a suffix.
    Datatype *found = arch.types->findByName(id);
    if (found && found->getMetatype() != TYPE_STRUCT) {
      id += "_class";
      found = arch.types->findByName(id);
    }
    if (found && found->getMetatype() == TYPE_STRUCT) return static_cast<TypeStruct *>(found);
    if (found) throw std::runtime_error("class type name is taken: " + id);
    return arch.types->getTypeStruct(id);
  }
  /// A persistent, name-locked symbol on data. An address that already holds a symbol keeps it.
  bool label(uint64_t address, const std::string &name, Datatype *type) {
    auto *scope = arch.symboltab->getGlobalScope();
    auto *space = arch.getDefaultCodeSpace();
    const uint64_t size = uint64_t(type->getSize());
    if (!size || address > UINT64_MAX - size || !arch.image().mapped(address) || !arch.image().mapped(address + size - 1))
      return false;
    if (scope->queryContainer(Address(space, address), 1, Address()) ||
        scope->queryContainer(Address(space, address + size - 1), 1, Address()))
      return false;
    if (++symbols > 100000) throw std::runtime_error("symbol limit exceeded");
    auto *entry = scope->addSymbol(name, type, Address(space, address), Address());
    if (!entry) return false;
    scope->setAttribute(entry->getSymbol(), Varnode::namelock);
    return true;
  }
  void ready() { if (poisoned) throw std::runtime_error("session failed previously; create a new session"); }
  void prepareRequestedWrapper(Funcdata *fd, uint32_t max_instructions) {
    auto entry = fd->getAddress().getOffset();
    if (supplied_entries.count(entry)) return;
    auto current = entry;
    // Local discovery policy: at most 64 straight-line instructions.
    for (uint32_t i = 0; i < std::min<uint32_t>(64, max_instructions); ++i) {
      if (current != entry && supplied_entries.count(current)) return;
      WrapperFlow flow;
      auto length = arch.translate->oneInstruction(flow, Address(arch.getDefaultCodeSpace(), current));
      if (flow.flows) {
        if (flow.flows == 1 && flow.direct && flow.target.getOffset() != entry &&
            supplied_entries.count(flow.target.getOffset()) &&
            arch.image().executable(flow.target.getOffset()))
        {
          fd->getOverride().insertFlowOverride(Address(arch.getDefaultCodeSpace(), current), Override::CALL_RETURN);
          invalidateInferred();
        }
        return;
      }
      if (length <= 0 || current > UINT64_MAX - uint64_t(length)) return;
      current += length;
    }
  }
  // Callee prototype inference. Locks never outlive one function's analysis.
  // Only context-independent scalar leaves can be cached across requests;
  // other results may depend on the requesting function's data symbols and types.
  // A cache hit charges the work the original computation took. set_signature
  // and the other mutators invalidate cached facts.
  // Local safety policy: at most 16 direct callees per request, 16 analyzed
  // functions below each, and four call levels.
  std::map<uint64_t, ProtoModel *> function_models;
  struct Inferred {
    bool usable = false;
    bool output_known = true;
    PrototypePieces pieces;
    uint64_t cost = 0;
    unsigned size = 0;
    bool context_independent = false;
  };
  std::map<std::pair<uint64_t, unsigned>, Inferred> inferred_cache;
  uint32_t analysis_passes = 0;
  uint32_t inference_cache_hits = 0;
  uint32_t inference_cache_misses = 0;
  uint32_t inference_cache_invalidations = 0;
  uint32_t inference_cache_evictions = 0;
  std::map<std::string, uint32_t> inference_invalidation_reasons;
  std::map<uint64_t, uint64_t> variadic_forwarders;
  std::set<uint64_t> callsite_argument_functions;
  // Indirect call overrides inserted on purpose (add_tail_call). Every other one was recorded by the
  // analysis of a request, and is removed when the request ends.
  std::map<uint64_t, std::set<uint64_t>> explicit_indirect;
  /// A parameter the argument-naming pass renamed on a function whose prototype is locked (a library
  /// function with an archive prototype). Its symbol outlives the request, so the new name and its
  /// name lock would show in every later request that calls the function; they are undone when the
  /// request ends.
  struct RenamedParameter {
    Funcdata *fd;
    int4 index;
    std::string name;
    bool name_locked;
  };
  std::vector<RenamedParameter> renamed_parameters;
  void restoreParameterNames() {
    for (const auto &entry : renamed_parameters) {
      auto &proto = entry.fd->getFuncProto();
      if (!proto.isInputLocked() || entry.index >= proto.numParams()) continue;
      try {
        Symbol *symbol = proto.getParam(entry.index)->getSymbol();
        if (!symbol) continue;
        auto *scope = entry.fd->getScopeLocal();
        if (!entry.name_locked) scope->clearAttribute(symbol, Varnode::namelock);
        if (symbol->getName() != entry.name) scope->renameSymbol(symbol, entry.name);
      } catch (const LowlevelError &) {
        // A prototype with no symbol for the parameter has no name to restore.
      }
    }
    renamed_parameters.clear();
  }
  void dropDeindirected(Funcdata *fd) {
    // Ghidra keeps these across analysis restarts, but inferred overrides must
    // not outlive the request that resolved them.
    auto &table = fd->getOverride().*access_indirect_overrides(IndirectOverrideTag{});
    if (table.empty()) return;
    const auto keep = explicit_indirect.find(fd->getAddress().getOffset());
    for (auto it = table.begin(); it != table.end();) {
      if (keep != explicit_indirect.end() && keep->second.count(it->first.getOffset())) ++it;
      else it = table.erase(it);
    }
  }
  std::map<uint64_t, std::pair<uint32_t, uint32_t>> go_stack_functions;
  std::set<uint64_t> supplied_prototypes;
  // Override owns these prototypes; replacing a call site's override replaces
  // its tracked pointer too. Explicit callee signatures supersede the hints.
  struct CallsitePrototype { uint64_t target; FuncProto *prototype; };
  std::map<std::pair<uint64_t, uint64_t>, CallsitePrototype> callsite_prototypes;
  void refreshExplicit(Funcdata *callee) {
    function_models.erase(callee->getAddress().getOffset());
    auto target = callee->getAddress().getOffset();
    go_stack_functions.erase(target);
    supplied_prototypes.insert(target);
    for (auto &entry : callsite_prototypes) {
      if (entry.second.target != target) continue;
      entry.second.prototype->copy(callee->getFuncProto());
      entry.second.prototype->setOverride(true);
    }
  }
  /// Inferences that ran out of work, with the work they had left. With no more than that left,
  /// one runs out again: fail at once rather than redo minutes of analysis for every caller.
  std::map<std::pair<uint64_t, unsigned>, uint64_t> exhausted_cache;
  std::set<uint64_t> in_progress;
  std::set<Funcdata *> touched;
  std::vector<Funcdata *> applied;
  uint32_t inference_max_instructions = 0;
  uint32_t print_work_limit = 0;
  void invalidateInferred(const char *reason = "explicit facts", uint64_t target = 0) {
    ++inference_cache_invalidations;
    ++inference_invalidation_reasons[reason];
    if (!target) {
      inference_cache_evictions += uint32_t(inferred_cache.size());
      inferred_cache.clear();
    } else {
      for (auto it = inferred_cache.begin(); it != inferred_cache.end();) {
        if (!it->second.context_independent || it->first.first == target) {
          ++inference_cache_evictions;
          it = inferred_cache.erase(it);
        } else ++it;
      }
    }
    // Failed inferences do not retain complete dependency information.
    exhausted_cache.clear();
  }
  /// Start a request from the facts that hold for any request. A callee's inferred prototype is
  /// computed while the requesting function's own state is in place (the data symbols its first
  /// pass found, the types it created), so a result that is not context independent can come out
  /// differently in another request; keeping it would make the output depend on request order.
  /// Scalar leaf results, which cannot observe another function's state, stay cached.
  void dropRequestLocalInferences() {
    const auto before = inferred_cache.size();
    for (auto it = inferred_cache.begin(); it != inferred_cache.end();) {
      if (!it->second.context_independent) it = inferred_cache.erase(it);
      else ++it;
    }
    const auto removed = before - inferred_cache.size();
    if (removed || !exhausted_cache.empty()) {
      ++inference_cache_invalidations;
      ++inference_invalidation_reasons["request context"];
      inference_cache_evictions += uint32_t(removed);
    }
    // These record how much work an inference had left when it ran out, in the context it ran in.
    exhausted_cache.clear();
  }
  void invalidateTemporary(uint64_t target, const char *reason) {
    // Keep the existing full reset for ABI-sensitive Go, Rust and x86 cases.
    const bool local = spec.sla == sla_x64_bytes && spec.pack == pack_x64_bytes &&
      !spec.go_pack && !rust_fixups && !counted_strings;
    invalidateInferred(reason, local ? target : 0);
  }
  // Data symbols added for the current request; dropped when it ends, so output is
  // a function of the image and the request, never of request order.
  std::vector<Symbol *> data_symbols;
  // Go and Rust keep strings as (pointer, length) pairs packed without terminators, so a
  // NUL-terminated scan runs on through neighbouring strings. Name such data, never print it.
  bool counted_strings = false;
  struct DataReference {
    int4 size = 0;
    bool address_taken = false;
    bool written = false;
    bool text_pointer = false;
    bool structured_pointer = false;
  };
  /// Name the data \p fd's finished analysis touched. Returns true if the global symbols changed,
  /// which leaves that analysis stale: the caller analyzes again.
  bool addDataSymbols(Funcdata *fd) {
    auto &image = arch.image();
    auto *scope = arch.symboltab->getGlobalScope();
    auto *space = arch.getDefaultCodeSpace();
    std::map<uint64_t, DataReference> refs;
    const auto data = [&](uint64_t address, bool byte_pointer = false) {
      if (!image.mapped(address)) return false;
      if (!image.executable(address)) return true;
      // UEFI and some static images merge literals into executable segments. Require a
      // longer terminated string there, and never replace a registered function entry.
      if (scope->queryFunction(Address(space, address))) return false;
      StringLiteral literal;
      return detectString(image, address, literal) && (literal.chars >= 4 || byte_pointer);
    };
    for (auto it = fd->beginLoc(); it != fd->endLoc() && refs.size() < 4096; ++it) {
      const Varnode *vn = *it;
      if (vn->getSpace() != space || vn->isFree() || vn->isAnnotation()) continue;
      if (!data(vn->getOffset())) continue;
      auto &ref = refs[vn->getOffset()];
      ref.size = std::max(ref.size, vn->getSize());
      ref.written |= vn->isWritten();
    }
    for (auto it = fd->beginOpAll(); it != fd->endOpAll() && refs.size() < 4096; ++it) {
      const PcodeOp *op = it->second;
      if (op->isDead()) continue;
      for (int4 slot = 0; slot < op->numInput(); ++slot) {
        const Varnode *vn = op->getIn(slot);
        if (!vn->isConstant() || (slot == 0 && (op->code() == CPUI_LOAD || op->code() == CPUI_STORE))) continue;
        if (slot == 0 && (op->code() == CPUI_CALL || op->code() == CPUI_BRANCH || op->code() == CPUI_CBRANCH)) continue;
        auto *type = vn->getTypeReadFacing(op);
        auto *pointee = type->getMetatype() == TYPE_PTR ?
          static_cast<TypePointer *>(type)->getPtrTo() : nullptr;
        const bool byte_pointer = pointee && (pointee->isCharPrint() ||
          (pointee->getSize() == 1 && (pointee->getMetatype() == TYPE_INT ||
           pointee->getMetatype() == TYPE_UINT || pointee->getMetatype() == TYPE_UNKNOWN)));
        if (!data(vn->getOffset(), byte_pointer)) continue;
        const bool access = slot == 1 && (op->code() == CPUI_LOAD || op->code() == CPUI_STORE);
        auto &ref = refs[vn->getOffset()];
        if (access) {
          const int4 size = op->code() == CPUI_LOAD ? op->getOut()->getSize() : op->getIn(2)->getSize();
          ref.size = std::max(ref.size, size);
          ref.written |= op->code() == CPUI_STORE;
        } else {
          // Zero is a null pointer even when a relocatable image maps its header at zero.
          if (vn->getOffset() == 0) continue;
          ref.address_taken = true;
          ref.text_pointer |= byte_pointer;
          ref.structured_pointer |= pointee && (pointee->getMetatype() == TYPE_STRUCT ||
            pointee->getMetatype() == TYPE_UNION || pointee->getMetatype() == TYPE_CODE);
        }
      }
    }
    uint64_t covered_until = 0;
    // Removing a placeholder frees a symbol the finished analysis still points at, so the
    // caller must analyze again whenever one was removed, even if nothing replaced it.
    bool added = false;
    bool removed = false;
    for (const auto &[address, ref] : refs) {
      if (address < covered_until) continue;
      // The first pass names untouched globals with engine default names such as `uRam...`;
      // those are placeholders to replace. Anything else (an import, a function) is kept.
      const auto occupied = [&](uint64_t at, bool replace) {
        for (int guard = 0; guard < 8; ++guard) {
          auto *found = scope->queryContainer(Address(space, at), 1, Address());
          if (!found) return false;
                  if (!replace || !(found->getSymbol()->isNameUndefined() || placeholderName(found->getSymbol()->getName()))) return true;
          scope->removeSymbol(found->getSymbol());
          removed = true;
        }
        return true;
      };
      if (occupied(address, true)) continue;
      StringLiteral literal;
      // A short printable prefix is common in sizes and pointers. Require a character
      // pointer for short strings, and never reinterpret a typed structure as text.
      const bool is_string = ref.address_taken && !ref.written && !ref.structured_pointer &&
        detectString(image, address, literal) && (literal.chars >= 4 || ref.text_pointer);
      int4 size = std::max<int4>(ref.size, 1);
      std::string name;
      Datatype *type = nullptr;
      if (is_string && counted_strings) {
        // The terminator is not the string's end here: keep the label, leave the bytes untyped.
        name = std::string(literal.wide ? "u_" : "s_") + literal.label + "_" + hexAddress(address);
        type = arch.types->getBase(size, TYPE_UNKNOWN);
      } else if (is_string) {
        name = std::string(literal.wide ? "u_" : "s_") + literal.label + "_" + hexAddress(address);
        size = int4((literal.chars + 1) * (literal.wide ? 2 : 1));
        type = arch.types->getTypeArray(int4(literal.chars + 1), arch.types->getTypeChar(literal.wide ? 2 : 1));
      } else {
        std::string target = "DAT";
        std::string label;
        const auto [bytes, available] = image.bytesAt(address);
        const int width = ptr();
        if ((ref.size == width || ref.size == 0) && address % width == 0 && available >= size_t(width)) {
          uint64_t value = 0;
          for (int i = width - 1; i >= 0; --i) value = (value << 8) | bytes[i];
          if (image.executable(value)) {
            target = "PTR_FUN";
            size = width;
          } else if (image.mapped(value)) {
            size = width;
            StringLiteral pointee;
            target = detectString(image, value, pointee)
                         ? std::string("PTR_") + (pointee.wide ? "u_" : "s_") + pointee.label
                         : "PTR_DAT";
          }
        }
        name = target + "_" + hexAddress(address);
        type = arch.types->getBase(size, TYPE_UNKNOWN);
      }
      if (address > UINT64_MAX - uint64_t(size) || occupied(address + size - 1, true))
        continue;
      if (++symbols > 100000) throw std::runtime_error("symbol limit exceeded");
      auto *entry = scope->addSymbol(name, type, Address(space, address), Address());
      if (!entry) continue;
      scope->setAttribute(entry->getSymbol(), Varnode::namelock | (is_string && !counted_strings ? Varnode::typelock |
        (arch.symboltab->getProperty(Address(space, address)) & Varnode::readonly) : 0));
      data_symbols.push_back(entry->getSymbol());
      covered_until = address + size;
      added = true;
    }
    return added || removed;
  }
  void dropDataSymbols() {
    auto *scope = arch.symboltab->getGlobalScope();
    for (auto *symbol : data_symbols) scope->removeSymbol(symbol);
    symbols -= std::min(symbols, data_symbols.size());
    data_symbols.clear();
    // Placeholder globals made while analyzing this request would otherwise leak into the
    // next one (named by whichever type was seen first), so output would depend on order.
    std::vector<Symbol *> placeholders;
    for (auto it = scope->begin(); it != scope->end(); ++it) {
      Symbol *symbol = (*it)->getSymbol();
      if (placeholderName(symbol->getName()) && placeholders.end() == std::find(placeholders.begin(), placeholders.end(), symbol))
        placeholders.push_back(symbol);
    }
    for (auto *symbol : placeholders) scope->removeSymbol(symbol);
  }
  std::set<uint64_t> directTargets(Funcdata *caller) {
    std::set<uint64_t> targets;
    for (int4 i = 0; i < caller->numCalls(); ++i) {
      binfera_check();
      auto *call = caller->getCallSpecs(i);
      if (call->getEntryAddress().isInvalid() || (call->isInputLocked() && call->isOutputLocked())) continue;
      const auto target = call->getEntryAddress().getOffset();
      if (!arch.image().executable(target)) continue;
      auto *fd = arch.symboltab->getGlobalScope()->queryFunction(call->getEntryAddress());
      // Known and external calls need no body analysis. Counting them would starve
      // unresolved callees and reject wrappers that call many already-typed APIs.
      if (fd && !fd->getFuncProto().isInputLocked() && !fd->getFuncProto().isOutputLocked())
        targets.insert(target);
    }
    return targets;
  }
  std::map<uint64_t, Funcdata *> syscall_functions;
  Funcdata *syscallFunction(uint64_t number) {
    auto existing = syscall_functions.find(number);
    if (existing != syscall_functions.end()) return existing->second;
    const auto *bytes = spec.wide ? syscalls_x64_bytes : syscalls_x86_bytes;
    const size_t size = spec.wide ? sizeof(syscalls_x64_bytes) : sizeof(syscalls_x86_bytes);
    std::istringstream table(std::string(reinterpret_cast<const char *>(bytes), size));
    std::string line, name;
    while (std::getline(table, line)) {
      uint64_t id;
      std::istringstream row(line);
      if (row >> id >> name && id == number) break;
      name.clear();
    }
    if (name.empty()) return nullptr;
    // Disjoint from the import allocator (at most 100000 symbols). Request-local data
    // symbols may come and go, so their count must not determine syscall addresses.
    const uint64_t target = spec.external_base + 0x1000000 + number * 16;
    auto *fd = function(target, "linux_" + name, name == "exit" || name == "exit_group");
    auto &proto = fd->getFuncProto();
    // libc wrappers can have different argument layouts from kernel entries. Only use
    // archive parameters for these matching interfaces; never reuse clone/open varargs.
    static const std::set<std::string> compatible = {
      "read", "write", "close", "lseek", "mprotect", "munmap", "getpid", "getppid",
      "fork", "vfork", "execve", "exit", "kill", "waitpid", "dup", "dup2", "pipe",
      "chdir", "fchdir", "getcwd", "unlink", "rename", "link", "mkdir", "rmdir",
      "readlink", "chmod", "fchmod", "chown", "fchown", "lchown", "umask",
      "getuid", "geteuid", "getgid", "getegid", "setuid", "setgid", "setsid",
      "socket", "connect", "bind", "listen", "accept", "shutdown", "sendto", "recvfrom",
      "getsockname", "getpeername", "socketpair", "setsockopt", "getsockopt",
      "poll", "nanosleep", "sched_yield", "fsync", "fdatasync", "access"
    };
    bool typed = false;
    if (compatible.count(name)) {
      try { typed = apply_pack_prototype(fd, name); }
      catch (const LowlevelError &) {}
      catch (const DecoderError &) {}
    }
    PrototypePieces pieces;
    proto.getPieces(pieces);
    pieces.model = arch.getModel("syscall");
    pieces.outtype = arch.types->getBase(ptr(), TYPE_INT);
    pieces.firstVarArgSlot = -1;
    // Raw kernel interfaces whose libc wrappers differ or are absent from the archive.
    // p: opaque pointer, c: char pointer, i/u: 32-bit integer, w: unsigned word.
    static const std::map<std::string, std::string> raw = {
      {"open", "ciu"}, {"openat", "iciu"}, {"openat2", "icpw"},
      {"stat", "cp"}, {"lstat", "cp"}, {"fstat", "ip"}, {"newfstatat", "icpi"},
      {"fstatat64", "icpi"}, {"stat64", "cp"}, {"lstat64", "cp"}, {"fstat64", "ip"},
      {"mmap2", "pwiiiw"}, {"mprotect", "pwi"}, {"brk", "p"},
      {"ioctl", "iww"}, {"fcntl", "iiw"}, {"fcntl64", "iiw"},
      {"execve", "cpp"}, {"execveat", "icppi"}, {"socketcall", "ip"},
      {"rt_sigaction", "ippw"}, {"rt_sigprocmask", "ippw"},
      {"futex", "piuppu"}, {"arch_prctl", "iw"}, {"prctl", "iwwww"},
      {"set_tid_address", "p"}, {"set_robust_list", "pw"}, {"get_robust_list", "ipp"},
      {"getrandom", "pwu"}, {"memfd_create", "cu"}, {"dup3", "iii"}, {"pipe2", "pi"},
      {"readlinkat", "icpw"}, {"unlinkat", "ici"}, {"mkdirat", "icu"},
      {"getdents", "ipu"}, {"getdents64", "ipu"}, {"accept4", "ippi"},
      {"epoll_create1", "i"}, {"epoll_ctl", "iiip"}, {"epoll_wait", "ipii"},
      {"epoll_pwait", "ipiipw"}, {"tgkill", "iii"}, {"tkill", "ii"},
      {"clock_gettime", "ip"}, {"clock_gettime64", "ip"}, {"clock_nanosleep", "iipp"},
      {"uname", "p"}, {"sysinfo", "p"}, {"clone3", "pw"}, {"restart_syscall", ""}
    };
    auto signature = raw.find(name);
    std::string args;
    if (signature != raw.end()) { args = signature->second; typed = true; }
    else if (name == "mmap") { args = spec.wide ? "pwiiiw" : "p"; typed = true; }
    else if (name == "clone") { args = spec.wide ? "wpppw" : "wppwp"; typed = true; }
    if (signature != raw.end() || name == "mmap" || name == "clone") {
      pieces.intypes.clear();
      pieces.innames.clear();
      for (char kind : args) {
        Datatype *type = kind == 'p' ? arch.types->getTypePointer(ptr(), arch.types->getTypeVoid(), 1) :
                         kind == 'c' ? arch.types->getTypePointer(ptr(), arch.types->getTypeChar(1), 1) :
                         arch.types->getBase(kind == 'w' ? ptr() : 4, kind == 'i' ? TYPE_INT : TYPE_UINT);
        pieces.intypes.push_back(type);
        pieces.innames.push_back("arg" + std::to_string(pieces.intypes.size()));
      }
    }
    if (name == "exit" || name == "exit_group") {
      pieces.intypes = {arch.types->getBase(4, TYPE_INT)};
      pieces.innames = {"status"};
      pieces.outtype = arch.types->getTypeVoid();
      typed = true;
    }
    proto.setPieces(pieces);
    proto.setInputLock(typed);
    proto.setOutputLock(true);
    proto.setModelLock(true);
    proto.setExtraPop(0);
    syscall_functions[number] = fd;
    return fd;
  }
  int4 analyze(Funcdata *fd) {
    auto &translator = *static_cast<const ImageSleigh *>(arch.translate);
    translator.syscall_targets.clear();
    translator.syscall_sites.clear();
    translator.probe_syscalls = linuxSpec(spec) && translator.linux_syscalls;
    if (translator.probe_syscalls && !translator.syscall_probe) {
      translator.syscall_probe = spec.external_base + 0xfffff0;
      auto *probe = function(translator.syscall_probe, "linux_syscall_probe", false);
      PrototypePieces pieces;
      pieces.model = arch.getModel("syscall");
      pieces.outtype = arch.types->getBase(ptr(), TYPE_INT);
      pieces.firstVarArgSlot = -1;
      for (int i = 0; i < 6; ++i) {
        pieces.intypes.push_back(arch.types->getTypePointer(ptr(), arch.types->getTypeVoid(), 1));
        pieces.innames.push_back("arg" + std::to_string(i));
      }
      probe->getFuncProto().setPieces(pieces);
      probe->getFuncProto().setInputLock(true);
      probe->getFuncProto().setOutputLock(true);
      probe->getFuncProto().setModelLock(true);
      probe->getFuncProto().setExtraPop(0);
    }
    struct ResetProbe {
      const ImageSleigh &translator;
      ~ResetProbe() { translator.probe_syscalls = false; translator.syscall_targets.clear(); }
    } reset{translator};
    int4 status = analyzePass(fd);
    translator.probe_syscalls = false;
    if (translator.syscall_sites.empty()) return status;
    std::map<uint64_t, uint64_t> numbers;
    std::set<uint64_t> ambiguous;
    for (auto it = fd->beginOpAll(); it != fd->endOpAll(); ++it) {
      const auto *op = it->second;
      const uint64_t site = op->getAddr().getOffset();
      if (op->isDead() || op->code() != CPUI_CALLOTHER || op->numInput() != 2 ||
          !translator.syscall_sites.count(site)) continue;
      if (!op->getIn(1)->isConstant()) { ambiguous.insert(site); continue; }
      const uint64_t number = op->getIn(1)->getOffset();
      auto inserted = numbers.emplace(site, number);
      if (!inserted.second && inserted.first->second != number) ambiguous.insert(site);
    }
    for (const auto &entry : numbers) {
      if (ambiguous.count(entry.first)) continue;
      if (auto *callee = syscallFunction(entry.second))
        translator.syscall_targets[entry.first] = callee->getAddress().getOffset();
    }
    return analyzePass(fd);
  }
  int4 analyzePass(Funcdata *fd) {
    ++analysis_passes;
    arch.clearAnalysis(fd);
    errors.str("");
    int4 status;
    try {
      arch.allacts.getCurrent()->reset(*fd);
      status = arch.allacts.getCurrent()->perform(*fd);
    } catch (...) {
      // An exception out of the action tree (a limit, or an engine error) leaves its groups
      // half-run, and the next request can walk off the stale state into a null action
      // (seen after a deadline during jump table recovery). Derive a fresh tree.
      arch.allacts.resetDefaults();
      throw;
    }
    // Some engine paths swallow the checkpoint exception (jump table recovery runs nested
    // analysis), leaving a function without structure. An empty budget says why.
    if (budget.active && budget.exhausted) throw BudgetExceeded(budget.reason);
    return status;
  }
  void apply(uint64_t target, const Inferred &entry, Funcdata *caller) {
    auto *fd = arch.symboltab->getGlobalScope()->queryFunction(Address(arch.getDefaultCodeSpace(), target));
    auto &proto = fd->getFuncProto();
    proto.setPieces(entry.pieces);
    proto.setInputLock(true);
    proto.setOutputLock(entry.output_known);
    proto.setModelLock(true);
    // A locked void result says the call may leave the return register as it was unless the
    // model kills it. The Windows and System V models do; Delphi's and Borland's leave its effect
    // unknown, so a caller that reads the callee's result would read the value from before the
    // call. Leave the result open and let the callers' uses decide, as Ghidra's unlocked
    // prototypes do.
    if (entry.pieces.outtype && entry.pieces.outtype->getMetatype() == TYPE_VOID) {
      const VarnodeData &result = arch.translate->getRegister(resultRegister(spec));
      bool used = false;
      for (int4 i = 0; i < caller->numCalls(); ++i) {
        const auto *call = caller->getCallSpecs(i);
        if (call->getEntryAddress() == fd->getAddress() && call->getOp()->getOut() != nullptr)
          used = true;
      }
      // An inferred void is not evidence against a live result in the caller.
      // Keep that result linked to the call and report its type as uncertain.
      if (used || proto.hasEffect(result.getAddr(), result.size) != EffectRecord::killedbycall)
        proto.setOutputLock(false);
    }
    applied.push_back(fd);
  }
  /// Drop every inferred lock and the analysis state of the callees a request analyzed, but
  /// keep \p selected's own analysis.
  void releaseCallees(Funcdata *selected) {
    for (auto *fd : applied) unlockOne(fd);
    applied.clear();
    in_progress.clear();
    touched.erase(selected);
    for (auto *fd : touched) {
      arch.clearAnalysis(fd);
      dropDeindirected(fd);
      fd->getFuncProto().clearUnlockedInput();
      fd->getFuncProto().clearUnlockedOutput();
      resetGoStack(fd);
    }
    touched.clear();
  }
  /// Drop every inferred lock and the analysis state of everything a request
  /// touched, so the next request sees only supplied facts.
  void release(Funcdata *selected) {
    restoreParameterNames();
    for (auto *fd : applied) {
      unlockOne(fd);
    }
    applied.clear();
    in_progress.clear();
    touched.insert(selected);
    for (auto *fd : touched) {
      arch.clearAnalysis(fd);
      dropDeindirected(fd);
      fd->getFuncProto().clearUnlockedInput();
      fd->getFuncProto().clearUnlockedOutput();
      resetGoStack(fd);
    }
    touched.clear();
  }
  const Inferred &infer(uint64_t target, unsigned level) {
    const auto key = std::make_pair(target, level);
    auto cached = inferred_cache.find(key);
    if (cached != inferred_cache.end()) {
      ++inference_cache_hits;
      charge(cached->second.cost);
      return cached->second;
    }
    ++inference_cache_misses;
    auto exhausted = exhausted_cache.find(key);
    if (exhausted != exhausted_cache.end() && budget.active && budget.remaining <= exhausted->second)
      charge(budget.remaining + 1);
    const uint64_t before = budget.active ? budget.remaining : 0;
    Inferred out;
    out.size = 1;
    auto *fd = arch.symboltab->getGlobalScope()->queryFunction(Address(arch.getDefaultCodeSpace(), target));
    if (arch.image().executable(target) && fd && !fd->getFuncProto().isInputLocked() &&
        !fd->getFuncProto().isOutputLocked()) {
      touched.insert(fd);
      in_progress.insert(target);
      // A callee whose flow cannot be translated (it runs into data or unmapped memory) only
      // costs its own inferred prototype; the selected function must not fail for it.
      const auto mark = applied.size();
      try {
        inferBody(fd, target, level, out);
      } catch (const BudgetExceeded &e) {
        // A deadline depends on the machine's speed; only the work limit is worth remembering.
        if (std::string(e.what()) == "native work limit exceeded") exhausted_cache[key] = before;
        throw;
      } catch (const LowlevelError &) {
        for (auto i = applied.size(); i-- > mark;) unlockOne(applied[i]);
        applied.resize(mark);
        out.usable = false;
        errors.str("");
        in_progress.erase(target);
        arch.clearAnalysis(fd);
      }
    }
    if (out.size > 16) out.usable = false;
    out.cost = budget.active ? before - budget.remaining : 0;
    return inferred_cache.emplace(key, std::move(out)).first->second;
  }
  void inferBody(Funcdata *fd, uint64_t target, unsigned level, Inferred &out) {
    {
      int4 status = analyze(fd);
      const auto own_errors = errors.str();
      if (fourHomedInputs(fd)) {
        out.usable = status >= 0;
        collect(fd, out);
        if (out.usable && !out.output_known) {
          in_progress.erase(target);
          arch.clearAnalysis(fd);
          errors.str("");
          return;
        }
      }
      // Child prototypes cannot repair an undecodable body. Nor can they supply
      // the prototype of an indirect call through this function's own input.
      // Such bodies never pass collect(), so do not recursively analyze their
      // unrelated direct callees before rejecting the same result.
      bool unrepairable = status < 0 || !own_errors.empty();
      for (auto it = arch.commentdb->beginComment(fd->getAddress()); it != arch.commentdb->endComment(fd->getAddress()); ++it) {
        const auto &text = (*it)->getText();
        unrepairable |= text.find("Bad instruction") != std::string::npos ||
          text.find("bad instruction data") != std::string::npos ||
          text == "WARNING: Subroutine does not return";
      }
      for (int4 i = 0; i < fd->numCalls(); ++i) {
        const auto *call = fd->getCallSpecs(i);
        const auto *op = call->getOp();
        unrepairable |= op->code() == CPUI_CALLIND && op->getIn(0)->isInput() &&
          (!call->isInputLocked() || !call->isOutputLocked());
        if (op->code() == CPUI_CALL && (!call->isInputLocked() || !call->isOutputLocked())) {
          const auto &entry = call->getEntryAddress();
          auto *callee = entry.isInvalid() ? nullptr : arch.symboltab->getGlobalScope()->queryFunction(entry);
          // directTargets() cannot infer external, missing or partly locked
          // prototypes. Other children cannot repair this direct call either.
          unrepairable |= !callee || !arch.image().executable(entry.getOffset()) ||
            callee->getFuncProto().isInputLocked() || callee->getFuncProto().isOutputLocked();
        }
      }
      if (unrepairable) {
        out.usable = false;
        in_progress.erase(target);
        arch.clearAnalysis(fd);
        errors.str("");
        return;
      }
      std::vector<std::pair<uint64_t, const Inferred *>> usable_children;
      if (level < 4) {
        for (auto child : directTargets(fd)) {
          const Inferred *entry = nullptr;
          if (!in_progress.count(child) && out.size <= 16) {
            entry = &infer(child, level + 1);
            out.size += entry->size;
          }
          if (entry && entry->usable) {
            usable_children.emplace_back(child, entry);
          } else if (homedParameters(fd) != 4) {
            // This direct call stays unknown, and only a complete four-register home prologue
            // lets collect() accept a body with an unknown call. Without one the answer is
            // settled, so the remaining children and the second analysis pass cannot change it.
            out.usable = false;
            in_progress.erase(target);
            arch.clearAnalysis(fd);
            errors.str("");
            return;
          }
        }
      }
      if (!usable_children.empty()) {
        const auto mark = applied.size();
        for (auto &[child, entry] : usable_children) apply(child, *entry, fd);
        status = analyze(fd);
        out.usable = status >= 0;
        collect(fd, out);
        for (auto i = applied.size(); i-- > mark;) unlockOne(applied[i]);
        applied.resize(mark);
      } else {
        errors.str(own_errors);
        out.usable = status >= 0;
        collect(fd, out);
      }
      in_progress.erase(target);
      arch.clearAnalysis(fd);
      errors.str("");
    }
  }
  /// Name unlocked locals and parameters passed directly (or by address) to a
  /// named, locked API parameter. A local with several roles takes the name of
  /// its first call, as IDA does. A parameter is part of the function's
  /// interface, so it is renamed only when every use gives it the same role.
  void nameArgumentLocals(Funcdata *fd) {
    if (spec.go_pack || !fd->isHighOn()) return;
    auto *scope = fd->getScopeLocal();
    std::map<Symbol *, std::vector<std::string>> candidates;
    for (int4 i = 0; i < fd->numCalls(); ++i) {
      const auto *call = fd->getCallSpecs(i);
      if (!call->isInputLocked()) continue;
      const auto *op = call->getOp();
      for (int4 slot = 1; slot < op->numInput() && slot <= call->numParams(); ++slot) {
        const auto *parameter = call->getParam(slot - 1);
        const auto &name = parameter->getName();
        if (name.empty() || name.find("param_") == 0 || name.find("arg") == 0 || name.find("__undef") == 0 || name == "this") continue;
        const Varnode *vn = op->getIn(slot);
        Symbol *symbol = nullptr;
        for (int depth = 0; depth < 8; ++depth) {
          symbol = vn->getHigh()->getSymbol();
          if (symbol && symbol->getScope() == scope) break;
          if (!vn->isWritten()) break;
          const auto *def = vn->getDef();
          if (def->code() == CPUI_PTRSUB && def->getIn(0)->getType()->getMetatype() == TYPE_PTR &&
              static_cast<TypePointer *>(def->getIn(0)->getType())->getPtrTo()->getMetatype() == TYPE_SPACEBASE) {
            symbol = def->getIn(1)->getHigh()->getSymbol();
            break;
          }
          if (def->code() != CPUI_COPY && def->code() != CPUI_CAST) break;
          vn = def->getIn(0);
        }
        if (symbol && symbol->getScope() == scope && !symbol->isNameLocked() &&
            (symbol->getCategory() == Symbol::no_category ||
             symbol->getCategory() == Symbol::function_parameter))
        {
          const std::string candidate = identifier(name, true);
          if (!candidate.empty() && candidate.find("__undef") != 0) candidates[symbol].push_back(candidate);
        }
      }
    }
    // Apply in symbol-id order, so suffixes do not depend on allocator addresses.
    std::vector<Symbol *> ordered;
    for (const auto &entry : candidates) {
      const auto &names = entry.second;
      const bool agree = std::all_of(names.begin(), names.end(), [&](const std::string &n) { return n == names.front(); });
      if (entry.first->getCategory() == Symbol::no_category || agree) ordered.push_back(entry.first);
    }
    std::sort(ordered.begin(), ordered.end(), [](const Symbol *a, const Symbol *b) { return a->getId() < b->getId(); });
    for (auto *symbol : ordered) {
      const auto &name = candidates[symbol].front();
      if (symbol->getCategory() == Symbol::function_parameter && fd->getFuncProto().isInputLocked())
        renamed_parameters.push_back({fd, symbol->getCategoryIndex(), symbol->getName(), symbol->isNameLocked()});
      if (symbol->getName() != name) scope->renameSymbol(symbol, scope->makeNameUnique(name));
      // An unlocked name on a type-locked parameter is reset to an undefined
      // name on the next pass, which then prints as "__undef...".
      if (symbol->getCategory() == Symbol::function_parameter) scope->setAttribute(symbol, Varnode::namelock);
    }
  }
  void unlockOne(Funcdata *fd) {
    fd->getFuncProto().setInputLock(false);
    fd->getFuncProto().setOutputLock(false);
    fd->getFuncProto().setModelLock(false);
    auto model = function_models.find(fd->getAddress().getOffset());
    if (model != function_models.end()) {
      fd->getFuncProto().setModel(model->second);
      fd->getFuncProto().setModelLock(true);
    }
  }
  /// Count explicit Win64 entry stores into the ABI's four register home slots.
  /// These are independent evidence of parameters even when optimization removes
  /// unused stores from a logging stub. Do not mistake those stubs for zero-arg calls.
  unsigned homedParameters(Funcdata *fd) {
    if (spec.cspec != cspec_x64_bytes) return 0;
    auto address = fd->getAddress().getOffset();
    unsigned mask = 0;
    for (unsigned i = 0; i < 4; ++i) {
      auto bytes = arch.image().bytesAt(address);
      if (!bytes.first || bytes.second < 5) break;
      const auto *p = bytes.first;
      if ((p[0] != 0x48 && p[0] != 0x4c && p[0] != 0x44) || p[1] != 0x89 || p[3] != 0x24) break;
      unsigned slot;
      if (p[0] == 0x48 && p[2] == 0x4c && p[4] == 8) slot = 0;
      else if (p[0] == 0x48 && p[2] == 0x54 && p[4] == 16) slot = 1;
      else if ((p[0] == 0x4c || p[0] == 0x44) && p[2] == 0x44 && p[4] == 24) slot = 2;
      else if ((p[0] == 0x4c || p[0] == 0x44) && p[2] == 0x4c && p[4] == 32) slot = 3;
      else break;
      if (mask & (1u << slot)) return 0;
      mask |= 1u << slot;
      address += 5;
    }
    return mask == 15 ? 4 : 0;
  }
  bool fourHomedInputs(Funcdata *fd) {
    const auto &proto = fd->getFuncProto();
    if (homedParameters(fd) != 4 || proto.numParams() != 4 || proto.isDotdotdot()) return false;
    const char *registers[] = {"RCX", "RDX", "R8", "R9"};
    for (int4 i = 0; i < 4; ++i) {
      const auto *parameter = proto.getParam(i);
      const auto &storage = arch.translate->getRegister(registers[i]);
      if (parameter->getAddress() != storage.getAddr() || parameter->getSize() > storage.size) return false;
    }
    return true;
  }
  /// Decide whether \p fd's finished analysis is trustworthy, and if so keep its pieces.
  void collect(Funcdata *fd, Inferred &out) {
    if (!out.usable || fd->getFuncProto().numParams() > 32 || !errors.str().empty()) { out.usable = false; return; }
    for (auto it = arch.commentdb->beginComment(fd->getAddress()); it != arch.commentdb->endComment(fd->getAddress()); ++it)
      if (((*it)->getType() & (Comment::warning | Comment::warningheader)) &&
          inferenceGap((*it)->getText())) out.usable = false;
    const auto homes = homedParameters(fd);
    if (homes && fd->getFuncProto().numParams() < int4(homes)) out.usable = false;
    bool unknown_calls = false;
    for (int4 i = 0; i < fd->numCalls(); ++i) {
      const auto *call = fd->getCallSpecs(i);
      if (!call->isInputLocked() || !call->isOutputLocked()) unknown_calls = true;
    }
    if (unknown_calls) {
      // A complete four-register home prologue corroborates four recovered
      // inputs. Keep the return unlocked and its uncertainty visible to callers.
      if (fourHomedInputs(fd)) out.output_known = false;
      else out.usable = false;
    }
    if (out.usable) {
      fd->getFuncProto().getPieces(out.pieces);
      // A non-leaf or memory-dependent result can carry request-local pointer,
      // array or global types. Retain those results only within the original
      // request. Pure scalar leaves cannot observe another function's hint.
      const auto scalar = [](const Datatype *type) {
        const auto kind = type->getMetatype();
        return type->getSize() <= 8 && (kind == TYPE_VOID || kind == TYPE_UNKNOWN ||
          kind == TYPE_INT || kind == TYPE_UINT || kind == TYPE_BOOL || kind == TYPE_FLOAT);
      };
      out.context_independent = spec.sla == sla_x64_bytes && spec.pack == pack_x64_bytes &&
        fd->numCalls() == 0 && fd->getBasicBlocks().getSize() == 1 && scalar(out.pieces.outtype) &&
        std::all_of(out.pieces.intypes.begin(), out.pieces.intypes.end(), scalar);
      for (auto it = fd->beginOpAll(); out.context_independent && it != fd->endOpAll(); ++it) {
        const auto code = it->second->code();
        if (code == CPUI_LOAD || code == CPUI_STORE || code == CPUI_CALL || code == CPUI_CALLIND || code == CPUI_CALLOTHER ||
            code == CPUI_CPOOLREF || code == CPUI_NEW) out.context_independent = false;
        for (int4 i = 0; out.context_independent && i < it->second->numInput(); ++i) {
          const auto *input = it->second->getIn(i);
          if (input->isConstant() && arch.image().mapped(input->getOffset())) out.context_independent = false;
        }
      }
      for (auto it = fd->beginLoc(); out.context_independent && it != fd->endLoc(); ++it) {
        const auto *input = *it;
        if (!input->isInput() || input->isSpacebase()) continue;
        bool parameter = false;
        for (int4 i = 0; i < fd->getFuncProto().numParams(); ++i) {
          const auto *param = fd->getFuncProto().getParam(i);
          const auto &address = param->getAddress();
          if (input->getSpace() != address.getSpace() || input->getOffset() < address.getOffset()) continue;
          const auto offset = input->getOffset() - address.getOffset();
          const auto size = uint64_t(param->getSize());
          parameter |= offset <= size && uint64_t(input->getSize()) <= size - offset;
        }
        if (!parameter) out.context_independent = false;
      }
    }
  }
  // A negative stack input has no reaching definition. It cannot establish
  // the high half of an inferred scalar result after a scratch-register pop.
  bool undefinedHighReturns(Funcdata *fd) {
    bool seen = false;
    for (auto it = fd->beginOpAll(); it != fd->endOpAll(); ++it) {
      const auto *op = it->second;
      if (op->isDead() || op->code() != CPUI_RETURN || op->getHaltType() == PcodeOp::noreturn) continue;
      if (op->numInput() != 2) return false;
      const auto *value = op->getIn(1);
      if (value->getSize() != 8 || !value->isWritten()) return false;
      const auto *piece = value->getDef();
      if (piece->code() != CPUI_PIECE || piece->getIn(1)->getSize() != 4) return false;
      const auto *high = piece->getIn(0);
      if (high->getSize() != 4 || !high->isInput() || high->getSpace() != arch.getStackSpace() ||
          (high->getOffset() & 0x80000000ULL) == 0) return false;
      seen = true;
    }
    return seen;
  }
  // A caller consumes AL and every return has a Boolean low byte. Require a
  // partial AL result too: this is not a general license to narrow integers.
  bool booleanByteReturns(Funcdata *fd) {
    bool partial = false, seen = false;
    for (auto it = fd->beginOpAll(); it != fd->endOpAll(); ++it) {
      const auto *op = it->second;
      if (op->isDead() || op->code() != CPUI_RETURN) continue;
      if (op->getHaltType() == PcodeOp::noreturn) continue;
      if (op->numInput() != 2) return false;
      const auto *value = op->getIn(1);
      if ((value->getNZMask() & 0xfe) != 0) return false;
      seen = true;
      if (value->isWritten()) {
        const auto *def = value->getDef();
        if (def->code() == CPUI_PIECE && def->getIn(1)->getSize() == 1 &&
            def->getIn(1)->getNZMask() <= 1) partial = true;
      }
    }
    return seen && partial;
  }
  /// Infer and lock the direct callees of \p selected; returns how many were applied.
  size_t inferDirect(Funcdata *selected) {
    in_progress.insert(selected->getAddress().getOffset());
    size_t count = 0, seen = 0;
    std::vector<std::pair<uint64_t, const Inferred *>> usable;
    for (auto target : directTargets(selected)) {
      if (in_progress.count(target)) continue;
      if (++seen > 16) break;
      const auto &entry = infer(target, 1);
      if (entry.usable) usable.emplace_back(target, &entry);
    }
    for (auto &[target, entry] : usable) { apply(target, *entry, selected); ++count; }
    return count;
  }
  Funcdata *function(uint64_t address, const std::string &name, bool noreturn) {
    auto *scope = arch.symboltab->getGlobalScope();
    Address addr(arch.getDefaultCodeSpace(), address);
    auto *fd = scope->queryFunction(addr);
    if (!fd) {
      if (++symbols > 100000) throw std::runtime_error("symbol limit exceeded");
      fd = scope->addFunction(addr, name)->getFunction();
    }
    fd->getFuncProto().setModel(arch.defaultfp);
    if (noreturn) fd->getFuncProto().setNoReturn(true);
    return fd;
  }
  /// Apply a packed archive prototype to \p fd. Windows x64 has one ABI, so
  /// archive convention names such as __stdcall map to the default model.
  bool apply_pack_prototype(Funcdata *fd, const std::string &function) {
    std::string xml;
    // Like Ghidra's ApplyFunctionDataTypesCmd, an archive function `free` also types a symbol
    // `_free` (the cdecl-decorated name Function ID reports on x86-32) when no exact name exists.
    if (!prototype_pack(spec).find("F:" + function, xml) &&
        !(function.size() > 1 && function[0] == '_' && prototype_pack(spec).find("F:" + function.substr(1), xml))) {
      // Win32 exports sometimes omit the A suffix. Require both archive variants.
      std::string wide;
      if (spec.pack != pack_x86_bytes && spec.pack != pack_x64_bytes) return false;
      if (!prototype_pack(spec).find("F:" + function + "A", xml) ||
          !prototype_pack(spec).find("F:" + function + "W", wide)) return false;
    }
    const size_t at = xml.find(" model=\"");
    if (at != std::string::npos) {
      const size_t start = at + 8, end = xml.find('"', start);
      // A Go compiler specification names the platform's C convention itself (`MSABI`, System V
      // `__stdcall`); its default model is Go's own.
      if (end != std::string::npos && spec.import_model && arch.getModel(spec.import_model))
        xml.replace(start, end - start, spec.import_model);
      else if (end != std::string::npos && !arch.getModel(xml.substr(start, end - start)))
        xml.replace(start, end - start, arch.defaultfp->getName());
    }
    std::istringstream input(xml);
    DocumentStorage store;
    XmlDecode decoder(&arch, store.parseDocument(input)->getRoot());
    // A symbol-backed prototype cannot decode a full definition, so decode into a
    // standalone prototype and transfer its pieces, as set_signature does.
    FuncProto decoded;
    decoded.setInternal(arch.defaultfp, arch.types->getTypeVoid());
    decoded.decode(decoder, &arch);
    PrototypePieces pieces;
    decoded.getPieces(pieces);
    if (spec.pack == pack_macos64_bytes) {
      // C array parameters decay to pointers. The Apple archive preserves some
      // header typedefs as arrays, which otherwise have no ABI storage location.
      for (auto *&type : pieces.intypes) {
        if (type->getMetatype() == TYPE_ARRAY)
          type = pointerTo(static_cast<TypeArray *>(type)->getBase());
      }
      // Refuse an unrepresentable parameter before ProtoStoreSymbol dereferences
      // its missing address space. Unknown prototypes remain inferred.
      std::vector<ParameterPieces> storage;
      pieces.model->assignParameterStorage(pieces, storage, false);
      for (const auto &piece : storage)
        if (piece.type->getMetatype() != TYPE_VOID && piece.addr.isInvalid()) return false;
    }
    auto &proto = fd->getFuncProto();
    const bool noreturn = proto.isNoReturn() || decoded.isNoReturn();
    proto.setPieces(pieces);
    proto.setInputLock(true);
    proto.setOutputLock(true);
    proto.setModelLock(true);
    proto.setNoReturn(noreturn);
    refreshExplicit(fd);
    // The x86 Windows archive describes fixed-argument stdcall imports but
    // leaves extrapop unknown. Once their argument storage is locked, the
    // compiler specification can calculate the callee's stack cleanup.
    // Without it, later stack arguments can be mistaken for earlier ones.
    if (!spec.wide && proto.getModelName() == "__stdcall" &&
        proto.getExtraPop() == ProtoModel::extrapop_unknown &&
        proto.isInputLocked() && !proto.isDotdotdot() && !proto.hasInputErrors())
      proto.resolveExtraPop();
    return true;
  }
  TypeFactoryPack &typesPack() { return *static_cast<TypeFactoryPack *>(arch.types); }
  /// Decode a Go pack function payload ("<marks>|<prototype>") and install it on \p fd. False when
  /// the Go ABI's storage cannot be expressed; engine errors propagate.
  bool applyGo(Funcdata *fd, const std::string &payload) {
    const size_t bar = payload.find('|');
    if (bar == std::string::npos) throw std::runtime_error("malformed Go prototype record");
    const std::string marks = payload.substr(0, bar);
    const bool abi0 = fd->getFuncProto().getModelName() == "abi0";
    std::istringstream input(payload.substr(bar + 1));
    DocumentStorage store;
    XmlDecode decoder(&arch, store.parseDocument(input)->getRoot());
    // Only the names and types are read: FuncProto::decode would also ask the model to place the
    // parameters, which fails for large values the Go ABI simply puts on the stack.
    const auto skip = [&]() {
      const uint4 element = decoder.openElement();
      decoder.closeElementSkipping(element);
    };
    const uint4 prototype = decoder.openElement(ELEM_PROTOTYPE);
    const uint4 returnsym = decoder.openElement(ELEM_RETURNSYM);
    skip();  // <addr/>
    Datatype *result = arch.types->decodeType(decoder);
    decoder.closeElement(returnsym);
    std::vector<Datatype *> types;
    std::vector<std::string> names;
    const uint4 list = decoder.openElement(ELEM_INTERNALLIST);
    while (decoder.peekElement() != 0) {
      const uint4 param = decoder.openElement();
      names.push_back(decoder.readString(ATTRIB_NAME));
      skip();  // <addr/>
      types.push_back(arch.types->decodeType(decoder));
      decoder.closeElement(param);
    }
    decoder.closeElement(list);
    decoder.closeElement(prototype);
    bool installed = installGo(fd, types, names, result, marks.find('m') != std::string::npos, abi0,
                               marks.find('n') != std::string::npos);
    if (installed) refreshExplicit(fd);
    return installed;
  }
  bool go_registers = false;
  /// Storage for one value: a register, a join of registers (most significant first, as the
  /// engine wants) or a stack slot. False when the pieces do not cover the value exactly (a struct
  /// whose registers skip padding), which Ghidra only logs.
  bool goStorage(const std::vector<VarnodeData> &regs, Datatype *type, Address &out) {
    if (regs.size() == 1) {
      if (int4(regs[0].size) != type->getSize()) return false;
      out = regs[0].getAddr();
      return true;
    }
    uint4 total = 0;
    for (const auto &reg : regs) total += reg.size;
    if (int4(total) != type->getSize()) return false;
    std::vector<VarnodeData> pieces(regs.rbegin(), regs.rend());
    // A logical size is only for a single truncated piece; several pieces add up.
    out = arch.findAddJoin(pieces, 0)->getUnified().getAddr();
    return true;
  }
  bool installGoStack(Funcdata *fd, uint32_t inputs, uint32_t results) {
    auto *word = arch.types->getBase(4, TYPE_UNKNOWN);
    std::vector<Datatype *> types(inputs / 4, word);
    std::vector<std::string> names;
    for (uint32_t i = 0; i < inputs / 4; ++i) names.push_back("param_" + std::to_string(i + 1));
    Datatype *result = results == 4 ? word : arch.types->getTypeArray(results / 4, word);
    return installGo(fd, types, names, result, false, true, false);
  }
  void resetGoStack(Funcdata *fd) {
    auto layout = go_stack_functions.find(fd->getAddress().getOffset());
    // Storage is inferred once, but an unknown word's semantic type can change
    // during analysis. Do not retain that request's type for the next caller.
    if (layout != go_stack_functions.end())
      installGoStack(fd, layout->second.first, layout->second.second);
  }
  /// Give \p fd the Go signature (\p types, \p names, \p result) with the storage the Go ABI assigns
  /// (`GoFunctionFixup.apply`). \p multi: the result is a structure of several Go results, each
  /// assigned on its own. False if some storage cannot be expressed; \p fd is then untouched.
  bool installGo(Funcdata *fd, const std::vector<Datatype *> &types, const std::vector<std::string> &names,
                 Datatype *result, bool multi, bool abi0, bool noreturn) {
    GoAllocator allocator(arch, spec.wide, go_registers && !abi0, spec.sla == sla_arm64_bytes);
    auto *stack = arch.getStackSpace();
    std::vector<ParameterPieces> inputs;
    std::vector<VarnodeData> regs;
    for (auto *type : types) {
      ParameterPieces piece;
      piece.type = type;
      piece.flags = ParameterPieces::typelock | ParameterPieces::namelock;
      if (allocator.registers(type, regs)) {
        if (!goStorage(regs, type, piece.addr)) return false;
      } else {
        piece.addr = Address(stack, uintb(allocator.onStack(type)));
      }
      inputs.push_back(piece);
    }
    allocator.alignStack();
    allocator.reset();
    ParameterPieces output;
    output.type = result;
    output.flags = ParameterPieces::typelock;
    if (result->getMetatype() != TYPE_VOID) {
      if (multi && result->getMetatype() == TYPE_STRUCT) {
        // `GoFunctionMultiReturn`: each result is assigned on its own, so registers hold them with
        // no padding between and the stack with Go's alignment. The structure the caller sees is
        // laid out the way the storage is.
        auto *structure = static_cast<TypeStruct *>(result);
        std::vector<VarnodeData> all;
        std::vector<TypeField> fields;
        int64_t first_stack = -1, stack_end = 0;
        int4 register_bytes = 0;
        for (auto it = structure->beginField(); it != structure->endField(); ++it) {
          if (allocator.registers(it->type, regs)) {
            if (first_stack >= 0) return false;  // split between registers and stack
            int4 bytes = 0;
            for (const auto &reg : regs) bytes += int4(reg.size);
            if (bytes != it->type->getSize()) return false;
            fields.emplace_back(int4(fields.size()), register_bytes, it->name, it->type);
            register_bytes += bytes;
            all.insert(all.end(), regs.begin(), regs.end());
          } else {
            if (!all.empty()) return false;
            const int64_t at = allocator.onStack(it->type);
            if (first_stack < 0) first_stack = at;
            fields.emplace_back(int4(fields.size()), int4(at - first_stack), it->name, it->type);
            stack_end = at + it->type->getSize();
          }
        }
        const int4 size = first_stack >= 0 ? int4(stack_end - first_stack) : register_bytes;
        if (size <= 0) return false;
        auto set_struct_fields = access_set_struct_fields(SetStructFieldsTag());
        auto *laid_out = arch.types->getTypeStruct(structure->getName() + "_storage");
        if (laid_out->numDepend() == 0)
          (arch.types->*set_struct_fields)(fields, {}, laid_out, size, 1, 0);
        output.type = laid_out;
        if (first_stack >= 0) {
          output.addr = Address(stack, uintb(first_stack));
        } else if (!goStorage(all, laid_out, output.addr)) {
          return false;
        }
      } else if (allocator.registers(result, regs)) {
        if (!goStorage(regs, result, output.addr)) return false;
      } else {
        // On the stack, after the arguments: the stack ABI, or a result too large for registers.
        output.addr = Address(stack, uintb(allocator.onStack(result)));
      }
    }
    auto &proto = fd->getFuncProto();
    ProtoModel *model = arch.getModel(abi0 || !go_registers ? "abi0" : "abi-internal");
    if (!model) throw std::runtime_error("Go compiler specification has no abi0 or abi-internal model");
    proto.setModel(model);
    ProtoStore *store = proto.*access_proto_store(ProtoStoreTag());
    store->clearAllInputs();
    store->setOutput(output);
    for (size_t i = 0; i < inputs.size(); ++i) store->setInput(int4(i), names[i], inputs[i]);
    proto.setInputLock(true);
    proto.setOutputLock(true);
    proto.setModelLock(true);
    if (noreturn) proto.setNoReturn(true);
    return true;
  }
};
Session::Session(binfera::Language language) : impl(checked([language] {
  const Spec &spec = spec_for(language);
  constructing_spec = &spec;
  return std::unique_ptr<Impl>(new Impl(spec));
})) {}
Session::~Session() { std::lock_guard<std::mutex> lock(engine_mutex); impl.reset(); }
std::unique_ptr<Session> new_session(binfera::Language language) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  return checked([language] {
    std::call_once(initialized, [] {
      AttributeId::initialize(); ElementId::initialize(); CapabilityPoint::initializeAll();
    });
    return std::unique_ptr<Session>(new Session(language));
  });
}
rust::Slice<const uint8_t> prototype_pack_bytes(binfera::Language language) {
  const Spec &spec = spec_for(language);
  return rust::Slice<const uint8_t>(spec.pack, spec.pack_size);
}
void Session::add_section(uint64_t address, rust::Slice<const uint8_t> bytes, bool executable, bool readonly) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    impl->ready();
    auto &image = impl->arch.image();
    if (bytes.empty() || address >= impl->spec.address_limit || bytes.size() >= impl->spec.address_limit - address)
      throw std::runtime_error("invalid section range");
    if (bytes.size() > 256 * 1024 * 1024 - image.total)
      throw std::runtime_error("mapped image limit exceeded (256 MiB)");
    if (image.sections.size() >= 4096)
      throw std::runtime_error("mapped section count limit exceeded (4096)");
    for (const auto &s : image.sections)
      if (address < s.address + s.bytes.size() && s.address < address + bytes.size())
        throw std::runtime_error("overlapping image sections");
    image.sections.push_back({address, std::vector<uint8_t>(bytes.begin(), bytes.end()), executable});
    image.total += bytes.size();
    if (readonly) impl->arch.symboltab->setPropertyRange(Varnode::readonly,
      Range(impl->arch.getDefaultCodeSpace(), address, address + bytes.size() - 1));
  });
}
void Session::set_arm_mode(uint64_t start, uint64_t end, bool thumb) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    impl->ready();
    if (impl->spec.sla != sla_arm32_bytes || start >= end || end > impl->spec.address_limit)
      throw std::runtime_error("invalid ARM context range");
    auto &arch = impl->arch;
    arch.context->setVariableRegion("TMode", Address(arch.getDefaultCodeSpace(), start), Address(arch.getDefaultCodeSpace(), end), thumb ? 1 : 0);
    impl->invalidateInferred();
  });
}
void Session::set_register_value(uint64_t start, uint64_t end, rust::Str name, uint64_t value) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    impl->ready();
    if (start >= end || end > impl->spec.address_limit) throw std::runtime_error("invalid register context range");
    auto &arch = impl->arch;
    const Address begin(arch.getDefaultCodeSpace(), start), limit(arch.getDefaultCodeSpace(), end);
    auto values = arch.context->getTrackedSet(begin);
    const auto reg = arch.translate->getRegister(std::string(name));
    values.erase(std::remove_if(values.begin(), values.end(), [&](const TrackedContext &v) { return v.loc.space == reg.space && v.loc.offset == reg.offset; }), values.end());
    values.push_back({reg, value});
    arch.context->createSet(begin, limit) = values;
    impl->invalidateInferred();
  });
}
void Session::set_code_exclusions(rust::Slice<const binfera::CodeRange> ranges) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    impl->ready();
    if (ranges.size() > 100000) throw std::runtime_error("code exclusion limit exceeded (100000)");
    uint64_t previous_end = 0;
    for (const auto &range : ranges) {
      if (range.start >= range.end || range.end > impl->spec.address_limit || range.start < previous_end)
        throw std::runtime_error("code exclusions must be sorted, non-overlapping address ranges");
      previous_end = range.end;
    }
    impl->arch.image().code_exclusions.assign(ranges.begin(), ranges.end());
    impl->invalidateInferred();
  });
}
void Session::set_function_ranges(rust::Slice<const binfera::CodeRange> ranges) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    impl->ready();
    if (ranges.size() > 100000) throw std::runtime_error("function range limit exceeded (100000)");
    uint64_t previous_end = 0;
    for (const auto &range : ranges) {
      if (range.start >= range.end || range.end > impl->spec.address_limit || range.start < previous_end)
        throw std::runtime_error("function ranges must be sorted and non-overlapping");
      previous_end = range.end;
    }
    impl->arch.image().function_ranges.assign(ranges.begin(), ranges.end());
    impl->invalidateInferred();
  });
}
void Session::add_function(uint64_t address, rust::Str name, bool noreturn) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    impl->ready();
    impl->invalidateInferred();
    impl->function(address, identifier(name, impl->spec.go_pack), noreturn);
    impl->supplied_entries.insert(address);
  });
}
void Session::add_import(uint64_t address, rust::Str name, bool noreturn) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    impl->ready();
    impl->invalidateInferred();
    auto &arch = impl->arch;
    if (address > UINT64_MAX - 7 || address + impl->ptr() > impl->spec.address_limit) throw std::runtime_error("import slot address overflow");
    // Only the IAT slot is mutable. Preserve read-only strings/constants in
    // the rest of the section instead of disabling the whole section.
    arch.symboltab->clearPropertyRange(Varnode::readonly,
      Range(arch.getDefaultCodeSpace(), address, address + impl->ptr() - 1));
    // ExternRefSymbol's address is the IAT slot. Its target names a function
    // in a reserved unmapped range, never executable sample bytes.
    const uint64_t target = impl->spec.external_base + impl->symbols * 16;
    impl->function(target, identifier(name, impl->spec.go_pack), noreturn);
    arch.symboltab->getGlobalScope()->addExternalRef(Address(arch.getDefaultCodeSpace(), address),
      Address(arch.getDefaultCodeSpace(), target), identifier(name));
  });
}
bool Session::set_callsite_arguments(uint64_t caller, uint64_t site, uint64_t target, uint32_t count) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  return checked([&] {
    impl->ready();
    if (impl->spec.cspec != cspec_x64_bytes || count < 4 || count > 32) return false;
    auto &arch = impl->arch;
    auto *scope = arch.symboltab->getGlobalScope();
    auto *fd = scope->queryFunction(Address(arch.getDefaultCodeSpace(), caller));
    auto *callee = scope->queryFunction(Address(arch.getDefaultCodeSpace(), target));
    if (!fd || !callee || impl->supplied_prototypes.count(target) || (callee->getFuncProto().isInputLocked() && !impl->callsite_argument_functions.count(target))) return false;
    PrototypePieces pieces;
    pieces.model = arch.defaultfp;
    pieces.outtype = arch.types->getBase(8, TYPE_UNKNOWN);
    pieces.firstVarArgSlot = -1;
    for (uint32_t i = 0; i < count; ++i) {
      pieces.intypes.push_back(arch.types->getBase(8, TYPE_UNKNOWN));
      pieces.innames.push_back("param_" + std::to_string(i + 1));
    }
    auto proto = std::make_unique<FuncProto>();
    proto->setInternal(arch.defaultfp, arch.types->getTypeVoid());
    proto->setPieces(pieces);
    proto->setInputLock(true);
    proto->setOutputLock(false);
    proto->setModelLock(true);
    auto *override_proto = proto.release();
    fd->getOverride().insertProtoOverride(Address(arch.getDefaultCodeSpace(), site), override_proto);
    impl->callsite_prototypes[{caller, site}] = {target, override_proto};
    pieces.intypes.resize(4);
    pieces.innames.resize(4);
    pieces.firstVarArgSlot = 4;
    callee->getFuncProto().setPieces(pieces);
    callee->getFuncProto().setInputLock(true);
    callee->getFuncProto().setOutputLock(false);
    impl->callsite_argument_functions.insert(caller);
    impl->callsite_argument_functions.insert(target);
    impl->invalidateInferred();
    return true;
  });
}
bool Session::set_message_send(uint64_t caller, uint64_t site, uint32_t count) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  return checked([&] {
    impl->ready();
    if (count < 2 || count > 16) return false;
    auto &arch = impl->arch;
    auto *fd = arch.symboltab->getGlobalScope()->queryFunction(Address(arch.getDefaultCodeSpace(), caller));
    if (!fd) return false;
    // `objc_msgSend(self, op, ...)`: the selector's colons say how many arguments follow, which
    // the variadic import's own prototype cannot. Typed as words; the selector names them.
    auto *pointer = arch.types->getTypePointer(impl->ptr(), arch.types->getTypeVoid(), 1);
    PrototypePieces pieces;
    pieces.model = arch.defaultfp;
    pieces.outtype = pointer;
    pieces.firstVarArgSlot = -1;
    for (uint32_t i = 0; i < count; ++i) {
      pieces.intypes.push_back(i < 2 ? pointer : arch.types->getBase(impl->ptr(), TYPE_UNKNOWN));
      pieces.innames.push_back(i == 0 ? "self" : i == 1 ? "op" : "arg" + std::to_string(i - 1));
    }
    auto proto = std::make_unique<FuncProto>();
    proto->setInternal(arch.defaultfp, arch.types->getTypeVoid());
    proto->setPieces(pieces);
    proto->setInputLock(true);
    proto->setOutputLock(false);
    proto->setModelLock(true);
    fd->getOverride().insertProtoOverride(Address(arch.getDefaultCodeSpace(), site), proto.release());
    impl->invalidateInferred();
    return true;
  });
}
bool Session::set_go_stack_layout(uint64_t address, uint32_t inputs, uint32_t results) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  return checked([&] {
    impl->ready();
    if (!impl->spec.go_pack || impl->spec.wide || inputs > 512 || results == 0 || results > 512 || (inputs % 4) || (results % 4)) return false;
    auto &arch = impl->arch;
    auto *fd = arch.symboltab->getGlobalScope()->queryFunction(Address(arch.getDefaultCodeSpace(), address));
    if (!fd || fd->getFuncProto().isInputLocked() || fd->getFuncProto().isOutputLocked()) return false;
    impl->invalidateInferred();
    bool installed = impl->installGoStack(fd, inputs, results);
    if (installed) impl->go_stack_functions[address] = {inputs, results};
    return installed;
  });
}
void Session::set_counted_strings(bool enabled) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    impl->ready();
    impl->invalidateInferred();
    impl->counted_strings = enabled;
  });
}
void Session::set_linux_syscalls(bool enabled) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    impl->ready();
    impl->invalidateInferred();
    static_cast<const ImageSleigh *>(impl->arch.translate)->linux_syscalls = enabled;
  });
}
bool Session::apply_prototype(uint64_t address, rust::Str name) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  return checked([&] {
    impl->ready();
    impl->invalidateInferred();
    if (name.size() > 256) throw std::runtime_error("function name exceeds 256 bytes");
    auto &arch = impl->arch;
    auto *scope = arch.symboltab->getGlobalScope();
    Address addr(arch.getDefaultCodeSpace(), address);
    auto *fd = scope->queryFunction(addr);
    if (!fd) fd = scope->queryExternalRefFunction(addr);
    if (!fd) throw std::runtime_error("prototype address is not a registered function or import");
    try {
      return impl->apply_pack_prototype(fd, std::string(name));
    } catch (const LowlevelError &) {
      // A handful of archive types still cannot be reconstructed (see the
      // validation test); leave the prototype unknown rather than guessed.
      return false;
    } catch (const DecoderError &) {
      return false;
    }
  });
}
rust::String Session::validate_prototype_pack(uint32_t max_report) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  return checked([&] {
    impl->ready();
    size_t functions = 0, types = 0, failures = 0;
    std::string report;
    auto fail = [&](const std::string &key, const std::string &what) {
      if (failures++ < max_report) report += "\n  " + key + ": " + what;
    };
    for (const auto &key : prototype_pack(impl->spec).keys()) {
      try {
        if (key.compare(0, 2, "T:") == 0) {
          types++;
          const uint64_t id = std::stoull(key.substr(2), nullptr, 16);
          if (!static_cast<TypeFactoryPack *>(impl->arch.types)->resolve(id)) fail(key, "not resolved");
        } else {
          functions++;
          if (impl->symbols + 1 > 99999) throw LowlevelError("validation symbol limit");
          const uint64_t target = impl->spec.external_base + impl->symbols * 16;
          auto *fd = impl->function(target, "validate_" + std::to_string(functions), false);
          if (!impl->apply_pack_prototype(fd, key.substr(2))) fail(key, "not found");
        }
      } catch (const LowlevelError &e) {
        fail(key, e.explain);
      } catch (const DecoderError &e) {
        fail(key, e.explain);
      }
    }
    return rust::String("functions=" + std::to_string(functions) + " types=" + std::to_string(types) +
                        " failures=" + std::to_string(failures) + report);
  });
}
int32_t Session::stack_purge(uint64_t address) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  return checked([&]() -> int32_t {
    impl->ready();
    auto &arch = impl->arch;
    auto *scope = arch.symboltab->getGlobalScope();
    Address at(arch.getDefaultCodeSpace(), address);
    auto *fd = scope->queryExternalRefFunction(at);
    if (!fd) fd = scope->queryFunction(at);
    if (!fd || impl->spec.wide) return -1;
    auto &proto = fd->getFuncProto();
    return proto.getExtraPop() == ProtoModel::extrapop_unknown ? -1 : proto.getExtraPop() - 4;
  });
}
void Session::set_stack_purge(uint64_t address, uint32_t bytes) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    impl->ready();
    if (impl->spec.wide || bytes > 1024 || bytes % 4) throw std::runtime_error("invalid x86 stack purge");
    auto &arch = impl->arch;
    auto *fd = arch.symboltab->getGlobalScope()->queryExternalRefFunction(Address(arch.getDefaultCodeSpace(), address));
    if (!fd) throw std::runtime_error("stack purge requires an import slot");
    auto &proto = fd->getFuncProto();
    if (!proto.isInputLocked()) proto.setExtraPop(bytes + 4);
    impl->invalidateInferred();
  });
}
void Session::add_branch(uint64_t site, uint64_t target, uint32_t length, uint32_t pop) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    impl->ready();
    auto &arch = impl->arch;
    if (!length || length > 15 || (pop != 0 && pop != 4) ||
        !arch.image().executable(site, length) || !arch.image().executable(target))
      throw std::runtime_error("invalid compiler branch override");
    auto *translator = static_cast<const ImageSleigh *>(arch.translate);
    if (translator->branches.size() >= 100000) throw std::runtime_error("branch override limit exceeded");
    translator->branches[site] = {target, length, pop};
    impl->invalidateInferred();
  });
}
void Session::add_tail_call(uint64_t caller, uint64_t site, uint64_t target) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    impl->ready();
    impl->invalidateInferred();
    auto &arch = impl->arch;
    auto *fd = arch.symboltab->getGlobalScope()->queryFunction(Address(arch.getDefaultCodeSpace(), caller));
    const auto target_address = Address(arch.getDefaultCodeSpace(), target);
    const bool known_import = arch.symboltab->getGlobalScope()->queryExternalRefFunction(target_address) != nullptr;
    if (!fd || !arch.image().executable(site) || (!arch.image().executable(target) && !known_import))
      throw std::runtime_error("tail call requires a registered caller, executable site and code/import target");
    if (++impl->edges > 1000000) throw std::runtime_error("call edge limit exceeded");
    fd->getOverride().insertFlowOverride(Address(arch.getDefaultCodeSpace(), site), Override::CALL_RETURN);
    if (impl->spec.sla == sla_arm64_bytes || impl->spec.sla == sla_arm32_bytes ||
        impl->spec.sla == sla_mipsle_bytes || impl->spec.sla == sla_mipsbe_bytes) {
      // The host validated the complete PLT/IAT stub, including its branch register.
      auto *external = arch.symboltab->getGlobalScope()->queryExternalRefFunction(target_address);
      fd->getOverride().insertIndirectOverride(Address(arch.getDefaultCodeSpace(), site),
        external ? external->getAddress() : target_address);
      impl->explicit_indirect[caller].insert(site);
    }
  });
}
// Only the debug reader's bounded type graph crosses this boundary. Recursive structures get
// identities before fields, so pointers can refer back to their containing type.
void Session::add_debug_types(rust::Slice<const DebugType> records) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    impl->ready();
    if (records.size() > 250000) throw std::runtime_error("debug type budget exceeded");
    auto *types = impl->arch.types;
    auto &known = impl->debug_types;
    known[0] = types->getTypeVoid();
    std::map<uint64_t, const DebugType *> by_id;
    for (const auto &record : records) {
      if (!record.id || record.size > (1u << 20) || record.fields.size() > 65536) continue;
      by_id.emplace(record.id, &record);
      if (record.kind == "struct" && record.size) {
        // DWARF IDs disambiguate unrelated types with the same spelling in different units.
        // Reuse a spelling only for its first definition, including archive name collisions.
        std::string name = identifier(record.name, true);
        if (types->findByName(name)) name += "_dwarf_" + hexAddress(record.id);
        known[record.id] = types->getTypeStruct(name);
      }
    }
    std::set<uint64_t> active, completed;
    std::function<Datatype *(uint64_t, unsigned)> resolve;
    resolve = [&](uint64_t id, unsigned depth) -> Datatype * {
      if (id == 0) return known[0];
      if (depth > 64) return nullptr;
      auto it = by_id.find(id);
      if (it == by_id.end()) return nullptr;
      const auto &r = *it->second;
      auto cached = known.find(id);
      if (cached != known.end() && (r.kind != "struct" || completed.count(id) || active.count(id))) return cached->second;
      if (!active.insert(id).second) return nullptr;
      Datatype *type = nullptr;
      if (r.kind == "struct") {
        auto *structure = static_cast<TypeStruct *>(known.at(id));
        std::vector<TypeField> fields;
        uint64_t end = 0;
        int4 alignment = 1;
        bool packed = false;
        // Offsets are sorted by Rust's reader below only implicitly for normal producer output;
        // sort here and reject overlaps rather than allow a bogus layout into the engine.
        std::vector<const DebugField *> sorted;
        for (const auto &field : r.fields) sorted.push_back(&field);
        std::stable_sort(sorted.begin(), sorted.end(), [](auto *a, auto *b) { return a->offset < b->offset; });
        for (const auto *field : sorted) {
          auto *member = resolve(field->type_id, depth + 1);
          if (!member || member->getSize() <= 0 || field->offset < end ||
              uint64_t(field->offset) + member->getSize() > r.size || member == structure) {
            impl->debug_incomplete.insert(id);
            continue;
          }
          if (impl->debug_incomplete.count(field->type_id)) impl->debug_incomplete.insert(id);
          const int4 member_alignment = std::max<int4>(1, member->getAlignment());
          alignment = std::max(alignment, member_alignment);
          packed |= field->offset % member_alignment != 0;
          fields.emplace_back(int4(fields.size()), field->offset, identifier(field->name, true), member);
          end = uint64_t(field->offset) + member->getSize();
        }
        auto set_fields = access_set_struct_fields(SetStructFieldsTag());
        (types->*set_fields)(fields, {}, structure, r.size, packed || r.size % alignment ? 1 : alignment, 0);
        type = structure;
      } else if (r.kind == "pointer") {
        // Pointers need a structure's identity, not its fields. Filling it here would
        // lose a member that points back through this still-unfinished pointer type.
        uint64_t target_id = r.target;
        auto target_record = by_id.find(target_id);
        for (unsigned i = 0; i < 64 && target_record != by_id.end() && target_record->second->kind == "alias"; ++i) {
          target_id = target_record->second->target;
          target_record = by_id.find(target_id);
        }
        auto *target = target_record != by_id.end() && target_record->second->kind == "struct"
          ? known.at(target_id) : resolve(r.target, depth + 1);
        // An absent pointee is still a pointer, but never a guessed scalar parameter.
        type = impl->pointerTo(target ? target : types->getTypeVoid());
      } else if (r.kind == "alias") {
        type = resolve(r.target, depth + 1);
        if (impl->debug_incomplete.count(r.target)) impl->debug_incomplete.insert(id);
      } else if (r.kind == "array") {
        auto *element = resolve(r.target, depth + 1);
        if (impl->debug_incomplete.count(r.target)) impl->debug_incomplete.insert(id);
        if (element && element->getSize() > 0 && r.count && uint64_t(element->getSize()) * r.count <= (1u << 20))
          type = types->getTypeArray(r.count, element);
      } else if (r.size == 1 || r.size == 2 || r.size == 4 || r.size == 8 || r.size == 16) {
        if (r.kind == "int") type = types->getBase(r.size, TYPE_INT);
        else if (r.kind == "uint") type = types->getBase(r.size, TYPE_UINT);
        else if (r.kind == "bool" && r.size == 1) type = types->getBase(1, TYPE_BOOL);
        else if (r.kind == "float" && (r.size == 4 || r.size == 8 || r.size == 16)) type = types->getBase(r.size, TYPE_FLOAT);
      }
      active.erase(id);
      completed.insert(id);
      known[id] = type;
      return type;
    };
    for (const auto &[id, record] : by_id) resolve(id, 0);
  });
}
bool Session::set_debug_signature(uint64_t address, uint64_t result, rust::Str model, rust::Slice<const DebugParameter> parameters,
                                  bool varargs, bool go, bool multi, bool noreturn) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  return checked([&] {
    impl->ready();
    impl->invalidateInferred();
    if (parameters.size() > 32) return false;
    auto &arch = impl->arch;
    auto *fd = arch.symboltab->getGlobalScope()->queryFunction(Address(arch.getDefaultCodeSpace(), address));
    if (!fd) return false;
    auto lookup = [&](uint64_t id) -> Datatype * {
      auto it = impl->debug_types.find(id);
      return it == impl->debug_types.end() || impl->debug_incomplete.count(id) ? nullptr : it->second;
    };
    PrototypePieces pieces;
    pieces.outtype = lookup(result);
    if (!pieces.outtype) return false;
    pieces.model = arch.defaultfp;
    // MinGW's ordinary DWARF C functions use cdecl on i386, not the Windows
    // recovery default (stdcall with an inferred purge).
    if (!impl->spec.wide && !go) {
      if (auto *cdecl_model = arch.getModel("__cdecl")) pieces.model = cdecl_model;
    }
    if (!model.empty()) {
      auto *requested = arch.getModel(std::string(model));
      if (!requested) return false;
      pieces.model = requested;
    }
    pieces.firstVarArgSlot = varargs ? int4(parameters.size()) : -1;
    for (const auto &parameter : parameters) {
      auto *type = lookup(parameter.type_id);
      if (!type || type->getMetatype() == TYPE_VOID || type->getSize() <= 0) return false;
      pieces.intypes.push_back(type);
      pieces.innames.push_back(identifier(parameter.name, true));
    }
    if (go) {
      if (!impl->spec.go_pack) return false;
      bool installed = impl->installGo(fd, pieces.intypes, pieces.innames, pieces.outtype, multi,
                                      fd->getFuncProto().getModelName() == "abi0", noreturn);
      if (installed) impl->refreshExplicit(fd);
      return installed;
    }
    auto &proto = fd->getFuncProto();
    const bool no_return = noreturn || proto.isNoReturn();
    proto.setPieces(pieces);
    proto.setInputLock(true);
    proto.setOutputLock(true);
    proto.setModelLock(true);
    proto.setNoReturn(no_return);
    impl->refreshExplicit(fd);
    for (int4 i = 0; i < proto.numParams(); ++i) proto.getParam(i)->setNameLock(true);
    return true;
  });
}
bool Session::add_debug_local(uint64_t address, rust::Str name, uint64_t type_id, int64_t offset) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  return checked([&] {
    impl->ready();
    auto &arch = impl->arch;
    auto it = impl->debug_types.find(type_id);
    if (it == impl->debug_types.end() || !it->second || it->second->getSize() <= 0) return false;
    auto *fd = arch.symboltab->getGlobalScope()->queryFunction(Address(arch.getDefaultCodeSpace(), address));
    if (!fd || offset < -(1 << 20) || offset > (1 << 20)) return false;
    auto *stack = arch.getStackSpace();
    Address storage(stack, uintb(offset) & stack->getHighest());
    auto *local = fd->getScopeLocal();
    if (local->queryContainer(storage, it->second->getSize(), Address())) return false;
    if (auto *entry = local->addSymbol(identifier(name, true), it->second, storage, Address())) {
      local->setAttribute(entry->getSymbol(), Varnode::namelock | Varnode::typelock);
      (local->*access_collect_name_recs(CollectNameRecsTag()))();
      impl->invalidateInferred();
      return true;
    }
    return false;
  });
}
void Session::set_signature(uint64_t address, ValueType result, rust::Slice<const ValueType> parameters) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    impl->ready();
    impl->invalidateInferred();
    if (parameters.size() > 32) throw std::runtime_error("signature exceeds 32 parameters");
    auto &arch = impl->arch;
    auto *scope = arch.symboltab->getGlobalScope();
    Address addr(arch.getDefaultCodeSpace(), address);
    auto *fd = scope->queryFunction(addr);
    if (!fd) fd = scope->queryExternalRefFunction(addr);
    if (!fd) throw std::runtime_error("signature address is not a registered function or import");
    const auto type = [&](ValueType value) { return impl->valueType(value); };
    PrototypePieces pieces;
    pieces.model = arch.defaultfp;
    pieces.outtype = type(result);
    pieces.firstVarArgSlot = -1;
    for (auto parameter : parameters) {
      if (parameter == ValueType::Void) throw std::runtime_error("void is not a parameter type");
      pieces.intypes.push_back(type(parameter));
      pieces.innames.push_back("param_" + std::to_string(pieces.intypes.size()));
    }
    auto &proto = fd->getFuncProto();
    const bool noreturn = proto.isNoReturn();
    proto.setPieces(pieces);
    proto.setInputLock(true);
    proto.setOutputLock(true);
    proto.setModelLock(true);
    proto.setNoReturn(noreturn);
    impl->refreshExplicit(fd);
  });
}
/// The short name of a member: what follows the last `::` outside template arguments.
static std::string memberName(const std::string &qualified) {
  int depth = 0;
  size_t start = 0;
  for (size_t i = 0; i + 1 < qualified.size(); ++i) {
    const char ch = qualified[i];
    if (ch == '<') ++depth;
    else if (ch == '>') depth = std::max(0, depth - 1);
    else if (depth == 0 && ch == ':' && qualified[i + 1] == ':') start = ++i + 1;
  }
  return qualified.substr(start);
}
void Session::add_class(rust::Str name, rust::Slice<const VfTable> tables) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    impl->ready();
    impl->invalidateInferred();
    if (tables.size() > 64) throw std::runtime_error("class exceeds 64 virtual function tables");
    auto &arch = impl->arch;
    auto *types = arch.types;
    auto *scope = arch.symboltab->getGlobalScope();
    auto *space = arch.getDefaultCodeSpace();
    auto set_struct_fields = access_set_struct_fields(SetStructFieldsTag());
    const int4 ptr = impl->ptr();
    std::map<int4, TypeField> class_fields;
    int4 class_size = 0;
    for (const auto &table : tables) {
      if (table.slots.empty() || table.slots.size() > 1024 || table.offset > 0x100000)
        throw std::runtime_error("invalid virtual function table");
      auto *layout = impl->classType(table.type_name);
      if (layout->isIncomplete()) {
        // Each slot is a method: `this` first, where the table's model puts it, the rest found at
        // the call as for a variadic function, so a call through the table passes `this` and
        // keeps whatever else the caller sets up.
        Datatype *self = table.this_class.empty() ? static_cast<Datatype *>(types->getTypeVoid()) : impl->classType(table.this_class);
        PrototypePieces pieces;
        auto *model = arch.getModel(std::string(table.model));
        pieces.model = model ? model : arch.defaultfp;
        pieces.outtype = types->getBase(ptr, TYPE_UNKNOWN);
        pieces.intypes.push_back(impl->pointerTo(self));
        pieces.innames.push_back("this");
        pieces.firstVarArgSlot = 1;
        auto *slot_type = impl->pointerTo(types->getTypeCode(pieces));
        std::vector<TypeField> fields;
        std::set<std::string> used;
        for (size_t i = 0; i < table.slots.size(); ++i) {
          auto *fd = scope->queryFunction(Address(space, table.slots[i]));
          std::string field = fd ? memberName(fd->getName()) : "slot_" + std::to_string(i);
          if (field.empty() || !used.insert(field).second) {
            field += "_" + std::to_string(i);
            used.insert(field);
          }
          fields.emplace_back(int4(i), int4(i) * ptr, field, slot_type);
        }
        (types->*set_struct_fields)(fields, {}, layout, int4(table.slots.size()) * ptr, ptr, 0);
      }
      impl->label(table.address, identifier(table.label), layout);
      const int4 offset = int4(table.offset);
      if (!class_fields.count(offset))
        class_fields.emplace(offset, TypeField(int4(class_fields.size()), offset, identifier(table.field), impl->pointerTo(layout)));
      class_size = std::max(class_size, offset + ptr);
    }
    auto *klass = impl->classType(name);
    if (klass->isIncomplete() && !class_fields.empty()) {
      std::vector<TypeField> fields;
      for (auto &[offset, field] : class_fields) fields.emplace_back(int4(fields.size()), offset, field.name, field.type);
      // The object's size is unknown: open-ended, so an access past the table pointers is an
      // offset into the object, never an index into an array of objects.
      // `Datatype::variable_length` (type.hh) is protected; its value is 128.
      const uint4 variable_length = 128;
      (types->*set_struct_fields)(fields, {}, klass, class_size, ptr, variable_length);
    }
  });
}
bool Session::set_method(uint64_t address, rust::Str class_name) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  return checked([&] {
    impl->ready();
    impl->invalidateInferred();
    auto &arch = impl->arch;
    auto *fd = arch.symboltab->getGlobalScope()->queryFunction(Address(arch.getDefaultCodeSpace(), address));
    if (!fd) throw std::runtime_error("method requires a registered function");
    auto &proto = fd->getFuncProto();
    auto *model = arch.getModel("__thiscall");
    if (!model || proto.isInputLocked() || proto.isModelLocked()) return false;
    proto.setModel(model);
    proto.setModelLock(true);
    // Ghidra's own route for a method's `this` whose other parameters are unknown: a name-locked
    // symbol on its storage, which each analysis turns into a name and a type recommendation for
    // the input there (ScopeLocal::collectNameRecs, Funcdata::prepareThisPointer).
    auto *type = impl->pointerTo(impl->classType(class_name));
    const Address storage = proto.getThisPointerStorage(type);
    if (storage.isInvalid()) return false;
    auto *local = fd->getScopeLocal();
    if (auto *entry = local->addSymbol("this", type, storage, fd->getAddress() - 1)) {
      local->setAttribute(entry->getSymbol(), Varnode::namelock);
      local->setThisPointer(entry->getSymbol(), true);
    }
    (local->*access_collect_name_recs(CollectNameRecsTag()))();
    return true;
  });
}
bool Session::set_variadic_forwarder(uint64_t address, uint32_t fixed, uint64_t target) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  return checked([&] {
    impl->ready();
    if (impl->spec.cspec != cspec_x64gcc_bytes || fixed == 0 || fixed > 6 || address == target) return false;
    auto &arch = impl->arch;
    auto *fd = arch.symboltab->getGlobalScope()->queryFunction(Address(arch.getDefaultCodeSpace(), address));
    if (!fd || !arch.image().executable(target)) return false;
    auto &proto = fd->getFuncProto();
    if (proto.isInputLocked() || proto.isOutputLocked() || proto.isModelLocked()) return false;
    PrototypePieces pieces;
    pieces.model = arch.defaultfp;
    pieces.outtype = arch.types->getTypeVoid();
    for (uint32_t i = 0; i < fixed; ++i) {
      pieces.intypes.push_back(arch.types->getBase(8, TYPE_UNKNOWN));
      pieces.innames.push_back("param_" + std::to_string(i + 1));
    }
    pieces.firstVarArgSlot = fixed;
    proto.setPieces(pieces);
    proto.setInputLock(true);
    proto.setOutputLock(false);
    proto.setModelLock(true);
    impl->variadic_forwarders[address] = target;
    impl->invalidateInferred();
    return true;
  });
}
void Session::set_method_signature(uint64_t address, rust::Str model_name, rust::Str this_class, ValueType result,
                                   rust::Slice<const ValueType> parameters, bool varargs) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    impl->ready();
    impl->invalidateInferred();
    if (parameters.size() > 32) throw std::runtime_error("signature exceeds 32 parameters");
    auto &arch = impl->arch;
    auto *scope = arch.symboltab->getGlobalScope();
    Address addr(arch.getDefaultCodeSpace(), address);
    auto *fd = scope->queryFunction(addr);
    if (!fd) fd = scope->queryExternalRefFunction(addr);
    if (!fd) throw std::runtime_error("signature address is not a registered function or import");
    auto *model = arch.getModel(std::string(model_name));
    PrototypePieces pieces;
    pieces.model = model ? model : arch.defaultfp;
    pieces.outtype = impl->valueType(result);
    if (!this_class.empty()) {
      pieces.intypes.push_back(impl->pointerTo(impl->classType(this_class)));
      pieces.innames.push_back("this");
    }
    for (auto parameter : parameters) {
      if (parameter == ValueType::Void) throw std::runtime_error("void is not a parameter type");
      pieces.intypes.push_back(impl->valueType(parameter));
      pieces.innames.push_back("param_" + std::to_string(pieces.intypes.size() - (this_class.empty() ? 0 : 1)));
    }
    pieces.firstVarArgSlot = varargs ? int4(pieces.intypes.size()) : -1;
    auto &proto = fd->getFuncProto();
    const bool noreturn = proto.isNoReturn();
    proto.setPieces(pieces);
    proto.setInputLock(true);
    proto.setOutputLock(true);
    proto.setModelLock(true);
    proto.setNoReturn(noreturn);
    impl->refreshExplicit(fd);
    if (!impl->spec.wide && proto.getExtraPop() == ProtoModel::extrapop_unknown && !proto.isDotdotdot() &&
        !proto.hasInputErrors())
      proto.resolveExtraPop();
  });
}
bool Session::add_label(uint64_t address, rust::Str name, uint32_t size) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  return checked([&] {
    impl->ready();
    impl->invalidateInferred();
    if (!size || size > (1u << 20)) throw std::runtime_error("invalid label size");
    auto *types = impl->arch.types;
    return impl->label(address, identifier(name), types->getTypeArray(int4(size), types->getBase(1, TYPE_UNKNOWN)));
  });
}
static void preserveRegister(Architecture &arch, Funcdata *fd, const char *name) {
  // FuncProto's XML effect overrides merge with the compiler model while
  // retaining the signature and all other register effects.
  auto &proto = fd->getFuncProto();
  std::ostringstream encoded;
  XmlEncode encoder(encoded);
  proto.encode(encoder);
  std::istringstream input(encoded.str());
  DocumentStorage store;
  auto *root = store.parseDocument(input)->getRoot();
  auto *effects = new Element(root);
  root->addChild(effects);
  effects->setName("unaffected");
  auto *reg = new Element(effects);
  effects->addChild(reg);
  reg->setName("register");
  reg->addAttribute("name", name);
  XmlDecode decoder(&arch, root);
  proto.decode(decoder, &arch);
}
void Session::set_print_work_limit(uint32_t work) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] { impl->print_work_limit = work; });
}
void Session::set_preserves_rax(uint64_t address) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    impl->ready();
    impl->invalidateInferred();
    auto &arch = impl->arch;
    auto *fd = arch.symboltab->getGlobalScope()->queryFunction(Address(arch.getDefaultCodeSpace(), address));
    if (!fd) throw std::runtime_error("register effect requires a registered function");
    preserveRegister(arch, fd, "RAX");
  });
}
void Session::set_leaf_effects(uint64_t address, uint32_t zero_from, bool preserves_ecx) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    impl->ready();
    auto &arch = impl->arch;
    auto *fd = arch.symboltab->getGlobalScope()->queryFunction(Address(arch.getDefaultCodeSpace(), address));
    if (!fd || impl->spec.sla == sla_arm64_bytes || zero_from >= impl->ptr())
      throw std::runtime_error("invalid x86 leaf register effects");
    impl->invalidateInferred();
    if (zero_from)
      static_cast<const ImageSleigh *>(arch.translate)->return_zero_from[address] = zero_from;
    else
      static_cast<const ImageSleigh *>(arch.translate)->return_zero_from.erase(address);
    if (preserves_ecx) preserveRegister(arch, fd, impl->spec.wide ? "RCX" : "ECX");
  });
}
void Session::add_code_label(uint64_t owner, uint64_t address, rust::Str name) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    impl->ready();
    auto &arch = impl->arch;
    auto *fd = arch.symboltab->getGlobalScope()->queryFunction(Address(arch.getDefaultCodeSpace(), owner));
    if (!fd || !arch.image().executable(address)) throw LowlevelError("invalid code label");
    auto *scope = fd->getScopeLocal();
    const Address at(arch.getDefaultCodeSpace(), address);
    if (!scope->queryCodeLabel(at)) {
      if (++impl->symbols > 100000) throw LowlevelError("symbol limit exceeded");
      auto *label = scope->addCodeLabel(at, identifier(name, true));
      scope->setAttribute(label, Varnode::namelock | Varnode::typelock);
    }
  });
}
bool Session::set_cpp_parameters(uint64_t address, rust::Slice<const CppParameter> parameters, bool varargs) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  return checked([&] {
    impl->ready();
    auto &arch = impl->arch;
    auto *scope = arch.symboltab->getGlobalScope();
    const Address addr(arch.getDefaultCodeSpace(), address);
    auto *fd = scope->queryFunction(addr);
    if (!fd) fd = scope->queryExternalRefFunction(addr);
    if (!fd || parameters.size() > 32 || fd->getFuncProto().isInputLocked()) return false;
    PrototypePieces pieces;
    auto &proto = fd->getFuncProto();
    proto.getPieces(pieces);
    pieces.intypes.clear(); pieces.innames.clear();
    for (const auto &parameter : parameters) {
      if (parameter.value == ValueType::Void || parameter.pointee.size() > 256) return false;
      auto *type = parameter.pointee.empty() ? impl->valueType(parameter.value) : impl->pointerTo(impl->classType(parameter.pointee));
      pieces.intypes.push_back(type);
      pieces.innames.push_back("param_" + std::to_string(pieces.intypes.size()));
    }
    pieces.firstVarArgSlot = varargs ? int4(pieces.intypes.size()) : -1;
    const bool output_locked = proto.isOutputLocked();
    proto.setPieces(pieces);
    proto.setInputLock(true);
    proto.setOutputLock(output_locked);
    proto.setModelLock(true);
    impl->invalidateInferred();
    return true;
  });
}
bool Session::set_function_model(uint64_t address, rust::Str name) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  return checked([&] {
    impl->ready();
    auto &arch = impl->arch;
    auto *fd = arch.symboltab->getGlobalScope()->queryFunction(Address(arch.getDefaultCodeSpace(), address));
    auto *model = arch.getModel(std::string(name));
    if (!fd || !model) return false;
    auto &proto = fd->getFuncProto();
    if (proto.isInputLocked() || proto.isOutputLocked() || proto.isModelLocked()) return false;
    impl->invalidateInferred();
    proto.setModel(model);
    proto.setModelLock(true);
    impl->function_models[address] = model;
    return true;
  });
}
void Session::set_rust_function(uint64_t address) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    impl->ready();
    auto &arch = impl->arch;
    auto *fd = arch.symboltab->getGlobalScope()->queryFunction(Address(arch.getDefaultCodeSpace(), address));
    if (!fd) fd = arch.symboltab->getGlobalScope()->queryExternalRefFunction(Address(arch.getDefaultCodeSpace(), address));
    if (!fd) throw std::runtime_error("Rust convention requires a registered function");
    if (!impl->rust_fixups) {
      const auto load = [&](const unsigned char *data, size_t size) {
        std::istringstream stream(std::string(reinterpret_cast<const char *>(data), size));
        DocumentStorage store;
        XmlDecode decoder(&arch, store.parseDocument(stream)->getRoot());
        arch.pcodeinjectlib->decodeInject("Ghidra Rust extension", "", InjectPayload::CALLFIXUP_TYPE, decoder);
      };
      load(rust_probe_bytes, sizeof(rust_probe_bytes));
      const bool windows = impl->spec.pack == pack_x64_bytes || impl->spec.pack == pack_x86_bytes;
      if (windows && impl->ptr() == 8) load(rust_try_windows64_bytes, sizeof(rust_try_windows64_bytes));
      else if (windows) load(rust_try_windows32_bytes, sizeof(rust_try_windows32_bytes));
      else if (impl->ptr() == 8) load(rust_try_unix64_bytes, sizeof(rust_try_unix64_bytes));
      else load(rust_try_unix32_bytes, sizeof(rust_try_unix32_bytes));
      impl->rust_fixups = true;
    }
    // x86 Rust functions use caller stack cleanup, even in a PE whose default is stdcall.
    // Keep unknown arguments unlocked; a demangled path is not a prototype.
    if (impl->ptr() == 4 && !fd->getFuncProto().isModelLocked() &&
        !fd->getFuncProto().isInputLocked() && !fd->getFuncProto().isOutputLocked()) {
      if (auto *model = arch.getModel("__cdecl")) {
        auto &proto = fd->getFuncProto();
        proto.setModel(model);
        proto.setModelLock(true);
      }
    }
    impl->invalidateInferred();
  });
}
bool Session::add_rust_string(uint64_t address, uint32_t length, uint64_t descriptor) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  return checked([&] {
    impl->ready();
    auto &arch = impl->arch;
    auto &image = arch.image();
    const auto bytes = image.bytesAt(address);
    if (!length || length > kMaxStringChars || bytes.second < length || image.executable(address)) return false;
    // Ghidra's decoder looks ahead up to four bytes. Pad its input and check the consumed width
    // so an incomplete UTF-8 character at the section boundary cannot read past the allocation.
    std::vector<uint1> padded(bytes.first, bytes.first + length);
    padded.resize(length + 4, 0);
    for (uint32_t i = 0; i < length;) {
      int4 skip = 0;
      const int4 cp = StringManager::getCodepoint(padded.data() + i, 1, false, skip);
      if (cp <= 0 || skip <= 0 || uint32_t(skip) > length - i ||
          (cp < 32 && cp != '\n' && cp != '\r' && cp != '\t') || cp == 127 ||
          cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff) ||
          (skip == 2 && cp < 0x80) || (skip == 3 && cp < 0x800) || (skip == 4 && cp < 0x10000)) return false;
      i += uint32_t(skip);
    }
    auto *types = arch.types;
    if (descriptor) {
      const auto raw = image.bytesAt(descriptor);
      const int width = impl->ptr();
      if (raw.second < size_t(2 * width) || image.executable(descriptor)) return false;
      uint64_t pointer = 0, size = 0;
      for (int i = width - 1; i >= 0; --i) {
        pointer = (pointer << 8) | raw.first[i];
        size = (size << 8) | raw.first[width + i];
      }
      if (pointer != address || size != length) return false;
      // rust-common.gdt's Str, adapted to the image's pointer width. Do not assume a String/Vec
      // field order: those are Rust-layout aggregates and can change between compiler versions.
      auto *str = types->findByName("RustStr");
      if (!str) {
        auto *structure = types->getTypeStruct("RustStr");
        auto set_fields = access_set_struct_fields(SetStructFieldsTag());
        (types->*set_fields)({TypeField(0, 0, "data_ptr", impl->pointerTo(types->getTypeChar(1))),
          TypeField(1, width, "length", types->getBase(width, TYPE_UINT))}, {}, structure, 2 * width, width, 0);
        str = structure;
      }
      impl->label(descriptor, "str_" + hexAddress(descriptor), str);
    }
    const Address at(arch.getDefaultCodeSpace(), address);
    auto *manager = static_cast<SliceStringManager *>(arch.stringManager);
    manager->add(at, bytes.first, length);
    const std::string label = "s_" + labelFromText(std::string(reinterpret_cast<const char *>(bytes.first), length)) + "_" + hexAddress(address);
    impl->label(address, label, types->getTypeArray(int4(length), types->getTypeChar(1)));
    impl->invalidateInferred();
    return true;
  });
}
void Session::set_call_fixup(uint64_t address, rust::Str fixup) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    impl->ready();
    auto &arch = impl->arch;
    auto *fd = arch.symboltab->getGlobalScope()->queryFunction(Address(arch.getDefaultCodeSpace(), address));
    if (!fd) fd = arch.symboltab->getGlobalScope()->queryExternalRefFunction(Address(arch.getDefaultCodeSpace(), address));
    if (!fd) throw std::runtime_error("call fixup requires a registered function");
    if (fixup.size() > 64) throw std::runtime_error("call fixup name exceeds 64 bytes");
    const std::string name(fixup.data(), fixup.size());
    const int4 id = arch.pcodeinjectlib->getPayloadId(InjectPayload::CALLFIXUP_TYPE, name);
    if (id < 0) throw std::runtime_error("unknown call fixup: " + name);
    impl->invalidateInferred();
    fd->getFuncProto().setInjectId(id);
  });
}
void Session::set_go_target(rust::Str os, uint32_t minor, bool register_abi, uint64_t text_start, uint64_t text_end) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    impl->ready();
    impl->invalidateInferred();
    auto &arch = impl->arch;
    const Spec &spec = impl->spec;
    if (!spec.go_pack) throw std::runtime_error("not a Go language");
    if (os.size() != 1 || std::string("wld").find(*os.data()) == std::string::npos)
      throw std::runtime_error("Go operating system must be w, l or d");
    if (text_start >= text_end || text_end > spec.address_limit) throw std::runtime_error("invalid Go text range");
    impl->typesPack().go = GoTarget{*os.data(), minor};
    // Functions without a known signature get the model of their Go release: the register ABI from
    // Go 1.17 on amd64, the stack ABI before (and always on 386). Registered functions take it.
    impl->go_registers = register_abi && spec.wide;
    if (auto *model = arch.getModel(impl->go_registers ? "abi-internal" : "abi0")) arch.defaultfp = model;
    if (!impl->go_registers || !spec.go_context) return;
    // `GolangSymbolAnalyzer.setupProgramContext`: R14 holds the current goroutine throughout Go
    // code, so it is a constant pointing at a `runtime.g` (CURRENT_G); XMM15 is always zero.
    auto *space = arch.getDefaultCodeSpace();
    const Address start(space, text_start), end(space, text_end);
    TrackedSet inherited = arch.context->getTrackedSet(start);
    TrackedSet &tracked = arch.context->createSet(start, end);
    tracked = inherited;
    const auto track = [&](const char *name, uintb value) {
      TrackedContext entry;
      entry.loc = arch.translate->getRegister(name);
      entry.val = value;
      tracked.push_back(entry);
    };
    if (spec.sla == sla_arm64_bytes) {
      track("x28", spec.go_context);
    } else {
      track("R14", spec.go_context);
      track("XMM15_Qa", 0);
      track("XMM15_Qb", 0);
    }
    Datatype *g = nullptr;
    try {
      g = impl->typesPack().goType("runtime.g");
    } catch (const LowlevelError &) {
      g = nullptr;
    }
    if (!g) g = arch.types->getBase(1, TYPE_UNKNOWN);
    auto *scope = arch.symboltab->getGlobalScope();
    if (++impl->symbols > 100000) throw std::runtime_error("symbol limit exceeded");
    auto *entry = scope->addSymbol("CURRENT_G", g, Address(space, spec.go_context), Address());
    scope->setAttribute(entry->getSymbol(), Varnode::namelock | Varnode::typelock);
  });
}
bool Session::apply_go_prototype(uint64_t address, rust::Str name) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  return checked([&] {
    impl->ready();
    impl->invalidateInferred();
    auto &arch = impl->arch;
    const auto &go = impl->typesPack().go;
    if (!impl->spec.go_pack || !go.os) throw std::runtime_error("Go target not set");
    if (name.size() > 1024) throw std::runtime_error("Go function name exceeds 1024 bytes");
    auto *fd = arch.symboltab->getGlobalScope()->queryFunction(Address(arch.getDefaultCodeSpace(), address));
    if (!fd) throw std::runtime_error("Go prototype address is not a registered function");
    std::string value, payload;
    if (!go_pack(impl->spec).find("F:" + std::string(name), value) || !go_record(value, go, payload)) return false;
    try {
      return impl->applyGo(fd, payload);
    } catch (const LowlevelError &) {
      // A type the engine cannot rebuild (nesting too deep, say): no signature, as for an unknown name.
      return false;
    } catch (const DecoderError &) {
      return false;
    }
  });
}
bool Session::set_go_special(uint64_t address, rust::Str kind) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  return checked([&] {
    impl->ready();
    impl->invalidateInferred();
    auto &arch = impl->arch;
    auto *fd = arch.symboltab->getGlobalScope()->queryFunction(Address(arch.getDefaultCodeSpace(), address));
    if (!fd) throw std::runtime_error("Go special function is not registered");
    const std::string what(kind);
    auto &proto = fd->getFuncProto();
    if (what == "abi0") {
      // Assembly and `.abi0` functions use the stack ABI; their parameters stay inferred.
      if (auto *model = arch.getModel("abi0")) proto.setModel(model);
      return true;
    }
    if (what == "void") {
      // An assembly helper declared `$0-0` (runtime.morestack): no arguments and no results.
      PrototypePieces pieces;
      pieces.model = arch.getModel("abi0");
      if (!pieces.model) return false;
      pieces.firstVarArgSlot = -1;
      pieces.outtype = arch.types->getTypeVoid();
      proto.setPieces(pieces);
      return true;
    }
    if (what == "panic_ax_cx" || what == "panic_ax_cx_u" ||
        what == "panic_cx_dx" || what == "panic_cx_dx_u" ||
        what == "panic_dx_bx" || what == "panic_dx_bx_u") {
      if (!impl->spec.go_pack) return false;
      auto *model = arch.getModel("abi0");
      if (!model) return false;
      proto.setModel(model);
      ProtoStore *store = proto.*access_proto_store(ProtoStoreTag());
      store->clearAllInputs();
      ParameterPieces output;
      output.type = arch.types->getTypeVoid();
      output.flags = ParameterPieces::typelock;
      store->setOutput(output);
      const char *first = what.find("panic_ax_cx") == 0 ? "AX" :
                          what.find("panic_cx_dx") == 0 ? "CX" : "DX";
      const char *second = first[0] == 'A' ? "CX" : first[0] == 'C' ? "DX" : "BX";
      const char *registers[2] = {first, second};
      const char *names[2] = {"index", "bound"};
      for (int i = 0; i < 2; ++i) {
        ParameterPieces piece;
        piece.type = arch.types->getBase(impl->ptr(), i == 0 && what.back() == 'u' ? TYPE_UINT : TYPE_INT);
        piece.flags = ParameterPieces::typelock | ParameterPieces::namelock;
        piece.addr = arch.translate->getRegister(std::string(impl->spec.wide ? "R" : "E") + registers[i]).getAddr();
        store->setInput(i, names[i], piece);
      }
      proto.setInputLock(true);
      proto.setOutputLock(true);
      proto.setModelLock(true);
      proto.setNoReturn(true);
      return true;
    }
    if (!impl->spec.wide && what != "duffzero" && what != "duffcopy") return false;
    auto *pointer = arch.types->getTypePointer(impl->ptr(), arch.types->getTypeVoid(), 1);
    auto *uint = arch.types->getBase(8, TYPE_UINT);
    // `GolangSymbolAnalyzer.fixDuffFunctions` and `fixGcWriteBarrier*Functions`: runtime helpers
    // with their own conventions in x86-64-golang.cspec.
    PrototypePieces pieces;
    pieces.firstVarArgSlot = -1;
    pieces.outtype = arch.types->getTypeVoid();
    std::string model = what;
    if (what == "duffzero") {
      pieces.intypes = {pointer};
      pieces.innames = {"dest"};
      if (!impl->spec.wide) { pieces.intypes.push_back(arch.types->getBase(4, TYPE_UINT)); pieces.innames.push_back("value"); }
    } else if (what == "duffcopy") {
      pieces.intypes = {pointer, pointer};
      pieces.innames = {"dest", "src"};
    } else if (what == "spillargs") {
      // runtime.spillArgs on arm64: stores the argument registers through x20.
      pieces.intypes = {pointer};
      pieces.innames = {"area"};
    } else if (what == "gcwrite_batch") {
      pieces.outtype = pointer;
    } else if (what == "gcwrite_batch_numbytes") {
      model = "gcwrite_batch";
      pieces.outtype = pointer;
      pieces.intypes = {uint};
      pieces.innames = {"numbytes"};
    } else if (what == "gcwrite_buffered") {
      pieces.intypes = {pointer, pointer};
      pieces.innames = {"value", "dest"};
    } else if (what.compare(0, 17, "gcwrite_buffered:") == 0) {
      // runtime.gcWriteBarrierCX and the others: the value in that register, the destination in RDI.
      auto *buffered = arch.getModel("gcwrite_buffered");
      if (!buffered) return false;
      proto.setModel(buffered);
      ProtoStore *store = proto.*access_proto_store(ProtoStoreTag());
      store->clearAllInputs();
      ParameterPieces output;
      output.type = arch.types->getTypeVoid();
      output.flags = ParameterPieces::typelock;
      store->setOutput(output);
      const std::string registers[2] = {what.substr(17), "RDI"};
      const char *names[2] = {"value", "dest"};
      for (int i = 0; i < 2; ++i) {
        ParameterPieces piece;
        piece.type = pointer;
        piece.flags = ParameterPieces::typelock | ParameterPieces::namelock;
        piece.addr = arch.translate->getRegister(registers[i]).getAddr();
        store->setInput(i, names[i], piece);
      }
      proto.setInputLock(true);
      proto.setOutputLock(true);
      proto.setModelLock(true);
      return true;
    } else {
      throw std::runtime_error("unknown Go special function: " + what);
    }
    pieces.model = arch.getModel(model);
    if (!pieces.model) return false;
    proto.setPieces(pieces);
    if (what == "duffzero" || what == "duffcopy" || what == "spillargs") {
      proto.setInputLock(true);
      proto.setOutputLock(true);
      proto.setModelLock(true);
    }
    return true;
  });
}
rust::String Session::validate_go_pack(rust::Str os, uint32_t minor, uint32_t max_report) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  return checked([&] {
    impl->ready();
    auto &arch = impl->arch;
    if (!impl->spec.go_pack || os.size() != 1) throw std::runtime_error("not a Go language");
    impl->typesPack().go = GoTarget{*os.data(), minor};
    impl->go_registers = impl->spec.wide && minor >= 17;
    if (auto *model = arch.getModel(impl->go_registers ? "abi-internal" : "abi0")) arch.defaultfp = model;
    size_t functions = 0, types = 0, failures = 0, unallocated = 0;
    std::string report;
    auto fail = [&](const std::string &key, const std::string &what) {
      if (failures++ < max_report) report += "\n  " + key + ": " + what;
    };
    auto &pack = go_pack(impl->spec);
    for (const auto &key : pack.keys()) {
      std::string value, payload;
      // Definitions are reached through the N records that name them.
      if (key.compare(0, 2, "D:") == 0) continue;
      if (!pack.find(key, value) || !go_record(value, impl->typesPack().go, payload)) continue;
      try {
        if (key.compare(0, 2, "N:") == 0) {
          types++;
          if (!impl->typesPack().goType(key.substr(2))) fail(key, "not resolved");
        } else if (key.compare(0, 2, "F:") == 0) {
          functions++;
          if (impl->symbols + 1 > 99999) throw LowlevelError("validation symbol limit");
          const uint64_t target = impl->spec.external_base + impl->symbols * 16;
          auto *fd = impl->function(target, "validate_" + std::to_string(functions), false);
          if (!impl->applyGo(fd, payload)) unallocated++;
        }
      } catch (const LowlevelError &e) {
        fail(key, e.explain);
      } catch (const DecoderError &e) {
        fail(key, e.explain);
      }
    }
    return rust::String("functions=" + std::to_string(functions) + " types=" + std::to_string(types) +
                        " failures=" + std::to_string(failures) + " unallocated=" + std::to_string(unallocated) + report);
  });
}
NativeOutput Session::decompile(uint64_t address, uint32_t timeout_ms, uint32_t max_instructions, uint32_t max_work, uint32_t return_bytes, bool use_cdecl) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  return checked([&] {
    impl->ready();
    impl->inference_cache_invalidations = 0;
    impl->inference_cache_evictions = 0;
    impl->inference_invalidation_reasons.clear();
    if (!timeout_ms || timeout_ms > 60000 || !max_instructions || max_instructions > 100000 || !max_work || max_work > 200000000 || (return_bytes != 0 && return_bytes != 1 && return_bytes != 4 && return_bytes != 8))
      throw std::runtime_error("invalid decompilation limits");
    auto &arch = impl->arch;
    if (!arch.image().executable(address)) throw std::runtime_error("function is not in executable mapped memory");
    impl->dropRequestLocalInferences();
    auto *fd = arch.symboltab->getGlobalScope()->queryFunction(Address(arch.getDefaultCodeSpace(), address));
    // A function nobody registered is created for this request and removed when it ends. Left behind,
    // it would make every later request that mentions its address see a function there (a code
    // pointer named FUN_...), so output would depend on which functions were decompiled before.
    struct OnDemandFunction {
      Impl *owner;
      uint64_t address;
      bool created = false;
      ~OnDemandFunction() {
        if (!created) return;
        try {
          auto *scope = owner->arch.symboltab->getGlobalScope();
          if (auto *made = scope->queryFunction(Address(owner->arch.getDefaultCodeSpace(), address))) {
            scope->removeSymbol(made->getSymbol());
            --owner->symbols;
          }
          owner->function_models.erase(address);
          owner->go_stack_functions.erase(address);
          owner->invalidateInferred("function removed");
        } catch (...) {
          // Do not reuse a session whose request-local symbols could not be removed.
          owner->poisoned = true;
        }
      }
    } on_demand{&*impl, address};
    if (!fd) {
      std::ostringstream name;
      name << "FUN_" << std::hex;
      if (!impl->spec.wide) name << std::setw(8) << std::setfill('0');
      name << address;
      fd = impl->function(address, name.str(), false);
      on_demand.created = true;
      impl->invalidateInferred("function added");
    }
    // A prototype completed under a larger flow limit is not evidence that its
    // callee can be analyzed under this request's smaller instruction limit.
    if (impl->inference_max_instructions != max_instructions) {
      impl->invalidateInferred("instruction limit");
      impl->inference_max_instructions = max_instructions;
    }
    // Each phase gets the full budget: a heavy callee inference must not starve
    // or lose the selected function's own analysis.
    // The request as a whole may take at most twice one phase's budget.
    const auto overall = std::chrono::steady_clock::now() + std::chrono::milliseconds(uint64_t(timeout_ms) * 2);
    const auto fresh = [&] { return BudgetGuard(timeout_ms, max_work, overall); };
    const auto attempt = [&](bool truncate) -> NativeOutput {
    impl->analysis_passes = 0;
    impl->inference_cache_hits = 0;
    impl->inference_cache_misses = 0;
    using Clock = std::chrono::steady_clock;
    const auto elapsed = [](Clock::time_point start) {
      return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
    };
    auto phase = Clock::now();
    double initial_ms = 0, data_ms = 0, returns_ms = 0, inference_ms = 0;
    auto &proto = fd->getFuncProto();
    // Hints are request-local. Explicit or archive-backed locks always win.
    struct TemporaryPrototype {
      Impl &owner;
      FuncProto &proto;
      uint64_t target;
      ProtoModel *model;
      int4 extra;
      bool model_locked;
      bool return_applied = false;
      bool cdecl_applied = false;
      bool restored = false;
      void restore() {
        if (restored) return;
        restored = true;
        if (return_applied) {
          proto.setOutputLock(false);
          proto.clearUnlockedOutput();
        }
        if (cdecl_applied || return_applied) {
          proto.setModel(model);
          proto.setModelLock(model_locked);
          proto.setExtraPop(extra);
        }
        // Analysis can retain ABI state beyond the explicit prototype flags.
        // Reusing prior entries here narrows some Rust multi-register returns.
        if (return_applied || cdecl_applied)
          owner.invalidateTemporary(target, "restore temporary ABI");
      }
      ~TemporaryPrototype() { restore(); }
    } temporary{*impl, proto, address, arch.getModel(proto.getModelName()), proto.getExtraPop(), proto.isModelLocked()};
    try {
      if (use_cdecl && !impl->spec.wide && !proto.isModelLocked() &&
          !proto.isInputLocked() && !proto.isOutputLocked()) {
        if (auto *model = arch.getModel("__cdecl")) {
          impl->invalidateTemporary(address, "temporary calling convention");
          proto.setModel(model);
          proto.setModelLock(true);
          temporary.cdecl_applied = true;
        }
      }
      arch.max_instructions = max_instructions;
      if (truncate) arch.flowoptions &= ~FlowInfo::error_toomanyinstructions;
      else arch.flowoptions |= FlowInfo::error_toomanyinstructions;
      int4 result;
      std::string baseline_errors;
      {
        auto guard = fresh();
        impl->prepareRequestedWrapper(fd, max_instructions);
        result = impl->analyze(fd);
        baseline_errors = impl->errors.str();
      }
      // Name the data the first pass found, then analyze again so the names print.
      initial_ms = elapsed(phase);
      phase = Clock::now();
      // The symbols are not part of the supplied facts: they live for this request only.
      if (result >= 0 && impl->addDataSymbols(fd)) {
        try {
          auto guard = fresh();
          result = impl->analyze(fd);
          baseline_errors = impl->errors.str();
        } catch (const BudgetExceeded &) {
          impl->dropDataSymbols();
          impl->release(fd);
          auto guard = fresh();
          result = impl->analyze(fd);
          baseline_errors = impl->errors.str();
        }
      }
      data_ms = elapsed(phase);
      phase = Clock::now();
      Datatype *hinted_return = nullptr;
      const bool boolean_return = return_bytes == 1 && impl->spec.wide &&
          impl->spec.sla == sla_x64_bytes && impl->booleanByteReturns(fd);
      bool forwarded_return = false;
      const auto forwarder = impl->variadic_forwarders.find(address);
      if (result >= 0 && forwarder != impl->variadic_forwarders.end() && proto.isDotdotdot() &&
          !proto.isOutputLocked() && !proto.isNoReturn()) {
        auto *callee = arch.symboltab->getGlobalScope()->queryFunction(
            Address(arch.getDefaultCodeSpace(), forwarder->second));
        if (callee && callee != fd && !callee->getFuncProto().isNoReturn()) {
          // This wrapper's verified epilogue forwards RAX unchanged. Analyze the
          // callee independently, accepting only a finished, canonical RAX result.
          // Unknown callees inside it still leave the semantic type uncertain.
          try {
            auto guard = fresh();
            impl->touched.insert(callee);
            bool valid = impl->analyze(callee) >= 0 && impl->errors.str().empty();
            for (auto it = arch.commentdb->beginComment(callee->getAddress());
                 it != arch.commentdb->endComment(callee->getAddress()); ++it)
              if (((*it)->getType() & (Comment::warning | Comment::warningheader)) &&
                  inferenceGap((*it)->getText())) valid = false;
            const auto *output = callee->getFuncProto().getOutput();
            const auto &rax = arch.translate->getRegister("RAX");
            if (valid && output->getType()->getMetatype() != TYPE_VOID &&
                output->getAddress() == rax.getAddr() &&
                (output->getSize() == 4 || output->getSize() == 8)) {
              hinted_return = arch.types->getBase(output->getSize(), TYPE_UNKNOWN);
              forwarded_return = true;
            }
          } catch (const BudgetExceeded &) {
            // Optional inference must not discard the selected function's body.
          } catch (const LowlevelError &) {
          } catch (const DecoderError &) {
          }
          arch.clearAnalysis(callee);
          callee->getFuncProto().clearUnlockedInput();
          callee->getFuncProto().clearUnlockedOutput();
          impl->errors.str(baseline_errors);
        }
      }
      const bool undefined_high = result >= 0 && !impl->spec.wide && return_bytes != 8 &&
          !proto.isOutputLocked() && impl->undefinedHighReturns(fd);
      if (undefined_high) {
        hinted_return = arch.types->getBase(4, TYPE_UNKNOWN);
      } else if (boolean_return) {
        hinted_return = arch.types->getBase(1, TYPE_BOOL);
      } else if (return_bytes == 1 && !impl->spec.wide && fd->numCalls() == 1) {
        const auto *call = fd->getCallSpecs(0);
        if (call->isOutputLocked() && !call->isNoReturn() && call->getOutputType()->getSize() == 4 &&
            call->getOutputType()->getMetatype() != TYPE_VOID)
          hinted_return = call->getOutputType();
      } else if (!hinted_return && (return_bytes == 4 || return_bytes == 8)) {
        hinted_return = arch.types->getBase(return_bytes, TYPE_UNKNOWN);
      }
      if (result >= 0 && hinted_return && !proto.isNoReturn() && !proto.isOutputLocked() &&
          (forwarded_return || (!proto.isInputLocked() && (!proto.isModelLocked() || temporary.cdecl_applied || !impl->spec.wide))) &&
          (proto.getOutputType()->getMetatype() == TYPE_VOID || boolean_return ||
           (!impl->spec.wide && (return_bytes == 4 || undefined_high) && proto.getOutputType()->getSize() == 8))) {
        impl->invalidateTemporary(address, "temporary return hint");
        PrototypePieces pieces;
        proto.getPieces(pieces);
        pieces.outtype = hinted_return;
        proto.setPieces(pieces);
        proto.setInputLock(forwarded_return);
        proto.setModelLock(temporary.cdecl_applied || temporary.model_locked);
        temporary.return_applied = true;
        auto guard = fresh();
        result = impl->analyze(fd);
        baseline_errors = impl->errors.str();
      }
      returns_ms = elapsed(phase);
      phase = Clock::now();
      size_t inferred = 0;
      std::string skipped;
      bool reanalyzing = false;
      try {
        auto guard = fresh();
        inferred = impl->inferDirect(fd);
        reanalyzing = inferred != 0;
        if (inferred) result = impl->analyze(fd);
      } catch (const BudgetExceeded &e) {
        skipped = e.what();
      } catch (const LowlevelError &e) {
        skipped = e.explain;
      } catch (const DecoderError &e) {
        skipped = e.explain;
      }
      if (!skipped.empty()) {
        // Enrichment is optional: drop it. Callee analysis leaves the selected function's own
        // analysis as it was, so only a limit hit while redoing that one needs it done again.
        impl->releaseCallees(fd);
        inferred = 0;
        if (reanalyzing) {
          impl->release(fd);
          auto guard = fresh();
          result = impl->analyze(fd);
        } else {
          impl->errors.str(baseline_errors);
        }
      } else if (!inferred) {
        impl->errors.str(baseline_errors);
      }
      // Keep one representative for repeated optimization comments before both prints.
      inference_ms = elapsed(phase);
      phase = Clock::now();
      rust::Vec<rust::String> file_warnings;
      std::set<std::string> seen_comments;
      std::vector<Comment *> repeated_comments;
      bool known_noreturn_calls = false;
      for (auto it = arch.commentdb->beginComment(fd->getAddress()); it != arch.commentdb->endComment(fd->getAddress()); ++it) {
        const std::string text = (*it)->getText();
        if (impl->spec.go_pack && text == "WARNING: Subroutine does not return") {
          known_noreturn_calls = true;
          repeated_comments.push_back(*it);
          continue;
        }
        if (text.find("Some values do not have unique names") != std::string::npos) {
          file_warnings.push_back(text);
          repeated_comments.push_back(*it);
          continue;
        }
        std::string key = text.find("Removing unreachable block") != std::string::npos
          ? "Removing unreachable block" : text;
        if (!seen_comments.insert(key).second) repeated_comments.push_back(*it);
      }
      for (auto *comment : repeated_comments) arch.commentdb->deleteComment(comment);
      impl->nameArgumentLocals(fd);
      static_cast<StringPrintC *>(arch.print)->writable_literals = false;
      static_cast<StringPrintC *>(arch.print)->unknown_types = false;
      OutputBuffer buffer;
      NativeOutput response;
      response.initial_ms = initial_ms;
      response.data_ms = data_ms;
      response.returns_ms = returns_ms;
      response.inference_ms = inference_ms;
      response.analysis_passes = impl->analysis_passes;
      response.inference_cache_hits = impl->inference_cache_hits;
      response.inference_cache_misses = impl->inference_cache_misses;
      response.file_warnings = std::move(file_warnings);
      response.unknown_callees = false;
      if (known_noreturn_calls)
        response.notes.push_back("Known non-returning calls terminate their paths; repeated call-site comments are omitted.");
      bool inferred_varargs = false;
      for (const auto &entry : impl->callsite_prototypes)
        inferred_varargs |= (entry.first.first == address || entry.second.target == address)
            && !impl->supplied_prototypes.count(entry.second.target);
      if (inferred_varargs)
        response.warnings.push_back("Variadic argument count inferred from explicit call-site register and stack writes; semantic types remain uncertain.");
      if (impl->function_models.count(address) && proto.getModelName() == "__fastcall")
        response.warnings.push_back("The i686 register calling convention is inferred from reads before writes; parameter types remain uncertain.");
      bool inferred_go = impl->go_stack_functions.count(address);
      for (int4 i = 0; i < fd->numCalls(); ++i)
        inferred_go |= impl->go_stack_functions.count(fd->getCallSpecs(i)->getEntryAddress().getOffset()) != 0;
      if (inferred_go)
        response.warnings.push_back("Go ABI0 argument/result storage inferred from pclntab and stack accesses; semantic types remain uncertain.");
      if (temporary.return_applied)
        response.warnings.push_back(forwarded_return
            ? "Return storage inferred from the forwarded callee; its semantic type is uncertain."
            : undefined_high
                ? "An undefined local stack value in EDX was excluded from the inferred return; its semantic type is uncertain."
                : "Return storage inferred from a caller or complete leaf; its type and width are uncertain.");
      if (temporary.cdecl_applied)
        response.warnings.push_back("The x86 cdecl calling convention was inferred from recursive caller stack cleanup.");
      {
        BudgetGuard guard(timeout_ms, impl->print_work_limit ? impl->print_work_limit : max_work, overall);
        binfera_check();
        PrinterReset reset{arch.print, &impl->errors};
        std::ostream output(&buffer);
        output.exceptions(std::ios::badbit | std::ios::failbit);
        arch.print->setOutputStream(&output);
        arch.print->setMarkup(false);
        try {
          arch.print->docFunction(fd);
        } catch (const LowlevelError &e) {
          // The engine's own notes (flow errors, unrecovered jump tables) say why.
          arch.print->setOutputStream(&impl->errors);
          std::string notes = "analysis status " + std::to_string(result) + " " + impl->errors.str();
          for (auto it = arch.commentdb->beginComment(fd->getAddress()); it != arch.commentdb->endComment(fd->getAddress()); ++it)
            if ((*it)->getType() & (Comment::warning | Comment::warningheader)) notes += " " + (*it)->getText();
          if (notes.size() > 400) notes.resize(400);
          throw std::runtime_error(notes.empty() ? e.explain : e.explain + " (" + notes + ")");
        }
        reset.finished = true;
        arch.print->setOutputStream(&impl->errors);
      }
      response.text = buffer.str();
      // A second, marked-up print, kept only to map output lines back to instruction addresses.
      // Best effort: a failure here must never affect the plain text above.
      {
        PrinterReset reset{arch.print, &impl->errors};
        OutputBuffer marked;
        std::ostream markedOut(&marked);
        try {
          arch.print->setOutputStream(&markedOut);
          arch.print->setMarkup(true);
          arch.print->setPackedOutput(false);
          arch.print->docFunction(fd);
          std::vector<std::pair<uint32_t, uint64_t>> ops;
          for (auto it = fd->beginOpAll(); it != fd->endOpAll(); ++it)
            ops.emplace_back(it->second->getTime(), it->second->getAddr().getOffset());
          // Bytes, not a string: identifiers in the markup need not be valid UTF-8.
          for (char ch : marked.str()) response.markup.push_back(static_cast<uint8_t>(ch));
          for (const auto &op : ops) {
            response.op_times.push_back(op.first);
            response.op_addrs.push_back(op.second);
          }
        } catch (const BudgetExceeded &) {
          throw;
        } catch (...) {
          // Leave the mapping out; the plain text is unaffected.
          arch.print->clear();
        }
        reset.finished = true;
        arch.print->setMarkup(false);
        arch.print->setOutputStream(&impl->errors);
      }
      for (auto it = arch.commentdb->beginComment(fd->getAddress()); it != arch.commentdb->endComment(fd->getAddress()); ++it)
        if ((*it)->getType() & (Comment::warning | Comment::warningheader)) response.warnings.push_back((*it)->getText());
      response.print_ms = elapsed(phase);
      std::istringstream diagnostics(impl->errors.str());
      for (std::string line; std::getline(diagnostics, line); ) {
        if (line.empty()) continue;
        if (line.find("Some values do not have unique names") != std::string::npos)
          response.file_warnings.push_back(line);
        else response.warnings.push_back(line);
      }
      size_t unknown_calls = 0;
      std::ostringstream uncertain;
      for (int4 index = 0; index < fd->numCalls(); ++index) {
        const auto *call = fd->getCallSpecs(index);
        if (call->isInputLocked() && call->isOutputLocked()) continue;
        if (++unknown_calls > 8) continue;
        if (unknown_calls > 1) uncertain << "; ";
        uncertain << "0x" << std::hex << call->getOp()->getAddr().getOffset() << " -> ";
        if (!call->getName().empty()) uncertain << call->getName();
        else if (!call->getEntryAddress().isInvalid()) uncertain << "0x" << call->getEntryAddress().getOffset();
        else uncertain << "indirect call";
        uncertain << " (";
        if (!call->isInputLocked()) uncertain << "arguments";
        if (!call->isInputLocked() && !call->isOutputLocked()) uncertain << ", ";
        if (!call->isOutputLocked()) uncertain << "return";
        uncertain << ")";
      }
      if (unknown_calls) {
        response.unknown_callees = true;
        std::string warning = "Unknown callee prototype: forwarded arguments or return types may be missing. Supply signatures for reliable call reconstruction. Uncertain calls (" +
          std::to_string(unknown_calls) + "): " + uncertain.str();
        if (unknown_calls > 8) warning += "; " + std::to_string(unknown_calls - 8) + " more calls";
        response.warnings.push_back(warning);
      }
      if (!skipped.empty())
        response.warnings.push_back("Callee prototype inference skipped (" + skipped + "); callee prototypes remain unknown.");
      // An applied call fixup is a modeled effect, not a gap in the analysis: it is a note. So is
      // the engine's remark that an archive enum (`__rlimit_resource`) has aliased values, which
      // it repeats on every function once the type is loaded.
      rust::Vec<rust::String> gaps;
      for (auto &warning : response.warnings) {
        const std::string text(warning);
        if (!informationalWarning(text))
          gaps.push_back(std::move(warning));
        else
          response.notes.push_back(std::move(warning));
      }
      if (static_cast<StringPrintC *>(arch.print)->writable_literals)
        response.notes.push_back("String literals in writable data show their initial file bytes; their contents can change at runtime.");
      if (static_cast<StringPrintC *>(arch.print)->unknown_types)
        response.notes.push_back("Untyped storage is displayed with unsigned C types of the same width; signedness remains unknown.");
      response.warnings = std::move(gaps);
      response.incomplete = result < 0 || !response.warnings.empty();
      if (inferred) response.notes.push_back("Direct callee prototypes inferred from bounded native analysis; validate against machine code.");
      // The type the analysis settled on for each data symbol, so a consumer that declares the
      // symbols (the self-contained unit) need not guess it from the text: the first typed
      // varnode at the symbol's address, in location order.
      for (auto *symbol : impl->data_symbols) {
        const SymbolEntry *entry = symbol->getFirstWholeMap();
        if (!entry) throw std::runtime_error("data symbol " + symbol->getName() + " has no mapping");
        const Address at = entry->getAddr();
        const Datatype *type = nullptr;
        for (auto it = fd->beginLoc(at); it != fd->endLoc() && (*it)->getAddr() == at; ++it) {
          const Varnode *vn = *it;
          if (vn->isFree() || vn->isAnnotation() || !vn->getType()) continue;
          if (vn->getType()->getMetatype() != TYPE_UNKNOWN) {
            type = vn->getType();
            break;
          }
        }
        NativeGlobal global;
        global.name = symbol->getName();
        global.address = at.getOffset();
        global.size = uint32_t(type ? type->getSize() : entry->getSize());
        switch (type ? type->getMetatype() : TYPE_UNKNOWN) {
        case TYPE_FLOAT: global.kind = "float"; break;
        case TYPE_INT: global.kind = "signed"; break;
        case TYPE_UINT: global.kind = "unsigned"; break;
        case TYPE_BOOL: global.kind = "bool"; break;
        case TYPE_PTR: global.kind = "pointer"; break;
        default: global.kind = "unknown"; break;
        }
        response.globals.push_back(std::move(global));
      }
      // Best effort, like the marked-up print: the pseudocode does not depend on it.
      try {
        if (auto *stack = arch.getStackSpace()) collectStackFrame(fd, stack, response.frame);
      } catch (const BudgetExceeded &) {
        throw;
      } catch (...) {
        response.frame.clear();
      }
      impl->release(fd);
      impl->dropDataSymbols();
      temporary.restore();
      response.inference_cache_invalidations = impl->inference_cache_invalidations;
      response.inference_cache_evictions = impl->inference_cache_evictions;
      for (const auto &entry : impl->inference_invalidation_reasons)
        response.inference_invalidation_reasons.push_back(entry.first + ": " + std::to_string(entry.second));
      return response;
    } catch (const BudgetExceeded &) {
      arch.print->setOutputStream(&impl->errors);
      impl->release(fd);
      impl->dropDataSymbols();
      throw;
    } catch (...) {
      arch.print->setOutputStream(&impl->errors);
      impl->poisoned = true;
      throw;
    }
    };
    // A function whose flow runs past the instruction limit (the entry stub of a packed file
    // walking into its payload) is still worth showing: Ghidra truncates the flow with a warning.
    try {
      return attempt(false);
    } catch (const LowlevelError &e) {
      if (e.explain.find("maximum allowable instructions") == std::string::npos) throw;
      impl->poisoned = false;
      impl->release(fd);
      impl->dropDataSymbols();
      NativeOutput truncated;
      try {
        truncated = attempt(true);
      } catch (const LowlevelError &retry) {
        // When the limit cuts the flow before the first instruction that emits p-code (leading
        // nops), the engine places its artificial halt ahead of any block-start mark and rejects
        // the flow. That is the same limit, so report it as such, not as an engine fault.
        if (retry.explain.find("First op not marked as entry point") == std::string::npos) throw;
        impl->poisoned = false;
        impl->release(fd);
        impl->dropDataSymbols();
        throw std::runtime_error("Flow exceeded the maximum allowable instructions (" +
                                 std::to_string(max_instructions) +
                                 ") before the function produced any p-code; raise the instruction limit");
      }
      truncated.incomplete = true;
      truncated.warnings.push_back("Instruction limit reached: some flow is truncated.");
      return truncated;
    }
  });
}

// Emulation. Every call holds the engine mutex like the decompiler's; a run is bounded by its
// step count and deadline.
namespace {
EmuState &emulation(std::unique_ptr<Session::Impl> &impl) {
  if (!impl->emu) throw std::runtime_error("emulation was not started; call emu_reset first");
  return *impl->emu;
}
}
void Session::emu_reset() {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    impl->ready();
    impl->emu.reset();
    const auto *trans = static_cast<const ImageSleigh *>(impl->arch.translate);
    impl->emu.reset(new EmuState(*trans, impl->arch.image()));
  });
}
void Session::emu_map(uint64_t address, uint64_t size) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    auto &emu = emulation(impl);
    if (emu.ram.regions.size() >= 4096) throw std::runtime_error("emulation region count limit exceeded");
    if (!size || size > (uint64_t(1) << 30) || address > UINT64_MAX - size || address + size > impl->spec.address_limit)
      throw std::runtime_error("invalid emulation region");
    uint64_t total = size;
    for (const auto &r : emu.ram.regions) {
      if (address < r.second && r.first < address + size) throw std::runtime_error("overlapping emulation region");
      total += r.second - r.first;
    }
    if (total > (uint64_t(1) << 31)) throw std::runtime_error("emulation region limit exceeded (2 GiB)");
    for (const auto &s : impl->arch.image().sections)
      if (address < s.address + s.bytes.size() && s.address < address + size)
        throw std::runtime_error("emulation region overlaps the image");
    emu.ram.regions.push_back({address, address + size});
  });
}
bool Session::emu_mapped(uint64_t address, uint64_t size) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  return checked([&] { return emulation(impl).ram.mapped(address, size); });
}
void Session::emu_write(uint64_t address, rust::Slice<const uint8_t> bytes, bool record) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    auto &emu = emulation(impl);
    if (bytes.size() > (size_t(1) << 28)) throw std::runtime_error("emulation write too large");
    if (!emu.ram.mapped(address, bytes.size())) throw std::runtime_error("emulation write to unmapped memory");
    if (bytes.empty()) return;
    emu.ram.setChunk(address, int4(bytes.size()), bytes.data());
    if (record) emu.ram.noteWrite(address, bytes.size());
    else emu.ram.noteCodeWrite(address, bytes.size());
  });
}
rust::Vec<uint8_t> Session::emu_read(uint64_t address, uint32_t size) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  return checked([&] {
    auto &emu = emulation(impl);
    if (size > (uint32_t(1) << 26)) throw std::runtime_error("emulation read too large");
    rust::Vec<uint8_t> out;
    if (!size || !emu.ram.mapped(address, size)) return out;
    std::vector<uint8_t> bytes(size);
    emu.ram.getChunk(address, int4(size), bytes.data());
    out.reserve(size);
    for (auto b : bytes) out.push_back(b);
    return out;
  });
}
void Session::emu_set_register(rust::Str name, uint64_t value) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    auto &emu = emulation(impl);
    const VarnodeData &reg = impl->arch.translate->getRegister(std::string(name));
    if (reg.size > 8) throw std::runtime_error("register wider than 64 bits: " + std::string(name));
    if (reg.size < 8 && (value >> (reg.size * 8)) != 0)
      throw std::runtime_error("value does not fit in register: " + std::string(name));
    emu.state.setValue(reg.space, reg.offset, reg.size, value);
  });
}
uint64_t Session::emu_get_register(rust::Str name) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  return checked([&] {
    auto &emu = emulation(impl);
    const VarnodeData &reg = impl->arch.translate->getRegister(std::string(name));
    if (reg.size > 8) throw std::runtime_error("register wider than 64 bits: " + std::string(name));
    return uint64_t(emu.state.getValue(reg.space, reg.offset, reg.size));
  });
}
rust::Vec<binfera::CodeRange> Session::emu_writes() {
  std::lock_guard<std::mutex> lock(engine_mutex);
  return checked([&] {
    rust::Vec<binfera::CodeRange> out;
    for (const auto &w : emulation(impl).ram.writes) out.push_back({w.first, w.second});
    return out;
  });
}
void Session::emu_clear_writes() {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] { emulation(impl).ram.writes.clear(); });
}
binfera::EmuStop Session::emu_run(uint64_t pc, uint64_t max_steps, uint32_t timeout_ms, rust::Slice<const uint64_t> stops) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  return checked([&] {
    auto &emu = emulation(impl);
    if (!max_steps || max_steps > 10000000 || !timeout_ms || timeout_ms > 60000 || stops.size() > 4096)
      throw std::runtime_error("invalid emulation run limits");
    const auto *trans = static_cast<const ImageSleigh *>(impl->arch.translate);
    const auto &image = impl->arch.image();
    std::set<uint64_t> breakpoints(stops.begin(), stops.end());
    struct Raw {
      const ImageSleigh *t;
      explicit Raw(const ImageSleigh *s) : t(s) { t->raw = true; }
      ~Raw() { t->raw = false; }
    } raw(trans);
    auto &machine = emu.machine;
    machine.jump(pc);
    const uint64_t start_steps = machine.steps;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    machine.deadline = deadline;
    binfera::EmuStop stop;
    auto finish = [&](const char *kind, std::string detail) {
      stop.kind = kind;
      stop.address = machine.address();
      stop.steps = machine.steps - start_steps;
      stop.detail = std::move(detail);
      for (const auto &name : machine.approximated) stop.approximated.push_back(name);
      return stop;
    };
    bool first = true;
    for (;;) {
      const uint64_t at = machine.address();
      if (!first && breakpoints.count(at)) return finish("breakpoint", "");
      first = false;
      if (machine.steps - start_steps >= max_steps) return finish("step_limit", "");
      if (((machine.steps - start_steps) & 1023) == 0 && std::chrono::steady_clock::now() >= deadline)
        return finish("timeout", "");
      if (!image.executable(at)) return finish("fetch", emu.ram.mapped(at, 1) ? "non-executable memory" : "unmapped memory");
      try {
        machine.step();
      } catch (const EmuLimit &limit) {
        machine.jump(at);
        return finish(limit.kind, "");
      } catch (const EmuFault &fault) {
        char text[96];
        std::snprintf(text, sizeof(text), "%s 0x%llx", fault.write ? "write to unmapped" : "read from unmapped",
                      static_cast<unsigned long long>(fault.address));
        machine.jump(at);
        return finish(fault.write ? "write_fault" : "read_fault", text);
      } catch (const EmuTrap &trap) {
        machine.jump(at);
        return finish("trap", trap.name);
      } catch (const BadDataError &e) {
        machine.jump(at);
        return finish("decode_error", e.explain);
      } catch (const UnimplError &e) {
        machine.jump(at);
        return finish("decode_error", e.explain);
      } catch (const LowlevelError &e) {
        machine.jump(at);
        return finish("unsupported", e.explain);
      }
    }
  });
}
}
