// Concrete p-code emulation over the session's image (included by bridge.cc inside its anonymous
// namespace). SLEIGH translates each instruction exactly (ImageSleigh::raw), and the emulator
// executes the p-code against a private copy-on-write memory. Nothing runs on the host CPU.
//
// The stock EmulateMemory evaluates values of at most eight bytes. x86-64 code routinely uses
// sixteen-byte temporaries (`mul`, `div`, SSE moves and logic), so wide values are handled here:
// byte-wise operations at any size, and integer arithmetic up to sixteen bytes in a portable
// 128-bit type (MSVC has no __int128).

/// An access to memory that is neither in the image nor mapped by the caller.
struct EmuFault {
  uint64_t address;
  bool write;
};
/// A user-defined operation that hands control to an operating system (syscall, software interrupt).
struct EmuLimit {
  const char *kind;
};

struct EmuTrap {
  std::string name;
};

struct U128 {
  uint64_t lo = 0, hi = 0;
  static U128 of(const std::vector<uint8_t> &bytes) {
    U128 v;
    for (size_t i = 0; i < bytes.size() && i < 16; ++i) {
      if (i < 8) v.lo |= uint64_t(bytes[i]) << (8 * i);
      else v.hi |= uint64_t(bytes[i]) << (8 * (i - 8));
    }
    return v;
  }
  std::vector<uint8_t> bytes(size_t size) const {
    std::vector<uint8_t> out(size, 0);
    for (size_t i = 0; i < size && i < 16; ++i)
      out[i] = uint8_t(i < 8 ? lo >> (8 * i) : hi >> (8 * (i - 8)));
    return out;
  }
  /// Sign-extend from \p size bytes to 128 bits.
  U128 sext(size_t size) const {
    if (size >= 16) return *this;
    const unsigned bit = unsigned(size * 8 - 1);
    const bool negative = bit < 64 ? (lo >> bit) & 1 : (hi >> (bit - 64)) & 1;
    U128 v = mask(size);
    if (!negative) return v;
    if (size < 8) { v.lo |= ~uint64_t(0) << (size * 8); v.hi = ~uint64_t(0); }
    else if (size == 8) v.hi = ~uint64_t(0);
    else v.hi |= ~uint64_t(0) << ((size - 8) * 8);
    return v;
  }
  U128 mask(size_t size) const {
    U128 v = *this;
    if (size >= 16) return v;
    if (size >= 8) { if (size > 8) v.hi &= (uint64_t(1) << ((size - 8) * 8)) - 1; else v.hi = 0; }
    else { v.hi = 0; v.lo &= (uint64_t(1) << (size * 8)) - 1; }
    return v;
  }
  bool zero() const { return !lo && !hi; }
  bool negative() const { return hi >> 63; }
  friend bool operator==(U128 a, U128 b) { return a.lo == b.lo && a.hi == b.hi; }
  friend bool operator<(U128 a, U128 b) { return a.hi != b.hi ? a.hi < b.hi : a.lo < b.lo; }
  friend U128 operator+(U128 a, U128 b) { U128 r; r.lo = a.lo + b.lo; r.hi = a.hi + b.hi + (r.lo < a.lo); return r; }
  friend U128 operator~(U128 a) { a.lo = ~a.lo; a.hi = ~a.hi; return a; }
  friend U128 operator|(U128 a, U128 b) { a.lo |= b.lo; a.hi |= b.hi; return a; }
  friend U128 operator-(U128 a, U128 b) { U128 one; one.lo = 1; return a + (~b + one); }
  U128 shl(unsigned n) const {
    if (n >= 128) return U128();
    if (n == 0) return *this;
    U128 r;
    if (n >= 64) { r.hi = lo << (n - 64); return r; }
    r.hi = (hi << n) | (lo >> (64 - n));
    r.lo = lo << n;
    return r;
  }
  U128 shr(unsigned n) const {
    if (n >= 128) return U128();
    if (n == 0) return *this;
    U128 r;
    if (n >= 64) { r.lo = hi >> (n - 64); return r; }
    r.lo = (lo >> n) | (hi << (64 - n));
    r.hi = hi >> n;
    return r;
  }
  static uint64_t mulhi64(uint64_t a, uint64_t b) {
    const uint64_t a0 = a & 0xffffffff, a1 = a >> 32, b0 = b & 0xffffffff, b1 = b >> 32;
    const uint64_t p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;
    const uint64_t middle = (p00 >> 32) + (p01 & 0xffffffff) + (p10 & 0xffffffff);
    return p11 + (p01 >> 32) + (p10 >> 32) + (middle >> 32);
  }
  friend U128 operator*(U128 a, U128 b) {
    U128 r;
    r.lo = a.lo * b.lo;
    r.hi = mulhi64(a.lo, b.lo) + a.lo * b.hi + a.hi * b.lo;
    return r;
  }
  /// Unsigned division; the caller rejects a zero divisor.
  static void divmod(U128 n, U128 d, U128 &q, U128 &r) {
    q = U128(); r = U128();
    for (int i = 127; i >= 0; --i) {
      r = r.shl(1);
      if (i >= 64 ? (n.hi >> (i - 64)) & 1 : (n.lo >> i) & 1) r.lo |= 1;
      if (!(r < d)) {
        r = r - d;
        if (i >= 64) q.hi |= uint64_t(1) << (i - 64); else q.lo |= uint64_t(1) << i;
      }
    }
  }
};

/// The emulated address space: the image's bytes, copied into a page on first write, plus the
/// regions the caller maps (stack, buffers, heap). Mapping is checked per access by the emulator,
/// not here, because the bank reads and writes whole aligned words around narrower accesses.
class EmuRam : public MemoryBank {
  const Image &image;
  mutable std::map<uint64_t, std::vector<uint8_t>> pages;
  void fill(uint64_t base, uint8_t *out) const {
    std::fill(out, out + getPageSize(), 0);
    for (int4 i = 0; i < getPageSize();) {
      const auto bytes = image.bytesAt(base + uint64_t(i));
      if (!bytes.first) { ++i; continue; }
      const size_t n = std::min<size_t>(bytes.second, size_t(getPageSize() - i));
      std::copy_n(bytes.first, n, out + i);
      i += int4(n);
    }
  }
  std::vector<uint8_t> &page(uint64_t base) {
    auto found = pages.find(base);
    if (found != pages.end()) return found->second;
    if (pages.size() >= max_pages) throw EmuLimit{"work_limit"};
    auto &bytes = pages[base];
    bytes.resize(size_t(getPageSize()));
    fill(base, bytes.data());
    return bytes;
  }
public:
  std::vector<std::pair<uint64_t, uint64_t>> regions; ///< Caller-mapped [start, end).
  std::map<uint64_t, uint64_t> modified_code;
  std::map<uint64_t, uint64_t> writes;               ///< Merged written ranges [start, end).
  size_t max_pages = 64 * 1024;                       ///< 256 MiB of 4 KiB pages.
  EmuRam(AddrSpace *space, const Image &img) : MemoryBank(space, 8, 4096), image(img) {}
  bool mapped(uint64_t address, uint64_t size) const {
    if (size > UINT64_MAX - address) return false;
    while (size) {
      const auto bytes = image.bytesAt(address);
      uint64_t run = bytes.second;
      if (!bytes.first) {
        run = 0;
        for (const auto &r : regions)
          if (address >= r.first && address < r.second) { run = r.second - address; break; }
      }
      if (!run) return false;
      if (run >= size) return true;
      size -= run;
      address += run;
    }
    return true;
  }
  /// Insert [start, end) into disjoint sorted ranges, merging anything it touches.
  static void mergeRange(std::map<uint64_t, uint64_t> &ranges, uint64_t start, uint64_t end, const char *limit) {
    auto it = ranges.upper_bound(start);
    if (it != ranges.begin()) {
      auto prev = std::prev(it);
      if (prev->second >= start) { start = prev->first; end = std::max(end, prev->second); it = ranges.erase(prev); }
    }
    while (it != ranges.end() && it->first <= end) { end = std::max(end, it->second); it = ranges.erase(it); }
    if (ranges.size() >= 8192) throw LowlevelError(limit);
    ranges[start] = end;
  }
  void noteCodeWrite(uint64_t start, uint64_t end) {
    for (const auto &section : image.sections) {
      if (!section.executable || start >= section.address + section.bytes.size() || section.address >= end) continue;
      mergeRange(modified_code, start, end, "modified code range limit exceeded (8192)");
      return;
    }
  }
  bool codeModified(uint64_t start, uint64_t end) const {
    auto it = modified_code.lower_bound(end);
    return it != modified_code.begin() && std::prev(it)->second > start;
  }
  void noteWrite(uint64_t start, uint64_t size) {
    if (!size) return;
    const uint64_t end = start + size < start ? UINT64_MAX : start + size;
    noteCodeWrite(start, end);
    mergeRange(writes, start, end, "emulated write range limit exceeded (8192)");
  }
protected:
  void insert(uintb addr, uintb val) override {
    const uint64_t base = addr & ~uint64_t(getPageSize() - 1);
    deconstructValue(page(base).data() + (addr - base), val, getWordSize(), getSpace()->isBigEndian());
  }
  uintb find(uintb addr) const override {
    uint8_t word[8];
    getPage(addr & ~uint64_t(getPageSize() - 1), word, int4(addr & uint64_t(getPageSize() - 1)), getWordSize());
    return constructValue(word, getWordSize(), getSpace()->isBigEndian());
  }
  void getPage(uintb addr, uint1 *res, int4 skip, int4 size) const override {
    auto found = pages.find(addr);
    if (found != pages.end()) { std::copy_n(found->second.data() + skip, size, res); return; }
    std::vector<uint8_t> scratch(static_cast<size_t>(getPageSize()));
    fill(addr, scratch.data());
    std::copy_n(scratch.data() + skip, size, res);
  }
  void setPage(uintb addr, const uint1 *val, int4 skip, int4 size) override {
    std::copy_n(val, size, page(addr).data() + skip);
  }
};

class BinferaEmulator : public EmulateMemory {
  struct Insn {
    std::vector<PcodeOpRaw *> ops;
    std::vector<VarnodeData *> vars;
    int4 length = 0;
    ~Insn() { for (auto *op : ops) delete op; for (auto *v : vars) delete v; }
  };
  const ImageSleigh &trans;
  EmuRam &ram;
  AddrSpace *code;
  std::vector<OpBehavior *> behaviors;
  std::vector<std::string> userops;
  std::map<uint64_t, std::unique_ptr<Insn>> cache;
  Address pc;
  size_t op_index = 0;
  bool flowed = false;

  Insn &translate(uint64_t address) {
    auto found = cache.find(address);
    if (found != cache.end()) return *found->second;
    std::unique_ptr<Insn> insn(new Insn);
    PcodeEmitCache emit(insn->ops, insn->vars, behaviors, 0);
    insn->length = trans.oneInstruction(emit, Address(code, address));
    if (cache.size() > 200000) cache.clear();
    return *(cache[address] = std::move(insn));
  }
  bool inRam(const AddrSpace *space) const { return space == ram.getSpace(); }
  void checkAccess(uint64_t address, uint64_t size, bool write) const {
    if (!ram.mapped(address, size)) throw EmuFault{address, write};
  }
  /// The value of \p vn as LSB-first bytes.
  std::vector<uint8_t> getWide(const VarnodeData *vn) {
    std::vector<uint8_t> out(size_t(vn->size), 0);
    if (vn->space->getType() == IPTR_CONSTANT) {
      for (size_t i = 0; i < out.size() && i < 8; ++i) out[i] = uint8_t(vn->offset >> (8 * i));
      return out;
    }
    if (inRam(vn->space)) checkAccess(vn->offset, vn->size, false);
    memstate->getChunk(out.data(), vn->space, vn->offset, vn->size);
    if (vn->space->isBigEndian()) std::reverse(out.begin(), out.end());
    return out;
  }
  void putBytes(AddrSpace *space, uint64_t offset, std::vector<uint8_t> bytes) {
    if (space->isBigEndian()) std::reverse(bytes.begin(), bytes.end());
    if (inRam(space)) { checkAccess(offset, bytes.size(), true); ram.noteWrite(offset, bytes.size()); }
    memstate->setChunk(bytes.data(), space, offset, int4(bytes.size()));
  }
  void setWide(const VarnodeData *vn, std::vector<uint8_t> bytes) {
    bytes.resize(size_t(vn->size), 0);
    putBytes(vn->space, vn->offset, std::move(bytes));
  }
  uintb get(const VarnodeData *vn) {
    if (inRam(vn->space)) checkAccess(vn->offset, vn->size, false);
    return memstate->getValue(vn->space, vn->offset, vn->size);
  }
  void set(const VarnodeData *vn, uintb value) {
    if (inRam(vn->space)) { checkAccess(vn->offset, vn->size, true); ram.noteWrite(vn->offset, vn->size); }
    memstate->setValue(vn->space, vn->offset, vn->size, value);
  }
  [[noreturn]] void unsupported(const char *what) const {
    char text[160];
    std::snprintf(text, sizeof(text), "%s %s on %d-byte values is not emulated", what,
                  get_opname(currentBehave->getOpcode()), int(currentOp->getOutput() ? currentOp->getOutput()->size : 0));
    throw LowlevelError(text);
  }
  int4 widest() const {
    int4 size = currentOp->getOutput() ? int4(currentOp->getOutput()->size) : 0;
    for (int4 i = 0; i < currentOp->numInput(); ++i) size = std::max(size, int4(currentOp->getInput(i)->size));
    return size;
  }
  std::vector<uint8_t> bool_bytes(bool value) const {
    std::vector<uint8_t> out(size_t(currentOp->getOutput()->size), 0);
    out[0] = value;
    return out;
  }

protected:
  void executeUnary() override {
    if (widest() <= 8) {
      const auto *in = currentOp->getInput(0);
      const auto *out = currentOp->getOutput();
      set(out, currentBehave->evaluateUnary(out->size, in->size, get(in)));
      return;
    }
    const auto *in = currentOp->getInput(0);
    const auto *out = currentOp->getOutput();
    auto a = getWide(in);
    switch (currentBehave->getOpcode()) {
    case CPUI_COPY: case CPUI_INT_ZEXT: setWide(out, a); return;
    case CPUI_INT_SEXT: {
      const uint8_t fill = (a.back() & 0x80) ? 0xff : 0;
      a.resize(size_t(out->size), fill);
      setWide(out, a);
      return;
    }
    case CPUI_INT_NEGATE: for (auto &b : a) b = uint8_t(~b); setWide(out, a); return;
    case CPUI_BOOL_NEGATE: setWide(out, bool_bytes(!a[0])); return;
    case CPUI_INT_2COMP:
      if (out->size <= 16) { setWide(out, (U128() - U128::of(a)).bytes(size_t(out->size))); return; }
      break;
    case CPUI_POPCOUNT: {
      uint64_t count = 0;
      for (auto b : a) for (; b; b &= uint8_t(b - 1)) ++count;
      std::vector<uint8_t> r(size_t(out->size), 0);
      for (size_t i = 0; i < r.size() && i < 8; ++i) r[i] = uint8_t(count >> (8 * i));
      setWide(out, r);
      return;
    }
    default: break;
    }
    unsupported("unary");
  }
  void executeBinary() override {
    const auto *in0 = currentOp->getInput(0);
    const auto *in1 = currentOp->getInput(1);
    const auto *out = currentOp->getOutput();
    if (widest() <= 8) {
      set(out, currentBehave->evaluateBinary(out->size, in0->size, get(in0), get(in1)));
      return;
    }
    const OpCode op = currentBehave->getOpcode();
    auto a = getWide(in0);
    auto b = getWide(in1);
    switch (op) {
    case CPUI_INT_XOR: case CPUI_INT_AND: case CPUI_INT_OR:
    case CPUI_BOOL_XOR: case CPUI_BOOL_AND: case CPUI_BOOL_OR:
      for (size_t i = 0; i < a.size(); ++i) {
        const uint8_t y = i < b.size() ? b[i] : 0;
        a[i] = op == CPUI_INT_XOR || op == CPUI_BOOL_XOR ? a[i] ^ y : op == CPUI_INT_AND || op == CPUI_BOOL_AND ? a[i] & y : a[i] | y;
      }
      setWide(out, a);
      return;
    case CPUI_PIECE: {
      std::vector<uint8_t> r(b);
      r.insert(r.end(), a.begin(), a.end());
      setWide(out, r);
      return;
    }
    case CPUI_SUBPIECE: {
      const size_t skip = size_t(in1->offset);
      std::vector<uint8_t> r(size_t(out->size), 0);
      for (size_t i = 0; i < r.size() && skip + i < a.size(); ++i) r[i] = a[skip + i];
      setWide(out, r);
      return;
    }
    case CPUI_INT_EQUAL: case CPUI_INT_NOTEQUAL: {
      b.resize(a.size(), 0);
      setWide(out, bool_bytes((a == b) == (op == CPUI_INT_EQUAL)));
      return;
    }
    default: break;
    }
    if (widest() > 16) unsupported("binary");
    const size_t size = a.size();
    const U128 x = U128::of(a), y = U128::of(b);
    const U128 sx = x.sext(size), sy = y.sext(b.size());
    const size_t osize = size_t(out->size);
    auto result = [&](U128 v) { setWide(out, v.mask(osize).bytes(osize)); };
    auto flag = [&](bool v) { setWide(out, bool_bytes(v)); };
    const unsigned shift = y.hi || y.lo > 128 ? 128 : unsigned(y.lo);
    switch (op) {
    case CPUI_INT_ADD: result(x + y); return;
    case CPUI_INT_SUB: result(x - y); return;
    case CPUI_INT_MULT: result(x * y); return;
    case CPUI_INT_LEFT: result(x.shl(shift)); return;
    case CPUI_INT_RIGHT: result(x.shr(shift)); return;
    case CPUI_INT_SRIGHT: {
      U128 v = sx.shr(shift);
      if (sx.negative()) v = v | ~(~U128()).shr(shift);
      result(v);
      return;
    }
    case CPUI_INT_LESS: flag(x < y); return;
    case CPUI_INT_LESSEQUAL: flag(!(y < x)); return;
    case CPUI_INT_SLESS: case CPUI_INT_SLESSEQUAL: {
      U128 bias;
      bias.hi = uint64_t(1) << 63;
      const U128 p = sx + bias, q = sy + bias;
      flag(op == CPUI_INT_SLESS ? p < q : !(q < p));
      return;
    }
    case CPUI_INT_CARRY: flag((x + y).mask(size) < x); return;
    case CPUI_INT_SCARRY: {
      const U128 r = (x + y).sext(size);
      flag(sx.negative() == sy.negative() && r.negative() != sx.negative());
      return;
    }
    case CPUI_INT_SBORROW: {
      const U128 r = (x - y).sext(size);
      flag(sx.negative() != sy.negative() && r.negative() != sx.negative());
      return;
    }
    case CPUI_INT_DIV: case CPUI_INT_REM: case CPUI_INT_SDIV: case CPUI_INT_SREM: {
      if (y.zero()) throw LowlevelError("division by zero");
      const bool sign = op == CPUI_INT_SDIV || op == CPUI_INT_SREM;
      U128 n = sign && sx.negative() ? U128() - sx : (sign ? sx : x);
      U128 d = sign && sy.negative() ? U128() - sy : (sign ? sy : y);
      U128 q, r;
      U128::divmod(n, d, q, r);
      if (sign && sx.negative() != sy.negative()) q = U128() - q;
      if (sign && sx.negative()) r = U128() - r;
      result(op == CPUI_INT_DIV || op == CPUI_INT_SDIV ? q : r);
      return;
    }
    default: break;
    }
    unsupported("binary");
  }
  void executeLoad() override {
    AddrSpace *space = currentOp->getInput(0)->getSpaceFromConst();
    const uint64_t offset = AddrSpace::addressToByte(get(currentOp->getInput(1)), space->getWordSize());
    const auto *out = currentOp->getOutput();
    if (inRam(space)) checkAccess(offset, out->size, false);
    if (out->size <= 8) { set(out, memstate->getValue(space, offset, out->size)); return; }
    std::vector<uint8_t> bytes(size_t(out->size));
    memstate->getChunk(bytes.data(), space, offset, out->size);
    if (space->isBigEndian()) std::reverse(bytes.begin(), bytes.end());
    setWide(out, bytes);
  }
  void executeStore() override {
    AddrSpace *space = currentOp->getInput(0)->getSpaceFromConst();
    const uint64_t offset = AddrSpace::addressToByte(get(currentOp->getInput(1)), space->getWordSize());
    const auto *value = currentOp->getInput(2);
    if (value->size <= 8) {
      const uintb v = get(value);
      if (inRam(space)) { checkAccess(offset, value->size, true); ram.noteWrite(offset, value->size); }
      memstate->setValue(space, offset, value->size, v);
      return;
    }
    putBytes(space, offset, getWide(value));
  }
  void executeBranch() override {
    const Address &dest = currentOp->getInput(0)->getAddr();
    if (!dest.isConstant()) { setExecuteAddress(dest); return; }
    // A relative branch moves within the instruction's own p-code.
    const auto target = int64_t(op_index) + int64_t(int32_t(dest.getOffset()));
    if (target < 0 || size_t(target) > current->ops.size()) throw LowlevelError("bad intra-instruction branch");
    op_index = size_t(target);
  }
  void executeCallother() override {
    const size_t id = size_t(currentOp->getInput(0)->offset);
    const std::string name = id < userops.size() ? userops[id] : "userop";
    const auto *out = currentOp->getOutput();
    static const char *const traps[] = {"syscall", "sysenter", "swi", "CallSupervisor", "software_interrupt",
      "SoftwareInterrupt", "HaltInstruction", "halt", "Breakpoint", "software_breakpoint", "int3", "trap", "break",
      "software_bkpt", "software_udf", "software_hlt", "software_hvc", "software_smc", "SoftwareBreakpoint",
      "HaltBreakPoint", "UndefinedInstructionException", "invalidInstructionException"};
    for (const char *trap : traps)
      if (name == trap) throw EmuTrap{name};
    if (name == "segment" && currentOp->numInput() >= 3 && out) {
      // 16-bit real-mode segmentation; protected and long mode use FS_OFFSET and GS_OFFSET.
      set(out, get(currentOp->getInput(2)));
    } else if (name == "rdtsc" && out) {
      set(out, steps * 4);
    } else if (out && (name == "ExclusiveMonitorPass" || name == "hasExclusiveAccess")) {
      set(out, 1);  // a single emulated thread always holds the exclusive monitor
    } else if (out && name == "ExclusiveMonitorsStatus") {
      set(out, 0);
    } else if (out && currentOp->numInput() >= 2 && out->size <= 8 &&
               (name.compare(0, 4, "Auth") == 0 || name.compare(0, 3, "pac") == 0 || name == "xpac")) {
      // Pointer authentication: keep the pointer as is (no signature bits are ever added).
      set(out, get(currentOp->getInput(1)));
    } else if (out) {
      // Unmodelled operation with a result: deterministic zero, reported to the caller.
      approximated.insert(name);
      if (out->size <= 8) set(out, 0); else setWide(out, {});
    } else {
      approximated.insert(name);
    }
    fallthruOp();
  }
  void fallthruOp() override { ++op_index; }

public:
  Insn *current = nullptr;
  uint64_t steps = 0;
  std::chrono::steady_clock::time_point deadline;
  std::set<std::string> approximated;
  BinferaEmulator(const ImageSleigh &t, MemoryState *state, EmuRam &r)
    : EmulateMemory(state), trans(t), ram(r), code(t.getDefaultCodeSpace()) {
    OpBehavior::registerInstructions(behaviors, &t);
    t.getUserOpNames(userops);
    pc = Address(code, 0);
  }
  ~BinferaEmulator() override { for (auto *b : behaviors) delete b; }
  void setExecuteAddress(const Address &address) override {
    pc = Address(code, address.getOffset());
    flowed = true;
  }
  Address getExecuteAddress() const override { return pc; }
  uint64_t address() const { return pc.getOffset(); }
  void jump(uint64_t address) { pc = Address(code, address); }
  /// Execute one machine instruction.
  void step() {
    Insn &insn = translate(pc.getOffset());
    // Translation uses the original image. Stop explicitly before executing changed code.
    if (ram.codeModified(pc.getOffset(), pc.getOffset() + uint64_t(insn.length)))
      throw LowlevelError("execution of modified image code is not supported");
    current = &insn;
    op_index = 0;
    flowed = false;
    uint64_t operations = 0;
    while (!flowed && op_index < insn.ops.size()) {
      if ((operations++ & 1023) == 0 && std::chrono::steady_clock::now() >= deadline)
        throw EmuLimit{"timeout"};
      if (operations > 1000000) throw EmuLimit{"work_limit"};
      currentOp = insn.ops[op_index];
      currentBehave = currentOp->getBehavior();
      executeCurrentOp();
    }
    if (!flowed) pc = pc + insn.length;
    ++steps;
  }
};

/// One emulation context: memory, registers, temporaries and the executing machine.
struct EmuState {
  EmuRam ram;
  MemoryPageOverlay registers;
  MemoryPageOverlay temporaries;
  MemoryState state;
  BinferaEmulator machine;
  EmuState(const ImageSleigh &trans, const Image &image)
    : ram(trans.getDefaultCodeSpace(), image),
      registers(trans.getSpaceByName("register"), 8, 4096, nullptr),
      temporaries(trans.getUniqueSpace(), 8, 4096, nullptr),
      state(const_cast<ImageSleigh *>(&trans)),
      machine(trans, &state, ram) {
    state.setMemoryBank(&ram);
    state.setMemoryBank(&registers);
    state.setMemoryBank(&temporaries);
  }
};
