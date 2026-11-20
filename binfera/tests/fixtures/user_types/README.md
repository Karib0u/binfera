# Analyst-type fixture

`packet.c` is compiled for inspection, never executed by the tests. Run `sh build.sh` to rebuild `packet.elf` with LLVM clang, lld and llvm-objcopy; `LLVM_BIN` and `LLD_BIN` override the script's Homebrew defaults.

- `packet.elf`: a freestanding, non-PIE x86-64 ELF built at `-O1`, then stripped of its symbol table. It has no debug sections; `.eh_frame` still lists every function.
- `packet_score` (`0x2012a0`) reads `struct packet` fields through a `void *`. `packet_reset` (`0x2012b0`) writes fields through its pointer, then passes it on. `packet_total` (`0x2012d0`) passes each node on and follows `next`.

The build prints the function addresses before stripping; `decompiler_user_types.rs` hard-codes them. That test supplies `struct packet` and the `packet_score` prototype as an analyst would, without DWARF.
