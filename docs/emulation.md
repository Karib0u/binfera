# Function emulation

Emulation needs the decompiler, which released builds include (from source: `--features decompiler`). It runs SLEIGH p-code against private image memory. Sample instructions never execute on the host CPU. Import calls are recorded stubs with fixed scalar return values, defaulting to zero.

## CLI

```sh
binfera sample.exe --emulate 0x140001000 --emulate-arg 6 --emulate-arg 3
binfera sample.exe --emulate 0x140001000 --emulate-call-sites --emulate-max-sites 32
binfera raw.bin -f sc64 --os linux --emulate 0 --emulate-arg 42
binfera sample.exe --emulate 0x140001000 --emulate-request < request.json
```

Output is JSON. `--emulate-max-steps` and `--emulate-timeout-ms` override the request budgets. Raw code starts at address zero, matching the decompiler's native raw-code mode. Arguments accept decimal or `0x`-prefixed hexadecimal values.

A full request uses numeric addresses and byte arrays:

```json
{
  "address": 5368713216,
  "args": [1048576, 4],
  "registers": {},
  "memory": [{"address": 1048576, "data": [65, 66, 67, 0]}],
  "capture": [{"address": 1048576, "size": 4}],
  "import_returns": {"GetTickCount": 123},
  "import_stack_pops": {},
  "max_steps": 100000,
  "timeout_ms": 1000,
  "max_calls": 256,
  "max_write_bytes": 65536
}
```

Fields have defaults; `address` defaults to zero for raw code and must match the CLI address. Unknown fields are rejected. Initial memory maps missing ranges or updates existing mapped data. Partial overlaps with existing mappings are rejected, as are initial patches to executable sections. Register overrides apply after stack and argument setup. Use `FS_OFFSET` or `GS_OFFSET` to supply x86 segment bases. Initialization writes are excluded from the reported writes.

The Rust API is `binfera::emulate::{Emulator, Request}`. Open an image with `Emulator::open(bytes, &BatchOptions::default())`, then call `run(&request)` or `call_sites(&request, max_sites)`. `from_analysis` accepts existing recovery plus an explicit platform calling convention. Every execution starts from fresh image memory and zero registers.

## Arguments and returns

Arguments are raw integer/pointer slots of the machine's word size. Aggregates, floating-point arguments and special compiler ABIs need explicit register and memory setup; automatic Go, Delphi and Borland convention setup is rejected.

| Platform | Argument registers | Stack arguments at entry | Return |
|---|---|---|---|
| Windows x64 | RCX, RDX, R8, R9 | RSP + 40, after return address and shadow space | RAX |
| System V/Darwin x64 | RDI, RSI, RDX, RCX, R8, R9 | RSP + 8 | RAX |
| Windows/System V x86 | none | ESP + 4 | EAX |
| AArch64 | x0 through x7 | sp | x0 |
| ARM32 | r0 through r3 | sp | r0 |
| MIPS32 o32 | a0 through a3 | sp + 16 | v0 |

The synthetic stack is 1 MiB. At x86 entry its return-address slot is one word below a 16-byte aligned caller stack pointer. Link-register architectures use their ABI link register as the synthetic return address. Scalars are stored with the target's endianness. Negative values should be supplied as their unsigned machine-word representation.

Import pointer slots are replaced with unique unmapped sentinels. On reaching one, the emulator records raw argument slots and the return address, sets the scalar result register, and resumes the caller. Returns can be keyed by full import location or symbol, with full locations taking precedence. A known x86 stdcall signature supplies the actual byte purge from the bundled type archive, including arguments wider than four bytes. Unknown Windows x86 stack effects stop as `unknown_import_abi`; supply an explicit `import_stack_pops` entry to continue. Import argument inspection is limited to 32 raw slots.

## Results and limits

A function result contains `stop`, instruction/stub `steps`, `return_value`, selected `registers`, recorded import `calls`, final `writes`, explicit captured `memory`, and `warnings`. Writes are merged ranges with their final bytes, not a chronological trace. A range retains its full `size` and sets `truncated` when its byte capture exceeds the output budget. An unmapped explicit capture returns an empty byte array with `truncated: true`.

Stops include `returned`, `caller_returned`, `fetch`, `read_fault`, `write_fault`, `trap`, `decode_error`, `unsupported`, `step_limit`, `work_limit`, `timeout`, `call_limit`, and `unknown_import_abi`. Unsupported operations stop explicitly. Approximated user operations are listed in warnings. Syscalls and interrupts stop; they do not run host APIs. Executing image code modified during emulation stops as unsupported because instruction translation reads the original image. Mapped memory is always writable: a store to a read-only section succeeds rather than stopping as `write_fault`.

Direct calls to external symbols in relocatable objects (`.o`) are not import stubs and stop as `fetch`. Output budgets apply per call site, and an MCP batch over the 16 MiB output limit fails as a whole, so keep `capture` and `max_write_bytes` small with many sites. Each MCP call repeats image recovery within its 120-second process deadline.

Defaults allow 100,000 instructions/stubs, one second, 256 import calls, and 64 KiB of captured write bytes. Requests allow at most 10 million steps, 60 seconds, 4,096 import calls, 256 argument slots, 128 register overrides, 128 input/capture regions, and 1 MiB each of initial memory, explicit captures, and captured write bytes. Native limits also bound allocated RAM pages, mappings, write ranges, and p-code operations within one machine instruction.

Call-site execution enumerates statically resolved calls from recovered function bodies. Each site gets a fresh caller state with `args` interpreted as the caller's arguments. Execution first runs from caller entry to the call instruction, then through the call until its fallthrough. A site may be unreachable under those arguments; `reached: false` preserves that run's stop reason. Writes, steps and import records include the caller prelude. One timeout covers the complete batch; `truncated` reports skipped sites. Unresolved register-indirect calls are not enumerated. This mode supports x86, x64 and AArch64; ARM32/MIPS delay-slot and interworking call sites are rejected.

## MCP

`emulate_function` and `emulate_call_sites` accept `project_id`, a hexadecimal string `address`, and an optional `request` object with the fields above except `address`. The call-site tool also accepts `max_sites` (default 32, at most 128). They run in isolated CLI child processes, check that the file still matches its project hash, and leave annotations unchanged. A child has a 120-second process deadline and a 16 MiB output limit. The executable must have the `decompiler` feature enabled.
