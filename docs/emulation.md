# Emulate a function

Run a single function with the arguments you choose and see what it returns, writes and calls. Emulation interprets the code in a private copy of the image: sample instructions never run on your CPU, and imports are stubs that return fixed values.

## In the app

Open a function, then **Emulate** in the function inspector (on a phone, the **Emulate** tab). Both the desktop app and the browser run the same engine.

- **Run function**: give each argument as an integer (decimal, `0x` hex or negative) or as a buffer of hex bytes, UTF-8 or UTF-16 text. Arguments start from the decompiled prototype; pointers become buffers. A buffer is mapped outside the image and its address is passed. Leave its size blank for the input plus 256 bytes. The result shows the stop reason, return value, written memory with decoded text, import calls and registers. **Copy** copies text or bytes, and **Hex** opens bytes that lie in the file.
- **Call sites**: runs the function at every recovered call site and lists what each call wrote, such as the strings a decryption helper produces. Click a site to open the call.

The app uses 2,000,000 steps and a 5 s timeout per run (15 s for all call sites together), and stops a run after two minutes.

## Run a function

```sh
# Call a function with two arguments
binfera sample.exe --emulate 0x140001000 --emulate-arg 6 --emulate-arg 3

# Run every call site of a function
binfera sample.exe --emulate 0x140001000 --emulate-call-sites --emulate-max-sites 32

# Raw shellcode starts at address 0
binfera raw.bin -f sc64 --os linux --emulate 0 --emulate-arg 42

# Full control with a request file
binfera sample.exe --emulate 0x140001000 --emulate-request < request.json
```

Output is JSON. Arguments accept decimal or `0x` hex. `--emulate-max-steps` and `--emulate-timeout-ms` override the budgets.

## Request file

Every field is optional. Addresses are numbers, memory is a byte array.

```json
{
  "args": [1048576, 4],
  "memory": [{"address": 1048576, "data": [65, 66, 67, 0]}],
  "capture": [{"address": 1048576, "size": 4}],
  "import_returns": {"GetTickCount": 123},
  "max_steps": 100000
}
```

| Field | What it does |
|---|---|
| `address` | Function address. Must match `--emulate`. |
| `args` | Integer or pointer arguments, one machine word each. |
| `registers` | Register values, applied after arguments. Use `FS_OFFSET` / `GS_OFFSET` for x86 segment bases. |
| `memory` | Bytes to place in memory before the run. |
| `capture` | Memory ranges to read back after the run. |
| `import_returns` | Return value per import, by name or location. Default `0`. |
| `import_stack_pops` | Stack bytes an unknown x86 import pops. |
| `max_steps`, `timeout_ms`, `max_calls`, `max_write_bytes` | Budgets (see [Limits](#limits)). |

Unknown fields are rejected. Pass negative numbers as their unsigned machine-word value.

## Calling conventions

| Platform | Arguments | Return |
|---|---|---|
| Windows x64 | RCX, RDX, R8, R9, then stack | RAX |
| System V / macOS x64 | RDI, RSI, RDX, RCX, R8, R9, then stack | RAX |
| x86 | stack | EAX |
| AArch64 | x0–x7, then stack | x0 |
| ARM32 | r0–r3, then stack | r0 |
| MIPS32 o32 | a0–a3, then stack | v0 |

Floating-point arguments, structs and special ABIs (Go, Delphi, Borland) need explicit `registers` and `memory`.

## Results

| Field | Content |
|---|---|
| `stop` | Why the run ended |
| `return_value` | Value in the return register |
| `steps` | Instructions and import stubs executed |
| `registers` | Selected final registers |
| `calls` | Import calls with their arguments |
| `writes` | Memory ranges written, with final bytes |
| `call_writes` | Call-site mode, on each site: ranges written by the call itself, not by the caller before it |
| `memory` | Ranges you asked to `capture` |
| `warnings` | Approximations made during the run |

| Stop | Meaning |
|---|---|
| `returned` | The function returned normally |
| `caller_returned` | Call-site mode: the caller returned |
| `fetch`, `read_fault`, `write_fault` | Jump or access to unmapped memory |
| `step_limit`, `work_limit`, `timeout`, `call_limit` | A budget ran out |
| `trap`, `decode_error`, `unsupported` | Instruction that cannot be emulated |
| `unknown_import_abi` | x86 import with unknown stack cleanup: set `import_stack_pops` |

## Call sites

`--emulate-call-sites` runs each call to the function from its caller. Each site starts fresh, runs the caller from its entry with your `args`, then runs through the call. A site the caller never reaches reports `reached: false`. The site's `call_writes` holds only what the call wrote, while `result.writes` also includes what the caller wrote on the way. Supported on x86, x64 and AArch64.

## Limits

| Budget | Default | Maximum |
|---|---|---|
| Steps | 100,000 | 10,000,000 |
| Time | 1 s | 60 s |
| Import calls | 256 | 4,096 |
| Captured write bytes | 64 KiB | 1 MiB |

Not supported:

- Syscalls and interrupts: the run stops.
- Self-modifying code: the run stops as `unsupported`.
- Read-only memory: writes to it succeed instead of faulting.
- Indirect calls through registers in call-site mode.
- External calls in object files (`.o`): they stop as `fetch`.

## From an agent

The MCP tools `emulate_function` and `emulate_call_sites` take a `project_id`, a hex `address` and an optional `request` with the fields above. `emulate_call_sites` also takes `max_sites` (default 32, max 128). Each call runs in a separate process with a 120-second limit and leaves annotations unchanged. See [Connect an AI agent](mcp.md).

## From Rust

```rust
use binfera::emulate::{Emulator, Request};

let mut emu = Emulator::open(bytes, &BatchOptions::default())?;
let result = emu.run(&request)?;            // or emu.call_sites(&request, max_sites)
```

Every run starts from fresh memory and zeroed registers.
