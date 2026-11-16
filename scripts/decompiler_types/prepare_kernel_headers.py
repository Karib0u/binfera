#!/usr/bin/env python3
"""Preprocess MinGW-w64 14.0.0 DDK + ReactOS 0.4.15 fltkernel.h for Ghidra.

Development only. Arguments: CROSS_GCC INCLUDE_DIR FLTKERNEL_H OUTPUT_H
Use the target's compiler and include directory for each pointer width.
"""
import hashlib
from pathlib import Path
import re
import subprocess
import sys


def main():
    compiler, include, fltkernel, output = sys.argv[1:]
    flt = Path(fltkernel).resolve()
    # Pin the public-domain ReactOS header, which MinGW does not ship.
    digest = hashlib.sha256(flt.read_bytes()).hexdigest()
    if digest != "6d772843b1338f7c1850e1fae55629954e410af4cd4ec6c52a4cb2672b508175":
        raise SystemExit("fltkernel.h must be from ReactOS 0.4.15-release")
    includes = ["-I" + include, "-I" + str(Path(include) / "ddk")]
    macros = subprocess.check_output(
        [compiler, *includes, "-dM", "-E", "-x", "c", "-", "-include", "_mingw_mac.h"],
        input="", text=True,
    )
    for name, value in [("MAJOR", 14), ("MINOR", 0), ("BUGFIX", 0)]:
        if f"#define __MINGW64_VERSION_{name} {value}\n" not in macros:
            raise SystemExit("MinGW-w64 14.0.0 headers are required")
    if "#define __x86_64__ " in macros:
        arch = "_M_AMD64=100"
    elif "#define __i386__ " in macros:
        arch = "_M_IX86=600"
    else:
        raise SystemExit("an x86 or x86-64 MinGW compiler is required")
    source = ('#include <ddk/ntifs.h>\n#include <ddk/ndis.h>\n'
              'typedef struct _KTRANSACTION *PKTRANSACTION;\n'
              f'#include "{flt.as_posix()}"\n')
    header = subprocess.check_output([
        compiler, *includes, "-E", "-P", "-x", "c", "-",
        "-D" + arch, "-D__INTRIN_H_", "-D_GCC_MAX_ALIGN_T", "-DNDIS_WRAPPER=1",
    ], input=source, text=True)
    # Ghidra accepts GNU attributes but does not retain their calling conventions.
    # Convert only convention attributes; keep alignment attributes and pack pragmas.
    header = re.sub(r"__attribute__\s*\(\(__(cdecl|stdcall|fastcall)__\)\)",
                    lambda m: "__" + m[1], header)
    header = header.replace("_CRT_PACKING", "8")
    # MinGW-w64 14.0.0 ndis.h: missing comma in this legacy declaration.
    header = header.replace("NDIS_HANDLE MiniportAdapterHandle\n NDIS_HANDLE NdisLinkContext",
                            "NDIS_HANDLE MiniportAdapterHandle,\n NDIS_HANDLE NdisLinkContext")
    Path(output).write_text(header)


if __name__ == "__main__":
    main()
