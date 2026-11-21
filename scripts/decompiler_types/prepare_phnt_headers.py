#!/usr/bin/env python3
"""Preprocess the phnt headers of System Informer (MIT) for Ghidra's C parser.

Development only. usage: prepare_phnt_headers.py CROSS_GCC MINGW_INCLUDE PHNT_INCLUDE OUTPUT.h

PHNT_INCLUDE is `phnt/include` of winsiderss/systeminformer at the commit pinned in README.md.
CROSS_GCC is `x86_64-w64-mingw32-gcc` or `i686-w64-mingw32-gcc`; MINGW_INCLUDE its include
directory (MinGW-w64 14.0.0). The headers describe the user-mode native API for the Windows 11
24H2 build. A copy of `phnt.h` without the headers that need Windows SDK files MinGW lacks is
preprocessed in place of it, and `minidumpapiset.h`, which `phnt_windows.h` includes and MinGW
lacks, is an empty stub (nothing in the kept headers uses it).
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

# Headers phnt.h includes that are not kept: they need SDK headers MinGW does not have (NDIS types,
# the user-mode window and WMI structures) or describe subsystems with no import in the corpus.
DROPPED = {"ntnsi.h", "ntuser.h", "ntwmi.h", "ntd3dkmt.h", "ntgdi.h", "winsta.h", "nthv.h", "ntfve.h",
           "ntsam.h", "ntlsa.h", "ntbcd.h", "ntpoapi.h", "ntpnpapi.h", "ntpfapi.h", "ntmisc.h", "ntsmss.h",
           "ntafd.h", "usermgr.h", "subprocesstag.h", "smbios.h"}


# Types of Windows SDK headers that MinGW-w64 14.0.0 lacks and the kept phnt headers use. Each is
# the SDK's own scalar or enum, as documented by Microsoft.
GAPS = """typedef int STORAGE_RESERVE_ID;
typedef unsigned long RTL_SYSTEM_GLOBAL_DATA_ID;
"""


def strip_bodies(text):
    """Replace every top-level function body, which Ghidra's C parser cannot read (MinGW's
    intrinsics are inline assembly), with a semicolon, keeping the declaration. A body starts at a
    top-level `{` that follows `)`; struct, union and enum bodies and initializers are kept."""
    out, depth, last, i, n = [], 0, "", 0, len(text)
    while i < n:
        ch = text[i]
        if ch in "\"'":
            j = i + 1
            while j < n and text[j] != ch:
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            last, i = ch, j + 1
            continue
        if ch == "{" and depth == 0 and last == ")":
            level, i = 1, i + 1
            while level:
                c = text[i]
                if c in "\"'":
                    j = i + 1
                    while text[j] != c:
                        j += 2 if text[j] == "\\" else 1
                    i = j
                elif c == "{":
                    level += 1
                elif c == "}":
                    level -= 1
                i += 1
            out.append(";")
            last = ";"
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        out.append(ch)
        if not ch.isspace():
            last = ch
        i += 1
    return "".join(out)


def main():
    compiler, mingw, phnt, output = sys.argv[1:]
    phnt = Path(phnt).resolve()
    macros = subprocess.check_output([compiler, "-I" + mingw, "-dM", "-E", "-x", "c", "-", "-include", "_mingw_mac.h"],
                                     input="", text=True)
    for name, value in [("MAJOR", 14), ("MINOR", 0), ("BUGFIX", 0)]:
        if f"#define __MINGW64_VERSION_{name} {value}\n" not in macros:
            raise SystemExit("MinGW-w64 14.0.0 headers are required")
    if "#define __x86_64__ " in macros:
        arch = "_M_AMD64=100"
    elif "#define __i386__ " in macros:
        arch = "_M_IX86=600"
    else:
        raise SystemExit("an x86 or x86-64 MinGW compiler is required")
    text = (phnt / "phnt.h").read_text()
    text = re.sub(r"#define PHNT_VERSION PHNT_WINDOWS_NEW", "#define PHNT_VERSION PHNT_WINDOWS_11_24H2", text)
    for name in DROPPED:
        text = text.replace(f"#include <{name}>", "")
    text = re.sub(r"static_assert\([^\n]*\n", "\n", text)
    with tempfile.TemporaryDirectory() as work:
        work = Path(work)
        (work / "minidumpapiset.h").write_text("")
        (work / "phnt_trimmed.h").write_text(text)
        source = "#include <phnt_windows.h>\n" + GAPS + "#include <phnt_trimmed.h>\n"
        header = subprocess.check_output([
            compiler, "-I" + str(work), "-I" + str(phnt), "-I" + mingw, "-E", "-P", "-x", "c", "-",
            "-D" + arch, "-D__INTRIN_H_", "-D_GCC_MAX_ALIGN_T", "-D_IMMINTRIN_H_INCLUDED", "-DEXTERN_C_START=", "-DEXTERN_C_END=", "-D_Kernel_entry_=", "-D_Analysis_noreturn_=", "-D_Enum_is_bitflag_=", "-DDECLSPEC_RESTRICT=", "-DDECLSPEC_ALLOCATOR=", "-D__callback=", "-DDECLSPEC_NOALIAS=", "-DDECLSPEC_NOINITALL=", "-D_X86INTRIN_H_INCLUDED", "-std=gnu11",
        ], input=source, text=True)
    # Ghidra accepts GNU attributes but does not retain their calling conventions.
    header = re.sub(r"__attribute__\s*\(\(__(cdecl|stdcall|fastcall)__\)\)", lambda m: "__" + m[1], header)
    header = header.replace("_CRT_PACKING", "8")
    header = strip_bodies(header)
    Path(output).write_text(header)


if __name__ == "__main__":
    main()
