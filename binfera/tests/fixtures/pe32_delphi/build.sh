#!/bin/sh
# Rebuilds the Delphi-layout fixture. Needs MinGW-w64 (i686) and Python 3.
# gcc's regparm(3) passes arguments in EAX, EDX and ECX like Delphi's `register` convention.
# Ghidra's compiler opinion for an image with a gcc/Visual C DOS stub, its header at 0x80, no
# Rich header and no symbol table pointer, falls through to the section names: a `CODE` section
# is Borland's (Delphi's). `delphi.exe` renames `.text` so; `plain.exe` is the same program.
set -e
cd "$(dirname "$0")"
i686-w64-mingw32-gcc -O1 -s -nostdlib -nostartfiles -e _WinMainCRTStartup@0 register.c -lkernel32 -o plain.exe
python3 -I - plain.exe delphi.exe <<'PY'
import struct, sys
data = bytearray(open(sys.argv[1], "rb").read())
pe = struct.unpack_from("<I", data, 0x3c)[0]
count = struct.unpack_from("<H", data, pe + 6)[0]
table = pe + 24 + struct.unpack_from("<H", data, pe + 20)[0]
for i in range(count):
    at = table + 40 * i
    if data[at:at + 8].rstrip(b"\0") == b".text":
        data[at:at + 8] = b"CODE".ljust(8, b"\0")
open(sys.argv[2], "wb").write(data)
PY
