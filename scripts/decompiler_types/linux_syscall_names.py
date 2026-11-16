#!/usr/bin/env python3
"""Export x86 Linux syscall number/name ABI facts from the pinned kernel tables."""
from pathlib import Path
from urllib.request import urlopen

VERSION = "v6.12"
ROOT = Path(__file__).resolve().parents[2]
BASE = f"https://raw.githubusercontent.com/torvalds/linux/refs/tags/{VERSION}/arch/x86/entry/syscalls/"


def main():
    for width in (32, 64):
        source = urlopen(BASE + f"syscall_{width}.tbl", timeout=30).read().decode()
        rows = []
        for line in source.splitlines():
            fields = line.split()
            if fields and fields[0].isdigit() and fields[1] in ("common", "64", "i386"):
                rows.append(f"{fields[0]} {fields[2]}")
        path = ROOT / f"binfera-ghidra/data/linux{width}_syscalls.txt"
        path.write_text(
            f"# Linux {VERSION} arch/x86/entry/syscalls/syscall_{width}.tbl\n"
            "# Numeric ABI facts; regenerate with scripts/decompiler_types/linux_syscall_names.py.\n"
            + "\n".join(rows) + "\n"
        )


if __name__ == "__main__":
    main()
