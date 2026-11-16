#!/usr/bin/env python3
"""Add missing fixed C ABI signatures to the generated prototype packs.

Run after pack_prototypes.py. Existing archive entries always take precedence.
The declarations and their primary sources are documented in README.md.
"""
import argparse
from pathlib import Path
import struct
import zlib
from xml.etree import ElementTree as ET

from pack_prototypes import pack


# void, signed int32, size_t, void*, char*, void**, size_t*.
POSIX = [
    ("dlopen", "p", ["c", "i"], False),
    ("dlsym", "p", ["p", "c"], False),
    ("dlclose", "i", ["p"], False),
    ("dlerror", "c", [], False),
    ("__stack_chk_fail", "v", [], True),
]
DARWIN = [
    ("objc_destroyWeak", "v", ["pp"], False),
    ("objc_initWeak", "p", ["pp", "p"], False),
    ("objc_storeWeak", "p", ["pp", "p"], False),
    ("objc_loadWeak", "p", ["pp"], False),
    ("objc_loadWeakRetained", "p", ["pp"], False),
    ("objc_copyWeak", "v", ["pp", "pp"], False),
    ("objc_moveWeak", "v", ["pp", "pp"], False),
    ("objc_retainAutorelease", "p", ["p"], False),
    ("objc_retainAutoreleaseReturnValue", "p", ["p"], False),
    ("objc_unsafeClaimAutoreleasedReturnValue", "p", ["p"], False),
    ("objc_autoreleasePoolPush", "p", [], False),
    ("objc_autoreleasePoolPop", "v", ["p"], False),
    ("objc_opt_self", "p", ["p"], False),
    ("CFRunLoopStop", "v", ["p"], False),
    ("CFRunLoopWakeUp", "v", ["p"], False),
    ("CFRunLoopPerformBlock", "v", ["p", "p", "p"], False),
]
WINDOWS = [
    (prefix + operation + "VirtualMemory", "i", ["p", "p", "p", "z", "pz"], False)
    for prefix in ("Nt", "Zw") for operation in ("Read", "Write")
] + [
    ("DeleteUrlCacheEntryA", "i", ["c"], False),
    ("DeleteUrlCacheEntryW", "i", ["pw2"], False),
    ("_initterm", "v", ["pp", "pp"], False),
    ("_initterm_e", "i", ["pp", "pp"], False),
]


def read_pack(path):
    data = path.read_bytes()
    if data[:8] != b"CXPROTO1":
        raise ValueError("not a prototype pack")
    count, = struct.unpack_from("<I", data, 8)
    position, blocks = 12, []
    for _ in range(count):
        offset, length, raw_size, key_size = struct.unpack_from("<IIIH", data, position)
        position += 14 + key_size
        blocks.append((offset, length, raw_size))
    entries = {}
    for offset, length, raw_size in blocks:
        raw = zlib.decompress(data[position + offset:position + offset + length])
        if len(raw) != raw_size:
            raise ValueError("wrong block size")
        for line in raw.decode().splitlines():
            key, value = line.split("\t", 1)
            entries[key] = value
    return entries


def value_type(kind, width):
    if kind == "v":
        return ET.Element("void")
    if kind.startswith("p") or kind == "c":
        node = ET.Element("type", name="", metatype="ptr", size=str(width))
        child = "c1" if kind == "c" else kind[1:] or "v"
        node.append(value_type(child, width))
        return node
    name, meta, size = {"i": ("int4", "int", 4),
                        "z": (f"uint{width}", "uint", width),
                        "c1": ("char", "int", 1),
                        "w2": ("wchar16", "int", 2)}[kind]
    node = ET.Element("type", name=name, metatype=meta, size=str(size))
    if kind in ("c1", "w2"):
        node.set("char", "true")
    return node


def prototype(platform, width, name, result, parameters, noreturn):
    stdcall = platform == "windows" and name.startswith(("Nt", "Zw", "DeleteUrlCacheEntry"))
    model = "__stdcall" if stdcall else "__cdecl"
    if platform == "windows" and width == 8:
        model = "__fastcall"
    cleanup = width + 4 * len(parameters) if stdcall and width == 4 else width
    node = ET.Element("prototype", extrapop=str(cleanup), model=model, modellock="true")
    if noreturn:
        node.set("noreturn", "true")
    if not parameters:
        node.set("voidlock", "true")
    output = ET.SubElement(node, "returnsym", typelock="true")
    ET.SubElement(output, "addr")
    output.append(value_type(result, width))
    inputs = ET.SubElement(node, "internallist", first="-1")
    for index, parameter in enumerate(parameters):
        arg = ET.SubElement(inputs, "param", name=f"param_{index + 1}", typelock="true", namelock="true")
        ET.SubElement(arg, "addr")
        arg.append(value_type(parameter, width))
    return ET.tostring(node, encoding="unicode", short_empty_elements=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("platform", choices=("linux", "darwin", "windows"))
    parser.add_argument("width", type=int, choices=(4, 8))
    parser.add_argument("pack", type=Path)
    args = parser.parse_args()
    entries = read_pack(args.pack)
    if args.platform == "windows":
        signatures = WINDOWS
    elif args.platform == "darwin":
        signatures = POSIX + DARWIN
    else:
        signatures = POSIX + [("__stack_chk_fail_local", "v", [], True)]
    for name, result, parameters, noreturn in signatures:
        entries.setdefault("F:" + name, prototype(args.platform, args.width, name, result, parameters, noreturn))
    pack(entries.items(), args.pack)


if __name__ == "__main__":
    main()
