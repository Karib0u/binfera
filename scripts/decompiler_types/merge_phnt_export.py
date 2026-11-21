#!/usr/bin/env python3
"""Development-only: add the phnt native API to a Windows prototype pack.

usage: merge_phnt_export.py EXPORT.tsv PHNT_INCLUDE PACK

EXPORT.tsv is ExportPrototypes.java's output for the archive that ParseKernelHeaders.java made from
prepare_phnt_headers.py's header (README.md, "Native API"). PHNT_INCLUDE is `phnt/include`; the
functions it declares with `NTAPI` are the ones added, because the archive also holds every
function of MinGW's `windows.h`. PACK is rewritten in place.

Existing entries keep priority: a function the pack has is not added, and a type whose name the
pack has is referenced as the pack's own (not an anonymous one: `_union_315` names a different
type in each archive), except for the loader and process structures in ROOTS,
which this adds under their own names even where the pack has a smaller declaration (the kernel
headers declare `_TEB` as an empty structure). Every other added type is reachable from an added
prototype or from a root. Type ids are renumbered into a range of their own.
"""
import re
import sys
from pathlib import Path

from pack_prototypes import pack
from supplement_prototypes import read_pack

ID_BASE = 0x8000000000200000
ROOTS = {"_PEB", "_TEB", "_PEB_LDR_DATA", "_LDR_DATA_TABLE_ENTRY", "_RTL_USER_PROCESS_PARAMETERS",
         "_CLIENT_ID", "_TEB_ACTIVE_FRAME", "_ACTIVATION_CONTEXT_STACK"}
BITFIELD = re.compile(r'<bitfield name="([^"]*)" id="\d+" offset="(\d+)" first="\d+" size="\d+">(.*?)</bitfield>')
BITREF = re.compile(r'<typeref name="(\w+):\d+" id="0x9[0-9a-f]+"/>')
# Takes a structure by value that the x86 calling convention cannot place; the x64 decoding is fine.
SKIP = {"RtlLocateExtendedFeature2"}
ANONYMOUS = re.compile(r"_(struct|union|enum|func)_\d+")
ID = re.compile(r'id="(0x[0-9a-f]+)"')
TYPEREF = re.compile(r'<typeref name="[^"]*" id="(0x[0-9a-f]+)"')


def flatten_bitfields(xml, by_name, types):
    """The engine cannot decode a structure of bitfields inside a union, and a bitfield's own type
    reference has no definition. The bitfields that share one storage unit become one field of the
    unit's base type, named after the first bit (`ImageUsesLargePages_bits`); the layout is
    unchanged."""
    def size_of(base):
        match = re.search(r'size="(\d+)"', base)
        ref = TYPEREF.search(base)
        if ref and ref.group(1) in types:
            match = re.search(r'size="(\d+)"', types[ref.group(1)][1])
        return int(match.group(1)) if match else 1
    unit_end = [-1]

    def group(match):
        name, offset, base = match.groups()
        if int(offset) < unit_end[0]:
            return ""           # inside the storage unit of an earlier bitfield
        unit_end[0] = int(offset) + size_of(base)
        return f'<field name="{name}_bits" offset="{offset}">{base}</field>'
    xml = BITFIELD.sub(group, xml)

    def base_ref(match):
        ident = by_name.get(match.group(1))
        return f'<typeref name="{match.group(1)}" id="{ident}"/>' if ident else match.group(0)
    return BITREF.sub(base_ref, xml)


def main():
    export, include, target = sys.argv[1:]
    declared = set()
    for header in Path(include).glob("*.h"):
        declared.update(re.findall(r"\bNTAPI\s+(\w+)\s*\(", header.read_text(errors="replace")))
    existing = read_pack(Path(target))
    old = {}
    for key, value in existing.items():
        if key.startswith("T:"):
            name, ident = value.split("\t", 1)[0], int(key[2:], 16)
            if name and ident < 0xc000000000000000 and ident < old.get(name, 1 << 64):
                old[name] = ident
    functions, types = {}, {}
    for line in Path(export).read_text(encoding="utf-8").splitlines():
        kind, rest = line.split("\t", 1)
        if kind == "F":
            name, xml = rest.split("\t", 1)
            functions[name] = xml
        else:
            ident, name, xml = rest.split("\t", 2)
            types[ident] = (name, xml)
    by_name = {}
    for ident, (name, _) in types.items():
        by_name.setdefault(name, ident)
    raw = types
    types = {i: (n, flatten_bitfields(x, by_name, raw)) for i, (n, x) in raw.items()}
    functions = {n: flatten_bitfields(x, by_name, raw) for n, x in functions.items()}
    kept = {name: xml for name, xml in functions.items() if name in declared and name not in SKIP and "F:" + name not in existing}
    # Types reachable from the kept prototypes and the roots.
    wanted, stack = set(), [i for i, (n, _) in types.items() if n in ROOTS]
    for xml in kept.values():
        stack.extend(TYPEREF.findall(xml) + ID.findall(xml))
    while stack:
        ident = stack.pop()
        if ident in wanted or ident not in types:
            continue
        wanted.add(ident)
        stack.extend(TYPEREF.findall(types[ident][1]))
    # Renumber: a type the pack has under its name is that type; the others get new ids.
    mapping, counter = {}, ID_BASE
    for ident in sorted(wanted, key=lambda i: (types[i][0], i)):
        name = types[ident][0]
        if name in old and name not in ROOTS and not ANONYMOUS.fullmatch(name):
            mapping[ident] = old[name]
        else:
            mapping[ident] = counter
            counter += 1

    def rewrite(xml):
        def sub(match):
            ident = match.group(1)
            if ident not in mapping and int(ident, 16) < 0xc000000000000000 and ident not in types:
                # A function type inlined in a field or parameter has its own id.
                mapping[ident] = counter_box[0]
                counter_box[0] += 1
            return f'id="0x{mapping[ident]:x}"' if ident in mapping else match.group(0)
        return ID.sub(sub, xml)

    counter_box = [counter]
    merged = dict(existing)
    added_types = added_functions = 0
    for ident in sorted(wanted):
        name, xml = types[ident]
        if name in old and name not in ROOTS and not ANONYMOUS.fullmatch(name):
            continue
        merged.setdefault(f"T:0x{mapping[ident]:x}", f"{name}\t{rewrite(xml)}")
        added_types += 1
    for name, xml in kept.items():
        merged[f"F:{name}"] = rewrite(xml)
        added_functions += 1
    print(f"added {added_functions} prototypes and {added_types} types")
    pack(merged.items(), Path(target))


if __name__ == "__main__":
    main()
