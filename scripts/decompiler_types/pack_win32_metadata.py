#!/usr/bin/env python3
"""Development-only: add Microsoft's Win32 metadata to a Windows prototype pack.

usage: pack_win32_metadata.py {x64|x86} DUMP.tsv PACK [--report FILE]

DUMP.tsv comes from scripts/decompiler_types/win32_metadata (a Rust tool that reads
Windows.Win32.winmd). PACK is rewritten in place. Run it after pack_prototypes.py and
supplement_prototypes.py, so everything already in the pack keeps priority: a function or a type
name that the pack has stays as it is, and only what it lacks is added.

Added entries, all in the pack format of pack_prototypes.py:
  F:<function>      prototype in Ghidra's decompiler marshalling XML (model, extrapop and pointer
                    sizes as in the Ghidra-derived entries for the same architecture)
  T:<hex id>        every struct, union, enum, handle typedef and function-pointer typedef of the
                    metadata, whether or not a prototype refers to it; ids start at ID_BASE
  P:<function>      parameter-to-enum association, "<index>=<EnumName>[+]" separated by ';'
                    (+ marks a flag set); parameters keep their integer type
"""
import argparse
import re
import sys
from pathlib import Path

from pack_prototypes import pack
from supplement_prototypes import read_pack

ID_BASE = 0x8000000000100000

PRIMITIVES = {          # name -> (size, builtin name, metatype, attributes); None size = pointer sized
    "bool": (1, "bool", "bool", ""),
    "char16": (2, "wchar_t", "int", ' utf="true"'),
    "i8": (1, "char", "int", ' char="true"'),
    "u8": (1, "uchar", "uint", ' char="true"'),
    "i16": (2, "short", "int", ""),
    "u16": (2, "ushort", "uint", ""),
    "i32": (4, "int", "int", ""),
    "u32": (4, "uint", "uint", ""),
    "i64": (8, "longlong", "int", ""),
    "u64": (8, "ulonglong", "uint", ""),
    "f32": (4, "float", "float", ""),
    "f64": (8, "double", "float", ""),
    "isize": (None, "", "int", ""),
    "usize": (None, "", "uint", ""),
}
# Builtin type ids of Ghidra's Windows archives (see the existing packs); others carry no id.
BUILTIN_IDS = {"int": 0xc000000000000095, "uint": 0xc0000000000000c4, "char": 0xc00000000000007b,
               "uchar": 0xc0000000000000be, "short": 0xc0000000000000a8, "ushort": 0xc0000000000000c8,
               "longlong": 0xc00000000000009a, "ulonglong": 0xc0000000000000c7,
               "float": 0xc00000000000008a, "double": 0xc000000000000082,
               "wchar_t": 0xc0000000000000cd}
ARCH_BIT = {"x86": 1, "x64": 2}


def parse_type(text):
    """'p:p:u8' -> ('p', ('p', ('prim', 'u8'))); 'a8:u8' -> ('a', 8, ...); 'n:ns.Name' -> ('n', 'ns.Name')."""
    if text == "void":
        return ("void",)
    if text.startswith("p:"):
        return ("p", parse_type(text[2:]))
    match = re.match(r"a(\d+):(.*)$", text, re.S)
    if match:
        return ("a", int(match.group(1)), parse_type(match.group(2)))
    if text.startswith("n:"):
        return ("n", text[2:])
    if text in PRIMITIVES:
        return ("prim", text)
    raise ValueError("unknown type " + text)


def xml_escape(text):
    return text.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;")


class Generator:
    def __init__(self, arch, dump, existing):
        self.arch = arch
        self.bit = ARCH_BIT[arch]
        self.ptr = 8 if arch == "x64" else 4
        self.existing = existing
        # Lowest-id existing type of each name: typedefs such as DWORD, HANDLE and LPCWSTR keep the
        # exact types the Ghidra-derived entries use.
        self.old_ids = {}
        for key, value in existing.items():
            if key.startswith("T:"):
                name = value.split("\t", 1)[0]
                ident = int(key[2:], 16)
                if name and ident < 0xc000000000000000 and ident < self.old_ids.get(name, (1 << 64, 0))[0]:
                    self.old_ids[name] = (ident, key)
        self.types = {}          # full name -> record for this architecture
        self.functions = {}      # name -> (dll, record)
        for line in dump:
            fields = line.rstrip("\n").split("\t")
            if fields[0] == "TD":
                arches = int(fields[2])
                if arches & self.bit:
                    self.types.setdefault(fields[1], fields)
            elif fields[0] == "FN":
                arches = int(fields[4])
                if arches & self.bit:
                    name = fields[1]
                    current = self.functions.get(name)
                    if current is None or (fields[2].lower(), fields) < (current[0].lower(), current[1]):
                        self.functions[name] = (fields[2], fields)
        # The metadata's GUID is the CLR's System.Guid; Ghidra's archives call it GUID.
        self.types.setdefault("System.Guid", ["TD", "System.Guid", "7", "struct", "0", "0", "16", "0",
                                              "Data1|u32|", "Data2|u16|", "Data3|u16|", "Data4|a8:u8|"])
        self.layouts = {}
        self.names = {}          # full name -> (emitted name, id, reused)
        self.out = {}            # key -> value
        self.stats = {"types": 0, "reused": 0, "functions": 0, "skipped": 0}
        self.assign_names()

    # ---- names and ids ------------------------------------------------------------------------
    def short(self, full):
        if "/" in full:
            outer, inner = full.split("/", 1)
            return self.short(outer) + inner.replace("/", "_")
        if full == "System.Guid":
            return "GUID"
        return full.rsplit(".", 1)[-1]

    def assign_names(self):
        taken = {}
        counter = ID_BASE
        for full in sorted(self.types, key=lambda f: (self.short(f), f)):
            record = self.types[full]
            kind = record[3]
            name = self.short(full)
            if name in self.old_ids and "/" not in full and kind != "interface":
                self.names[full] = (name, self.old_ids[name][0], True)
                continue
            if kind == "interface" and name in self.old_ids:
                self.names[full] = (name, self.old_ids[name][0], True)
                continue
            unique = name
            if unique in taken:
                unique = f"{name}_{full.split('.')[-2] if '.' in full else 'x'}"
                while unique in taken:
                    unique += "_"
            taken[unique] = full
            self.names[full] = (unique, counter, False)
            counter += 1

    def code_id(self, full):
        """Id of the function type behind a delegate typedef, after every named type."""
        return self.names[full][1] + (1 << 24)

    # ---- layout -------------------------------------------------------------------------------
    def size_align(self, t):
        kind = t[0]
        if kind == "void":
            return 1, 1
        if kind == "prim":
            size = PRIMITIVES[t[1]][0] or self.ptr
            return size, size
        if kind == "p":
            return self.ptr, self.ptr
        if kind == "a":
            size, align = self.size_align(t[2])
            return size * t[1], align
        record = self.types.get(t[1])
        if record is None:
            raise KeyError(t[1])
        return self.type_layout(t[1])

    def type_layout(self, full):
        if full in self.layouts:
            return self.layouts[full]
        record = self.types[full]
        kind = record[3]
        if kind in ("delegate", "interface"):
            result = (self.ptr, self.ptr)
        elif kind == "enum":
            result = self.size_align(parse_type(record[4]))
        elif kind == "typedef":
            members = self.members(record)
            result = self.size_align(parse_type(members[0][1]))
        else:
            self.layouts[full] = (1, 1)       # break cycles; pointers do not reach here
            result = self.struct_layout(record)[:2]
            name, ident, reused = self.names.get(full, ("", 0, False))
            if reused:
                # The existing definition is the one referenced, so its size is the array stride.
                old = self.existing.get(f"T:0x{ident:x}", "")
                for _ in range(8):      # a typedef of a struct: follow it to the struct
                    link = re.fullmatch(r'[^\t]*\t<def [^>]*><typeref name="[^"]*" id="(0x[0-9a-f]+)"/></def>', old)
                    if not link:
                        break
                    old = self.existing.get("T:" + link.group(1), "")
                match = re.search(r'metatype="(?:struct|union)" size="(\d+)"(?: alignment="(\d+)")?', old)
                if match:
                    result = (int(match.group(1)), int(match.group(2) or result[1]))
        self.layouts[full] = result
        return result

    def members(self, record):
        start = 8 if record[3] in ("struct", "typedef") else 0
        out = []
        for item in record[start:]:
            parts = item.split("|")
            out.append((parts[0], parts[1], parts[2] if len(parts) > 2 else ""))
        return out

    def struct_layout(self, record):
        """(size, alignment, [(name, type, offset)]) of a struct or union record."""
        explicit = record[4] == "1"
        pack_size = int(record[5])
        declared = int(record[6])
        offset, align, offsets = 0, 1, []
        for name, text, _bits in self.members(record):
            size, field_align = self.size_align(parse_type(text))
            if pack_size:
                field_align = min(field_align, pack_size)
            align = max(align, field_align)
            if explicit:
                offsets.append((name, text, 0))
                offset = max(offset, size)
            else:
                offset = (offset + field_align - 1) // field_align * field_align
                offsets.append((name, text, offset))
                offset += size
        size = (offset + align - 1) // align * align
        return max(size, declared) or 1, align, offsets

    # ---- XML ----------------------------------------------------------------------------------
    def builtin(self, prim):
        size, name, meta, attrs = PRIMITIVES[prim]
        if size is None:
            size = self.ptr
            name = ("longlong" if size == 8 else "int") if prim == "isize" else ("ulonglong" if size == 8 else "uint")
        ident = BUILTIN_IDS.get(name)
        id_attr = f' id="0x{ident:x}"' if ident else ""
        return f'<type name="{name}"{id_attr} metatype="{meta}" size="{size}"{attrs}/>'

    def ref(self, t, resolve_enum=False):
        """XML of a type used in a field, parameter or return value."""
        kind = t[0]
        if kind == "void":
            return "<void/>"
        if kind == "prim":
            return self.builtin(t[1])
        if kind == "p":
            return f'<type name="" metatype="ptr" size="{self.ptr}">{self.ref(t[1])}</type>'
        if kind == "a":
            size, _ = self.size_align(t[2])
            return f'<type name="" metatype="array" size="{size * t[1]}" arraysize="{t[1]}">{self.ref(t[2])}</type>'
        full = t[1]
        record = self.types.get(full)
        if record is None:
            return f'<type name="" metatype="ptr" size="{self.ptr}"><void/></type>'
        if record[3] == "enum" and resolve_enum:
            return self.ref(parse_type(record[4]))
        name, ident, _ = self.names[full]
        return f'<typeref name="{xml_escape(name)}" id="0x{ident:x}"/>'

    def prototype_xml(self, ret, params, conv, variadic, noreturn, nested=False):
        if nested:
            model, extrapop = "unknown", "8" if self.arch == "x64" else ("4" if conv == "cdecl" else "unknown")
        else:
            model = "__cdecl" if conv == "cdecl" or variadic else "__stdcall"
            extrapop = "8" if self.arch == "x64" else ("4" if model == "__cdecl" else "unknown")
        attrs = f'extrapop="{extrapop}" model="{model}" modellock="true"'
        if not params:
            attrs += ' voidlock="true"'
        if variadic:
            attrs += ' dotdotdot="true"'
        if noreturn:
            attrs += ' noreturn="true"'
        parts = [f"<prototype {attrs}>", f'<returnsym typelock="true"><addr/>{self.ref(ret, True)}</returnsym>']
        parts.append("<internallist>" if nested else '<internallist first="0">')
        for index, (name, t) in enumerate(params):
            label = name if re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", name or "") else f"param_{index + 1}"
            if t[0] == "a":
                t = ("p", t[2])
            parts.append(f'<param name="{label}" typelock="true" namelock="true"><addr/>{self.ref(t, True)}</param>')
        parts.append("</internallist></prototype>")
        return "".join(parts)

    def emit(self, ident, name, xml):
        self.out[f"T:0x{ident:x}"] = f"{name}\t{xml}"
        self.stats["types"] += 1

    def emit_types(self):
        for full, record in self.types.items():
            name, ident, reused = self.names[full]
            kind = record[3]
            if reused:
                self.stats["reused"] += 1
                continue
            n = xml_escape(name)
            if kind == "enum":
                underlying = parse_type(record[4])
                size = PRIMITIVES[underlying[1]][0] or self.ptr
                signed = record[4].startswith("i")
                vals = []
                for item in record[6:]:
                    member, _, value = item.rpartition("=")
                    number = int(value)
                    if not signed and number < 0:
                        number += 1 << (8 * size)
                    vals.append(f'<val name="{xml_escape(member)}" value="{number}"/>')
                meta = "enum_int" if signed else "enum_uint"
                self.emit(ident, name, f'<type name="{n}" id="0x{ident:x}" metatype="{meta}" size="{size}">{"".join(vals)}</type>')
            elif kind == "typedef":
                member = self.members(record)[0]
                t = parse_type(member[1])
                if record[7] == "1" and t[0] == "prim" and t[1] in ("isize", "usize"):
                    t = ("p", ("void",))       # a handle: print it as a pointer
                self.emit(ident, name, f'<def name="{n}" id="0x{ident:x}">{self.ref(t)}</def>')
            elif kind == "delegate":
                conv, ret = record[4], parse_type(record[5])
                params = [(p.split("|")[0], parse_type(p.split("|")[1])) for p in record[6:]]
                proto = self.prototype_xml(ret, params, conv, False, False, nested=True)
                code = f'<type name="_func_{n}" id="0x{self.code_id(full):x}" metatype="code" size="1">{proto}</type>'
                self.emit(ident, name, f'<def name="{n}" id="0x{ident:x}"><type name="" metatype="ptr" size="{self.ptr}">{code}</type></def>')
            elif kind == "interface":
                self.emit(ident, name, f'<type name="{n}" id="0x{ident:x}" metatype="struct" size="{self.ptr}" alignment="{self.ptr}">'
                          f'<field name="lpVtbl" offset="0"><type name="" metatype="ptr" size="{self.ptr}"><void/></type></field></type>')
            else:
                size, align, fields = self.struct_layout(record)
                union = record[4] == "1"
                body = []
                for index, (fname, text, offset) in enumerate(fields):
                    ident_attr = f' id="{index}"' if union else ""
                    body.append(f'<field name="{xml_escape(fname)}" offset="{offset}"{ident_attr}>{self.ref(parse_type(text))}</field>')
                meta = "union" if union else "struct"
                self.emit(ident, name, f'<type name="{n}" id="0x{ident:x}" metatype="{meta}" size="{size}" alignment="{align}">{"".join(body)}</type>')

    def emit_functions(self):
        for name, (dll, fields) in sorted(self.functions.items()):
            conv, flags, ret = fields[3], fields[5], fields[6]
            variadic, noreturn = flags[0] == "1", flags[1] == "1"
            params, associations = [], []
            try:
                for index, item in enumerate(fields[8:]):
                    pname, text, assoc = (item.split("|") + ["", ""])[:3]
                    t = parse_type(text)
                    flag = ""
                    if t[0] == "n" and t[1] in self.types and self.types[t[1]][3] == "enum":
                        enum_name = self.names[t[1]][0]
                        flag = "+" if self.types[t[1]][5] == "1" else ""
                        associations.append(f"{index}={enum_name}{flag}")
                    elif assoc:
                        target = next((f for f in self.types if self.types[f][3] == "enum" and self.short(f) == assoc.split(",")[0].rsplit(".", 1)[-1]), None)
                        if target:
                            associations.append(f"{index}={self.names[target][0]}{'+' if self.types[target][5] == '1' else ''}")
                    params.append((pname, t))
                # The association is kept even where the Ghidra-derived entry has priority.
                if associations:
                    self.out["P:" + name] = ";".join(associations)
                if "F:" + name in self.existing:
                    continue
                xml = self.prototype_xml(parse_type(ret), params, conv, variadic, noreturn)
            except (KeyError, ValueError) as error:
                self.stats["skipped"] += 1
                print(f"skip {name}: {error}", file=sys.stderr)
                continue
            self.out["F:" + name] = xml
            self.stats["functions"] += 1


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("arch", choices=sorted(ARCH_BIT))
    parser.add_argument("dump", type=Path)
    parser.add_argument("pack", type=Path)
    parser.add_argument("--skip", type=Path, help="file listing function names to leave out, one per line")
    args = parser.parse_args()
    existing = read_pack(args.pack)
    dump = args.dump.read_text(encoding="utf-8").splitlines()
    generator = Generator(args.arch, dump, existing)
    if args.skip:
        skipped = {line.strip() for line in args.skip.read_text().splitlines() if line.strip()}
        generator.functions = {k: v for k, v in generator.functions.items() if k not in skipped}
    generator.emit_types()
    generator.emit_functions()
    merged = dict(existing)
    for key, value in generator.out.items():
        merged.setdefault(key, value)
    print(generator.stats)
    pack(merged.items(), args.pack)


if __name__ == "__main__":
    main()
