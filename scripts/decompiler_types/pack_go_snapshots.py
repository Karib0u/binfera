#!/usr/bin/env python3
"""Development-only: pack Ghidra's Go API snapshots into the Go prototype pack.

usage: pack_go_snapshots.py SNAPSHOT_DIR POINTER_SIZE OUTPUT.pack

SNAPSHOT_DIR is Ghidra's `Features/Base/data/typeinfo/golang` (go1.15.0.json ... go1.25.0.json),
POINTER_SIZE 8 (amd64) or 4 (386). The pack has the CXPROTO1 layout of pack_prototypes.py, so the
native bridge reads it with the same code. Keys:

  F:<function>  the Go signature of a standard library function
  N:<type>      which definition a named type has
  D:<hex id>    a type definition, "<name><TAB><xml>"

F and N values are records separated by \\x1f, each "<os>|<first>|<last>|<payload>": <os> is a set of
w (windows), l (linux) and d (darwin), <first> and <last> are Go minor versions (99: every later
release, since the newest snapshot also describes releases Ghidra has none for). Payloads:

  F  "<flags>|<prototype xml>"; flags: n (does not return), m (several results)
  N  "<hex id>" of a D entry

Go's own types are written in Ghidra's decompiler marshalling. A named Go type is referenced by name
only (`<typeref name="os.File"/>`); the bridge resolves the name through N for the binary's version.
A definition holds no id, so identical definitions in several releases share one D entry. Base types
and unnamed composites (`string`, `[]T`, interfaces) are written inline with an explicit id outside
the name-hash range, so a Go `int` (8 bytes) never meets the Windows archive's `int` (4 bytes).

Selection follows Ghidra's GoApiSnapshot: for each operating system, the snapshot's sections are
searched in the order os-arch, os, unix (not on Windows), arch, all. Functions with type parameters
(flag 2) and interface methods (flag 16) are left out, and so is a function whose parameter or result
types cannot all be resolved.
"""
import hashlib, json, os, re, struct, sys, zlib

BLOCK = 96 * 1024
# Larger arrays exist only behind pointers (runtime's `*[1 << 40]T` views); the engine sizes types
# in 32 bits.
MAX_ARRAY = 1 << 28
OSES = {"w": "windows", "l": "linux", "d": "darwin"}
LATEST_OPEN = 99
FLAG_VARARG, FLAG_GENERIC, FLAG_METHOD, FLAG_NORETURN, FLAG_IFACE = 1, 2, 4, 8, 16


class Unresolved(Exception):
    pass


def type_id(text):
    """An explicit id outside Ghidra's name-hash range (0xC000...), stable across runs."""
    digest = hashlib.sha256(text.encode()).digest()
    return 0x4000000000000000 | (int.from_bytes(digest[:8], "little") & 0x3FFFFFFFFFFFFFFF)


def unesc(text):
    return text.replace("&quot;", '"').replace("&gt;", ">").replace("&lt;", "<").replace("&amp;", "&")


def esc(text):
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def split_top(text, sep):
    """Split on `sep` outside brackets, braces and parentheses."""
    parts, depth, start = [], 0, 0
    for i, ch in enumerate(text):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif depth == 0 and text.startswith(sep, i):
            parts.append(text[start:i])
            start = i + len(sep)
    parts.append(text[start:])
    return [p.strip() for p in parts if p.strip()]


def matching(text, start):
    """Index of the bracket closing the one at `start`."""
    depth = 0
    for i in range(start, len(text)):
        if text[i] in "([{":
            depth += 1
        elif text[i] in ")]}":
            depth -= 1
            if depth == 0:
                return i
    raise Unresolved(text)


class Layout:
    """Size, alignment and the XML that references a resolved Go type."""

    def __init__(self, size, align, xml, kind):
        self.size, self.align, self.xml, self.kind = size, align, xml, kind


class Resolver:
    def __init__(self, types, ptr):
        self.types, self.ptr = types, ptr
        self.defs = {}  # name -> (xml definition) for every named type reached
        self.cache = {}
        self.resolving = set()

    def base(self, name, size, meta, align=None):
        ident = type_id(f"go:{name}:{size}:{meta}")
        xml = f'<type name="{esc(name)}" id="0x{ident:x}" metatype="{meta}" size="{size}"/>'
        return Layout(size, align or min(size, self.ptr) or 1, xml, "base")

    def pointer(self, target_xml):
        return Layout(self.ptr, self.ptr, f'<type name="" metatype="ptr" size="{self.ptr}">{target_xml}</type>', "ptr")

    def void_pointer(self):
        return self.pointer("<void/>")

    def inline_struct(self, name, fields):
        """An unnamed composite, written in full with an explicit id."""
        offset, align, body = 0, 1, []
        for field_name, layout in fields:
            offset = (offset + layout.align - 1) // layout.align * layout.align
            if layout.size:
                body.append(f'<field name="{esc(field_name)}" offset="{offset}">{layout.xml}</field>')
            offset += layout.size
            align = max(align, layout.align)
        size = (offset + align - 1) // align * align
        ident = type_id(f"go:{name}:{self.ptr}:" + "".join(body))
        xml = (f'<type name="{esc(name)}" id="0x{ident:x}" metatype="struct" size="{size}" '
               f'alignment="{align}">{"".join(body)}</type>')
        return Layout(size, align, xml, "struct")

    BUILTIN_INTS = {
        "bool": (1, "bool"), "int8": (1, "int"), "uint8": (1, "uint"), "byte": (1, "uint"),
        "int16": (2, "int"), "uint16": (2, "uint"), "int32": (4, "int"), "uint32": (4, "uint"),
        "rune": (4, "int"), "int64": (8, "int"), "uint64": (8, "uint"),
        "float32": (4, "float"), "float64": (8, "float"),
    }

    def resolve(self, text):
        text = text.strip()
        if text in self.cache:
            return self.cache[text]
        layout = self._resolve(text)
        self.cache[text] = layout
        return layout

    def _resolve(self, text):
        ptr = self.ptr
        if text in self.BUILTIN_INTS:
            size, meta = self.BUILTIN_INTS[text]
            name = {"byte": "uint8", "rune": "int32"}.get(text, text)
            return self.base(name, size, meta)
        if text in ("int", "uint", "uintptr"):
            return self.base(text, ptr, "uint" if text != "int" else "int")
        if text in ("complex64", "complex128"):
            half = self.resolve("float32" if text == "complex64" else "float64")
            return self.inline_struct(text, [("real", half), ("imag", half)])
        if text == "string":
            return self.inline_struct("string", [("str", self.pointer(self.resolve("uint8").xml)),
                                                 ("len", self.resolve("int"))])
        if text in ("unsafe.Pointer",):
            return self.void_pointer()
        if text.startswith("..."):
            return self.resolve("[]" + text[3:])
        if text.startswith("*"):
            return self.pointer(self.reference(text[1:]))
        if text.startswith("[]"):
            elem = text[2:]
            return self.inline_struct(text, [("array", self.pointer(self.reference(elem))),
                                             ("len", self.resolve("int")), ("cap", self.resolve("int"))])
        if text.startswith("["):
            close = matching(text, 0)
            count = text[1:close]
            if not count.isdigit():
                raise Unresolved(text)
            count = int(count)
            elem = self.resolve(text[close + 1:])
            if count * elem.size > MAX_ARRAY:
                raise Unresolved(text)
            if count == 0 or elem.size == 0:
                return Layout(0, elem.align, "", "empty")
            xml = (f'<type name="" metatype="array" size="{count * elem.size}" '
                   f'arraysize="{count}">{elem.xml}</type>')
            return Layout(count * elem.size, elem.align, xml, "array")
        if text.startswith(("map[", "chan ", "<-chan ", "chan<- ", "chan(", "func(", "func (")):
            return self.void_pointer()
        if text.startswith("interface"):
            body = text[text.index("{") + 1:text.rindex("}")].strip() if "{" in text else ""
            return self.interface("interface {}" if not body else text, empty=not body)
        if text.startswith("struct"):
            if "{" not in text:
                raise Unresolved(text)
            body = text[text.index("{") + 1:text.rindex("}")]
            fields = []
            for i, decl in enumerate(split_top(body, ";")):
                decl = re.sub(r'\s+"[^"]*"$', "", decl)  # struct tags
                names = split_top(decl, " ")
                if len(names) == 1:  # embedded
                    fields.append((names[0].lstrip("*").split(".")[-1], self.resolve(names[0])))
                else:
                    field_type = self.resolve(" ".join(names[1:]))
                    for field_name in names[0].split(","):
                        fields.append((field_name.strip() or f"_{i}", field_type))
            return self.inline_struct(text, fields)
        if text in ("error", "any"):
            return self.interface(text, empty=(text == "any"))
        return self.named(text)

    def interface(self, name, empty):
        first = "_type" if empty else "tab"
        return self.inline_struct(name, [(first, self.void_pointer()), ("data", self.void_pointer())])

    def reference(self, text):
        """XML for a pointer's target: named types by name, so their definitions load lazily."""
        text = text.strip()
        if text in self.resolving:
            # A struct that points back at one being defined: its definition is on the way.
            return f'<typeref name="{esc(text)}"/>'
        if self.is_named(text):
            try:
                return self.named(text).xml or "<void/>"
            except Unresolved:
                return "<void/>"
        try:
            layout = self.resolve(text)
        except Unresolved:
            if text.startswith("[") and "]" in text:
                return self.reference(text[matching(text, 0) + 1:])  # a huge array: its element
            return "<void/>"
        return layout.xml or "<void/>"

    def is_named(self, text):
        return text in self.types

    def named(self, name):
        definition = self.types.get(name)
        if definition is None:
            raise Unresolved(name)
        if name in self.cache:
            return self.cache[name]
        kind = definition.get("Kind")
        if definition.get("TypeParams"):
            raise Unresolved(name)
        if kind == "alias":
            target = self.resolve(definition["Target"])
            if target.kind == "base":
                xml = f'<def name="{esc(name)}">{target.xml}</def>'
                self.defs[name] = (xml, target.size, target.align)
                layout = Layout(target.size, target.align, f'<typeref name="{esc(name)}"/>', "base")
            else:
                layout = target
            self.cache[name] = layout
            return layout
        if kind == "iface":
            layout = self.interface(name, empty=False)
            self.cache[name] = layout
            return layout
        if kind == "funcdef":
            layout = self.void_pointer()
            self.cache[name] = layout
            return layout
        if kind != "struct":
            raise Unresolved(name)
        if name in self.resolving:
            raise Unresolved(name)  # a by-value cycle cannot exist in Go; be safe anyway
        self.resolving.add(name)
        try:
            offset, align, body = 0, 1, []
            for i, field in enumerate(definition.get("Fields") or []):
                field_type = field["DataType"]
                layout = self.resolve(field_type)
                offset = (offset + layout.align - 1) // layout.align * layout.align
                if layout.size:
                    field_name = field.get("Name") or field_type.lstrip("*").split(".")[-1]
                    if field_name == "_":
                        field_name = f"_{i}"
                    body.append(f'<field name="{esc(field_name)}" offset="{offset}">{layout.xml}</field>')
                offset += layout.size
                align = max(align, layout.align)
            size = (offset + align - 1) // align * align
        finally:
            self.resolving.discard(name)
        if size == 0:
            layout = Layout(0, 1, "", "empty")
        else:
            xml = (f'<type name="{esc(name)}" metatype="struct" size="{size}" '
                   f'alignment="{align}">{"".join(body)}</type>')
            self.defs[name] = (xml, size, align)
            layout = Layout(size, align, f'<typeref name="{esc(name)}"/>', "struct")
        self.cache[name] = layout
        return layout


def prototype(resolver, name, funcdef):
    """The prototype XML of one function, or None when a type does not resolve."""
    flags = funcdef.get("Flags") or 0
    if flags & (FLAG_GENERIC | FLAG_IFACE) or funcdef.get("TypeParams"):
        return None
    params = []
    try:
        for i, p in enumerate(funcdef.get("Params") or []):
            layout = resolver.resolve(p["DataType"])
            if layout.size == 0:
                continue  # occupies no storage
            pname = p.get("Name") or ("self" if i == 0 and flags & FLAG_METHOD else f"param_{i + 1}")
            if pname == "_":
                pname = f"param_{i + 1}"
            params.append((pname, layout))
        results = []
        for i, r in enumerate(funcdef.get("Results") or []):
            layout = resolver.resolve(r["DataType"])
            if layout.size == 0:
                continue
            results.append((r.get("Name") or f"~r{i}", layout))
    except Unresolved:
        return None
    marks = "n" if flags & FLAG_NORETURN else ""
    if not results:
        out = "<void/>"
    elif len(results) == 1:
        out = results[0][1].xml
    else:
        marks += "m"
        out = resolver.inline_struct(name + "_multivalue_return_type", results).xml
    body = "".join(
        f'<param name="{esc(pname)}" typelock="true" namelock="true"><addr/>{layout.xml}</param>'
        for pname, layout in params)
    xml = (f'<prototype extrapop="unknown" model="default" modellock="true">'
           f'<returnsym typelock="true"><addr/>{out}</returnsym>'
           f'<internallist first="-1">{body}</internallist></prototype>')
    return marks + "|" + xml


def sections_for(snapshot, os_name, arch):
    order = [f"{os_name}-{arch}", os_name] + (["unix"] if os_name != "windows" else []) + [arch, "all"]
    funcs, types = {}, {}
    for key in reversed(order):  # earlier keys win
        section = snapshot.get(key) or {}
        funcs.update(section.get("Funcs") or {})
        types.update(section.get("Types") or {})
    return funcs, types


def main():
    snapshot_dir, ptr, dst = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    arch = {8: "amd64", 4: "386"}[ptr]
    versions = sorted(
        (int(m.group(1)), os.path.join(snapshot_dir, f))
        for f in os.listdir(snapshot_dir) if (m := re.fullmatch(r"go1\.(\d+)\.0\.json", f)))
    newest = versions[-1][0]
    # (key, payload) -> {os letter -> set of minors}
    seen = {}
    definitions = {}
    for minor, path in versions:
        snapshot = json.load(open(path, encoding="utf-8"))
        for letter, os_name in OSES.items():
            if os_name == "darwin" and arch == "386":
                continue
            funcs, types = sections_for(snapshot, os_name, arch)
            resolver = Resolver(types, ptr)
            payloads = {}
            for fname, funcdef in funcs.items():
                payload = prototype(resolver, fname, funcdef)
                if payload is not None:
                    payloads[fname] = payload
            # A pointer to a struct that was still being defined is written as a reference; if that
            # definition failed after all, the pointer points at nothing known.
            defined = set(resolver.defs)
            dangling = lambda xml: re.sub(
                r'<typeref name="([^"]*)"/>',
                lambda m: m.group(0) if unesc(m.group(1)) in defined else "<void/>", xml)
            for fname, payload in payloads.items():
                seen.setdefault(("F:" + fname, dangling(payload)), {}).setdefault(letter, set()).add(minor)
            for tname, (xml, size, align) in resolver.defs.items():
                xml = dangling(xml)
                ident = type_id(f"def:{ptr}:{xml}")
                definitions[ident] = (tname, xml)
                seen.setdefault(("N:" + tname, f"{ident:x}"), {}).setdefault(letter, set()).add(minor)
        print(f"go1.{minor}: {len(seen)} records, {len(definitions)} definitions", file=sys.stderr)
    records = {}
    for (key, payload), by_os in seen.items():
        # Group the operating systems that share the same versions; split versions into runs.
        groups = {}
        for letter, minors in by_os.items():
            groups.setdefault(tuple(sorted(minors)), []).append(letter)
        for minors, letters in groups.items():
            runs, start, prev = [], None, None
            for minor in minors:
                if start is None:
                    start = prev = minor
                elif minor == prev + 1:
                    prev = minor
                else:
                    runs.append((start, prev)); start = prev = minor
            runs.append((start, prev))
            for first, last in runs:
                last = LATEST_OPEN if last == newest else last
                records.setdefault(key, []).append(f"{''.join(sorted(letters))}|{first}|{last}|{payload}")
    entries = [(key, "\x1f".join(sorted(values))) for key, values in records.items()]
    entries += [(f"D:{ident:x}", f"{name}\t{xml}") for ident, (name, xml) in definitions.items()]
    entries.sort()
    blocks, cur, size = [], [], 0
    for key, value in entries:
        raw = f"{key}\t{value}\n".encode("utf-8")
        if cur and size + len(raw) > BLOCK:
            blocks.append(cur); cur, size = [], 0
        cur.append((key, raw)); size += len(raw)
    if cur:
        blocks.append(cur)
    index, data = [], bytearray()
    for block in blocks:
        raw = b"".join(r for _, r in block)
        comp = zlib.compress(raw, 9)
        index.append((len(data), len(comp), len(raw), block[0][0].encode()))
        data += comp
    with open(dst, "wb") as out:
        out.write(b"CXPROTO1" + struct.pack("<I", len(index)))
        for off, clen, rlen, key in index:
            out.write(struct.pack("<IIIH", off, clen, rlen, len(key)) + key)
        out.write(data)
    functions = sum(1 for key, _ in entries if key.startswith("F:"))
    print(f"{functions} functions, {len(definitions)} definitions, {len(entries)} entries, "
          f"{len(blocks)} blocks, {os.path.getsize(dst)} bytes")


main()
