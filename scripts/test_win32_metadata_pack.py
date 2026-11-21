"""The Win32 metadata generator keeps existing pack entries, lays structures out per architecture
and records parameter-to-enum associations."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

TYPE_SCRIPTS = Path(__file__).resolve().parent / "decompiler_types"
sys.path.insert(0, str(TYPE_SCRIPTS))
from pack_prototypes import pack
from supplement_prototypes import read_pack

NS = "Windows.Win32"
DUMP = "\n".join([
    # FN name dll conv arches flags ret ns params...   (param = name|type|associated enum)
    f"FN\tOldCall\tX.dll\tstdcall\t7\t00\tvoid\t{NS}\ta|u32|",
    f"FN\tNewCall\tX.dll\tstdcall\t7\t00\tn:{NS}.HANDLE\t{NS}\tflags|n:{NS}.MODE|\tname|p:u8|\tout|p:n:{NS}.POINTISH|",
    f"FN\tWide\tX.dll\tstdcall\t7\t00\tvoid\t{NS}\tv|isize|\tw|n:{NS}.OLD_STRUCT|",
    f"FN\tChatty\tX.dll\tcdecl\t7\t10\ti32\t{NS}\tfmt|p:u8|",
    # TD name arches kind ...
    f"TD\t{NS}.MODE\t7\tenum\tu32\t1\tFIRST=1\tSECOND=2",
    f"TD\t{NS}.HANDLE\t7\ttypedef\t0\t0\t0\t1\tValue|isize|",
    f"TD\t{NS}.OLD_STRUCT\t7\tstruct\t0\t0\t0\t0\tx|u8|",
    f"TD\t{NS}.POINTISH\t7\tstruct\t0\t0\t0\t0\tc|u8|\tp|p:void|\tn|u16|",
    f"TD\t{NS}.UNIONISH\t7\tstruct\t1\t0\t0\t0\ta|u8|\tb|u64|",
]) + "\n"


class Win32MetadataPackTests(unittest.TestCase):
    def generate(self, arch, directory):
        directory = Path(directory)
        dump = directory / "dump.tsv"
        dump.write_text(DUMP)
        path = directory / f"{arch}.pack"
        pack({"F:OldCall": "original prototype", "T:0x1\tHANDLE": "x",
              "T:0x8000000000000002": "OLD_STRUCT\told type"}.items(), path)
        command = [sys.executable, str(TYPE_SCRIPTS / "pack_win32_metadata.py"), arch, str(dump), str(path)]
        subprocess.run(command, check=True, capture_output=True)
        return path, command

    def type_named(self, entries, name):
        return next(v.split("\t", 1)[1] for k, v in entries.items() if k.startswith("T:") and v.split("\t")[0] == name)

    def test_priority_layout_associations_and_idempotence(self):
        for arch, word in (("x64", 8), ("x86", 4)):
            with tempfile.TemporaryDirectory() as directory:
                path, command = self.generate(arch, directory)
                entries = read_pack(path)
                self.assertEqual(entries["F:OldCall"], "original prototype")
                self.assertIn("F:NewCall", entries)
                self.assertEqual(entries["P:NewCall"], "0=MODE+")
                # Fields with natural alignment: u8, then a pointer, then u16.
                point = self.type_named(entries, "POINTISH")
                self.assertIn(f'size="{3 * word if word == 8 else 12}"', point)
                self.assertIn(f'<field name="p" offset="{word}">', point)
                # Existing types are referenced, not replaced.
                self.assertNotIn("OLD_STRUCT\t", "".join(v for k, v in entries.items() if k.startswith("T:0x8000000000100")))
                union = self.type_named(entries, "UNIONISH")
                self.assertIn('metatype="union" size="8"', union)
                self.assertIn('<field name="b" offset="0" id="1">', union)
                self.assertIn('dotdotdot="true"', entries["F:Chatty"])
                self.assertIn('model="__cdecl"', entries["F:Chatty"])
                first = path.read_bytes()
                subprocess.run(command, check=True, capture_output=True)
                self.assertEqual(path.read_bytes(), first)


if __name__ == "__main__":
    unittest.main()
