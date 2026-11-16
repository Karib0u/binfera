"""Preserve exported archive facts when extending the generated packs."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

TYPE_SCRIPTS = Path(__file__).resolve().parent / "decompiler_types"
sys.path.insert(0, str(TYPE_SCRIPTS))
from pack_prototypes import pack
from supplement_prototypes import read_pack


class PrototypeSupplementTests(unittest.TestCase):
    def test_existing_entries_win_and_regeneration_is_identical(self):
        original = {"F:dlsym": "original prototype", "T:0x1": "original type"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.pack"
            pack(original.items(), path)
            command = [sys.executable, str(TYPE_SCRIPTS / "supplement_prototypes.py"),
                       "linux", "8", str(path)]
            subprocess.run(command, check=True, capture_output=True)
            result = read_pack(path)
            self.assertEqual({key: result[key] for key in original}, original)
            self.assertIn("F:__stack_chk_fail", result)
            first = path.read_bytes()
            subprocess.run(command, check=True, capture_output=True)
            self.assertEqual(path.read_bytes(), first)


if __name__ == "__main__":
    unittest.main()
