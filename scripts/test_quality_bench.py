"""Checks for scripts/bench/quality.py's counting and baseline logic, using only the stdlib."""

import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
for sub in ("bench", "decompiler_types", "."):
    sys.path.insert(0, str(HERE / sub))

import coverage  # noqa: E402
import quality  # noqa: E402


class IndirectCalls(unittest.TestCase):
    def test_counts_calls_through_a_dereference(self):
        text = """
        x = (*DAT_00436014)(a, b);
        (**(code **)(iVar1 + 8))(iVar1);
        if ((*pcVar3)() != 0) { y = (code *)p; }
        z = (*q);
        _File = (FILE *)(*PTR_FUN_0042c110)(1);
        """
        self.assertEqual(quality.indirect_call_sites(text),
                         ["*DAT_00436014", "**(code **)(iVar1 + 8)", "*pcVar3", "*PTR_FUN_0042c110"])

    def test_a_cast_or_a_name_is_not_an_indirect_call(self):
        self.assertEqual(quality.indirect_call_sites("f((int)(*p)); g(x)(1); h = (code *)(1); k(*p)(2);"), [])

    def test_a_wrapped_argument_list_is_still_a_call(self):
        text = "  (iVar6 = (**(code **)(*piStackX_8 + 0x50))\n                     (piStackX_8,0), x);"
        self.assertEqual(quality.indirect_call_sites(text), ["**(code **)(*piStackX_8 + 0x50)"])

    def test_an_unbalanced_tail_is_ignored(self):
        self.assertEqual(quality.indirect_call_sites("x = (*p"), [])


class NumericArguments(unittest.TestCase):
    ENUMS = {"VirtualAlloc": {2: "VIRTUAL_ALLOCATION_TYPE", 3: "PAGE_PROTECTION_FLAGS"},
             "CreateFileA": {2: "FILE_SHARE_MODE"}}

    def test_counts_non_zero_numbers_at_enum_parameters(self):
        text = "p = VirtualAlloc(0,0x1000,0x3000,0x40); q = VirtualAlloc(0, n, MEM_COMMIT, PAGE_READWRITE);"
        hits = quality.numeric_api_arguments(text, self.ENUMS)
        self.assertEqual([(f, i, v) for f, i, v, _ in hits],
                         [("VirtualAlloc", 2, 0x3000), ("VirtualAlloc", 3, 0x40)])

    def test_zero_and_other_parameters_are_not_counted(self):
        self.assertEqual(quality.numeric_api_arguments("VirtualAlloc(0x400000,0x1000,0,0);", self.ENUMS), [])

    def test_a_module_prefix_and_a_cast_are_read_through(self):
        hits = quality.numeric_api_arguments('h = kernel32_CreateFileA("f",(DWORD)1,(DWORD)3,0,3,0,0);', self.ENUMS)
        self.assertEqual([(f, i, v) for f, i, v, _ in hits], [("CreateFileA", 2, 3)])

    def test_commas_inside_strings_and_calls_do_not_split_arguments(self):
        hits = quality.numeric_api_arguments('CreateFileA(f(1, 2), "a,b", 7);', self.ENUMS)
        self.assertEqual([(f, i, v) for f, i, v, _ in hits], [("CreateFileA", 2, 7)])


class Parsing(unittest.TestCase):
    def test_metrics_of_a_decompile_all_stream(self):
        lines = [
            json.dumps({"type": "start", "functions": [1, 2, 3]}),
            json.dumps({"type": "function", "address": 1, "text": "x = (*DAT_1)(a);",
                        "warnings": ["Unknown callee prototype: x. Uncertain calls (2): 0x1 -> f"]}),
            json.dumps({"type": "function", "address": 2, "error": "boom"}),
            json.dumps({"type": "function", "address": 3, "error": "deadline", "retry_pending": True}),
            json.dumps({"type": "function", "address": 3, "text": "return;", "warnings": []}),
            json.dumps({"type": "done"}),
        ]
        parsed = quality.parse_decompile_all(lines)
        self.assertEqual((parsed["functions"], parsed["errors"], parsed["indirect_calls"],
                          parsed["unknown_callee_calls"]), (3, 1, 1, 2))


class Baseline(unittest.TestCase):
    NOW = {"a": {"untyped_imports": 3, "indirect_calls": 5, "unknown_callee_calls": 1, "numeric_api_args": 0, "errors": 0}}

    def test_equal_or_lower_passes(self):
        baseline = {"a": {"untyped_imports": 3, "indirect_calls": 6, "unknown_callee_calls": 1, "numeric_api_args": 0, "errors": 0}}
        failures, improvements = quality.check_against_baseline(baseline, self.NOW)
        self.assertEqual(failures, [])
        self.assertEqual(improvements, ["a: indirect_calls 6 -> 5"])

    def test_a_higher_count_fails(self):
        baseline = {"a": {"untyped_imports": 2, "indirect_calls": 5, "unknown_callee_calls": 1, "numeric_api_args": 0, "errors": 0}}
        failures, _ = quality.check_against_baseline(baseline, self.NOW)
        self.assertEqual(failures, ["a: untyped_imports 2 -> 3"])

    def test_a_sample_missing_either_side_fails(self):
        failures, _ = quality.check_against_baseline({}, self.NOW)
        self.assertEqual(len(failures), 1)
        failures, _ = quality.check_against_baseline({"b": {}}, {})
        self.assertEqual(failures, ["b: in the baseline but not measured"])


class UntypedImports(unittest.TestCase):
    def test_causes_split(self):
        imports = [{"dll": "KERNEL32.dll", "name": "CreateFileA"}, {"dll": "KERNEL32.dll", "name": "Nope"},
                   {"dll": "weird.dll", "name": "CreateFileA"}, {"dll": "pdh.dll", "name": "PdhOpenQueryA"}, {"name": ""}]
        names = {"CreateFileA", "PdhOpenQueryA"}
        self.assertEqual(coverage.untyped_imports(imports, names, {"kernel32", "pdh"}),
                         [("kernel32", "Nope", "no_prototype"), ("weird", "CreateFileA", "module_not_listed")])

    def test_the_allow_list_is_read_from_source(self):
        source = 'fn system_import_function(n: &str) { const MODULES: &[&str] = &[ "a", // c\n "b" ]; }'
        self.assertEqual(coverage.allowed_modules(source), {"a", "b"})


if __name__ == "__main__":
    unittest.main()
