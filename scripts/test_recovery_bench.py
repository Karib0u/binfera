"""Checks for scripts/bench/recovery.py's diff and scoring logic, using only the stdlib."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "bench"))

from recovery import (  # noqa: E402
    aggregate_tier_b,
    census,
    covering_region,
    diff_starts,
    parse_start_record,
    read_allow_removed,
    score_tier_b,
    sniff_format,
    split_allowed,
    tier_b_truth,
)


def evidence(seeds, chained=None, regions=None, names=None):
    return {
        "seeds": {address: set(kinds) for address, kinds in seeds.items()},
        "chained": chained or {},
        "regions": regions or {},
        "names": names or {},
    }


class DiffTests(unittest.TestCase):
    def test_added_and_removed_are_sorted_set_differences(self):
        self.assertEqual(diff_starts([3, 1, 2], [4, 2, 1, 0]), ([0, 4], [3]))

    def test_identical_inventories_differ_in_nothing(self):
        self.assertEqual(diff_starts([1, 2], [2, 1]), ([], []))

    def test_allow_list_accepts_addresses_and_wildcards(self):
        allowed = read_allow_removed(
            "# comment\nsub dir/a.exe_ 0x10  # why\nb.elf *\n\nsub dir/a.exe_ 32\n"
        )
        self.assertEqual(allowed, {"sub dir/a.exe_": {0x10, 32}, "b.elf": {"*"}})
        self.assertEqual(split_allowed("sub dir/a.exe_", [0x10, 0x11], allowed), ([0x11], [0x10]))
        self.assertEqual(split_allowed("b.elf", [1, 2], allowed), ([], [1, 2]))
        self.assertEqual(split_allowed("c", [5], allowed), ([5], []))

    def test_allow_list_line_needs_an_address(self):
        with self.assertRaises(ValueError):
            read_allow_removed("0x10\n")

    def test_start_record_keys_become_integers(self):
        parsed = parse_start_record(
            {
                "type": "start",
                "functions": [20, 10],
                "names": {"10": "main"},
                "arch": "x86_64",
                "evidence": {
                    "seeds": {"10": ["Unwind"], "30": ["EhFrame"]},
                    "chained_unwind": {"15": 10},
                    "regions": {"10": 40},
                    "names": {"30": "f.cold"},
                },
            }
        )
        self.assertEqual(parsed["starts"], [10, 20])
        ev = parsed["evidence"]
        self.assertEqual(ev["seeds"], {10: {"Unwind"}, 30: {"EhFrame"}})
        self.assertEqual(ev["chained"], {15: 10})
        self.assertEqual(ev["regions"], {10: 40})
        self.assertEqual(ev["names"], {10: "main", 30: "f.cold"})

    def test_record_without_evidence_has_none(self):
        self.assertIsNone(parse_start_record({"functions": []})["evidence"])

    def test_format_sniffing(self):
        self.assertEqual(sniff_format(b"MZ\x90\x00"), "PE")
        self.assertEqual(sniff_format(b"\x7fELF"), "ELF")
        self.assertEqual(sniff_format(b"\xcf\xfa\xed\xfe"), "Mach-O")
        self.assertEqual(sniff_format(b"\xca\xfe\xba\xbe"), "Mach-O")
        self.assertEqual(sniff_format(b"\x00\x00"), "other")


class TierBTests(unittest.TestCase):
    def test_table_kinds_are_truth_and_other_kinds_are_not(self):
        truth, fragments = tier_b_truth(
            evidence({1: ["Unwind", "CallTarget"], 2: ["IncrementalTarget"], 3: ["CallTarget"]})
        )
        self.assertEqual(truth, {1: {"pdata"}, 2: {"ilt"}})
        self.assertEqual(fragments, {})

    def test_chained_fragment_is_a_fragment_and_its_primary_is_truth(self):
        truth, fragments = tier_b_truth(evidence({}, chained={0x50: 0x10}))
        self.assertEqual(truth, {0x10: {"pdata"}})
        self.assertEqual(fragments, {0x50: "chained"})

    def test_funclets_and_cold_parts_are_fragments(self):
        truth, fragments = tier_b_truth(
            evidence(
                {
                    1: ["Unwind", "MsvcException"],
                    2: ["Unwind", "MsvcException", "IncrementalTarget"],
                    3: ["EhFrame"],
                },
                names={3: "parse.cold"},
            )
        )
        # An exception target that the incremental-link table also names is a function.
        self.assertEqual(truth, {2: {"pdata", "ilt"}})
        self.assertEqual(fragments, {1: "funclet", 3: "cold"})

    def test_score_counts_recall_fragments_and_interior_starts(self):
        ev = evidence(
            {0x10: ["Unwind"], 0x40: ["Unwind"], 0x60: ["Unwind", "MsvcException"]},
            chained={0x30: 0x10},
            regions={0x10: 0x30, 0x30: 0x38, 0x40: 0x58, 0x60: 0x70},
        )
        # 0x20 is inside 0x10's row; 0x30 is the chained fragment; 0x90 is outside every row.
        score = score_tier_b([0x10, 0x20, 0x30, 0x90], ev)
        self.assertEqual((score["truth"], score["found"], score["missed"]), (2, 1, [0x40]))
        self.assertEqual(score["sources"], {"pdata": {"truth": 2, "found": 1}})
        self.assertEqual(score["fragments"]["chained"], {"total": 1, "listed": 1})
        self.assertEqual(score["fragments"]["funclet"], {"total": 1, "listed": 0})
        self.assertEqual(score["starts_in_regions"], 3)
        self.assertEqual(score["interior"], [0x20])

    def test_covering_region_handles_nesting(self):
        regions = sorted({0x100: 0x200, 0x120: 0x130, 0x300: 0x310}.items())
        self.assertEqual(covering_region(regions, 0x125), (0x120, 0x130))
        self.assertEqual(covering_region(regions, 0x150), (0x100, 0x200))
        self.assertIsNone(covering_region(regions, 0x200))
        self.assertIsNone(covering_region(regions, 0x50))

    def test_aggregate_groups_by_format_and_arch_and_skips_files_without_truth(self):
        a = score_tier_b([1], evidence({1: ["Unwind"], 2: ["Unwind"]}))
        b = score_tier_b([5], evidence({5: ["EhFrame"]}))
        empty = score_tier_b([9], evidence({}))
        groups = aggregate_tier_b(
            [("PE", "x86_64", a), ("ELF", "x86_64", b), ("PE", "i386", empty)]
        )
        self.assertEqual(list(groups), ["ELF x86_64", "PE x86_64", "all"])
        self.assertEqual(groups["PE x86_64"]["recall"], 0.5)
        self.assertEqual(groups["all"]["files"], 2)
        self.assertEqual((groups["all"]["truth"], groups["all"]["found"]), (3, 2))
        self.assertEqual(
            groups["all"]["sources"],
            {"eh_frame": {"truth": 1, "found": 1}, "pdata": {"truth": 2, "found": 1}},
        )


class CensusTests(unittest.TestCase):
    def test_census_counts_binaries_listed_and_sole_evidence(self):
        table = census(
            [
                ([1, 2, 3], evidence({1: ["Unwind", "CallTarget"], 2: ["CallTarget"], 7: ["Prologue"]})),
                ([5], evidence({5: ["CallTarget"]})),
            ]
        )
        self.assertEqual(table["CallTarget"], {"binaries": 2, "seeded": 3, "listed": 3, "only": 2})
        self.assertEqual(table["Unwind"], {"binaries": 1, "seeded": 1, "listed": 1, "only": 0})
        self.assertEqual(table["(none)"], {"binaries": 1, "seeded": 0, "listed": 1, "only": 1})
        self.assertEqual(table["Prologue"], {"binaries": 0, "seeded": 1, "listed": 0, "only": 0})


if __name__ == "__main__":
    unittest.main()
