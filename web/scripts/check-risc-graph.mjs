import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { stripTypes } from "./strip-types.mjs";
const source = await fs.readFile(new URL("../src/graph.ts", import.meta.url), "utf8");
const compiled = stripTypes(source);
const { rowFlow, buildCfg } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString("base64")}`);
const flow = (text, arch = "arm") => rowFlow([0x1000, "00000000", text], arch);
assert.equal(flow("mov r0, pc").kind, "none");
assert.equal(flow("mov pc, lr").kind, "ret");
assert.equal(flow("bxeq lr").kind, "cond");
assert.equal(flow("popeq {r7, pc}").kind, "cond");
assert.equal(flow("blx 0x2000").target, 0x2000);
for (const arch of ["mips", "mipsel"]) {
  for (const likely of [false, true]) {
    const rows = [
      [0x1000, "00000000", `${likely ? "beql" : "beq"} $a0, $zero, 0x1010`],
      [0x1004, "00000000", "addiu $v0, $zero, 5"],
      [0x1008, "00000000", "jr $ra"],
      [0x100c, "00000000", "nop"],
      [0x1010, "00000000", "jr $ra"],
      [0x1014, "00000000", "nop"],
    ];
    const cfg = buildCfg(rows, arch);
    const branch = cfg.blocks[0];
    const slot = cfg.blocks.find(b => b.rows.some(r => r[0] === 0x1004));
    assert.equal(slot.id !== branch.id, likely);
    const edges = cfg.edges.filter(e => e.from === branch.id);
    assert.ok(edges.some(e => e.kind === "false" && cfg.blocks[e.to].addr === 0x1008));
    assert.ok(edges.some(e => e.kind === "true" && cfg.blocks[e.to].addr === (likely ? 0x1004 : 0x1010)));
    assert.ok(!cfg.edges.some(e => cfg.blocks[e.from].addr === 0x1008));
  }
}
console.log("ARM transfers and both MIPS delay-slot graph forms: passed");
