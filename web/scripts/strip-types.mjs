// Turns a TypeScript source into plain ES module JavaScript for the check scripts.
// Node's built-in type stripping replaces the TypeScript compiler API, which
// TypeScript 7 no longer ships.
import { stripTypeScriptTypes } from "node:module";

export const stripTypes = (source) => stripTypeScriptTypes(source, { mode: "strip" });
