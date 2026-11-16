import type { CodeView } from "./location";

export interface PanePlace { address: number; cursor: number | null }
export interface Pane { id: number; view: CodeView; place: PanePlace | null }
export type Axis = "vertical" | "horizontal";
export type DropSide = "left" | "right" | "top" | "bottom" | "center";
export type PaneTree = Pane | { axis: Axis; ratio: number; first: PaneTree; second: PaneTree };

export function panesIn(tree: PaneTree): Pane[] {
  return "view" in tree ? [tree] : [...panesIn(tree.first), ...panesIn(tree.second)];
}

/** Existing multi-pane links open in a balanced layout. */
export function treeOf(panes: Pane[], axis: Axis = "vertical"): PaneTree {
  if (panes.length === 1) return panes[0];
  const mid = Math.ceil(panes.length / 2), next = axis === "vertical" ? "horizontal" : "vertical";
  return { axis, ratio: .5, first: treeOf(panes.slice(0, mid), next), second: treeOf(panes.slice(mid), next) };
}

export function updatePane(tree: PaneTree, id: number, update: (pane: Pane) => PaneTree): PaneTree {
  if ("view" in tree) return tree.id === id ? update(tree) : tree;
  return { ...tree, first: updatePane(tree.first, id, update), second: updatePane(tree.second, id, update) };
}

export function withoutPane(tree: PaneTree, id: number): PaneTree | null {
  if ("view" in tree) return tree.id === id ? null : tree;
  const first = withoutPane(tree.first, id), second = withoutPane(tree.second, id);
  return !first ? second : !second ? first : { ...tree, first, second };
}

export function splitPane(tree: PaneTree, id: number, added: Pane, axis: Axis): PaneTree {
  return updatePane(tree, id, (pane) => ({ axis, ratio: .5, first: pane, second: added }));
}

/** Drop on an edge to dock there; drop in the middle to swap two panes. */
export function movePane(tree: PaneTree, sourceId: number, targetId: number, side: DropSide): PaneTree {
  if (sourceId === targetId) return tree;
  const panes = panesIn(tree), source = panes.find((p) => p.id === sourceId), target = panes.find((p) => p.id === targetId);
  if (!source || !target) return tree;
  if (side === "center") {
    const swap = (node: PaneTree): PaneTree => "view" in node
      ? node.id === sourceId ? target : node.id === targetId ? source : node
      : { ...node, first: swap(node.first), second: swap(node.second) };
    return swap(tree);
  }
  const remaining = withoutPane(tree, sourceId)!;
  return updatePane(remaining, targetId, (pane) => ({
    axis: side === "left" || side === "right" ? "vertical" : "horizontal", ratio: .5,
    first: side === "left" || side === "top" ? source : pane,
    second: side === "left" || side === "top" ? pane : source,
  }));
}

/** Which dock a point inside a pane means: the middle swaps, otherwise the nearest edge; no dead zones. */
export function dropSideAt(x: number, y: number): DropSide {
  const dx = x - .5, dy = y - .5;
  if (Math.abs(dx) < .18 && Math.abs(dy) < .18) return "center";
  return Math.abs(dx) > Math.abs(dy) ? (dx < 0 ? "left" : "right") : (dy < 0 ? "top" : "bottom");
}
