import { useEffect, useSyncExternalStore } from "react";
import type { ImageInfo } from "../engine/image";
import type { Analysis } from "../types";
import { packRows, type BuildRequest, type ListingIndex, type ListingModel } from "./model";

type Input = Pick<Analysis, "functions" | "strings" | "settled">;
type Snapshot = ListingModel | "failed" | null;

/** One worker and row index for all Listing panes showing the same analysis. */
class ListingStore {
  private listeners = new Set<() => void>();
  private snapshot: Snapshot = null;
  private input: Input | null = null;
  private indexed: Input | null = null;
  private worker: Worker | null = null;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private busy = false;
  private lastBuild = -Infinity;

  constructor(private image: ImageInfo) {}

  getSnapshot = () => this.snapshot;

  subscribe = (listener: () => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
      if (!this.listeners.size) this.stop();
    };
  };

  update(input: Input) {
    this.input = input;
    this.schedule();
  }

  private schedule() {
    if (!this.input || !this.listeners.size || this.busy || this.timer !== null) return;
    // While records are streaming in, batch updates to leave resources for decompilation.
    const delay = this.input.settled ? 0 : Math.max(0, 300 - (performance.now() - this.lastBuild));
    this.timer = setTimeout(() => {
      this.timer = null;
      this.build();
    }, delay);
  }

  private stop() {
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
    this.worker?.terminate();
    this.worker = null;
    this.busy = false;
  }

  private publish(snapshot: Snapshot) {
    this.snapshot = snapshot;
    for (const listener of this.listeners) listener();
  }

  private build() {
    const input = this.input!;
    const previous = this.indexed;
    if (previous?.strings === input.strings && previous.functions === input.functions) return;

    const changed = [];
    for (const [fn, f] of input.functions) {
      const before = previous?.functions.get(fn);
      if (f.asm?.length && (f.asm !== before?.asm || f.labels !== before?.labels)) changed.push(fn);
    }
    const removed = [];
    for (const [fn, f] of previous?.functions ?? []) {
      if (f.asm?.length && !input.functions.get(fn)?.asm?.length) removed.push(fn);
    }
    if (previous?.strings === input.strings && !changed.length && !removed.length) {
      this.indexed = input;
      return;
    }

    try {
      const initial = !this.worker;
      const worker = this.worker ?? new Worker(new URL("./listing.worker.ts", import.meta.url), { type: "module" });
      this.worker = worker;
      this.busy = true;
      this.lastBuild = performance.now();
      worker.onmessage = ({ data }: MessageEvent<ListingIndex>) => {
        if (this.worker !== worker) return;
        this.busy = false;
        this.indexed = input;
        this.publish({ ...data, functions: input.functions });
        if (this.input !== input) this.schedule();
      };
      worker.onerror = worker.onmessageerror = () => {
        if (this.worker === worker) this.fail();
      };
      const request: BuildRequest = { changes: [] };
      const keys = initial ? [...input.functions.keys()] : changed;
      const size = keys.reduce((sum, fn) => sum + (input.functions.get(fn)?.asm?.length ?? 0) * 2, 0);
      // Transfer one buffer for the batch, leaving the assembly text in the UI.
      const packed = new Float64Array(size);
      let offset = 0;
      for (const fn of keys) {
        const { asm, labels } = input.functions.get(fn)!;
        if (!asm?.length) continue;
        const end = offset + asm.length * 2;
        const rows = packed.subarray(offset, end);
        packRows(asm, rows);
        request.changes.push([fn, { rows, labels }]);
        offset = end;
      }
      if (initial) {
        const { regions, sections, imports, details, ptrSize } = this.image;
        request.image = { regions, sections, imports, structures: details?.structures, ptrSize };
      } else {
        for (const fn of removed) request.changes.push([fn, null]);
      }
      if (initial || previous?.strings !== input.strings) request.strings = input.strings;
      worker.postMessage(request, [packed.buffer]);
    } catch {
      this.fail();
    }
  }

  private fail() {
    this.stop();
    this.publish("failed");
    this.indexed = null;
  }
}

const stores = new WeakMap<ImageInfo, ListingStore>();
const noSnapshot = () => null;
const noSubscribe = () => () => {};

export function useListing({ image, functions, strings, settled }: Analysis): Snapshot {
  let store = image ? stores.get(image) : undefined;
  if (image && !store) {
    store = new ListingStore(image);
    stores.set(image, store);
  }
  const snapshot = useSyncExternalStore(store?.subscribe ?? noSubscribe, store?.getSnapshot ?? noSnapshot, noSnapshot);
  useEffect(() => {
    store?.update({ functions, strings, settled });
  }, [store, functions, strings, settled]);
  return snapshot;
}
