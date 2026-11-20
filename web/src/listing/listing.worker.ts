import type { StringEntry } from "../types";
import { buildIndex, type BuildRequest, type ListingImage, type PackedFunction } from "./model";

let image: ListingImage;
let strings: StringEntry[] = [];
const functions = new Map<number, PackedFunction>();

self.addEventListener("message", ({ data }: MessageEvent<BuildRequest>) => {
  if (data.image) image = data.image;
  if (data.strings) strings = data.strings;
  for (const [fn, f] of data.changes) {
    if (f) functions.set(fn, f);
    else functions.delete(fn);
  }
  const index = buildIndex(image, strings, functions);
  self.postMessage(index, { transfer: [index.starts.buffer] });
});
