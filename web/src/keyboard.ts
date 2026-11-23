import { useEffect } from "react";

/**
 * Mirrors the on-screen keyboard into CSS: `--kb` is how far it covers the bottom of the page and
 * `--vvh` the height left above it. Phones do not shrink the layout viewport for a keyboard, so a
 * sheet or search box pinned to the bottom or middle would otherwise sit behind it.
 */
export function useKeyboardInset() {
  useEffect(() => {
    const vv = window.visualViewport;
    if (!vv) return;
    const root = document.documentElement;
    const update = () => {
      root.style.setProperty("--kb", Math.max(0, Math.round(window.innerHeight - vv.height - vv.offsetTop)) + "px");
      root.style.setProperty("--vvh", Math.round(vv.height) + "px");
    };
    update();
    vv.addEventListener("resize", update);
    vv.addEventListener("scroll", update);
    return () => {
      vv.removeEventListener("resize", update);
      vv.removeEventListener("scroll", update);
      root.style.removeProperty("--kb");
      root.style.removeProperty("--vvh");
    };
  }, []);
}
