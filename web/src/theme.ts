import { useEffect, useState } from "react";

export type Theme = "light" | "dark";
const KEY = "binfera.theme";

/** The choice the person made, if any. Until they choose, the system setting decides. */
export function storedTheme(): Theme | null {
  try { const v = localStorage.getItem(KEY); return v === "light" || v === "dark" ? v : null; } catch { return null; }
}
const system = (): Theme => (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");

/** Applies the choice to the page and tells canvases that read CSS colours to repaint. */
export function applyTheme(theme: Theme | null) {
  const root = document.documentElement;
  if (theme) root.dataset.theme = theme; else delete root.dataset.theme;
  const color = getComputedStyle(root).getPropertyValue("--panel").trim();
  document.querySelectorAll('meta[name="theme-color"]').forEach((m) => m.setAttribute("content", color || (theme === "dark" ? "#141211" : "#fafaf9")));
  window.dispatchEvent(new Event("binfera-theme"));
}

export function chooseTheme(theme: Theme) {
  try { localStorage.setItem(KEY, theme); } catch { /* the choice lasts for this visit only */ }
  applyTheme(theme);
}

/** The theme in effect, and a way to flip it between light and dark. */
export function useTheme(): [Theme, () => void] {
  const [theme, setTheme] = useState<Theme>(() => storedTheme() ?? system());
  useEffect(() => {
    const sync = () => setTheme(storedTheme() ?? system());
    window.addEventListener("binfera-theme", sync);
    const mq = matchMedia("(prefers-color-scheme: dark)");
    mq.addEventListener("change", sync);
    return () => { window.removeEventListener("binfera-theme", sync); mq.removeEventListener("change", sync); };
  }, []);
  return [theme, () => chooseTheme(theme === "dark" ? "light" : "dark")];
}
