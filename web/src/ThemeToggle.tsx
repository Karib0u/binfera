import { useTheme } from "./theme";

/** Light or dark, remembered on this device. The first visit follows the system setting. */
export default function ThemeToggle() {
  const [theme, flip] = useTheme();
  const dark = theme === "dark";
  return (
    <button className="ghost theme-toggle" onClick={flip} aria-label={dark ? "Switch to light mode" : "Switch to dark mode"} title={dark ? "Switch to light mode" : "Switch to dark mode"}>
      <svg viewBox="0 0 24 24" aria-hidden>
        {dark
          ? <><circle cx="12" cy="12" r="4" /><path d="M12 3v2M12 19v2M3 12h2M19 12h2M5.6 5.6l1.4 1.4M17 17l1.4 1.4M5.6 18.4L7 17M17 7l1.4-1.4" /></>
          : <path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z" />}
      </svg>
    </button>
  );
}
