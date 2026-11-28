import { useEffect, useState } from "react";
import { desktop } from "./project/client";

const CACHE_KEY = "binfera-github-stars";
const CACHE_MS = 60 * 60 * 1000;

function remembered(): number | null {
  try {
    const hit = JSON.parse(localStorage.getItem(CACHE_KEY) ?? "null");
    return hit && Date.now() - hit.at < CACHE_MS && Number.isFinite(hit.stars) ? hit.stars : null;
  } catch {
    return null;
  }
}

/** The repository's star count, served by the site's Worker. The desktop app never asks: it makes no network calls of its own. */
function useStars(): number | null {
  const [stars, setStars] = useState(remembered);
  useEffect(() => {
    if (desktop) return;
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), 4000);
    fetch("/api/github-meta", { headers: { Accept: "application/json" }, cache: "no-store", signal: ctl.signal })
      .then((r) => (r.ok ? r.json() : null))
      .then((meta) => {
        const n = Number(meta?.stars);
        if (meta?.stars == null || !Number.isFinite(n)) return;
        setStars(n);
        try { localStorage.setItem(CACHE_KEY, JSON.stringify({ stars: n, at: Date.now() })); } catch { /* best effort */ }
      })
      .catch(() => {})
      .finally(() => clearTimeout(timer));
    return () => { clearTimeout(timer); ctl.abort(); };
  }, []);
  return stars;
}

const short = (n: number) => (n >= 1000 ? `${(n / 1000).toFixed(1).replace(/\.0$/, "")}k` : String(n));

/** The GitHub link with the live star count, the way most open-source sites show it. Without a count it is a plain "GitHub" link. */
export default function GitHubStars({ repo }: { repo: string }) {
  const stars = useStars();
  const known = stars !== null && stars > 0;
  return (
    <a className="lp-gh" href={repo} target="_blank" rel="noreferrer" title="binfera on GitHub" aria-label={known ? `binfera on GitHub, ${stars} stars` : "binfera on GitHub"}>
      <svg className="lp-gh-mark" viewBox="0 0 24 24" aria-hidden>
        <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z" />
      </svg>
      {known
        ? <><svg className="lp-gh-star" viewBox="0 0 24 24" aria-hidden><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z" /></svg><span>{short(stars)}</span></>
        : <span>GitHub</span>}
    </a>
  );
}
