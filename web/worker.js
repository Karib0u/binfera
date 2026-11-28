const REPO = "Karib0u/binfera";
// GitHub allows 60 unauthenticated requests an hour per IP, so the count is fetched at most every 10 minutes
// per edge location, and the last real one is kept for a month to cover rate limits and outages.
const FRESH_SECONDS = 10 * 60;
const LAST_GOOD_SECONDS = 30 * 24 * 60 * 60;
const FRESH_KEY = "https://binfera.internal/api/github-meta";
const LAST_GOOD_KEY = "https://binfera.internal/api/github-meta/last-good";

const json = (body, cacheControl) => new Response(JSON.stringify(body), {
  headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": cacheControl },
});

/** Outside Cloudflare (the dev server) there is no edge cache: keep the same answers in memory for as long. */
const memory = new Map();
const memoryCache = {
  match: async (key) => { const hit = memory.get(key); return hit && hit.until > Date.now() ? hit.res.clone() : undefined; },
  put: async (key, res) => { memory.set(key, { res, until: Date.now() + Number(/max-age=(\d+)/.exec(res.headers.get("Cache-Control"))?.[1] ?? 0) * 1000 }); },
};

async function cached(cache, key) {
  try {
    const hit = await cache?.match(key);
    return hit ? await hit.json() : null;
  } catch {
    return null;
  }
}

async function fetchStars(token) {
  const headers = { Accept: "application/vnd.github+json", "User-Agent": "binfera-site", "X-GitHub-Api-Version": "2022-11-28" };
  if (token) headers.Authorization = `Bearer ${token}`;
  try {
    const res = await fetch(`https://api.github.com/repos/${REPO}`, { headers });
    if (!res.ok) return null;
    const stars = Number((await res.json()).stargazers_count);
    return Number.isFinite(stars) && stars >= 0 ? stars : null;
  } catch {
    return null;
  }
}

/** The repository's star count for the landing page: `{ stars }`, or `{ stars: null }` when GitHub can't say. */
async function githubMeta(env, ctx) {
  const cache = globalThis.caches?.default ?? memoryCache;
  // Browsers always ask again; freshness is the edge cache's job.
  const client = "private, no-store";
  const fresh = await cached(cache, FRESH_KEY);
  if (fresh) return json(fresh, client);

  const stars = await fetchStars(env.GITHUB_TOKEN);
  if (stars === null) return json((await cached(cache, LAST_GOOD_KEY)) ?? { stars: null }, client);

  const body = { stars };
  const store = Promise.all([
    cache.put(FRESH_KEY, json(body, `public, max-age=${FRESH_SECONDS}`)),
    cache.put(LAST_GOOD_KEY, json(body, `public, max-age=${LAST_GOOD_SECONDS}`)),
  ]).catch(() => {});
  if (ctx?.waitUntil) ctx.waitUntil(store); else await store;
  return json(body, client);
}

export default {
  async fetch(request, env, ctx) {
    const path = new URL(request.url).pathname;
    if (path === "/api/github-meta") return githubMeta(env, ctx);
    const response = await env.ASSETS.fetch(request);
    if (!path.startsWith("/assets/")) return response;
    const headers = new Headers(response.headers);
    headers.set("Cache-Control", response.status === 404
      ? "no-store"
      : response.ok || response.status === 304 ? "public, max-age=31536000, immutable" : "no-store");
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
  },
};
