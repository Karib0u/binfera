export default {
  async fetch(request, env) {
    const response = await env.ASSETS.fetch(request);
    if (!new URL(request.url).pathname.startsWith("/assets/")) return response;
    const headers = new Headers(response.headers);
    headers.set("Cache-Control", response.status === 404
      ? "no-store"
      : response.ok || response.status === 304 ? "public, max-age=31536000, immutable" : "no-store");
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
  },
};
