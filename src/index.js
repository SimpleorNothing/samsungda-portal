const ROUTES = [
  { prefix: "/report",      key: "REPORT_UPSTREAM",      rewrite: null },
  { prefix: "/webauto",     key: "WEBAUTO_UPSTREAM",     rewrite: p => "/admin" + (p.slice("/webauto".length) || "/") },
  { prefix: "/agent-guide", key: "AGENT_GUIDE_UPSTREAM", rewrite: null },
  { prefix: "/mi",          key: "MI_UPSTREAM",          rewrite: null },
  { prefix: "/2030",        key: "UPSTREAM_2030",        rewrite: null },
];

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    for (const route of ROUTES) {
      if (path.startsWith(route.prefix)) {
        const upstream = env[route.key];
        if (!upstream) return new Response(`Upstream not configured: ${route.key}`, { status: 502 });
        const upstreamPath = route.rewrite ? route.rewrite(path) : path;
        return proxyTo(request, upstream, upstreamPath, url.search);
      }
    }

    return env.ASSETS.fetch(request);  // / 및 정적 자산
  }
};

async function proxyTo(request, upstream, path, search) {
  const target = upstream.replace(/\/$/, "") + path + (search || "");
  const headers = new Headers(request.headers);
  headers.delete("host");
  return fetch(target, {
    method: request.method,
    headers,
    redirect: "follow",
    body: ["GET","HEAD"].includes(request.method) ? null : request.body,
  });
}
