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
  // 스킴이 없으면 https:// 보정 (대시보드에 host만 넣은 경우 방지)
  const base = (/^https?:\/\//i.test(upstream) ? upstream : "https://" + upstream).replace(/\/$/, "");
  const target = base + path + (search || "");
  const headers = new Headers(request.headers);
  headers.delete("host");
  try {
    return await fetch(target, {
      method: request.method,
      headers,
      redirect: "follow",
      body: ["GET","HEAD"].includes(request.method) ? null : request.body,
    });
  } catch (err) {
    // 1101로 죽는 대신 원인을 노출
    return new Response(`Upstream fetch failed\ntarget: ${target}\nerror: ${err}`, {
      status: 502,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }
}
