export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // 루트/포털 페이지는 정적 자산으로 서빙
    if (path === "/" || path === "/index.html") {
      return env.ASSETS.fetch(request);
    }

    // 그 외 모든 경로는 백엔드(Railway)로 경로 그대로 프록시
    const upstream = env.BACKEND_UPSTREAM;
    if (!upstream) return new Response("BACKEND_UPSTREAM not set", { status: 502 });

    const target = upstream.replace(/\/$/, "") + path + (url.search || "");
    const headers = new Headers(request.headers);
    headers.delete("host");
    try {
      return await fetch(target, {
        method: request.method,
        headers,
        redirect: "follow",
        body: ["GET", "HEAD"].includes(request.method) ? null : request.body,
      });
    } catch (err) {
      return new Response(`Upstream fetch failed\ntarget: ${target}\nerror: ${err}`, {
        status: 502,
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    }
  }
};
