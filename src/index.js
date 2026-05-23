export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // 루트만 포털 정적 페이지
    if (path === "/" || path === "/index.html") {
      return env.ASSETS.fetch(request);
    }

    // 그 외 전부 Railway(report-site)로 프록시
    const upstream = env.REPORT_UPSTREAM;
    if (!upstream) return new Response("REPORT_UPSTREAM not set", { status: 502 });

    const target = upstream.replace(/\/$/, "") + path + (url.search || "");
    const headers = new Headers(request.headers);
    headers.delete("host");
    return fetch(target, {
      method: request.method,
      headers,
      redirect: "follow",
      body: ["GET","HEAD"].includes(request.method) ? null : request.body,
    });
  }
};
