const TEXT = { "content-type": "text/plain; charset=utf-8" };

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
async function pbkdf2(password, salt) {
  const km = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, km, 256);
  return new Uint8Array(bits);
}
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return { pwhash: bytesToHex(await pbkdf2(password, salt)), pwsalt: bytesToHex(salt) };
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
async function verifyPassword(password, pwhash, pwsalt) {
  if (!password || !pwhash || !pwsalt) return false;
  return timingSafeEqual(bytesToHex(await pbkdf2(password, hexToBytes(pwsalt))), pwhash);
}

// ── 사이트 접근 비밀번호(게이트) ─────────────────────────────────────────────
const AUTH_COOKIE = "da_portal_session";
const AUTH_MSG = "da-portal-auth-v1";
const AUTH_MAX_AGE = 60 * 60 * 24 * 180; // 약 180일 동안 재입력 없이 유지

function parseCookies(header) {
  const out = {};
  (header || "").split(";").forEach((part) => {
    const i = part.indexOf("=");
    if (i > -1) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  });
  return out;
}

async function hmacHex(key, message) {
  const k = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(message));
  return bytesToHex(new Uint8Array(sig));
}

// 현재 비밀번호에서 결정되는 세션 토큰(비밀번호를 바꾸면 기존 쿠키는 자동 무효화).
function sessionToken(env) {
  return hmacHex(env.SITE_PASSWORD, AUTH_MSG);
}

async function isAuthed(request, env) {
  const cookie = parseCookies(request.headers.get("cookie"))[AUTH_COOKIE];
  if (!cookie) return false;
  return timingSafeEqual(cookie, await sessionToken(env));
}

// 같은 출처 경로만 허용 — //evil.com 이나 절대 URL로의 오픈 리다이렉트 차단.
function safeNextPath(next) {
  return typeof next === "string" && /^\/(?!\/)/.test(next) ? next : "/";
}

function escAttr(s) {
  return String(s).replace(/[&<>"']/g, (m) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m]));
}

function loginPage(next, isError) {
  const html = `<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>기획 도구 모음 — 로그인</title>
<style>
  :root{--bg:#fff;--surface:#f6f7f9;--text:#1a1d21;--muted:#5b6470;--border:#e6e9ee;--brand:#1257d6}
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Pretendard',system-ui,-apple-system,'Segoe UI',Roboto,'Apple SD Gothic Neo','Noto Sans KR',sans-serif;color:var(--text);background:var(--bg);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
  .login{width:100%;max-width:360px;background:var(--surface);border:1.5px solid var(--border);border-radius:16px;padding:32px 28px}
  h1{font-size:22px;font-weight:800;letter-spacing:-.5px;margin-bottom:8px}
  .sub{color:var(--muted);font-size:14px;margin-bottom:22px}
  input[type=password]{width:100%;font:inherit;font-size:15px;padding:12px 14px;border:1.5px solid var(--border);border-radius:10px;background:#fff;outline:none;transition:border-color .15s}
  input[type=password]:focus{border-color:var(--brand)}
  button{width:100%;margin-top:14px;font:inherit;font-size:15px;font-weight:700;color:#fff;background:var(--brand);border:none;border-radius:10px;padding:12px 14px;cursor:pointer;transition:opacity .15s}
  button:hover{opacity:.92}
  .err{color:#c0392b;font-size:13px;margin-bottom:14px}
</style>
</head>
<body>
  <form class="login" method="POST" action="/__auth">
    <h1>기획 도구 모음</h1>
    <p class="sub">계속하려면 비밀번호를 입력하세요.</p>
    ${isError ? '<p class="err">비밀번호가 올바르지 않습니다.</p>' : ""}
    <input type="password" name="password" placeholder="비밀번호" autocomplete="current-password" autofocus required>
    <input type="hidden" name="next" value="${escAttr(safeNextPath(next))}">
    <button type="submit">입장</button>
  </form>
</body>
</html>`;
  return new Response(html, {
    status: 401,
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
  });
}

async function handleLogin(request, env, url) {
  let form;
  try {
    form = await request.formData();
  } catch {
    return loginPage("/", true);
  }
  const password = String(form.get("password") || "");
  const next = safeNextPath(String(form.get("next") || "/"));
  if (!timingSafeEqual(password, env.SITE_PASSWORD)) {
    return loginPage(next, true);
  }
  const secure = url.protocol === "https:" ? "; Secure" : "";
  const headers = new Headers({ Location: next });
  headers.append(
    "Set-Cookie",
    `${AUTH_COOKIE}=${await sessionToken(env)}; Path=/; Max-Age=${AUTH_MAX_AGE}; HttpOnly; SameSite=Lax${secure}`
  );
  return new Response(null, { status: 303, headers });
}

async function handleResearchApi(request, env, id) {
  if (!env.RESEARCH) return json({ error: "R2 bucket not configured" }, 503);

  // Collection: /api/research
  if (!id) {
    if (request.method === "GET") {
      const listed = await env.RESEARCH.list({ include: ["customMetadata", "httpMetadata"] });
      const items = listed.objects.map((o) => ({
        id: o.key,
        title: o.customMetadata?.title ? decodeURIComponent(o.customMetadata.title) : o.key,
        name: o.customMetadata?.name ? decodeURIComponent(o.customMetadata.name) : o.key,
        size: o.size,
        type: o.httpMetadata?.contentType || "",
        uploaded: o.uploaded,
        uploader: o.customMetadata?.uploader ? decodeURIComponent(o.customMetadata.uploader) : "",
      }));
      items.sort((a, b) => new Date(b.uploaded) - new Date(a.uploaded));
      return json(items);
    }
    if (request.method === "POST") {
      // 업로드 권한은 사이트 비밀번호 게이트로 보호됨 — 별도의 공용 업로드 토큰은 불필요.
      let form;
      try {
        form = await request.formData();
      } catch {
        return json({ error: "expected multipart/form-data" }, 400);
      }
      const file = form.get("file");
      if (!file || typeof file.arrayBuffer !== "function") return json({ error: "missing file" }, 400);
      const password = String(form.get("password") || "");
      if (!password) return json({ error: "file password required" }, 400);
      const name = String(file.name || "untitled");
      const title = String(form.get("title") || name.replace(/\.[^.]+$/, ""));
      const uploader = String(form.get("uploader") || "").slice(0, 40);
      const safe = (name.replace(/[^\w.\-]+/g, "_").slice(-80)) || "file";
      const key = Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 7) + "-" + safe;
      const { pwhash, pwsalt } = await hashPassword(password);
      await env.RESEARCH.put(key, await file.arrayBuffer(), {
        httpMetadata: { contentType: file.type || "application/octet-stream" },
        customMetadata: { title: encodeURIComponent(title), name: encodeURIComponent(name), uploader: encodeURIComponent(uploader), pwhash, pwsalt },
      });
      return json({ id: key, title, name }, 201);
    }
    return json({ error: "method not allowed" }, 405);
  }

  // Item: /api/research/<id>
  if (request.method === "DELETE") {
    const obj = await env.RESEARCH.head(id);
    if (!obj) return new Response(null, { status: 204 }); // already gone
    const provided = request.headers.get("x-file-password") || "";
    const meta = obj.customMetadata || {};
    let ok;
    if (meta.pwhash && meta.pwsalt) {
      // delete requires the per-file password set by the uploader
      ok = await verifyPassword(provided, meta.pwhash, meta.pwsalt);
    } else {
      // legacy item (no per-file password): fall back to the shared upload token
      ok = !!env.UPLOAD_TOKEN && provided === env.UPLOAD_TOKEN;
    }
    if (!ok) return json({ error: "wrong password" }, 403);
    await env.RESEARCH.delete(id);
    return new Response(null, { status: 204 });
  }
  return json({ error: "method not allowed" }, 405);
}

async function serveResearchFile(env, id) {
  if (!env.RESEARCH) return new Response("R2 bucket not configured", { status: 503, headers: TEXT });
  const obj = await env.RESEARCH.get(id);
  if (!obj) return new Response("Not found", { status: 404, headers: TEXT });
  const headers = new Headers();
  obj.writeHttpMetadata(headers);
  headers.set("etag", obj.httpEtag);
  if (!headers.get("content-type")) headers.set("content-type", "application/octet-stream");
  headers.set("x-content-type-options", "nosniff");
  // 다운로드 시 R2 키(랜덤 prefix가 붙은 이름) 대신 업로드 당시의 원본 파일명을 사용한다.
  const meta = obj.customMetadata || {};
  if (meta.name) {
    const original = decodeURIComponent(meta.name);
    const encoded = encodeURIComponent(original);
    const ascii = original.replace(/[^\x20-\x7E]/g, "_").replace(/["\\]/g, "_");
    headers.set("content-disposition", `attachment; filename="${ascii}"; filename*=UTF-8''${encoded}`);
  }
  headers.set("cache-control", "private, max-age=300");
  // Render uploaded content in an opaque origin so it can never read the
  // portal's storage/cookies (protects the saved upload token).
  headers.set(
    "content-security-policy",
    "sandbox allow-scripts allow-popups allow-forms allow-modals allow-downloads"
  );
  return new Response(obj.body, { headers });
}

// ── 접속 로그(D1) ────────────────────────────────────────────────────────────
// 요청마다 IP/브라우저/시각을 남겨, 날짜별 고유 방문자를 집계할 수 있게 한다.
// 날짜 경계는 한국시간(KST, UTC+9) 기준 — "5월 28일"을 사용자가 생각하는 그대로 끊는다.
function kstDay(date) {
  return new Date(date.getTime() + 9 * 3600 * 1000).toISOString().slice(0, 10);
}
function fmtKstTime(iso) {
  if (!iso) return "";
  const k = new Date(new Date(iso).getTime() + 9 * 3600 * 1000);
  const p = (n) => String(n).padStart(2, "0");
  return `${p(k.getUTCHours())}:${p(k.getUTCMinutes())}:${p(k.getUTCSeconds())}`;
}
function shiftDay(day, delta) {
  const d = new Date(day + "T00:00:00Z");
  d.setUTCDate(d.getUTCDate() + delta);
  return d.toISOString().slice(0, 10);
}

// User-Agent 문자열에서 브라우저 종류를 뽑아낸다. 순서 중요(Edge/삼성은 UA에
// "Chrome"을 포함하므로 먼저 가려낸다).
function parseBrowser(ua) {
  if (!ua) return "Unknown";
  if (/bot|crawler|spider|crawling|facebookexternalhit|slurp|bingpreview|monitor/i.test(ua)) return "Bot";
  if (/SamsungBrowser/i.test(ua)) return "Samsung Internet";
  if (/Edg\//i.test(ua)) return "Edge";
  if (/OPR\/|Opera/i.test(ua)) return "Opera";
  if (/Chrome\//i.test(ua) && !/Chromium/i.test(ua)) return "Chrome";
  if (/Firefox\//i.test(ua)) return "Firefox";
  if (/Safari/i.test(ua)) return "Safari";
  return "Other";
}

// 첫 기록 시 한 번만 테이블을 만든다(아이솔레이트당 1회). 이렇게 하면 별도의
// 마이그레이션 실행 없이 D1만 연결해도 바로 동작한다.
let schemaReady = false;
async function ensureSchema(db) {
  if (schemaReady) return;
  await db.exec(
    "CREATE TABLE IF NOT EXISTS access_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, day TEXT NOT NULL, ip TEXT, ua TEXT, browser TEXT, path TEXT, method TEXT, country TEXT)"
  );
  await db.exec("CREATE INDEX IF NOT EXISTS idx_access_day ON access_log(day)");
  schemaReady = true;
}

function logAccess(env, ctx, request, url) {
  if (!env.ACCESS_LOG) return; // D1 미연결 시 무동작
  if (url.pathname.startsWith("/__")) return; // 로그/인증 내부 경로는 기록 제외
  const now = new Date();
  const ua = request.headers.get("user-agent") || "";
  const row = {
    ts: now.toISOString(),
    day: kstDay(now),
    ip: request.headers.get("cf-connecting-ip") || "",
    ua: ua.slice(0, 300),
    browser: parseBrowser(ua),
    path: url.pathname.slice(0, 200),
    method: request.method,
    country: (request.cf && request.cf.country) || request.headers.get("cf-ipcountry") || "",
  };
  // 로깅이 절대 요청을 깨뜨리지 않도록 백그라운드에서 처리하고 오류는 삼킨다.
  ctx.waitUntil(
    (async () => {
      try {
        await ensureSchema(env.ACCESS_LOG);
        await env.ACCESS_LOG.prepare(
          "INSERT INTO access_log (ts,day,ip,ua,browser,path,method,country) VALUES (?,?,?,?,?,?,?,?)"
        )
          .bind(row.ts, row.day, row.ip, row.ua, row.browser, row.path, row.method, row.country)
          .run();
      } catch {
        /* noop */
      }
    })()
  );
}

async function renderLogsPage(env, url) {
  if (!env.ACCESS_LOG) {
    return new Response("ACCESS_LOG D1 바인딩이 설정되지 않았습니다. wrangler.jsonc 참고.", {
      status: 503,
      headers: TEXT,
    });
  }
  await ensureSchema(env.ACCESS_LOG);
  const day = (url.searchParams.get("date") || kstDay(new Date())).slice(0, 10);
  const db = env.ACCESS_LOG;

  const uniq = (await db.prepare("SELECT COUNT(DISTINCT ip) AS n FROM access_log WHERE day=?").bind(day).first()) || { n: 0 };
  const total = (await db.prepare("SELECT COUNT(*) AS n FROM access_log WHERE day=?").bind(day).first()) || { n: 0 };
  const visitors =
    (
      await db
        .prepare(
          "SELECT ip, COUNT(*) AS hits, MIN(ts) AS first_seen, MAX(ts) AS last_seen, " +
            "GROUP_CONCAT(DISTINCT browser) AS browsers, GROUP_CONCAT(DISTINCT country) AS countries " +
            "FROM access_log WHERE day=? GROUP BY ip ORDER BY hits DESC"
        )
        .bind(day)
        .all()
    ).results || [];
  const browsers =
    (
      await db
        .prepare(
          "SELECT browser, COUNT(DISTINCT ip) AS visitors, COUNT(*) AS hits FROM access_log WHERE day=? GROUP BY browser ORDER BY visitors DESC, hits DESC"
        )
        .bind(day)
        .all()
    ).results || [];

  const esc = (s) => escAttr(s == null ? "" : s);
  const visitorRows =
    visitors
      .map(
        (v, i) =>
          `<tr><td>${i + 1}</td><td class="mono">${esc(v.ip) || "(미상)"}</td><td>${esc(v.browsers)}</td><td>${esc(
            v.countries
          )}</td><td class="num">${v.hits}</td><td class="mono">${fmtKstTime(v.first_seen)}</td><td class="mono">${fmtKstTime(
            v.last_seen
          )}</td></tr>`
      )
      .join("") || `<tr><td colspan="7" class="empty">이 날짜에는 접속 기록이 없습니다.</td></tr>`;
  const browserRows =
    browsers
      .map((b) => `<tr><td>${esc(b.browser)}</td><td class="num">${b.visitors}</td><td class="num">${b.hits}</td></tr>`)
      .join("") || `<tr><td colspan="3" class="empty">—</td></tr>`;

  const html = `<!DOCTYPE html>
<html lang="ko"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>접속 로그 — ${esc(day)}</title>
<style>
  :root{--bg:#fff;--surface:#f6f7f9;--text:#1a1d21;--muted:#5b6470;--border:#e6e9ee;--brand:#1257d6}
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:system-ui,-apple-system,'Segoe UI',Roboto,'Apple SD Gothic Neo','Noto Sans KR',sans-serif;color:var(--text);background:var(--bg);padding:28px;max-width:920px;margin:0 auto}
  h1{font-size:22px;font-weight:800;letter-spacing:-.5px;margin-bottom:4px}
  .day{color:var(--muted);font-size:14px;margin-bottom:20px}
  .nav{display:flex;gap:8px;align-items:center;margin-bottom:20px;flex-wrap:wrap}
  .nav a,.nav button{font:inherit;font-size:13px;text-decoration:none;color:var(--text);background:var(--surface);border:1.5px solid var(--border);border-radius:8px;padding:7px 12px;cursor:pointer}
  .nav input[type=date]{font:inherit;font-size:13px;padding:6px 10px;border:1.5px solid var(--border);border-radius:8px}
  .cards{display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap}
  .card{flex:1;min-width:160px;background:var(--surface);border:1.5px solid var(--border);border-radius:12px;padding:16px 18px}
  .card .k{color:var(--muted);font-size:13px;margin-bottom:6px}
  .card .v{font-size:28px;font-weight:800;letter-spacing:-1px}
  h2{font-size:15px;font-weight:700;margin:24px 0 10px}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border)}
  th{color:var(--muted);font-weight:600;font-size:12px}
  td.num,td.mono{font-variant-numeric:tabular-nums}
  td.num{text-align:right}
  .mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
  .empty{color:var(--muted);text-align:center;padding:20px}
</style></head><body>
  <h1>접속 로그</h1>
  <p class="day">${esc(day)} (한국시간 기준)</p>
  <form class="nav" method="GET" action="/__logs">
    <a href="/__logs?date=${esc(shiftDay(day, -1))}">← 이전날</a>
    <input type="date" name="date" value="${esc(day)}">
    <button type="submit">조회</button>
    <a href="/__logs?date=${esc(shiftDay(day, 1))}">다음날 →</a>
    <a href="/__logs?date=${esc(kstDay(new Date()))}">오늘</a>
  </form>
  <div class="cards">
    <div class="card"><div class="k">고유 방문자 (IP 기준)</div><div class="v">${uniq.n}</div></div>
    <div class="card"><div class="k">총 요청 수</div><div class="v">${total.n}</div></div>
  </div>
  <h2>방문자별 (IP 단위로 1명 = 1줄)</h2>
  <table><thead><tr><th>#</th><th>IP</th><th>브라우저</th><th>국가</th><th class="num">요청</th><th>첫 접속</th><th>마지막</th></tr></thead><tbody>${visitorRows}</tbody></table>
  <h2>브라우저별 집계</h2>
  <table><thead><tr><th>브라우저</th><th class="num">방문자</th><th class="num">요청</th></tr></thead><tbody>${browserRows}</tbody></table>
</body></html>`;
  return new Response(html, {
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
  });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // 비밀번호 게이트: SITE_PASSWORD가 설정되면 사이트 전체 접근을 보호한다.
    // 한 번 올바른 비밀번호를 입력하면 세션 쿠키가 남아, 다음 접속부터는 재입력이 필요 없다.
    if (env.SITE_PASSWORD) {
      if (path === "/__auth" && request.method === "POST") {
        return handleLogin(request, env, url);
      }
      if (!(await isAuthed(request, env))) {
        return loginPage(path + (url.search || ""), false);
      }
    }

    // 인증을 통과한 실제 접속만 기록한다(로그인 페이지에서 튕긴 요청은 제외).
    logAccess(env, ctx, request, url);

    // 관리자용 접속 로그 조회 페이지(이미 사이트 비밀번호 게이트로 보호됨)
    if (path === "/__logs" && request.method === "GET") {
      return renderLogsPage(env, url);
    }

    // 루트/포털 페이지는 정적 자산으로 서빙
    if (path === "/" || path === "/index.html") {
      return env.ASSETS.fetch(request);
    }

    // 디자인 시안 미리보기(/mockups/...)도 정적 자산으로 서빙.
    // 이 경로가 없으면 워커가 백엔드로 프록시해 "Not Found"가 떨어진다.
    if (path === "/mockups" || path.startsWith("/mockups/")) {
      // 디렉터리 요청(/mockups, /mockups/)은 index.html로 매핑한다.
      // ASSETS는 정확히 일치하는 키만 찾으므로 슬래시만으로는 404가 난다.
      let assetPath = path;
      if (path === "/mockups" || path === "/mockups/") assetPath = "/mockups/index.html";
      const assetUrl = new URL(request.url);
      assetUrl.pathname = assetPath;
      return env.ASSETS.fetch(new Request(assetUrl, request));
    }

    // 조사 결과물 업로드/목록/삭제 API
    if (path === "/api/research") {
      return handleResearchApi(request, env, null);
    }
    if (path.startsWith("/api/research/")) {
      const id = decodeURIComponent(path.slice("/api/research/".length));
      return handleResearchApi(request, env, id);
    }
    // 업로드된 결과물 열람
    if (path.startsWith("/research/")) {
      const id = decodeURIComponent(path.slice("/research/".length));
      if (!id) return new Response("Not found", { status: 404, headers: TEXT });
      return serveResearchFile(env, id);
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
        headers: TEXT,
      });
    }
  },
};
