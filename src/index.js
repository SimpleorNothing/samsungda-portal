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

// samsungda.net 영역에서는 서브도메인 간 세션 공유를 위해 Domain=.samsungda.net 으로
// 쿠키를 발급한다(예: agentguide.samsungda.net 도 같은 로그인 세션을 인식). 로컬
// (localhost)·*.workers.dev 미리보기에서는 Domain을 생략해 쿠키 거부를 피한다.
function cookieDomainAttr(hostname) {
  return hostname === "samsungda.net" || hostname.endsWith(".samsungda.net")
    ? "; Domain=.samsungda.net"
    : "";
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
<link rel="stylesheet" as="style" crossorigin href="https://cdn.jsdelivr.net/gh/orioncactus/pretendard@v1.3.9/dist/web/static/pretendard.min.css">
<style>
  :root{--bg:#fff;--surface:#f6f7f9;--text:#1a1d21;--muted:#5b6470;--border:#e6e9ee;--brand:#1257d6}
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:"Pretendard",-apple-system,BlinkMacSystemFont,"Apple SD Gothic Neo","Malgun Gothic",sans-serif;color:var(--text);background:var(--bg);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
  .login{width:100%;max-width:360px;background:var(--surface);border:1.5px solid var(--border);border-radius:16px;padding:32px 28px}
  h1{font-size:22px;font-weight:800;letter-spacing:-.5px;margin-bottom:8px}
  .sub{color:var(--muted);font-size:15px;margin-bottom:22px}
  input[type=password]{width:100%;font:inherit;font-size:15px;padding:12px 14px;border:1.5px solid var(--border);border-radius:10px;background:#fff;outline:none;transition:border-color .15s}
  input[type=password]:focus{border-color:var(--brand)}
  button{width:100%;margin-top:14px;font:inherit;font-size:15px;font-weight:700;color:#fff;background:var(--brand);border:none;border-radius:10px;padding:12px 14px;cursor:pointer;transition:opacity .15s}
  button:hover{opacity:.92}
  .err{color:#c0392b;font-size:15px;margin-bottom:14px}
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
    `${AUTH_COOKIE}=${await sessionToken(env)}; Path=/; Max-Age=${AUTH_MAX_AGE}; HttpOnly; SameSite=Lax${cookieDomainAttr(url.hostname)}${secure}`
  );
  return new Response(null, { status: 303, headers });
}

// ── 이동된 페이지 안내 ───────────────────────────────────────────────────────
// 위치가 변경된 경로(/report, /mi, /2030, /quickshare 등)에 접근하면
// 안내 문구를 보여준 뒤 5초 카운트다운 후 자동으로 메인(samsungda.net)으로 이동한다.
// "바로 이동" 버튼으로 즉시 이동할 수도 있다.
const MOVED_PAGES = new Set(["/report", "/mi", "/2030", "/quickshare"]);

function movedPage() {
  const html = `<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>페이지 위치가 변경되었습니다 — 기획 도구 모음</title>
<link rel="stylesheet" as="style" crossorigin href="https://cdn.jsdelivr.net/gh/orioncactus/pretendard@v1.3.9/dist/web/static/pretendard.min.css">
<style>
  :root{--bg:#fff;--surface:#f6f7f9;--text:#1a1d21;--muted:#5b6470;--border:#e6e9ee;--brand:#1257d6}
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:"Pretendard",-apple-system,BlinkMacSystemFont,"Apple SD Gothic Neo","Malgun Gothic",sans-serif;color:var(--text);background:var(--bg);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
  .box{width:100%;max-width:420px;background:var(--surface);border:1.5px solid var(--border);border-radius:16px;padding:36px 30px;text-align:center}
  h1{font-size:24px;font-weight:800;letter-spacing:-.5px;margin-bottom:12px}
  .sub{color:var(--muted);font-size:15px;line-height:1.65;margin-bottom:24px}
  .count{font-weight:700;color:var(--brand)}
  .actions{display:flex;gap:10px;justify-content:center;flex-wrap:wrap}
  a.btn{font:inherit;font-size:15px;font-weight:700;text-decoration:none;border-radius:10px;padding:12px 20px;cursor:pointer;transition:opacity .15s,border-color .15s,background .15s}
  a.primary{color:#fff;background:var(--brand);border:1.5px solid var(--brand)}
  a.primary:hover{opacity:.92}
  a.ghost{color:var(--text);background:#fff;border:1.5px solid var(--border)}
  a.ghost:hover{border-color:var(--brand);color:var(--brand)}
</style>
</head>
<body>
  <div class="box">
    <h1>페이지 위치가 변경되었습니다</h1>
    <p class="sub">요청하신 페이지의 위치가 변경되었습니다.<br><span class="count" id="count">5</span>초 후 메인 페이지로 자동 이동합니다.</p>
    <div class="actions">
      <a class="btn primary" id="go" href="/">바로 이동</a>
    </div>
  </div>
<script>
  (function(){
    var DEST = "/";
    var n = 5;
    var el = document.getElementById("count");
    var timer = setInterval(function(){
      n -= 1;
      if (n <= 0) { clearInterval(timer); window.location.replace(DEST); return; }
      el.textContent = n;
    }, 1000);
    document.getElementById("go").addEventListener("click", function(e){
      e.preventDefault();
      clearInterval(timer);
      window.location.replace(DEST);
    });
  })();
</script>
</body>
</html>`;
  return new Response(html, {
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
  });
}

async function handleResearchApi(request, env, id) {
  if (!env.RESEARCH) return json({ error: "R2 bucket not configured" }, 503);

  // Collection: /api/research
  if (!id) {
    if (request.method === "GET") {
      const listed = await env.RESEARCH.list({ include: ["customMetadata", "httpMetadata"] });
      // report-idea의 아이디어 뱅크(idea-bank/ prefix)는 같은 버킷을 공유하지만
      // 이 파일 목록의 대상이 아니다. report-idea가 직접 CRUD하며 파일별 삭제
      // 비밀번호가 없어 여기선 삭제할 수도 없으므로 목록에서 제외한다.
      const items = listed.objects
        .filter((o) => !o.key.startsWith("idea-bank/"))
        .map((o) => ({
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
<link rel="stylesheet" as="style" crossorigin href="https://cdn.jsdelivr.net/gh/orioncactus/pretendard@v1.3.9/dist/web/static/pretendard.min.css">
<style>
  :root{--bg:#fff;--surface:#f6f7f9;--text:#1a1d21;--muted:#5b6470;--border:#e6e9ee;--brand:#1257d6}
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:"Pretendard",-apple-system,BlinkMacSystemFont,"Apple SD Gothic Neo","Malgun Gothic",sans-serif;color:var(--text);background:var(--bg);padding:28px;max-width:920px;margin:0 auto}
  h1{font-size:22px;font-weight:800;letter-spacing:-.5px;margin-bottom:4px}
  .day{color:var(--muted);font-size:15px;margin-bottom:20px}
  .nav{display:flex;gap:8px;align-items:center;margin-bottom:20px;flex-wrap:wrap}
  .nav a,.nav button{font:inherit;font-size:15px;text-decoration:none;color:var(--text);background:var(--surface);border:1.5px solid var(--border);border-radius:8px;padding:7px 12px;cursor:pointer}
  .nav input[type=date]{font:inherit;font-size:15px;padding:6px 10px;border:1.5px solid var(--border);border-radius:8px}
  .cards{display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap}
  .card{flex:1;min-width:160px;background:var(--surface);border:1.5px solid var(--border);border-radius:12px;padding:16px 18px}
  .card .k{color:var(--muted);font-size:15px;margin-bottom:6px}
  .card .v{font-size:28px;font-weight:800;letter-spacing:-1px}
  h2{font-size:15px;font-weight:700;margin:24px 0 10px}
  table{width:100%;border-collapse:collapse;font-size:15px}
  th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border)}
  th{color:var(--muted);font-weight:600;font-size:15px}
  td.num,td.mono{font-variant-numeric:tabular-nums}
  td.num{text-align:right}
  .mono{font-family:"Pretendard",-apple-system,BlinkMacSystemFont,"Apple SD Gothic Neo","Malgun Gothic",sans-serif}
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

// ── 산하 도구 투명 프록시 ────────────────────────────────────────────────────
// 예전에는 /us10y·/webauto 도 BACKEND_UPSTREAM(report-site)로 넘어가 report-site가
// 다시 각 upstream으로 리버스 프록시했다. 이제 포털이 곧장 각 upstream으로 보내
// report-site 홉을 제거한다. 업스트림의 3xx(트레일링 슬래시 정규화 등)는 브라우저가
// 처리하도록 manual로 흘려보낸다.
async function proxyPass(request, target) {
  const headers = new Headers(request.headers);
  headers.delete("host");
  try {
    const resp = await fetch(target, {
      method: request.method,
      headers,
      redirect: "manual",
      body: ["GET", "HEAD"].includes(request.method) ? null : request.body,
    });
    // 불변(immutable) 헤더를 수정 가능하도록 새 Response로 복제해 반환.
    return new Response(resp.body, {
      status: resp.status,
      statusText: resp.statusText,
      headers: resp.headers,
    });
  } catch (err) {
    return new Response(`Upstream fetch failed\ntarget: ${target}\nerror: ${err}`, {
      status: 502,
      headers: TEXT,
    });
  }
}


// ── 업데이트 내역(/version.json) — 커밋 이력에서 자동 생성 ─────────────────
// 배포마다 index.html의 내역을 손으로 고칠 필요 없이, GitHub 커밋 메시지의
// 첫 줄이 그대로 "업데이트 내역"이 된다(update-badge.js가 이 JSON을 읽음).
//  - 제외: Merge/chore 커밋, 메시지에 [skip-log]가 포함된 커밋
//  - 표시 정리: "type(scope):" 접두어와 "(#PR번호)" 꼬리표 제거
//  - 엣지 캐시 5분(GitHub API 무인증 한도 보호). GITHUB_TOKEN 시크릿이 있으면 사용.
const LOG_REPO = "SimpleorNothing/samsungda-portal";
const LOG_LIMIT = 40;

function cleanCommitSummary(line) {
  let s = (line || "").trim();
  s = s.replace(/^[a-z]+(\([^)]*\))?!?:\s*/i, ""); // conventional commit 접두어
  s = s.replace(/\s*\(#\d+\)\s*$/, "");            // PR 번호 꼬리표
  return s.trim();
}

async function handleVersionJson(request, env, ctx) {
  const cache = caches.default;
  const cacheKey = new Request("https://samsungda-portal.internal/version.json");
  const hit = await cache.match(cacheKey);
  if (hit) return hit;

  let log = [];
  try {
    const headers = {
      "user-agent": "samsungda-portal-update-badge",
      accept: "application/vnd.github+json",
    };
    if (env.GITHUB_TOKEN) headers.authorization = "Bearer " + env.GITHUB_TOKEN;
    const r = await fetch(
      `https://api.github.com/repos/${LOG_REPO}/commits?per_page=60`,
      { headers }
    );
    if (r.ok) {
      const commits = await r.json();
      log = commits
        .filter((c) => !(c.parents && c.parents.length > 1)) // merge 커밋 제외
        .map((c) => ({
          at: (c.commit && c.commit.author && c.commit.author.date) || "",
          raw: ((c.commit && c.commit.message) || "").split("\n")[0].trim(),
        }))
        .filter(
          (it) =>
            it.at &&
            it.raw &&
            !/^(merge|chore)\b/i.test(it.raw) &&
            !it.raw.includes("[skip-log]")
        )
        .map((it) => ({ at: it.at, summary: cleanCommitSummary(it.raw) }))
        .filter((it) => it.summary)
        .slice(0, LOG_LIMIT);
    }
  } catch (e) {
    // GitHub 장애/한도 초과 시 빈 log → 배지는 meta(배포 시각) 기반으로 폴백
  }

  const vm = env.CF_VERSION_METADATA;
  const updatedAt =
    (vm && vm.timestamp) || (log[0] && log[0].at) || new Date().toISOString();
  const res = json({ updated_at: updatedAt, log });
  res.headers.set("cache-control", "public, max-age=60, s-maxage=300");
  if (log.length) ctx.waitUntil(cache.put(cacheKey, res.clone()));
  return res;
}

// ── 도구별 업데이트 피드(/api/tool-updates) ────────────────────────────────
// 각 산하 도구 레포의 최신 커밋을 모아 "구축 핸드북"이 소비한다.
// 어느 도구 레포에 push가 생기면 핸드북의 해당 도구 항목이 자동 반영된다(연동).
// 엣지 캐시로 GitHub API 한도를 보호. private 레포(report-site)는 GITHUB_TOKEN 필요.
const HANDBOOK_OWNER = "SimpleorNothing";
const HANDBOOK_PER_TOOL = 100; // 레포당 1회 요청 상한(GitHub per_page 최대). 버스트·2차 레이트리밋 회피
const HANDBOOK_REPOS = [
  { id: "mi",         repo: "market-insight" },
  { id: "ci",         repo: "competitor_intelligence" },
  { id: "2030",       repo: "2030-insight" },
  { id: "idea",       repo: "report-idea" },
  { id: "report",     repo: "report-site" },
  { id: "guide",      repo: "agentguide" },
  { id: "quickshare", repo: "quickshare" },
  { id: "space",      repo: "samsungda-space" },
  { id: "portal",     repo: "samsungda-portal" },
  { id: "newsletter", repo: "samsungda-newsletter" },
];

async function fetchRepoLog(owner, repo, env) {
  const headers = {
    "user-agent": "samsungda-portal-handbook",
    accept: "application/vnd.github+json",
  };
  if (env.GITHUB_TOKEN) headers.authorization = "Bearer " + env.GITHUB_TOKEN;
  try {
    // sha 미지정 → 레포 기본 브랜치의 커밋을 반환(quickshare처럼 main이 아니어도 안전).
    // 레포당 1회만 요청(per_page=100). 페이지 순회하면 10개 레포를
    // 동시에 수십 건 던져 GitHub 2차 레이트리밋에 걸려 전체 빈 로그가 된다 — 기존 패턴(레포당 1회) 유지.
    const r = await fetch(
      `https://api.github.com/repos/${owner}/${repo}/commits?per_page=${HANDBOOK_PER_TOOL}`,
      { headers }
    );
    if (!r.ok) return { updated_at: "", log: [] };
    const commits = await r.json();
    if (!Array.isArray(commits)) return { updated_at: "", log: [] };
    const log = commits
      .filter((c) => !(c.parents && c.parents.length > 1)) // merge 커밋 제외
      .map((c) => ({
        at: (c.commit && c.commit.author && c.commit.author.date) || "",
        raw: ((c.commit && c.commit.message) || "").split("\n")[0].trim(),
      }))
      .filter(
        (it) =>
          it.at &&
          it.raw &&
          !/^(merge|chore)\b/i.test(it.raw) &&
          !it.raw.includes("[skip-log]")
      )
      .map((it) => ({ at: it.at, summary: cleanCommitSummary(it.raw) }))
      .filter((it) => it.summary);
    return { updated_at: (log[0] && log[0].at) || "", log };
  } catch (e) {
    return { updated_at: "", log: [] };
  }
}

async function handleToolUpdates(request, env, ctx) {
  const cache = caches.default;
  const cacheKey = new Request(
    "https://samsungda-portal.internal/api/tool-updates"
  );
  const hit = await cache.match(cacheKey);
  if (hit) return hit;

  const results = await Promise.all(
    HANDBOOK_REPOS.map(async (t) => [
      t.id,
      await fetchRepoLog(HANDBOOK_OWNER, t.repo, env),
    ])
  );
  const repos = {};
  for (const [id, data] of results) repos[id] = data;

  const res = json({ generated_at: new Date().toISOString(), repos });
  res.headers.set("cache-control", "public, max-age=120, s-maxage=600");
  const anyLog = Object.values(repos).some((d) => d.log && d.log.length);
  if (anyLog) ctx.waitUntil(cache.put(cacheKey, res.clone()));
  return res;
}

// ══════════════════════════════════════════════════════════════════════════
// 사이트 관리(/__admin) — 사이트 게이트(SITE_PASSWORD) 위에 얹는 2차 게이트.
// 관리자 전용: ① API 비용 분석 ② 구독자·발송 현황 ③ 뉴스레터 프리뷰.
// 스타일은 형제 격 내부 페이지(/__logs·로그인)와 동일한 기본 파랑 토큰을 사용.
// ══════════════════════════════════════════════════════════════════════════
const ADMIN_COOKIE = "da_admin_session";
const ADMIN_MSG = "da-admin-auth-v1";
const ADMIN_MAX_AGE = 60 * 60 * 12; // 12시간
const NL_BASE = "https://samsungda-newsletter.cw120-park.workers.dev";

function adminSessionToken(env) {
  return hmacHex(env.ADMIN_PASSWORD, ADMIN_MSG);
}
async function isAdmin(request, env) {
  const cookie = parseCookies(request.headers.get("cookie"))[ADMIN_COOKIE];
  if (!cookie) return false;
  return timingSafeEqual(cookie, await adminSessionToken(env));
}

function adminLoginPage(next, isError) {
  const html = `<!DOCTYPE html>
<html lang="ko"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>사이트 관리 — 로그인</title>
<link rel="stylesheet" as="style" crossorigin href="https://cdn.jsdelivr.net/gh/orioncactus/pretendard@v1.3.9/dist/web/static/pretendard.min.css">
<style>
  :root{--bg:#fff;--surface:#f6f7f9;--text:#1a1d21;--muted:#5b6470;--border:#e6e9ee;--brand:#1257d6}
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:"Pretendard",-apple-system,BlinkMacSystemFont,"Apple SD Gothic Neo","Malgun Gothic",sans-serif;color:var(--text);background:var(--bg);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
  .login{width:100%;max-width:360px;background:var(--surface);border:1.5px solid var(--border);border-radius:16px;padding:32px 28px}
  h1{font-size:22px;font-weight:800;letter-spacing:-.5px;margin-bottom:8px}
  .sub{color:var(--muted);font-size:15px;margin-bottom:22px}
  input[type=password]{width:100%;font:inherit;font-size:15px;padding:12px 14px;border:1.5px solid var(--border);border-radius:10px;background:#fff;outline:none;transition:border-color .15s}
  input[type=password]:focus{border-color:var(--brand)}
  button{width:100%;margin-top:14px;font:inherit;font-size:15px;font-weight:700;color:#fff;background:var(--brand);border:none;border-radius:10px;padding:12px 14px;cursor:pointer;transition:opacity .15s}
  button:hover{opacity:.92}
  .err{color:#c0392b;font-size:15px;margin-bottom:14px}
</style></head><body>
  <form class="login" method="POST" action="/__admin/auth">
    <h1>사이트 관리</h1>
    <p class="sub">관리자 비밀번호를 입력하세요.</p>
    ${isError ? '<p class="err">비밀번호가 올바르지 않습니다.</p>' : ""}
    <input type="password" name="password" placeholder="관리자 비밀번호" autocomplete="current-password" autofocus required>
    <input type="hidden" name="next" value="${escAttr(safeNextPath(next))}">
    <button type="submit">입장</button>
  </form>
</body></html>`;
  return new Response(html, { status: 401, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
}

async function handleAdminLogin(request, env, url) {
  let form;
  try { form = await request.formData(); } catch { return adminLoginPage("/__admin", true); }
  const password = String(form.get("password") || "");
  let next = safeNextPath(String(form.get("next") || "/__admin"));
  if (!next.startsWith("/__admin")) next = "/__admin";
  if (!env.ADMIN_PASSWORD || !timingSafeEqual(password, env.ADMIN_PASSWORD)) return adminLoginPage(next, true);
  const secure = url.protocol === "https:" ? "; Secure" : "";
  const headers = new Headers({ Location: next });
  headers.append("Set-Cookie", `${ADMIN_COOKIE}=${await adminSessionToken(env)}; Path=/__admin; Max-Age=${ADMIN_MAX_AGE}; HttpOnly; SameSite=Lax${cookieDomainAttr(url.hostname)}${secure}`);
  return new Response(null, { status: 303, headers });
}

// ── 기능1: API 비용 — Export CSV 업로드/보관(R2 usage/) ──
async function handleAdminUsage(request, env, sub) {
  if (!env.RESEARCH) return json({ error: "R2 미설정" }, 503);
  const PREFIX = "usage/";
  if (request.method === "GET" && sub === "file") {
    const key = new URL(request.url).searchParams.get("key") || "";
    if (!key.startsWith(PREFIX)) return json({ error: "bad key" }, 400);
    const obj = await env.RESEARCH.get(key);
    if (!obj) return json({ error: "not found" }, 404);
    return new Response(await obj.text(), { headers: { "content-type": "text/csv; charset=utf-8", "cache-control": "no-store" } });
  }
  if (request.method === "GET") {
    const listed = await env.RESEARCH.list({ prefix: PREFIX });
    const items = listed.objects
      .map((o) => ({ key: o.key, name: o.key.slice(PREFIX.length), size: o.size, uploaded: o.uploaded }))
      .sort((a, b) => new Date(b.uploaded) - new Date(a.uploaded));
    return json(items);
  }
  if (request.method === "POST") {
    let form;
    try { form = await request.formData(); } catch { return json({ error: "expected multipart/form-data" }, 400); }
    const file = form.get("file");
    if (!file || typeof file.arrayBuffer !== "function") return json({ error: "missing file" }, 400);
    const raw = String(file.name || "usage.csv").replace(/[^\w.\-]+/g, "_").slice(-60) || "usage.csv";
    const key = PREFIX + Date.now().toString(36) + "-" + raw;
    await env.RESEARCH.put(key, await file.arrayBuffer(), { httpMetadata: { contentType: "text/csv; charset=utf-8" } });
    return json({ key }, 201);
  }
  if (request.method === "DELETE") {
    const key = new URL(request.url).searchParams.get("key") || "";
    if (!key.startsWith(PREFIX)) return json({ error: "bad key" }, 400);
    await env.RESEARCH.delete(key);
    return new Response(null, { status: 204 });
  }
  return json({ error: "method not allowed" }, 405);
}

// ── 기능2: 구독자 현황 — 뉴스레터 Worker /recipients 프록시(TRIGGER_KEY) ──
async function handleAdminRecipients(env) {
  if (!env.NL_TRIGGER_KEY) return json({ error: "NL_TRIGGER_KEY 미설정" }, 503);
  try {
    const r = await fetch(`${NL_BASE}/recipients?key=${encodeURIComponent(env.NL_TRIGGER_KEY)}`);
    if (!r.ok) return json({ error: "newsletter " + r.status }, 502);
    return json(await r.json());
  } catch (e) {
    return json({ error: String(e) }, 502);
  }
}

// ── 기능2: 발송현황 — R2 newsletter/reports/ (postsend.js가 저장) ──
async function handleAdminDispatches(env) {
  if (!env.RESEARCH) return json({ error: "R2 미설정" }, 503);
  const listed = await env.RESEARCH.list({ prefix: "newsletter/reports/" });
  const keys = listed.objects.map((o) => o.key).sort((a, b) => b.localeCompare(a)).slice(0, 60);
  const out = [];
  for (const k of keys) {
    try {
      const obj = await env.RESEARCH.get(k);
      if (obj) out.push(JSON.parse(await obj.text()));
    } catch { /* skip */ }
  }
  return json(out);
}

function renderAdminPage(env) {
  const hasNL = !!env.NL_TRIGGER_KEY;
  const html = `<!DOCTYPE html>
<html lang="ko"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>사이트 관리</title>
<link rel="stylesheet" as="style" crossorigin href="https://cdn.jsdelivr.net/gh/orioncactus/pretendard@v1.3.9/dist/web/static/pretendard.min.css">
<style>
  :root{--bg:#fff;--surface:#f6f7f9;--text:#1a1d21;--muted:#5b6470;--border:#e6e9ee;--brand:#1257d6}
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:"Pretendard",-apple-system,BlinkMacSystemFont,"Apple SD Gothic Neo","Malgun Gothic",sans-serif;color:var(--text);background:var(--bg);padding:28px;max-width:940px;margin:0 auto}
  h1{font-size:24px;font-weight:800;letter-spacing:-.5px;margin-bottom:4px}
  .lede{color:var(--muted);font-size:14px;margin-bottom:20px}
  .tabs{display:flex;gap:6px;border-bottom:1.5px solid var(--border);margin-bottom:22px;flex-wrap:wrap}
  .tab{font:inherit;font-size:14px;font-weight:600;color:var(--muted);background:none;border:none;border-bottom:2px solid transparent;padding:9px 14px;margin-bottom:-1.5px;cursor:pointer;transition:color .15s,border-color .15s}
  .tab:hover{color:var(--text)}
  .tab.active{color:var(--brand);border-bottom-color:var(--brand)}
  .panel{display:none}
  .panel.active{display:block}
  .dropzone{border:1.5px dashed var(--border);border-radius:14px;padding:26px;text-align:center;color:var(--muted);font-size:14px;cursor:pointer;transition:border-color .15s,background .15s}
  .dropzone.over{border-color:var(--brand);background:rgba(18,87,214,.06)}
  .cards{display:flex;gap:12px;margin:18px 0;flex-wrap:wrap}
  .kcard{flex:1;min-width:150px;background:var(--surface);border:1.5px solid var(--border);border-radius:12px;padding:15px 17px}
  .kcard .k{color:var(--muted);font-size:13px;margin-bottom:6px}
  .kcard .v{font-size:24px;font-weight:800;letter-spacing:-.6px;font-variant-numeric:tabular-nums}
  .kcard .v small{font-size:14px;font-weight:600;color:var(--muted)}
  h2{font-size:14px;font-weight:700;margin:22px 0 10px}
  table{width:100%;border-collapse:collapse;font-size:13.5px}
  th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--border)}
  th{color:var(--muted);font-weight:600}
  td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}
  .bar{height:7px;background:var(--brand);border-radius:4px;min-width:1px}
  .barwrap{background:var(--surface);border-radius:4px;overflow:hidden}
  .muted{color:var(--muted);font-size:13px}
  .legend{color:var(--muted);font-size:12px;margin-top:14px;line-height:1.6}
  .flist{list-style:none;margin:14px 0 0;padding:0;font-size:13px}
  .flist li{display:flex;align-items:center;gap:8px;padding:6px 0;border-top:1px solid var(--border)}
  .flist a{color:var(--brand);text-decoration:none;cursor:pointer}
  .flist .del{margin-left:auto;color:var(--muted);cursor:pointer;font-size:12px}
  .flist .del:hover{color:#c0392b}
  .badge{display:inline-block;font-size:11px;font-weight:700;padding:1px 7px;border-radius:20px}
  .ok{background:#e5f6ec;color:#1a7f43}
  .fail{background:#fdeaea;color:#c0392b}
  iframe{width:100%;height:640px;border:1.5px solid var(--border);border-radius:12px;background:#fff}
  .empty{color:var(--muted);padding:18px 0}
  .toplink{font-size:13px;color:var(--muted);text-decoration:none}
  .toplink:hover{color:var(--brand)}
  .err{color:#c0392b;font-size:13px}
</style></head><body>
  <h1>사이트 관리</h1>
  <p class="lede">기획도구 모음 운영 관리 · <a class="toplink" href="/">← 포털로</a> · <a class="toplink" href="/__logs">접속 로그</a></p>
  <div class="tabs">
    <button class="tab active" data-t="cost">API 비용</button>
    <button class="tab" data-t="subs">구독자 · 발송</button>
    <button class="tab" data-t="nl">뉴스레터 프리뷰</button>
  </div>

  <section class="panel active" id="p-cost">
    <div class="dropzone" id="drop">콘솔 Export CSV를 여기에 끌어다 놓거나 클릭해 업로드<input type="file" id="file" accept=".csv" hidden></div>
    <div id="cost-err" class="err"></div>
    <div id="cost-out"></div>
    <div class="legend">단가(USD, 표준 티어·100만 토큰당): Opus $5/$25 · Sonnet $3/$15 · Haiku $1/$5 · 캐시쓰기 ×1.25(5m)/×2(1h) · 캐시읽기 ×0.1 · 웹서치 $0.01/건. 실제 청구와 정합하려면 소스의 단가표를 최신 pricing으로 조정.</div>
    <h2>보관된 파일</h2>
    <ul class="flist" id="flist"><li class="empty">불러오는 중…</li></ul>
  </section>

  <section class="panel" id="p-subs">
    <div class="cards" id="subs-cards"><div class="kcard"><div class="k">불러오는 중…</div><div class="v">—</div></div></div>
    <div id="subs-err" class="err"></div>
    <h2>수신자 목록</h2>
    <table id="subs-table"><thead><tr><th>#</th><th>주소</th><th>구분</th></tr></thead><tbody><tr><td colspan="3" class="empty">불러오는 중…</td></tr></tbody></table>
    <h2>발송현황 (최근)</h2>
    <table id="disp-table"><thead><tr><th>날짜</th><th class="n">전체</th><th class="n">성공</th><th class="n">실패</th></tr></thead><tbody><tr><td colspan="4" class="empty">불러오는 중…</td></tr></tbody></table>
  </section>

  <section class="panel" id="p-nl">
    <p class="muted" id="nl-note">발송은 보류(hold) 상태입니다. 아래는 오늘자 기준 렌더 미리보기입니다(실발송 아님).</p>
    ${hasNL ? `<iframe src="${NL_BASE}/preview" title="뉴스레터 미리보기"></iframe>` : '<p class="empty">NL_TRIGGER_KEY 미설정 — 미리보기를 표시하려면 시크릿을 추가하세요.</p>'}
  </section>

<script>
(function(){
  var $=function(s,r){return (r||document).querySelector(s);};
  var fmt=function(n){return (n||0).toLocaleString('en-US');};
  var usd=function(n){return '$'+(n||0).toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2});};
  function esc(s){return String(s==null?'':s).replace(/[&<>]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;'}[c];});}
  // 탭
  var tabs=document.querySelectorAll('.tab'), loaded={};
  tabs.forEach(function(t){t.addEventListener('click',function(){
    tabs.forEach(function(x){x.classList.remove('active');});
    document.querySelectorAll('.panel').forEach(function(x){x.classList.remove('active');});
    t.classList.add('active'); $('#p-'+t.dataset.t).classList.add('active');
    if(t.dataset.t==='subs' && !loaded.subs){loaded.subs=1; loadSubs();}
  });});

  // ── 단가 ──
  function priceFor(m){ m=(m||'').toLowerCase();
    if(m.indexOf('opus')>-1) return {i:5,o:25};
    if(m.indexOf('haiku')>-1) return {i:1,o:5};
    if(m.indexOf('sonnet')>-1) return {i:3,o:15};
    return {i:3,o:15};
  }
  var CW5=1.25, CW1H=2, CR=0.1, WEB=0.01;

  // ── CSV 파싱(콘솔 Export 스키마) ──
  function parseCSV(text){
    var lines=text.replace(/\\r/g,'').split('\\n').filter(function(l){return l.trim();});
    if(!lines.length) return {rows:[],header:[]};
    var header=lines[0].split(',');
    var idx={}; header.forEach(function(h,i){idx[h.trim()]=i;});
    var rows=lines.slice(1).map(function(l){
      var c=l.split(','); var g=function(k){return c[idx[k]];};
      var num=function(k){var v=parseFloat(g(k));return isNaN(v)?0:v;};
      return {
        date:(g('usage_date_utc')||'').trim(),
        model:(g('model_version')||'').trim(),
        key:(g('api_key')||'').trim(),
        no_cache:num('usage_input_tokens_no_cache'),
        cw5:num('usage_input_tokens_cache_write_5m'),
        cw1h:num('usage_input_tokens_cache_write_1h'),
        cr:num('usage_input_tokens_cache_read'),
        out:num('usage_output_tokens'),
        web:num('web_search_count')
      };
    });
    return {rows:rows,header:header};
  }
  function rowCost(r){var p=priceFor(r.model);
    return (r.no_cache*p.i + r.cw5*p.i*CW5 + r.cw1h*p.i*CW1H + r.cr*p.i*CR + r.out*p.o)/1e6 + r.web*WEB;
  }
  function analyze(text){
    var parsed=parseCSV(text); var rows=parsed.rows;
    if(!rows.length){ $('#cost-err').textContent='CSV에서 데이터 행을 찾지 못했습니다.'; return; }
    $('#cost-err').textContent='';
    var tot={cost:0,inTok:0,out:0,web:0}, byModel={}, byTool={}, byDate={};
    rows.forEach(function(r){
      var cost=rowCost(r); var inTok=r.no_cache+r.cw5+r.cw1h+r.cr;
      tot.cost+=cost; tot.inTok+=inTok; tot.out+=r.out; tot.web+=r.web;
      (byModel[r.model]=byModel[r.model]||{cost:0,inTok:0,out:0,web:0,n:0}); var m=byModel[r.model]; m.cost+=cost;m.inTok+=inTok;m.out+=r.out;m.web+=r.web;m.n++;
      (byTool[r.key]=byTool[r.key]||{cost:0,n:0}); byTool[r.key].cost+=cost; byTool[r.key].n++;
      (byDate[r.date]=byDate[r.date]||{cost:0}); byDate[r.date].cost+=cost;
    });
    var dates=Object.keys(byDate).sort();
    var maxDay=Math.max.apply(null,dates.map(function(d){return byDate[d].cost;}).concat([0.0001]));
    var range=dates.length?(dates[0]+' ~ '+dates[dates.length-1]):'';
    var h='';
    h+='<div class="cards">'
      +'<div class="kcard"><div class="k">총 비용 ('+esc(range)+')</div><div class="v">'+usd(tot.cost)+'</div></div>'
      +'<div class="kcard"><div class="k">입력 토큰</div><div class="v">'+fmt(tot.inTok)+'</div></div>'
      +'<div class="kcard"><div class="k">출력 토큰</div><div class="v">'+fmt(tot.out)+'</div></div>'
      +'<div class="kcard"><div class="k">웹서치</div><div class="v">'+fmt(tot.web)+'</div></div>'
      +'</div>';
    // 모델별
    var mk=Object.keys(byModel).sort(function(a,b){return byModel[b].cost-byModel[a].cost;});
    h+='<h2>모델별</h2><table><thead><tr><th>모델</th><th class="n">건수</th><th class="n">입력</th><th class="n">출력</th><th class="n">웹서치</th><th class="n">비용</th><th class="n">비중</th></tr></thead><tbody>';
    mk.forEach(function(k){var m=byModel[k];h+='<tr><td>'+esc(k)+'</td><td class="n">'+fmt(m.n)+'</td><td class="n">'+fmt(m.inTok)+'</td><td class="n">'+fmt(m.out)+'</td><td class="n">'+fmt(m.web)+'</td><td class="n">'+usd(m.cost)+'</td><td class="n">'+(tot.cost?Math.round(m.cost/tot.cost*100):0)+'%</td></tr>';});
    h+='</tbody></table>';
    // 도구(api_key)별
    var tk=Object.keys(byTool).sort(function(a,b){return byTool[b].cost-byTool[a].cost;});
    h+='<h2>도구(API 키)별</h2><table><thead><tr><th>API 키</th><th class="n">건수</th><th class="n">비용</th><th class="n">비중</th></tr></thead><tbody>';
    tk.forEach(function(k){var t=byTool[k];h+='<tr><td>'+esc(k||'(미상)')+'</td><td class="n">'+fmt(t.n)+'</td><td class="n">'+usd(t.cost)+'</td><td class="n">'+(tot.cost?Math.round(t.cost/tot.cost*100):0)+'%</td></tr>';});
    h+='</tbody></table>';
    // 일자별
    h+='<h2>일자별 추이</h2><table><thead><tr><th>날짜</th><th class="n">비용</th><th style="width:45%">&nbsp;</th></tr></thead><tbody>';
    dates.forEach(function(d){var c=byDate[d].cost;var w=Math.round(c/maxDay*100);h+='<tr><td>'+esc(d)+'</td><td class="n">'+usd(c)+'</td><td><div class="barwrap"><div class="bar" style="width:'+w+'%"></div></div></td></tr>';});
    h+='</tbody></table>';
    $('#cost-out').innerHTML=h;
  }

  // ── 업로드/드롭 ──
  var drop=$('#drop'), fileInput=$('#file');
  drop.addEventListener('click',function(){fileInput.click();});
  ['dragenter','dragover'].forEach(function(e){drop.addEventListener(e,function(ev){ev.preventDefault();drop.classList.add('over');});});
  ['dragleave','drop'].forEach(function(e){drop.addEventListener(e,function(ev){ev.preventDefault();drop.classList.remove('over');});});
  drop.addEventListener('drop',function(ev){if(ev.dataTransfer.files[0])handleFile(ev.dataTransfer.files[0]);});
  fileInput.addEventListener('change',function(){if(fileInput.files[0])handleFile(fileInput.files[0]);});
  function handleFile(f){
    var rd=new FileReader();
    rd.onload=function(){ analyze(String(rd.result)); upload(f); };
    rd.readAsText(f);
  }
  function upload(f){
    var fd=new FormData(); fd.append('file',f);
    fetch('/__admin/api/usage',{method:'POST',body:fd}).then(function(r){return r.json();}).then(function(){loadFiles();}).catch(function(){});
  }
  function loadFiles(){
    fetch('/__admin/api/usage').then(function(r){return r.json();}).then(function(items){
      var ul=$('#flist');
      if(!items.length){ul.innerHTML='<li class="empty">아직 업로드된 파일이 없습니다.</li>';return;}
      ul.innerHTML=items.map(function(it){
        return '<li><a data-key="'+esc(it.key)+'" class="open">'+esc(it.name)+'</a> <span class="muted">'+Math.round(it.size/1024)+'KB · '+new Date(it.uploaded).toLocaleDateString('ko-KR')+'</span><span class="del" data-key="'+esc(it.key)+'">삭제</span></li>';
      }).join('');
      ul.querySelectorAll('.open').forEach(function(a){a.addEventListener('click',function(){
        fetch('/__admin/api/usage/file?key='+encodeURIComponent(a.dataset.key)).then(function(r){return r.text();}).then(analyze);
      });});
      ul.querySelectorAll('.del').forEach(function(d){d.addEventListener('click',function(){
        fetch('/__admin/api/usage?key='+encodeURIComponent(d.dataset.key),{method:'DELETE'}).then(function(){loadFiles();});
      });});
    }).catch(function(){$('#flist').innerHTML='<li class="empty">목록을 불러오지 못했습니다.</li>';});
  }
  loadFiles();

  // ── 구독자·발송 ──
  function loadSubs(){
    fetch('/__admin/api/recipients').then(function(r){return r.json();}).then(function(d){
      if(d.error){$('#subs-err').textContent='구독자 조회 실패: '+d.error;return;}
      $('#subs-cards').innerHTML=''
        +'<div class="kcard"><div class="k">전체 수신자</div><div class="v">'+fmt(d.count)+'<small> 명</small></div></div>'
        +'<div class="kcard"><div class="k">고정(RECIPIENTS)</div><div class="v">'+fmt(d.fixed)+'</div></div>'
        +'<div class="kcard"><div class="k">구독</div><div class="v">'+fmt(d.subscribed)+'</div></div>';
      var rows=(d.recipients||[]).map(function(r,i){
        var lab=r.source==='both'?'고정+구독':r.source==='fixed'?'고정':'구독';
        return '<tr><td>'+(i+1)+'</td><td style="font-family:monospace">'+esc(r.email)+'</td><td>'+lab+'</td></tr>';
      }).join('');
      $('#subs-table').querySelector('tbody').innerHTML=rows||'<tr><td colspan="3" class="empty">수신자가 없습니다.</td></tr>';
    }).catch(function(e){$('#subs-err').textContent='구독자 조회 실패';});
    fetch('/__admin/api/dispatches').then(function(r){return r.json();}).then(function(list){
      if(!list.length){$('#disp-table').querySelector('tbody').innerHTML='<tr><td colspan="4" class="empty">저장된 발송 리포트가 없습니다. (postsend 저장 반영 이후부터 집계)</td></tr>';return;}
      $('#disp-table').querySelector('tbody').innerHTML=list.map(function(r){
        var fail=(r.stillMissing?r.stillMissing.length:(r.intended-r.sent))||0;
        return '<tr><td>'+esc(r.date)+'</td><td class="n">'+fmt(r.intended)+'</td><td class="n"><span class="badge ok">'+fmt(r.sent)+'</span></td><td class="n">'+(fail?'<span class="badge fail">'+fmt(fail)+'</span>':'0')+'</td></tr>';
      }).join('');
    }).catch(function(){$('#disp-table').querySelector('tbody').innerHTML='<tr><td colspan="4" class="empty">발송현황을 불러오지 못했습니다.</td></tr>';});
  }
})();
</script>
</body></html>`;
  return new Response(html, { status: 200, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
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

    // ── 사이트 관리(/__admin) — SITE_PASSWORD 게이트 위 2차 게이트(ADMIN_PASSWORD) ──
    if (path === "/__admin/auth" && request.method === "POST") {
      return handleAdminLogin(request, env, url);
    }
    if (path === "/__admin" || path.startsWith("/__admin/")) {
      if (!env.ADMIN_PASSWORD) {
        return new Response("ADMIN_PASSWORD 시크릿이 설정되지 않았습니다.", { status: 503, headers: TEXT });
      }
      if (!(await isAdmin(request, env))) {
        return adminLoginPage(path, false);
      }
      if (path === "/__admin" || path === "/__admin/") return renderAdminPage(env);
      if (path === "/__admin/api/usage" || path.startsWith("/__admin/api/usage/")) {
        return handleAdminUsage(request, env, path.slice("/__admin/api/usage".length).replace(/^\//, ""));
      }
      if (path === "/__admin/api/recipients") return handleAdminRecipients(env);
      if (path === "/__admin/api/dispatches") return handleAdminDispatches(env);
      return json({ error: "not found" }, 404);
    }

    // 관리자용 접속 로그 조회 페이지(이미 사이트 비밀번호 게이트로 보호됨)
    if (path === "/__logs" && request.method === "GET") {
      return renderLogsPage(env, url);
    }

    // 루트/포털 페이지는 정적 자산으로 서빙
    // + 왼쪽 하단 "업데이트" 배지용으로 현재 배포 시각/메모를 <head>에 주입한다.
    //   (런타임에 git이 없는 Worker라 CF 배포 메타데이터를 단일 진실원으로 사용 → "반영 안 됨" 차단)
    if (path === "/" || path === "/index.html") {
      const assetRes = await env.ASSETS.fetch(request);
      const vm = env.CF_VERSION_METADATA;
      const ct = assetRes.headers.get("content-type") || "";
      if (vm && vm.timestamp && ct.includes("text/html")) {
        const ts = escAttr(vm.timestamp);
        const note = vm.tag ? escAttr(vm.tag) : "";
        return new HTMLRewriter()
          .on("head", {
            element(el) {
              el.append(`\n<meta name="app-updated" content="${ts}">`, { html: true });
              if (note) el.append(`\n<meta name="app-update-note" content="${note}">`, { html: true });
              el.append(`\n<script defer src="/update-badge.js"></script>`, { html: true });
            },
          })
          .transform(assetRes);
      }
      return assetRes;
    }

    // 위치가 변경된 페이지(/report, /mi, /2030, /quickshare): 안내 후 메인으로 자동 이동
    const normalized = path.replace(/\/+$/, "").toLowerCase() || "/";
    if (request.method === "GET" && MOVED_PAGES.has(normalized)) {
      return movedPage();
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

    // 업데이트 내역 JSON — 커밋 이력에서 자동 생성(update-badge.js가 소비)
    if (path === "/version.json") {
      return handleVersionJson(request, env, ctx);
    }

    // 도구별 업데이트 피드 — 구축 핸드북이 소비(각 도구 레포 push 시 자동 반영)
    if (path === "/api/tool-updates") {
      return handleToolUpdates(request, env, ctx);
    }

    // 정적 하위 페이지(구축 핸드북 등) — /static/* 는 정적 자산으로 서빙
    if (path.startsWith("/static/")) {
      return env.ASSETS.fetch(request);
    }

    // 업데이트 배지 스크립트(정적 자산)
    if (path === "/update-badge.js") {
      return env.ASSETS.fetch(request);
    }

    // 산하 도구 직접 프록시 (report-site 경유 제거) — 비밀번호 게이트는 위에서 이미 통과.
    // US 10Y 대시보드(Railway/Express): serve-static의 트레일링 슬래시 301을 그대로
    // 흘려보내야 하므로 경로를 가공하지 않고 그대로 전달한다.
    if (path === "/us10y" || path.startsWith("/us10y/")) {
      const us10y = (env.US10Y_UPSTREAM || "https://us10y-production.up.railway.app").replace(/\/$/, "");
      return proxyPass(request, us10y + path + (url.search || ""));
    }
    // 웹사이트 구축기(website-automation Worker): Worker는 /admin/* 로 서빙하므로
    // /webauto 접두어를 /admin 으로 교체한다. /webauto → /admin, /webauto/x → /admin/x
    if (path === "/webauto" || path.startsWith("/webauto/")) {
      const webauto = (env.WEBAUTO_UPSTREAM || "https://website-automation.cw120-park.workers.dev").replace(/\/$/, "");
      const rest = path.slice("/webauto".length) || "/";
      return proxyPass(request, webauto + "/admin" + rest + (url.search || ""));
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
