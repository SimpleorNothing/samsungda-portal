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

// ── 이동된 페이지 안내 ───────────────────────────────────────────────────────────────
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
    status: 410,
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
  });
}

// ── 조사 결과물 업로드(R2) ─────────────────────────────────────────────────────────
const RESEARCH_PREFIX = "research/";
const MAX_UPLOAD_BYTES = 25 * 1024 * 1024; // 25MB

function slugifyFilename(name) {
  const dot = name.lastIndexOf(".");
  const ext = dot > -1 ? name.slice(dot).toLowerCase() : "";
  const base = (dot > -1 ? name.slice(0, dot) : name)
    .replace(/[^\w\uac00-\ud7a3-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80) || "file";
  return base + ext;
}

async function handleResearchApi(request, env, id) {
  if (!env.RESEARCH) return json({ error: "R2 버킷이 설정되지 않았습니다" }, 501);

  // 목록
  if (!id && request.method === "GET") {
    const list = await env.RESEARCH.list({ prefix: RESEARCH_PREFIX, include: ["customMetadata"] });
    const items = list.objects
      .map((o) => ({
        id: o.key.slice(RESEARCH_PREFIX.length),
        size: o.size,
        uploaded: o.uploaded,
        title: (o.customMetadata && o.customMetadata.title) || o.key.slice(RESEARCH_PREFIX.length),
        contentType: (o.customMetadata && o.customMetadata.contentType) || "",
      }))
      .sort((a, b) => new Date(b.uploaded) - new Date(a.uploaded));
    return json({ items });
  }

  // 업로드
  if (!id && request.method === "POST") {
    const ct = request.headers.get("content-type") || "";
    if (!ct.includes("multipart/form-data")) return json({ error: "multipart/form-data 필요" }, 400);
    const form = await request.formData();
    const file = form.get("file");
    if (!file || typeof file === "string") return json({ error: "file 필드 필요" }, 400);
    if (file.size > MAX_UPLOAD_BYTES) return json({ error: "25MB 이하만 업로드 가능" }, 413);
    const title = String(form.get("title") || file.name || "제목 없음").slice(0, 200);
    const key = RESEARCH_PREFIX + Date.now() + "-" + slugifyFilename(file.name || "file");
    await env.RESEARCH.put(key, file.stream(), {
      httpMetadata: { contentType: file.type || "application/octet-stream" },
      customMetadata: { title, contentType: file.type || "" },
    });
    return json({ ok: true, id: key.slice(RESEARCH_PREFIX.length) });
  }

  // 삭제
  if (id && request.method === "DELETE") {
    await env.RESEARCH.delete(RESEARCH_PREFIX + id);
    return json({ ok: true });
  }

  return json({ error: "method not allowed" }, 405);
}

async function serveResearchFile(env, id) {
  if (!env.RESEARCH) return new Response("R2 not configured", { status: 501, headers: TEXT });
  const obj = await env.RESEARCH.get(RESEARCH_PREFIX + id);
  if (!obj) return new Response("Not found", { status: 404, headers: TEXT });
  const headers = new Headers();
  obj.writeHttpMetadata(headers);
  if (!headers.get("content-type")) headers.set("content-type", "application/octet-stream");
  headers.set("cache-control", "private, max-age=300");
  return new Response(obj.body, { headers });
}

// ── 접속 로그(D1, 선택) ─────────────────────────────────────────────────────────────
function kstDay(date) {
  return new Intl.DateTimeFormat("sv-SE", { timeZone: "Asia/Seoul", year: "numeric", month: "2-digit", day: "2-digit" }).format(date);
}
function fmtKstTime(iso) {
  try {
    return new Intl.DateTimeFormat("sv-SE", { timeZone: "Asia/Seoul", hour12: false, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date(iso));
  } catch { return iso; }
}
function shiftDay(day, delta) {
  const d = new Date(day + "T00:00:00Z");
  d.setUTCDate(d.getUTCDate() + delta);
  return d.toISOString().slice(0, 10);
}

// UA 문자열에서 브라우저/기기 유형을 대략 분류(정확함보다 가독성 우선).
function parseBrowser(ua) {
  ua = ua || "";
  let device = /Mobile|Android|iPhone|iPad/i.test(ua) ? "모바일" : "PC";
  let browser = "기타";
  if (/Edg\//.test(ua)) browser = "Edge";
  else if (/SamsungBrowser\//.test(ua)) browser = "삼성브라우저";
  else if (/Chrome\//.test(ua)) browser = "Chrome";
  else if (/Safari\//.test(ua) && /Version\//.test(ua)) browser = "Safari";
  else if (/Firefox\//.test(ua)) browser = "Firefox";
  return { device, browser };
}

async function ensureSchema(db) {
  await db.exec(
    "CREATE TABLE IF NOT EXISTS access_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, day TEXT NOT NULL, path TEXT NOT NULL, method TEXT NOT NULL, country TEXT, city TEXT, ip_hash TEXT, device TEXT, browser TEXT, ua TEXT, referer TEXT); CREATE INDEX IF NOT EXISTS idx_access_log_day ON access_log(day); CREATE INDEX IF NOT EXISTS idx_access_log_ts ON access_log(ts);"
  );
}

// 응답을 막지 않도록 waitUntil로 비동기 기록. D1 바인딩이 없으면 조용히 스킵.
function logAccess(env, ctx, request, url) {
  const db = env.ACCESS_LOG;
  if (!db) return;
  const path = url.pathname;
  if (path === "/favicon.ico" || path === "/__logs" || path.startsWith("/__logs/")) return;
  ctx.waitUntil(
    (async () => {
      try {
        await ensureSchema(db);
        const now = new Date();
        const cf = request.cf || {};
        const ua = request.headers.get("user-agent") || "";
        const { device, browser } = parseBrowser(ua);
        const ipRaw = request.headers.get("cf-connecting-ip") || "";
        // 원본 IP는 저장하지 않고 일 단위 솔트로 해시(같은 날 안에서만 방문자 구분).
        const day = kstDay(now);
        const ipHashBytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(day + "|" + ipRaw));
        const ipHash = bytesToHex(new Uint8Array(ipHashBytes)).slice(0, 16);
        await db
          .prepare(
            "INSERT INTO access_log (ts, day, path, method, country, city, ip_hash, device, browser, ua, referer) VALUES (?,?,?,?,?,?,?,?,?,?,?)"
          )
          .bind(
            now.toISOString(),
            day,
            path,
            request.method,
            cf.country || "",
            cf.city || "",
            ipHash,
            device,
            browser,
            ua.slice(0, 300),
            (request.headers.get("referer") || "").slice(0, 300)
          )
          .run();
      } catch (e) {
        // 로깅 실패는 서비스에 영향을 주지 않는다.
      }
    })()
  );
}

async function renderLogsPage(env, url) {
  const db = env.ACCESS_LOG;
  if (!db) {
    return new Response("접속 로그가 꺼져 있습니다. wrangler.jsonc의 d1_databases 바인딩을 추가하세요.", {
      status: 501,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }
  await ensureSchema(db);

  const day = /^\d{4}-\d{2}-\d{2}$/.test(url.searchParams.get("day") || "") ? url.searchParams.get("day") : kstDay(new Date());

  const [{ results: rows }, { results: dailyCounts }, { results: pathCounts }] = await Promise.all([
    db.prepare("SELECT ts, path, method, country, city, ip_hash, device, browser, referer FROM access_log WHERE day = ? ORDER BY ts DESC LIMIT 500").bind(day).all(),
    db.prepare("SELECT day, COUNT(*) AS hits, COUNT(DISTINCT ip_hash) AS visitors FROM access_log GROUP BY day ORDER BY day DESC LIMIT 14").all(),
    db.prepare("SELECT path, COUNT(*) AS hits FROM access_log WHERE day = ? GROUP BY path ORDER BY hits DESC LIMIT 12").bind(day).all(),
  ]);

  const esc = escAttr;
  const rowsHtml = rows
    .map(
      (r) =>
        `<tr><td>${esc(fmtKstTime(r.ts).slice(11))}</td><td>${esc(r.path)}</td><td>${esc(r.country || "")}${r.city ? " · " + esc(r.city) : ""}</td><td title="${esc(r.ua || "")}">${esc(r.device)} · ${esc(r.browser)}</td><td>${esc((r.ip_hash || "").slice(0, 8))}</td></tr>`
    )
    .join("");
  const dailyHtml = dailyCounts
    .map((d) => `<tr${d.day === day ? ' class="cur"' : ""}><td><a href="?day=${esc(d.day)}">${esc(d.day)}</a></td><td>${d.hits}</td><td>${d.visitors}</td></tr>`)
    .join("");
  const pathHtml = pathCounts.map((p) => `<tr><td>${esc(p.path)}</td><td>${p.hits}</td></tr>`).join("");

  const html = `<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>접속 로그 — ${esc(day)}</title>
<link rel="stylesheet" as="style" crossorigin href="https://cdn.jsdelivr.net/gh/orioncactus/pretendard@v1.3.9/dist/web/static/pretendard.min.css">
<style>
  :root{--bg:#fff;--surface:#f6f7f9;--text:#1a1d21;--muted:#5b6470;--border:#e6e9ee;--brand:#1257d6}
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:"Pretendard",-apple-system,BlinkMacSystemFont,"Apple SD Gothic Neo","Malgun Gothic",sans-serif;color:var(--text);background:var(--bg);padding:28px;max-width:1100px;margin:0 auto}
  h1{font-size:22px;font-weight:800;letter-spacing:-.5px;margin-bottom:4px}
  .sub{color:var(--muted);font-size:15px;margin-bottom:20px}
  .nav{display:flex;gap:8px;align-items:center;margin-bottom:20px;font-size:15px}
  .nav a{color:var(--brand);text-decoration:none;border:1.5px solid var(--border);border-radius:8px;padding:6px 12px}
  .nav a:hover{border-color:var(--brand)}
  .nav b{font-weight:700}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px}
  @media(max-width:760px){.grid{grid-template-columns:1fr}}
  .card{background:var(--surface);border:1.5px solid var(--border);border-radius:12px;padding:16px}
  .card h2{font-size:15px;color:var(--muted);font-weight:700;margin-bottom:10px}
  table{width:100%;border-collapse:collapse;font-size:15px}
  th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--border);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:340px}
  th{color:var(--muted);font-weight:700}
  tr.cur{background:#eef3fd}
  .muted{color:var(--muted)}
</style>
</head>
<body>
  <h1>접속 로그</h1>
  <p class="sub">KST 기준 · 원본 IP는 저장하지 않으며 일 단위 해시로 방문자만 구분합니다.</p>
  <div class="nav">
    <a href="?day=${esc(shiftDay(day, -1))}">← 전날</a>
    <b>${esc(day)}</b>
    <a href="?day=${esc(shiftDay(day, 1))}">다음날 →</a>
    <a href="/__logs">오늘</a>
  </div>
  <div class="grid">
    <div class="card"><h2>최근 14일</h2><table><tr><th>날짜</th><th>요청</th><th>방문자</th></tr>${dailyHtml || '<tr><td colspan="3" class="muted">기록 없음</td></tr>'}</table></div>
    <div class="card"><h2>경로별 (${esc(day)})</h2><table><tr><th>경로</th><th>요청</th></tr>${pathHtml || '<tr><td colspan="2" class="muted">기록 없음</td></tr>'}</table></div>
  </div>
  <div class="card"><h2>상세 (${esc(day)} · 최근 500건)</h2><table><tr><th>시각</th><th>경로</th><th>지역</th><th>환경</th><th>방문자</th></tr>${rowsHtml || '<tr><td colspan="5" class="muted">기록 없음</td></tr>'}</table></div>
</body>
</html>`;
  return new Response(html, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
}

// ── 프록시 ─────────────────────────────────────────────────────────────────────────────
// 산하 도구로 가는 요청을 upstream으로 그대로 전달한다. redirect는 manual로 보존해
// upstream이 보내는 301/302가 브라우저까지 그대로 전달되도록 한다.
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

    // 인증을 통과한 실제 접속만 기록한다(로그인 페이지에서 튅긴 요청은 제외).
    logAccess(env, ctx, request, url);

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
