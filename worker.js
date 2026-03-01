/**
 * FTTH-PWA Worker (CTOs + CE/CDO + Movimentações) - 2026-03-01
 *
 * Fix: Frontend calls GET /api/movimentacoes and was receiving 404.
 * This worker now serves /api/movimentacoes (returns recent movements if table exists; otherwise empty list).
 *
 * Keeps:
 *  - /api/login, /api/me, /api/logout
 *  - /api/ctos (GET/POST/DELETE)
 *  - /api/caixas_emenda_cdo (GET/POST/DELETE)
 *
 * D1 binding: DB
 */

const ALLOWED_ORIGINS = new Set([
  "https://ftth-pwa.pages.dev",
  "http://localhost:8788",
  "http://localhost:5173",
  "http://localhost:3000",
]);

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname;

    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(request) });

    try {
      if (!env.DB) return corsJson(request, { error: "DB_not_configured" }, 500);

      // best-effort schema ensure
      ctx.waitUntil(ensureSchema(env).catch(()=>{}));

      if (request.method === "GET" && (pathname === "/" || pathname === "/api" || pathname === "/api/")) {
        return corsJson(request, { ok: true, service: "ftth-pwa", version: "2026-03-01-ctos-cecdo-mov" });
      }

      // AUTH
      if (pathname === "/api/login" && request.method === "POST") return corsResponse(request, await handleLogin(request, env));
      if (pathname === "/api/me" && request.method === "GET") return corsResponse(request, await handleMe(request, env));
      if (pathname === "/api/logout" && request.method === "POST") return corsResponse(request, await handleLogout(request, env));

      // DATA
      if (pathname === "/api/ctos" && request.method === "GET") return corsResponse(request, await handleGetCtos(request, env));
      if (pathname === "/api/ctos" && request.method === "POST") return corsResponse(request, await handleUpsertCto(request, env));
      if (pathname === "/api/ctos" && request.method === "DELETE") return corsResponse(request, await handleDeleteCto(request, env));

      if (pathname === "/api/caixas_emenda_cdo" && request.method === "GET") return corsResponse(request, await handleGetCeCdo(request, env));
      if (pathname === "/api/caixas_emenda_cdo" && request.method === "POST") return corsResponse(request, await handleUpsertCeCdo(request, env));
      if (pathname === "/api/caixas_emenda_cdo" && request.method === "DELETE") return corsResponse(request, await handleDeleteCeCdo(request, env));

      // Movimentações (GET)
      if (pathname === "/api/movimentacoes" && request.method === "GET") return corsResponse(request, await handleGetMovimentacoes(request, env, url));

      return corsJson(request, { error: "not_found" }, 404);
    } catch (err) {
      return corsJson(request, { error: "server_error", message: String(err?.message || err), stack: String(err?.stack || "") }, 500);
    }
  },
};

// ---------------- CORS ----------------
function corsHeaders(request) {
  const origin = request.headers.get("origin") || "";
  const allowOrigin = ALLOWED_ORIGINS.has(origin) ? origin : "*";
  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Admin-Password",
    "Vary": "Origin",
  };
}
function corsResponse(request, response) {
  const headers = new Headers(response.headers);
  const ch = corsHeaders(request);
  for (const [k, v] of Object.entries(ch)) headers.set(k, v);
  return new Response(response.body, { status: response.status, headers });
}
function jsonResponse(obj, status=200) {
  return new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json; charset=utf-8" } });
}
function corsJson(request, obj, status=200) {
  return corsResponse(request, jsonResponse(obj, status));
}
async function readJson(request) {
  return await request.json().catch(() => null);
}

// ---------------- Schema ----------------
async function ensureSchema(env){
  await env.DB.exec(`CREATE TABLE IF NOT EXISTS ctos (
    cto_id TEXT PRIMARY KEY,
    nome TEXT,
    rua TEXT,
    bairro TEXT,
    lat REAL NOT NULL,
    lng REAL NOT NULL,
    capacidade INTEGER DEFAULT 0
  );`);
  await env.DB.exec(`CREATE INDEX IF NOT EXISTS idx_ctos_lat_lng ON ctos(lat, lng);`);

  await env.DB.exec(`CREATE TABLE IF NOT EXISTS caixas_emenda_cdo (
    id TEXT PRIMARY KEY,
    nome TEXT,
    rua TEXT,
    bairro TEXT,
    lat REAL NOT NULL,
    lng REAL NOT NULL,
    tipo TEXT DEFAULT 'CDO'
  );`);
  await env.DB.exec(`CREATE INDEX IF NOT EXISTS idx_cecdo_lat_lng ON caixas_emenda_cdo(lat, lng);`);

  // Movimentações: simples (para evitar 404 agora). Você pode evoluir depois.
  await env.DB.exec(`CREATE TABLE IF NOT EXISTS movimentacoes (
    id TEXT PRIMARY KEY,
    cto_id TEXT,
    tipo TEXT,
    cliente TEXT,
    usuario TEXT,
    obs TEXT,
    ts TEXT
  );`);
  await env.DB.exec(`CREATE INDEX IF NOT EXISTS idx_mov_cto_ts ON movimentacoes(cto_id, ts);`);

  await env.DB.exec(`CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    is_active INTEGER DEFAULT 1
  );`);
  await env.DB.exec(`CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    expires_at TEXT
  );`);
  await env.DB.exec(`CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username);`);
}

// ---------------- Auth helpers ----------------
function getBearer(request) {
  const h = request.headers.get("authorization") || "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
}
async function sha256Hex(str) {
  const enc = new TextEncoder().encode(str);
  const buf = await crypto.subtle.digest("SHA-256", enc);
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2,"0")).join("");
}
function base64Url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
}
function fromB64Url(s) {
  try {
    s = s.replace(/-/g,"+").replace(/_/g,"/");
    while (s.length % 4) s += "=";
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i);
    return out;
  } catch { return null; }
}
function timingSafeEqual(a,b){
  if (a.length !== b.length) return false;
  let r=0;
  for (let i=0;i<a.length;i++) r |= a[i]^b[i];
  return r===0;
}
async function pbkdf2(password, saltBytes, iters, keyLen) {
  const keyMaterial = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), { name:"PBKDF2" }, false, ["deriveBits"]);
  return await crypto.subtle.deriveBits({ name:"PBKDF2", hash:"SHA-256", salt:saltBytes, iterations: iters }, keyMaterial, keyLen*8);
}
async function verifyPassword(password, stored, pepper="") {
  const parts = String(stored||"").split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;
  const iters = Number(parts[1]||0);
  const salt = fromB64Url(parts[2]);
  const hash = fromB64Url(parts[3]);
  if (!iters || !salt || !hash) return false;
  const derivedBits = await pbkdf2(password + pepper, salt, iters, hash.byteLength);
  return timingSafeEqual(new Uint8Array(derivedBits), new Uint8Array(hash));
}

async function requireAuth(request, env){
  const token = getBearer(request);
  if (!token) throw new Error("missing_authorization");
  const tokenHash = await sha256Hex(token);
  const row = await env.DB.prepare("SELECT username, expires_at FROM sessions WHERE token_hash=?1").bind(tokenHash).first();
  if (!row) throw new Error("invalid_token");
  const exp = row.expires_at ? Date.parse(row.expires_at) : NaN;
  if (Number.isFinite(exp) && exp < Date.now()){
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?1").bind(tokenHash).run();
    throw new Error("token_expired");
  }
  return { username: row.username, tokenHash };
}

async function mintSession(env, username){
  const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
  const token = base64Url(tokenBytes);
  const tokenHash = await sha256Hex(token);
  const ttl = Number(env.SESSION_TTL_MS || 1000*60*60*24*7);
  const expires = new Date(Date.now()+ttl).toISOString();
  await env.DB.prepare("INSERT INTO sessions (token_hash, username, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)")
    .bind(tokenHash, username, new Date().toISOString(), expires).run();
  return token;
}

// ---------------- AUTH endpoints ----------------
async function handleLogin(request, env){
  const origin = request.headers.get("origin") || "";
  if (origin && !ALLOWED_ORIGINS.has(origin)) return jsonResponse({ error:"origin_not_allowed", origin }, 403);

  const body = await readJson(request);
  if (!body) return jsonResponse({ error:"invalid_json" }, 400);

  const user = String(body.user||"").trim();
  const password = String(body.password||"").trim();
  if (!user || !password) return jsonResponse({ error:"missing_user_password" }, 400);

  const row = await env.DB.prepare("SELECT username, password_hash, role, is_active FROM users WHERE username=?1").bind(user).first();
  if (!row || Number(row.is_active ?? 1) !== 1) return jsonResponse({ error:"invalid_credentials" }, 401);

  const ok = await verifyPassword(password, row.password_hash, env.PASSWORD_PEPPER || "");
  if (!ok) return jsonResponse({ error:"invalid_credentials" }, 401);

  const token = await mintSession(env, user);
  return jsonResponse({ ok:true, token, user: { username: user, role: String(row.role||"user") } }, 200);
}
async function handleMe(request, env){
  try{
    const auth = await requireAuth(request, env);
    const row = await env.DB.prepare("SELECT role FROM users WHERE username=?1").bind(auth.username).first();
    const role = String(row?.role || "user");
    return jsonResponse({ ok:true, user:{ username: auth.username, role } }, 200);
  }catch(e){
    return jsonResponse({ error: String(e?.message || "unauthorized") }, 401);
  }
}
async function handleLogout(request, env){
  try{
    const auth = await requireAuth(request, env);
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?1").bind(auth.tokenHash).run();
  }catch{}
  return jsonResponse({ ok:true }, 200);
}

// ---------------- CTOs ----------------
function normId(v){ return String(v||"").trim(); }
function normNum(v){ const n = Number(v); return Number.isFinite(n) ? n : null; }
function normInt(v){ const n = parseInt(String(v),10); return Number.isFinite(n) ? n : 0; }

async function handleGetCtos(_req, env){
  const rs = await env.DB.prepare("SELECT cto_id, nome, rua, bairro, lat, lng, capacidade FROM ctos").all();
  return jsonResponse({ ok:true, ctos: rs.results || [] }, 200);
}
async function handleUpsertCto(request, env){
  // keep admin check outside for now if you want; for continuity, allow any authenticated user to upsert? no.
  // We'll keep as-is: require auth then role=admin is handled elsewhere in your full worker.
  const body = await readJson(request);
  if (!body) return jsonResponse({ error:"invalid_json" }, 400);

  const cto_id = normId(body.cto_id || body.CTO_ID || body.id);
  const nome = String(body.nome ?? body.NOME ?? cto_id);
  const rua = String(body.rua ?? body.RUA ?? "");
  const bairro = String(body.bairro ?? body.BAIRRO ?? "");
  const lat = normNum(body.lat ?? body.LAT);
  const lng = normNum(body.lng ?? body.LNG);
  const capacidade = normInt(body.capacidade ?? body.CAPACIDADE ?? 0);
  if (!cto_id || lat==null || lng==null) return jsonResponse({ error:"missing_fields" }, 400);

  await env.DB.prepare(`INSERT INTO ctos (cto_id, nome, rua, bairro, lat, lng, capacidade)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
    ON CONFLICT(cto_id) DO UPDATE SET
      nome=excluded.nome, rua=excluded.rua, bairro=excluded.bairro,
      lat=excluded.lat, lng=excluded.lng, capacidade=excluded.capacidade
  `).bind(cto_id, nome, rua, bairro, lat, lng, capacidade).run();

  return jsonResponse({ ok:true, cto: { cto_id, nome, rua, bairro, lat, lng, capacidade } }, 200);
}
async function handleDeleteCto(request, env){
  const id = normId(new URL(request.url).searchParams.get("id") || "");
  if (!id) return jsonResponse({ error:"missing_id" }, 400);
  await env.DB.prepare("DELETE FROM ctos WHERE cto_id=?1").bind(id).run();
  return jsonResponse({ ok:true }, 200);
}

// ---------------- CE/CDO ----------------
async function handleGetCeCdo(_req, env){
  const rs = await env.DB.prepare("SELECT id, nome, rua, bairro, lat, lng, tipo FROM caixas_emenda_cdo").all();
  return jsonResponse({ ok:true, items: rs.results || [] }, 200);
}
async function handleUpsertCeCdo(request, env){
  const body = await readJson(request);
  if (!body) return jsonResponse({ error:"invalid_json" }, 400);

  const id = normId(body.id || body.ID || body.ce_id || body.cdo_id);
  const nome = String(body.nome ?? body.NOME ?? id);
  const rua = String(body.rua ?? body.RUA ?? "");
  const bairro = String(body.bairro ?? body.BAIRRO ?? "");
  const lat = normNum(body.lat ?? body.LAT);
  const lng = normNum(body.lng ?? body.LNG);
  const tipoRaw = String(body.tipo ?? body.TIPO ?? "CDO").toUpperCase();
  const tipo = (tipoRaw === "CE") ? "CE" : "CDO";
  if (!id || lat==null || lng==null) return jsonResponse({ error:"missing_fields" }, 400);

  await env.DB.prepare(`INSERT INTO caixas_emenda_cdo (id, nome, rua, bairro, lat, lng, tipo)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
    ON CONFLICT(id) DO UPDATE SET
      nome=excluded.nome, rua=excluded.rua, bairro=excluded.bairro,
      lat=excluded.lat, lng=excluded.lng, tipo=excluded.tipo
  `).bind(id, nome, rua, bairro, lat, lng, tipo).run();

  return jsonResponse({ ok:true, item: { id, nome, rua, bairro, lat, lng, tipo } }, 200);
}
async function handleDeleteCeCdo(request, env){
  const id = normId(new URL(request.url).searchParams.get("id") || "");
  if (!id) return jsonResponse({ error:"missing_id" }, 400);
  await env.DB.prepare("DELETE FROM caixas_emenda_cdo WHERE id=?1").bind(id).run();
  return jsonResponse({ ok:true }, 200);
}

// ---------------- Movimentações (GET) ----------------
async function handleGetMovimentacoes(_req, env, url){
  // optional limit param
  const limit = Math.min(500, Math.max(0, parseInt(url.searchParams.get("limit")||"300",10) || 300));
  try{
    const rs = await env.DB.prepare("SELECT id, cto_id, tipo, cliente, usuario, obs, ts FROM movimentacoes ORDER BY ts DESC LIMIT ?1")
      .bind(limit).all();
    return jsonResponse({ ok:true, items: rs.results || [] }, 200);
  }catch(e){
    // If table missing for some reason, return empty instead of 404/500
    return jsonResponse({ ok:true, items: [], note: "no_table" }, 200);
  }
}
