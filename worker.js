/**
 * FTTH-PWA Worker - FULL (D1 + Roles + CTO CRUD + CSV endpoints) - 2026-03-01
 *
 * Fixes:
 * - Login returns ROLE (admin shows as admin, not user)
 * - Restores /api/movimentacoes, /api/rotas_fibras, /api/caixas_emenda_cdo, /api/log_eventos, /api/usuarios
 * - CORS allows Authorization + X-Admin-Password
 *
 * REQUIRED:
 * - D1 binding: DB  (ftth-db)
 * - D1 tables: users, sessions, ctos
 * - Secret: ADMIN_PASSWORD (for writes)
 *
 * OPTIONAL (CSV reads): SHEETS_*_CSV_URL variables (if missing -> returns [] / empty FC)
 * OPTIONAL (/api/submit): APPS_SCRIPT_URL, SUBMIT_KEY
 */

const ALLOWED_ORIGINS = new Set([
  "https://ftth-pwa.pages.dev",
  "http://localhost:8788",
  "http://localhost:5173",
  "http://localhost:3000",
]);

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const { pathname } = url;

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(request, { restricted: true }) });
    }

    try {
      if (request.method === "GET" && (pathname === "/" || pathname === "/api" || pathname === "/api/")) {
        return corsJson(request, { ok: true, service: "ftth-pwa", version: "2026-03-01-full-d1-role-csv" });
      }

      // AUTH
      if (pathname === "/api/login" && request.method === "POST") return corsResponse(request, await handleLogin(request, env));
      if (pathname === "/api/me" && request.method === "GET") return corsResponse(request, await handleMe(request, env));
      if (pathname === "/api/logout" && request.method === "POST") return corsResponse(request, await handleLogout(request, env));

      // CTOs (D1)
      if (pathname === "/api/ctos") {
        if (!env.DB) return corsJson(request, { error: "DB_not_configured" }, 500);
        if (request.method === "GET") return corsResponse(request, await handleGetCtos(env));
        if (request.method === "POST") return corsResponse(request, await handleUpsertCto(request, env));
        if (request.method === "DELETE") return corsResponse(request, await handleDeleteCto(request, env));
        return corsJson(request, { error: "method_not_allowed" }, 405);
      }

      // CSV endpoints (UI expects these)
      if (pathname === "/api/movimentacoes" && request.method === "GET") return corsJson(request, await getMovimentacoes(env), 200, { cacheSeconds: 30 });
      if (pathname === "/api/rotas_fibras" && request.method === "GET") return corsJson(request, await getRotasFibras(env), 200, { cacheSeconds: 60 });
      if (pathname === "/api/caixas_emenda_cdo" && request.method === "GET") return corsJson(request, await getCaixas(env), 200, { cacheSeconds: 60 });
      if (pathname === "/api/log_eventos" && request.method === "GET") return corsJson(request, await getLogEventos(env, url), 200, { cacheSeconds: 15 });
      if (pathname === "/api/usuarios" && request.method === "GET") return corsJson(request, await getUsuarios(env), 200, { cacheSeconds: 30 });

      // Optional /api/submit
      if (pathname === "/api/submit" && request.method === "POST") return corsResponse(request, await handleSubmit(request, env));

      return corsJson(request, { error: "not_found" }, 404);
    } catch (err) {
      return corsJson(request, { error: "server_error", message: String(err?.stack || err) }, 500);
    }
  },
};

// ---------------- CORS ----------------
function corsHeaders(request, { restricted } = { restricted: true }) {
  const origin = request.headers.get("origin") || "";
  const allowOrigin = restricted ? (ALLOWED_ORIGINS.has(origin) ? origin : "") : "*";

  const h = {
    "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Admin-Password",
    "Vary": "Origin",
  };
  if (allowOrigin) h["Access-Control-Allow-Origin"] = allowOrigin;
  else if (!restricted) h["Access-Control-Allow-Origin"] = "*";
  return h;
}
function corsResponse(request, response) {
  const headers = new Headers(response.headers);
  const ch = corsHeaders(request, { restricted: true });
  for (const [k, v] of Object.entries(ch)) headers.set(k, v);
  return new Response(response.body, { status: response.status, headers });
}
function corsJson(request, obj, status = 200, { cacheSeconds } = {}) {
  const headers = {};
  if (cacheSeconds != null) headers["Cache-Control"] = `public, max-age=${cacheSeconds}`;
  return corsResponse(request, new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json; charset=utf-8", ...headers } }));
}
async function readJson(request) { return await request.json().catch(() => null); }

// ---------------- Admin ----------------
function requireAdmin(request, env) {
  const expected = String(env.ADMIN_PASSWORD || "").trim();
  if (!expected) return { ok: false, status: 500, error: "ADMIN_PASSWORD_not_configured" };
  const got = String(request.headers.get("x-admin-password") || request.headers.get("X-Admin-Password") || "").trim();
  if (!got) return { ok: false, status: 401, error: "missing_admin_password" };
  if (got !== expected) return { ok: false, status: 401, error: "invalid_admin_password" };
  return { ok: true };
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
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function base64Url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
async function mintSession(env, username) {
  const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
  const token = base64Url(tokenBytes);
  const tokenHash = await sha256Hex(token);
  const ttl = Number(env.SESSION_TTL_MS || 1000 * 60 * 60 * 24 * 7);
  const expires = new Date(Date.now() + ttl).toISOString();
  await env.DB.prepare("INSERT INTO sessions (token_hash, username, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)")
    .bind(tokenHash, username, new Date().toISOString(), expires).run();
  return token;
}
async function requireAuth(request, env) {
  const token = getBearer(request);
  if (!token) throw new Error("missing_authorization");
  const tokenHash = await sha256Hex(token);
  const row = await env.DB.prepare("SELECT username, expires_at FROM sessions WHERE token_hash=?1").bind(tokenHash).first();
  if (!row) throw new Error("invalid_token");
  const exp = row.expires_at ? Date.parse(row.expires_at) : NaN;
  if (Number.isFinite(exp) && exp < Date.now()) {
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?1").bind(tokenHash).run();
    throw new Error("token_expired");
  }
  return { user: row.username, tokenHash };
}

// PBKDF2 verify
async function verifyPassword(password, stored, pepper) {
  const parts = String(stored || "").split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;
  const iters = Number(parts[1] || 0);
  const salt = fromB64Url(parts[2]);
  const hash = fromB64Url(parts[3]);
  if (!iters || !salt || !hash) return false;
  const derived = await pbkdf2(password + (pepper || ""), salt, iters, hash.byteLength);
  return timingSafeEqual(new Uint8Array(derived), new Uint8Array(hash));
}
async function pbkdf2(password, saltBytes, iters, keyLen) {
  const keyMaterial = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), { name: "PBKDF2" }, false, ["deriveBits"]);
  return await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations: iters }, keyMaterial, keyLen * 8);
}
function fromB64Url(s) {
  try {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = atob(s);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  } catch { return null; }
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a[i] ^ b[i];
  return r === 0;
}

// ---------------- AUTH handlers ----------------
async function handleLogin(request, env) {
  const origin = request.headers.get("origin") || "";
  if (origin && !ALLOWED_ORIGINS.has(origin)) return new Response(JSON.stringify({ error: "origin_not_allowed", origin }), { status: 403, headers: { "Content-Type": "application/json" } });
  if (!env.DB) return new Response(JSON.stringify({ error: "DB_not_configured" }), { status: 500, headers: { "Content-Type": "application/json" } });

  const body = await readJson(request);
  if (!body) return new Response(JSON.stringify({ error: "invalid_json" }), { status: 400, headers: { "Content-Type": "application/json" } });

  const user = String(body.user || "").trim();
  const password = String(body.password || "").trim();
  if (!user || !password) return new Response(JSON.stringify({ error: "missing_user_password" }), { status: 400, headers: { "Content-Type": "application/json" } });

  const row = await env.DB.prepare("SELECT username, password_hash, role FROM users WHERE username=?1 AND is_active=1").bind(user).first();
  if (!row) return new Response(JSON.stringify({ error: "invalid_credentials" }), { status: 401, headers: { "Content-Type": "application/json" } });

  const ok = await verifyPassword(password, row.password_hash, env.PASSWORD_PEPPER || "");
  if (!ok) return new Response(JSON.stringify({ error: "invalid_credentials" }), { status: 401, headers: { "Content-Type": "application/json" } });

  const token = await mintSession(env, user);
  const role = String(row.role || "user").trim() || "user";
  return new Response(JSON.stringify({ ok: true, token, user: { username: user, role } }), { status: 200, headers: { "Content-Type": "application/json" } });
}

async function handleMe(request, env) {
  try {
    const auth = await requireAuth(request, env);
    const row = await env.DB.prepare("SELECT role FROM users WHERE username=?1").bind(auth.user).first();
    const role = String(row?.role || "user").trim() || "user";
    return new Response(JSON.stringify({ ok: true, user: { username: auth.user, role } }), { status: 200, headers: { "Content-Type": "application/json" } });
  } catch {
    return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: { "Content-Type": "application/json" } });
  }
}

async function handleLogout(request, env) {
  const origin = request.headers.get("origin") || "";
  if (origin && !ALLOWED_ORIGINS.has(origin)) return new Response(JSON.stringify({ error: "origin_not_allowed", origin }), { status: 403, headers: { "Content-Type": "application/json" } });

  try {
    const auth = await requireAuth(request, env);
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?1").bind(auth.tokenHash).run();
  } catch { /* ignore */ }

  return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "Content-Type": "application/json" } });
}

// ---------------- CTO handlers ----------------
async function handleGetCtos(env) {
  const rs = await env.DB.prepare("SELECT CTO_ID, NOME, RUA, BAIRRO, LAT, LNG, CAPACIDADE, created_at, updated_at FROM ctos").all();
  const items = (rs.results || []).map((r) => ({
    cto_id: String(r.CTO_ID || "").trim(),
    nome: String(r.NOME || "").trim(),
    rua: String(r.RUA || "").trim(),
    bairro: String(r.BAIRRO || "").trim(),
    lat: Number(r.LAT),
    lng: Number(r.LNG),
    capacidade: r.CAPACIDADE == null ? null : Number(r.CAPACIDADE),
    created_at: r.created_at,
    updated_at: r.updated_at,
  })).filter((x) => x.cto_id && Number.isFinite(x.lat) && Number.isFinite(x.lng));

  return new Response(JSON.stringify(items), { status: 200, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
}

async function handleUpsertCto(request, env) {
  const origin = request.headers.get("origin") || "";
  if (origin && !ALLOWED_ORIGINS.has(origin)) return new Response(JSON.stringify({ error: "origin_not_allowed", origin }), { status: 403, headers: { "Content-Type": "application/json" } });

  const adm = requireAdmin(request, env);
  if (!adm.ok) return new Response(JSON.stringify({ error: adm.error }), { status: adm.status, headers: { "Content-Type": "application/json" } });

  const body = await readJson(request);
  if (!body) return new Response(JSON.stringify({ error: "invalid_json" }), { status: 400, headers: { "Content-Type": "application/json" } });

  const CTO_ID = String(body.CTO_ID ?? body.cto_id ?? body.id ?? "").trim();
  const NOME = String(body.NOME ?? body.nome ?? CTO_ID ?? "").trim();
  const RUA = String(body.RUA ?? body.rua ?? "").trim();
  const BAIRRO = String(body.BAIRRO ?? body.bairro ?? "").trim();
  const LAT = Number(String(body.LAT ?? body.lat ?? "").replace(",", "."));
  const LNG = Number(String(body.LNG ?? body.lng ?? "").replace(",", "."));
  const CAPACIDADE = Number.isFinite(Number(body.CAPACIDADE ?? body.capacidade)) ? Math.trunc(Number(body.CAPACIDADE ?? body.capacidade)) : 0;

  if (!CTO_ID) return new Response(JSON.stringify({ error: "missing_CTO_ID" }), { status: 400, headers: { "Content-Type": "application/json" } });
  if (!Number.isFinite(LAT) || !Number.isFinite(LNG)) return new Response(JSON.stringify({ error: "missing_lat_lng" }), { status: 400, headers: { "Content-Type": "application/json" } });

  const now = new Date().toISOString();
  await env.DB.prepare(`
    INSERT INTO ctos (CTO_ID, NOME, RUA, BAIRRO, LAT, LNG, CAPACIDADE, created_at, updated_at)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, COALESCE(?8, datetime('now')), ?9)
    ON CONFLICT(CTO_ID) DO UPDATE SET
      NOME = excluded.NOME,
      RUA = excluded.RUA,
      BAIRRO = excluded.BAIRRO,
      LAT = excluded.LAT,
      LNG = excluded.LNG,
      CAPACIDADE = excluded.CAPACIDADE,
      updated_at = excluded.updated_at
  `).bind(CTO_ID, NOME, RUA, BAIRRO, LAT, LNG, CAPACIDADE, now, now).run();

  return new Response(JSON.stringify({ ok: true, cto: { cto_id: CTO_ID, nome: NOME, rua: RUA, bairro: BAIRRO, lat: LAT, lng: LNG, capacidade: CAPACIDADE } }), { status: 200, headers: { "Content-Type": "application/json" } });
}

async function handleDeleteCto(request, env) {
  const origin = request.headers.get("origin") || "";
  if (origin && !ALLOWED_ORIGINS.has(origin)) return new Response(JSON.stringify({ error: "origin_not_allowed", origin }), { status: 403, headers: { "Content-Type": "application/json" } });

  const adm = requireAdmin(request, env);
  if (!adm.ok) return new Response(JSON.stringify({ error: adm.error }), { status: adm.status, headers: { "Content-Type": "application/json" } });

  const url = new URL(request.url);
  const id = String(url.searchParams.get("id") || "").trim();
  if (!id) return new Response(JSON.stringify({ error: "missing_id" }), { status: 400, headers: { "Content-Type": "application/json" } });

  await env.DB.prepare("DELETE FROM ctos WHERE CTO_ID=?1").bind(id).run();
  return new Response(JSON.stringify({ ok: true, deleted: id }), { status: 200, headers: { "Content-Type": "application/json" } });
}

// ---------------- Optional /api/submit ----------------
async function handleSubmit(request, env) {
  const origin = request.headers.get("origin") || "";
  if (origin && !ALLOWED_ORIGINS.has(origin)) return new Response(JSON.stringify({ error: "origin_not_allowed", origin }), { status: 403, headers: { "Content-Type": "application/json" } });

  const auth = await requireAuth(request, env);
  const key = String(env.SUBMIT_KEY || "").trim();
  const scriptUrl = String(env.APPS_SCRIPT_URL || "").trim();
  if (!key) return new Response(JSON.stringify({ error: "SUBMIT_KEY_not_configured" }), { status: 500, headers: { "Content-Type": "application/json" } });
  if (!scriptUrl) return new Response(JSON.stringify({ error: "APPS_SCRIPT_URL_not_configured" }), { status: 500, headers: { "Content-Type": "application/json" } });

  const body = await readJson(request);
  if (!body) return new Response(JSON.stringify({ error: "invalid_json" }), { status: 400, headers: { "Content-Type": "application/json" } });

  const items = Array.isArray(body.items) ? body.items : [body];

  const forward = await fetch(scriptUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ key, user: auth.user, items }),
  });

  const text = await forward.text();
  return new Response(text, { status: forward.status, headers: { "Content-Type": forward.headers.get("content-type") || "text/plain; charset=utf-8" } });
}

// ---------------- CSV endpoints ----------------
async function fetchCSV(csvUrl) {
  if (!csvUrl) return [];
  const res = await fetch(csvUrl, { cf: { cacheTtl: 60, cacheEverything: true }, headers: { "user-agent": "ftth-pwa-worker" } });
  if (!res.ok) return [];
  return parseCSV(await res.text());
}
function parseCSV(text) {
  const lines = text.split(/\r?\n/).map((l) => l.trimEnd()).filter((l) => l.length > 0);
  if (!lines.length) return [];
  const header = splitCSVLine(lines[0]).map((h) => h.trim());
  const out = [];
  for (let i = 1; i < lines.length; i++) {
    const cols = splitCSVLine(lines[i]);
    const obj = {};
    for (let c = 0; c < header.length; c++) obj[header[c]] = cols[c] ?? "";
    out.push(obj);
  }
  return out;
}
function splitCSVLine(line) {
  const res = [];
  let cur = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') { cur += '"'; i++; }
      else inQuotes = !inQuotes;
      continue;
    }
    if (ch === "," && !inQuotes) { res.push(cur); cur = ""; continue; }
    cur += ch;
  }
  res.push(cur);
  return res;
}

async function getMovimentacoes(env) {
  const rows = await fetchCSV(env.SHEETS_MOVIMENTACOES_CSV_URL);
  return rows.map((r) => ({
    data: s(r.DATA),
    cto_id: s(r.CTO_ID),
    tipo: s(r.Tipo ?? r.TIPO),
    cliente: s(r.Cliente ?? r.CLIENTE),
    usuario: s(r.Usuario ?? r.USUARIO),
    observacao: s(r.Observacao ?? r.OBSERVACAO),
  })).filter((x) => x.data || x.cto_id);
}
async function getCaixas(env) {
  const rows = await fetchCSV(env.SHEETS_CAIXAS_EMENDA_CDO_CSV_URL);
  return rows.map((r) => ({
    id: s(r.ID),
    tipo: s(r.TIPO),
    lat: num(r.LAT),
    lng: num(r.LNG),
    obs: s(r.OBS),
    img_url: s(r.IMG_URL),
    dt_criacao: s(r.DT_CRIACAO),
    dt_atualizacao: s(r.DT_ATUALIZACAO),
  })).filter((x) => x.id && finite(x.lat) && finite(x.lng));
}
async function getRotasFibras(env) {
  const rows = await fetchCSV(env.SHEETS_ROTAS_FIBRAS_CSV_URL);
  const points = rows.map((r) => ({
    rota_id: s(r.ROTA_ID),
    ordem: intOrNull(r.ORDEM),
    lat: num(r.LAT),
    lng: num(r.LNG),
    tipo: s(r.TIPO),
    peso: numOrNull(r.PESO),
  })).filter((p) => p.rota_id && finite(p.lat) && finite(p.lng) && p.ordem !== null);

  const byRoute = new Map();
  for (const p of points) {
    if (!byRoute.has(p.rota_id)) byRoute.set(p.rota_id, []);
    byRoute.get(p.rota_id).push(p);
  }

  const features = [];
  for (const [rota_id, pts] of byRoute.entries()) {
    pts.sort((a, b) => a.ordem - b.ordem);
    const coords = pts.map((p) => [p.lng, p.lat]);
    const tipos = uniq(pts.map((p) => p.tipo).filter(Boolean));
    const pesoVals = pts.map((p) => p.peso).filter((x) => x !== null);
    const pesoMedio = pesoVals.length ? avg(pesoVals) : null;

    features.push({
      type: "Feature",
      geometry: { type: "LineString", coordinates: coords },
      properties: { rota_id, pontos: pts.length, tipos, peso_medio: pesoMedio },
    });
  }
  return { type: "FeatureCollection", features };
}
async function getLogEventos(env, url) {
  const rows = await fetchCSV(env.SHEETS_LOG_EVENTOS_CSV_URL);
  const since = url.searchParams.get("since");
  const sinceMs = since ? Date.parse(since) : null;

  const items = rows.map((r) => ({
    ts: s(r.TS),
    user: s(r.USER),
    role: s(r.ROLE),
    action: s(r.ACTION),
    entity: s(r.ENTITY),
    entity_id: s(r.ENTITY_ID),
    details: s(r.DETAILS),
  })).filter((x) => x.ts);

  if (sinceMs && Number.isFinite(sinceMs)) {
    return items.filter((x) => {
      const t = Date.parse(x.ts);
      return Number.isFinite(t) ? t >= sinceMs : true;
    });
  }
  return items;
}
async function getUsuarios(env) {
  const rows = await fetchCSV(env.SHEETS_USUARIOS_CSV_URL);
  return rows.map((r) => ({
    user: s(r.USER),
    role: s(r.ROLE),
    active: bool(r.ACTIVE),
    created_at: s(r.CREATED_AT),
    must_change: bool(r.MUST_CHANGE),
    updated_at: s(r.UPDATED_AT),
    last_login: s(r.LAST_LOGIN),
  })).filter((x) => x.user);
}
