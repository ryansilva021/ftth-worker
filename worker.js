// FTTH-PWA Worker (Cloudflare Workers + D1)
// 2026-02-27
// Fixes in this build:
// - /api/ctos 404 on save: implements CRUD routes (POST/PUT/PATCH/DELETE) with RBAC (admin only)
// - Keeps GET data endpoints (CSV -> JSON) for map rendering
// - Normalizes user roles so admin shows as admin
// - Proxy: /api/tiles/* and /api/reverse_geocode to avoid CORS issues

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      let { pathname } = url;

  // Alias: keep GET /api/rotas_fibras (GeoJSON export), but route writes to /api/rotas for backward-compat.
  if (pathname === "/api/rotas_fibras" && request.method !== "GET") {
    pathname = "/api/rotas";
  }
// CORS preflight
      if (request.method === "OPTIONS") return corsResponse(request, new Response(null, { status: 204 }));

      // Health / root
      if (request.method === "GET" && (pathname === "/" || pathname === "/health")) {
        return corsJson(request, {
          ok: true,
          service: "ftth-pwa",
          version: "2026-02-27-crud",
          endpoints: [
            "POST /api/login",
            "GET  /api/me",
            "POST /api/logout",
            "GET  /api/ctos",
            "POST /api/ctos (admin)",
            "DELETE /api/ctos (admin)",
            "GET  /api/caixas_emenda_cdo",
            "POST /api/caixas_emenda_cdo (admin)",
            "DELETE /api/caixas_emenda_cdo (admin)",
            "GET  /api/rotas_fibras",
            "POST /api/rotas (admin)",
            "DELETE /api/rotas (admin)",
            "GET  /api/movimentacoes",
            "GET  /api/usuarios",
            "GET  /api/log_eventos",
            "GET  /api/reverse_geocode?lat=..&lng=..",
            "GET  /api/tiles/{z}/{x}/{y}.png"
          ]
        });
      }

      // Auth
      if (pathname === "/api/login" && request.method === "POST") return corsResponse(request, await handleLogin(request, env));
      if (pathname === "/api/me" && request.method === "GET") return corsResponse(request, await handleMe(request, env));
      if (pathname === "/api/logout" && request.method === "POST") return corsResponse(request, await handleLogout(request, env));

      // Proxy helpers
      if (pathname === "/api/reverse_geocode" && request.method === "GET") return corsResponse(request, await handleReverseGeocode(request));
      if (pathname.startsWith("/api/tiles/") && request.method === "GET") return corsResponse(request, await handleTileProxy(request));

      // ===== CRUD (admin only) =====
      // NOTE: Pages currently saves to /api/ctos and expects success.
      // We accept flexible body shapes and forward to Apps Script (APPS_SCRIPT_URL) using SUBMIT_KEY.
      if (pathname === "/api/ctos" && isWriteMethod(request.method)) return corsResponse(request, await handleCrudCtos(request, env));
      if (pathname === "/api/caixas_emenda_cdo" && isWriteMethod(request.method)) return corsResponse(request, await handleCrudCaixas(request, env));
      if (pathname === "/api/rotas" && isWriteMethod(request.method)) return corsResponse(request, await handleCrudRotas(request, env));

      // ===== Data endpoints (auth required) =====
      if (pathname === "/api/ctos" && request.method === "GET") return corsResponse(request, await handleGetCtos(request, env));
      if (pathname === "/api/caixas_emenda_cdo" && request.method === "GET") return corsResponse(request, await handleGetCaixas(request, env));
      if (pathname === "/api/rotas_fibras" && request.method === "GET") return corsResponse(request, await handleGetRotas(request, env));
      if (pathname === "/api/movimentacoes" && request.method === "GET") return corsResponse(request, await handleGetMovimentacoes(request, env));
      if (pathname === "/api/usuarios" && request.method === "GET") return corsResponse(request, await handleGetUsuarios(request, env));
      if (pathname === "/api/log_eventos" && request.method === "GET") return corsResponse(request, await handleGetLogEventos(request, env));

      return corsJson(request, { error: "not_found" }, 404);
    } catch (err) {
      return corsJson(request, { error: "server_error", message: String(err?.stack || err) }, 500);
    }
  }
};

function isWriteMethod(m) {
  return m === "POST" || m === "PUT" || m === "PATCH" || m === "DELETE";
}

// ======================= CORS helpers =======================
function corsHeaders(request) {
  const origin = request.headers.get("Origin") || "*";
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Credentials": "true",
    "Vary": "Origin"
  };
}
function corsResponse(request, response) {
  const h = new Headers(response.headers);
  const ch = corsHeaders(request);
  for (const [k, v] of Object.entries(ch)) h.set(k, v);
  return new Response(response.body, { status: response.status, headers: h });
}
function corsJson(request, obj, status = 200) {
  return corsResponse(request, json(obj, status));
}
function json(obj, status = 200, headers = {}) {
  const extra = headers?.cacheSeconds
    ? { "Cache-Control": `public, max-age=${Number(headers.cacheSeconds) || 0}` }
    : {};
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...extra }
  });
}
async function readJson(request) {
  const ct = request.headers.get("Content-Type") || "";
  // Some browsers send "application/json;charset=utf-8"
  if (!ct.includes("application/json")) return null;
  return await request.json().catch(() => null);
}

// ======================= Auth / Sessions =======================
function getBearer(request) {
  const h = request.headers.get("Authorization") || "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}
async function sha256Hex(str) {
  const enc = new TextEncoder().encode(str);
  const buf = await crypto.subtle.digest("SHA-256", enc);
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}

// PBKDF2 format stored: pbkdf2$<iter>$<salt_b64>$<hash_b64>
async function verifyPassword(password, stored) {
  if (!stored) return false;

  if (stored.startsWith("pbkdf2$")) {
    const parts = stored.split("$");
    if (parts.length !== 4) return false;
    const iter = Number(parts[1]);
    const saltB64 = parts[2];
    const hashB64 = parts[3];

    const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
    const expected = Uint8Array.from(atob(hashB64), c => c.charCodeAt(0));

    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );
    const derivedBits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations: iter },
      keyMaterial,
      expected.length * 8
    );
    const got = new Uint8Array(derivedBits);
    return timingSafeEqual(got, expected);
  }

  // legacy: raw sha256 hex (tecnico1 inserted manually)
  if (/^[0-9a-f]{64}$/i.test(stored)) {
    const got = await sha256Hex(password);
    return got.toLowerCase() === stored.toLowerCase();
  }

  return false;
}
function timingSafeEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
function base64Url(bytes) {
  let s = btoa(String.fromCharCode(...bytes));
  return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
async function mintSession(env, username) {
  const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
  const token = base64Url(tokenBytes);
  const tokenHash = await sha256Hex(token);
  const ttl = Number(env.SESSION_TTL_MS || (1000 * 60 * 60 * 24 * 7));
  const expiresAt = new Date(Date.now() + ttl).toISOString();
  await env.DB.prepare(
    "INSERT INTO sessions (token_hash, username, created_at, expires_at) VALUES (?1, ?2, datetime('now'), ?3)"
  ).bind(tokenHash, username, expiresAt).run();
  return token;
}
async function requireAuth(request, env) {
  const token = getBearer(request);
  if (!token) throw Object.assign(new Error("unauthorized"), { code: "unauthorized" });

  const tokenHash = await sha256Hex(token);
  const row = await env.DB.prepare(
    "SELECT username, expires_at FROM sessions WHERE token_hash=?1"
  ).bind(tokenHash).first();

  if (!row) throw Object.assign(new Error("unauthorized"), { code: "unauthorized" });
  if (row.expires_at && Date.parse(row.expires_at) < Date.now()) {
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?1").bind(tokenHash).run();
    throw Object.assign(new Error("unauthorized"), { code: "unauthorized" });
  }
  return { user: row.username, tokenHash };
}
function normalizeRole(role) {
  const r = String(role || "").trim().toLowerCase();
  if (r === "admin") return "admin";
  return "user";
}
async function getUserRole(env, username) {
  try {
    const row = await env.DB.prepare("SELECT role FROM users WHERE username=?1 AND is_active=1").bind(username).first();
    return normalizeRole(row?.role || "user");
  } catch (_e) {
    return "user";
  }
}
async function requireRole(request, env, allowedRoles) {
  const auth = await requireAuth(request, env);
  const role = await getUserRole(env, auth.user);
  if (!allowedRoles.includes(role)) {
    const err = new Error("forbidden");
    err.code = "forbidden";
    err.role = role;
    throw err;
  }
  return { ...auth, role };
}

async function handleLogin(request, env) {
  const body = await readJson(request);
  const username = String(body?.username ?? body?.user ?? body?.login ?? "").trim();
  const password = String(body?.password ?? body?.pass ?? "");
  if (!username || !password) return json({ error: "missing_credentials" }, 400);

  const user = await env.DB.prepare(
    "SELECT username, password_hash, is_active, role FROM users WHERE username=?1"
  ).bind(username).first();

  if (!user || !user.is_active) return json({ error: "invalid_credentials" }, 401);
  const ok = await verifyPassword(password, user.password_hash);
  if (!ok) return json({ error: "invalid_credentials" }, 401);

  const role = normalizeRole(user.role);
  const token = await mintSession(env, username);
  return json({ ok: true, token, user: { username, role } });
}
async function handleMe(request, env) {
  try {
    const auth = await requireAuth(request, env);
    const role = await getUserRole(env, auth.user);
    return json({ ok: true, user: { username: auth.user, role } });
  } catch (_e) {
    return json({ error: "unauthorized" }, 401);
  }
}
async function handleLogout(request, env) {
  try {
    const auth = await requireAuth(request, env);
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?1").bind(auth.tokenHash).run();
    return json({ ok: true });
  } catch (_e) {
    return json({ ok: true });
  }
}

// ======================= Reverse Geocode (proxy) =======================
async function handleReverseGeocode(request) {
  const url = new URL(request.url);
  const lat = url.searchParams.get("lat");
  const lng = url.searchParams.get("lng");
  if (!lat || !lng) return json({ ok: false, error: "missing_lat_lng" }, 400);

  const api = `https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat=${encodeURIComponent(lat)}&lon=${encodeURIComponent(lng)}&zoom=18&addressdetails=1`;
  const res = await fetch(api, {
    headers: {
      "accept": "application/json",
      "accept-language": "pt-BR,pt;q=0.9,en;q=0.5",
      "user-agent": "ftth-pwa/1.0 (Cloudflare Worker)"
    }
  });
  if (!res.ok) return json({ ok: false, error: "reverse_geocode_failed", status: res.status }, 502);

  const data = await res.json().catch(() => null);
  const a = data?.address || {};
  const rua = a.road || a.pedestrian || a.footway || a.residential || "";
  const bairro = a.suburb || a.neighbourhood || a.quarter || a.city_district || a.district || "";
  return json({ ok: true, rua, bairro, raw: data });
}

// ======================= Tile Proxy (OSM) =======================
async function handleTileProxy(request) {
  const url = new URL(request.url);
  const parts = url.pathname.split("/").filter(Boolean); // ["api","tiles","z","x","y.png"]
  if (parts.length < 5) return json({ error: "bad_tile_path" }, 400);
  const z = parts[2], x = parts[3];
  let y = parts[4];
  if (y.endsWith(".png")) y = y.slice(0, -4);
  if (![z, x, y].every(v => /^\d+$/.test(v))) return json({ error: "bad_tile_coords" }, 400);

  const tileUrl = `https://tile.openstreetmap.org/${z}/${x}/${y}.png`;

  const cache = caches.default;
  const cacheKey = new Request(tileUrl, { method: "GET" });
  let resp = await cache.match(cacheKey);

  if (!resp) {
    const upstream = await fetch(tileUrl, { headers: { "user-agent": "ftth-pwa/1.0 (Cloudflare Worker)" } });
    if (!upstream.ok) return new Response(upstream.body, { status: upstream.status, headers: upstream.headers });

    resp = new Response(upstream.body, upstream);
    resp.headers.set("Cache-Control", "public, max-age=86400");
    try { await cache.put(cacheKey, resp.clone()); } catch (_e) {}
  }

  const h = new Headers(resp.headers);
  h.set("Content-Type", "image/png");
  h.set("Cache-Control", "public, max-age=86400");
  return new Response(resp.body, { status: 200, headers: h });
}

// ======================= Apps Script submit (CRUD) =======================
function envFirst(env, keys) {
  for (const k of keys) {
    const v = env[k];
    if (v && String(v).trim()) return String(v).trim();
  }
  return "";
}
function getSubmitKey(env) {
  return envFirst(env, ["SUBMIT_KEY", "SHEETS_SUBMIT_KEY", "FTTH_SUBMIT_KEY"]);
}
function getAppsScriptUrl(env) {
  return envFirst(env, ["APPS_SCRIPT_URL", "GOOGLE_APPS_SCRIPT_URL", "SHEETS_APPS_SCRIPT_URL"]);
}

async function submitToAppsScript(env, payload) {
  const key = getSubmitKey(env);
  const url = getAppsScriptUrl(env);
  if (!url) {
    return { ok: false, error: "missing_apps_script_url", hint: "Configure APPS_SCRIPT_URL nas variáveis do Worker." };
  }
  if (!key) {
    return { ok: false, error: "missing_submit_key", hint: "Configure SUBMIT_KEY (mesma chave do seu Apps Script)." };
  }

  const body = { key, ...payload };
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });

  const txt = await res.text();
  let data = null;
  try { data = JSON.parse(txt); } catch (_e) { data = { raw: txt }; }

  if (!res.ok) {
    return { ok: false, error: "apps_script_http_error", status: res.status, data };
  }
  return data;
}

function s(v){ return (v ?? "").toString().trim(); }
function n(v){ const t = s(v).replace(",", "."); const num = Number(t); return Number.isFinite(num) ? num : null; }

// Normalize the various shapes the Pages may send
function extractCto(body) {
  const src = body?.cto ?? body?.data ?? body?.payload ?? body ?? {};
  return {
    CTO_ID: s(src.CTO_ID ?? src.cto_id ?? src.id ?? src.ID),
    NOME: s(src.NOME ?? src.nome ?? src.name),
    LAT: n(src.LAT ?? src.lat ?? src.latitude),
    LNG: n(src.LNG ?? src.lng ?? src.longitude ?? src.lon),
    RUA: s(src.RUA ?? src.rua),
    BAIRRO: s(src.BAIRRO ?? src.bairro),
    CAPACIDADE: s(src.CAPACIDADE ?? src.capacidade)
  };
}
function extractCaixa(body) {
  const src = body?.caixa ?? body?.cdo ?? body?.ce_cdo ?? body?.data ?? body?.payload ?? body ?? {};
  return {
    ID: s(src.ID ?? src.id),
    TIPO: s(src.TIPO ?? src.tipo),
    LAT: n(src.LAT ?? src.lat),
    LNG: n(src.LNG ?? src.lng ?? src.lon),
    OBS: s(src.OBS ?? src.obs),
    IMG_URL: s(src.IMG_URL ?? src.img_url),
    DT_CRIACAO: s(src.DT_CRIACAO ?? src.dt_criacao),
    DT_ATUALIZACAO: s(src.DT_ATUALIZACAO ?? src.dt_atualizacao)
  };
}
function extractRota(body) {
  // Rotas are usually an array of points for one route.
  const src = body?.rota ?? body?.data ?? body?.payload ?? body ?? {};
  const rota_id = s(src.ROTA_ID ?? src.rota_id ?? src.id ?? src.ID);
  const pontos = Array.isArray(src.PONTOS) ? src.PONTOS : (Array.isArray(src.pontos) ? src.pontos : (Array.isArray(body?.pontos) ? body.pontos : []));
  const pts = pontos.map(p => ({
    ROTA_ID: rota_id,
    ORDEM: Number.isFinite(Number(p.ORDEM ?? p.ordem)) ? Number(p.ORDEM ?? p.ordem) : null,
    LAT: n(p.LAT ?? p.lat),
    LNG: n(p.LNG ?? p.lng ?? p.lon),
    TIPO: s(p.TIPO ?? p.tipo),
    PESO: s(p.PESO ?? p.peso)
  })).filter(p => p.ORDEM !== null && p.LAT !== null && p.LNG !== null);
  return { ROTA_ID: rota_id, PONTOS: pts };
}

async function handleCrudCtos(request, env) {
  try {
    const auth = await requireRole(request, env, ["admin"]);
    const body = await readJson(request) || {};
    const action = request.method === "DELETE" ? "DELETE" : "UPSERT";
    const cto = extractCto(body);

    if (!cto.CTO_ID) return json({ ok: false, error: "missing_cto_id" }, 400);
    if (action !== "DELETE" && (cto.LAT === null || cto.LNG === null)) return json({ ok: false, error: "missing_lat_lng" }, 400);

    const items = [{
      kind: "CTOS",
      action,
      payload: cto
    }, {
      kind: "LOG_EVENTOS",
      payload: {
        TS: new Date().toISOString(),
        USER: auth.user,
        ROLE: auth.role,
        ACTION: `${action}_CTO`,
        ENTITY: "CTO",
        ENTITY_ID: cto.CTO_ID,
        DETAILS: JSON.stringify(cto)
      }
    }];

    const res = await submitToAppsScript(env, { user: auth.user, role: auth.role, items });
    // If Apps Script doesn't support CTOS yet, it may return ok:false — bubble it.
    if (!res?.ok) return json({ ok: false, error: res?.error || "apps_script_rejected", details: res }, 502);
    return json({ ok: true, result: res });
  } catch (e) {
    if (e?.code === "forbidden") return json({ ok: false, error: "forbidden", role: e.role }, 403);
    if (e?.code === "unauthorized") return json({ ok: false, error: "unauthorized" }, 401);
    return json({ ok: false, error: "cto_crud_failed", message: String(e?.stack || e) }, 500);
  }
}

async function handleCrudCaixas(request, env) {
  try {
    const auth = await requireRole(request, env, ["admin"]);
    const body = await readJson(request) || {};
    const action = request.method === "DELETE" ? "DELETE" : "UPSERT";
    const cx = extractCaixa(body);

    if (!cx.ID) return json({ ok: false, error: "missing_id" }, 400);
    if (action !== "DELETE" && (cx.LAT === null || cx.LNG === null)) return json({ ok: false, error: "missing_lat_lng" }, 400);

    const items = [{
      kind: "CAIXAS_EMENDA_CDO",
      action,
      payload: cx
    }, {
      kind: "LOG_EVENTOS",
      payload: {
        TS: new Date().toISOString(),
        USER: auth.user,
        ROLE: auth.role,
        ACTION: `${action}_CAIXA`,
        ENTITY: "CE/CDO",
        ENTITY_ID: cx.ID,
        DETAILS: JSON.stringify(cx)
      }
    }];

    const res = await submitToAppsScript(env, { user: auth.user, role: auth.role, items });
    if (!res?.ok) return json({ ok: false, error: res?.error || "apps_script_rejected", details: res }, 502);
    return json({ ok: true, result: res });
  } catch (e) {
    if (e?.code === "forbidden") return json({ ok: false, error: "forbidden", role: e.role }, 403);
    if (e?.code === "unauthorized") return json({ ok: false, error: "unauthorized" }, 401);
    return json({ ok: false, error: "caixa_crud_failed", message: String(e?.stack || e) }, 500);
  }
}

async function handleCrudRotas(request, env) {
  try {
    const auth = await requireRole(request, env, ["admin"]);
    const body = await readJson(request) || {};
    const action = request.method === "DELETE" ? "DELETE" : "UPSERT";
    const rota = extractRota(body);

    if (!rota.ROTA_ID) return json({ ok: false, error: "missing_rota_id" }, 400);
    if (action !== "DELETE" && (!Array.isArray(rota.PONTOS) || !rota.PONTOS.length)) {
      return json({ ok: false, error: "missing_points" }, 400);
    }

    const items = [{
      kind: "ROTAS_FIBRAS",
      action,
      payload: rota
    }, {
      kind: "LOG_EVENTOS",
      payload: {
        TS: new Date().toISOString(),
        USER: auth.user,
        ROLE: auth.role,
        ACTION: `${action}_ROTA`,
        ENTITY: "ROTA",
        ENTITY_ID: rota.ROTA_ID,
        DETAILS: JSON.stringify({ rota_id: rota.ROTA_ID, pontos: rota.PONTOS?.length || 0 })
      }
    }];

    const res = await submitToAppsScript(env, { user: auth.user, role: auth.role, items });
    if (!res?.ok) return json({ ok: false, error: res?.error || "apps_script_rejected", details: res }, 502);
    return json({ ok: true, result: res });
  } catch (e) {
    if (e?.code === "forbidden") return json({ ok: false, error: "forbidden", role: e.role }, 403);
    if (e?.code === "unauthorized") return json({ ok: false, error: "unauthorized" }, 401);
    return json({ ok: false, error: "rota_crud_failed", message: String(e?.stack || e) }, 500);
  }
}

// ======================= CSV Helpers (Sheets published as CSV) =======================
function getCsvUrl(env, logicalName) {
  // Compatibility: accept older variable names too.
  const map = {
    CTOS: ["SHEETS_CTOS_CSV_URL", "SHEETS_CTOS_URL", "SHEETS_CTOS_CSV", "SHEETS_CTO_CSV_URL", "SHEETS_CTO_URL"],
    CAIXAS: ["SHEETS_CAIXAS_EMENDA_CDO_CSV_URL", "SHEETS_CAIXAS_EMENDA_CDO_URL", "SHEETS_CAIXAS_CSV_URL", "SHEETS_CE_CDO_CSV_URL", "SHEETS_CE_CDO_URL"],
    ROTAS: ["SHEETS_ROTAS_FIBRAS_CSV_URL", "SHEETS_ROTAS_FIBRAS_URL", "SHEETS_ROTAS_CSV_URL", "SHEETS_ROTAS_URL"],
    MOV: ["SHEETS_MOVIMENTACOES_CSV_URL", "SHEETS_MOVIMENTACOES_URL", "SHEETS_MOV_CSV_URL", "SHEETS_MOV_URL"],
    USERS: ["SHEETS_USUARIOS_CSV_URL", "SHEETS_USUARIOS_URL", "SHEETS_USERS_CSV_URL", "SHEETS_USERS_URL"],
    LOG: ["SHEETS_LOG_EVENTOS_CSV_URL", "SHEETS_LOG_EVENTOS_URL", "SHEETS_LOG_CSV_URL", "SHEETS_LOG_URL"]
  };
  return envFirst(env, map[logicalName] || []);
}

async function fetchCSV(csvUrl) {
  if (!csvUrl) {
    const err = new Error("missing_csv_url");
    err.code = "missing_csv_url";
    throw err;
  }
  const res = await fetch(csvUrl, { cf: { cacheTtl: 60, cacheEverything: true }, headers: { "user-agent": "ftth-pwa-worker" } });
  if (!res.ok) {
    const err = new Error(`csv_fetch_failed:${res.status}`);
    err.code = "csv_fetch_failed";
    err.status = res.status;
    throw err;
  }
  return parseCSV(await res.text());
}
function parseCSV(text) {
  const lines = String(text || "").split(/\r?\n/).map(l => l.trimEnd()).filter(l => l.length > 0);
  if (!lines.length) return [];
  const header = splitCSVLine(lines[0]).map(h => h.trim());
  const out = [];
  for (let i = 1; i < lines.length; i++) {
    const cols = splitCSVLine(lines[i]);
    const obj = {};
    for (let c = 0; c < header.length; c++) obj[header[c]] = (cols[c] ?? "");
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
function num(v) { const t = s(v).replace(",", "."); return Number(t); }
function finite(n) { return Number.isFinite(n); }
function intOrNull(v) { const t = s(v); if (!t) return null; const n = parseInt(t, 10); return Number.isFinite(n) ? n : null; }
function numOrNull(v) { const nn = num(v); return Number.isFinite(nn) ? nn : null; }
function bool(v) { const t = s(v).toLowerCase(); return t === "1" || t === "true" || t === "yes" || t === "y" || t === "sim"; }
function uniq(arr) { const set = new Set(); for (const x of arr) if (x != null && String(x).trim() !== "") set.add(String(x)); return Array.from(set); }
function avg(nums) { if (!nums.length) return null; const ss = nums.reduce((a, b) => a + b, 0); return ss / nums.length; }

async function requireViewer(request, env) {
  return await requireAuth(request, env);
}

// ======================= GET: CTOs / Caixas / Rotas =======================
async function handleGetCtos(request, env) {
  try {
    await requireViewer(request, env);
    const csvUrl = getCsvUrl(env, "CTOS");
    const rows = await fetchCSV(csvUrl);

    const items = rows.map(r => {
      const id = s(r.CTO_ID || r.CTO || r.ID || r.cto_id);
      const lat = num(r.LAT || r.Lat || r.latitude || r.lat);
      const lng = num(r.LNG || r.Lon || r.longitude || r.lng || r.LON);
      return {
        CTO_ID: id,
        cto_id: id,
        LAT: lat,
        LNG: lng,
        lat,
        lng,
        CAPACIDADE: intOrNull(r.CAPACIDADE || r.capacidade),
        capacidade: intOrNull(r.CAPACIDADE || r.capacidade),
        BAIRRO: s(r.BAIRRO || r.bairro),
        bairro: s(r.BAIRRO || r.bairro),
        RUA: s(r.RUA || r.rua),
        rua: s(r.RUA || r.rua),
        NOME: s(r.NOME || r.nome),
        nome: s(r.NOME || r.nome)
      };
    }).filter(x => x.cto_id && finite(x.lat) && finite(x.lng));

    return json({ ok: true, items, data: items }, 200, { cacheSeconds: 60 });
  } catch (e) {
    const code = e?.code || "unknown";
    if (code === "missing_csv_url") {
      return json({ ok: false, error: "missing_csv_url", hint: "Configure env SHEETS_CTOS_* (CSV URL publicado)." }, 500);
    }
    return json({ ok: false, error: "ctos_failed", message: String(e?.message || e) }, 500);
  }
}

async function handleGetCaixas(request, env) {
  try {
    await requireViewer(request, env);
    const csvUrl = getCsvUrl(env, "CAIXAS");
    const rows = await fetchCSV(csvUrl);

    const items = rows.map(r => {
      const id = s(r.ID || r.id || r.CAIXA_ID || r.CE_ID);
      const lat = num(r.LAT || r.lat);
      const lng = num(r.LNG || r.lng || r.LON);
      return {
        ID: id,
        id,
        TIPO: s(r.TIPO || r.tipo),
        tipo: s(r.TIPO || r.tipo),
        LAT: lat,
        LNG: lng,
        lat,
        lng,
        OBS: s(r.OBS || r.obs),
        obs: s(r.OBS || r.obs),
        IMG_URL: s(r.IMG_URL || r.img_url),
        img_url: s(r.IMG_URL || r.img_url),
        DT_CRIACAO: s(r.DT_CRIACAO || r.dt_criacao),
        dt_criacao: s(r.DT_CRIACAO || r.dt_criacao),
        DT_ATUALIZACAO: s(r.DT_ATUALIZACAO || r.dt_atualizacao),
        dt_atualizacao: s(r.DT_ATUALIZACAO || r.dt_atualizacao)
      };
    }).filter(x => x.id && finite(x.lat) && finite(x.lng));

    return json({ ok: true, items, data: items }, 200, { cacheSeconds: 60 });
  } catch (e) {
    const code = e?.code || "unknown";
    if (code === "missing_csv_url") {
      return json({ ok: false, error: "missing_csv_url", hint: "Configure env SHEETS_CAIXAS_* (CSV URL publicado)." }, 500);
    }
    return json({ ok: false, error: "caixas_failed", message: String(e?.message || e) }, 500);
  }
}

async function handleGetRotas(request, env) {
  try {
    await requireViewer(request, env);
    const csvUrl = getCsvUrl(env, "ROTAS");
    const rows = await fetchCSV(csvUrl);

    const points = rows.map(r => ({
      rota_id: s(r.ROTA_ID || r.rota_id || r.ID),
      ordem: intOrNull(r.ORDEM || r.ordem),
      lat: num(r.LAT || r.lat),
      lng: num(r.LNG || r.lng || r.LON),
      tipo: s(r.TIPO || r.tipo),
      peso: numOrNull(r.PESO || r.peso)
    })).filter(p => p.rota_id && finite(p.lat) && finite(p.lng) && p.ordem !== null);

    const byRoute = new Map();
    for (const p of points) {
      if (!byRoute.has(p.rota_id)) byRoute.set(p.rota_id, []);
      byRoute.get(p.rota_id).push(p);
    }

    const features = [];
    for (const [rota_id, pts] of byRoute.entries()) {
      pts.sort((a, b) => a.ordem - b.ordem);
      const coords = pts.map(p => [p.lng, p.lat]);
      const tipos = uniq(pts.map(p => p.tipo).filter(Boolean));
      const pesoVals = pts.map(p => p.peso).filter(x => x !== null);
      const peso_medio = pesoVals.length ? avg(pesoVals) : null;

      features.push({
        type: "Feature",
        geometry: { type: "LineString", coordinates: coords },
        properties: { rota_id, pontos: pts.length, tipos, peso_medio }
      });
    }

    const geojson = { type: "FeatureCollection", features };
    return json({ ok: true, geojson, data: geojson }, 200, { cacheSeconds: 60 });
  } catch (e) {
    const code = e?.code || "unknown";
    if (code === "missing_csv_url") {
      return json({ ok: false, error: "missing_csv_url", hint: "Configure env SHEETS_ROTAS_* (CSV URL publicado)." }, 500);
    }
    return json({ ok: false, error: "rotas_failed", message: String(e?.message || e) }, 500);
  }
}

async function handleGetMovimentacoes(request, env) {
  try {
    await requireViewer(request, env);
    const csvUrl = getCsvUrl(env, "MOV");
    const rows = await fetchCSV(csvUrl);
    const items = rows.map(r => ({
      DATA: s(r.DATA || r.data),
      CTO_ID: s(r.CTO_ID || r.cto_id),
      Tipo: s(r.Tipo ?? r.TIPO ?? r.tipo),
      Cliente: s(r.Cliente ?? r.CLIENTE ?? r.cliente),
      Usuario: s(r.Usuario ?? r.USUARIO ?? r.usuario),
      Observacao: s(r.Observacao ?? r.OBSERVACAO ?? r.observacao)
    }));
    return json({ ok: true, items, data: items }, 200, { cacheSeconds: 30 });
  } catch (e) {
    return json({ ok: false, error: "mov_failed", message: String(e?.message || e) }, 500);
  }
}

async function handleGetUsuarios(request, env) {
  try {
    await requireViewer(request, env);
    const csvUrl = getCsvUrl(env, "USERS");
    const rows = await fetchCSV(csvUrl);
    const items = rows.map(r => ({
      USER: s(r.USER || r.user || r.username),
      ROLE: normalizeRole(r.ROLE || r.role),
      ACTIVE: bool(r.ACTIVE || r.active),
      CREATED_AT: s(r.CREATED_AT || r.created_at),
      MUST_CHANGE: bool(r.MUST_CHANGE || r.must_change),
      UPDATED_AT: s(r.UPDATED_AT || r.updated_at),
      LAST_LOGIN: s(r.LAST_LOGIN || r.last_login)
    })).filter(x => x.USER);
    return json({ ok: true, items, data: items }, 200, { cacheSeconds: 30 });
  } catch (e) {
    return json({ ok: false, error: "users_failed", message: String(e?.message || e) }, 500);
  }
}

async function handleGetLogEventos(request, env) {
  try {
    await requireViewer(request, env);
    const csvUrl = getCsvUrl(env, "LOG");
    const rows = await fetchCSV(csvUrl);

    const items = rows.map(r => ({
      TS: s(r.TS || r.ts),
      USER: s(r.USER || r.user),
      ROLE: normalizeRole(r.ROLE || r.role),
      ACTION: s(r.ACTION || r.action),
      ENTITY: s(r.ENTITY || r.entity),
      ENTITY_ID: s(r.ENTITY_ID || r.entity_id),
      DETAILS: s(r.DETAILS || r.details)
    })).filter(x => x.TS);

    return json({ ok: true, items, data: items }, 200, { cacheSeconds: 15 });
  } catch (e) {
    return json({ ok: false, error: "log_failed", message: String(e?.message || e) }, 500);
  }
}
