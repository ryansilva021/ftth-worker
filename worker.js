/**
 * FTTH-PWA Worker - FULL (D1 + Login + CTO CRUD + Proxies) - 2026-03-01
 *
 * Fixes:
 * - Restores /api/login, /api/logout, /api/me (your UI requires /api/login)
 * - CTO persistence in D1:
 *      GET    /api/ctos              -> list from D1
 *      POST   /api/ctos              -> upsert (admin password required)
 *      DELETE /api/ctos?id=CTO123    -> delete (admin password required)
 * - CORS: allows Authorization header + X-Admin-Password (fixes preflight errors)
 * - Adds proxy endpoints:
 *      GET /api/reverse_geocode?lat=..&lng=..
 *      GET /api/tiles/{z}/{x}/{y}.png
 *
 * REQUIRED:
 * - D1 binding: DB  (points to your "ftth-db")
 * - Secret: ADMIN_PASSWORD
 *
 * OPTIONAL for /api/submit forwarding:
 * - APPS_SCRIPT_URL (secret)
 * - SUBMIT_KEY (secret)
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
    const { pathname } = url;

    // ---- CORS preflight ----
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(request, { restricted: isRestrictedPath(pathname) }),
      });
    }

    try {
      // Health
      if (request.method === "GET" && (pathname === "/" || pathname === "/health" || pathname === "/api" || pathname === "/api/")) {
        return corsJson(
          request,
          {
            ok: true,
            service: "ftth-pwa",
            version: "2026-03-01-full-d1",
            endpoints: [
              "POST /api/login",
              "GET  /api/me",
              "POST /api/logout",
              "GET  /api/ctos",
              "POST /api/ctos (admin)",
              "DELETE /api/ctos?id= (admin)",
              "POST /api/submit (Bearer token, optional)",
              "GET  /api/reverse_geocode?lat=.&lng=.",
              "GET  /api/tiles/{z}/{x}/{y}.png",
            ],
          },
          200
        );
      }

      // ---- AUTH ----
      if (pathname === "/api/login" && request.method === "POST") return corsResponse(request, await handleLogin(request, env));
      if (pathname === "/api/me" && request.method === "GET") return corsResponse(request, await handleMe(request, env));
      if (pathname === "/api/logout" && request.method === "POST") return corsResponse(request, await handleLogout(request, env));

      // ---- PROXIES ----
      if (pathname === "/api/reverse_geocode" && request.method === "GET") return corsResponse(request, await handleReverseGeocode(request));
      if (pathname.startsWith("/api/tiles/") && request.method === "GET") return corsResponse(request, await handleTileProxy(request));

      // ---- SUBMIT (optional) ----
      if (pathname === "/api/submit" && request.method === "POST") return corsResponse(request, await handleSubmit(request, env));

      // ---- CTOs (D1) ----
      if (pathname === "/api/ctos") {
        if (!env.DB) return corsJson(request, { error: "DB_not_configured" }, 500);

        if (request.method === "GET") return corsResponse(request, await handleGetCtos(env));
        if (request.method === "POST") return corsResponse(request, await handleUpsertCto(request, env));
        if (request.method === "DELETE") return corsResponse(request, await handleDeleteCto(request, env));

        return corsJson(request, { error: "method_not_allowed" }, 405);
      }

      return corsJson(request, { error: "not_found" }, 404);
    } catch (err) {
      return corsJson(request, { error: "server_error", message: String(err?.stack || err) }, 500);
    }
  },
};

// ======================= CORS helpers =======================
function isRestrictedPath(pathname) {
  return (
    pathname === "/api/login" ||
    pathname === "/api/logout" ||
    pathname === "/api/me" ||
    pathname === "/api/submit" ||
    pathname === "/api/ctos"
  );
}

function corsHeaders(request, { restricted } = { restricted: false }) {
  const origin = request.headers.get("Origin") || request.headers.get("origin") || "";
  const allowOrigin = restricted ? (ALLOWED_ORIGINS.has(origin) ? origin : "") : "*";

  const h = {
    "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
    // FIX: allow Authorization + X-Admin-Password
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Admin-Password",
    "Vary": "Origin",
  };

  if (allowOrigin) h["Access-Control-Allow-Origin"] = allowOrigin;
  else if (!restricted) h["Access-Control-Allow-Origin"] = "*";

  return h;
}

function corsResponse(request, response) {
  const restricted = isRestrictedPath(new URL(request.url).pathname);
  const h = new Headers(response.headers);
  const ch = corsHeaders(request, { restricted });
  for (const [k, v] of Object.entries(ch)) h.set(k, v);
  return new Response(response.body, { status: response.status, headers: h });
}

function corsJson(request, obj, status = 200) {
  return corsResponse(request, json(obj, status));
}

function json(obj, status = 200, headers = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...headers },
  });
}

async function readJson(request) {
  const ct = request.headers.get("Content-Type") || "";
  if (!ct.includes("application/json")) return null;
  return await request.json().catch(() => null);
}

// ======================= Admin password =======================
function requireAdmin(request, env) {
  const expected = String(env.ADMIN_PASSWORD || "").trim();
  if (!expected) return { ok: false, status: 500, error: "ADMIN_PASSWORD_not_configured" };

  const got = String(request.headers.get("x-admin-password") || request.headers.get("X-Admin-Password") || "").trim();
  if (!got) return { ok: false, status: 401, error: "missing_admin_password" };
  if (got !== expected) return { ok: false, status: 401, error: "invalid_admin_password" };

  return { ok: true };
}

// ======================= AUTH / Sessions =======================
function getBearer(request) {
  const h = request.headers.get("Authorization") || request.headers.get("authorization") || "";
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

  await env.DB
    .prepare("INSERT INTO sessions (token_hash, username, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)")
    .bind(tokenHash, username, new Date().toISOString(), expires)
    .run();

  return token;
}

async function requireAuth(request, env) {
  const token = getBearer(request);
  if (!token) throw new Error("missing_authorization");

  const tokenHash = await sha256Hex(token);
  const row = await env.DB.prepare("SELECT username, expires_at FROM sessions WHERE token_hash=?1").bind(tokenHash).first();
  if (!row) throw new Error("invalid_token");

  if (row.expires_at) {
    const exp = Date.parse(row.expires_at);
    if (Number.isFinite(exp) && exp < Date.now()) {
      await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?1").bind(tokenHash).run();
      throw new Error("token_expired");
    }
  }
  return { user: row.username, tokenHash };
}

// users.password_hash format: pbkdf2$<iters>$<salt_b64url>$<hash_b64url>
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
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  return await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations: iters },
    keyMaterial,
    keyLen * 8
  );
}

function fromB64Url(s) {
  try {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = atob(s);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a[i] ^ b[i];
  return r === 0;
}

// ======================= Handlers =======================
async function handleLogin(request, env) {
  const origin = request.headers.get("origin") || "";
  if (origin && !ALLOWED_ORIGINS.has(origin)) return json({ error: "origin_not_allowed", origin }, 403);

  if (!env.DB) return json({ error: "DB_not_configured" }, 500);

  const body = await readJson(request);
  if (!body) return json({ error: "invalid_json" }, 400);

  const user = String(body.user || "").trim();
  const password = String(body.password || "").trim();
  if (!user || !password) return json({ error: "missing_user_password" }, 400);

  const row = await env.DB.prepare("SELECT username, password_hash FROM users WHERE username=?1 AND is_active=1").bind(user).first();
  if (!row) return json({ error: "invalid_credentials" }, 401);

  const ok = await verifyPassword(password, row.password_hash, env.PASSWORD_PEPPER || "");
  if (!ok) return json({ error: "invalid_credentials" }, 401);

  const token = await mintSession(env, user);
  return json({ ok: true, token }, 200);
}

async function handleMe(request, env) {
  try {
    if (!env.DB) return json({ error: "DB_not_configured" }, 500);
    const auth = await requireAuth(request, env);
    return json({ ok: true, user: { username: auth.user } }, 200);
  } catch {
    return json({ error: "unauthorized" }, 401);
  }
}

async function handleLogout(request, env) {
  const origin = request.headers.get("origin") || "";
  if (origin && !ALLOWED_ORIGINS.has(origin)) return json({ error: "origin_not_allowed", origin }, 403);

  if (!env.DB) return json({ error: "DB_not_configured" }, 500);

  try {
    const auth = await requireAuth(request, env);
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?1").bind(auth.tokenHash).run();
  } catch {
    // ignore
  }
  return json({ ok: true }, 200);
}

async function handleGetCtos(env) {
  const rs = await env.DB.prepare("SELECT CTO_ID, NOME, RUA, BAIRRO, LAT, LNG, CAPACIDADE, created_at, updated_at FROM ctos").all();
  const items = (rs.results || [])
    .map((r) => ({
      cto_id: String(r.CTO_ID || "").trim(),
      nome: String(r.NOME || "").trim(),
      rua: String(r.RUA || "").trim(),
      bairro: String(r.BAIRRO || "").trim(),
      lat: Number(r.LAT),
      lng: Number(r.LNG),
      capacidade: r.CAPACIDADE == null ? null : Number(r.CAPACIDADE),
      created_at: r.created_at,
      updated_at: r.updated_at,
    }))
    .filter((x) => x.cto_id && Number.isFinite(x.lat) && Number.isFinite(x.lng));

  return json(items, 200, { "Cache-Control": "no-store" });
}

async function handleUpsertCto(request, env) {
  const origin = request.headers.get("origin") || "";
  if (origin && !ALLOWED_ORIGINS.has(origin)) return json({ error: "origin_not_allowed", origin }, 403);

  const adm = requireAdmin(request, env);
  if (!adm.ok) return json({ error: adm.error }, adm.status);

  const body = await readJson(request);
  if (!body) return json({ error: "invalid_json" }, 400);

  const CTO_ID = String(body.CTO_ID ?? body.cto_id ?? body.id ?? "").trim();
  const NOME = String(body.NOME ?? body.nome ?? CTO_ID ?? "").trim();
  const RUA = String(body.RUA ?? body.rua ?? "").trim();
  const BAIRRO = String(body.BAIRRO ?? body.bairro ?? "").trim();
  const LAT = Number(String(body.LAT ?? body.lat ?? "").replace(",", "."));
  const LNG = Number(String(body.LNG ?? body.lng ?? "").replace(",", "."));
  const CAPACIDADE = Number.isFinite(Number(body.CAPACIDADE ?? body.capacidade)) ? Math.trunc(Number(body.CAPACIDADE ?? body.capacidade)) : 0;

  if (!CTO_ID) return json({ error: "missing_CTO_ID" }, 400);
  if (!Number.isFinite(LAT) || !Number.isFinite(LNG)) return json({ error: "missing_lat_lng" }, 400);

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

  return json({ ok: true, cto: { cto_id: CTO_ID, nome: NOME, rua: RUA, bairro: BAIRRO, lat: LAT, lng: LNG, capacidade: CAPACIDADE } }, 200);
}

async function handleDeleteCto(request, env) {
  const origin = request.headers.get("origin") || "";
  if (origin && !ALLOWED_ORIGINS.has(origin)) return json({ error: "origin_not_allowed", origin }, 403);

  const adm = requireAdmin(request, env);
  if (!adm.ok) return json({ error: adm.error }, adm.status);

  const url = new URL(request.url);
  const id = String(url.searchParams.get("id") || "").trim();
  if (!id) return json({ error: "missing_id" }, 400);

  await env.DB.prepare("DELETE FROM ctos WHERE CTO_ID=?1").bind(id).run();
  return json({ ok: true, deleted: id }, 200);
}

async function handleSubmit(request, env) {
  const origin = request.headers.get("origin") || "";
  if (origin && !ALLOWED_ORIGINS.has(origin)) return json({ error: "origin_not_allowed", origin }, 403);

  if (!env.DB) return json({ error: "DB_not_configured" }, 500);
  const auth = await requireAuth(request, env);

  const key = String(env.SUBMIT_KEY || "").trim();
  const scriptUrl = String(env.APPS_SCRIPT_URL || "").trim();
  if (!key) return json({ error: "SUBMIT_KEY_not_configured" }, 500);
  if (!scriptUrl) return json({ error: "APPS_SCRIPT_URL_not_configured" }, 500);

  const body = await readJson(request);
  if (!body) return json({ error: "invalid_json" }, 400);

  const items = Array.isArray(body.items) ? body.items : [body];

  const forward = await fetch(scriptUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ key, user: auth.user, items }),
  });

  const text = await forward.text();
  return new Response(text, {
    status: forward.status,
    headers: { "Content-Type": forward.headers.get("content-type") || "text/plain; charset=utf-8" },
  });
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
      "user-agent": "ftth-pwa/1.0 (Cloudflare Worker)",
    },
  });
  if (!res.ok) return json({ ok: false, error: "reverse_geocode_failed", status: res.status }, 502);

  const data = await res.json().catch(() => null);
  const a = data?.address || {};
  const rua = a.road || a.pedestrian || a.footway || a.residential || "";
  const bairro = a.suburb || a.neighbourhood || a.quarter || a.city_district || a.district || "";
  return json({ ok: true, rua, bairro, raw: data }, 200);
}

// ======================= Tile Proxy (OSM) =======================
async function handleTileProxy(request) {
  const url = new URL(request.url);
  const parts = url.pathname.split("/").filter(Boolean); // ["api","tiles","z","x","y.png"]
  if (parts.length < 5) return json({ error: "bad_tile_path" }, 400);
  const z = parts[2], x = parts[3];
  let y = parts[4];
  if (y.endsWith(".png")) y = y.slice(0, -4);
  if (![z, x, y].every((v) => /^\d+$/.test(v))) return json({ error: "bad_tile_coords" }, 400);

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
