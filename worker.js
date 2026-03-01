/**
 * FTTH-PWA Worker (robust admin users upsert) - 2026-03-01
 *
 * Fixes: /api/admin/users POST returning 500 due to schema mismatches (missing created_at/updated_at/etc).
 * Approach:
 * - ONLY uses core columns: username, password_hash, role, is_active
 * - Uses SELECT to detect existence, then:
 *    - INSERT (new) requires password
 *    - UPDATE (existing) updates role/is_active and optionally password_hash
 * - Never references created_at/updated_at/last_login in writes (safe for older schemas)
 * - List users: tries full columns; falls back automatically.
 *
 * Requires D1 binding: DB
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
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    try {
      if (request.method === "GET" && (pathname === "/" || pathname === "/api" || pathname === "/api/")) {
        return corsJson(request, { ok: true, service: "ftth-pwa", version: "2026-03-01-robust-users" });
      }

      // AUTH
      if (pathname === "/api/login" && request.method === "POST") return corsResponse(request, await handleLogin(request, env));
      if (pathname === "/api/me" && request.method === "GET") return corsResponse(request, await handleMe(request, env));
      if (pathname === "/api/logout" && request.method === "POST") return corsResponse(request, await handleLogout(request, env));

      // ADMIN USERS (Bearer-admin)
      if (pathname === "/api/admin/users" && request.method === "GET") return corsResponse(request, await handleAdminListUsers(request, env));
      if (pathname === "/api/admin/users" && request.method === "POST") return corsResponse(request, await handleAdminUpsertUser(request, env));
      if (pathname === "/api/admin/users/reset_password" && request.method === "POST") return corsResponse(request, await handleAdminResetPassword(request, env));
      if (pathname === "/api/admin/users/disable" && request.method === "POST") return corsResponse(request, await handleAdminDisableUser(request, env));

      return corsJson(request, { error: "not_found" }, 404);
    } catch (err) {
      // Return detailed error (helps debug without console)
      const msg = String(err?.message || err);
      const stack = String(err?.stack || "");
      return corsJson(request, { error: "server_error", message: msg, stack }, 500);
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
function corsJson(request, obj, status = 200) {
  return corsResponse(
    request,
    new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json; charset=utf-8" } })
  );
}
async function readJson(request) {
  return await request.json().catch(() => null);
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
async function requireAuth(request, env) {
  if (!env.DB) throw new Error("DB_not_configured");
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
async function requireBearerAdmin(request, env) {
  const auth = await requireAuth(request, env);
  const row = await env.DB.prepare("SELECT role, is_active FROM users WHERE username=?1").bind(auth.user).first();
  const role = String(row?.role || "user").trim().toLowerCase();
  const active = Number(row?.is_active ?? 1) === 1;
  if (!active) throw new Error("user_inactive");
  if (role !== "admin") throw new Error("not_admin");
  return auth;
}
function normalizeBool(v, def = 1) {
  if (v === undefined || v === null || v === "") return def;
  if (typeof v === "boolean") return v ? 1 : 0;
  const s = String(v).trim().toLowerCase();
  if (["1","true","sim","yes","y"].includes(s)) return 1;
  if (["0","false","nao","não","no","n"].includes(s)) return 0;
  return def;
}
function safeRole(v) {
  const r = String(v || "user").trim().toLowerCase();
  return r === "admin" ? "admin" : "user";
}

// ---------------- Password hashing (pbkdf2$iters$salt$hash) ----------------
function base64Url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
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
async function pbkdf2(password, saltBytes, iters, keyLen) {
  const keyMaterial = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), { name: "PBKDF2" }, false, ["deriveBits"]);
  return await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations: iters }, keyMaterial, keyLen * 8);
}
async function makePasswordHash(password, iters = 120000, pepper="") {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const bits = await pbkdf2(password + pepper, salt, iters, 32);
  const hash = new Uint8Array(bits);
  return `pbkdf2$${iters}$${base64Url(salt)}$${base64Url(hash)}`;
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a[i] ^ b[i];
  return r === 0;
}
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

// ---------------- AUTH endpoints ----------------
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
async function handleLogin(request, env) {
  const origin = request.headers.get("origin") || "";
  if (origin && !ALLOWED_ORIGINS.has(origin)) return new Response(JSON.stringify({ error: "origin_not_allowed", origin }), { status: 403, headers: { "Content-Type": "application/json" } });
  if (!env.DB) return new Response(JSON.stringify({ error: "DB_not_configured" }), { status: 500, headers: { "Content-Type": "application/json" } });

  const body = await readJson(request);
  if (!body) return new Response(JSON.stringify({ error: "invalid_json" }), { status: 400, headers: { "Content-Type": "application/json" } });

  const user = String(body.user || "").trim();
  const password = String(body.password || "").trim();
  if (!user || !password) return new Response(JSON.stringify({ error: "missing_user_password" }), { status: 400, headers: { "Content-Type": "application/json" } });

  const row = await env.DB.prepare("SELECT username, password_hash, role, is_active FROM users WHERE username=?1").bind(user).first();
  if (!row || Number(row.is_active ?? 1) !== 1) return new Response(JSON.stringify({ error: "invalid_credentials" }), { status: 401, headers: { "Content-Type": "application/json" } });

  const ok = await verifyPassword(password, row.password_hash, env.PASSWORD_PEPPER || "");
  if (!ok) return new Response(JSON.stringify({ error: "invalid_credentials" }), { status: 401, headers: { "Content-Type": "application/json" } });

  const token = await mintSession(env, user);
  const role = String(row.role || "user").trim() || "user";
  try { await env.DB.prepare("UPDATE users SET last_login=?1 WHERE username=?2").bind(new Date().toISOString(), user).run(); } catch {}
  return new Response(JSON.stringify({ ok: true, token, user: { username: user, role } }), { status: 200, headers: { "Content-Type": "application/json" } });
}
async function handleMe(request, env) {
  try {
    const auth = await requireAuth(request, env);
    const row = await env.DB.prepare("SELECT role FROM users WHERE username=?1").bind(auth.user).first();
    const role = String(row?.role || "user").trim() || "user";
    return new Response(JSON.stringify({ ok: true, user: { username: auth.user, role } }), { status: 200, headers: { "Content-Type": "application/json" } });
  } catch (e) {
    return new Response(JSON.stringify({ error: String(e?.message || "unauthorized") }), { status: 401, headers: { "Content-Type": "application/json" } });
  }
}
async function handleLogout(request, env) {
  try {
    const auth = await requireAuth(request, env);
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?1").bind(auth.tokenHash).run();
  } catch {}
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "Content-Type": "application/json" } });
}

// ---------------- ADMIN USERS ----------------
async function handleAdminListUsers(request, env) {
  await requireBearerAdmin(request, env);
  try {
    const rs = await env.DB.prepare("SELECT username, role, is_active, created_at, updated_at, last_login FROM users ORDER BY username").all();
    return new Response(JSON.stringify({ ok: true, users: rs.results || [] }), { status: 200, headers: { "Content-Type": "application/json" } });
  } catch {
    const rs = await env.DB.prepare("SELECT username, role, is_active FROM users ORDER BY username").all();
    const users = (rs.results || []).map(u => ({ ...u, created_at: null, updated_at: null, last_login: null }));
    return new Response(JSON.stringify({ ok: true, users, note: "fallback_columns" }), { status: 200, headers: { "Content-Type": "application/json" } });
  }
}

async function handleAdminUpsertUser(request, env) {
  await requireBearerAdmin(request, env);
  const body = await readJson(request);
  if (!body) return new Response(JSON.stringify({ error: "invalid_json" }), { status: 400, headers: { "Content-Type": "application/json" } });

  const username = String(body.username || "").trim();
  if (!username) return new Response(JSON.stringify({ error: "missing_username" }), { status: 400, headers: { "Content-Type": "application/json" } });

  const role = safeRole(body.role);
  const is_active = normalizeBool(body.is_active, 1);

  const password = (body.password != null) ? String(body.password).trim() : "";
  const iters = Number(body.iters || 120000);

  // Existence check
  const existing = await env.DB.prepare("SELECT username FROM users WHERE username=?1").bind(username).first();

  if (!existing) {
    if (!password) return new Response(JSON.stringify({ error: "missing_password_for_new_user" }), { status: 400, headers: { "Content-Type": "application/json" } });
    const password_hash = await makePasswordHash(password, iters, env.PASSWORD_PEPPER || "");
    const ins = await env.DB.prepare("INSERT INTO users (username, password_hash, role, is_active) VALUES (?1, ?2, ?3, ?4)")
      .bind(username, password_hash, role, is_active).run();
    if (ins?.success === false) return new Response(JSON.stringify({ error: "insert_failed" }), { status: 500, headers: { "Content-Type": "application/json" } });
  } else {
    if (password) {
      const password_hash = await makePasswordHash(password, iters, env.PASSWORD_PEPPER || "");
      const up = await env.DB.prepare("UPDATE users SET password_hash=?1, role=?2, is_active=?3 WHERE username=?4")
        .bind(password_hash, role, is_active, username).run();
      if (up?.success === false) return new Response(JSON.stringify({ error: "update_failed" }), { status: 500, headers: { "Content-Type": "application/json" } });
    } else {
      const up = await env.DB.prepare("UPDATE users SET role=?1, is_active=?2 WHERE username=?3")
        .bind(role, is_active, username).run();
      if (up?.success === false) return new Response(JSON.stringify({ error: "update_failed" }), { status: 500, headers: { "Content-Type": "application/json" } });
    }
  }

  // Confirm
  const row = await env.DB.prepare("SELECT username, role, is_active FROM users WHERE username=?1").bind(username).first();
  if (!row) return new Response(JSON.stringify({ error: "upsert_failed", message: "user_not_found_after_write" }), { status: 500, headers: { "Content-Type": "application/json" } });

  return new Response(JSON.stringify({ ok: true, user: row }), { status: 200, headers: { "Content-Type": "application/json" } });
}

async function handleAdminResetPassword(request, env) {
  await requireBearerAdmin(request, env);
  const body = await readJson(request);
  if (!body) return new Response(JSON.stringify({ error: "invalid_json" }), { status: 400, headers: { "Content-Type": "application/json" } });

  const username = String(body.username || "").trim();
  const password = String(body.password || "").trim();
  if (!username) return new Response(JSON.stringify({ error: "missing_username" }), { status: 400, headers: { "Content-Type": "application/json" } });
  if (!password) return new Response(JSON.stringify({ error: "missing_password" }), { status: 400, headers: { "Content-Type": "application/json" } });

  const iters = Number(body.iters || 120000);
  const password_hash = await makePasswordHash(password, iters, env.PASSWORD_PEPPER || "");
  const up = await env.DB.prepare("UPDATE users SET password_hash=?1 WHERE username=?2").bind(password_hash, username).run();
  if (up?.success === false) return new Response(JSON.stringify({ error: "update_failed" }), { status: 500, headers: { "Content-Type": "application/json" } });
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "Content-Type": "application/json" } });
}

async function handleAdminDisableUser(request, env) {
  await requireBearerAdmin(request, env);
  const body = await readJson(request);
  if (!body) return new Response(JSON.stringify({ error: "invalid_json" }), { status: 400, headers: { "Content-Type": "application/json" } });

  const username = String(body.username || "").trim();
  if (!username) return new Response(JSON.stringify({ error: "missing_username" }), { status: 400, headers: { "Content-Type": "application/json" } });

  const is_active = normalizeBool(body.is_active, 0);
  const up = await env.DB.prepare("UPDATE users SET is_active=?1 WHERE username=?2").bind(is_active, username).run();
  if (up?.success === false) return new Response(JSON.stringify({ error: "update_failed" }), { status: 500, headers: { "Content-Type": "application/json" } });

  if (is_active === 0) {
    try { await env.DB.prepare("DELETE FROM sessions WHERE username=?1").bind(username).run(); } catch {}
  }
  return new Response(JSON.stringify({ ok: true, user: { username, is_active } }), { status: 200, headers: { "Content-Type": "application/json" } });
}
