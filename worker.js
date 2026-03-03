// worker.js - FTTH Rotas (D1) - binding-friendly
// - Usa D1 (produto), mas o "nome do binding" pode ser DB, D1, FTTH_DB, etc.
// - Aqui vamos priorizar env.DB e env.D1 (e só depois outros).
// - /api/rotas + /api/rotas_fibras (alias)
// - GET público (não exige token) | POST/PUT/DELETE exigem token válido em sessions
// - /api/debug/db mostra qual binding está sendo usado e colunas das tabelas.
//
// BUILD: 2026-03-03T03:xx (rotas-d1-binding-fix)

const BUILD_ID = "FTTH-ROTAS-D1-BINDING-FIX-2026-03-03";

function json(obj, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...extraHeaders },
  });
}

function corsHeaders(request) {
  const origin = request.headers.get("Origin") || "*";
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-credentials": "true",
    "access-control-allow-methods": "GET,POST,PUT,DELETE,OPTIONS",
    "access-control-allow-headers":
      request.headers.get("Access-Control-Request-Headers") ||
      "content-type,authorization,x-auth-token",
    "access-control-max-age": "86400",
    vary: "Origin",
  };
}

function withCors(request, resp) {
  const out = new Response(resp.body, resp);
  const h = corsHeaders(request);
  for (const [k, v] of Object.entries(h)) out.headers.set(k, v);
  return out;
}

function pickDb(env) {
  // ✅ Prioriza nomes comuns de binding D1 (variável do Worker), não "B1".
  if (env.DB) return { db: env.DB, name: "DB" };
  if (env.D1) return { db: env.D1, name: "D1" };
  if (env.FTTH_DB) return { db: env.FTTH_DB, name: "FTTH_DB" };
  if (env.B1) return { db: env.B1, name: "B1" }; // mantém compatibilidade se existir

  // fallback: pega o primeiro binding que pareça D1
  for (const k of Object.keys(env)) {
    const v = env[k];
    if (v && typeof v.prepare === "function" && typeof v.exec === "function") {
      return { db: v, name: k };
    }
  }
  return { db: null, name: null };
}

function getToken(request) {
  const auth = request.headers.get("Authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  const t1 = m ? String(m[1]).trim() : "";
  if (t1) return t1;
  const t2 = String(request.headers.get("X-Auth-Token") || "").trim();
  return t2 || "";
}

async function sha256hex(input) {
  const enc = new TextEncoder();
  const data = enc.encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const arr = Array.from(new Uint8Array(digest));
  return arr.map((b) => b.toString(16).padStart(2, "0")).join("");
}

let _sessionsCols = null;
async function sessionsCols(db) {
  if (_sessionsCols) return _sessionsCols;
  try {
    const r = await db.prepare("PRAGMA table_info(sessions)").all();
    _sessionsCols = (r?.results || []).map((x) => String(x.name));
  } catch {
    _sessionsCols = [];
  }
  return _sessionsCols;
}

async function requireWriteAuth(request, db) {
  // GET não precisa de auth (para UI conseguir listar e abrir modal sem travar)
  if (request.method === "GET") return { ok: true, reason: "get_public" };

  const token = getToken(request);
  if (!token) return { ok: false, reason: "missing_token" };

  const cols = await sessionsCols(db);

  const tries = [];
  if (cols.includes("token")) tries.push({ sql: "SELECT 1 FROM sessions WHERE token=? LIMIT 1", bind: [token] });
  if (cols.includes("session_token")) tries.push({ sql: "SELECT 1 FROM sessions WHERE session_token=? LIMIT 1", bind: [token] });
  if (cols.includes("access_token")) tries.push({ sql: "SELECT 1 FROM sessions WHERE access_token=? LIMIT 1", bind: [token] });
  if (cols.includes("token_hash")) {
    const h = await sha256hex(token);
    tries.push({ sql: "SELECT 1 FROM sessions WHERE token_hash=? LIMIT 1", bind: [h] });
  }

  // fallback: tenta token_hash mesmo se PRAGMA falhar/cols vazio
  if (tries.length === 0) {
    const h = await sha256hex(token);
    tries.push({ sql: "SELECT 1 FROM sessions WHERE token_hash=? LIMIT 1", bind: [h] });
  }

  for (const t of tries) {
    try {
      const r = await db.prepare(t.sql).bind(...t.bind).first();
      if (r) return { ok: true, reason: "session_ok" };
    } catch {
      // tenta próximo
    }
  }
  return { ok: false, reason: "invalid_token" };
}

async function ensureRotasTable(db) {
  await db.exec(`
    CREATE TABLE IF NOT EXISTS rotas (
      rota_id TEXT PRIMARY KEY,
      nome TEXT,
      geojson TEXT,
      updated_at TEXT
    );
  `);
}

async function handleRotas(request, env) {
  const { db, name } = pickDb(env);
  if (!db) return json({ ok: false, error: "no_d1_binding", build: BUILD_ID }, 500);

  const auth = await requireWriteAuth(request, db);
  if (!auth.ok) {
    return json({ ok: false, error: "unauthorized", reason: auth.reason, dbBinding: name, build: BUILD_ID }, 401);
  }

  await ensureRotasTable(db);

  if (request.method === "GET") {
    const r = await db
      .prepare("SELECT rota_id, nome, geojson, updated_at FROM rotas ORDER BY updated_at DESC NULLS LAST")
      .all();
    return json({ ok: true, dbBinding: name, results: r.results || [] });
  }

  const body = await request.json().catch(() => ({}));

  if (request.method === "DELETE") {
    const rota_id = String(body.rota_id || body.id || "").trim();
    if (!rota_id) return json({ ok: false, error: "missing_rota_id" }, 400);
    await db.prepare("DELETE FROM rotas WHERE rota_id=?").bind(rota_id).run();
    return json({ ok: true });
  }

  // POST / PUT => UPSERT
  const rota_id = String(body.rota_id || body.id || "").trim();
  const nome = String(body.nome || body.name || "").trim();
  const geojson = typeof body.geojson === "string" ? body.geojson : JSON.stringify(body.geojson ?? null);
  if (!rota_id) return json({ ok: false, error: "missing_rota_id" }, 400);

  const now = new Date().toISOString();
  await db
    .prepare(
      `
    INSERT INTO rotas (rota_id, nome, geojson, updated_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(rota_id) DO UPDATE SET
      nome=excluded.nome,
      geojson=excluded.geojson,
      updated_at=excluded.updated_at
  `
    )
    .bind(rota_id, nome, geojson, now)
    .run();

  return json({ ok: true, rota_id, updated_at: now, dbBinding: name });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "OPTIONS") return withCors(request, new Response(null, { status: 204 }));

    if (path === "/api/debug/db" && request.method === "GET") {
      const { db, name } = pickDb(env);
      let sessionsCols = [];
      let rotasCols = [];
      try {
        if (db) {
          const s = await db.prepare("PRAGMA table_info(sessions)").all();
          sessionsCols = (s?.results || []).map((x) => x.name);
          const r = await db.prepare("PRAGMA table_info(rotas)").all();
          rotasCols = (r?.results || []).map((x) => x.name);
        }
      } catch {}
      return withCors(request, json({ ok: true, build: BUILD_ID, binding: name, hasDb: !!db, sessionsCols, rotasCols }));
    }

    if ((path === "/api/rotas" || path === "/api/rotas_fibras") && ["GET", "POST", "PUT", "DELETE"].includes(request.method)) {
      try {
        return withCors(request, await handleRotas(request, env));
      } catch (e) {
        return withCors(request, json({ ok: false, error: "rotas_failed", message: String(e), build: BUILD_ID }, 500));
      }
    }

    return withCors(request, json({ ok: false, error: "not_found", path, build: BUILD_ID }, 404));
  },
};
