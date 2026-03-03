// FTTH Worker - unified API for CTOS, CE/CDO and Rotas (D1)
// IMPORTANT: set a D1 binding (recommended name: DB) and a Secret ADMIN_TOKEN in Cloudflare Worker settings.

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...headers,
    },
  });
}

function corsHeaders(req) {
  const origin = req.headers.get("origin") || "*";
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-credentials": "true",
    "access-control-allow-headers": "content-type, x-admin-token, authorization",
    "access-control-allow-methods": "GET,POST,PUT,DELETE,OPTIONS",
    "vary": "origin",
  };
}

function pickDb(env) {
  // Prefer common binding names.
  const candidates = ["DB", "FTTH_DB", "D1", "DATABASE", "db", "ftth_db"];
  for (const k of candidates) {
    if (env && env[k] && typeof env[k].prepare === "function") return { binding: k, db: env[k] };
  }
  return { binding: null, db: null };
}

function requireAdmin(req, env) {
  const configured = (env && env.ADMIN_TOKEN) ? String(env.ADMIN_TOKEN) : "";
  if (!configured) return { ok: true, reason: "no_admin_token_configured" }; // dev-friendly
  const tok = req.headers.get("x-admin-token") || "";
  const auth = req.headers.get("authorization") || "";
  const bearer = auth.toLowerCase().startsWith("bearer ") ? auth.slice(7).trim() : "";
  const provided = tok || bearer;
  if (!provided) return { ok: false, reason: "missing_token" };
  if (provided !== configured) return { ok: false, reason: "invalid_token" };
  return { ok: true };
}

async function ensureSchema(db) {
  // Create tables if missing (safe/no-op if they exist).
  await db.exec(`
    CREATE TABLE IF NOT EXISTS ctos (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      lat REAL,
      lng REAL,
      capacidade INTEGER,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS caixas_emenda_cdo (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      lat REAL,
      lng REAL,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS rotas (
      rota_id TEXT PRIMARY KEY,
      nome TEXT,
      geojson TEXT,
      updated_at TEXT DEFAULT (datetime('now'))
    );
  `);
}

async function handleRotas(req, env, url) {
  const { db } = pickDb(env);
  if (!db) return json({ error: "D1 binding not found. Configure a D1 binding (e.g., DB) on the Worker." }, 500, corsHeaders(req));
  await ensureSchema(db);

  // Method override support (POST with _method)
  let method = req.method.toUpperCase();
  let body = null;
  if (method !== "GET" && method !== "OPTIONS") {
    const ct = req.headers.get("content-type") || "";
    if (ct.includes("application/json")) {
      body = await req.json().catch(() => null);
      if (method === "POST" && body && body._method) method = String(body._method).toUpperCase();
    }
  }

  if (method === "GET") {
    const rows = await db.prepare("SELECT rota_id, nome, geojson, updated_at FROM rotas ORDER BY updated_at DESC").all();
    return json({ ok: true, rotas: rows.results || [] }, 200, corsHeaders(req));
  }

  // Mutations require admin
  const auth = requireAdmin(req, env);
  if (!auth.ok) return json({ error: "unauthorized", reason: auth.reason }, 401, corsHeaders(req));

  if (method === "PUT" || method === "POST") {
    const rota_id = String(body?.rota_id || body?.id || "").trim();
    const nome = String(body?.nome || "").trim();
    const geojson = body?.geojson == null ? null : String(body.geojson);
    if (!rota_id) return json({ error: "rota_id_required" }, 400, corsHeaders(req));

    await db.prepare(
      "INSERT INTO rotas (rota_id, nome, geojson, updated_at) VALUES (?1, ?2, ?3, datetime('now')) " +
      "ON CONFLICT(rota_id) DO UPDATE SET nome=excluded.nome, geojson=excluded.geojson, updated_at=datetime('now')"
    ).bind(rota_id, nome, geojson).run();

    return json({ ok: true, rota_id }, 200, corsHeaders(req));
  }

  if (method === "DELETE") {
    const rota_id = String(body?.rota_id || body?.id || url.searchParams.get("rota_id") || "").trim();
    if (!rota_id) return json({ error: "rota_id_required" }, 400, corsHeaders(req));
    await db.prepare("DELETE FROM rotas WHERE rota_id=?1").bind(rota_id).run();
    return json({ ok: true, rota_id }, 200, corsHeaders(req));
  }

  return json({ error: "method_not_allowed" }, 405, corsHeaders(req));
}

async function handleCtos(req, env) {
  const { db } = pickDb(env);
  if (!db) return json({ error: "D1 binding not found" }, 500, corsHeaders(req));
  await ensureSchema(db);

  if (req.method === "GET") {
    const rows = await db.prepare("SELECT id, lat, lng, capacidade, created_at, updated_at FROM ctos ORDER BY id DESC").all();
    return json({ ok: true, ctos: rows.results || [] }, 200, corsHeaders(req));
  }

  const auth = requireAdmin(req, env);
  if (!auth.ok) return json({ error: "unauthorized", reason: auth.reason }, 401, corsHeaders(req));

  const body = await req.json().catch(() => null);
  const method = (req.method === "POST" && body && body._method) ? String(body._method).toUpperCase() : req.method.toUpperCase();

  if (method === "POST" || method === "PUT") {
    const id = body?.id ?? null;
    const lat = Number(body?.lat);
    const lng = Number(body?.lng);
    const capacidade = body?.capacidade == null ? null : Number(body.capacidade);
    if (!Number.isFinite(lat) || !Number.isFinite(lng)) return json({ error: "lat_lng_required" }, 400, corsHeaders(req));

    if (id) {
      await db.prepare("UPDATE ctos SET lat=?1, lng=?2, capacidade=?3, updated_at=datetime('now') WHERE id=?4")
        .bind(lat, lng, capacidade, id).run();
      return json({ ok: true, id }, 200, corsHeaders(req));
    } else {
      const r = await db.prepare("INSERT INTO ctos (lat, lng, capacidade) VALUES (?1, ?2, ?3)")
        .bind(lat, lng, capacidade).run();
      return json({ ok: true, id: r.meta?.last_row_id }, 200, corsHeaders(req));
    }
  }

  if (method === "DELETE") {
    const id = body?.id;
    if (!id) return json({ error: "id_required" }, 400, corsHeaders(req));
    await db.prepare("DELETE FROM ctos WHERE id=?1").bind(id).run();
    return json({ ok: true, id }, 200, corsHeaders(req));
  }

  return json({ error: "method_not_allowed" }, 405, corsHeaders(req));
}

async function handleCaixas(req, env) {
  const { db } = pickDb(env);
  if (!db) return json({ error: "D1 binding not found" }, 500, corsHeaders(req));
  await ensureSchema(db);

  if (req.method === "GET") {
    const rows = await db.prepare("SELECT id, lat, lng, created_at, updated_at FROM caixas_emenda_cdo ORDER BY id DESC").all();
    return json({ ok: true, caixas: rows.results || [] }, 200, corsHeaders(req));
  }

  const auth = requireAdmin(req, env);
  if (!auth.ok) return json({ error: "unauthorized", reason: auth.reason }, 401, corsHeaders(req));

  const body = await req.json().catch(() => null);
  const method = (req.method === "POST" && body && body._method) ? String(body._method).toUpperCase() : req.method.toUpperCase();

  if (method === "POST" || method === "PUT") {
    const id = body?.id ?? null;
    const lat = Number(body?.lat);
    const lng = Number(body?.lng);
    if (!Number.isFinite(lat) || !Number.isFinite(lng)) return json({ error: "lat_lng_required" }, 400, corsHeaders(req));
    if (id) {
      await db.prepare("UPDATE caixas_emenda_cdo SET lat=?1, lng=?2, updated_at=datetime('now') WHERE id=?3").bind(lat, lng, id).run();
      return json({ ok: true, id }, 200, corsHeaders(req));
    } else {
      const r = await db.prepare("INSERT INTO caixas_emenda_cdo (lat, lng) VALUES (?1, ?2)").bind(lat, lng).run();
      return json({ ok: true, id: r.meta?.last_row_id }, 200, corsHeaders(req));
    }
  }

  if (method === "DELETE") {
    const id = body?.id;
    if (!id) return json({ error: "id_required" }, 400, corsHeaders(req));
    await db.prepare("DELETE FROM caixas_emenda_cdo WHERE id=?1").bind(id).run();
    return json({ ok: true, id }, 200, corsHeaders(req));
  }

  return json({ error: "method_not_allowed" }, 405, corsHeaders(req));
}

async function handleDebugDb(req, env) {
  const { binding, db } = pickDb(env);
  const hasToken = !!(env && env.ADMIN_TOKEN);
  return json({
    ok: true,
    d1_binding: binding,
    d1_ready: !!db,
    admin_token_configured: hasToken,
    note: "This endpoint is for debugging only."
  }, 200, corsHeaders(req));
}

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);

    // Preflight
    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(req) });
    }

    try {
      if (url.pathname === "/api/debug/db") return handleDebugDb(req, env);
      if (url.pathname === "/api/rotas") return handleRotas(req, env, url);
      if (url.pathname === "/api/ctos") return handleCtos(req, env);
      if (url.pathname === "/api/caixas_emenda_cdo") return handleCaixas(req, env);

      return json({ error: "not_found" }, 404, corsHeaders(req));
    } catch (e) {
      return json({ error: "internal_error", message: String(e?.message || e) }, 500, corsHeaders(req));
    }
  }
};
