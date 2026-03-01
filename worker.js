/**
 * FTTH-PWA Worker - CTOs + CE/CDO + Rotas + Movimentações - 2026-03-01
 *
 * Fix: Frontend calls /api/rotas_fibras and was receiving 404.
 * This worker implements Rotas Fibra endpoints backed by D1.
 *
 * D1 binding required: DB
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

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    try {
      if (!env.DB) return corsJson(request, { error: "DB_not_configured" }, 500);

      // Ensure schema (safe even if ctx missing)
      const schemaPromise = ensureSchema(env);
      if (ctx && typeof ctx.waitUntil === "function") ctx.waitUntil(schemaPromise.catch(() => {}));
      else await schemaPromise.catch(() => {});

      // Health
      if (request.method === "GET" && (pathname === "/" || pathname === "/api" || pathname === "/api/")) {
        return corsJson(request, { ok: true, service: "ftth-pwa", version: "2026-03-01-rotas" });
      }

      // CTOs
      if (pathname === "/api/ctos" && request.method === "GET") return corsResponse(request, await handleGetCtos(env));
      if (pathname === "/api/ctos" && request.method === "POST") return corsResponse(request, await handleUpsertCto(request, env));
      if (pathname === "/api/ctos" && request.method === "DELETE") return corsResponse(request, await handleDeleteCto(request, env));

      // CE/CDO
      if (pathname === "/api/caixas_emenda_cdo" && request.method === "GET") return corsResponse(request, await handleGetCeCdo(env));
      if (pathname === "/api/caixas_emenda_cdo" && request.method === "POST") return corsResponse(request, await handleUpsertCeCdo(request, env));
      if (pathname === "/api/caixas_emenda_cdo" && request.method === "DELETE") return corsResponse(request, await handleDeleteCeCdo(request, env));

      // Rotas fibras
      if (pathname === "/api/rotas_fibras" && request.method === "GET") return corsResponse(request, await handleGetRotas(env));
      if (pathname === "/api/rotas_fibras" && request.method === "POST") return corsResponse(request, await handleUpsertRota(request, env));
      if (pathname === "/api/rotas_fibras" && request.method === "DELETE") return corsResponse(request, await handleDeleteRota(request, env));

      // Movimentações
      if (pathname === "/api/movimentacoes" && request.method === "GET") return corsResponse(request, await handleGetMovimentacoes(env, url));

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

  // table already created in D1: caixas_emenda_cdo
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

  await env.DB.exec(`CREATE TABLE IF NOT EXISTS rotas_fibras (
    id TEXT PRIMARY KEY,
    nome TEXT,
    geojson TEXT NOT NULL
  );`);

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
}

// ---------------- CTOs ----------------
function normId(v){ return String(v||"").trim(); }
function normNum(v){ const n = Number(v); return Number.isFinite(n) ? n : null; }
function normInt(v){ const n = parseInt(String(v),10); return Number.isFinite(n) ? n : 0; }

async function handleGetCtos(env){
  const rs = await env.DB.prepare("SELECT cto_id, nome, rua, bairro, lat, lng, capacidade FROM ctos").all();
  return jsonResponse({ ok:true, ctos: rs.results || [] }, 200);
}
async function handleUpsertCto(request, env){
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
async function handleGetCeCdo(env){
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

// ---------------- Rotas ----------------
function toFeatureCollection(features){ return { type:"FeatureCollection", features: features || [] }; }
function safeJsonParse(s){ try{ return JSON.parse(s); }catch{ return null; } }

async function handleGetRotas(env){
  const rs = await env.DB.prepare("SELECT id, nome, geojson FROM rotas_fibras").all();
  const features = [];
  for (const r of (rs.results || [])){
    const gj = safeJsonParse(r.geojson);
    if (gj && gj.type === "Feature") features.push(gj);
  }
  const fc = toFeatureCollection(features);
  return jsonResponse({ ok:true, geojson: fc, features: fc.features }, 200);
}
async function handleUpsertRota(request, env){
  const body = await readJson(request);
  if (!body) return jsonResponse({ error:"invalid_json" }, 400);

  const id = normId(body.id || body.ID || body.rota_id || body.ROTA_ID || body.nome);
  const nome = String(body.nome ?? body.NOME ?? id);
  let feature = body.geojson || body.feature;
  if (typeof feature === "string") feature = safeJsonParse(feature);

  if (feature && feature.type === "FeatureCollection" && Array.isArray(feature.features) && feature.features.length){
    feature = feature.features[0];
  }
  if (feature && feature.type === "LineString"){
    feature = { type:"Feature", geometry: feature, properties:{ id, nome } };
  }
  if (!id || !feature || feature.type !== "Feature" || !feature.geometry || feature.geometry.type !== "LineString"){
    return jsonResponse({ error:"missing_fields", message:"id + geojson Feature(LineString) required" }, 400);
  }
  feature.properties = { ...(feature.properties||{}), id, nome };

  await env.DB.prepare(`INSERT INTO rotas_fibras (id, nome, geojson)
    VALUES (?1, ?2, ?3)
    ON CONFLICT(id) DO UPDATE SET
      nome=excluded.nome, geojson=excluded.geojson
  `).bind(id, nome, JSON.stringify(feature)).run();

  return jsonResponse({ ok:true, rota:{ id, nome }, feature }, 200);
}
async function handleDeleteRota(request, env){
  const id = normId(new URL(request.url).searchParams.get("id") || "");
  if (!id) return jsonResponse({ error:"missing_id" }, 400);
  await env.DB.prepare("DELETE FROM rotas_fibras WHERE id=?1").bind(id).run();
  return jsonResponse({ ok:true }, 200);
}

// ---------------- Movimentações ----------------
async function handleGetMovimentacoes(env, url){
  const limit = Math.min(500, Math.max(0, parseInt(url.searchParams.get("limit")||"300",10) || 300));
  try{
    const rs = await env.DB.prepare("SELECT id, cto_id, tipo, cliente, usuario, obs, ts FROM movimentacoes ORDER BY ts DESC LIMIT ?1")
      .bind(limit).all();
    return jsonResponse({ ok:true, items: rs.results || [] }, 200);
  }catch(e){
    return jsonResponse({ ok:true, items: [], note: "no_table_or_query_error", message:String(e?.message||e) }, 200);
  }
}
