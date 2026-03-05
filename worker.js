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

  // Alias: /api/caixas -> /api/caixas_emenda_cdo (front/backward compatibility)
  if (pathname === "/api/caixas") {
    pathname = "/api/caixas_emenda_cdo";
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
      if (pathname === "/api/health") return corsResponse(request, json({ ok: true, ts: new Date().toISOString() }));
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

      // ===== Registro público (sem autenticação) =====
      if (pathname === "/api/registro" && request.method === "POST")   return corsResponse(request, await handleRegistroPublico(request, env));
      if (pathname === "/api/registro/check" && request.method === "GET") return corsResponse(request, await handleCheckDisponivel(request, env));

      // ===== OLTs e Topologia =====
      if (pathname === "/api/olts" && request.method === "GET")    return corsResponse(request, await handleGetOlts(request, env));
      if (pathname === "/api/diagrama" && request.method === "GET")  return corsResponse(request, await handleGetDiagrama(request, env));
      if (pathname === "/api/diagrama" && request.method === "POST") return corsResponse(request, await handleSaveDiagrama(request, env));
      if (pathname === "/api/olts" && isWriteMethod(request.method)) return corsResponse(request, await handleCrudOlts(request, env));
      if (pathname === "/api/topologia" && request.method === "GET") return corsResponse(request, await handleGetTopologia(request, env));
      if (pathname === "/api/topologia/link" && request.method === "POST") return corsResponse(request, await handleLinkTopologia(request, env));

      // ===== Gerenciamento de projetos (superadmin) =====
      if (pathname === "/api/projetos" && request.method === "GET")    return corsResponse(request, await handleListProjetos(request, env));
      if (pathname === "/api/projetos" && request.method === "POST")   return corsResponse(request, await handleUpsertProjeto(request, env));
      if (pathname === "/api/projetos" && request.method === "DELETE") return corsResponse(request, await handleDeleteProjeto(request, env));
      if (pathname === "/api/projetos/stats" && request.method === "GET") return corsResponse(request, await handleProjetoStats(request, env));
      if (pathname === "/api/registros" && request.method === "GET")           return corsResponse(request, await handleListRegistros(request, env));
      if (pathname === "/api/registros/aprovar"  && request.method === "POST") return corsResponse(request, await handleAprovarRegistro(request, env));
      if (pathname === "/api/registros/rejeitar" && request.method === "POST") return corsResponse(request, await handleRejeitarRegistro(request, env));

      // ===== Gerenciamento de usuários (admin) =====
      if (pathname === "/api/users" && request.method === "GET")    return corsResponse(request, await handleListUsers(request, env));
      if (pathname === "/api/users" && request.method === "POST")   return corsResponse(request, await handleUpsertUser(request, env));
      if (pathname === "/api/users" && request.method === "DELETE") return corsResponse(request, await handleDeleteUser(request, env));
      if (pathname === "/api/users/set-password" && request.method === "POST") return corsResponse(request, await handleSetPassword(request, env));
      if (pathname === "/api/users/toggle-active" && request.method === "POST") return corsResponse(request, await handleToggleActive(request, env));

      // ===== Data endpoints (auth required) =====
      if (pathname === "/api/ctos" && request.method === "GET") return corsResponse(request, await handleGetCtos(request, env));
      if (pathname === "/api/caixas_emenda_cdo" && request.method === "GET") return corsResponse(request, await handleGetCaixas(request, env));
      if (pathname === "/api/rotas_fibras" && request.method === "GET") return corsResponse(request, await handleGetRotas(request, env));
      if (pathname === "/api/movimentacoes" && request.method === "GET")    return corsResponse(request, await handleGetMovimentacoes(request, env));
      if (pathname === "/api/movimentacoes" && request.method === "POST")   return corsResponse(request, await handleAddMovimentacao(request, env));
      if (pathname === "/api/movimentacoes/remove-cliente" && request.method === "POST") return corsResponse(request, await handleRemoveCliente(request, env));
      if (pathname === "/api/movimentacoes/import"  && request.method === "POST") return corsResponse(request, await handleImportMovimentacoes(request, env));
      if (pathname === "/api/movimentacoes/export"  && request.method === "GET")  return corsResponse(request, await handleExportMovimentacoes(request, env));
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


function db(env) {
  // Prefer the user-requested D1 binding name "B1"; fall back to legacy "DB" if present.
  const d = env.B1 || env.DB;
  if (!d) throw new Error("Missing D1 binding. Bind your database as B1 (preferred) or DB (legacy).");
  return d;
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
  // Header names are case-insensitive per HTTP spec; browser sometimes sends lowercase.
  const ct = (request.headers.get("Content-Type") || request.headers.get("content-type") || "").toLowerCase();
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
async function mintSession(env, username, projeto_id) {
  const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
  const token      = base64Url(tokenBytes);
  const tokenHash  = await sha256Hex(token);
  const ttl        = Number(env.SESSION_TTL_MS || (1000 * 60 * 60 * 24 * 7));
  const expiresAt  = new Date(Date.now() + ttl).toISOString();
  const pid        = projeto_id || "default";
  await db(env).prepare(
    "INSERT INTO sessions (token_hash, username, projeto_id, created_at, expires_at) VALUES (?1, ?2, ?3, datetime('now'), ?4)"
  ).bind(tokenHash, username, pid, expiresAt).run();
  return token;
}
async function requireAuth(request, env) {
  const token = getBearer(request);
  if (!token) throw Object.assign(new Error("unauthorized"), { code: "unauthorized" });

  const tokenHash = await sha256Hex(token);
  const row = await db(env).prepare(
    "SELECT username, projeto_id, expires_at FROM sessions WHERE token_hash=?1"
  ).bind(tokenHash).first();

  if (!row) throw Object.assign(new Error("unauthorized"), { code: "unauthorized" });
  if (row.expires_at && Date.parse(row.expires_at) < Date.now()) {
    await db(env).prepare("DELETE FROM sessions WHERE token_hash=?1").bind(tokenHash).run();
    throw Object.assign(new Error("unauthorized"), { code: "unauthorized" });
  }
  return { user: row.username, tokenHash, projeto_id: row.projeto_id || "default" };
}
function normalizeRole(role) {
  const r = String(role || "").trim().toLowerCase();
  if (r === "superadmin") return "superadmin";
  if (r === "admin")      return "admin";
  if (r === "tecnico")    return "tecnico";
  return "user";
}
async function getUserFull(env, username) {
  try {
    const row = await db(env).prepare(
      "SELECT role, projeto_id FROM users WHERE username=?1 AND is_active=1"
    ).bind(username).first();
    return {
      role:       normalizeRole(row?.role || "user"),
      projeto_id: row?.projeto_id || "default"
    };
  } catch (_e) {
    return { role: "user", projeto_id: "default" };
  }
}
async function getUserRole(env, username) {
  return (await getUserFull(env, username)).role;
}
async function requireRole(request, env, allowedRoles) {
  const auth = await requireAuth(request, env);
  const full = await getUserFull(env, auth.user);
  // superadmin tem acesso a tudo
  const effective = full.role === "superadmin" && !allowedRoles.includes("superadmin")
    ? [...allowedRoles, "superadmin"] : allowedRoles;
  if (!effective.includes(full.role)) {
    const err = new Error("forbidden");
    err.code  = "forbidden";
    err.role  = full.role;
    throw err;
  }
  return { ...auth, role: full.role, projeto_id: auth.projeto_id || full.projeto_id };
}
async function requireSuperAdmin(request, env) {
  return await requireRole(request, env, ["superadmin"]);
}

async function handleLogin(request, env) {
  await ensureSchema(env);
  const body = await readJson(request);
  const username = String(body?.username ?? body?.user ?? body?.login ?? "").trim();
  const password = String(body?.password ?? body?.pass ?? "");
  if (!username || !password) return json({ error: "missing_credentials" }, 400);

  const user = await db(env).prepare(
    "SELECT username, password_hash, is_active, role, projeto_id FROM users WHERE username=?1"
  ).bind(username).first();

  if (!user || !user.is_active) return json({ error: "invalid_credentials" }, 401);
  const ok = await verifyPassword(password, user.password_hash);
  if (!ok) return json({ error: "invalid_credentials" }, 401);

  const role       = normalizeRole(user.role);
  const projeto_id = user.projeto_id || "default";
  const token      = await mintSession(env, username, projeto_id);

  // Busca nome do projeto
  let projeto_nome = projeto_id;
  try {
    const p = await db(env).prepare("SELECT nome FROM projetos WHERE projeto_id=?1").bind(projeto_id).first();
    if (p?.nome) projeto_nome = p.nome;
  } catch (_) {}

  return json({ ok: true, token, user: { username, role, projeto_id, projeto_nome } });
}
async function handleMe(request, env) {
  try {
    const auth = await requireAuth(request, env);
    const full = await getUserFull(env, auth.user);
    let projeto_nome = auth.projeto_id;
    try {
      const p = await db(env).prepare("SELECT nome FROM projetos WHERE projeto_id=?1").bind(auth.projeto_id).first();
      if (p?.nome) projeto_nome = p.nome;
    } catch (_) {}
    return json({ ok: true, user: { username: auth.user, role: full.role, projeto_id: auth.projeto_id, projeto_nome } });
  } catch (_e) {
    return json({ error: "unauthorized" }, 401);
  }
}
async function handleLogout(request, env) {
  try {
    const auth = await requireAuth(request, env);
    await db(env).prepare("DELETE FROM sessions WHERE token_hash=?1").bind(auth.tokenHash).run();
    return json({ ok: true });
  } catch (_e) {
    return json({ ok: true });
  }
}



async function ensureSchema(env) {
  // Garante que nunca lança exceção — cada bloco tem try-catch individual
  // Rotas
  try {
    await db(env).prepare(
      "CREATE TABLE IF NOT EXISTS rotas (rota_id TEXT PRIMARY KEY, nome TEXT, geojson TEXT NOT NULL, updated_at TEXT)"
    ).run();
  } catch (_e) {}

  // CTOs
  try {
    await db(env).prepare(
      "CREATE TABLE IF NOT EXISTS ctos (cto_id TEXT PRIMARY KEY, projeto_id TEXT NOT NULL DEFAULT \'default\', nome TEXT, rua TEXT, bairro TEXT, capacidade INTEGER, lat REAL, lng REAL, updated_at TEXT, cdo_id TEXT, porta_cdo INTEGER, splitter_cto TEXT)"
    ).run();
  } catch (_e) {}

  // CE/CDO table (existing in your D1): caixas_emenda_cdo
  // We patch missing columns with ALTER TABLE ADD COLUMN (best-effort).
  try {
    await db(env).prepare(
      "CREATE TABLE IF NOT EXISTS caixas_emenda_cdo (id TEXT PRIMARY KEY, projeto_id TEXT NOT NULL DEFAULT \'default\', tipo TEXT, obs TEXT, img_url TEXT, lat REAL, lng REAL, updated_at TEXT, olt_id TEXT, porta_olt INTEGER, splitter_cdo TEXT, diagrama TEXT, nome TEXT, rua TEXT, bairro TEXT)"
    ).run();
  } catch (_e) {}

  // Patch missing columns (if table existed with partial schema)
  const colsToEnsure = [
    ["tipo","TEXT"], ["obs","TEXT"], ["img_url","TEXT"],
    ["lat","REAL"], ["lng","REAL"], ["updated_at","TEXT"]
  ];
  try {
    const info = await db(env).prepare("PRAGMA table_info(caixas_emenda_cdo)").all();
    const have = new Set((info?.results || []).map(r => String(r.name || "").toLowerCase()));
    for (const [c,t] of colsToEnsure) {
      if (!have.has(c)) {
        try { await db(env).prepare(`ALTER TABLE caixas_emenda_cdo ADD COLUMN ${c} ${t}`).run(); } catch (_e) {}
      }
    }
  } catch (_e) {}

  // Patch rotas columns if needed
  try {
    const info = await db(env).prepare("PRAGMA table_info(rotas)").all();
    const have = new Set((info?.results || []).map(r => String(r.name || "").toLowerCase()));
    const cols = [["nome","TEXT"],["geojson","TEXT"],["updated_at","TEXT"]];
    for (const [c,t] of cols) {
      if (!have.has(c)) {
        try { await db(env).prepare(`ALTER TABLE rotas ADD COLUMN ${c} ${t}`).run(); } catch (_e) {}
      }
    }
  } catch (_e) {}

  // Tabela users — cria se não existir, garante colunas mínimas
  try {
    await db(env).prepare(`
      CREATE TABLE IF NOT EXISTS users (
        username      TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        role          TEXT NOT NULL DEFAULT 'user',
        is_active     INTEGER NOT NULL DEFAULT 1,
        created_at    TEXT,
        updated_at    TEXT
      )
    `).run();
  } catch (_e) {}

  // Garante colunas que podem faltar em tabelas antigas
  try {
    const info = await db(env).prepare("PRAGMA table_info(users)").all();
    const have = new Set((info?.results || []).map(r => String(r.name || "").toLowerCase()));
    const userCols = [
      ["role","TEXT NOT NULL DEFAULT 'user'"],
      ["is_active","INTEGER NOT NULL DEFAULT 1"],
      ["created_at","TEXT"],
      ["updated_at","TEXT"]
    ];
    for (const [c,t] of userCols) {
      if (!have.has(c)) {
        try { await db(env).prepare(`ALTER TABLE users ADD COLUMN ${c} ${t}`).run(); } catch (_e) {}
      }
    }
  } catch (_e) {}

  // Tabela sessions — cria se não existir
  try {
    await db(env).prepare(`
      CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        username   TEXT NOT NULL,
        created_at TEXT,
        expires_at TEXT
      )
    `).run();
  } catch (_e) {}

  // Movimentacoes D1
  try {
    await db(env).prepare(`
      CREATE TABLE IF NOT EXISTS movimentacoes_d1 (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        projeto_id TEXT NOT NULL DEFAULT 'default',
        DATA       TEXT,
        CTO_ID     TEXT NOT NULL,
        Tipo       TEXT NOT NULL,
        Cliente    TEXT NOT NULL,
        Usuario    TEXT,
        Observacao TEXT,
        created_at TEXT
      )
    `).run();
  } catch (_e) {}

  // Tabela projetos (multi-tenant)
  try {
    await db(env).prepare(`
      CREATE TABLE IF NOT EXISTS projetos (
        projeto_id TEXT PRIMARY KEY,
        nome       TEXT NOT NULL,
        plano      TEXT NOT NULL DEFAULT 'basico',
        ativo      INTEGER NOT NULL DEFAULT 1,
        criado_em  TEXT,
        config     TEXT
      )
    `).run();
  } catch (_e) {}

  // Tabela registros_pendentes (cadastros aguardando aprovação)
  try {
    await db(env).prepare(`
      CREATE TABLE IF NOT EXISTS registros_pendentes (
        id                   INTEGER PRIMARY KEY AUTOINCREMENT,
        projeto_id_proposto  TEXT NOT NULL,
        empresa              TEXT NOT NULL,
        admin_login          TEXT NOT NULL,
        admin_senha_hash     TEXT NOT NULL,
        email                TEXT,
        telefone             TEXT,
        plano                TEXT NOT NULL DEFAULT 'basico',
        status               TEXT NOT NULL DEFAULT 'pendente',
        criado_em            TEXT,
        aprovado_em          TEXT,
        aprovado_por         TEXT
      )
    `).run();
  } catch (_e) {}

  // Tabela OLTs (equipamento principal da rede)
  try {
    await db(env).prepare(`
      CREATE TABLE IF NOT EXISTS olts (
        id          TEXT PRIMARY KEY,
        projeto_id  TEXT NOT NULL DEFAULT 'default',
        nome        TEXT NOT NULL,
        modelo      TEXT,
        ip          TEXT,
        capacidade  INTEGER DEFAULT 16,
        obs         TEXT,
        lat         REAL,
        lng         REAL,
        updated_at  TEXT
      )
    `).run();
  } catch (_e) {}

  // Colunas de topologia em caixas_emenda_cdo: olt_id, porta_olt, splitter
  try {
    const cxInfo = await db(env).prepare("PRAGMA table_info(caixas_emenda_cdo)").all();
    const cxHave = new Set((cxInfo?.results||[]).map(r=>String(r.name||"").toLowerCase()));
    for (const [c,t] of [["olt_id","TEXT"],["porta_olt","INTEGER"],["splitter_cdo","TEXT"],["diagrama","TEXT"],["nome","TEXT"],["rua","TEXT"],["bairro","TEXT"]]) {
      if (!cxHave.has(c)) try { await db(env).prepare(`ALTER TABLE caixas_emenda_cdo ADD COLUMN ${c} ${t}`).run(); } catch(_){}
    }
  } catch(_) {}

  // Colunas de topologia em ctos: cdo_id, porta_cdo, splitter
  try {
    const ctInfo = await db(env).prepare("PRAGMA table_info(ctos)").all();
    const ctHave = new Set((ctInfo?.results||[]).map(r=>String(r.name||"").toLowerCase()));
    for (const [c,t] of [["cdo_id","TEXT"],["porta_cdo","INTEGER"],["splitter_cto","TEXT"]]) {
      if (!ctHave.has(c)) try { await db(env).prepare(`ALTER TABLE ctos ADD COLUMN ${c} ${t}`).run(); } catch(_){}
    }
  } catch(_) {}

  // Garante projeto "default" para dados legados
  try {
    const def = await db(env).prepare("SELECT projeto_id FROM projetos WHERE projeto_id='default'").first();
    if (!def) {
      await db(env).prepare(
        "INSERT INTO projetos (projeto_id, nome, plano, ativo, criado_em) VALUES ('default','Projeto Principal','pro',1,datetime('now'))"
      ).run();
    }
  } catch (_e) {}

  // Adiciona projeto_id em todas as tabelas (ALTER TABLE ADD COLUMN — ignora se já existe)
  const tablesWithProjeto = [
    "ctos", "caixas_emenda_cdo", "rotas",
    "users", "sessions", "movimentacoes_d1"
  ];
  for (const tbl of tablesWithProjeto) {
    try {
      await db(env).prepare(`ALTER TABLE ${tbl} ADD COLUMN projeto_id TEXT NOT NULL DEFAULT 'default'`).run();
    } catch (_e) { /* já existe — ok */ }
  }

  // Migra linhas sem projeto_id para 'default'
  for (const tbl of ["ctos","caixas_emenda_cdo","rotas","users","movimentacoes_d1"]) {
    try {
      await db(env).prepare(`UPDATE ${tbl} SET projeto_id='default' WHERE projeto_id IS NULL OR projeto_id=''`).run();
    } catch (_e) {}
  }
}

// ======================= Helpers de senha =======================

// Gera hash PBKDF2 no formato armazenado: pbkdf2$<iter>$<salt_b64>$<hash_b64>
async function hashPassword(password) {
  const iter = 100000;
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: iter },
    keyMaterial, 256
  );
  const saltB64 = btoa(String.fromCharCode(...salt));
  const hashB64 = btoa(String.fromCharCode(...new Uint8Array(bits)));
  return `pbkdf2$${iter}$${saltB64}$${hashB64}`;
}





// ======================= Diagrama CE/CDO =======================

async function handleGetDiagrama(request, env) {
  try {
    const auth = await requireViewer(request, env);
    const pid  = auth.projeto_id || "default";
    const url  = new URL(request.url);
    const id   = s(url.searchParams.get("id") || "");
    if (!id) return json({ error: "id_required" }, 400);
    await ensureSchema(env);
    const row = await db(env).prepare(
      "SELECT id, tipo, nome, obs, diagrama FROM caixas_emenda_cdo WHERE id=?1 AND projeto_id=?2"
    ).bind(id, pid).first();
    if (!row) return json({ error: "not_found" }, 404);
    let diagrama = null;
    try { diagrama = row.diagrama ? JSON.parse(row.diagrama) : null; } catch(_) {}
    return json({ ok: true, id: row.id, tipo: row.tipo, nome: row.nome, obs: row.obs, diagrama });
  } catch(e) {
    if (e.code === "unauthorized") return json({ error: "unauthorized" }, 401);
    return json({ error: String(e?.message || e) }, 500);
  }
}

async function handleSaveDiagrama(request, env) {
  try {
    const auth = await requireRole(request, env, ["admin"]);
    const pid  = auth.projeto_id || "default";
    await ensureSchema(env);
    const body = await readJson(request);
    const id   = s(body?.id || "");
    if (!id) return json({ error: "id_required" }, 400);
    const diagrama = JSON.stringify(body?.diagrama || {});
    const exists = await db(env).prepare(
      "SELECT id FROM caixas_emenda_cdo WHERE id=?1 AND projeto_id=?2"
    ).bind(id, pid).first();
    if (!exists) return json({ error: "not_found" }, 404);
    await db(env).prepare(
      "UPDATE caixas_emenda_cdo SET diagrama=?1, updated_at=?2 WHERE id=?3 AND projeto_id=?4"
    ).bind(diagrama, new Date().toISOString(), id, pid).run();
    return json({ ok: true });
  } catch(e) {
    if (e.code === "forbidden")    return json({ error: "forbidden" }, 403);
    if (e.code === "unauthorized") return json({ error: "unauthorized" }, 401);
    return json({ error: String(e?.message || e) }, 500);
  }
}

// ======================= OLTs e Topologia =======================

// GET /api/olts
async function handleGetOlts(request, env) {
  try {
    const auth = await requireViewer(request, env);
    try { await ensureSchema(env); } catch(_) {}
    const pid = auth.projeto_id || "default";
    let results = [];
    try {
      const rows = await db(env).prepare(
        "SELECT * FROM olts WHERE projeto_id=?1 ORDER BY nome"
      ).bind(pid).all();
      results = rows?.results || [];
    } catch(e2) {
      // Tabela pode não ter projeto_id ainda — tenta sem filtro
      try {
        const rows2 = await db(env).prepare("SELECT * FROM olts ORDER BY nome LIMIT 200").all();
        results = rows2?.results || [];
      } catch(_) { results = []; }
    }
    return json({ ok: true, items: results });
  } catch(e) {
    if (e.code==="unauthorized") return json({error:"unauthorized"},401);
    // Retorna lista vazia em vez de 500 para não travar o mapa
    return json({ ok: true, items: [], _warn: String(e?.message||e) });
  }
}

// POST /api/olts  body: {action:"upsert"|"delete", olt:{id,nome,modelo,ip,capacidade,obs,lat,lng}}
async function handleCrudOlts(request, env) {
  try {
    const auth = await requireRole(request, env, ["admin"]);
    await ensureSchema(env);
    const pid  = auth.projeto_id || "default";
    const body = await readJson(request);
    const action = s(body?.action || (request.method==="DELETE"?"delete":"upsert"));
    const olt    = body?.olt || body;
    const now    = new Date().toISOString();

    if (action === "delete") {
      const id = s(olt?.id || body?.id);
      if (!id) return json({error:"id_required"},400);
      // desvincula CE/CDOs que usavam essa OLT
      await db(env).prepare("UPDATE caixas_emenda_cdo SET olt_id=NULL, porta_olt=NULL WHERE olt_id=?1 AND projeto_id=?2").bind(id, pid).run();
      await db(env).prepare("DELETE FROM olts WHERE id=?1 AND projeto_id=?2").bind(id, pid).run();
      return json({ok:true});
    }

    // upsert
    const id   = s(olt?.id || olt?.ID || "").trim() || ("olt_"+Date.now().toString(36));
    const nome = s(olt?.nome || "OLT");
    const modelo   = s(olt?.modelo || "");
    const ip       = s(olt?.ip || "");
    const cap      = Number(olt?.capacidade) || 16;
    const obs      = s(olt?.obs || "");
    const lat      = olt?.lat != null ? Number(olt.lat) : null;
    const lng      = olt?.lng != null ? Number(olt.lng) : null;

    const exists = await db(env).prepare("SELECT id FROM olts WHERE id=?1 AND projeto_id=?2").bind(id, pid).first();
    if (exists) {
      await db(env).prepare(
        "UPDATE olts SET nome=?2,modelo=?3,ip=?4,capacidade=?5,obs=?6,lat=?7,lng=?8,updated_at=?9 WHERE id=?1 AND projeto_id=?10"
      ).bind(id,nome,modelo,ip,cap,obs,lat,lng,now,pid).run();
    } else {
      await db(env).prepare(
        "INSERT INTO olts (id,projeto_id,nome,modelo,ip,capacidade,obs,lat,lng,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)"
      ).bind(id,pid,nome,modelo,ip,cap,obs,lat,lng,now).run();
    }
    return json({ok:true, id});
  } catch(e) {
    if (e.code==="forbidden")    return json({error:"forbidden"},403);
    if (e.code==="unauthorized") return json({error:"unauthorized"},401);
    return json({error:String(e?.message||e)},500);
  }
}

// POST /api/topologia/link — vincula CE/CDO a OLT, ou CTO a CE/CDO
// body: { type:"cdo_to_olt"|"cto_to_cdo", id, parent_id, porta, splitter }
async function handleLinkTopologia(request, env) {
  try {
    const auth = await requireRole(request, env, ["admin"]);
    await ensureSchema(env);
    const pid  = auth.projeto_id || "default";
    const body = await readJson(request);
    const type = s(body?.type);
    const id   = s(body?.id);
    const parent_id = s(body?.parent_id);
    const porta = body?.porta != null ? Number(body.porta) : null;
    const splitter = s(body?.splitter || "");

    if (type === "cdo_to_olt") {
      await db(env).prepare(
        "UPDATE caixas_emenda_cdo SET olt_id=?1, porta_olt=?2, splitter_cdo=?3 WHERE id=?4 AND projeto_id=?5"
      ).bind(parent_id||null, porta, splitter||null, id, pid).run();
      return json({ok:true});
    }
    if (type === "cto_to_cdo") {
      await db(env).prepare(
        "UPDATE ctos SET cdo_id=?1, porta_cdo=?2, splitter_cto=?3 WHERE cto_id=?4 AND projeto_id=?5"
      ).bind(parent_id||null, porta, splitter||null, id, pid).run();
      return json({ok:true});
    }
    return json({error:"type_invalid"},400);
  } catch(e) {
    if (e.code==="forbidden")    return json({error:"forbidden"},403);
    if (e.code==="unauthorized") return json({error:"unauthorized"},401);
    return json({error:String(e?.message||e)},500);
  }
}

// GET /api/topologia — retorna árvore completa OLT→CE/CDO→CTOs
async function handleGetTopologia(request, env) {
  try {
    const auth = await requireViewer(request, env);
    await ensureSchema(env);
    const pid = auth.projeto_id || "default";
    const url = new URL(request.url);
    const oltId = s(url.searchParams.get("olt_id")||"");
    const cdoId = s(url.searchParams.get("cdo_id")||"");

    const [oltsRes, cdosRes, ctosRes] = await Promise.all([
      db(env).prepare("SELECT * FROM olts WHERE projeto_id=?1 ORDER BY nome").bind(pid).all(),
      db(env).prepare("SELECT * FROM caixas_emenda_cdo WHERE projeto_id=?1 ORDER BY id").bind(pid).all(),
      db(env).prepare("SELECT * FROM ctos WHERE projeto_id=?1 ORDER BY cto_id").bind(pid).all(),
    ]);

    const olts = oltsRes?.results || [];
    const cdos = cdosRes?.results || [];
    const ctos = ctosRes?.results || [];

    // Monta árvore
    const tree = olts.map(olt => {
      const myCdos = cdos.filter(c => String(c.olt_id||"") === String(olt.id));
      return {
        ...olt,
        cdos: myCdos.map(cdo => ({
          ...cdo,
          ctos: ctos.filter(ct => String(ct.cdo_id||"") === String(cdo.id))
        }))
      };
    });

    // CDOs sem OLT
    const orphanCdos = cdos.filter(c => !c.olt_id).map(cdo => ({
      ...cdo,
      ctos: ctos.filter(ct => String(ct.cdo_id||"") === String(cdo.id))
    }));

    // CTOs sem CDO
    const orphanCtos = ctos.filter(ct => !ct.cdo_id);

    return json({ ok:true, tree, orphanCdos, orphanCtos,
      stats: { olts: olts.length, cdos: cdos.length, ctos: ctos.length } });
  } catch(e) {
    if (e.code==="unauthorized") return json({error:"unauthorized"},401);
    return json({error:String(e?.message||e)},500);
  }
}

// ======================= Registro Público de Novos Assinantes =======================

// Tabela registros_pendentes — criada em ensureSchema
// GET /api/registro/check?empresa=xxx&login=yyy — verifica disponibilidade
async function handleCheckDisponivel(request, env) {
  try {
    await ensureSchema(env);
    const url    = new URL(request.url);
    const empresa = s(url.searchParams.get("empresa") || "").trim();
    const login   = s(url.searchParams.get("login")   || "").trim().toLowerCase();

    const result = { empresa_ok: true, login_ok: true };

    if (empresa) {
      const pid = empresa.toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 20);
      const ex  = await db(env).prepare(
        "SELECT projeto_id FROM projetos WHERE projeto_id=?1 OR nome=?2"
      ).bind(pid, empresa).first();
      result.empresa_ok = !ex;
    }

    if (login) {
      const ex = await db(env).prepare(
        "SELECT username FROM users WHERE username=?1"
      ).bind(login).first();
      // também verifica pendentes
      const exp = await db(env).prepare(
        "SELECT id FROM registros_pendentes WHERE admin_login=?1 AND status='pendente'"
      ).bind(login).first();
      result.login_ok = !ex && !exp;
    }

    return json({ ok: true, ...result });
  } catch (e) {
    return json({ ok: true, empresa_ok: true, login_ok: true }); // fail open
  }
}

// POST /api/registro — cadastro público de novo assinante
// Body: { empresa, admin_login, admin_senha, email?, telefone?, plano? }
// Se REGISTRO_AUTO_APROVAR=true no env → cria o projeto direto
// Caso contrário → cria registro pendente aguardando superadmin aprovar
async function handleRegistroPublico(request, env) {
  try {
    await ensureSchema(env);
    const body = await readJson(request);

    const empresa     = s(body?.empresa    || "").trim();
    const admin_login = s(body?.admin_login|| "").trim().toLowerCase().replace(/[^a-z0-9_-]/g, "");
    const admin_senha = s(body?.admin_senha|| "").trim();
    const email       = s(body?.email      || "").trim();
    const telefone    = s(body?.telefone   || "").trim();
    const plano       = ["basico","pro"].includes(body?.plano) ? body.plano : "basico";

    // Validações
    if (!empresa)                    return json({ error: "empresa_obrigatoria" }, 400);
    if (empresa.length < 2)          return json({ error: "empresa_muito_curta" }, 400);
    if (!admin_login)                return json({ error: "login_obrigatorio" }, 400);
    if (admin_login.length < 3)      return json({ error: "login_muito_curto", min: 3 }, 400);
    if (!admin_senha)                return json({ error: "senha_obrigatoria" }, 400);
    if (admin_senha.length < 6)      return json({ error: "senha_muito_curta", min: 6 }, 400);

    // Verifica duplicatas
    const projeto_id = empresa.toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 20)
                       + "_" + Date.now().toString(36);

    const exEmpresa = await db(env).prepare(
      "SELECT projeto_id FROM projetos WHERE nome=?1"
    ).bind(empresa).first();
    if (exEmpresa) return json({ error: "empresa_ja_cadastrada" }, 409);

    const exLogin = await db(env).prepare(
      "SELECT username FROM users WHERE username=?1"
    ).bind(admin_login).first();
    if (exLogin) return json({ error: "login_ja_existe" }, 409);

    const exPendente = await db(env).prepare(
      "SELECT id FROM registros_pendentes WHERE admin_login=?1 AND status='pendente'"
    ).bind(admin_login).first();
    if (exPendente) return json({ error: "cadastro_ja_pendente" }, 409);

    const now = new Date().toISOString();
    const autoAprovar = env.REGISTRO_AUTO_APROVAR === "true" || env.REGISTRO_AUTO_APROVAR === "1";

    if (autoAprovar) {
      // Cria projeto e usuário admin imediatamente
      const hash = await hashPassword(admin_senha);
      await db(env).prepare(
        "INSERT INTO projetos (projeto_id, nome, plano, ativo, criado_em) VALUES (?1,?2,?3,1,?4)"
      ).bind(projeto_id, empresa, plano, now).run();
      await db(env).prepare(
        "INSERT INTO users (username, password_hash, role, is_active, projeto_id, created_at, updated_at) VALUES (?1,?2,'admin',1,?3,?4,?4)"
      ).bind(admin_login, hash, projeto_id, now).run();

      return json({ ok: true, status: "ativo", projeto_id, message: "Conta criada! Faça login no app." });
    } else {
      // Salva como pendente para aprovação manual
      await db(env).prepare(`
        INSERT INTO registros_pendentes
          (projeto_id_proposto, empresa, admin_login, admin_senha_hash, email, telefone, plano, status, criado_em)
        VALUES (?1,?2,?3,?4,?5,?6,?7,'pendente',?8)
      `).bind(projeto_id, empresa, admin_login, await hashPassword(admin_senha), email, telefone, plano, now).run();

      return json({ ok: true, status: "pendente", message: "Cadastro recebido! Em breve você receberá o acesso." });
    }
  } catch (e) {
    return json({ error: String(e?.message || e) }, 500);
  }
}


// GET /api/registros — lista pendentes (superadmin)
async function handleListRegistros(request, env) {
  try {
    await requireSuperAdmin(request, env);
    await ensureSchema(env);
    const url    = new URL(request.url);
    const status = s(url.searchParams.get("status") || "pendente");
    const rows   = await db(env).prepare(
      "SELECT id,projeto_id_proposto,empresa,admin_login,email,telefone,plano,status,criado_em,aprovado_em,aprovado_por FROM registros_pendentes WHERE status=?1 ORDER BY criado_em DESC"
    ).bind(status).all();
    return json({ ok: true, items: rows?.results || [] });
  } catch (e) {
    if (e.code === "forbidden")    return json({ error: "forbidden" }, 403);
    if (e.code === "unauthorized") return json({ error: "unauthorized" }, 401);
    return json({ error: String(e?.message || e) }, 500);
  }
}

// POST /api/registros/aprovar — aprova cadastro pendente (superadmin)
async function handleAprovarRegistro(request, env) {
  try {
    const auth = await requireSuperAdmin(request, env);
    await ensureSchema(env);
    const body = await readJson(request);
    const id   = Number(body?.id);
    if (!id) return json({ error: "id_required" }, 400);

    const reg = await db(env).prepare(
      "SELECT * FROM registros_pendentes WHERE id=?1 AND status='pendente'"
    ).bind(id).first();
    if (!reg) return json({ error: "registro_nao_encontrado" }, 404);

    const now = new Date().toISOString();

    // Cria projeto
    await db(env).prepare(
      "INSERT INTO projetos (projeto_id, nome, plano, ativo, criado_em) VALUES (?1,?2,?3,1,?4)"
    ).bind(reg.projeto_id_proposto, reg.empresa, reg.plano, now).run();

    // Cria usuário admin com a senha já hashada
    await db(env).prepare(
      "INSERT INTO users (username, password_hash, role, is_active, projeto_id, created_at, updated_at) VALUES (?1,?2,'admin',1,?3,?4,?4)"
    ).bind(reg.admin_login, reg.admin_senha_hash, reg.projeto_id_proposto, now).run();

    // Marca como aprovado
    await db(env).prepare(
      "UPDATE registros_pendentes SET status='aprovado', aprovado_em=?1, aprovado_por=?2 WHERE id=?3"
    ).bind(now, auth.user, id).run();

    return json({ ok: true, projeto_id: reg.projeto_id_proposto, empresa: reg.empresa, admin_login: reg.admin_login });
  } catch (e) {
    if (e.code === "forbidden")    return json({ error: "forbidden" }, 403);
    if (e.code === "unauthorized") return json({ error: "unauthorized" }, 401);
    return json({ error: String(e?.message || e) }, 500);
  }
}

// POST /api/registros/rejeitar — rejeita cadastro pendente (superadmin)
async function handleRejeitarRegistro(request, env) {
  try {
    const auth = await requireSuperAdmin(request, env);
    await ensureSchema(env);
    const body = await readJson(request);
    const id   = Number(body?.id);
    if (!id) return json({ error: "id_required" }, 400);

    const now = new Date().toISOString();
    await db(env).prepare(
      "UPDATE registros_pendentes SET status='rejeitado', aprovado_em=?1, aprovado_por=?2 WHERE id=?3 AND status='pendente'"
    ).bind(now, auth.user, id).run();

    return json({ ok: true });
  } catch (e) {
    if (e.code === "forbidden")    return json({ error: "forbidden" }, 403);
    if (e.code === "unauthorized") return json({ error: "unauthorized" }, 401);
    return json({ error: String(e?.message || e) }, 500);
  }
}

// ======================= Gerenciamento de Projetos (superadmin) =======================

// GET /api/projetos
async function handleListProjetos(request, env) {
  try {
    await requireSuperAdmin(request, env);
    await ensureSchema(env);
    const rows = await db(env).prepare(
      "SELECT projeto_id, nome, plano, ativo, criado_em, config FROM projetos ORDER BY criado_em DESC"
    ).all();
    const projetos = rows?.results || [];

    // Conta usuários e CTOs por projeto em paralelo
    const [usersRes, ctosRes, movsRes] = await Promise.allSettled([
      db(env).prepare("SELECT projeto_id, COUNT(*) as total FROM users GROUP BY projeto_id").all(),
      db(env).prepare("SELECT projeto_id, COUNT(*) as total FROM ctos GROUP BY projeto_id").all(),
      db(env).prepare("SELECT projeto_id, COUNT(*) as total FROM movimentacoes_d1 GROUP BY projeto_id").all()
    ]);

    const usersMap = new Map((usersRes.value?.results || []).map(r => [r.projeto_id, r.total]));
    const ctosMap  = new Map((ctosRes.value?.results  || []).map(r => [r.projeto_id, r.total]));
    const movsMap  = new Map((movsRes.value?.results  || []).map(r => [r.projeto_id, r.total]));

    const items = projetos.map(p => ({
      projeto_id:   p.projeto_id,
      nome:         p.nome,
      plano:        p.plano || "basico",
      ativo:        p.ativo === 1 || p.ativo === true,
      criado_em:    p.criado_em || "",
      config:       p.config   || null,
      stats: {
        usuarios:     usersMap.get(p.projeto_id) || 0,
        ctos:         ctosMap.get(p.projeto_id)  || 0,
        movimentacoes:movsMap.get(p.projeto_id)  || 0
      }
    }));
    return json({ ok: true, items });
  } catch (e) {
    if (e.code === "forbidden")    return json({ error: "forbidden" }, 403);
    if (e.code === "unauthorized") return json({ error: "unauthorized" }, 401);
    return json({ error: String(e?.message || e) }, 500);
  }
}

// GET /api/projetos/stats — stats do próprio projeto (admin)
async function handleProjetoStats(request, env) {
  try {
    const auth = await requireRole(request, env, ["admin", "superadmin"]);
    await ensureSchema(env);
    const url = new URL(request.url);
    const pid = auth.role === "superadmin"
      ? (s(url.searchParams.get("projeto_id")) || auth.projeto_id)
      : auth.projeto_id;

    const [usersRes, ctosRes, rotasRes, movsRes] = await Promise.allSettled([
      db(env).prepare("SELECT COUNT(*) as t FROM users WHERE projeto_id=?1 AND is_active=1").bind(pid).first(),
      db(env).prepare("SELECT COUNT(*) as t FROM ctos WHERE projeto_id=?1").bind(pid).first(),
      db(env).prepare("SELECT COUNT(*) as t FROM rotas WHERE projeto_id=?1").bind(pid).first(),
      db(env).prepare("SELECT COUNT(*) as t FROM movimentacoes_d1 WHERE projeto_id=?1").bind(pid).first()
    ]);

    const proj = await db(env).prepare("SELECT nome, plano, ativo FROM projetos WHERE projeto_id=?1").bind(pid).first();
    return json({
      ok: true,
      projeto_id: pid,
      nome:  proj?.nome  || pid,
      plano: proj?.plano || "basico",
      ativo: proj?.ativo !== 0,
      stats: {
        usuarios:      usersRes.value?.t  || 0,
        ctos:          ctosRes.value?.t   || 0,
        rotas:         rotasRes.value?.t  || 0,
        movimentacoes: movsRes.value?.t   || 0
      }
    });
  } catch (e) {
    if (e.code === "forbidden")    return json({ error: "forbidden" }, 403);
    if (e.code === "unauthorized") return json({ error: "unauthorized" }, 401);
    return json({ error: String(e?.message || e) }, 500);
  }
}

// POST /api/projetos — cria ou atualiza projeto + cria admin inicial
// Body: { projeto_id, nome, plano?, ativo?, admin_username?, admin_password? }
async function handleUpsertProjeto(request, env) {
  try {
    await requireSuperAdmin(request, env);
    await ensureSchema(env);
    const body = await readJson(request);

    let projeto_id   = s(body?.projeto_id || "").toLowerCase().replace(/[^a-z0-9_-]/g, "");
    const nome       = s(body?.nome || "").trim();
    const plano      = ["basico","pro","enterprise"].includes(body?.plano) ? body.plano : "basico";
    const ativo      = body?.ativo !== false ? 1 : 0;
    const adminUser  = s(body?.admin_username || "").trim().toLowerCase();
    const adminPass  = s(body?.admin_password || "").trim();

    if (!nome) return json({ error: "nome_required" }, 400);

    // Gera projeto_id se não informado
    if (!projeto_id) {
      projeto_id = nome.toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 20) +
                   "_" + Date.now().toString(36);
    }

    const now = new Date().toISOString();
    const existing = await db(env).prepare(
      "SELECT projeto_id FROM projetos WHERE projeto_id=?1"
    ).bind(projeto_id).first();

    if (existing) {
      await db(env).prepare(
        "UPDATE projetos SET nome=?2, plano=?3, ativo=?4 WHERE projeto_id=?1"
      ).bind(projeto_id, nome, plano, ativo).run();
    } else {
      await db(env).prepare(
        "INSERT INTO projetos (projeto_id, nome, plano, ativo, criado_em) VALUES (?1,?2,?3,?4,?5)"
      ).bind(projeto_id, nome, plano, ativo, now).run();
    }

    // Se veio admin_username + admin_password, cria/atualiza o admin do projeto
    let adminCreated = false;
    if (adminUser && adminPass && adminPass.length >= 4) {
      const hash = await hashPassword(adminPass);
      const existingAdmin = await db(env).prepare(
        "SELECT username FROM users WHERE username=?1"
      ).bind(adminUser).first();
      if (existingAdmin) {
        await db(env).prepare(
          "UPDATE users SET password_hash=?1, role='admin', is_active=1, projeto_id=?2, updated_at=?3 WHERE username=?4"
        ).bind(hash, projeto_id, now, adminUser).run();
      } else {
        await db(env).prepare(
          "INSERT INTO users (username, password_hash, role, is_active, projeto_id, created_at, updated_at) VALUES (?1,?2,'admin',1,?3,?4,?4)"
        ).bind(adminUser, hash, projeto_id, now).run();
      }
      adminCreated = true;
    }

    return json({ ok: true, projeto_id, nome, plano, ativo: ativo === 1, admin_created: adminCreated, action: existing ? "updated" : "created" });
  } catch (e) {
    if (e.code === "forbidden")    return json({ error: "forbidden" }, 403);
    if (e.code === "unauthorized") return json({ error: "unauthorized" }, 401);
    return json({ error: String(e?.message || e) }, 500);
  }
}

// DELETE /api/projetos — desativa ou remove projeto
// Body: { projeto_id, force?: true } — force=true remove todos os dados
async function handleDeleteProjeto(request, env) {
  try {
    await requireSuperAdmin(request, env);
    await ensureSchema(env);
    const body       = await readJson(request);
    const projeto_id = s(body?.projeto_id || "").trim();
    const force      = body?.force === true;

    if (!projeto_id) return json({ error: "projeto_id_required" }, 400);
    if (projeto_id === "default") return json({ error: "cannot_delete_default" }, 400);

    if (force) {
      // Remove todos os dados do projeto
      await db(env).batch([
        db(env).prepare("DELETE FROM ctos                WHERE projeto_id=?1").bind(projeto_id),
        db(env).prepare("DELETE FROM caixas_emenda_cdo   WHERE projeto_id=?1").bind(projeto_id),
        db(env).prepare("DELETE FROM rotas               WHERE projeto_id=?1").bind(projeto_id),
        db(env).prepare("DELETE FROM movimentacoes_d1    WHERE projeto_id=?1").bind(projeto_id),
        db(env).prepare("DELETE FROM sessions WHERE username IN (SELECT username FROM users WHERE projeto_id=?1)").bind(projeto_id),
        db(env).prepare("DELETE FROM users               WHERE projeto_id=?1").bind(projeto_id),
        db(env).prepare("DELETE FROM projetos            WHERE projeto_id=?1").bind(projeto_id)
      ]);
      return json({ ok: true, action: "deleted", projeto_id });
    } else {
      // Apenas desativa
      await db(env).prepare("UPDATE projetos SET ativo=0 WHERE projeto_id=?1").bind(projeto_id).run();
      // Invalida sessões dos usuários do projeto
      await db(env).prepare(
        "DELETE FROM sessions WHERE username IN (SELECT username FROM users WHERE projeto_id=?1)"
      ).bind(projeto_id).run();
      return json({ ok: true, action: "deactivated", projeto_id });
    }
  } catch (e) {
    if (e.code === "forbidden")    return json({ error: "forbidden" }, 403);
    if (e.code === "unauthorized") return json({ error: "unauthorized" }, 401);
    return json({ error: String(e?.message || e) }, 500);
  }
}

// ======================= Handlers de usuários =======================

// GET /api/users — lista usuários do projeto (admin) ou todos (superadmin)
async function handleListUsers(request, env) {
  try {
    const auth = await requireRole(request, env, ["admin", "superadmin"]);
    await ensureSchema(env);
    const url = new URL(request.url);
    // superadmin pode filtrar por projeto_id via ?projeto_id=
    const pid = auth.role === "superadmin"
      ? s(url.searchParams.get("projeto_id") || auth.projeto_id)
      : auth.projeto_id;

    const res = auth.role === "superadmin" && !url.searchParams.get("projeto_id")
      ? await db(env).prepare("SELECT username, role, projeto_id, is_active, created_at, updated_at FROM users ORDER BY projeto_id, username").all()
      : await db(env).prepare("SELECT username, role, projeto_id, is_active, created_at, updated_at FROM users WHERE projeto_id=?1 ORDER BY username").bind(pid).all();

    const items = (res?.results || []).map(u => ({
      username:   u.username,
      role:       u.role || "user",
      projeto_id: u.projeto_id || "default",
      is_active:  u.is_active === 1 || u.is_active === true,
      created_at: u.created_at || "",
      updated_at: u.updated_at || ""
    }));
    return json({ ok: true, items });
  } catch (e) {
    if (e.code === "forbidden")    return json({ error: "forbidden" }, 403);
    if (e.code === "unauthorized") return json({ error: "unauthorized" }, 401);
    return json({ error: String(e?.message || e) }, 500);
  }
}

// POST /api/users — cria ou atualiza usuário { username, password, role, projeto_id? }
async function handleUpsertUser(request, env) {
  try {
    const auth = await requireRole(request, env, ["admin", "superadmin"]);
    await ensureSchema(env);
    const body = await readJson(request);
    const username = String(body?.username || "").trim().toLowerCase();
    const password = String(body?.password || "");
    const active   = body?.is_active !== false ? 1 : 0;

    if (!username) return json({ error: "username_required" }, 400);
    if (!password) return json({ error: "password_required" }, 400);
    if (username.length < 2) return json({ error: "username_too_short" }, 400);
    if (password.length < 4) return json({ error: "password_too_short" }, 400);

    // admin só pode criar roles abaixo do seu nível
    const requestedRole = String(body?.role || "user").trim().toLowerCase();
    const validRoles = auth.role === "superadmin"
      ? ["superadmin","admin","tecnico","user"]
      : ["admin","tecnico","user"];
    const finalRole = validRoles.includes(requestedRole) ? requestedRole : "user";

    // projeto_id: superadmin pode especificar qualquer projeto; admin usa o próprio
    const finalProjeto = auth.role === "superadmin" && body?.projeto_id
      ? String(body.projeto_id).trim()
      : auth.projeto_id;

    const hash = await hashPassword(password);
    const now  = new Date().toISOString();

    const existing = await db(env).prepare(
      "SELECT username, projeto_id FROM users WHERE username=?1"
    ).bind(username).first();

    // Admin só pode editar usuários do próprio projeto
    if (existing && auth.role !== "superadmin" && existing.projeto_id !== auth.projeto_id) {
      return json({ error: "forbidden" }, 403);
    }

    if (existing) {
      await db(env).prepare(
        "UPDATE users SET password_hash=?1, role=?2, is_active=?3, updated_at=?4, projeto_id=?5 WHERE username=?6"
      ).bind(hash, finalRole, active, now, finalProjeto, username).run();
    } else {
      await db(env).prepare(
        "INSERT INTO users (username, password_hash, role, is_active, projeto_id, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?6)"
      ).bind(username, hash, finalRole, active, finalProjeto, now).run();
    }

    return json({ ok: true, username, role: finalRole, projeto_id: finalProjeto, is_active: active === 1, action: existing ? "updated" : "created" });
  } catch (e) {
    if (e.code === "forbidden")    return json({ error: "forbidden" }, 403);
    if (e.code === "unauthorized") return json({ error: "unauthorized" }, 401);
    return json({ error: String(e?.message || e) }, 500);
  }
}

// DELETE /api/users — remove usuário { username }
async function handleDeleteUser(request, env) {
  try {
    await requireRole(request, env, ["admin"]);
    await ensureSchema(env);
    const body = await readJson(request);
    const username = String(body?.username || "").trim().toLowerCase();
    if (!username) return json({ error: "username_required" }, 400);

    // Impede remover o próprio usuário
    const auth = await requireAuth(request, env);
    if (auth.user === username) return json({ error: "cannot_delete_self" }, 400);

    await db(env).prepare("DELETE FROM users WHERE username=?1").bind(username).run();
    await db(env).prepare("DELETE FROM sessions WHERE username=?1").bind(username).run();
    return json({ ok: true, username, action: "deleted" });
  } catch (e) {
    if (e.code === "forbidden")    return json({ error: "forbidden" }, 403);
    if (e.code === "unauthorized") return json({ error: "unauthorized" }, 401);
    return json({ error: String(e?.message || e) }, 500);
  }
}

// POST /api/users/set-password — troca senha { username, password }
async function handleSetPassword(request, env) {
  try {
    await requireRole(request, env, ["admin"]);
    await ensureSchema(env);
    const body = await readJson(request);
    const username = String(body?.username || "").trim().toLowerCase();
    const password = String(body?.password || "");
    if (!username) return json({ error: "username_required" }, 400);
    if (password.length < 4) return json({ error: "password_too_short" }, 400);

    const hash = await hashPassword(password);
    const now  = new Date().toISOString();
    await db(env).prepare(
      "UPDATE users SET password_hash=?1, updated_at=?2 WHERE username=?3"
    ).bind(hash, now, username).run();
    // Invalida sessões antigas
    await db(env).prepare("DELETE FROM sessions WHERE username=?1").bind(username).run();
    return json({ ok: true, username, action: "password_updated" });
  } catch (e) {
    if (e.code === "forbidden")    return json({ error: "forbidden" }, 403);
    if (e.code === "unauthorized") return json({ error: "unauthorized" }, 401);
    return json({ error: String(e?.message || e) }, 500);
  }
}

// POST /api/users/toggle-active — ativa/desativa { username, is_active }
async function handleToggleActive(request, env) {
  try {
    await requireRole(request, env, ["admin"]);
    await ensureSchema(env);
    const body     = await readJson(request);
    const username = String(body?.username || "").trim().toLowerCase();
    const active   = body?.is_active ? 1 : 0;
    if (!username) return json({ error: "username_required" }, 400);

    const auth = await requireAuth(request, env);
    if (!active && auth.user === username) return json({ error: "cannot_deactivate_self" }, 400);

    const now = new Date().toISOString();
    await db(env).prepare(
      "UPDATE users SET is_active=?1, updated_at=?2 WHERE username=?3"
    ).bind(active, now, username).run();
    if (!active) {
      // Invalida sessões ao desativar
      await db(env).prepare("DELETE FROM sessions WHERE username=?1").bind(username).run();
    }
    return json({ ok: true, username, is_active: active === 1 });
  } catch (e) {
    if (e.code === "forbidden")    return json({ error: "forbidden" }, 403);
    if (e.code === "unauthorized") return json({ error: "unauthorized" }, 401);
    return json({ error: String(e?.message || e) }, 500);
  }
}

async function safeLog(env, entry) {
  // Optional: if table log_eventos exists, store logs; otherwise ignore.
  try {
    await db(env).prepare(
      "INSERT INTO log_eventos (ts, user, role, action, entity, entity_id, details) VALUES (?1,?2,?3,?4,?5,?6,?7)"
    ).bind(entry.ts, entry.user, entry.role, entry.action, entry.entity, entry.entity_id, entry.details).run();
  } catch (_e) { /* ignore */ }
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
        await ensureSchema(env);
const body = await readJson(request) || {};
    const action = request.method === "DELETE" ? "DELETE" : "UPSERT";
    const cto = extractCto(body);

    const pid_cto = auth.projeto_id || "default";
    if (!cto.CTO_ID) return json({ ok: false, error: "missing_cto_id" }, 400);
    if (action !== "DELETE" && (cto.LAT === null || cto.LNG === null)) return json({ ok: false, error: "missing_lat_lng" }, 400);

    if (action === "DELETE") {
      await db(env).prepare("DELETE FROM ctos WHERE cto_id=?1 AND projeto_id=?2").bind(cto.CTO_ID, pid_cto).run();
    } else {
      const cdoId   = s(cto.cdo_id   || cto.CDO_ID   || body.cdo_id   || "");
      const portaCdo= intOrNull(cto.porta_cdo ?? body.porta_cdo ?? null);
      const splitCto= s(cto.splitter_cto || body.splitter_cto || "");
      const upd = await db(env).prepare(
        "UPDATE ctos SET nome=?2, rua=?3, bairro=?4, capacidade=?5, lat=?6, lng=?7, updated_at=?8, cdo_id=?10, porta_cdo=?11, splitter_cto=?12 WHERE cto_id=?1 AND projeto_id=?9"
      ).bind(cto.CTO_ID, s(cto.NOME), s(cto.RUA), s(cto.BAIRRO), intOrNull(cto.CAPACIDADE), num(cto.LAT), num(cto.LNG), new Date().toISOString(), pid_cto, cdoId||null, portaCdo, splitCto||null).run();

      if (!upd || !upd.meta || upd.meta.changes === 0) {
        await db(env).prepare(
          "INSERT INTO ctos (cto_id, projeto_id, nome, rua, bairro, capacidade, lat, lng, updated_at, cdo_id, porta_cdo, splitter_cto) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)"
        ).bind(cto.CTO_ID, pid_cto, s(cto.NOME), s(cto.RUA), s(cto.BAIRRO), intOrNull(cto.CAPACIDADE), num(cto.LAT), num(cto.LNG), new Date().toISOString(), cdoId||null, portaCdo, splitCto||null).run();
      }
    }

    // log
    await safeLog(env, {
      ts: new Date().toISOString(),
      user: auth.user,
      role: auth.role,
      action: `${action}_CTO`,
      entity: "CTO",
      entity_id: cto.CTO_ID,
      details: JSON.stringify(cto)
    });

    return json({ ok: true });
  } catch (e) {
    if (e?.code === "forbidden") return json({ ok: false, error: "forbidden", role: e.role }, 403);
    if (e?.code === "unauthorized") return json({ ok: false, error: "unauthorized" }, 401);
    return json({ ok: false, error: "cto_crud_failed", message: String(e?.stack || e), hint: "Verifique colunas da tabela ctos (cto_id/nome/rua/bairro/capacidade/lat/lng). Se sua tabela usa outros nomes, avise que eu ajusto." }, 500);
  // cto_crud_fallback
  }
}

async function handleCrudCaixas(request, env) {
  try {
    const auth = await requireRole(request, env, ["admin"]);
        await ensureSchema(env);
const body = await readJson(request) || {};
    const action = request.method === "DELETE" ? "DELETE" : "UPSERT";
    const cx = extractCaixa(body);

    const pid_cx = auth.projeto_id || "default";
    if (!cx.ID) return json({ ok: false, error: "missing_id" }, 400);
    if (action !== "DELETE" && (cx.LAT === null || cx.LNG === null)) return json({ ok: false, error: "missing_lat_lng" }, 400);

    if (action === "DELETE") {
      await db(env).prepare("DELETE FROM caixas_emenda_cdo WHERE id=?1 AND projeto_id=?2").bind(cx.ID, pid_cx).run();
    } else {
      const oltId   = s(cx.olt_id   || body.olt_id   || "");
      const portaOlt= intOrNull(cx.porta_olt ?? body.porta_olt ?? null);
      const splitCdo= s(cx.splitter_cdo || body.splitter_cdo || "");
      const upd = await db(env).prepare(
        "UPDATE caixas_emenda_cdo SET tipo=?2, obs=?3, img_url=?4, lat=?5, lng=?6, updated_at=?7, olt_id=?9, porta_olt=?10, splitter_cdo=?11 WHERE id=?1 AND projeto_id=?8"
      ).bind(cx.ID, s(cx.TIPO), s(cx.OBS), s(cx.IMG_URL), num(cx.LAT), num(cx.LNG), new Date().toISOString(), pid_cx, oltId||null, portaOlt, splitCdo||null).run();

      if (!upd || !upd.meta || upd.meta.changes === 0) {
        await db(env).prepare(
          "INSERT INTO caixas_emenda_cdo (id, projeto_id, tipo, obs, img_url, lat, lng, updated_at, olt_id, porta_olt, splitter_cdo) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)"
        ).bind(cx.ID, pid_cx, s(cx.TIPO), s(cx.OBS), s(cx.IMG_URL), num(cx.LAT), num(cx.LNG), new Date().toISOString(), oltId||null, portaOlt, splitCdo||null).run();
      }
    }

    await safeLog(env, {
      ts: new Date().toISOString(),
      user: auth.user,
      role: auth.role,
      action: `${action}_CAIXA`,
      entity: "CE/CDO",
      entity_id: cx.ID,
      details: JSON.stringify(cx)
    });

    return json({ ok: true });
  } catch (e) {
    if (e?.code === "forbidden") return json({ ok: false, error: "forbidden", role: e.role }, 403);
    if (e?.code === "unauthorized") return json({ ok: false, error: "unauthorized" }, 401);
    return json({ ok: false, error: "caixa_crud_failed", message: String(e?.stack || e) }, 500);
  }
}

async function handleCrudRotas(request, env) {
  try {
    const auth = await requireRole(request, env, ["admin"]);
        await ensureSchema(env);
const body = await readJson(request) || {};
    const action = request.method === "DELETE" ? "DELETE" : "UPSERT";

    const rota_id = s(body.rota_id || body.ROTA_ID || body.id || body.ID);
    const nome = s(body.nome || body.NOME);
    let geojsonRaw = body.geojson ?? body.GEOJSON ?? body.data ?? body.feature ?? body.features;

    const pid_r = auth.projeto_id || "default";
    if (!rota_id) return json({ ok: false, error: "missing_rota_id" }, 400);

    if (action === "DELETE") {
      await db(env).prepare("DELETE FROM rotas WHERE rota_id=?1 AND projeto_id=?2").bind(rota_id, pid_r).run();
    } else {
      if (!geojsonRaw) return json({ ok: false, error: "missing_geojson", message: "O campo geojson é obrigatório para salvar uma rota." }, 400);
      if (typeof geojsonRaw === "string") {
        try { geojsonRaw = JSON.parse(geojsonRaw); } catch (_e) { /* keep as string */ }
      }
      // normalize to string
      const geojsonText = (typeof geojsonRaw === "string") ? geojsonRaw : JSON.stringify(geojsonRaw || {});
      const upd = await db(env).prepare(
        "UPDATE rotas SET nome=?2, geojson=?3, updated_at=?4 WHERE rota_id=?1 AND projeto_id=?5"
      ).bind(rota_id, nome, geojsonText, new Date().toISOString(), pid_r).run();

      if (!upd || !upd.meta || upd.meta.changes === 0) {
        await db(env).prepare(
          "INSERT INTO rotas (rota_id, projeto_id, nome, geojson, updated_at) VALUES (?1,?2,?3,?4,?5)"
        ).bind(rota_id, pid_r, nome, geojsonText, new Date().toISOString()).run();
      }
    }

    await safeLog(env, {
      ts: new Date().toISOString(),
      user: auth.user,
      role: auth.role,
      action: `${action}_ROTA`,
      entity: "ROTA",
      entity_id: rota_id,
      details: JSON.stringify({ rota_id, nome })
    });

    return json({ ok: true });
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
    const auth = await requireViewer(request, env);
    await ensureSchema(env);
    const pid  = auth.projeto_id || "default";
    const rows = await db(env).prepare(
      "SELECT * FROM ctos WHERE projeto_id=?1 ORDER BY cto_id"
    ).bind(pid).all();

    const items = (rows?.results || []).map(r => {
      const cto_id = s(r.cto_id || r.CTO_ID || r.id || r.ID || r.codigo || r.code);
      const nome = s(r.nome || r.NOME || r.name);
      const rua = s(r.rua || r.RUA);
      const bairro = s(r.bairro || r.BAIRRO);
      const capacidade = intOrNull(r.capacidade ?? r.CAPACIDADE);
      const lat = num(r.lat ?? r.LAT ?? r.latitude ?? r.Latitude);
      const lng = num(r.lng ?? r.LNG ?? r.longitude ?? r.Longitude);
      return {
        CTO_ID: cto_id,
        cto_id,
        NOME: nome,
        nome,
        RUA: rua,
        rua,
        BAIRRO: bairro,
        bairro,
        CAPACIDADE: capacidade,
        capacidade,
        LAT: lat,
        LNG: lng,
        lat,
        lng,
        updated_at: s(r.updated_at || r.updatedAt || r.atualizado_em || r.ts),
        created_at: s(r.created_at || r.createdAt)
      };
    }).filter(x => finite(x.lat) && finite(x.lng));

    // If some rows lack id, synthesize stable ids from rowid
    for (let i=0;i<items.length;i++){
      if (!items[i].cto_id){
        const row = (rows?.results || [])[i];
        const rid = row && (row.rowid || row.ROWID);
        const sid = rid ? `CTO-${rid}` : `CTO-${i+1}`;
        items[i].cto_id = sid;
        items[i].CTO_ID = sid;
      }
    }

    return json({ ok: true, items, data: items }, 200, { cacheSeconds: 5 });
  } catch (e) {
    const msg = String(e?.message || e);
    if (msg.includes("no such table") || msg.includes("no such column")) {
      return json({ ok: false, error: "d1_schema_missing", message: msg }, 500);
    }
    return json({ ok: false, error: "ctos_failed", message: msg }, 500);
  }
}

async function handleGetCaixas(request, env) {
  try {
    const auth = await requireViewer(request, env);
    // ensureSchema defensivo — nunca lança exceção para o caller
    try { await ensureSchema(env); } catch (_se) { console.error("ensureSchema:", _se); }

    const pid = auth.projeto_id || "default";

    // Tenta query completa; se falhar por coluna missing, tenta sem WHERE projeto_id
    let results = [];
    try {
      const rows = await db(env).prepare(
        "SELECT * FROM caixas_emenda_cdo WHERE projeto_id=?1 ORDER BY id"
      ).bind(pid).all();
      results = rows?.results || [];
    } catch (e1) {
      const m1 = String(e1?.message || e1);
      if (m1.includes("no such column") || m1.includes("no such table")) {
        // Tabela existe mas sem projeto_id: tentar sem filtro
        try {
          const rows2 = await db(env).prepare(
            "SELECT * FROM caixas_emenda_cdo ORDER BY id LIMIT 500"
          ).all();
          results = rows2?.results || [];
        } catch (_e2) { results = []; }
      } else {
        throw e1;
      }
    }

    const items = results.map(r => {
      const id      = s(r.id || r.caixa_id || r.ID || r.codigo || r.code);
      const tipo    = s(r.tipo || r.TIPO || r.type || "CE");
      const obs     = s(r.obs || r.OBS || r.observacao || "");
      const img_url = s(r.img_url || r.IMG_URL || r.foto || "");
      const lat     = num(r.lat ?? r.latitude ?? r.LAT ?? r.Latitude);
      const lng     = num(r.lng ?? r.longitude ?? r.LNG ?? r.Longitude);
      const olt_id  = s(r.olt_id || "");
      const porta_olt = r.porta_olt != null ? Number(r.porta_olt) : null;
      return {
        ID: id, id,
        TIPO: tipo, tipo,
        OBS: obs, obs,
        IMG_URL: img_url, img_url,
        LAT: lat, LNG: lng, lat, lng,
        olt_id, porta_olt,
        updated_at: s(r.updated_at || "")
      };
    }).filter(x => x.id && finite(x.lat) && finite(x.lng));

    return json({ ok: true, items, data: items }, 200, { cacheSeconds: 5 });
  } catch (e) {
    console.error("handleGetCaixas:", e);
    // Retorna lista vazia em vez de 500 para não travar o mapa
    return json({ ok: true, items: [], data: [], _warn: String(e?.message || e) }, 200);
  }
}

async function handleGetRotas(request, env) {
  try {
    const auth = await requireViewer(request, env);
    await ensureSchema(env);

    const url = new URL(request.url);
    const rotaIdFilter = s(url.searchParams.get("rota_id") || url.searchParams.get("id") || "").trim();
    const pid  = auth.projeto_id || "default";
    // Schema-flexible read
    const rows = await db(env).prepare("SELECT * FROM rotas WHERE projeto_id=?1").bind(pid).all();

    const items = [];
    const features = [];

    const pick = (r, keys) => {
      for (const k of keys) {
        if (r && Object.prototype.hasOwnProperty.call(r, k) && r[k] !== undefined && r[k] !== null) return r[k];
      }
      return undefined;
    };

    for (const r of (rows?.results || [])) {
      const rota_id = s(pick(r, ["rota_id","ROTA_ID","id","ID","codigo","CODE"]));
      if (rotaIdFilter && rota_id !== rotaIdFilter) continue;

      const nome = s(pick(r, ["nome","NOME","name"]));
      const updated_at = s(pick(r, ["updated_at","UPDATED_AT","updatedAt","atualizado_em","ts"]));

      items.push({ rota_id, nome, updated_at });

      const raw = pick(r, ["geojson","GEOJSON","data","DATA","geom","GEOM","geometry","GEOMETRY","json","JSON"]);
      if (!raw) continue;

      let gj = null;
      try {
        gj = (typeof raw === "string") ? JSON.parse(raw) : raw;
      } catch (_e) { continue; }

      const attachProps = (f) => {
        if (!f || f.type !== "Feature") return null;
        const p = (f.properties && typeof f.properties === "object") ? f.properties : {};
        return { ...f, properties: { ...p, rota_id, nome } };
      };

      if (gj.type === "FeatureCollection" && Array.isArray(gj.features)) {
        for (const f of gj.features) {
          const ff = attachProps(f);
          if (ff) features.push(ff);
        }
      } else if (gj.type === "Feature") {
        const ff = attachProps(gj);
        if (ff) features.push(ff);
      } else if (gj.type === "LineString") {
        // If stored as bare geometry
        features.push(attachProps({ type:"Feature", properties:{}, geometry: gj }));
      }
    }

    const geojson = { type: "FeatureCollection", features };
    return json({ ok: true, geojson, items, data: geojson }, 200, { cacheSeconds: 5 });
  } catch (e) {
    const msg = String(e?.message || e);
    return json({ ok: false, error: "rotas_failed", message: msg }, 500);
  }
}

async function handleGetMovimentacoes(request, env) {
  try {
    const auth = await requireViewer(request, env);
    await ensureSchema(env);

    const url    = new URL(request.url);
    const ctoId  = s(url.searchParams.get("cto_id") || "");
    const limit  = Math.min(Number(url.searchParams.get("limit") || 2000), 5000);

    const pid_mov = auth.projeto_id || "default";
    const d1Res = await db(env).prepare(
      ctoId
        ? "SELECT * FROM movimentacoes_d1 WHERE projeto_id=?1 AND CTO_ID=?2 ORDER BY id DESC LIMIT ?3"
        : "SELECT * FROM movimentacoes_d1 WHERE projeto_id=?1 ORDER BY id DESC LIMIT ?2"
    ).bind(...(ctoId ? [pid_mov, ctoId, limit] : [pid_mov, limit])).all();

    const d1Items = (d1Res?.results || []);

    // Se D1 vazio, tenta CSV legado para não quebrar instalações antigas
    let items = [];
    if (d1Items.length === 0) {
      try {
        const csvUrl = getCsvUrl(env, "MOV");
        if (csvUrl) {
          const rows = await fetchCSV(csvUrl);
          items = rows.map(r => ({
            id:        null,
            DATA:      s(r.DATA || r.data),
            CTO_ID:    s(r.CTO_ID || r.cto_id),
            Tipo:      s(r.Tipo ?? r.TIPO ?? r.tipo),
            Cliente:   s(r.Cliente ?? r.CLIENTE ?? r.cliente),
            Usuario:   s(r.Usuario ?? r.USUARIO ?? r.usuario),
            Observacao:s(r.Observacao ?? r.OBSERVACAO ?? r.observacao),
            _source:   "csv_legado"
          }));
        }
      } catch (_) { /* CSV não disponível — OK */ }
    } else {
      // Ordena do mais antigo para o mais novo (frontend espera ordem cronológica)
      items = d1Items.reverse().map(r => ({
        id:        r.id,
        DATA:      s(r.DATA),
        CTO_ID:    s(r.CTO_ID),
        Tipo:      s(r.Tipo),
        Cliente:   s(r.Cliente),
        Usuario:   s(r.Usuario),
        Observacao:s(r.Observacao),
        _source:   "d1"
      }));
    }

    return json({ ok: true, items, data: items, total: items.length }, 200, { cacheSeconds: 10 });
  } catch (e) {
    return json({ ok: false, error: "mov_failed", message: String(e?.message || e) }, 500);
  }
}

// GET /api/movimentacoes/export — exporta CSV para backup/migração
async function handleExportMovimentacoes(request, env) {
  try {
    await requireRole(request, env, ["admin"]);
    await ensureSchema(env);

    const rows = await db(env).prepare(
      "SELECT * FROM movimentacoes_d1 ORDER BY id ASC"
    ).all();
    const results = rows?.results || [];

    const header = "id,DATA,CTO_ID,Tipo,Cliente,Usuario,Observacao,created_at";
    const lines = results.map(r => [
      r.id, csvEsc(r.DATA), csvEsc(r.CTO_ID), csvEsc(r.Tipo),
      csvEsc(r.Cliente), csvEsc(r.Usuario), csvEsc(r.Observacao), csvEsc(r.created_at)
    ].join(","));

    const csv = [header, ...lines].join("\r\n");
    return new Response(csv, {
      headers: {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": `attachment; filename="movimentacoes_${new Date().toISOString().slice(0,10)}.csv"`,
        "Access-Control-Allow-Origin": "*"
      }
    });
  } catch (e) {
    if (e.code === "forbidden")    return json({ error: "forbidden" }, 403);
    if (e.code === "unauthorized") return json({ error: "unauthorized" }, 401);
    return json({ error: String(e?.message || e) }, 500);
  }
}
function csvEsc(v) {
  const s2 = String(v ?? "");
  return s2.includes(",") || s2.includes('"') || s2.includes("\n")
    ? '"' + s2.replace(/"/g, '""') + '"'
    : s2;
}

// POST /api/movimentacoes/import — importa CSV legado em lote (admin)
async function handleImportMovimentacoes(request, env) {
  try {
    await requireRole(request, env, ["admin"]);
    await ensureSchema(env);
    const body = await readJson(request);
    // Aceita { items: [{DATA, CTO_ID, Tipo, Cliente, Usuario, Observacao}, ...] }
    const items = Array.isArray(body?.items) ? body.items : [];
    if (!items.length) return json({ error: "items_empty" }, 400);
    if (items.length > 50000) return json({ error: "too_many_items", max: 50000 }, 400);

    let inserted = 0;
    let skipped  = 0;
    // Insere em lotes de 100 para não estourar limites do D1
    for (let i = 0; i < items.length; i += 100) {
      const batch = items.slice(i, i + 100);
      const stmt = db(env).prepare(
        "INSERT INTO movimentacoes_d1 (projeto_id,DATA,CTO_ID,Tipo,Cliente,Usuario,Observacao,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)"
      );
      await db(env).batch(batch.map(r => {
        const cto   = s(r.CTO_ID || r.cto_id || "");
        const tipo  = s(r.Tipo   || r.tipo   || "");
        const cli   = s(r.Cliente || r.cliente || "");
        if (!cto || !tipo || !cli) { skipped++; return stmt.bind("","","","","","",""); }
        inserted++;
        const pid_imp = auth.projeto_id || "default";
        return stmt.bind(
          pid_imp,
          s(r.DATA || r.data || new Date().toISOString()),
          cto, tipo, cli,
          s(r.Usuario || r.usuario || ""),
          s(r.Observacao || r.observacao || ""),
          s(r.DATA || r.data || new Date().toISOString())
        );
      }).filter((_, idx) => {
        const r = batch[idx];
        return !!(s(r.CTO_ID||r.cto_id||"") && s(r.Tipo||r.tipo||"") && s(r.Cliente||r.cliente||""));
      }));
    }

    return json({ ok: true, inserted, skipped, total: items.length });
  } catch (e) {
    if (e.code === "forbidden")    return json({ error: "forbidden" }, 403);
    if (e.code === "unauthorized") return json({ error: "unauthorized" }, 401);
    return json({ error: String(e?.message || e) }, 500);
  }
}

// POST /api/movimentacoes — insere movimentação manual no D1
async function handleAddMovimentacao(request, env) {
  try {
    await requireRole(request, env, ["admin"]);
    await ensureSchema(env);
    const body    = await readJson(request);
    const cto_id  = s(body?.CTO_ID  || body?.cto_id  || "");
    const tipo    = s(body?.Tipo     || body?.tipo     || "");
    const cliente = s(body?.Cliente  || body?.cliente  || "");
    const usuario = s(body?.Usuario  || body?.usuario  || "");
    const obs     = s(body?.Observacao || body?.observacao || "");
    if (!cto_id || !tipo || !cliente) return json({ error: "missing_fields" }, 400);
    const now     = new Date().toISOString();
    const pid_add = auth.projeto_id || "default";
    await db(env).prepare(
      "INSERT INTO movimentacoes_d1 (projeto_id,DATA,CTO_ID,Tipo,Cliente,Usuario,Observacao,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?2)"
    ).bind(pid_add, now, cto_id, tipo, cliente, usuario, obs).run();
    return json({ ok: true, action: "inserted" });
  } catch (e) {
    if (e.code === "forbidden")    return json({ error: "forbidden" }, 403);
    if (e.code === "unauthorized") return json({ error: "unauthorized" }, 401);
    return json({ error: String(e?.message || e) }, 500);
  }
}

// POST /api/movimentacoes/remove-cliente — desativa cliente (insere DESATIVACAO no D1)
async function handleRemoveCliente(request, env) {
  try {
    await requireRole(request, env, ["admin"]);
    await ensureSchema(env);
    const body    = await readJson(request);
    const cto_id  = s(body?.cto_id  || body?.CTO_ID  || "");
    const cliente = s(body?.cliente  || body?.Cliente  || "");
    const usuario = s(body?.usuario  || body?.Usuario  || "");
    if (!cto_id || !cliente) return json({ error: "missing_fields: cto_id, cliente" }, 400);
    const now     = new Date().toISOString();
    const pid_rem = auth.projeto_id || "default";
    await db(env).prepare(
      "INSERT INTO movimentacoes_d1 (projeto_id,DATA,CTO_ID,Tipo,Cliente,Usuario,Observacao,created_at) VALUES (?1,?2,?3,'DESATIVACAO',?4,?5,'Removido pelo admin',?2)"
    ).bind(pid_rem, now, cto_id, cliente, usuario).run();
    return json({ ok: true, action: "removed", cto_id, cliente });
  } catch (e) {
    if (e.code === "forbidden")    return json({ error: "forbidden" }, 403);
    if (e.code === "unauthorized") return json({ error: "unauthorized" }, 401);
    return json({ error: String(e?.message || e) }, 500);
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
