// FTTH Worker mínimo (D1 CTOs + senha admin)
//
// Requisitos no Cloudflare (Settings):
// - D1 binding: DB  -> seu banco "ftth-db"
// - Secret/Env: ADMIN_PASSWORD
//
// Endpoints:
//   GET    /api/ctos
//   POST   /api/ctos            (admin)
//   DELETE /api/ctos?id=CTO123  (admin)
//   GET    /api                (health)

const ALLOWED_ORIGINS = new Set([
  "https://ftth-pwa.pages.dev",
  "http://localhost:3000",
  "http://localhost:5173",
]);

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    if (url.pathname === "/api" || url.pathname === "/api/") {
      return json(request, { ok: true, service: "ftth-d1", endpoints: ["/api/ctos"] }, 200);
    }

    if (url.pathname === "/api/ctos") {
      // --- READ ---
      if (request.method === "GET") {
        if (!env.DB) return json(request, { error: "DB_not_configured" }, 500);

        const rs = await env.DB
          .prepare("SELECT CTO_ID, NOME, RUA, BAIRRO, LAT, LNG, CAPACIDADE, created_at, updated_at FROM ctos")
          .all();

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
        })).filter(x => x.cto_id && Number.isFinite(x.lat) && Number.isFinite(x.lng));

        return json(request, items, 200, { cacheSeconds: 0 });
      }

      // --- WRITE ---
      if (request.method === "POST") {
        // CORS origin check (write)
        const origin = request.headers.get("origin") || "";
        if (origin && !ALLOWED_ORIGINS.has(origin)) return json(request, { error: "origin_not_allowed", origin }, 403);

        requireAdmin(request, env);
        if (!env.DB) return json(request, { error: "DB_not_configured" }, 500);

        const body = await request.json().catch(() => null);
        if (!body) return json(request, { error: "invalid_json" }, 400);

        const CTO_ID = s(body.CTO_ID ?? body.cto_id ?? body.id);
        const NOME = s(body.NOME ?? body.nome ?? CTO_ID);
        const RUA = s(body.RUA ?? body.rua);
        const BAIRRO = s(body.BAIRRO ?? body.bairro);
        const LAT = num(body.LAT ?? body.lat);
        const LNG = num(body.LNG ?? body.lng);
        const CAPACIDADE = intOrZero(body.CAPACIDADE ?? body.capacidade);

        if (!CTO_ID) return json(request, { error: "missing_CTO_ID" }, 400);
        if (!Number.isFinite(LAT) || !Number.isFinite(LNG)) return json(request, { error: "missing_lat_lng" }, 400);

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

        return json(request, { ok: true, cto: { cto_id: CTO_ID, nome: NOME, rua: RUA, bairro: BAIRRO, lat: LAT, lng: LNG, capacidade: CAPACIDADE } }, 200);
      }

      if (request.method === "DELETE") {
        const origin = request.headers.get("origin") || "";
        if (origin && !ALLOWED_ORIGINS.has(origin)) return json(request, { error: "origin_not_allowed", origin }, 403);

        requireAdmin(request, env);
        if (!env.DB) return json(request, { error: "DB_not_configured" }, 500);

        const id = String(url.searchParams.get("id") || "").trim();
        if (!id) return json(request, { error: "missing_id" }, 400);

        await env.DB.prepare("DELETE FROM ctos WHERE CTO_ID = ?1").bind(id).run();
        return json(request, { ok: true, deleted: id }, 200);
      }

      return json(request, { error: "method_not_allowed" }, 405);
    }

    return json(request, { error: "not_found" }, 404);
  },
};

// ---------- helpers ----------
function corsHeaders(request) {
  const origin = request.headers.get("origin") || "";
  const allow = ALLOWED_ORIGINS.has(origin) ? origin : "*";
  return {
    "access-control-allow-origin": allow,
    "access-control-allow-methods": "GET,POST,DELETE,OPTIONS",
    "access-control-allow-headers": "content-type,x-admin-password",
  };
}

function json(request, obj, status = 200, opts = {}) {
  const headers = { ...corsHeaders(request), "content-type": "application/json; charset=utf-8" };
  if (opts.cacheSeconds != null) headers["cache-control"] = `public, max-age=${opts.cacheSeconds}`;
  return new Response(JSON.stringify(obj), { status, headers });
}

function requireAdmin(request, env) {
  const expected = String(env.ADMIN_PASSWORD || "").trim();
  if (!expected) throw new Error("ADMIN_PASSWORD_not_configured");
  const got = String(request.headers.get("x-admin-password") || "").trim();
  if (!got) throw new Error("missing_admin_password");
  if (got !== expected) throw new Error("invalid_admin_password");
}

function s(v) { return (v ?? "").toString().trim(); }
function num(v) { const t = s(v).replace(",", "."); return Number(t); }
function intOrZero(v) { const n = Number(String(v ?? "").trim()); return Number.isFinite(n) ? Math.trunc(n) : 0; }
