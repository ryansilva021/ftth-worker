/**
 * FTTH Worker - Step 3 (LOGIN D1)
 * - Keeps read endpoints (CSV) exactly as before
 * - Adds POST /api/login (D1 users) -> Bearer token
 * - Adds POST /api/logout (revoke session)
 * - POST /api/submit now requires Authorization: Bearer <token>
 * - Worker forwards to Apps Script with { key: SUBMIT_KEY, user: <auth.user>, items: [...] }
 * - CORS allowlist for submit and auth endpoints (Pages + localhost). Read endpoints remain open (*).
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
    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(request, { submitOnly: url.pathname === "/api/submit" }) });
    }

    if (url.pathname === "/api" || url.pathname === "/api/") {
      return json(
        request,
        {
          ok: true,
          endpoints: [
            "/api/ctos",
            "/api/usuarios",
            "/api/log_eventos",
            "/api/caixas_emenda_cdo",
            "/api/rotas_fibras",
            "/api/movimentacoes",
            "POST /api/login",
            "POST /api/logout",
            "POST /api/submit",
          ],
          security: {
            submit: {
              requiresHeader: "authorization: Bearer <token>",
              originAllowlist: Array.from(ALLOWED_ORIGINS),
            },
          },
        },
        200
      );
    }

    try {
            // ---- AUTH ----
      if (url.pathname === "/api/login") {
        if (request.method !== "POST") return json(request, { error: "method_not_allowed" }, 405);

        const origin = request.headers.get("origin") || "";
        if (origin && !ALLOWED_ORIGINS.has(origin)) {
          return json(request, { error: "origin_not_allowed", origin }, 403);
        }

        if (!env.DB) return json(request, { error: "DB_not_configured" }, 500);
        const body = await request.json().catch(() => null);
        if (!body) return json(request, { error: "invalid_json" }, 400);

        const user = String(body.user || "").trim();
        const password = String(body.password || "").trim();
        if (!user || !password) return json(request, { error: "missing_user_password" }, 400);

        const row = await env.DB
          .prepare("SELECT username, password_hash FROM users WHERE username = ?1 AND is_active = 1")
          .bind(user)
          .first();

        if (!row) return json(request, { error: "invalid_credentials" }, 401);

        const ok = await verifyPassword(password, row.password_hash, env.PASSWORD_PEPPER || "");
        if (!ok) return json(request, { error: "invalid_credentials" }, 401);

        const token = await mintSession(env, user);
        return json(request, { ok: true, token }, 200);
      }

      if (url.pathname === "/api/logout") {
        if (request.method !== "POST") return json(request, { error: "method_not_allowed" }, 405);

        const origin = request.headers.get("origin") || "";
        if (origin && !ALLOWED_ORIGINS.has(origin)) {
          return json(request, { error: "origin_not_allowed", origin }, 403);
        }

        if (!env.DB) return json(request, { error: "DB_not_configured" }, 500);

        const auth = await requireAuth(request, env);
        await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?1").bind(auth.tokenHash).run();
        return json(request, { ok: true }, 200);
      }

// ---- SUBMIT (WRITE) ----
      if (url.pathname === "/api/submit") {
        if (request.method !== "POST") return json(request, { error: "method_not_allowed" }, 405);

        const origin = request.headers.get("origin") || "";
        if (origin && !ALLOWED_ORIGINS.has(origin)) {
          return json(request, { error: "origin_not_allowed", origin }, 403);
        }

        // Auth (Bearer token)
        if (!env.DB) return json(request, { error: "DB_not_configured" }, 500);
        const auth = await requireAuth(request, env);

        // Worker -> Apps Script key (server-side secret)
        if (!env.SUBMIT_KEY) return json(request, { error: "SUBMIT_KEY_not_configured" }, 500);
        if (!env.APPS_SCRIPT_URL) return json(request, { error: "APPS_SCRIPT_URL_not_configured" }, 500);

        const body = await request.json().catch(() => null);
        if (!body) return json(request, { error: "invalid_json" }, 400);

        const items = Array.isArray(body.items) ? body.items : [body];

        const forward = await fetch(env.APPS_SCRIPT_URL, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ key: env.SUBMIT_KEY, user: auth.user, items }),
        });

        const text = await forward.text();
        return new Response(text, {
          status: forward.status,
          headers: {
            ...corsHeaders(request, { submitOnly: true }),
            "content-type": forward.headers.get("content-type") || "text/plain; charset=utf-8",
          },
        });
      }

      // ---- READ endpoints ----// ---- READ endpoints ----
      if (url.pathname === "/api/ctos") {
        const rows = await fetchCSV(env.SHEETS_CTOS_CSV_URL);
        const items = rows
          .map((r) => ({
            cto_id: s(r.CTO_ID),
            lat: num(r.LAT),
            lng: num(r.LNG),
            capacidade: intOrNull(r.CAPACIDADE),
            bairro: s(r.BAIRRO),
            rua: s(r.RUA),
          }))
          .filter((x) => x.cto_id && finite(x.lat) && finite(x.lng));
        return json(request, items, 200, { cacheSeconds: 60 });
      }

      if (url.pathname === "/api/usuarios") {
        const rows = await fetchCSV(env.SHEETS_USUARIOS_CSV_URL);
        const items = rows
          .map((r) => ({
            user: s(r.USER),
            role: s(r.ROLE),
            active: bool(r.ACTIVE),
            created_at: s(r.CREATED_AT),
            must_change: bool(r.MUST_CHANGE),
            updated_at: s(r.UPDATED_AT),
            last_login: s(r.LAST_LOGIN),
          }))
          .filter((x) => x.user);
        return json(request, items, 200, { cacheSeconds: 30 });
      }

      if (url.pathname === "/api/log_eventos") {
        const rows = await fetchCSV(env.SHEETS_LOG_EVENTOS_CSV_URL);
        const since = url.searchParams.get("since");
        const sinceMs = since ? Date.parse(since) : null;

        const items = rows
          .map((r) => ({
            ts: s(r.TS),
            user: s(r.USER),
            role: s(r.ROLE),
            action: s(r.ACTION),
            entity: s(r.ENTITY),
            entity_id: s(r.ENTITY_ID),
            details: s(r.DETAILS),
          }))
          .filter((x) => x.ts);

        const filtered =
          sinceMs && Number.isFinite(sinceMs)
            ? items.filter((x) => {
                const t = Date.parse(x.ts);
                return Number.isFinite(t) ? t >= sinceMs : true;
              })
            : items;

        return json(request, filtered, 200, { cacheSeconds: 15 });
      }

      if (url.pathname === "/api/caixas_emenda_cdo") {
        const rows = await fetchCSV(env.SHEETS_CAIXAS_EMENDA_CDO_CSV_URL);
        const items = rows
          .map((r) => ({
            id: s(r.ID),
            tipo: s(r.TIPO),
            lat: num(r.LAT),
            lng: num(r.LNG),
            obs: s(r.OBS),
            img_url: s(r.IMG_URL),
            dt_criacao: s(r.DT_CRIACAO),
            dt_atualizacao: s(r.DT_ATUALIZACAO),
          }))
          .filter((x) => x.id && finite(x.lat) && finite(x.lng));
        return json(request, items, 200, { cacheSeconds: 60 });
      }

      if (url.pathname === "/api/rotas_fibras") {
        const rows = await fetchCSV(env.SHEETS_ROTAS_FIBRAS_CSV_URL);
        const points = rows
          .map((r) => ({
            rota_id: s(r.ROTA_ID),
            ordem: intOrNull(r.ORDEM),
            lat: num(r.LAT),
            lng: num(r.LNG),
            tipo: s(r.TIPO),
            peso: numOrNull(r.PESO),
          }))
          .filter((p) => p.rota_id && finite(p.lat) && finite(p.lng) && p.ordem !== null);

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
        return json(request, { type: "FeatureCollection", features }, 200, { cacheSeconds: 60 });
      }

      if (url.pathname === "/api/movimentacoes") {
        const rows = await fetchCSV(env.SHEETS_MOVIMENTACOES_CSV_URL);
        const items = rows
          .map((r) => ({
            data: s(r.DATA),
            cto_id: s(r.CTO_ID),
            tipo: s(r.Tipo ?? r.TIPO),
            cliente: s(r.Cliente ?? r.CLIENTE),
            usuario: s(r.Usuario ?? r.USUARIO),
            observacao: s(r.Observacao ?? r.OBSERVACAO),
          }))
          .filter((x) => x.data || x.cto_id);
        return json(request, items, 200, { cacheSeconds: 30 });
      }

      return json(request, { error: "not_found" }, 404);
    } catch (e) {
      return json(request, { error: "internal_error", message: String(e?.message ?? e) }, 500);
    }

    function corsHeaders(request, { submitOnly } = { submitOnly: false }) {
      const origin = request.headers.get("origin") || "";
      const allowOrigin = submitOnly ? (ALLOWED_ORIGINS.has(origin) ? origin : "") : "*";

      const h = {
        "access-control-allow-methods": "GET,POST,OPTIONS",
        "access-control-allow-headers": "content-type,authorization",
      };
      if (allowOrigin) h["access-control-allow-origin"] = allowOrigin;
      else if (!submitOnly) h["access-control-allow-origin"] = "*";
      return h;
    }

    function json(request, obj, status = 200, opts = {}) {
      const headers = {
        ...corsHeaders(request, { submitOnly: request && new URL(request.url).pathname === "/api/submit" }),
        "content-type": "application/json; charset=utf-8",
      };
      if (opts.cacheSeconds != null) headers["cache-control"] = `public, max-age=${opts.cacheSeconds}`;
      return new Response(JSON.stringify(obj), { status, headers });
    }

    async function fetchCSV(csvUrl) {
      if (!csvUrl) throw new Error("CSV URL não configurada (env.*_CSV_URL).");
      const res = await fetch(csvUrl, { cf: { cacheTtl: 60, cacheEverything: true }, headers: { "user-agent": "ftth-pwa-worker" } });
      if (!res.ok) throw new Error(`Falha ao ler CSV (${res.status}).`);
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

    function s(v) { return (v ?? "").toString().trim(); }
    function num(v) { const t = s(v).replace(",", "."); return Number(t); }
    function numOrNull(v) { const n = num(v); return Number.isFinite(n) ? n : null; }
    function intOrNull(v) { const t = s(v); if (!t) return null; const n = Number(t); return Number.isFinite(n) ? Math.trunc(n) : null; }
    function bool(v) { const t = s(v).toLowerCase(); return t === "1" || t === "true" || t === "sim" || t === "yes" || t === "y"; }
    function finite(n) { return Number.isFinite(n); }
    function uniq(arr) { return Array.from(new Set(arr)); }
    function avg(arr) { return arr.reduce((a, b) => a + b, 0) / arr.length; }
    // ===== AUTH HELPERS (D1) =====
    async function requireAuth(request, env) {
      const h = request.headers.get("authorization") || "";
      const m = h.match(/^Bearer\s+(.+)$/i);
      if (!m) throw new Error("missing_authorization");
      const token = m[1].trim();
      const tokenHash = await sha256Hex(token);

      const row = await env.DB
        .prepare("SELECT username, expires_at FROM sessions WHERE token_hash = ?1")
        .bind(tokenHash)
        .first();

      if (!row) throw new Error("invalid_token");
      if (row.expires_at) {
        const exp = Date.parse(row.expires_at);
        if (Number.isFinite(exp) && exp < Date.now()) {
          await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?1").bind(tokenHash).run();
          throw new Error("token_expired");
        }
      }
      return { user: row.username, tokenHash };
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

    function base64Url(bytes) {
      let bin = "";
      for (const b of bytes) bin += String.fromCharCode(b);
      return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }

    async function sha256Hex(s) {
      const data = new TextEncoder().encode(s);
      const digest = await crypto.subtle.digest("SHA-256", data);
      return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
    }

    // Password hashing:
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
      const bits = await crypto.subtle.deriveBits(
        { name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations: iters },
        keyMaterial,
        keyLen * 8
      );
      return bits;
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

  },
};
