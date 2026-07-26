// Single catch-all API handler for /api/*.
// The server stores ciphertext only: no name, personal number, or phone ever
// arrives here in plaintext. See PLAN.md §4 and §6 for the contract.

const SESSION_MS = 60 * 60 * 1000;        // 1 hour, refreshed on each authed request
const LOGIN_LIMIT = 8;                    // login attempts per IP...
const LOGIN_WINDOW_MS = 10 * 60 * 1000;   // ...per 10-minute lockout window
const SUB_LIMIT = 40;                     // submissions per IP...
const SUB_WINDOW_MS = 60 * 60 * 1000;     // ...per hour

const HEX32 = /^[0-9a-f]{32}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const B64RE = /^[A-Za-z0-9+/]+={0,2}$/;

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...headers,
    },
  });

const err = (status, message) => json({ error: message }, status);

const isB64 = (s, max) =>
  typeof s === 'string' && s.length > 0 && s.length <= max && s.length % 4 === 0 && B64RE.test(s);

const isHex = (s, re) => typeof s === 'string' && re.test(s);

// Constant-time string comparison for the verifier.
function tsEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function readBody(request) {
  try {
    const body = await request.json();
    return body && typeof body === 'object' && !Array.isArray(body) ? body : null;
  } catch {
    return null;
  }
}

// Fixed-window rate limit backed by the throttle table. Returns false when the
// caller has exhausted its budget for the current window.
async function allow(db, key, limit, windowMs, now) {
  const row = await db.prepare('SELECT hits, until FROM throttle WHERE k = ?1').bind(key).first();
  if (!row || row.until <= now) {
    await db
      .prepare(
        'INSERT INTO throttle (k, hits, until) VALUES (?1, 1, ?2) ' +
          'ON CONFLICT(k) DO UPDATE SET hits = 1, until = ?2'
      )
      .bind(key, now + windowMs)
      .run();
    return true;
  }
  if (row.hits >= limit) return false;
  await db.prepare('UPDATE throttle SET hits = hits + 1 WHERE k = ?1').bind(key).run();
  return true;
}

const getConfig = (db) => db.prepare('SELECT * FROM config WHERE id = 1').first();

async function getSession(db, request, now) {
  const cookie = request.headers.get('Cookie') || '';
  const m = cookie.match(/(?:^|;\s*)sid=([0-9a-f]{64})(?:;|$)/);
  if (!m) return null;
  const row = await db
    .prepare('SELECT token, expires FROM sessions WHERE token = ?1')
    .bind(m[1])
    .first();
  if (!row || row.expires <= now) return null;
  await db
    .prepare('UPDATE sessions SET expires = ?1 WHERE token = ?2')
    .bind(now + SESSION_MS, row.token)
    .run();
  return row.token;
}

const sessionCookie = (token) =>
  `sid=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_MS / 1000}`;

const clearedCookie = () => 'sid=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0';

export async function onRequest(context) {
  const { request, env } = context;
  const db = env.DB;
  const url = new URL(request.url);
  const method = request.method;
  const seg = Array.isArray(context.params.path)
    ? context.params.path
    : context.params.path
      ? [context.params.path]
      : [];
  const now = Date.now();
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

  // Cross-origin writes are rejected outright (CSRF backstop behind SameSite=Strict).
  if (method !== 'GET') {
    const origin = request.headers.get('Origin');
    if (origin) {
      let host = null;
      try {
        host = new URL(origin).host;
      } catch {
        // fall through with host = null → rejected below
      }
      if (host !== url.host) return err(403, 'מקור הבקשה נדחה');
    }
  }

  try {
    // ── GET /api/config ──────────────────────────────────────────────
    if (seg[0] === 'config' && seg.length === 1 && method === 'GET') {
      const cfg = await getConfig(db);
      if (!cfg) return json({ ready: false });
      return json({ ready: true, pub: JSON.parse(cfg.pub), idSalt: cfg.id_salt });
    }

    // ── POST /api/setup ──────────────────────────────────────────────
    if (seg[0] === 'setup' && seg.length === 1 && method === 'POST') {
      if (env.SETUP_TOKEN && request.headers.get('X-Setup-Token') !== env.SETUP_TOKEN) {
        return err(403, 'טוקן הקמה שגוי');
      }
      const existing = await getConfig(db);
      if (existing) return err(409, 'המערכת כבר הוגדרה');
      const b = await readBody(request);
      if (!b) return err(400, 'בקשה לא תקינה');
      const { pub, salt, idSalt, verifier, keyIv, wrappedKey } = b;
      let pubOk = false;
      try {
        const jwk = JSON.parse(pub);
        pubOk =
          typeof pub === 'string' && pub.length <= 2000 && jwk && jwk.kty === 'RSA' && !jwk.d;
      } catch {
        pubOk = false;
      }
      if (
        !pubOk ||
        !isB64(salt, 64) ||
        !isB64(idSalt, 64) ||
        !isHex(verifier, HEX64) ||
        !isB64(keyIv, 64) ||
        !isB64(wrappedKey, 8000)
      ) {
        return err(400, 'בקשה לא תקינה');
      }
      await db
        .prepare(
          'INSERT INTO config (id, pub, salt, id_salt, verifier, key_iv, wrapped_key, created_at) ' +
            'VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)'
        )
        .bind(pub, salt, idSalt, verifier, keyIv, wrappedKey, now)
        .run();
      return json({ ok: true });
    }

    // ── GET /api/status/:rid ─────────────────────────────────────────
    if (seg[0] === 'status' && seg.length === 2 && method === 'GET') {
      if (!isHex(seg[1], HEX32)) return err(400, 'בקשה לא תקינה');
      const row = await db
        .prepare('SELECT status FROM records WHERE rid = ?1')
        .bind(seg[1])
        .first();
      if (!row) return json({ exists: false });
      return json({ exists: true, status: row.status });
    }

    // ── POST /api/records ────────────────────────────────────────────
    if (seg[0] === 'records' && seg.length === 1 && method === 'POST') {
      if (!(await allow(db, `sub:${ip}`, SUB_LIMIT, SUB_WINDOW_MS, now))) {
        return err(429, 'יותר מדי הגשות, נסו שוב מאוחר יותר');
      }
      const b = await readBody(request);
      if (!b) return err(400, 'בקשה לא תקינה');
      const { rid, ek, iv, ct } = b;
      if (!isHex(rid, HEX32) || !isB64(ek, 1000) || !isB64(iv, 64) || !isB64(ct, 8000)) {
        return err(400, 'בקשה לא תקינה');
      }
      const existing = await db
        .prepare('SELECT status FROM records WHERE rid = ?1')
        .bind(rid)
        .first();
      if (existing && existing.status === 'approved') {
        return err(409, 'הרשומה כבר אושרה ואינה ניתנת לעדכון — פנו למנהל הציוד');
      }
      if (existing) {
        await db
          .prepare('UPDATE records SET ek = ?1, iv = ?2, ct = ?3, updated_at = ?4 WHERE rid = ?5')
          .bind(ek, iv, ct, now, rid)
          .run();
      } else {
        await db
          .prepare(
            'INSERT INTO records (rid, ek, iv, ct, status, created_at, updated_at) ' +
              "VALUES (?1, ?2, ?3, ?4, 'pending', ?5, ?5)"
          )
          .bind(rid, ek, iv, ct, now)
          .run();
      }
      return json({ ok: true });
    }

    // ── /api/admin/* ─────────────────────────────────────────────────
    if (seg[0] === 'admin') {
      // GET /api/admin/challenge
      if (seg[1] === 'challenge' && seg.length === 2 && method === 'GET') {
        const cfg = await getConfig(db);
        if (!cfg) return err(404, 'המערכת עדיין לא הוגדרה');
        return json({ salt: cfg.salt });
      }

      // POST /api/admin/login
      if (seg[1] === 'login' && seg.length === 2 && method === 'POST') {
        if (!(await allow(db, `login:${ip}`, LOGIN_LIMIT, LOGIN_WINDOW_MS, now))) {
          return err(429, 'יותר מדי ניסיונות התחברות — נעילה של 10 דקות');
        }
        const cfg = await getConfig(db);
        if (!cfg) return err(404, 'המערכת עדיין לא הוגדרה');
        const b = await readBody(request);
        if (!b || !isHex(b.verifier, HEX64)) return err(400, 'בקשה לא תקינה');
        if (!tsEqual(b.verifier, cfg.verifier)) return err(401, 'סיסמה שגויה');
        const token = randomToken();
        await db.prepare('DELETE FROM sessions WHERE expires <= ?1').bind(now).run();
        await db
          .prepare('INSERT INTO sessions (token, expires) VALUES (?1, ?2)')
          .bind(token, now + SESSION_MS)
          .run();
        return json(
          { keyIv: cfg.key_iv, wrappedKey: cfg.wrapped_key },
          200,
          { 'Set-Cookie': sessionCookie(token) }
        );
      }

      // Everything below requires a live session.
      const session = await getSession(db, request, now);
      if (!session) return err(401, 'נדרשת התחברות');

      // POST /api/admin/logout
      if (seg[1] === 'logout' && seg.length === 2 && method === 'POST') {
        await db.prepare('DELETE FROM sessions WHERE token = ?1').bind(session).run();
        return json({ ok: true }, 200, { 'Set-Cookie': clearedCookie() });
      }

      // GET | PUT /api/admin/vault — the encrypted inventory blob
      if (seg[1] === 'vault' && seg.length === 2) {
        if (method === 'GET') {
          const v = await db
            .prepare('SELECT ek, iv, ct, updated_at FROM vault WHERE id = 1')
            .first();
          return json({ vault: v || null });
        }
        if (method === 'PUT') {
          const b = await readBody(request);
          if (!b) return err(400, 'בקשה לא תקינה');
          const { ek, iv, ct } = b;
          if (!isB64(ek, 1000) || !isB64(iv, 64) || !isB64(ct, 20000)) {
            return err(400, 'בקשה לא תקינה');
          }
          await db
            .prepare(
              `INSERT INTO vault (id, ek, iv, ct, updated_at) VALUES (1, ?1, ?2, ?3, ?4)
               ON CONFLICT(id) DO UPDATE SET ek = ?1, iv = ?2, ct = ?3, updated_at = ?4`
            )
            .bind(ek, iv, ct, now)
            .run();
          return json({ ok: true });
        }
      }

      // GET /api/admin/records
      if (seg[1] === 'records' && seg.length === 2 && method === 'GET') {
        const { results } = await db
          .prepare(
            'SELECT rid, ek, iv, ct, status, created_at, updated_at FROM records ORDER BY created_at'
          )
          .all();
        return json({ records: results });
      }

      // POST /api/admin/notify
      // Sends the approval message through the WhatsApp Cloud API. The phone
      // number and item list pass through this Worker in plaintext — that is
      // unavoidable for automatic delivery, since a messaging provider must be
      // able to read what it sends. Nothing here is ever written to D1 or
      // logged; the plaintext exists only for the duration of this request.
      // Without WHATSAPP_TOKEN / WHATSAPP_PHONE_ID configured this returns
      // {sent:false, reason:'not_configured'} and the client falls back to the
      // manual send button.
      if (seg[1] === 'notify' && seg.length === 2 && method === 'POST') {
        const token = env.WHATSAPP_TOKEN;
        const phoneId = env.WHATSAPP_PHONE_ID;
        if (!token || !phoneId) return json({ sent: false, reason: 'not_configured' });

        const b = await readBody(request);
        if (!b) return err(400, 'בקשה לא תקינה');
        const to = String(b.phone || '').replace(/\D/g, '');
        const name = String(b.name || '').slice(0, 60);
        const items = String(b.items || '').slice(0, 300);
        if (to.length < 9 || to.length > 15 || !name || !items) {
          return err(400, 'בקשה לא תקינה');
        }

        const payload = {
          messaging_product: 'whatsapp',
          to,
          type: 'template',
          template: {
            name: env.WHATSAPP_TEMPLATE || 'equipment_approved',
            language: { code: env.WHATSAPP_LANG || 'he' },
            components: [
              {
                type: 'body',
                parameters: [
                  { type: 'text', text: name },
                  { type: 'text', text: items },
                ],
              },
            ],
          },
        };

        let res;
        try {
          res = await fetch(`https://graph.facebook.com/v21.0/${phoneId}/messages`, {
            method: 'POST',
            headers: {
              Authorization: `Bearer ${token}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(payload),
          });
        } catch {
          return json({ sent: false, reason: 'network' });
        }
        if (!res.ok) {
          let detail = '';
          try {
            const e = await res.json();
            detail = (e && e.error && e.error.message) || '';
          } catch {
            // provider returned a non-JSON error body
          }
          return json({ sent: false, reason: 'api', status: res.status, detail });
        }
        return json({ sent: true });
      }

      // PUT | DELETE /api/admin/records/:rid
      if (seg[1] === 'records' && seg.length === 3) {
        const rid = seg[2];
        if (!isHex(rid, HEX32)) return err(400, 'בקשה לא תקינה');

        if (method === 'PUT') {
          const b = await readBody(request);
          if (!b) return err(400, 'בקשה לא תקינה');
          const { ek, iv, ct, status } = b;
          if (
            !isB64(ek, 1000) ||
            !isB64(iv, 64) ||
            !isB64(ct, 8000) ||
            (status !== 'pending' && status !== 'approved')
          ) {
            return err(400, 'בקשה לא תקינה');
          }
          const r = await db
            .prepare(
              'UPDATE records SET ek = ?1, iv = ?2, ct = ?3, status = ?4, updated_at = ?5 WHERE rid = ?6'
            )
            .bind(ek, iv, ct, status, now, rid)
            .run();
          if (!r.meta.changes) return err(404, 'הרשומה לא נמצאה');
          return json({ ok: true });
        }

        if (method === 'DELETE') {
          const r = await db.prepare('DELETE FROM records WHERE rid = ?1').bind(rid).run();
          if (!r.meta.changes) return err(404, 'הרשומה לא נמצאה');
          return json({ ok: true });
        }
      }

      // POST /api/admin/rotate
      if (seg[1] === 'rotate' && seg.length === 2 && method === 'POST') {
        const b = await readBody(request);
        if (!b) return err(400, 'בקשה לא תקינה');
        const { salt, verifier, keyIv, wrappedKey } = b;
        if (
          !isB64(salt, 64) ||
          !isHex(verifier, HEX64) ||
          !isB64(keyIv, 64) ||
          !isB64(wrappedKey, 8000)
        ) {
          return err(400, 'בקשה לא תקינה');
        }
        await db
          .prepare(
            'UPDATE config SET salt = ?1, verifier = ?2, key_iv = ?3, wrapped_key = ?4 WHERE id = 1'
          )
          .bind(salt, verifier, keyIv, wrappedKey)
          .run();
        await db.prepare('DELETE FROM sessions').run();
        return json({ ok: true }, 200, { 'Set-Cookie': clearedCookie() });
      }

      // POST /api/admin/wipe
      if (seg[1] === 'wipe' && seg.length === 2 && method === 'POST') {
        await db.batch([
          db.prepare('DELETE FROM records'),
          db.prepare('DELETE FROM vault'),
          db.prepare('DELETE FROM sessions'),
          db.prepare('DELETE FROM throttle'),
          db.prepare('DELETE FROM config'),
        ]);
        return json({ ok: true }, 200, { 'Set-Cookie': clearedCookie() });
      }
    }

    return err(404, 'הנתיב לא נמצא');
  } catch (e) {
    return err(500, 'שגיאת שרת');
  }
}
