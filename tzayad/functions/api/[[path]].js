// Single catch-all API handler for /api/*.
// The server stores ciphertext only: no name, personal number, or phone ever
// arrives here in plaintext. See PLAN.md §4 and §6 for the contract.

const SESSION_MS = 60 * 60 * 1000;        // 1 hour, refreshed on each authed request
const LOGIN_LIMIT = 8;                    // login attempts per IP...
const LOGIN_WINDOW_MS = 10 * 60 * 1000;   // ...per 10-minute lockout window
// A whole unit signing out is typically behind ONE base-WiFi NAT address, so
// this budget is shared by ~90 soldiers submitting within minutes of each
// other. 40/hour silently locked most of them out; 400 leaves ample headroom
// while still stopping a scripted flood.
const SUB_LIMIT = 400;                    // submissions per IP...
const SUB_WINDOW_MS = 60 * 60 * 1000;     // ...per hour
const DOC_LIMIT = 120;                    // licence photos per IP per hour (heavier rows)

// ~400 KB of base64 ≈ 300 KB of JPEG. The client compresses well below this;
// the cap is a backstop so a single row can never bloat the database.
const DOC_MAX_B64 = 400000;

// The vault holds opening stock, extra items, and the two counting registers
// (צלם / צלם ארמון). ~600 KB of base64 leaves room for a few thousand rows.
const VAULT_MAX_B64 = 600000;

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
  // Single statement: start a fresh window if the old one lapsed, otherwise
  // increment. RETURNING gives us the post-increment count, so two concurrent
  // callers can never both see the same remaining budget.
  const row = await db
    .prepare(
      `INSERT INTO throttle (k, hits, until) VALUES (?1, 1, ?2)
       ON CONFLICT(k) DO UPDATE SET
         hits  = CASE WHEN throttle.until <= ?3 THEN 1 ELSE throttle.hits + 1 END,
         until = CASE WHEN throttle.until <= ?3 THEN ?2 ELSE throttle.until END
       RETURNING hits`
    )
    .bind(key, now + windowMs, now)
    .first();
  return !row || row.hits <= limit;
}

// The throttle table is write-heavy and nothing ever removed lapsed rows.
// Swept opportunistically so it cannot grow without bound.
async function sweepThrottle(db, now) {
  if (Math.random() < 0.02) {
    await db.prepare('DELETE FROM throttle WHERE until <= ?1').bind(now - 86400000).run();
  }
}

// admin  — everything, including users, audit and the trash
// editor  — may read AND change, but only on the screens granted to them
// viewer  — may read only, and only on the screens granted to them
const ROLES = ['admin', 'editor', 'viewer'];
const isRestricted = (role) => role === 'editor' || role === 'viewer';

const getConfig = (db) => db.prepare('SELECT * FROM config WHERE id = 1').first();

const TRASH_MS = 30 * 24 * 60 * 60 * 1000;   // deleted rows stay recoverable for 30 days
const TICKET_MS = 30 * 60 * 1000;         // a ticket is good for half an hour
const TICKET_LIMIT = 60;                  // tickets per IP per hour

// A submission ticket. The public key is public by design, so anyone could
// craft a valid encrypted payload; requiring a ticket means a writer must
// first fetch one, and each ticket is worth exactly one write. It is not
// identity — it is a cost, and it caps how fast a script can inject.
async function issueTicket(db, now) {
  const id = randomToken().slice(0, 32);
  await db.prepare('DELETE FROM tickets WHERE expires <= ?1').bind(now).run();
  await db
    .prepare('INSERT INTO tickets (id, expires) VALUES (?1, ?2)')
    .bind(id, now + TICKET_MS)
    .run();
  return { ticket: id, expires: now + TICKET_MS };
}

// Spends a ticket. Returns false when it is unknown, expired or already used —
// the UPDATE itself is the check, so two concurrent requests cannot both win.
async function spendTicket(db, id, now) {
  if (!isHex(id, HEX32)) return false;
  const r = await db
    .prepare('UPDATE tickets SET used_at = ?1 WHERE id = ?2 AND used_at IS NULL AND expires > ?1')
    .bind(now, id)
    .run();
  return !!(r.meta && r.meta.changes);
}

// Append-only trail of admin actions. Never records anything identifying —
// the console is encrypted and the audit log is not.
async function audit(db, now, session, action, target, detail) {
  await db
    .prepare('INSERT INTO audit (at, username, action, target, detail) VALUES (?1, ?2, ?3, ?4, ?5)')
    .bind(now, (session && session.username) || null, action, target || null, detail || null)
    .run()
    .catch(() => {});   // a failed audit write must never block the action
}

// Returns null rather than throwing when the table predates the users feature.
const getUser = (db, username) =>
  db.prepare('SELECT * FROM users WHERE username = ?1').bind(username).first().catch(() => null);

// Usernames are a small, fixed alphabet so they can be compared and stored
// without escaping surprises, and so a typo cannot become a wildcard.
const isUsername = (v) => typeof v === 'string' && /^[a-z0-9][a-z0-9._-]{1,30}$/.test(v);

// Which data sources each console screen actually reads. The tab list a user
// is given is turned into this set, and the endpoint guard below enforces it —
// screens that share a source cannot be separated any finer than the source.
const TAB_NEEDS = {
  over: ['records', 'vault', 'reports'],
  pending: ['records'],
  track: ['records'],
  reports: ['reports'],
  faults: ['reports'],
  inv: ['records', 'vault'],
  armon: ['vault', 'reports'],
  comms: ['vault'],
  tzelem: ['vault'],
  ammo: ['vault'],
  veh: ['vault'],
  sum: ['records'],
  sec: [],
};

function scopesFor(tabs) {
  if (tabs === '*') return new Set(['records', 'vault', 'reports']);
  let list;
  try { list = JSON.parse(tabs); } catch { return new Set(); }
  const out = new Set();
  for (const t of Array.isArray(list) ? list : []) {
    for (const need of TAB_NEEDS[t] || []) out.add(need);
  }
  return out;
}

// A stable decoy salt for names that do not exist, so the challenge endpoint
// cannot be used to enumerate usernames — an unknown user fails at the
// verifier instead, exactly like a wrong password.
async function decoySalt(db, username) {
  const cfg = await getConfig(db);
  const seed = new TextEncoder().encode(`decoy:${(cfg && cfg.id_salt) || ''}:${username}`);
  const hash = await crypto.subtle.digest('SHA-256', seed);
  return btoa(String.fromCharCode(...new Uint8Array(hash).slice(0, 16)));
}

async function getSession(db, request, now) {
  const cookie = request.headers.get('Cookie') || '';
  const m = cookie.match(/(?:^|;\s*)sid=([0-9a-f]{64})(?:;|$)/);
  if (!m) return null;
  const row = await db
    .prepare('SELECT token, expires, role, username, tabs FROM sessions WHERE token = ?1')
    .bind(m[1])
    .first();
  if (!row || row.expires <= now) return null;
  await db
    .prepare('UPDATE sessions SET expires = ?1 WHERE token = ?2')
    .bind(now + SESSION_MS, row.token)
    .run();
  // Anything but an explicit 'viewer' is treated as an admin, matching the
  // column default for sessions created before the role existed.
  return {
    token: row.token,
    role: ROLES.includes(row.role) ? row.role : 'admin',
    username: row.username || null,
    tabs: row.tabs || '*',
  };
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
    await sweepThrottle(db, now);

    // ── GET /api/config ──────────────────────────────────────────────
    if (seg[0] === 'config' && seg.length === 1 && method === 'GET') {
      const cfg = await getConfig(db);
      if (!cfg) return json({ ready: false });
      return json({ ready: true, pub: JSON.parse(cfg.pub), idSalt: cfg.id_salt });
    }

    // ── GET /api/ticket ──────────────────────────────────────────────
    // A one-shot permit to submit. Cheap to get, but it has to be got.
    if (seg[0] === 'ticket' && seg.length === 1 && method === 'GET') {
      if (!(await allow(db, `tkt:${ip}`, TICKET_LIMIT, SUB_WINDOW_MS, now))) {
        return err(429, 'יותר מדי בקשות, נסו שוב מאוחר יותר');
      }
      return json(await issueTicket(db, now));
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
      try {
        await db
          .prepare(
            'INSERT INTO config (id, pub, salt, id_salt, verifier, key_iv, wrapped_key, created_at) ' +
              'VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)'
          )
          .bind(pub, salt, idSalt, verifier, keyIv, wrappedKey, now)
          .run();
        // the first administrator, under the name the console logs in with
        await db
          .prepare(
            `INSERT OR IGNORE INTO users (username, role, salt, verifier, key_iv, wrapped_key, tabs, created_at)
             VALUES ('admin.951', 'admin', ?1, ?2, ?3, ?4, '*', ?5)`
          )
          .bind(salt, verifier, keyIv, wrappedKey, now)
          .run();
      } catch {
        // lost the race against a concurrent setup — the other one owns it
        return err(409, 'המערכת כבר הוגדרה');
      }
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
      if (!(await spendTicket(db, b.ticket, now))) {
        return err(403, 'ההרשאה לשליחה פגה — רעננו את הדף ונסו שוב');
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

    // ── POST /api/reports ────────────────────────────────────────────
    // A soldier's free-text shortage report. Unrelated to sign-out, and a
    // soldier may file more than one, so the id comes from the client at random.
    if (seg[0] === 'reports' && seg.length === 1 && method === 'POST') {
      if (!(await allow(db, `sub:${ip}`, SUB_LIMIT, SUB_WINDOW_MS, now))) {
        return err(429, 'יותר מדי דיווחים, נסו שוב מאוחר יותר');
      }
      const b = await readBody(request);
      if (!b) return err(400, 'בקשה לא תקינה');
      const { id, ek, iv, ct } = b;
      if (!isHex(id, HEX32) || !isB64(ek, 1000) || !isB64(iv, 64) || !isB64(ct, 12000)) {
        return err(400, 'בקשה לא תקינה');
      }
      if (!(await spendTicket(db, b.ticket, now))) {
        return err(403, 'ההרשאה לשליחה פגה — רעננו את הדף ונסו שוב');
      }
      const clash = await db.prepare('SELECT id FROM reports WHERE id = ?1').bind(id).first();
      if (clash) return err(409, 'מזהה כפול — נסו שוב');
      await db
        .prepare(
          'INSERT INTO reports (id, ek, iv, ct, status, created_at, updated_at) ' +
            "VALUES (?1, ?2, ?3, ?4, 'open', ?5, ?5)"
        )
        .bind(id, ek, iv, ct, now)
        .run();
      return json({ ok: true });
    }

    // ── POST /api/docs ───────────────────────────────────────────────
    // An encrypted licence photo. Stored apart from the record so listing
    // soldiers never pulls image data. Same write rules as records: a photo
    // can be replaced while pending, but not once the record is approved.
    if (seg[0] === 'docs' && seg.length === 1 && method === 'POST') {
      if (!(await allow(db, `doc:${ip}`, DOC_LIMIT, SUB_WINDOW_MS, now))) {
        return err(429, 'יותר מדי העלאות, נסו שוב מאוחר יותר');
      }
      const b = await readBody(request);
      if (!b) return err(400, 'בקשה לא תקינה');
      const { rid, kind, ek, iv, ct } = b;
      if (
        !isHex(rid, HEX32) ||
        (kind !== 'civil' && kind !== 'military') ||
        !isB64(ek, 1000) ||
        !isB64(iv, 64) ||
        !isB64(ct, DOC_MAX_B64)
      ) {
        return err(400, 'בקשה לא תקינה');
      }
      const owner = await db
        .prepare('SELECT status FROM records WHERE rid = ?1')
        .bind(rid)
        .first();
      if (!owner) return err(409, 'אין רשומה לצרף אליה צילום');
      if (owner.status === 'approved') {
        return err(409, 'הרשומה כבר אושרה — פנו למנהל הציוד');
      }
      await db
        .prepare(
          `INSERT INTO docs (rid, kind, ek, iv, ct, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
           ON CONFLICT(rid, kind) DO UPDATE SET ek = ?3, iv = ?4, ct = ?5, created_at = ?6`
        )
        .bind(rid, kind, ek, iv, ct, now)
        .run();
      return json({ ok: true });
    }

    // ── /api/admin/* ─────────────────────────────────────────────────
    if (seg[0] === 'admin') {
      // GET /api/admin/challenge?u=<username> — the salt to derive that
      // user's KEK from. Unknown names get a stable decoy so the endpoint
      // cannot be used to discover who exists.
      if (seg[1] === 'challenge' && seg.length === 2 && method === 'GET') {
        const cfg = await getConfig(db);
        if (!cfg) return err(404, 'המערכת עדיין לא הוגדרה');
        const username = (url.searchParams.get('u') || '').toLowerCase();
        if (!username) return json({ salt: cfg.salt });          // legacy client
        if (!isUsername(username)) return json({ salt: await decoySalt(db, username) });
        const u = await getUser(db, username);
        return json({ salt: u ? u.salt : await decoySalt(db, username) });
      }

      // POST /api/admin/login — { username, verifier }
      if (seg[1] === 'login' && seg.length === 2 && method === 'POST') {
        if (!(await allow(db, `login:${ip}`, LOGIN_LIMIT, LOGIN_WINDOW_MS, now))) {
          return err(429, 'יותר מדי ניסיונות התחברות — נעילה של 10 דקות');
        }
        const b = await readBody(request);
        if (!b || !isHex(b.verifier, HEX64)) return err(400, 'בקשה לא תקינה');
        const username = (b.username || '').toLowerCase();
        // Per-IP alone lets a distributed attacker grind one account. The
        // account itself also has a budget.
        if (username && !(await allow(db, `luser:${username}`, LOGIN_LIMIT, LOGIN_WINDOW_MS, now))) {
          return err(429, 'החשבון ננעל זמנית לאחר ניסיונות כושלים — נסו בעוד 10 דקות');
        }

        let cred = null;
        if (username) {
          if (!isUsername(username)) return err(401, 'שם משתמש או סיסמה שגויים');
          cred = await getUser(db, username);
        } else {
          // no username: the pre-users client, which only ever had the admin
          const cfg = await getConfig(db);
          if (cfg) cred = { ...cfg, username: 'admin.951', role: 'admin', tabs: '*' };
        }
        if (!cred || !tsEqual(b.verifier, cred.verifier)) {
          return err(401, 'שם משתמש או סיסמה שגויים');
        }

        const role = ROLES.includes(cred.role) ? cred.role : 'admin';
        const tabs = role === 'admin' ? '*' : (cred.tabs || '*');
        const token = randomToken();
        await db.prepare('DELETE FROM sessions WHERE expires <= ?1').bind(now).run();
        await db
          .prepare('INSERT INTO sessions (token, expires, role, username, tabs) VALUES (?1, ?2, ?3, ?4, ?5)')
          .bind(token, now + SESSION_MS, role, cred.username || username || null, tabs)
          .run();
        await db
          .prepare('UPDATE users SET last_seen = ?1 WHERE username = ?2')
          .bind(now, cred.username || username || '')
          .run()
          .catch(() => {});
        return json(
          { keyIv: cred.key_iv, wrappedKey: cred.wrapped_key, role, tabs, username: cred.username || username },
          200,
          { 'Set-Cookie': sessionCookie(token) }
        );
      }

      // Everything below requires a live session.
      const session = await getSession(db, request, now);
      if (!session) return err(401, 'נדרשת התחברות');

      // A viewer may read; it may not change anything. Enforced here rather
      // than per-endpoint so a new write route cannot forget to opt in.
      if (session.role === 'viewer' && method !== 'GET' && !(seg[1] === 'logout' && method === 'POST')) {
        return err(403, 'משתמש צפייה בלבד — אין הרשאת עריכה');
      }

      // Screen permissions, enforced where they can actually be enforced: at
      // the three data sources. This binds editors as much as viewers — an
      // editor may write, but only within the screens they were given, so the
      // same scope check gates their writes as well as their reads.
      if (isRestricted(session.role)) {
        const scopes = scopesFor(session.tabs);
        const wants =
          seg[1] === 'records' ? 'records'
            : seg[1] === 'docs' ? 'records'
              : seg[1] === 'vault' ? 'vault'
                : seg[1] === 'reports' ? 'reports'
                  : null;
        if (wants && !scopes.has(wants)) return err(403, 'אין הרשאה לנתונים אלה');
        // User management, the audit trail, the trash, password rotation and
        // the wipe stay with the administrator whatever screens were granted.
        if (['users', 'audit', 'trash', 'rotate', 'wipe'].includes(seg[1])) {
          return err(403, 'אין הרשאה לאזור זה — נדרשת הרשאת מנהל');
        }
      }

      // POST /api/admin/logout
      if (seg[1] === 'logout' && seg.length === 2 && method === 'POST') {
        await db.prepare('DELETE FROM sessions WHERE token = ?1').bind(session.token).run();
        return json({ ok: true }, 200, { 'Set-Cookie': clearedCookie() });
      }

      // GET /api/admin/users — the roster, never the credentials themselves
      if (seg[1] === 'users' && seg.length === 2 && method === 'GET') {
        const { results } = await db
          .prepare('SELECT username, role, tabs, created_at, last_seen FROM users ORDER BY role DESC, username')
          .all();
        return json({ users: results, me: session.username });
      }

      // PUT | DELETE /api/admin/users/:username
      // The client wraps the same private key under the new user's password;
      // the server only ever stores the wrapped blob, the verifier and the
      // screen list.
      if (seg[1] === 'users' && seg.length === 3) {
        const username = decodeURIComponent(seg[2]).toLowerCase();
        if (!isUsername(username)) return err(400, 'שם משתמש לא תקין');

        if (method === 'PUT') {
          const b = await readBody(request);
          if (!b) return err(400, 'בקשה לא תקינה');
          const role = ROLES.includes(b.role) ? b.role : 'viewer';
          let tabs = '*';
          if (isRestricted(role)) {
            if (!Array.isArray(b.tabs) || !b.tabs.length) return err(400, 'נא לבחור לפחות מסך אחד');
            const clean = [...new Set(b.tabs)].filter((t) => Object.prototype.hasOwnProperty.call(TAB_NEEDS, t) && t !== 'sec');
            if (!clean.length) return err(400, 'נא לבחור לפחות מסך אחד');
            tabs = JSON.stringify(clean);
          }

          const existing = await getUser(db, username);
          // Changing only the screens: keep the password already in place.
          if (existing && b.tabsOnly) {
            if (existing.role === 'admin') return err(400, 'למנהל יש גישה לכל המסכים');
            await db
              .prepare('UPDATE users SET tabs = ?1, role = ?2 WHERE username = ?3')
              .bind(tabs, role, username)
              .run();
            await db
              .prepare('UPDATE sessions SET tabs = ?1, role = ?2 WHERE username = ?3')
              .bind(tabs, role, username)
              .run();
            return json({ ok: true });
          }

          if (
            !isB64(b.salt, 64) ||
            !isHex(b.verifier, HEX64) ||
            !isB64(b.keyIv, 64) ||
            !isB64(b.wrappedKey, 8000)
          ) {
            return err(400, 'בקשה לא תקינה');
          }
          await db
            .prepare(
              `INSERT INTO users (username, role, salt, verifier, key_iv, wrapped_key, tabs, created_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
               ON CONFLICT(username) DO UPDATE SET role = ?2, salt = ?3, verifier = ?4,
                                                   key_iv = ?5, wrapped_key = ?6, tabs = ?7`
            )
            .bind(username, role, b.salt, b.verifier, b.keyIv, b.wrappedKey, tabs, now)
            .run();
          await audit(db, now, session, existing ? 'user-update' : 'user-create', username, role);
          // a password change signs that user out everywhere
          await db.prepare('DELETE FROM sessions WHERE username = ?1').bind(username).run();
          return json({ ok: true });
        }

        if (method === 'DELETE') {
          if (username === session.username) return err(400, 'אי אפשר למחוק את המשתמש שאיתו התחברתם');
          const target = await getUser(db, username);
          if (!target) return err(404, 'המשתמש לא נמצא');
          if (target.role === 'admin') {
            const row = await db.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'admin'").first();
            if (!row || row.n <= 1) return err(400, 'חייב להישאר מנהל אחד לפחות');
          }
          await db.batch([
            db.prepare('DELETE FROM users WHERE username = ?1').bind(username),
            db.prepare('DELETE FROM sessions WHERE username = ?1').bind(username),
          ]);
          await audit(db, now, session, 'user-delete', username, null);
          return json({ ok: true });
        }
      }

      // GET /api/admin/reports — every shortage report
      if (seg[1] === 'reports' && seg.length === 2 && method === 'GET') {
        const { results } = await db
          .prepare(
            'SELECT id, ek, iv, ct, status, created_at, updated_at FROM reports WHERE deleted_at IS NULL ORDER BY created_at DESC'
          )
          .all();
        return json({ reports: results });
      }

      // PUT | DELETE /api/admin/reports/:id — flip the handled flag, or drop it
      if (seg[1] === 'reports' && seg.length === 3) {
        const id = seg[2];
        if (!isHex(id, HEX32)) return err(400, 'בקשה לא תקינה');

        if (method === 'PUT') {
          const b = await readBody(request);
          if (!b || !['open', 'partial', 'done'].includes(b.status)) {
            return err(400, 'בקשה לא תקינה');
          }
          const r = await db
            .prepare('UPDATE reports SET status = ?1, updated_at = ?2 WHERE id = ?3')
            .bind(b.status, now, id)
            .run();
          if (!r.meta.changes) return err(404, 'הדיווח לא נמצא');
          return json({ ok: true });
        }

        if (method === 'DELETE') {
          const r = await db
            .prepare('UPDATE reports SET deleted_at = ?1 WHERE id = ?2 AND deleted_at IS NULL')
            .bind(now, id)
            .run();
          if (!r.meta.changes) return err(404, 'הדיווח לא נמצא');
          await audit(db, now, session, 'delete-report', id, null);
          return json({ ok: true });
        }
      }

      // GET /api/admin/docs/:rid — licence photos for one soldier, on demand
      if (seg[1] === 'docs' && seg.length === 3 && method === 'GET') {
        if (!isHex(seg[2], HEX32)) return err(400, 'בקשה לא תקינה');
        const { results } = await db
          .prepare('SELECT kind, ek, iv, ct FROM docs WHERE rid = ?1')
          .bind(seg[2])
          .all();
        return json({ docs: results });
      }

      // PUT | DELETE /api/admin/docs/:rid/:kind — admin-owned attachments.
      // Only 'fuel' (a refuelling receipt): these belong to the vault rather
      // than to any soldier, so unlike POST /docs there is no record to check.
      if (seg[1] === 'docs' && seg.length === 4) {
        const [, , rid, kind] = seg;
        if (!isHex(rid, HEX32) || kind !== 'fuel') return err(400, 'בקשה לא תקינה');

        if (method === 'PUT') {
          const b = await readBody(request);
          if (!b) return err(400, 'בקשה לא תקינה');
          const { ek, iv, ct } = b;
          if (!isB64(ek, 1000) || !isB64(iv, 64) || !isB64(ct, DOC_MAX_B64)) {
            return err(400, 'בקשה לא תקינה');
          }
          await db
            .prepare(
              `INSERT INTO docs (rid, kind, ek, iv, ct, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
               ON CONFLICT(rid, kind) DO UPDATE SET ek = ?3, iv = ?4, ct = ?5, created_at = ?6`
            )
            .bind(rid, kind, ek, iv, ct, now)
            .run();
          return json({ ok: true });
        }

        if (method === 'DELETE') {
          await db.prepare('DELETE FROM docs WHERE rid = ?1 AND kind = ?2').bind(rid, kind).run();
          return json({ ok: true });
        }
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
          if (!isB64(ek, 1000) || !isB64(iv, 64) || !isB64(ct, VAULT_MAX_B64)) {
            return err(400, 'בקשה לא תקינה');
          }
          // Optimistic concurrency: the client sends the updated_at it loaded.
          // If the stored one moved, someone else saved in between and blindly
          // overwriting would silently destroy their work. The version is
          // required, not optional — an omitted one was a way to skip the
          // check and clobber the vault, which is exactly what it exists to
          // prevent.
          const cur = await db.prepare('SELECT updated_at FROM vault WHERE id = 1').first();
          if (cur && b.baseVersion === undefined) {
            return err(400, 'חסרה גרסת בסיס — רעננו לפני השמירה');
          }
          if (cur && Number(b.baseVersion) !== cur.updated_at) {
            return json(
              { error: 'המלאי עודכן בינתיים על ידי מנהל אחר — רעננו לפני השמירה', current: cur.updated_at },
              409
            );
          }
          await db
            .prepare(
              `INSERT INTO vault (id, ek, iv, ct, updated_at) VALUES (1, ?1, ?2, ?3, ?4)
               ON CONFLICT(id) DO UPDATE SET ek = ?1, iv = ?2, ct = ?3, updated_at = ?4`
            )
            .bind(ek, iv, ct, now)
            .run();
          await audit(db, now, session, 'vault', null, `${ct.length} תווים`);
          return json({ ok: true, updatedAt: now });
        }
      }

      // GET /api/admin/records
      if (seg[1] === 'records' && seg.length === 2 && method === 'GET') {
        const { results } = await db
          .prepare(
            'SELECT rid, ek, iv, ct, status, created_at, updated_at FROM records WHERE deleted_at IS NULL ORDER BY created_at'
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
          await audit(db, now, session, status === 'approved' ? 'approve' : 'update', rid, null);
          return json({ ok: true });
        }

        // Soft delete. The row leaves the console but survives for 30 days,
        // photos included, so one mis-click is recoverable.
        if (method === 'DELETE') {
          const r = await db
            .prepare('UPDATE records SET deleted_at = ?1 WHERE rid = ?2 AND deleted_at IS NULL')
            .bind(now, rid)
            .run();
          if (!r.meta.changes) return err(404, 'הרשומה לא נמצאה');
          await audit(db, now, session, 'delete-record', rid, null);
          return json({ ok: true });
        }
      }

      // GET /api/admin/trash — what is recoverable, and for how long
      if (seg[1] === 'trash' && seg.length === 2 && method === 'GET') {
        const cutoff = now - TRASH_MS;
        await db.batch([
          db.prepare('DELETE FROM records WHERE deleted_at IS NOT NULL AND deleted_at < ?1').bind(cutoff),
          db.prepare('DELETE FROM reports WHERE deleted_at IS NOT NULL AND deleted_at < ?1').bind(cutoff),
        ]);
        const recs = await db
          .prepare('SELECT rid, ek, iv, ct, status, created_at, deleted_at FROM records WHERE deleted_at IS NOT NULL ORDER BY deleted_at DESC')
          .all();
        const reps = await db
          .prepare('SELECT id, ek, iv, ct, status, created_at, deleted_at FROM reports WHERE deleted_at IS NOT NULL ORDER BY deleted_at DESC')
          .all();
        return json({ records: recs.results, reports: reps.results, keepMs: TRASH_MS });
      }

      // POST /api/admin/trash/:kind/:id — put it back
      if (seg[1] === 'trash' && seg.length === 4 && method === 'POST') {
        const [, , kind, id] = seg;
        if (!isHex(id, HEX32) || (kind !== 'record' && kind !== 'report')) {
          return err(400, 'בקשה לא תקינה');
        }
        const table = kind === 'record' ? 'records' : 'reports';
        const col = kind === 'record' ? 'rid' : 'id';
        const r = await db
          .prepare(`UPDATE ${table} SET deleted_at = NULL WHERE ${col} = ?1 AND deleted_at IS NOT NULL`)
          .bind(id)
          .run();
        if (!r.meta.changes) return err(404, 'הפריט לא נמצא בסל');
        await audit(db, now, session, `restore-${kind}`, id, null);
        return json({ ok: true });
      }

      // GET /api/admin/audit — the admin action trail
      if (seg[1] === 'audit' && seg.length === 2 && method === 'GET') {
        const { results } = await db
          .prepare('SELECT at, username, action, target, detail FROM audit ORDER BY at DESC LIMIT 500')
          .all();
        return json({ audit: results });
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
        // the same password change against the row the console authenticates on
        await db
          .prepare('UPDATE users SET salt = ?1, verifier = ?2, key_iv = ?3, wrapped_key = ?4 WHERE username = ?5')
          .bind(salt, verifier, keyIv, wrappedKey, session.username || 'admin.951')
          .run()
          .catch(() => {});
        await db.prepare('DELETE FROM sessions').run();
        return json({ ok: true }, 200, { 'Set-Cookie': clearedCookie() });
      }

      // POST /api/admin/wipe
      if (seg[1] === 'wipe' && seg.length === 2 && method === 'POST') {
        await db.batch([
          db.prepare('DELETE FROM records'),
          db.prepare('DELETE FROM docs'),
          db.prepare('DELETE FROM reports'),
          db.prepare('DELETE FROM vault'),
          db.prepare('DELETE FROM sessions'),
          db.prepare('DELETE FROM throttle'),
          db.prepare('DELETE FROM users'),
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
