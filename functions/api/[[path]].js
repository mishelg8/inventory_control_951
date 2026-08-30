// Single catch-all API handler for /api/*.
// The server stores ciphertext only: no name, personal number, or phone ever
// arrives here in plaintext. See PLAN.md §4 and §6 for the contract.
//
// The WhatsApp Cloud integration is the one place that receives plaintext
// from outside — Meta sends it — and it seals what it receives before writing
// it down. The contract above still holds for anything that reaches storage.
// Its infrastructure lives under lib/whatsapp/; this file only routes to it.

import { waConfig } from '../../lib/whatsapp/config.js';
import { waCloudContext, sendTextMessage, sendTemplateMessage } from '../../lib/whatsapp/service.js';
import {
  listConversations, listMessages, getConversation, clearUnread, getMediaRow,
} from '../../lib/whatsapp/store.js';
import { waClient } from '../../lib/whatsapp/client.js';
import { userMessage as userFacingMeta } from '../../lib/whatsapp/errors.js';

const SESSION_MS = 60 * 60 * 1000;        // 1 hour, refreshed on each authed request
// ...but not forever. A console that is used all day used to hold its session
// open indefinitely, because every request pushed the hour out again. Twelve
// hours from sign-in is a long shift and a firm end: after that the password
// is needed again, which is also the only way the browser gets the key back.
const SESSION_ABS_MS = 12 * 60 * 60 * 1000;
const LOGIN_LIMIT = 8;                    // login attempts per IP...
const LOGIN_WINDOW_MS = 10 * 60 * 1000;   // ...per 10-minute lockout window
// A whole unit signing out is typically behind ONE base-WiFi NAT address, so
// this budget is shared by ~90 soldiers submitting within minutes of each
// other. 40/hour silently locked most of them out; 400 leaves ample headroom
// while still stopping a scripted flood.
const SUB_LIMIT = 400;                    // submissions per IP...
const SUB_WINDOW_MS = 60 * 60 * 1000;     // ...per hour
// Two licences each, so 120 was sixty soldiers an hour — the same shared
// address, and the same day that stops halfway through.
const DOC_LIMIT = 400;                    // licence photos per IP per hour (heavier rows)

// ~400 KB of base64 ≈ 300 KB of JPEG. The client compresses well below this;
// the cap is a backstop so a single row can never bloat the database.
const DOC_MAX_B64 = 400000;

// The vault holds opening stock, extra items, and the two counting registers
// (צלם / צלם ארמון). ~600 KB of base64 leaves room for a few thousand rows.
const VAULT_MAX_B64 = 600000;

// The vault, one row per domain. The names are the client's own keys, listed
// here so a client cannot invent rows the console will never read again.
// Each part carries its own ceiling, so the movement logs — the only things
// here that grow without end — can no longer crowd out the vehicles.
const VAULT_PARTS = [
  'stock', 'countedAt',
  'armon', 'armonLog', 'comms', 'commsLog',
  'ammo', 'ammoLog', 'vehicles', 'fuel', 'missions',
];
const VAULT_PART_MAX_B64 = 400000;

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
//
// Its failures are swallowed on purpose. This runs before every request,
// including a plain read of /api/config — the first call the app makes, before
// a soldier has seen anything at all. A one-in-fifty housekeeping write that
// took the request down with it turned a passing D1 hiccup into "שגיאת שרת" on
// the front door, over rows nobody asked to delete. If the sweep loses, the
// lapsed rows wait for the next one.
async function sweepThrottle(db, now) {
  if (Math.random() < 0.02) {
    try {
      await db.prepare('DELETE FROM throttle WHERE until <= ?1').bind(now - 86400000).run();
    } catch (e) {
      console.error('sweepThrottle', e && e.message);
    }
  }
}

/* ── Pacing the unit's line ──────────────────────────────────────────
   WhatsApp restricted the number. Twenty approvals under one press meant
   twenty chats opened within a few seconds, nearly all of them with people
   who had never written to that number — which is the shape their spam
   detection looks for, and it was right about the shape.

   Nothing here makes the detection go away. An unofficial gateway is not a
   sanctioned sender and will not become one; only the official WhatsApp
   Business API is. What is ours to fix is the burst, and it is fixed here
   rather than only in the browser, because the browser can be reloaded,
   opened twice, or closed mid-run, and none of those may reset the pace.

   Three limits, read from wrangler.toml so they can be loosened later
   without changing code:

     WA_GAP_MS    the floor between any two messages   (default 60s)
     WA_HOUR_MAX  messages in a rolling hour           (default 10)
     WA_DAY_MAX   messages in a rolling day            (default 20)

   The defaults are the provider's figures for a number that is new or has
   just been restricted, which is what this one is. They are deliberately
   the same as wrangler.toml: a deploy that loses the vars should get the
   careful pace, not the fast one.

   Being refused is not a failure state. Every refusal hands the caller back
   to the wa.me path — the chat opens on the sender's own phone, nothing
   passes through the provider — which is where this project started and is
   still the safer of the two. */
const waPace = (env) => ({
  gapMs:   Math.max(0, Number(env.WA_GAP_MS)   || 60000),
  hourMax: Math.max(1, Number(env.WA_HOUR_MAX) || 10),
  dayMax:  Math.max(1, Number(env.WA_DAY_MAX)  || 20),
});

/* Claims the next slot, or says how long until there is one. Conditional
   upsert so two tabs cannot both believe the line is free: the UPDATE runs
   only where the previous slot has already lapsed, and a claim that loses
   returns no row. */
async function waGapClaim(db, now, gapMs) {
  if (gapMs <= 0) return { ok: true };
  const won = await db
    .prepare(
      `INSERT INTO throttle (k, hits, until) VALUES ('wa:gap', 1, ?1)
       ON CONFLICT(k) DO UPDATE SET until = ?1, hits = throttle.hits + 1
         WHERE throttle.until <= ?2
       RETURNING until`
    )
    .bind(now + gapMs, now)
    .first();
  if (won) return { ok: true };
  const cur = await db.prepare("SELECT until FROM throttle WHERE k = 'wa:gap'").first();
  return { ok: false, why: 'gap', waitMs: Math.max(0, ((cur && cur.until) || now) - now) };
}

// How many went out in the window that is still open. A lapsed window is nil,
// not stale — the row simply has not been rewritten yet.
async function waCount(db, k, now) {
  const r = await db.prepare('SELECT hits, until FROM throttle WHERE k = ?1').bind(k).first();
  return r && r.until > now ? r.hits : 0;
}

async function waBump(db, k, windowMs, now) {
  await db
    .prepare(
      `INSERT INTO throttle (k, hits, until) VALUES (?1, 1, ?2)
       ON CONFLICT(k) DO UPDATE SET
         hits  = CASE WHEN throttle.until <= ?3 THEN 1 ELSE throttle.hits + 1 END,
         until = CASE WHEN throttle.until <= ?3 THEN ?2 ELSE throttle.until END`
    )
    .bind(k, now + windowMs, now)
    .run();
}

// When the hour or the day is full, the useful number is when it empties —
// "try later" sends somebody back every two minutes to find out.
async function waUntil(db, k, now) {
  const r = await db.prepare('SELECT until FROM throttle WHERE k = ?1').bind(k).first();
  return Math.max(0, ((r && r.until) || now) - now);
}

// admin  — everything, including users, audit and the trash
// editor  — may read AND change, but only on the screens granted to them
// viewer  — may read only, and only on the screens granted to them
/* How many {{n}} placeholders a template body expects.
   Meta returns the components as authored, and a template sent with the wrong
   number of parameters is rejected with 132000 — after the round trip, and
   after the console has already told someone it was sent. Counting here lets
   the screen ask for the right number of values in the first place. */
function countTemplateParams(components) {
  let n = 0;
  for (const c of Array.isArray(components) ? components : []) {
    if (!c || c.type !== 'BODY' || typeof c.text !== 'string') continue;
    const seen = new Set();
    for (const m of c.text.matchAll(/\{\{(\d+)\}\}/g)) seen.add(m[1]);
    n = Math.max(n, seen.size);
  }
  return n;
}

const ROLES = ['admin', 'editor', 'viewer'];
const isRestricted = (role) => role === 'editor' || role === 'viewer';

const getConfig = (db) => db.prepare('SELECT * FROM config WHERE id = 1').first();

const TRASH_MS = 30 * 24 * 60 * 60 * 1000;   // deleted rows stay recoverable for 30 days
const TICKET_MS = 30 * 60 * 1000;         // a ticket is good for half an hour
/* A whole company signs up on the same day, from the same base, over the same
   Wi-Fi — which is one public address as far as this counter is concerned. At
   60 the sixty-first soldier of the hour was refused, and the day stopped. The
   submission cap beside it was raised to 400 for exactly this reason and this
   one was left behind, so it became the narrower gate of the two. */
const TICKET_LIMIT = 400;                 // tickets per IP per hour

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
/* What an update touched, in one word, chosen from a list the server owns.

   The audit table is not encrypted — that is the whole reason it holds no
   names — so it cannot take a sentence the console composed. A closed list
   can be let through: these words identify nobody, they only say which part
   of a record an administrator went into. Anything else is dropped rather
   than stored, so a client cannot turn this field into a channel for writing
   a soldier's details into plaintext. */
/* A device label, short enough to be useless to anybody but the person who
   owns the device. Two sessions of the same account are otherwise
   indistinguishable, and "sign everybody out" was the only answer available.

   What is deliberately not kept: the raw User-Agent, which is long enough to
   fingerprint a machine, and the address, because a whole base sits behind one
   address — it would name nobody while still being one more thing written down
   about people in a table that is not encrypted. */
function deviceLabel(ua) {
  const s = String(ua || '');
  if (!s) return null;
  const os = /Android/i.test(s) ? 'אנדרואיד'
    : /iPhone|iPad|iOS/i.test(s) ? 'אייפון'
      : /Macintosh|Mac OS/i.test(s) ? 'מק'
        : /Windows/i.test(s) ? 'Windows'
          : /Linux/i.test(s) ? 'Linux'
            : 'מכשיר';
  // Order matters: Edge and Chrome both say "Chrome", Chrome says "Safari".
  const app = /Edg\//i.test(s) ? 'Edge'
    : /OPR\/|Opera/i.test(s) ? 'Opera'
      : /Firefox\//i.test(s) ? 'Firefox'
        : /Chrome\//i.test(s) ? 'Chrome'
          : /Safari\//i.test(s) ? 'Safari'
            : '';
  return app ? `${os} · ${app}` : os;
}

const AUDIT_NOTES = ['פרטים', 'רישיונות', 'ציוד', 'זיכוי', 'נשק', 'תזונה'];
const auditNote = (v) => (AUDIT_NOTES.includes(v) ? v : null);

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

const SERIAL_FIELDS = ['weapon', 'amral', 'scope'];
const FIELD_HE = { weapon: 'מספר הנשק', amral: 'מק״ט האמר״ל', scope: 'מק״ט הכוונת' };
const STATE_HE = {
  pending: 'ממתין לאישור', approved: 'רשום על חייל',
  deposit: 'הופקד בארמון וממתין לקליטה', armoury: 'רשום בארמון',
};

// Claim the numbers on one submission. Equal numbers give equal tags, so the
// primary key is what actually stops the second soldier — the check the form
// ran a moment earlier is only there to say so before they press send.
// Re-filing the same slip must not collide with itself, hence the owner test.
async function claimSerials(db, tags, kind, ownerId, state, now) {
  if (!Array.isArray(tags)) return null;
  const clean = tags
    .filter((t) => t && isHex(t.tag, HEX32) && SERIAL_FIELDS.includes(t.field))
    .slice(0, SERIAL_FIELDS.length);
  if (clean.length !== (tags || []).length) return { bad: true };

  for (const t of clean) {
    const held = await db.prepare('SELECT owner_kind, owner_id, state FROM serial_tags WHERE tag = ?1')
      .bind(t.tag).first();
    if (held && !(held.owner_kind === kind && held.owner_id === ownerId)) {
      return { field: t.field, state: held.state };
    }
  }
  // The slip may have been edited, so its old numbers are released first.
  await db.prepare('DELETE FROM serial_tags WHERE owner_kind = ?1 AND owner_id = ?2')
    .bind(kind, ownerId).run();
  for (const t of clean) {
    try {
      await db.prepare(
        'INSERT INTO serial_tags (tag, field, state, owner_kind, owner_id, created_at) ' +
        'VALUES (?1, ?2, ?3, ?4, ?5, ?6)'
      ).bind(t.tag, t.field, state, kind, ownerId, now).run();
    } catch {
      // Two submissions in the same instant: the index decides, and the
      // loser is told exactly what the winner would have been told.
      return { field: t.field, state };
    }
  }
  return null;
}

const releaseSerials = (db, kind, ownerId) =>
  db.prepare('DELETE FROM serial_tags WHERE owner_kind = ?1 AND owner_id = ?2')
    .bind(kind, ownerId).run().catch(() => {});

// Which data sources each console screen actually reads. The tab list a user
// is given is turned into this set, and the endpoint guard below enforces it —
// screens that share a source cannot be separated any finer than the source.
const TAB_NEEDS = {
  over: ['records', 'vault', 'reports'],
  pending: ['records'],
  track: ['records'],
  reports: ['reports'],
  faults: ['reports'],
  mission: ['reports'],
  mdefs: ['vault'],
  inv: ['records', 'vault'],
  armon: ['vault', 'reports'],
  comms: ['vault'],
  tzelem: ['vault'],
  ammo: ['vault'],
  veh: ['vault'],
  lic: ['records'],
  food: ['records'],
  sum: ['records'],
  // Neither screen reads a soldier's data: one is the WhatsApp line's own
  // state, the other is users and the audit trail. Both are administrator-only,
  // and that is enforced above rather than through a scope.
  wa: [],
  sec: [],
};

/* A building fault takes more than one photograph. A leak is a stain on a
   ceiling, a puddle on a floor and the pipe behind a panel, and one frame of
   the three sends somebody to look at the other two.

   The docs table is keyed (rid, kind), so several photographs on one report
   need several kinds. Numbered rather than given their own ids: the rid stays
   the report's, which is what lets the server go on checking that the report
   exists and is still open before it accepts an image from a stranger. Four
   is the cap — enough to show a room from two angles and the thing itself,
   and four at 280KB apiece is still a send a phone can finish on a base
   connection. */
const FAULT_DOC_KINDS = ['fault', 'fault2', 'fault3', 'fault4'];

/* One photograph per item on a shift report. The docs table is keyed
   (rid, kind), so each picture needs a kind of its own, and the count is
   fixed by the checklist rather than by the reporter — six items, six keys,
   in the checklist's order. Kept in step with MISSION_ITEMS in
   public/lib/catalog.js. */
const MISSION_DOC_KINDS = ['msn1', 'msn2', 'msn3', 'msn4', 'msn5', 'msn6'];

// Which data source each kind of attachment belongs to, and therefore which
// screen permission may read it. A photograph is not its own thing: it is part
// of the record, the report or the fuel card it was attached to.
const DOC_SOURCE = {
  civil: 'records',
  military: 'records',
  signature: 'records',
  refuel: 'reports',
  fuel: 'vault',            // a receipt the office has filed onto a card
  ...Object.fromEntries(FAULT_DOC_KINDS.map((k) => [k, 'reports'])),
  ...Object.fromEntries(MISSION_DOC_KINDS.map((k) => [k, 'reports'])),
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
    .prepare('SELECT token, expires, role, username, tabs, created_at FROM sessions WHERE token = ?1')
    .bind(m[1])
    .first();
  if (!row || row.expires <= now) return null;
  // Sessions from before this column existed have no start time. They are
  // stamped now rather than killed, so a migration never signs anyone out.
  if (row.created_at == null) {
    await db.prepare('UPDATE sessions SET created_at = ?1 WHERE token = ?2').bind(now, row.token).run();
  } else if (now - row.created_at >= SESSION_ABS_MS) {
    await db.prepare('DELETE FROM sessions WHERE token = ?1').bind(row.token).run();
    return null;
  }
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
    // A deleted record does not exist. It is kept for thirty days so a
    // mis-click is recoverable, but that is the admin's business — to the
    // soldier standing at the form it is gone, and signing again starts a
    // new registration rather than a supplement to a slip nobody can see.
    if (seg[0] === 'status' && seg.length === 2 && method === 'GET') {
      if (!isHex(seg[1], HEX32)) return err(400, 'בקשה לא תקינה');
      const row = await db
        .prepare('SELECT status FROM records WHERE rid = ?1 AND deleted_at IS NULL')
        .bind(seg[1])
        .first();
      if (!row) return json({ exists: false });
      return json({ exists: true, status: row.status });
    }

    // ── GET /api/cards ───────────────────────────────────────────────
    // What the refuelling form may offer: the fuel cards, and the vehicles.
    // Ids and labels only — a card's full number never leaves the admin's
    // vault — and anything the admin credited, removed or never entered is
    // not in here at all, which is what makes it unpickable rather than
    // merely discouraged.
    if (seg[0] === 'cards' && seg.length === 1 && method === 'GET') {
      const { results } = await db
        .prepare('SELECT kind, id, label, data FROM pub_pick ORDER BY kind, sort')
        .all()
        .catch(() => ({ results: [] }));
      const rows = results || [];
      const of = (k) => rows.filter((r) => r.kind === k).map((r) => ({ id: r.id, label: r.label }));
      /* A mission carries the kit it requires, so the shift form can put the
         right rows in front of the commander instead of the whole catalogue.
         Parsed here rather than in the browser: a row that will not parse is
         a row the form should not see at all. */
      const missions = rows.filter((r) => r.kind === 'mission').map((r) => {
        let items = [];
        try { const p = JSON.parse(r.data || '[]'); if (Array.isArray(p)) items = p; } catch { items = []; }
        return { id: r.id, label: r.label, items };
      });
      return json({ cards: of('card'), vehicles: of('vehicle'), missions });
    }

    // ── GET /api/serial?tag=… ────────────────────────────────────────
    // "Is this number already on the books?" answered without the server ever
    // seeing a number: the client sends the blind index, the server looks it
    // up. The answer carries the state — pending, with a soldier, in the
    // armoury — because a soldier told "already registered" needs to know
    // whether that is their own slip from ten minutes ago or someone else's
    // rifle. It never carries who, which stays encrypted.
    //
    // This is an oracle over a low-entropy space, so it is rate-limited per
    // IP like every other public read here. It only ever confirms what the
    // submit path would refuse anyway.
    if (seg[0] === 'serial' && seg.length === 1 && method === 'GET') {
      if (!(await allow(db, `ser:${ip}`, 120, SUB_WINDOW_MS, now))) {
        return err(429, 'יותר מדי בדיקות, נסו שוב מאוחר יותר');
      }
      const tag = url.searchParams.get('tag') || '';
      if (!isHex(tag, HEX32)) return err(400, 'בקשה לא תקינה');
      const row = await db
        .prepare('SELECT field, state FROM serial_tags WHERE tag = ?1')
        .bind(tag)
        .first();
      return json(row ? { taken: true, field: row.field, state: row.state } : { taken: false });
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
        .prepare('SELECT status FROM records WHERE rid = ?1 AND deleted_at IS NULL')
        .bind(rid)
        .first();
      if (existing && existing.status === 'approved') {
        return err(409, 'הרשומה כבר אושרה ואינה ניתנת לעדכון — פנו למנהל הציוד');
      }
      // Nothing live under this id, but a deleted one may still be sitting in
      // the bin holding the id — and the id is derived from the personal
      // number, so it is the same soldier signing again. The old slip is
      // taken out for good, photos included: leaving it would either block
      // the insert or, worse, let the new registration inherit the deleted
      // one's licence photos, which share the id. Deleting a record in the
      // console is meant to mean the soldier can sign again from scratch.
      if (!existing) {
        const buried = await db
          .prepare('DELETE FROM records WHERE rid = ?1 AND deleted_at IS NOT NULL')
          .bind(rid)
          .run();
        if (buried.meta.changes) {
          await db.prepare('DELETE FROM docs WHERE rid = ?1').bind(rid).run();
          await releaseSerials(db, 'record', rid);
        }
      }
      const clash = await claimSerials(db, b.tags, 'record', rid, 'pending', now);
      if (clash) {
        if (clash.bad) return err(400, 'בקשה לא תקינה');
        return err(409, `${FIELD_HE[clash.field]} כבר קיים במערכת (${STATE_HE[clash.state] || clash.state}). ` +
          'בדקו שהקלדתם נכון, ואם המספר באמת שלכם פנו למנהל הציוד.');
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
      const dupId = await db.prepare('SELECT id FROM reports WHERE id = ?1').bind(id).first();
      if (dupId) return err(409, 'מזהה כפול — נסו שוב');
      // A weapon deposit carries the same numbers a sign-out does, so it
      // claims them the same way. Reports with no numbers send no tags.
      const clash = await claimSerials(db, b.tags, 'report', id, 'deposit', now);
      if (clash) {
        if (clash.bad) return err(400, 'בקשה לא תקינה');
        return err(409, `${FIELD_HE[clash.field]} כבר קיים במערכת (${STATE_HE[clash.state] || clash.state}). ` +
          'בדקו שהקלדתם נכון, ואם המספר באמת שלכם פנו למנהל הציוד.');
      }
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
        // 'signature' is the soldier's own hand on the sign-out slip. It
        // hangs off the record like a licence photo and is sealed the same
        // way — the server stores a picture it cannot see, of a signature it
        // could not verify anyway.
        // The fault kinds are photographs of the broken thing itself, attached
        // to a building-fault report. Optional, unlike the receipt beside it.
        !['civil', 'military', 'refuel', 'signature', ...FAULT_DOC_KINDS, ...MISSION_DOC_KINDS].includes(kind) ||
        !isB64(ek, 1000) ||
        !isB64(iv, 64) ||
        !isB64(ct, DOC_MAX_B64)
      ) {
        return err(400, 'בקשה לא תקינה');
      }
      // A refuelling receipt and a fault photograph hang off the report, not
      // off a sign-out record, and the same rule applies: either may be
      // attached while the report is still open and not once it is closed.
      if (kind === 'refuel' || FAULT_DOC_KINDS.includes(kind) || MISSION_DOC_KINDS.includes(kind)) {
        const rep = await db
          .prepare('SELECT status FROM reports WHERE id = ?1 AND deleted_at IS NULL')
          .bind(rid)
          .first();
        if (!rep) return err(409, 'אין דיווח לצרף אליו צילום');
        if (rep.status === 'done') {
          return err(409, kind === 'refuel'
            ? 'הדיווח כבר נקלט — פנו למנהל הרכב'
            : 'התקלה כבר סומנה כטופלה — פנו למנהל');
        }
      } else {
        const owner = await db
          .prepare('SELECT status FROM records WHERE rid = ?1 AND deleted_at IS NULL')
          .bind(rid)
          .first();
        if (!owner) return err(409, 'אין רשומה לצרף אליה צילום');
        if (owner.status === 'approved') {
          return err(409, 'הרשומה כבר אושרה — פנו למנהל הציוד');
        }
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
          await audit(db, now, { username }, 'login-lock', username, null);
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
          // The name that was tried, never what was tried against it. A run of
          // these against one account is the thing worth being able to see.
          await audit(db, now, { username }, 'login-fail', username || null, null);
          return err(401, 'שם משתמש או סיסמה שגויים');
        }
        /* Checked after the password and not before it, so that a blocked
           account and a mistyped one cannot be told apart by anybody who does
           not already know the password. Whoever does know it is told plainly
           — they are not an attacker, they are somebody who needs to go and
           ask why. */
        if (cred.blocked) {
          await audit(db, now, { username: cred.username || username }, 'login-blocked',
                      cred.username || username || null, null);
          return err(403, 'החשבון חסום — פנו למנהל המערכת');
        }

        const role = ROLES.includes(cred.role) ? cred.role : 'admin';
        const tabs = role === 'admin' ? '*' : (cred.tabs || '*');
        const token = randomToken();
        await db.prepare('DELETE FROM sessions WHERE expires <= ?1').bind(now).run();
        await db
          .prepare('INSERT INTO sessions (token, expires, role, username, tabs, created_at, agent) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)')
          .bind(token, now + SESSION_MS, role, cred.username || username || null, tabs, now,
                deviceLabel(request.headers.get('User-Agent')))
          .run();
        await db
          .prepare('UPDATE users SET last_seen = ?1 WHERE username = ?2')
          .bind(now, cred.username || username || '')
          .run()
          .catch(() => {});
        await audit(db, now, { username: cred.username || username }, 'login', null, role);
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
      // than per-endpoint so a new write route cannot forget to opt in. The
      // two exceptions are the writes that only ever take access away from
      // the caller: signing out, here or everywhere.
      const selfWrite =
        (seg[1] === 'logout' && seg.length === 2) ||
        (seg[1] === 'sessions' && seg[2] === 'revoke' && seg.length === 3);
      if (session.role === 'viewer' && method !== 'GET' && !(selfWrite && method === 'POST')) {
        return err(403, 'משתמש צפייה בלבד — אין הרשאת עריכה');
      }

      // Screen permissions, enforced where they can actually be enforced: at
      // the three data sources. This binds editors as much as viewers — an
      // editor may write, but only within the screens they were given, so the
      // same scope check gates their writes as well as their reads.
      const scopes = isRestricted(session.role) ? scopesFor(session.tabs) : null;
      if (scopes) {
        const wants =
          seg[1] === 'records' ? 'records'
            /* Attachments are the one route whose source is not the route.
               A photograph is readable by whoever may read the thing it hangs
               off, and that differs per attachment: a licence belongs to the
               soldier's record, a refuelling receipt and a photograph of a
               broken pipe to the report, a filed receipt to the vault. Asking
               for 'records' here denied the fault photograph to precisely the
               person the fault screen exists for. Decided per kind instead —
               see DOC_SOURCE at the two docs routes below. */
            : seg[1] === 'docs' ? null
              : seg[1] === 'vault' ? 'vault'
                : seg[1] === 'reports' ? 'reports'
                  : null;
        if (wants && !scopes.has(wants)) return err(403, 'אין הרשאה לנתונים אלה');
        // User management, the audit trail, the trash, password rotation and
        // the wipe stay with the administrator whatever screens were granted.
        // Sending on the unit's WhatsApp line is the same kind of authority:
        // it goes out under the unit's name and it can get the number banned.
        if (['users', 'audit', 'trash', 'rotate', 'wipe', 'wa'].includes(seg[1])) {
          return err(403, 'אין הרשאה לאזור זה — נדרשת הרשאת מנהל');
        }
      }

      // POST /api/admin/logout
      if (seg[1] === 'logout' && seg.length === 2 && method === 'POST') {
        await db.prepare('DELETE FROM sessions WHERE token = ?1').bind(session.token).run();
        await audit(db, now, session, 'logout', null, null);
        return json({ ok: true }, 200, { 'Set-Cookie': clearedCookie() });
      }

      // POST /api/admin/sessions/revoke — end every session of this user,
      // this one included. For a laptop left signed in somewhere else, which
      // until now could only be waited out. A viewer may do this too: it is
      // the one write that only ever takes access away, and it is their own.
      if (seg[1] === 'sessions' && seg[2] === 'revoke' && seg.length === 3 && method === 'POST') {
        if (!session.username) {
          await db.prepare('DELETE FROM sessions WHERE token = ?1').bind(session.token).run();
          return json({ ok: true, ended: 1 }, 200, { 'Set-Cookie': clearedCookie() });
        }
        const r = await db
          .prepare('DELETE FROM sessions WHERE username = ?1')
          .bind(session.username)
          .run();
        const ended = (r.meta && r.meta.changes) || 0;
        await audit(db, now, session, 'sessions-revoke', session.username, `${ended}`);
        return json({ ok: true, ended }, 200, { 'Set-Cookie': clearedCookie() });
      }

      /* GET /api/admin/sessions — who is signed in right now.
         Administrator only: it names every account with a live session, which
         is more than an editor has any business seeing. The token never leaves
         the server whole — a session is addressed by the first sixteen
         characters of it, which is enough to name one row and not enough to
         be one. */
      if (seg[1] === 'sessions' && seg.length === 2 && method === 'GET') {
        if (session.role !== 'admin') return err(403, 'אין הרשאה לאזור זה — נדרשת הרשאת מנהל');
        await db.prepare('DELETE FROM sessions WHERE expires <= ?1').bind(now).run();
        const { results } = await db
          .prepare('SELECT token, username, role, created_at, expires, agent FROM sessions ORDER BY created_at DESC')
          .all();
        return json({
          sessions: (results || []).map((s) => ({
            id: String(s.token).slice(0, 16),
            username: s.username,
            role: s.role,
            createdAt: s.created_at,
            // Refreshed on every authenticated request, so this is the last
            // time that device did anything, not a countdown.
            lastSeen: s.expires - SESSION_MS,
            agent: s.agent || null,
            current: s.token === session.token,
          })),
          idleMs: SESSION_MS,
          maxMs: SESSION_ABS_MS,
        });
      }

      // DELETE /api/admin/sessions/:id — end one device, by the short id above.
      if (seg[1] === 'sessions' && seg.length === 3 && method === 'DELETE') {
        if (session.role !== 'admin') return err(403, 'אין הרשאה לאזור זה — נדרשת הרשאת מנהל');
        const id = seg[2];
        if (!/^[0-9a-f]{16}$/.test(id)) return err(400, 'בקשה לא תקינה');
        const row = await db
          .prepare("SELECT token, username FROM sessions WHERE substr(token, 1, 16) = ?1")
          .bind(id)
          .first();
        if (!row) return err(404, 'החיבור כבר אינו קיים');
        await db.prepare('DELETE FROM sessions WHERE token = ?1').bind(row.token).run();
        await audit(db, now, session, 'session-end', row.username || null, null);
        // Ending your own session has to clear your own cookie too, or the
        // browser goes on presenting a token the server has forgotten.
        const self = row.token === session.token;
        return json({ ok: true, self }, 200, self ? { 'Set-Cookie': clearedCookie() } : undefined);
      }

      // GET /api/admin/users — the roster, never the credentials themselves
      if (seg[1] === 'users' && seg.length === 2 && method === 'GET') {
        const { results } = await db
          .prepare('SELECT username, role, tabs, created_at, last_seen, blocked FROM users ORDER BY role DESC, username')
          .all();
        return json({ users: results, me: session.username });
      }

      /* POST /api/admin/users/:username/block — {blocked: true|false}
         Stopping an account without destroying it. Deleting a user takes their
         wrapped copy of the private key with it and cannot be undone; blocking
         is the reversible answer, which is the one you want at the moment you
         are not yet sure what happened. Blocking also ends whatever that
         account has open — a block that leaves a live session running has
         stopped nothing. */
      if (seg[1] === 'users' && seg[3] === 'block' && seg.length === 4 && method === 'POST') {
        if (session.role !== 'admin') return err(403, 'אין הרשאה לאזור זה — נדרשת הרשאת מנהל');
        const username = decodeURIComponent(seg[2]).toLowerCase();
        if (!isUsername(username)) return err(400, 'שם משתמש לא תקין');
        if (username === session.username) return err(400, 'אי אפשר לחסום את החשבון שאיתו אתם מחוברים');
        const b = await readBody(request);
        const blocked = !!(b && b.blocked);
        const u = await getUser(db, username);
        if (!u) return err(404, 'המשתמש לא נמצא');
        await db
          .prepare('UPDATE users SET blocked = ?1 WHERE username = ?2')
          .bind(blocked ? 1 : 0, username)
          .run();
        let ended = 0;
        if (blocked) {
          const r = await db.prepare('DELETE FROM sessions WHERE username = ?1').bind(username).run();
          ended = (r.meta && r.meta.changes) || 0;
        }
        await audit(db, now, session, blocked ? 'user-block' : 'user-unblock', username,
                    blocked && ended ? `${ended} חיבורים נותקו` : null);
        return json({ ok: true, ended });
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
      // GET /api/admin/pulse — "has anything arrived?" in one cheap query.
      // The console asks every few seconds so a soldier's submission shows up
      // on its own; sending counts and the newest timestamp rather than the
      // rows themselves keeps that to two aggregates and no ciphertext, and
      // means the client only re-fetches when the answer actually changed.
      if (seg[1] === 'pulse' && seg.length === 2 && method === 'GET') {
        // A count is small but it is still information, so the pulse answers
        // only for the sources this session is allowed to read at all.
        const scopes = isRestricted(session.role)
          ? scopesFor(session.tabs)
          : new Set(['records', 'vault', 'reports']);
        const out = {};
        if (scopes.has('records')) {
          const r = await db
            .prepare('SELECT COUNT(*) AS n, IFNULL(MAX(updated_at), 0) AS t FROM records WHERE deleted_at IS NULL')
            .first();
          out.rn = r.n; out.rt = r.t;
        }
        if (scopes.has('reports')) {
          const p = await db
            .prepare('SELECT COUNT(*) AS n, IFNULL(MAX(updated_at), 0) AS t FROM reports WHERE deleted_at IS NULL')
            .first();
          out.pn = p.n; out.pt = p.t;
        }
        if (scopes.has('vault')) {
          const v = await db.prepare('SELECT IFNULL(updated_at, 0) AS t FROM vault WHERE id = 1').first();
          out.vt = v ? v.t : 0;
        }
        return json(out);
      }

      // GET /api/admin/reports[?since=<ms>] — same bargain as records above.
      if (seg[1] === 'reports' && seg.length === 2 && method === 'GET') {
        const since = Number(url.searchParams.get('since'));
        const cols = 'id, ek, iv, ct, status, created_at, updated_at';
        if (Number.isFinite(since) && since > 0) {
          const { results } = await db
            .prepare(`SELECT ${cols} FROM reports WHERE deleted_at IS NULL AND updated_at >= ?1 ORDER BY created_at DESC`)
            .bind(since)
            .all();
          const gone = await db
            .prepare('SELECT id FROM reports WHERE deleted_at IS NOT NULL AND deleted_at >= ?1')
            .bind(since)
            .all();
          return json({ reports: results, gone: (gone.results || []).map((r) => r.id), partial: true });
        }
        const { results } = await db
          .prepare(`SELECT ${cols} FROM reports WHERE deleted_at IS NULL ORDER BY created_at DESC`)
          .all();
        return json({ reports: results });
      }

      // PUT | DELETE /api/admin/reports/:id — flip the handled flag, or drop it
      if (seg[1] === 'reports' && seg.length === 3) {
        const id = seg[2];
        if (!isHex(id, HEX32)) return err(400, 'בקשה לא תקינה');

        if (method === 'PUT') {
          const b = await readBody(request);
          if (!b) return err(400, 'בקשה לא תקינה');

          // Correcting the body: the admin re-sealed it in the browser, so
          // what arrives is a new envelope and the server still sees nothing.
          // The status is left alone — a correction is not a state change.
          if (b.ek !== undefined || b.iv !== undefined || b.ct !== undefined) {
            const { ek, iv, ct } = b;
            if (!isB64(ek, 1000) || !isB64(iv, 64) || !isB64(ct, 12000)) {
              return err(400, 'בקשה לא תקינה');
            }
            const r = await db
              .prepare('UPDATE reports SET ek = ?1, iv = ?2, ct = ?3, updated_at = ?4 ' +
                       'WHERE id = ?5 AND deleted_at IS NULL')
              .bind(ek, iv, ct, now, id)
              .run();
            if (!r.meta.changes) return err(404, 'הדיווח לא נמצא');
            await audit(db, now, session, 'edit-report', id, null);
            return json({ ok: true });
          }

          if (!['open', 'partial', 'done'].includes(b.status)) {
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
          await releaseSerials(db, 'report', id);     // the numbers are free again
          await audit(db, now, session, 'delete-report', id, null);
          return json({ ok: true });
        }
      }

      // GET /api/admin/docs/:rid — the photographs hanging off one id, on demand
      if (seg[1] === 'docs' && seg.length === 3 && method === 'GET') {
        if (!isHex(seg[2], HEX32)) return err(400, 'בקשה לא תקינה');
        const { results } = await db
          .prepare('SELECT kind, ek, iv, ct FROM docs WHERE rid = ?1')
          .bind(seg[2])
          .all();
        // One id can only be a record or a report, never both, so this filter
        // never splits a real response — it is here so that a restricted user
        // gets the attachments of the screens they were given and nothing else.
        const rows = scopes
          ? (results || []).filter((r) => scopes.has(DOC_SOURCE[r.kind] || 'records'))
          : results;
        return json({ docs: rows });
      }

      // PUT | DELETE /api/admin/docs/:rid/:kind — attachments the office owns.
      //
      // 'fuel' is a refuelling receipt: it belongs to the vault rather than to
      // any soldier, so unlike POST /docs there is no record to check.
      //
      // 'civil' and 'military' are licence photographs, and they are here for
      // the opposite reason: POST /docs deliberately refuses to touch a record
      // once it is approved, which is right for a soldier and wrong for the
      // office. A licence that was photographed out of focus, or forgotten, is
      // found after approval or not at all — so the correction has to be
      // possible from the console. A signature is not on this list: that is
      // the soldier's own hand and nobody else's to replace.
      if (seg[1] === 'docs' && seg.length === 4) {
        const [, , rid, kind] = seg;
        // The shift photographs are here for the licence's reason: a picture
        // taken in the dark, of the wrong item, or not taken at all is found
        // afterwards or not at all, and POST /docs answers to the report's
        // status rather than to the office. The correction belongs here.
        if (!isHex(rid, HEX32) || ![
          'fuel', 'civil', 'military', ...MISSION_DOC_KINDS,
        ].includes(kind)) {
          return err(400, 'בקשה לא תקינה');
        }
        if (scopes && !scopes.has(DOC_SOURCE[kind])) return err(403, 'אין הרשאה לנתונים אלה');

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
      // PUT /api/admin/cards — republish the roster the refuelling form offers.
      // Sent by the admin's browser whenever the vault is saved, since only it
      // can read the cards and the vehicles. The whole list of a kind is
      // replaced each time, so a card that has been credited or a vehicle that
      // has left the fleet disappears by simply not being sent. A kind that is
      // absent from the body is left alone rather than emptied — an older tab
      // that only knows about cards must not wipe the vehicles.
      if (seg[1] === 'cards' && seg.length === 2 && method === 'PUT') {
        if (isRestricted(session.role) && !scopesFor(session.tabs).has('vault')) {
          return err(403, 'אין הרשאה לנתונים אלה');
        }
        const b = await readBody(request);
        if (!b) return err(400, 'בקשה לא תקינה');
        const lists = {};
        for (const [key, kind] of [['cards', 'card'], ['vehicles', 'vehicle'], ['missions', 'mission']]) {
          if (b[key] === undefined) continue;
          if (!Array.isArray(b[key])) return err(400, 'בקשה לא תקינה');
          const list = b[key].slice(0, 500);
          for (const c of list) {
            if (!c || typeof c.id !== 'string' || c.id.length > 40 ||
                typeof c.label !== 'string' || c.label.length > 60) {
              return err(400, 'בקשה לא תקינה');
            }
            /* Only a mission carries a payload, and it is bounded here rather
               than trusted: this row is read by an endpoint with no login in
               front of it, so what can be stored decides what can be served. */
            if (c.data !== undefined && (typeof c.data !== 'string' || c.data.length > 2000)) {
              return err(400, 'בקשה לא תקינה');
            }
          }
          lists[kind] = list;
        }
        if (!Object.keys(lists).length) return err(400, 'בקשה לא תקינה');
        let n = 0;
        for (const [kind, list] of Object.entries(lists)) {
          await db.prepare('DELETE FROM pub_pick WHERE kind = ?1').bind(kind).run();
          for (let i = 0; i < list.length; i += 1) {
            await db
              .prepare('INSERT OR REPLACE INTO pub_pick (kind, id, label, sort, updated_at, data) VALUES (?1, ?2, ?3, ?4, ?5, ?6)')
              .bind(kind, list[i].id, list[i].label, i, now, list[i].data ?? null)
              .run();
          }
          n += list.length;
        }
        return json({ ok: true, n });
      }

      // PUT /api/admin/vault/:part — one domain of the vault.
      //
      // The version check is per part, which is the whole point: an admin
      // saving vehicles is no longer refused because someone else saved
      // ammunition a minute ago. Same envelope, same blindness — the server
      // knows a part changed and when, never what is in it.
      if (seg[1] === 'vault' && seg.length === 3 && method === 'PUT') {
        const part = seg[2];
        if (!VAULT_PARTS.includes(part)) return err(400, 'בקשה לא תקינה');
        const b = await readBody(request);
        if (!b) return err(400, 'בקשה לא תקינה');
        const { ek, iv, ct } = b;
        if (!isB64(ek, 1000) || !isB64(iv, 64) || !isB64(ct, VAULT_PART_MAX_B64)) {
          return err(400, 'בקשה לא תקינה');
        }
        const cur = await db
          .prepare('SELECT updated_at FROM vault_parts WHERE part = ?1')
          .bind(part)
          .first();
        if (cur && b.baseVersion === undefined) {
          return err(400, 'חסרה גרסת בסיס — רעננו לפני השמירה');
        }
        if (cur && Number(b.baseVersion) !== cur.updated_at) {
          return json(
            { error: 'החלק הזה עודכן בינתיים על ידי מנהל אחר — רעננו לפני השמירה', part, current: cur.updated_at },
            409
          );
        }
        await db
          .prepare(
            `INSERT INTO vault_parts (part, ek, iv, ct, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(part) DO UPDATE SET ek = ?2, iv = ?3, ct = ?4, updated_at = ?5`
          )
          .bind(part, ek, iv, ct, now)
          .run();
        await audit(db, now, session, 'vault', part, `${ct.length} תווים`);
        return json({ ok: true, updatedAt: now });
      }

      if (seg[1] === 'vault' && seg.length === 2) {
        if (method === 'GET') {
          const v = await db
            .prepare('SELECT ek, iv, ct, updated_at FROM vault WHERE id = 1')
            .first();
          // Both, always: the parts for a client that understands them, and
          // the old blob for one that does not — and for the first new client
          // to sign in, which is what turns one into the other.
          const parts = await db
            .prepare('SELECT part, ek, iv, ct, updated_at FROM vault_parts')
            .all()
            .catch(() => ({ results: [] }));
          return json({ vault: v || null, parts: (parts && parts.results) || [] });
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
          // Once the vault has been split, this row is a copy and not the
          // record. A client still running the pre-split code would write its
          // work here and nowhere else, and no one would ever read it again —
          // so it is refused, loudly, rather than accepted and lost. The new
          // client's own shadow write says `force` and is let through.
          const split = await db
            .prepare('SELECT COUNT(*) AS n FROM vault_parts')
            .first()
            .catch(() => ({ n: 0 }));
          if (split && split.n > 0 && b.force !== true) {
            return err(409, 'המערכת עודכנה — רעננו את הדף לפני השמירה כדי לא לאבד את השינוי');
          }
          if (b.force === true) {
            await db
              .prepare(
                `INSERT INTO vault (id, ek, iv, ct, updated_at) VALUES (1, ?1, ?2, ?3, ?4)
                 ON CONFLICT(id) DO UPDATE SET ek = ?1, iv = ?2, ct = ?3, updated_at = ?4`
              )
              .bind(ek, iv, ct, now)
              .run();
            return json({ ok: true, updatedAt: now });
          }
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

      // GET /api/admin/records[?since=<ms>]
      //
      // Without `since`, everything — opening the console, or asking for a
      // clean slate. With it, only what has moved, which is what the console
      // asks for every few seconds while it is open. During a sign-out the
      // whole set used to come down the wire each time any one soldier
      // pressed send; now one submission costs one row.
      //
      // `gone` is the other half: a soft-deleted row simply stops appearing,
      // and a client holding it would never learn it had gone. Deletions are
      // reported by their own clock, so a delete is never missed because the
      // row it removed was old.
      if (seg[1] === 'records' && seg.length === 2 && method === 'GET') {
        const since = Number(url.searchParams.get('since'));
        const cols = 'rid, ek, iv, ct, status, created_at, updated_at';
        if (Number.isFinite(since) && since > 0) {
          const { results } = await db
            .prepare(`SELECT ${cols} FROM records WHERE deleted_at IS NULL AND updated_at >= ?1 ORDER BY created_at`)
            .bind(since)
            .all();
          const gone = await db
            .prepare('SELECT rid FROM records WHERE deleted_at IS NOT NULL AND deleted_at >= ?1')
            .bind(since)
            .all();
          return json({ records: results, gone: (gone.results || []).map((r) => r.rid), partial: true });
        }
        const { results } = await db
          .prepare(`SELECT ${cols} FROM records WHERE deleted_at IS NULL ORDER BY created_at`)
          .all();
        return json({ records: results });
      }

      // There was a POST /api/admin/notify here: the Worker calling Meta's
      // WhatsApp Cloud API so an approval message went out by itself. It is
      // gone. Automatic delivery needs a business registration this unit
      // cannot obtain, so the route never sent a message — it answered
      // 'not_configured' to every approval. It was also the only place where a
      // name, a phone number and an equipment list passed through this server
      // in the clear, and the only outbound call to a third party. The console
      // opens WhatsApp on the admin's own device instead, which reveals
      // nothing to anyone.

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
          /* Read the status before writing it, because the log is about what
             happened and not about what the request said.

             This used to call every save of an approved record an approval —
             the request carries `status: 'approved'` whether it is approving a
             pending soldier or correcting a licence on one approved in July,
             and the trail said "אישור רשומה" for both. An action log that
             cannot tell an approval from an edit is not much of an action log,
             and it was quietly wrong on every correction ever made. */
          const before = await db
            .prepare('SELECT status FROM records WHERE rid = ?1')
            .bind(rid)
            .first();
          const approving = status === 'approved' && (!before || before.status !== 'approved');

          const r = await db
            .prepare(
              'UPDATE records SET ek = ?1, iv = ?2, ct = ?3, status = ?4, updated_at = ?5 WHERE rid = ?6'
            )
            .bind(ek, iv, ct, status, now, rid)
            .run();
          if (!r.meta.changes) return err(404, 'הרשומה לא נמצאה');
          // An admin correction may have changed the numbers, and approving
          // moves them from 'pending' to 'with a soldier'. The console has
          // already refused a duplicate, so a clash here is a race — and the
          // record is written either way; only the claim is reported.
          const held = await claimSerials(db, b.tags, 'record', rid, status === 'approved' ? 'approved' : 'pending', now);
          await audit(db, now, session, approving ? 'approve' : 'update', rid,
                      approving ? null : auditNote(b.note));
          if (held && !held.bad) {
            return err(409, `${FIELD_HE[held.field]} כבר קיים במערכת (${STATE_HE[held.state] || held.state})`);
          }
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
          await releaseSerials(db, 'record', rid);   // the numbers are free again
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
        // updated_at moves too, or a console that only asks for what changed
        // would never hear that this came back.
        const r = await db
          .prepare(`UPDATE ${table} SET deleted_at = NULL, updated_at = ?2 WHERE ${col} = ?1 AND deleted_at IS NOT NULL`)
          .bind(id, now)
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

      /* ── /api/admin/wa/* — WhatsApp through GREEN-API ─────────────
         A hosted service runs the browser and the session; we only ask it
         things. That is the whole reason it is here: the same job on our own
         machine needed a browser we could not afford to run.

         Three calls and no more. The token is a Pages secret and never
         reaches a browser — the console asks, this signs nothing and stores
         nothing, and the recipient's number and the message text pass through
         on their way out and are not written down on this side: not to D1,
         not to a log line. They are, however, read by GREEN-API, which is the
         cost of not owning the machine. */
      /* ── The official Cloud API ──────────────────────────────────────
         Meta's own platform, beside the gateway rather than instead of it.
         Everything personal that comes back from here is sealed on arrival
         by the webhook, so these endpoints hand the console ciphertext and
         the console opens it — the same shape as every other read in this
         file. The access token is never among the things returned. */
      if (seg[1] === 'wa' && seg[2] === 'cloud' && seg.length >= 4) {
        if (session.role !== 'admin') return err(403, 'אין הרשאה');
        const act = seg[3];

        // GET /api/admin/wa/cloud/status
        if (method === 'GET' && act === 'status' && seg.length === 4) {
          const { cfg, client, paused } = await waCloudContext(db, env);
          if (!cfg.ready) {
            return json({
              ready: false, missing: cfg.missing, paused,
              version: cfg.version, phoneNumberId: cfg.phoneNumberId || null,
              wabaId: cfg.wabaId || null,
              templates: cfg.templates, templateLang: cfg.templateLang,
            });
          }
          /* Two questions worth answering on a diagnostics screen, and both
             are questions about identity: is this the number I think it is,
             and is it on the account I think it is. Answered by asking Meta,
             because the alternative is trusting the same environment
             variable that would be wrong. */
          const [num, waba] = await Promise.all([client.getPhoneNumber(), client.listWabaNumbers()]);
          const listed = (waba.ok && waba.data && Array.isArray(waba.data.data) ? waba.data.data : [])
            .map((n) => ({ id: String(n.id || ''), display: String(n.display_phone_number || '') }));
          return json({
            ready: true, paused, version: cfg.version,
            wabaId: cfg.wabaId,
            phoneNumberId: cfg.phoneNumberId,
            reachable: num.ok,
            error: num.ok ? null : userFacingMeta(num.err),
            phone: num.ok && num.data ? {
              id: String(num.data.id || ''),
              display: String(num.data.display_phone_number || ''),
              name: String(num.data.verified_name || ''),
              quality: String(num.data.quality_rating || ''),
            } : null,
            // Does the configured number actually belong to the configured
            // account? A yes here is what rules out the duplicate WABA.
            onWaba: listed.some((n) => n.id === cfg.phoneNumberId),
            numbers: listed,
            pace: cfg.pace,
            templates: cfg.templates,
            templateLang: cfg.templateLang,
          }, num.ok ? 200 : 502);
        }

        // GET /api/admin/wa/cloud/templates — what Meta has actually approved
        if (method === 'GET' && act === 'templates' && seg.length === 4) {
          const cfg = waConfig(env);
          if (!cfg.ready) return json({ ready: false, missing: cfg.missing });
          const r = await waClient(cfg).listTemplates();
          if (!r.ok) return json({ ready: true, error: userFacingMeta(r.err) }, 502);
          const rows = (r.data && Array.isArray(r.data.data) ? r.data.data : []).map((t) => ({
            name: String(t.name || ''),
            status: String(t.status || ''),
            category: String(t.category || ''),
            language: String(t.language || ''),
            // How many {{n}} the body expects, so the console can ask for
            // exactly that many and not discover the mismatch from Meta.
            params: countTemplateParams(t.components),
          }));
          return json({ ready: true, templates: rows });
        }

        // GET /api/admin/wa/cloud/conversations
        if (method === 'GET' && act === 'conversations' && seg.length === 4) {
          const r = await listConversations(db, 60);
          return json({ conversations: (r && r.results) || [] });
        }

        // GET /api/admin/wa/cloud/messages/<conv>
        if (method === 'GET' && act === 'messages' && seg.length === 5) {
          if (!isHex(seg[4], HEX32)) return err(400, 'בקשה לא תקינה');
          const conv = await getConversation(db, seg[4]);
          if (!conv) return err(404, 'שיחה לא נמצאה');
          const r = await listMessages(db, seg[4], 200);
          return json({
            conv: {
              id: conv.id,
              windowExpires: conv.window_expires,
              lastInboundAt: conv.last_inbound_at,
              unread: conv.unread,
            },
            messages: (r && r.results) || [],
          });
        }

        // GET /api/admin/wa/cloud/media/<mediaId> — sealed bytes, never Meta's URL
        if (method === 'GET' && act === 'media' && seg.length === 5) {
          if (!/^[A-Za-z0-9_.-]{1,200}$/.test(seg[4])) return err(400, 'בקשה לא תקינה');
          const row = await getMediaRow(db, seg[4]);
          if (!row) return err(404, 'המדיה אינה שמורה');
          return json({ mime: row.mime, bytes: row.bytes, ek: row.ek, iv: row.iv, ct: row.ct });
        }

        // POST /api/admin/wa/cloud/read/<conv>
        if (method === 'POST' && act === 'read' && seg.length === 5) {
          if (!isHex(seg[4], HEX32)) return err(400, 'בקשה לא תקינה');
          await clearUnread(db, seg[4]);
          return json({ ok: true });
        }

        /* "Has this exact message already gone to this soldier."
           Built for the gateway, and the reason for it never had anything to
           do with which channel carries the text: a double press, a loop or
           a queued job that ran twice sends the same sentence again, and two
           identical messages are what a recipient reports. The key is the
           record id and the message kind — identifiers only, no name, no
           number, no text — and it is recorded only once the send succeeded,
           so a failure does not block the retry that would deliver. */
        const dupKey = async (b) => {
          const k = typeof b.key === 'string' && /^[0-9a-f]{32}:(notified|returnNotified)$/.test(b.key)
            ? `wa:sent:${b.key}` : '';
          if (!k || b.resend === true) return { k, blocked: false };
          const seen = await db.prepare('SELECT until FROM throttle WHERE k = ?1').bind(k).first();
          return { k, blocked: !!(seen && seen.until > now) };
        };

        // POST /api/admin/wa/cloud/send — free text, inside the window only
        if (method === 'POST' && act === 'send' && seg.length === 4) {
          const b = await readBody(request);
          if (!b) return err(400, 'בקשה לא תקינה');
          const dup = await dupKey(b);
          if (dup.blocked) {
            return json({ duplicate: true, error: 'ההודעה הזו כבר נשלחה לחייל הזה. לשליחה חוזרת — דרך פירוט הרשומה' }, 409);
          }
          const r = await sendTextMessage(db, env, b.to, b.text, {
            replyTo: typeof b.replyTo === 'string' ? b.replyTo.slice(0, 200) : undefined,
          });
          if (dup.k && r.ok) await waBump(db, dup.k, 604800000, now);
          await audit(db, now, session, 'wa-cloud-send', null, null);
          return json(r, r.ok ? 200 : (r.status || 502));
        }

        // POST /api/admin/wa/cloud/template — the business-initiated path
        if (method === 'POST' && act === 'template' && seg.length === 4) {
          const b = await readBody(request);
          if (!b) return err(400, 'בקשה לא תקינה');
          const dup = await dupKey(b);
          if (dup.blocked) {
            return json({ duplicate: true, error: 'ההודעה הזו כבר נשלחה לחייל הזה. לשליחה חוזרת — דרך פירוט הרשומה' }, 409);
          }
          const r = await sendTemplateMessage(db, env, b.to, b.name, b.language, b.components, {
            replyTo: typeof b.replyTo === 'string' ? b.replyTo.slice(0, 200) : undefined,
          });
          if (dup.k && r.ok) await waBump(db, dup.k, 604800000, now);
          await audit(db, now, session, 'wa-cloud-template', null, null);
          return json(r, r.ok ? 200 : (r.status || 502));
        }

        return err(404, 'נתיב לא קיים');
      }

      if (seg[1] === 'wa' && seg.length === 3) {
        /* The emergency stop. Read before anything else on this path, and
           held on the server rather than in a tab: a pause that lives in a
           browser is not a pause — reload it and sending resumes, and a
           second console never knew about it. Pausing takes one press
           because the moment you want it is not the moment for a dialogue;
           resuming is the direction that asks. */
        const paused = async () => {
          const row = await db.prepare('SELECT wa_paused FROM config WHERE id = 1').first();
          return !!(row && row.wa_paused);
        };
        if (method === 'POST' && (seg[2] === 'pause' || seg[2] === 'resume')) {
          if (session.role !== 'admin') return err(403, 'אין הרשאה');
          const on = seg[2] === 'pause' ? 1 : 0;
          await db.prepare('UPDATE config SET wa_paused = ?1 WHERE id = 1').bind(on).run();
          await audit(db, now, session, on ? 'wa-pause' : 'wa-resume', null, null);
          return json({ ok: true, paused: !!on });
        }

        const base = (env.GREEN_API_URL || '').replace(/\/+$/, '');
        const id = env.GREEN_ID || '';
        const token = env.GREEN_TOKEN || '';
        if (!base || !id || !token) {
          /* Not configured is a normal state: the wa.me links carry on. Which
             of the three is missing is the whole diagnosis, though — saying
             "one of these three" sends someone to check all three, and two of
             them live in wrangler.toml while the third is a Pages secret, set
             a different way. Names only; a value never leaves this side. */
          const missing = [
            !base && 'GREEN_API_URL', !id && 'GREEN_ID', !token && 'GREEN_TOKEN',
          ].filter(Boolean);
          if (method === 'GET') return json({ enabled: false, missing, paused: await paused() });
          return err(503, 'שירות הוואטסאפ אינו מוגדר');
        }
        const call = async (path, init) => {
          try {
            const r = await fetch(`${base}/waInstance${id}/${path}/${token}`, {
              ...init,
              signal: AbortSignal.timeout(20000),
            });
            const text = await r.text();
            let data;
            try { data = JSON.parse(text); } catch { data = null; }
            return { ok: r.ok, status: r.status, data, text };
          } catch {
            return { ok: false, status: 0, data: null, text: '' };
          }
        };

        /* What the provider actually said, safe to put on a screen.
           Any long run of letters and digits is replaced before it leaves
           here: the service does not echo the token in its errors, but a
           diagnostic that could ever print a secret is not one worth having.
           Trimmed hard, because this is a hint under a sentence, not a log. */
        const waSaid = (t) =>
          String(t || '').replace(/[A-Za-z0-9]{20,}/g, '…').replace(/\s+/g, ' ').trim().slice(0, 180);

        /* The shape of the request, with the token replaced by a description
           of itself. Length and character class are not the secret, and they
           answer the two questions a wrong token actually raises: is anything
           there at all, and did a newline or a space come along with it. */
        const waShape = (method) => ({
          url: `${base}/waInstance${id}/${method}/<token>`,
          tokenLen: token.length,
          tokenPlain: /^[A-Za-z0-9]+$/.test(token),
        });

        /* Six different faults used to arrive on the screen as one sentence,
           "השירות אינו מגיב", and somebody stood in front of a console that
           would not say which. The code the provider answered with is the
           whole diagnosis, and the commonest one by far — a token that still
           belongs to the previous instance — is a sentence, not a mystery.

           The instance id is named in the answer because it is not a secret
           and because the mistake is almost always that the two do not match.
           The token never appears, in the answer or in a log line: it is in
           the URL, so the URL is never one either. */
        const waWhy = (r) =>
          r.status === 401 || r.status === 403
            /* Measured against the real service, not guessed: 7107.api.greenapi.com
               answers 401 both for a token that does not match the instance and
               for an instance that does not exist. One code, two causes — so the
               sentence names both, likeliest first, and prints the id it is
               actually using so the second can be ruled out by looking. */
            ? `הספק דחה את הפנייה (401). כמעט תמיד: GREEN_TOKEN אינו הטוקן של מופע ${id}. אותו קוד חוזר גם אם המזהה עצמו שגוי — ${id} הוא מה שמוגדר כאן`
            : r.status === 404
              ? `הספק לא מכיר את הנתיב — בדקו את GREEN_API_URL`
              : r.status === 429
                ? 'הספק מגביל את קצב הפניות. המתינו רגע ונסו שוב'
                : r.status === 0
                  ? 'אין תשובה מהספק — פסק זמן או תקלת רשת'
                  : r.status >= 500
                    ? `הספק החזיר שגיאה (${r.status}) — תקלה בצד שלו`
                    : `הספק החזיר ${r.status}`;

        if (method === 'GET' && seg[2] === 'status') {
          const r = await call('getStateInstance');
          if (!r.ok) {
            console.error('wa status', r.status, waSaid(r.text));   // no URL: the URL carries the token
            return json({
              enabled: true, reachable: false, instance: id, providerStatus: r.status,
              error: waWhy(r), said: waSaid(r.text), shape: waShape('getStateInstance'),
              // the switch has to be visible even when the line is not
              paused: await paused(),
            }, 502);
          }
          const state = (r.data && r.data.stateInstance) || 'unknown';
          const pace = waPace(env);
          /* What is left of the hour and the day, so the screen can say it
             before somebody presses approve on twenty rows rather than
             after. Counting is free — reading the same rows the send path
             writes — and asking the provider is not, so only the state that
             carries a deadline asks. */
          const budget = {
            gapMs: pace.gapMs,
            hourMax: pace.hourMax,
            dayMax: pace.dayMax,
            hour: await waCount(db, 'wa:hour', now),
            day: await waCount(db, 'wa:day', now),
          };
          /* suspended is WhatsApp's own word: the number may still answer
             and reply, but may not open a new chat — which is every message
             this system sends. It lifts by itself, and the only fact worth
             having is when. */
          let until = null;
          if (state === 'suspended') {
            const w = await call('getWaSettings');
            const raw = w.ok && w.data && w.data.suspendedUntil;
            const n = Number(raw);
            // unix seconds at the provider, milliseconds everywhere here
            if (n > 0) until = n < 1e12 ? n * 1000 : n;
          }
          // The instance id is not a secret, and "which instance is this
          // talking to" is the question standing behind most of the faults
          // above — so the screen gets to show it.
          return json({
            enabled: true, reachable: true, instance: id, state, budget,
            suspendedUntil: until, paused: await paused(),
          });
        }

        if (method === 'GET' && seg[2] === 'qr') {
          const r = await call('qr');
          if (!r.ok) {
            console.error('wa qr', r.status, waSaid(r.text));
            return json({
              enabled: true, reachable: false, instance: id, providerStatus: r.status,
              error: waWhy(r), said: waSaid(r.text), shape: waShape('qr'),
              paused: await paused(),
            }, 502);
          }
          // { type: 'qrCode' | 'alreadyLogged' | 'error', message: <base64 png | text> }
          return json({ enabled: true, reachable: true, ...(r.data || {}) });
        }

        if (method === 'POST' && seg[2] === 'send') {
          const b = await readBody(request);
          if (!b) return err(400, 'בקשה לא תקינה');
          const digits = String(b.phone || '').replace(/\D/g, '');
          const text = String(b.message || '');
          // Israeli local (0xx…) to international, since that is what the
          // console holds and what the service expects.
          const intl = digits.startsWith('0') ? `972${digits.slice(1)}` : digits;
          if (!/^\d{9,15}$/.test(intl)) return err(400, 'מספר טלפון לא תקין');
          if (!text.trim() || text.length > 1200) return err(400, 'הודעה ריקה או ארוכה מדי');
          if (await paused()) {
            return json({ paused: true, error: 'שליחת הוואטסאפ מושהית. בטלו את ההשהיה במסך וואטסאפ' }, 503);
          }

          /* "Was this exact message already sent." The tick on the row says a
             message went out, but it only describes what happened — it never
             stopped anything, so a loop, a double press, or the same job
             queued twice sent the soldier the same sentence again. Two
             identical messages are what spam detection is built to notice,
             and the soldier who gets them is the one who presses report.

             The key is the record id and the kind of message, both
             identifiers — no name, no number, no text, the same rule the
             audit table follows. Seven days: long enough to catch a bug that
             surfaces tomorrow.

             A deliberate second send says so, and the console only says so
             from the one control that asks first. */
          const key = typeof b.key === 'string' && /^[0-9a-f]{32}:(notified|returnNotified)$/.test(b.key)
            ? `wa:sent:${b.key}` : '';
          if (key && b.resend !== true) {
            const seen = await db.prepare('SELECT until FROM throttle WHERE k = ?1').bind(key).first();
            if (seen && seen.until > now) {
              return json({
                duplicate: true,
                error: 'ההודעה הזו כבר נשלחה לחייל הזה. לשליחה חוזרת — דרך פירוט הרשומה',
              }, 409);
            }
          }
          /* The gate, before the provider is touched. A refused send is not
             an error to be retried in a loop — it is the wa.me path, and the
             answer says how long until the line is free so the caller can
             wait rather than hammer. 429 rather than 503: the request was
             fine, the rate was not. */
          const pace = waPace(env);
          const gap = await waGapClaim(db, now, pace.gapMs);
          if (!gap.ok) {
            return json({
              paced: 'gap', waitMs: gap.waitMs,
              error: `הקו שולח הודעה אחת כל ${Math.round(pace.gapMs / 1000)} שניות — עוד ${Math.ceil(gap.waitMs / 1000)} שניות`,
            }, 429);
          }
          const hour = await waCount(db, 'wa:hour', now);
          const day = await waCount(db, 'wa:day', now);
          if (day >= pace.dayMax) {
            return json({
              paced: 'day', waitMs: await waUntil(db, 'wa:day', now),
              error: `נשלחו היום ${day} הודעות מהקו — זו התקרה. שלחו את השאר ידנית, או המתינו למחר`,
            }, 429);
          }
          if (hour >= pace.hourMax) {
            return json({
              paced: 'hour', waitMs: await waUntil(db, 'wa:hour', now),
              error: `נשלחו בשעה האחרונה ${hour} הודעות מהקו — זו התקרה. שלחו את השאר ידנית, או המתינו`,
            }, 429);
          }
          await waBump(db, 'wa:hour', 3600000, now);
          await waBump(db, 'wa:day', 86400000, now);
          const r = await call('sendMessage', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chatId: `${intl}@c.us`, message: text }),
          });
          // Recorded only once the provider took it: a message that failed
          // must not block the retry that would actually deliver it.
          if (key && r.ok) await waBump(db, key, 604800000, now);
          // The number and the text are deliberately absent from the trail.
          await audit(db, now, session, 'wa-send', null, null);
          if (!r.ok) return json({ enabled: true, reachable: false, error: 'השליחה נכשלה' }, 502);
          return json({ enabled: true, reachable: true, id: (r.data && r.data.idMessage) || null });
        }

        return err(404, 'נתיב לא קיים');
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
      //
      // Every table that belongs to the old keypair, not only the ones that
      // existed when this was written. A wipe is followed by a fresh setup
      // with a new key, so anything left behind sealed under the old one can
      // never be opened again: the vault parts came back as ten undecryptable
      // rows, and the published pick-lists went on offering cards nobody
      // holds. The blind indexes were worse than useless — a serial tag with
      // no record behind it tells the next soldier their weapon is already
      // registered, to a slip that no longer exists. The audit trail stays: it
      // is not sealed, it names nobody, and the wipe itself is the entry most
      // worth keeping.
      if (seg[1] === 'wipe' && seg.length === 2 && method === 'POST') {
        await audit(db, now, session, 'wipe', null, null);
        await db.batch([
          db.prepare('DELETE FROM records'),
          db.prepare('DELETE FROM docs'),
          db.prepare('DELETE FROM reports'),
          db.prepare('DELETE FROM vault'),
          db.prepare('DELETE FROM vault_parts'),
          db.prepare('DELETE FROM pub_pick'),
          db.prepare('DELETE FROM serial_tags'),
          db.prepare('DELETE FROM tickets'),
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
    /* The client is told nothing beyond "שגיאת שרת" — it is a stranger and an
       exception text is a map of the inside. But this used to be told to
       nobody at all, which meant a 500 seen on a phone could not be explained
       afterwards: Cloudflare keeps no request log of its own here, so the only
       account of what broke was the one we threw away. Now it goes to the
       stream `wrangler pages deployment tail` reads.

       What is logged is deliberately thin: the method, the route family, and
       the error with its stack. No body, no path tail, no headers — the stack
       already names the line, which identifies the route more precisely than
       the URL would, and none of the three can carry a soldier's details. */
    console.error('api 500', method, seg[0] || '/', seg.length, e && e.message, e && e.stack);
    return err(500, 'שגיאת שרת');
  }
}
