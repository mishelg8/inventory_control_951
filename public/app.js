'use strict';

/* ════════════════════════════════════════════════════════════════════
   החתמת ציוד — client logic. All plaintext personal data lives only in
   this browser's memory; everything sent to the server is ciphertext or
   a one-way derivation. See PLAN.md §4 for the cryptographic design.
   ════════════════════════════════════════════════════════════════════ */

const $app = document.getElementById('app');
const $toast = document.getElementById('toast');
const te = new TextEncoder();
const td = new TextDecoder();

/* ── Equipment catalog ─────────────────────────────────────────────── */

const SVG_OPEN =
  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" ' +
  'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">';

// Every item is quantifiable — a soldier can receive 2 vests, 3 magazines, etc.
const ITEMS = [
  {
    id: 'helmet', name: 'קסדה', qty: true, min: 1, max: 10,
    icon: `${SVG_OPEN}<path d="M4 14a8 8 0 0 1 16 0v3H4z"/><path d="M2 17h20"/></svg>`,
  },
  {
    id: 'vest', name: 'ווסט', qty: true, min: 1, max: 10,
    icon: `${SVG_OPEN}<path d="M8 3c1 1.8 7 1.8 8 0l4 4-2.5 3v10h-11V10L4 7z"/><path d="M6.5 14h11"/></svg>`,
  },
  {
    id: 'mitznefet', name: 'מצנפת', qty: true, min: 1, max: 10,
    icon: `${SVG_OPEN}<path d="M5 15c0-6 3-10 7-10s7 4 7 10c-2.5-1.5-4.5 1.5-7 .5s-4.5 1-7-.5z"/><path d="M9 19h6"/></svg>`,
  },
  {
    id: 'knee', name: 'ברכיות', qty: true, min: 1, max: 10,
    icon: `${SVG_OPEN}<rect x="6.5" y="3.5" width="11" height="17" rx="5.5"/><path d="M6.5 12h11"/></svg>`,
  },
  {
    id: 'mags', name: 'מחסניות', qty: true, min: 1, max: 20,
    icon: `${SVG_OPEN}<path d="M9 3h7c-.5 6-1.5 11-3.5 17H7C7.5 14 8.5 9 9 3z"/><path d="M9.5 7h6"/></svg>`,
  },
];
const itemById = (id) => ITEMS.find((i) => i.id === id);

/* ── Departments ───────────────────────────────────────────────────── */

const DEPTS = [
  { id: 'p1', name: 'מחלקה 1' },
  { id: 'p2', name: 'מחלקה 2' },
  { id: 'p3', name: 'מחלקה 3' },
  { id: 'mplag', name: 'מפל״ג' },
  { id: 'attached', name: 'מסופחים' },
];
const deptName = (id) => (DEPTS.find((d) => d.id === id) || {}).name || 'ללא שיוך';

/* ── Small helpers ─────────────────────────────────────────────────── */

const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[c]);

function b64(buf) {
  const u = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < u.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

function ub64(s) {
  const bin = atob(s);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}

const hex = (buf) =>
  [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

const fmtDate = (ts) =>
  ts ? new Date(ts).toLocaleString('he-IL', { dateStyle: 'short', timeStyle: 'short' }) : '—';

const maskPhone = (p) => (p && p.length >= 6 ? p.slice(0, 3) + '•••' + p.slice(-3) : '•••');

let toastTimer = null;
function toast(msg, isErr) {
  $toast.textContent = msg;
  $toast.classList.toggle('err', !!isErr);
  $toast.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { $toast.hidden = true; }, 3200);
}

/* ── API client ────────────────────────────────────────────────────── */

async function api(path, opts = {}) {
  const init = { method: opts.method || (opts.body !== undefined ? 'POST' : 'GET'), headers: {} };
  if (opts.body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(opts.body);
  }
  if (opts.headers) Object.assign(init.headers, opts.headers);
  let r;
  try {
    r = await fetch('/api' + path, init);
  } catch {
    throw new Error('שגיאת רשת — בדקו את החיבור');
  }
  let data = null;
  try { data = await r.json(); } catch { /* non-JSON body */ }
  if (!r.ok) {
    const e = new Error((data && data.error) || 'שגיאה בשרת');
    e.status = r.status;
    throw e;
  }
  return data;
}

/* ── Cryptography (PLAN §4) ────────────────────────────────────────── */

// One PBKDF2 pass, split output: KEK (encryption half) + verifier (auth half).
async function deriveAuth(password, saltB64) {
  const km = await crypto.subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: ub64(saltB64), iterations: 310000, hash: 'SHA-256' }, km, 512
  ));
  const kek = await crypto.subtle.importKey('raw', bits.slice(0, 32), 'AES-GCM', false, ['encrypt', 'decrypt']);
  const verifier = hex(await crypto.subtle.digest('SHA-256', bits.slice(32)));
  bits.fill(0);
  return { kek, verifier };
}

// Record identifier: slow-KDF mask of the personal number (§4.6).
async function deriveRid(pn, idSaltB64) {
  const km = await crypto.subtle.importKey('raw', te.encode(pn), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: ub64(idSaltB64), iterations: 60000, hash: 'SHA-256' }, km, 256
  );
  return hex(bits).slice(0, 32);
}

const importPubKey = (jwk) =>
  crypto.subtle.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);

// Seal: fresh content key per write, wrapped under the public key (§4.4).
async function seal(pubKey, payload) {
  const cek = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const rawCek = await crypto.subtle.exportKey('raw', cek);
  const ek = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pubKey, rawCek);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cek, te.encode(JSON.stringify(payload)));
  return { ek: b64(ek), iv: b64(iv), ct: b64(ct) };
}

/* ── Trust boundary ────────────────────────────────────────────────────
   The RSA public key is public by design — that is what lets any soldier
   submit without an account. The consequence is that ANYONE can encrypt an
   arbitrary payload and POST it, so a decrypted record is untrusted input,
   not our own data. Everything below coerces a payload to the shape the UI
   expects: strings are capped, numbers are real finite numbers, ids are
   whitelisted. Without this, a crafted quantity like "<img …>" flows into
   innerHTML in the admin console — where the private key lives.
   ──────────────────────────────────────────────────────────────────── */

const asText = (v, max) => (typeof v === 'string' ? v.slice(0, max) : '');

// Non-negative integer, or 0. Rejects strings, NaN, Infinity, negatives.
const asCount = (v, max = 9999) => {
  const n = typeof v === 'number' ? v : NaN;
  if (!Number.isFinite(n)) return 0;
  return Math.min(max, Math.max(0, Math.floor(n)));
};

const asTime = (v) => (Number.isFinite(v) && v > 0 ? v : null);

function cleanRecord(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('bad payload');
  const items = {};
  const rawItems = raw.items && typeof raw.items === 'object' ? raw.items : {};
  for (const item of ITEMS) {                       // whitelist: unknown ids dropped
    const it = rawItems[item.id];
    if (!it || typeof it !== 'object') continue;
    const t = asCount(it.t, item.max || 9999);
    if (t <= 0) continue;
    items[item.id] = { t, r: Math.min(t, asCount(it.r)) };   // returned never exceeds taken
  }

  const lic = {};
  for (const k of LIC_KINDS) {
    const l = raw.lic && typeof raw.lic === 'object' ? raw.lic[k.id] : null;
    if (!l || typeof l !== 'object' || !l.has) continue;
    lic[k.id] = { has: true, doc: !!l.doc };
    if (k.id === 'civil') {
      lic.civil.no = asText(l.no, 20);
      // only an ISO date is ever accepted; anything else is dropped
      lic.civil.exp = /^\d{4}-\d{2}-\d{2}$/.test(l.exp) ? l.exp : '';
    }
  }

  return {
    pn: asText(raw.pn, 9),
    name: asText(raw.name, 60),
    phone: asText(raw.phone, 15),
    dept: DEPTS.some((d) => d.id === raw.dept) ? raw.dept : '',
    weapon: asText(raw.weapon, 20),
    items,
    ...(Object.keys(lic).length ? { lic } : {}),
    createdAt: asTime(raw.createdAt) || Date.now(),
    approvedAt: asTime(raw.approvedAt),
    notified: asTime(raw.notified),
    returnNotified: asTime(raw.returnNotified),
    supp: !!raw.supp,
    log: Array.isArray(raw.log) ? raw.log.slice(-50) : [],
  };
}

function cleanReport(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('bad payload');
  return {
    name: asText(raw.name, 60),
    text: asText(raw.text, 1500),
    // legacy reports carried identity fields; keep them if present
    pn: asText(raw.pn, 9),
    phone: asText(raw.phone, 15),
    dept: DEPTS.some((d) => d.id === raw.dept) ? raw.dept : '',
    createdAt: asTime(raw.createdAt) || Date.now(),
  };
}

/* ── Armoury domain ────────────────────────────────────────────────── */

const ARM_KINDS = [
  { id: 'weapon', name: 'נשק' },
  { id: 'tzelem', name: 'צל״ם' },
];
const ARM_LOCS = [
  { id: 'armon', name: 'ארמון' },
  { id: 'soldier', name: 'אצל חייל' },
  { id: 'mission', name: 'במשימה' },
];
// where an item goes when it leaves the armoury for good
const AMMO_DESTS = [
  { id: 'mission', name: 'משימה' },
  { id: 'soldier', name: 'חייל' },
  { id: 'credit', name: 'זיכוי' },
];
const ARM_DESTS = [
  { id: 'soldier', name: 'חייל' },
  { id: 'repair', name: 'תיקון' },
  { id: 'credit', name: 'זיכוי' },
];
const nameOf = (list, id) => (list.find((x) => x.id === id) || {}).name || '—';

const cleanArmItem = (x) => ({
  id: asText(x && x.id, 40) || rndId(),
  kind: ARM_KINDS.some((k) => k.id === (x && x.kind)) ? x.kind : 'weapon',
  name: asText(x && x.name, 60),
  serial: asText(x && x.serial, 40),
  owner: asText(x && x.owner, 60),
  loc: ARM_LOCS.some((l) => l.id === (x && x.loc)) ? x.loc : 'armon',
  note: asText(x && x.note, 120),
  addedAt: asTime(x && x.addedAt),
});

const cleanArmLog = (x) => ({
  t: asTime(x && x.t),
  action: (x && x.action) === 'remove' ? 'remove' : 'add',
  kind: asText(x && x.kind, 20),
  name: asText(x && x.name, 60),
  serial: asText(x && x.serial, 40),
  owner: asText(x && x.owner, 60),
  dest: asText(x && x.dest, 20),
  note: asText(x && x.note, 120),
});

const cleanAmmo = (x) => ({
  id: asText(x && x.id, 40) || rndId(),
  name: asText(x && x.name, 60),
  qty: asCount(x && x.qty),
});

const cleanAmmoLog = (x) => ({
  t: asTime(x && x.t),
  action: (x && x.action) === 'issue' ? 'issue' : 'add',
  name: asText(x && x.name, 60),
  qty: asCount(x && x.qty),
  dest: asText(x && x.dest, 20),
  who: asText(x && x.who, 60),
});

const VEH_KIT = [
  { id: 'jack', name: 'ג׳ק' },
  { id: 'wrench', name: 'מפתח גלגלים' },
  { id: 'vest', name: 'אפודה זוהרת' },
  { id: 'triangle', name: 'משולש' },
  { id: 'checklist', name: 'צ׳קלקה' },
];

const cleanVehicle = (x) => {
  const v = {
    id: asText(x && x.id, 40) || rndId(),
    plate: asText(x && x.plate, 20),
    company: asText(x && x.company, 40),
    km: asCount(x && x.km, 9999999),
    service: asText(x && x.service, 10),
    note: asText(x && x.note, 120),
  };
  for (const k of VEH_KIT) v[k.id] = !!(x && x[k.id]);
  return v;
};

const rndId = () => hex(crypto.getRandomValues(new Uint8Array(8)));

function cleanInv(raw) {
  const src = raw && typeof raw === 'object' ? raw : {};
  const open = {};
  for (const item of ITEMS) open[item.id] = asCount(src.open && src.open[item.id]);
  const extra = (Array.isArray(src.extra) ? src.extra : []).slice(0, 200).map((x) => ({
    name: asText(x && x.name, 40),
    open: asCount(x && x.open),
    out: asCount(x && x.out),
  }));
  const arr = (v, fn, cap) => (Array.isArray(v) ? v : []).slice(0, cap).map(fn);
  const counted = src.countedAt && typeof src.countedAt === 'object' ? src.countedAt : {};
  return {
    open,
    extra,
    notes: asText(src.notes, 4000),
    armon: arr(src.armon, cleanArmItem, 4000),
    armonLog: arr(src.armonLog, cleanArmLog, 5000),
    ammo: arr(src.ammo, cleanAmmo, 1000),
    ammoLog: arr(src.ammoLog, cleanAmmoLog, 5000),
    vehicles: arr(src.vehicles, cleanVehicle, 500),
    countedAt: { tzelem: asTime(counted.tzelem), armon: asTime(counted.armon) },
    updatedAt: asTime(src.updatedAt),
  };
}

// Open: admin only (§4.5). Throws on tampered ciphertext — caller counts it.
// `clean` is the schema guard above; never skip it for attacker-writable data.
async function openRecord(privKey, rec, clean = cleanRecord) {
  const rawCek = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privKey, ub64(rec.ek));
  const cek = await crypto.subtle.importKey('raw', rawCek, 'AES-GCM', false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ub64(rec.iv) }, cek, ub64(rec.ct));
  return clean(JSON.parse(td.decode(pt)));
}

// Seals raw bytes rather than JSON — used for licence photos.
async function sealBytes(pubKey, bytes) {
  const cek = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const ek = await crypto.subtle.encrypt(
    { name: 'RSA-OAEP' }, pubKey, await crypto.subtle.exportKey('raw', cek)
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cek, bytes);
  return { ek: b64(ek), iv: b64(iv), ct: b64(ct) };
}

async function openBytes(privKey, rec) {
  const rawCek = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privKey, ub64(rec.ek));
  const cek = await crypto.subtle.importKey('raw', rawCek, 'AES-GCM', false, ['decrypt']);
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: ub64(rec.iv) }, cek, ub64(rec.ct));
}

/* ── Licence photos ────────────────────────────────────────────────── */

// Civilian licence is captured as typed fields (number + expiry) so the admin
// can actually sort and chase expiry dates; the military one stays a photo.
const LIC_KINDS = [
  { id: 'civil', label: 'רישיון נהיגה אזרחי בתוקף', short: 'רישיון אזרחי', mode: 'fields' },
  { id: 'military', label: 'רישיון נהיגה צבאי בתוקף', short: 'רישיון צבאי', mode: 'photo' },
];

const DAY_MS = 24 * 60 * 60 * 1000;
const EXPIRING_SOON_DAYS = 60;

// 'valid' | 'soon' | 'expired' | 'nodate' — drives the red/amber/green states.
function licState(expiry) {
  if (!expiry) return 'nodate';
  const t = Date.parse(`${expiry}T23:59:59`);
  if (Number.isNaN(t)) return 'nodate';
  const days = Math.floor((t - Date.now()) / DAY_MS);
  if (days < 0) return 'expired';
  return days <= EXPIRING_SOON_DAYS ? 'soon' : 'valid';
}

const fmtDay = (iso) => {
  if (!iso) return '';
  const d = new Date(`${iso}T12:00:00`);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleDateString('he-IL');
};

const DOC_MAX_BYTES = 280 * 1024;   // stays clear of the server's 400 KB b64 cap

// Downscale and re-encode a camera photo until it fits, keeping the licence
// text legible. Runs entirely on the soldier's device — the original file is
// never uploaded, only the compressed result, and only after encryption.
async function compressImage(file) {
  const dataUrl = await new Promise((res, rej) => {
    const fr = new FileReader();
    fr.onload = () => res(fr.result);
    fr.onerror = () => rej(new Error('קריאת הקובץ נכשלה'));
    fr.readAsDataURL(file);
  });
  const img = await new Promise((res, rej) => {
    const im = new Image();
    im.onload = () => res(im);
    im.onerror = () => rej(new Error('הקובץ אינו תמונה תקינה'));
    im.src = dataUrl;
  });

  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d');
  for (const [maxDim, quality] of [[1600, 0.8], [1400, 0.72], [1200, 0.65], [1000, 0.55], [800, 0.45]]) {
    const scale = Math.min(1, maxDim / Math.max(img.width, img.height));
    canvas.width = Math.round(img.width * scale);
    canvas.height = Math.round(img.height * scale);
    ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
    const blob = await new Promise((r) => canvas.toBlob(r, 'image/jpeg', quality));
    if (blob && blob.size <= DOC_MAX_BYTES) {
      return { bytes: new Uint8Array(await blob.arrayBuffer()), size: blob.size };
    }
  }
  throw new Error('התמונה גדולה מדי — נסו לצלם שוב מקרוב יותר');
}

/* ── State ─────────────────────────────────────────────────────────── */

function routeFromHash() {
  const h = location.hash;
  if (h === '#admin') return 'admin';
  if (h === '#report') return 'report';
  if (h === '#sign') return 'soldier';
  return 'home';   // the link a soldier is given lands on the chooser
}

const S = {
  config: null,                 // { ready, pub?, idSalt? }
  route: routeFromHash(),

  // shortage reporting (soldier-facing, separate flow)
  rep: null,                    // draft { pn, name, phone, dept, text }
  repSent: false,

  // soldier flow
  sStep: 1,
  ident: null,                  // { pn, name, phone, dept, weapon }
  rid: null,
  suppMode: false,              // main record approved → this is a supplement
  existingPending: false,
  sel: {},                      // itemId -> quantity
  lic: { civil: false, military: false },   // "I hold a valid licence" ticks
  licNo: '',                    // civilian licence number (typed, not OCR'd)
  licExp: '',                   // civilian licence expiry, ISO yyyy-mm-dd
  licPhoto: {},                 // kind -> { bytes, size, preview } pending upload

  // admin
  adminView: 'login',           // 'setup' | 'login' | 'console'
  priv: null,                   // CryptoKey (RSA private)
  pkcs8: null,                  // Uint8Array — kept for password rotation, zeroed on lock
  pubKey: null,                 // CryptoKey (RSA public, for re-sealing)
  recs: [],                     // { rid, status, created_at, updated_at, data|null, damaged }
  inv: null,                    // { open:{}, extra:[], notes } — decrypted inventory
  docs: {},                     // "rid:kind" -> data URL, fetched on demand
  reports: [],                  // { id, status, created_at, data|null, damaged }
  repFilter: 'open',            // 'open' | 'done' | 'all'
  repQ: '',                     // search over request name + body
  invQ: '',                     // search over the extra-inventory rows
  regQ: {},                     // section key -> search query
  armKind: 'all',               // armoury type filter
  tab: 'over',
  filter: 'out',
  q: '',                        // free-text search over name / pn / phone
  dept: 'all',                  // department filter
  collapsed: new Set(),         // department ids folded shut
  page: {},                     // list key -> current page index (0-based)
  revealed: new Set(),          // rids with phone shown
  busy: false,
};

const IDLE_MS = 10 * 60 * 1000;
let idleTimer = null;

function armIdle() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => {
    if (S.priv) { lock(); toast('המסך ננעל לאחר חוסר פעילות'); }
  }, IDLE_MS);
}

['pointerdown', 'keydown', 'wheel'].forEach((ev) =>
  window.addEventListener(ev, () => { if (S.priv) armIdle(); }, { passive: true })
);

function lock() {
  if (S.pkcs8) S.pkcs8.fill(0);
  S.pkcs8 = null;
  S.priv = null;
  S.pubKey = null;
  S.recs = [];
  S.inv = null;
  S.reports = [];
  S.docs = {};                  // decrypted licence images must not outlive the session
  S.q = '';
  S.repQ = '';
  S.invQ = '';
  S.regQ = {};
  S.revealed.clear();
  clearTimeout(idleTimer);
  api('/admin/logout', { method: 'POST', body: {} }).catch(() => {});
  if (S.route === 'admin') {
    S.adminView = S.config && S.config.ready ? 'login' : 'setup';
    renderRoute();
  }
}

function resetSoldier() {
  S.sStep = 1;
  S.ident = null;
  S.rid = null;
  S.suppMode = false;
  S.existingPending = false;
  S.sel = {};
  S.lic = { civil: false, military: false };
  S.licNo = '';
  S.licExp = '';
  S.licPhoto = {};
}

/* ── Rendering ─────────────────────────────────────────────────────── */

let lastRenderKey = '';

const render = (html, focusKey) => {
  $app.innerHTML = html;
  // On a genuine view change, put focus on the new heading. Re-renders of the
  // same view (typing in search, stepping a quantity) must NOT steal focus.
  if (focusKey && focusKey !== lastRenderKey) {
    lastRenderKey = focusKey;
    const h = $app.querySelector('h1, h2');
    if (h) { h.setAttribute('tabindex', '-1'); h.focus({ preventScroll: true }); }
  }
  // Setting .style via script is CSSOM, not an inline style attribute, so it
  // is allowed under style-src 'self'.
  for (const el of $app.querySelectorAll('.brk-fill[data-w], .minibar-fill[data-w]')) {
    el.style.width = `${el.dataset.w}%`;
  }
};

function renderRoute() {
  // the console needs a wide column for tables; soldier pages stay narrow
  $app.classList.toggle('wide', S.route === 'admin' && !!S.priv);
  if (S.route === 'admin') renderAdmin();
  else if (S.route === 'report') renderReport();
  else if (S.route === 'home') renderHome();
  else renderSoldier();
}

/* ── Landing: what does the soldier want to do? ────────────────────── */

function renderHome() {
  render(`
    <section class="panel center-head hero">
      <img class="unit-badge" src="/logo.png" alt="סמל מסייעת 951">
      <h1 class="panel-title center">מסייעת 951</h1>
      <p class="panel-sub center mb0">בחרו מה תרצו לעשות.</p>
    </section>
    <div class="choices">
      <a class="choice" href="#sign">
        <span class="choice-ico" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"
               stroke-linecap="round" stroke-linejoin="round">
            <path d="M9 4H6a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V6a2 2 0 0 0-2-2h-3"/>
            <rect x="9" y="2.5" width="6" height="3.4" rx="1"/>
            <path d="M8.5 12.5l2.4 2.4 4.6-5"/>
          </svg>
        </span>
        <span class="choice-txt">
          <span class="choice-t">החתמת ציוד</span>
          <span class="choice-s">רישום הציוד האישי שקיבלתם — קסדה, ווסט, מחסניות ועוד.</span>
        </span>
        <span class="choice-go" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"
               stroke-linecap="round" stroke-linejoin="round"><path d="M15 5l-7 7 7 7"/></svg>
        </span>
      </a>
      <a class="choice" href="#report">
        <span class="choice-ico alt" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"
               stroke-linecap="round" stroke-linejoin="round">
            <path d="M5 21V4.5"/>
            <path d="M5 5c4-2 8 2 12 0v8c-4 2-8-2-12 0z"/>
          </svg>
        </span>
        <span class="choice-txt">
          <span class="choice-t">בקשת ציוד / דיווח חוסר</span>
          <span class="choice-s">חסר לכם משהו או צריך השלמה? כתבו ומנהל הציוד יטפל.</span>
        </span>
        <span class="choice-go" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"
               stroke-linecap="round" stroke-linejoin="round"><path d="M15 5l-7 7 7 7"/></svg>
        </span>
      </a>
    </div>`, 'home');
}

/* ── Shortage reporting (soldier-facing, separate from sign-out) ────── */

function renderReport() {
  if (!S.config || !S.config.ready) {
    render(`
      <section class="panel center">
        <h1 class="panel-title">המערכת עדיין לא הוגדרה</h1>
        <p class="panel-sub mb0">מנהל הציוד צריך להשלים את ההקמה לפני שאפשר לדווח.</p>
      </section>`);
    return;
  }
  if (S.repSent) {
    render(`
      <section class="panel center">
        <div class="big-ok" aria-hidden="true"></div>
        <h1 class="panel-title">הדיווח נשלח</h1>
        <p class="panel-sub">מנהל הציוד יראה את הדיווח ויסמן אותו כשטופל. אין צורך לשלוח שוב.</p>
        <button class="btn ghost wide mt" data-act="rep-again">דיווח נוסף</button>
        <p class="muted-txt mt mb0"><a class="foot-link" href="#">חזרה לתפריט</a></p>
      </section>`);
    return;
  }
  const v = S.rep || { name: '', phone: '', text: '' };
  render(`
    <section class="panel center-head">
      <img class="unit-badge" src="/logo.png" alt="סמל מסייעת 951">
      <h1 class="panel-title center">בקשת ציוד / דיווח חוסר</h1>
      <p class="panel-sub center">חסר לכם ציוד או שאתם צריכים השלמה? כתבו כאן ומנהל הציוד יטפל. אין צורך במספר אישי — רק שם ומה שחסר.</p>
      <form data-form="report" novalidate>
        <label class="field">
          <span class="field-label">שם מלא</span>
          <input class="input" name="name" autocomplete="off" maxlength="60"
                 value="${esc(v.name)}" required>
        </label>
        <label class="field">
          <span class="field-label">טלפון נייד <span class="opt-tag">רשות</span></span>
          <input class="input num" name="phone" inputmode="tel" autocomplete="tel"
                 maxlength="10" value="${esc(v.phone)}" placeholder="0501234567">
          <span class="field-hint">רק כדי שנוכל לעדכן אתכם כשהבקשה מטופלת. אפשר להשאיר ריק.</span>
        </label>
        <label class="field">
          <span class="field-label">מה חסר לכם או מה אתם צריכים?</span>
          <textarea class="input area" name="text" rows="7" maxlength="1500"
                    placeholder="לדוגמה: חסרות לי 2 מחסניות, והווסט שקיבלתי עם רצועה קרועה — צריך להחליף." required>${esc(v.text)}</textarea>
          <span class="field-hint">כתבו בחופשיות — כמה שיותר פרטים, כך קל יותר לטפל.</span>
        </label>
        <p class="form-err" data-err></p>
        <button class="btn primary wide" type="submit">שליחת הבקשה</button>
      </form>
      <p class="muted-txt mt mb0 center"><a class="foot-link" href="#">חזרה לתפריט</a></p>
    </section>`);
}

async function reportSubmit(form) {
  const name = form.name.value.trim();
  const phone = form.phone.value.trim();
  const text = form.text.value.trim();
  if (name.length < 2) return setFormErr(form, 'נא למלא שם מלא');
  if (phone && !/^\d{9,10}$/.test(phone)) {
    return setFormErr(form, 'טלפון: 9–10 ספרות, ללא מקפים (או להשאיר ריק)');
  }
  if (text.length < 5) return setFormErr(form, 'נא לפרט מה חסר');
  setFormErr(form, '');
  S.rep = { name, phone, text };
  const btn = form.querySelector('button[type=submit]');
  btn.disabled = true;
  btn.textContent = 'שולח…';
  await withBusy(async () => {
    const sealed = await seal(await importPubKey(S.config.pub), { name, phone, text, createdAt: Date.now() });
    await api('/reports', { body: { id: hex(crypto.getRandomValues(new Uint8Array(16))), ...sealed } });
    S.repSent = true;
    S.rep = null;
    renderReport();
  });
  if (!S.repSent) {
    btn.disabled = false;
    btn.textContent = 'שליחת הבקשה';
  }
}

/* ── Soldier views (PLAN §7.1) ─────────────────────────────────────── */

function stepsBar(n) {
  const labels = ['פרטים', 'ציוד', 'אישור', 'סיום'];
  return `<ol class="steps" aria-hidden="true">${labels
    .map((lbl, i) => {
      const idx = i + 1;
      const cls = ['stp', idx <= n ? 'on' : '', idx === n ? 'now' : '']
        .filter(Boolean)
        .join(' ');
      return `<li class="${cls}"><span class="stp-dot num">${idx}</span><span class="stp-lbl">${lbl}</span></li>`;
    })
    .join('')}</ol>`;
}

function renderSoldier() {
  if (!S.config || !S.config.ready) {
    render(`
      <section class="panel center">
        <h1 class="panel-title">המערכת עדיין לא הוגדרה</h1>
        <p class="panel-sub mb0">מנהל הציוד צריך להשלים את ההקמה לפני שאפשר להירשם.</p>
      </section>`);
    return;
  }
  if (S.sStep === 1) renderSoldierStep1();
  else if (S.sStep === 2) renderSoldierStep2();
  else if (S.sStep === 3) renderSoldierConfirm();
  else renderSoldierDone();
}

// The camera / gallery pair, shared by both licence kinds.
function licCapture(kind) {
  const shot = S.licPhoto[kind.id];
  return `
    ${shot
      ? `<div class="lic-shot">
           <img class="lic-thumb" src="${shot.preview}" alt="תצוגה מקדימה של ${esc(kind.short)}">
           <div class="lic-shot-side">
             <span class="lic-ok">✓ צולם</span>
             <span class="lic-size num">${Math.round(shot.size / 1024)} KB</span>
             <button type="button" class="linkbtn danger-link" data-act="lic-clear" data-kind="${kind.id}">הסרה</button>
           </div>
         </div>`
      : ''}
    <div class="lic-actions">
      <label class="btn ghost lic-pick">
        <span>📷 ${shot ? 'צילום מחדש' : 'צילום'}</span>
        <input class="vis-hidden" type="file" accept="image/*" capture="environment"
               data-act="lic-file" data-kind="${kind.id}">
      </label>
      <label class="btn ghost lic-pick">
        <span>🖼 מהגלריה</span>
        <input class="vis-hidden" type="file" accept="image/*"
               data-act="lic-file" data-kind="${kind.id}">
      </label>
    </div>
    ${shot ? '' : '<p class="field-hint center mb0">התמונה מוצפנת במכשיר שלכם לפני השליחה — רק מנהל הציוד יוכל לפתוח אותה.</p>'}`;
}

// Checkbox, then the fields that licence needs. The civilian one also takes
// typed number + expiry, so the admin can chase renewals without opening a photo.
function licBlock(kind) {
  const on = !!S.lic[kind.id];
  let body = '';

  if (on && kind.mode === 'fields') {
    const st = licState(S.licExp);
    body = `
      <div class="lic-body">
        <label class="field">
          <span class="field-label">מספר רישיון</span>
          <input class="input num" data-act="lic-no" inputmode="numeric" autocomplete="off"
                 maxlength="20" value="${esc(S.licNo)}" placeholder="12345678">
        </label>
        <label class="field">
          <span class="field-label">בתוקף עד</span>
          <input class="input" type="date" data-act="lic-exp" value="${esc(S.licExp)}">
          ${S.licExp && st === 'expired'
            ? '<span class="field-hint bad-hint">⚠ התאריך שהוזן כבר עבר — הרישיון אינו בתוקף.</span>'
            : S.licExp && st === 'soon'
              ? '<span class="field-hint warn-hint">הרישיון פג בקרוב — כדאי לחדש.</span>'
              : ''}
        </label>
        <span class="field-label">צילום הרישיון</span>
        ${licCapture(kind)}
      </div>`;
  } else if (on) {
    body = `<div class="lic-body">${licCapture(kind)}</div>`;
  }

  return `
    <div class="lic ${on ? 'on' : ''}">
      <label class="check lic-head">
        <input type="checkbox" data-act="lic-toggle" data-kind="${kind.id}" ${on ? 'checked' : ''}>
        <span>${esc(kind.label)}</span>
      </label>
      ${body}
    </div>`;
}

function renderSoldierStep1() {
  const v = S.ident || { pn: '', name: '', phone: '', dept: '', weapon: '', amral: '', scope: '' };
  const deptOpts = DEPTS.map(
    (d) => `<option value="${d.id}"${v.dept === d.id ? ' selected' : ''}>${esc(d.name)}</option>`
  ).join('');
  render(`
    ${stepsBar(1)}
    <section class="panel center-head">
      <img class="unit-badge" src="/logo.png" alt="סמל מסייעת 951">
      <h1 class="panel-title center">רישום ציוד אישי</h1>
      <p class="panel-sub center">מלאו פרטים, בחרו את הציוד שקיבלתם ושלחו לאישור. הפרטים מוצפנים במכשיר שלכם — רק מנהל הציוד יכול לקרוא אותם.</p>
      <form data-form="ident" novalidate>
        <label class="field">
          <span class="field-label">מספר אישי</span>
          <input class="input num" name="pn" inputmode="numeric" autocomplete="off"
                 maxlength="9" value="${esc(v.pn)}" required>
        </label>
        <label class="field">
          <span class="field-label">שם מלא</span>
          <input class="input" name="name" autocomplete="off" maxlength="60"
                 value="${esc(v.name)}" required>
        </label>
        <label class="field">
          <span class="field-label">טלפון נייד</span>
          <input class="input num" name="phone" inputmode="tel" autocomplete="off"
                 maxlength="10" value="${esc(v.phone)}" required>
        </label>
        <label class="field">
          <span class="field-label">מחלקה</span>
          <select class="input select" name="dept" required>
            <option value="">— בחרו מחלקה —</option>
            ${deptOpts}
          </select>
        </label>
        <fieldset class="lic-set">
          <legend class="field-label">נשק ואמצעים נלווים</legend>
          <div class="grid2">
            <label class="field">
              <span class="field-label">מספר סידורי של הנשק</span>
              <input class="input num" name="weapon" autocomplete="off" maxlength="20"
                     value="${esc(v.weapon || '')}" placeholder="1234567">
            </label>
            <label class="field">
              <span class="field-label">מספר אמר״ל</span>
              <input class="input num" name="amral" autocomplete="off" maxlength="20"
                     value="${esc(v.amral || '')}" placeholder="1234567">
            </label>
            <label class="field">
              <span class="field-label">מספר כוונת</span>
              <input class="input num" name="scope" autocomplete="off" maxlength="20"
                     value="${esc(v.scope || '')}" placeholder="1234567">
            </label>
          </div>
          <span class="field-hint">אם לא קיבלתם — אפשר להשאיר ריק.</span>
        </fieldset>

        <fieldset class="lic-set">
          <legend class="field-label">רישיונות נהיגה</legend>
          ${LIC_KINDS.map(licBlock).join('')}
        </fieldset>

        <p class="form-err" data-err></p>
        <button class="btn primary wide" type="submit">המשך</button>
      </form>
    </section>`, 'sign-1');
}

function renderSoldierStep2() {
  const rows = ITEMS.map((item) => {
    const on = item.id in S.sel;
    const stepper = item.qty && on
      ? `<span class="step">
           <button type="button" class="step-btn" data-act="s-dec" data-item="${item.id}"
                   aria-label="פחות ${esc(item.name)}" ${S.sel[item.id] <= item.min ? 'disabled' : ''}>−</button>
           <span class="step-val num">${S.sel[item.id]}</span>
           <button type="button" class="step-btn" data-act="s-inc" data-item="${item.id}"
                   aria-label="עוד ${esc(item.name)}" ${S.sel[item.id] >= item.max ? 'disabled' : ''}>+</button>
         </span>`
      : '';
    return `
      <li class="opt" role="checkbox" aria-checked="${on}" tabindex="0"
          data-act="s-toggle" data-item="${item.id}">
        <span class="opt-box" aria-hidden="true"></span>
        <span class="opt-ico" aria-hidden="true">${item.icon}</span>
        <span class="opt-name">${esc(item.name)}</span>
        ${stepper}
      </li>`;
  }).join('');

  const suppNote = S.suppMode
    ? `<div class="callout alert">
         <p class="callout-title">⚠ כבר חתמת על ציוד בעבר</p>
         <p class="mb0">הרישום הקודם שלך <strong>כבר מאושר</strong>. סמנו כאן <strong>רק את הציוד הנוסף</strong> שקיבלתם עכשיו — הוא יתווסף למה שכבר רשום עליכם.${S.existingPending ? ' <strong>שימו לב:</strong> השלמה קודמת שממתינה לאישור תוחלף, לכן כללו את כל הציוד הנוסף.' : ''}</p>
       </div>`
    : S.existingPending
      ? `<div class="callout alert">
           <p class="callout-title">⚠ קיימת כבר הגשה ממתינה</p>
           <p class="mb0">למספר האישי הזה כבר נשלחה הגשה שממתינה לאישור. שליחה חדשה <strong>תחליף</strong> אותה — סמנו את כל הציוד, לא רק את התוספת.</p>
         </div>`
      : '';
  render(`
    ${stepsBar(2)}
    <section class="panel">
      <h1 class="panel-title">${S.suppMode ? 'איזה ציוד נוסף קיבלת?' : 'איזה ציוד קיבלת?'}</h1>
      <p class="panel-sub">שלום ${esc(S.ident.name)} — סמנו את כל הפריטים שקיבלתם.</p>
      ${suppNote}
      <ul>${rows}</ul>
      <p class="form-err" data-err></p>
      <button class="btn primary wide" data-act="s-review">המשך לסיכום</button>
      <button class="btn ghost wide mt" data-act="s-back">חזרה לפרטים</button>
    </section>`, 'sign-2');
}

// Last chance to check the list before it becomes a signature. Every row is
// editable from here without losing the rest of the form.
function renderSoldierConfirm() {
  const v = S.ident || {};
  const rows = ITEMS.filter((i) => i.id in S.sel)
    .map(
      (item) => `
      <div class="confirm-row">
        <span class="confirm-ico" aria-hidden="true">${item.icon}</span>
        <span class="confirm-name">${esc(item.name)}</span>
        <span class="step">
          <button type="button" class="step-btn" data-act="s-dec" data-item="${item.id}"
                  aria-label="פחות ${esc(item.name)}" ${S.sel[item.id] <= item.min ? 'disabled' : ''}>−</button>
          <span class="confirm-qty num">${S.sel[item.id]}</span>
          <button type="button" class="step-btn" data-act="s-inc" data-item="${item.id}"
                  aria-label="עוד ${esc(item.name)}" ${S.sel[item.id] >= item.max ? 'disabled' : ''}>+</button>
        </span>
        <button type="button" class="linkbtn danger-link" data-act="s-remove" data-item="${item.id}"
                aria-label="הסרת ${esc(item.name)}">הסרה</button>
      </div>`
    )
    .join('');

  const licLine = LIC_KINDS.filter((k) => S.lic[k.id])
    .map((k) => {
      const extra = k.id === 'civil'
        ? [S.licNo && `מס׳ ${S.licNo}`, S.licExp && `בתוקף עד ${fmtDay(S.licExp)}`].filter(Boolean).join(' · ')
        : '';
      const shot = S.licPhoto[k.id] ? ' · צילום מצורף' : '';
      return `<div><dt>${esc(k.short)}:</dt><dd>${esc(extra || 'סומן')}${shot}</dd></div>`;
    })
    .join('');

  render(`
    ${stepsBar(3)}
    <section class="panel">
      <h1 class="panel-title">אישור לפני שליחה</h1>
      <p class="panel-sub">בדקו שהכול נכון. אחרי השליחה לא ניתן לשנות — רק מנהל הציוד יוכל לתקן.</p>

      <dl class="confirm-who">
        <div><dt>שם:</dt><dd>${esc(v.name || '')}</dd></div>
        <div><dt>מספר אישי:</dt><dd><span class="num">${esc(v.pn || '')}</span></dd></div>
        <div><dt>טלפון:</dt><dd><span class="num">${esc(v.phone || '')}</span></dd></div>
        <div><dt>מחלקה:</dt><dd>${esc(deptName(v.dept))}</dd></div>
        ${v.weapon ? `<div><dt>נשק:</dt><dd><span class="num">${esc(v.weapon)}</span></dd></div>` : ''}
        ${licLine}
      </dl>

      <h2 class="field-label">הציוד שאתם חותמים עליו</h2>
      <div class="confirm-list">${rows}</div>
      <p class="form-err" data-err></p>
      <button class="btn primary wide" data-act="s-submit">אישור ושליחה</button>
      <button class="btn ghost wide mt" data-act="s-edit">חזרה לעריכת הציוד</button>
    </section>`, 'sign-3');
}

function renderSoldierDone() {
  const list = Object.entries(S.sel)
    .map(([id, q]) => {
      const item = itemById(id);
      return `<span class="tagi">${esc(item.name)}${item.qty ? ` <span class="num">×${q}</span>` : ''}</span>`;
    })
    .join('');
  render(`
    ${stepsBar(4)}
    <section class="panel center">
      <div class="big-ok" aria-hidden="true"></div>
      <h1 class="panel-title">${S.suppMode ? 'ההשלמה נשלחה' : 'הרישום נשלח'}</h1>
      <p class="panel-sub">${
        S.suppMode
          ? 'הציוד הנוסף נקלט במצב <span class="state wait">ממתין לאישור</span> — לאחר אישור המנהל הוא יתווסף לרישום הקיים שלך ותקבל הודעת וואטסאפ מעודכנת.'
          : 'הרשומה נקלטה במצב <span class="state wait">ממתין לאישור</span> — לאחר אישור המנהל תקבל הודעת וואטסאפ עם פירוט הציוד שהוחתם.'
      }</p>
      <div class="tags center">${list}</div>
      <div class="fp num"><span aria-hidden="true">🔒</span><span class="fp-code">${esc(S.rid.slice(0, 16))}</span></div>
      <p class="muted-txt mt">סיימנו — אפשר לסגור את הדף.</p>
      <button class="btn ghost wide mt" data-act="s-reset">תיקון ורישום מחדש</button>
    </section>`, 'sign-4');
}

/* ── Admin views (PLAN §7.2) ───────────────────────────────────────── */

function renderAdmin() {
  if (!S.config) {
    render('<p class="loading">טוען…</p>');
    return;
  }
  if (S.priv) renderConsole();
  else if (!S.config.ready) renderSetup();
  else renderLogin();
}

function renderSetup() {
  $app.classList.remove('wide');
  render(`
    <section class="panel">
      <h1 class="panel-title">הקמת המערכת</h1>
      <p class="panel-sub">הפעלה ראשונה: בחרו סיסמת מנהל. הסיסמה מגינה על מפתח ההצפנה של כל הרשומות.</p>
      <div class="callout risk">
        <p class="callout-title">אין שחזור סיסמה</p>
        <p class="mb0">אם הסיסמה תאבד — כל הנתונים יאבדו לצמיתות. זהו מחיר האבטחה: לשרת אין שום דרך לקרוא את המידע.</p>
      </div>
      <form data-form="setup" novalidate>
        <label class="field">
          <span class="field-label">סיסמת מנהל (10 תווים לפחות)</span>
          <input class="input" type="password" name="pw" autocomplete="new-password" required>
        </label>
        <label class="field">
          <span class="field-label">אימות סיסמה</span>
          <input class="input" type="password" name="pw2" autocomplete="new-password" required>
        </label>
        <label class="field">
          <span class="field-label">טוקן הקמה (רק אם הוגדר SETUP_TOKEN)</span>
          <input class="input" type="password" name="token" autocomplete="off">
          <span class="field-hint">להשאיר ריק אם לא הוגדר טוקן בהגדרות הפריסה.</span>
        </label>
        <label class="check">
          <input type="checkbox" name="ack">
          <span>אני מבין/ה שאין דרך לשחזר את הסיסמה, ושאיבודה משמעו איבוד כל הנתונים.</span>
        </label>
        <p class="form-err" data-err></p>
        <button class="btn primary wide" type="submit">הקמה וכניסה</button>
      </form>
    </section>`);
}

function renderLogin() {
  $app.classList.remove('wide');
  render(`
    <section class="panel">
      <h1 class="panel-title">כניסת מנהל</h1>
      <p class="panel-sub">הסיסמה פותחת את מפתח ההצפנה בדפדפן — היא לעולם לא נשלחת לשרת.</p>
      <form data-form="login" novalidate>
        <label class="field">
          <span class="field-label">סיסמת מנהל</span>
          <input class="input" type="password" name="pw" autocomplete="current-password" required>
        </label>
        <p class="form-err" data-err></p>
        <button class="btn primary wide" type="submit">כניסה</button>
      </form>
    </section>`);
}

/* — console — */

const outstanding = (data) =>
  Object.values(data.items || {}).reduce((sum, it) => sum + (it.t - (it.r || 0)), 0);

function counts() {
  const pending = S.recs.filter((r) => r.status === 'pending').length;
  const approved = S.recs.filter((r) => r.status === 'approved').length;
  const damaged = S.recs.filter((r) => r.damaged).length;
  return { pending, approved, damaged };
}

function renderConsole() {
  $app.classList.add('wide');
  const c = counts();
  const openReps = openReports();
  const SECTIONS = [
    ['over',    'סקירה',        null],
    ['pending', 'ממתין לאישור', c.pending],
    ['track',   'מעקב ציוד',    c.approved],
    ['reports', 'בקשות חוסר',   openReps, openReps > 0],
    ['inv',     'מלאי',         null],
    ['armon',   'ארמון',        armonCount() || null],
    ['tzelem',  'דו״ח צלם',     null],
    ['ammo',    'תחמושת ואלפא', null],
    ['veh',     'רכבים',        vehAlerts() || null, true],
    ['sum',     'דוחות',        null],
    ['sec',     'אבטחה',        null],
  ];

  const nav = SECTIONS.map(
    ([id, label, count, hot]) => `
      <button class="nav-item" role="tab" aria-selected="${S.tab === id}"
              data-act="tab" data-tab="${id}">
        <span>${label}</span>
        ${count !== null ? `<span class="nav-count num${hot ? ' hot' : ''}">${count}</span>` : ''}
      </button>`
  ).join('');

  const title = (SECTIONS.find((x) => x[0] === S.tab) || ['', 'ניהול ציוד'])[1];

  let body = '';
  if (S.tab === 'over') body = renderOverviewTab();
  else if (S.tab === 'pending') body = renderPendingTab();
  else if (S.tab === 'track') body = renderTrackTab();
  else if (S.tab === 'reports') body = renderReportsTab();
  else if (S.tab === 'inv') body = renderInvTab();
  else if (S.tab === 'armon') body = renderArmonTab();
  else if (S.tab === 'tzelem') body = renderTzelemTab();
  else if (S.tab === 'ammo') body = renderAmmoTab();
  else if (S.tab === 'veh') body = renderVehTab();
  else if (S.tab === 'sum') body = renderSummaryTab();
  else body = renderSecurityTab();

  render(`
    <div class="conbar">
      <span class="conbar-title">${esc(title)}</span>
      <div class="conbar-actions">
        <button class="btn ghost small" data-act="refresh">רענון</button>
        <button class="btn ghost small" data-act="lock">נעילה</button>
      </div>
    </div>
    ${c.damaged
      ? `<div class="callout risk"><p class="mb0"><strong class="num">${c.damaged}</strong> רשומות פגומות — הפענוח נכשל (חשד לשיבוש נתונים בשרת).</p></div>`
      : ''}
    <div class="console">
      <aside class="side">
        <div class="navlist" role="tablist">${nav}</div>
      </aside>
      <div class="cmain">${body}</div>
    </div>`);
}

function fpStrip(rid) {
  return `<footer class="fp"><span aria-hidden="true">🔒</span><span class="fp-code num">${esc(rid.slice(0, 16))}</span></footer>`;
}

// Weapon serial + licence chips, with an on-demand viewer for the photos.
// Images are fetched and decrypted only when the admin asks for one.
function extrasRow(rec) {
  const d = rec.data;
  const bits = [];
  const serials = [
    ['נשק', d.weapon], ['אמר״ל', d.amral], ['כוונת', d.scope],
  ].filter(([, v]) => v);
  if (serials.length) {
    bits.push(`<div class="rec-meta">${serials
      .map(([k, v]) => `${k} <span class="num">${esc(v)}</span>`)
      .join(' · ')}</div>`);
  }
  const lic = d.lic || {};
  const chips = LIC_KINDS.filter((k) => lic[k.id] && lic[k.id].has).map((k) => {
    const key = `${rec.rid}:${k.id}`;
    const shown = S.docs[key];
    const hasDoc = lic[k.id].doc;
    return `
      <div class="licv">
        <span class="tagi lic-chip">✓ ${esc(k.short)}</span>
        ${hasDoc
          ? `<button class="linkbtn" data-act="doc" data-rid="${esc(rec.rid)}" data-kind="${k.id}">${
              shown ? 'הסתרה' : 'הצגת צילום'
            }</button>`
          : '<span class="muted-txt">ללא צילום</span>'}
        ${shown ? `<img class="doc-img" src="${shown}" alt="צילום ${esc(k.short)}">` : ''}
      </div>`;
  });
  if (chips.length) bits.push(`<div class="licv-wrap">${chips.join('')}</div>`);
  return bits.join('');
}

function phoneRow(rec) {
  const shown = S.revealed.has(rec.rid);
  return `<div class="rec-meta">טלפון:
    <span class="num">${esc(shown ? rec.data.phone : maskPhone(rec.data.phone))}</span>
    <button class="linkbtn" data-act="reveal" data-rid="${esc(rec.rid)}">${shown ? 'הסתרה' : 'הצגה'}</button>
  </div>`;
}

const itemsText = (d) =>
  ITEMS.filter((i) => d.items[i.id])
    .map((i) => `${i.name} ×${d.items[i.id].t}`)
    .join(', ');

/* ── Search & grouping (PLAN §7.2 — usable at 100+ soldiers) ────────── */

// Matches a record against the free-text query: name, personal number, phone.
function matchesQuery(d, q) {
  if (!q) return true;
  const needle = q.trim().toLowerCase();
  if (!needle) return true;
  const digits = needle.replace(/\D/g, '');
  return (
    (d.name || '').toLowerCase().includes(needle) ||
    (!!digits && (d.pn || '').includes(digits)) ||
    (!!digits && (d.phone || '').includes(digits))
  );
}

const applyFilters = (recs) =>
  recs.filter(
    (r) =>
      !r.damaged &&
      r.data &&
      (S.dept === 'all' || r.data.dept === S.dept) &&
      matchesQuery(r.data, S.q)
  );

// Groups records by department, preserving DEPTS order; unassigned last.
function groupByDept(recs) {
  const groups = DEPTS.map((dp) => ({
    id: dp.id,
    name: dp.name,
    recs: recs.filter((r) => r.data.dept === dp.id),
  }));
  const orphans = recs.filter((r) => !DEPTS.some((dp) => dp.id === r.data.dept));
  if (orphans.length) groups.push({ id: '_none', name: 'ללא שיוך', recs: orphans });
  return groups.filter((g) => g.recs.length);
}

// Standalone search box for lists that aren't the soldier roster.
function plainSearch(act, clearAct, value, placeholder, total, shown) {
  return `
    <div class="search">
      <input class="input search-in" type="search" data-act="${act}" value="${esc(value)}"
             placeholder="${esc(placeholder)}" autocomplete="off" enterkeyhint="search">
      ${value ? `<button class="linkbtn search-clear" data-act="${clearAct}">ניקוי</button>` : ''}
    </div>
    ${shown !== total
      ? `<p class="result-count"><span class="num">${shown}</span> מתוך <span class="num">${total}</span></p>`
      : ''}`;
}

function searchBar(total, shown) {
  const chips = [['all', 'כל המחלקות'], ...DEPTS.map((d) => [d.id, d.name])]
    .map(
      ([id, label]) =>
        `<button class="filter" aria-pressed="${S.dept === id}" data-act="dept" data-dept="${id}">${esc(label)}</button>`
    )
    .join('');
  return `
    <div class="search">
      <input class="input search-in" type="search" data-act="search" value="${esc(S.q)}"
             placeholder="חיפוש לפי שם, מספר אישי או טלפון" autocomplete="off" enterkeyhint="search">
      ${S.q ? '<button class="linkbtn search-clear" data-act="qclear">ניקוי</button>' : ''}
    </div>
    <div class="filters">${chips}</div>
    ${shown !== total
      ? `<p class="result-count"><span class="num">${shown}</span> מתוך <span class="num">${total}</span></p>`
      : ''}`;
}

const PAGE_SIZE = 25;

// Slices a list to the current page and renders a pager beneath it. Paging is
// client-side by necessity: the server stores ciphertext, so it cannot filter
// or order by name — every record must be decrypted here before it can be
// searched at all. Paging the DOM is what keeps a 1000-soldier roster fast.
function paged(key, rows) {
  const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  const cur = Math.min(S.page[key] || 0, pages - 1);
  return { slice: rows.slice(cur * PAGE_SIZE, (cur + 1) * PAGE_SIZE), cur, pages, total: rows.length };
}

function pager(key, p) {
  if (p.pages <= 1) return '';
  const from = p.cur * PAGE_SIZE + 1;
  const to = Math.min(p.total, (p.cur + 1) * PAGE_SIZE);
  const btn = (page, label, disabled) =>
    `<button class="pg-btn" data-act="page" data-key="${key}" data-page="${page}"
             ${disabled ? 'disabled' : ''} aria-label="${esc(label)}">${label}</button>`;
  // a window of page numbers, so 40 pages don't produce 40 buttons
  const win = [];
  for (let i = Math.max(0, p.cur - 2); i < Math.min(p.pages, p.cur + 3); i++) win.push(i);
  return `
    <nav class="pager" aria-label="ניווט בין עמודים">
      ${btn(p.cur - 1, '‹ הקודם', p.cur === 0)}
      <span class="pg-nums">
        ${win.map((i) => `<button class="pg-btn num${i === p.cur ? ' on' : ''}"
             data-act="page" data-key="${key}" data-page="${i}"
             aria-current="${i === p.cur}">${i + 1}</button>`).join('')}
      </span>
      ${btn(p.cur + 1, 'הבא ›', p.cur >= p.pages - 1)}
      <span class="pg-info"><span class="num">${from}–${to}</span> מתוך <span class="num">${p.total}</span></span>
    </nav>`;
}

// Renders grouped, collapsible department sections around a card renderer.
function deptSections(recs, cardFn, emptyMsg) {
  const groups = groupByDept(recs);
  if (!groups.length) return `<p class="empty">${esc(emptyMsg)}</p>`;
  // A search narrows things down enough that folding just hides the answer.
  const forceOpen = !!S.q.trim() || S.dept !== 'all';
  return groups
    .map((g) => {
      const open = forceOpen || !S.collapsed.has(g.id);
      const out = g.recs.filter((r) => outstanding(r.data) > 0).length;
      return `
        <section class="grp">
          <button class="grp-head" data-act="fold" data-dept="${g.id}" aria-expanded="${open}">
            <span class="grp-caret" aria-hidden="true">${open ? '▾' : '◂'}</span>
            <span class="grp-name">${esc(g.name)}</span>
            <span class="grp-meta">${
              g.recs.length === 1 ? 'חייל אחד' : `<span class="num">${g.recs.length}</span> חיילים`
            }${out ? ` · <span class="num">${out}</span> עם ציוד בחוץ` : ''}</span>
          </button>
          ${open ? `<div class="grp-body">${g.recs.map(cardFn).join('')}</div>` : ''}
        </section>`;
    })
    .join('');
}

// Israeli local number → international digits, as wa.me requires.
function waPhone(raw) {
  const digits = String(raw).replace(/\D/g, '');
  if (digits.startsWith('972')) return digits;
  if (digits.startsWith('0')) return '972' + digits.slice(1);
  return '972' + digits;
}

// Prefilled WhatsApp message opened on the ADMIN's device — the server never
// sees the phone number, so this is the only E2E-preserving way to notify a
// soldier. Opened in a new tab so the console keeps its in-memory key.
// Automatic send via the Worker (WhatsApp Cloud API). Resolves to a reason
// string when it could not send, so approval never fails because of delivery.
async function notifySoldier(d) {
  try {
    const r = await api('/admin/notify', {
      body: { phone: waPhone(d.phone), name: d.name, items: itemsText(d) },
    });
    return r && r.sent ? null : (r && r.reason) || 'unknown';
  } catch {
    return 'unknown';
  }
}

function waLink(d, rid) {
  const lines = ITEMS.filter((i) => d.items[i.id])
    .map((i) => `• ${i.name}${i.qty ? ` ×${d.items[i.id].t}` : ''}`)
    .join('\n');
  const msg =
    '*אישור החתמת ציוד — מסייעת 951*\n\n' +
    `שלום ${d.name},\n` +
    'רישום הציוד שלך אושר והוחתמת על:\n\n' +
    `${lines}\n\n` +
    `מס' רישום: ${rid.slice(0, 8)}\n` +
    'נא לשמור הודעה זו לצורך החזרת הציוד.';
  return `https://wa.me/${waPhone(d.phone)}?text=${encodeURIComponent(msg)}`;
}

// Return receipt — what came back, and what is still outstanding.
function returnWaLink(d, rid) {
  const back = ITEMS.filter((i) => d.items[i.id] && (d.items[i.id].r || 0) > 0)
    .map((i) => `• ${i.name} ×${d.items[i.id].r}`)
    .join('\n');
  const left = ITEMS.filter((i) => d.items[i.id] && d.items[i.id].t - (d.items[i.id].r || 0) > 0)
    .map((i) => `• ${i.name} ×${d.items[i.id].t - (d.items[i.id].r || 0)}`)
    .join('\n');
  const msg =
    '*זיכוי ציוד — מסייעת 951*\n\n' +
    `שלום ${d.name},\n` +
    'הציוד הבא הוחזר וזוכה על שמך:\n\n' +
    `${back}\n\n` +
    (left
      ? `*עדיין רשום עליך:*\n${left}\n\n`
      : '*אין ציוד נוסף הרשום על שמך — החשבון סגור.*\n\n') +
    `מס' רישום: ${rid.slice(0, 8)}`;
  return `https://wa.me/${waPhone(d.phone)}?text=${encodeURIComponent(msg)}`;
}

function damagedCard(rec) {
  return `
    <article class="rec broken">
      <header class="rec-head">
        <div class="rec-name">רשומה פגומה</div>
        <span class="state live">שגיאה</span>
      </header>
      <p class="muted-txt">לא ניתן לפענח את הרשומה — ייתכן שהנתונים שובשו בצד השרת.</p>
      <div class="rec-actions">
        <button class="btn danger" data-act="del" data-rid="${esc(rec.rid)}">מחיקה</button>
      </div>
      ${fpStrip(rec.rid)}
    </article>`;
}

function pendingCard(rec) {
  const d = rec.data;
  const rows = ITEMS.filter((i) => d.items[i.id])
    .map((item) => {
      const t = d.items[item.id].t;
      return `<li class="rec-row">
          <span class="rec-row-main">
            <span class="row-ico" aria-hidden="true">${item.icon}</span>
            <span class="rec-row-name">${esc(item.name)}</span>
          </span>
          <span class="rec-row-tools">
            <span class="step">
              <button type="button" class="step-btn" data-act="adj" data-rid="${esc(rec.rid)}"
                      data-item="${item.id}" data-d="-1" aria-label="פחות" ${t <= item.min ? 'disabled' : ''}>−</button>
              <span class="step-val num">${t}</span>
              <button type="button" class="step-btn" data-act="adj" data-rid="${esc(rec.rid)}"
                      data-item="${item.id}" data-d="1" aria-label="עוד" ${t >= item.max ? 'disabled' : ''}>+</button>
            </span>
          </span>
        </li>`;
    })
    .join('');
  return `
    <article class="rec wait">
      <header class="rec-head">
        <div>
          <div class="rec-name">${esc(d.name)}</div>
          <div class="rec-meta">מ״א <span class="num">${esc(d.pn)}</span> · ${esc(deptName(d.dept))}</div>
          <div class="rec-meta">נשלח ${esc(fmtDate(d.createdAt))}</div>
        </div>
        <span class="state wait">${d.supp ? 'השלמה' : 'ממתין'}</span>
      </header>
      ${d.supp
        ? '<p class="muted-txt">השלמת ציוד — באישור, הפריטים יתווספו לרישום המאושר הקיים של החייל.</p>'
        : ''}
      ${phoneRow(rec)}
          ${extrasRow(rec)}
      <ul>${rows}</ul>
      <div class="rec-actions">
        <button class="btn primary" data-act="approve" data-rid="${esc(rec.rid)}">אישור</button>
        <button class="btn danger" data-act="del" data-rid="${esc(rec.rid)}">מחיקה</button>
      </div>
      ${fpStrip(rec.rid)}
    </article>`;
}

function renderPendingTab() {
  const all = S.recs.filter((r) => r.status === 'pending');
  if (!all.length) return '<p class="empty">אין הגשות ממתינות. לחצו רענון כדי לבדוק שוב.</p>';
  const broken = all.filter((r) => r.damaged).map(damagedCard).join('');
  const visible = applyFilters(all);
  const p = paged('pending', visible);
  return `
    ${searchBar(all.length, visible.length)}
    ${broken}
    ${deptSections(p.slice, pendingCard, 'אין הגשות שתואמות את החיפוש.')}
    ${pager('pending', p)}`;
}

function renderTrackTab() {
  const approved = S.recs.filter((r) => r.status === 'approved');
  const filters = [
    ['out', 'ציוד בחוץ'],
    ['done', 'הוחזר במלואו'],
    ['all', 'הכל'],
  ]
    .map(
      ([id, label]) =>
        `<button class="filter" aria-pressed="${S.filter === id}" data-act="filter" data-filter="${id}">${label}</button>`
    )
    .join('');

  const visible = applyFilters(approved).filter((rec) => {
    const out = outstanding(rec.data) > 0;
    return S.filter === 'all' || (S.filter === 'out' ? out : !out);
  });

  const card = (rec) => {
      const d = rec.data;
      const out = outstanding(d);
      const rows = ITEMS.filter((i) => d.items[i.id])
        .map((item) => {
          const it = d.items[item.id];
          const r = it.r || 0;
          const returned = r >= it.t;
          return `<li class="rec-row">
              <span class="rec-row-main">
                <span class="row-ico" aria-hidden="true">${item.icon}</span>
                <span>
                  <span class="tagi${returned ? ' done' : ''}">${esc(item.name)}</span>
                  <span class="rec-row-sub">הוחזרו <span class="num">${r}</span> מתוך <span class="num">${it.t}</span></span>
                </span>
              </span>
              <span class="rec-row-tools step">
                <button type="button" class="step-btn" data-act="credit" data-rid="${esc(rec.rid)}"
                        data-item="${item.id}" data-d="-1" aria-label="ביטול החזרה" ${r <= 0 ? 'disabled' : ''}>−</button>
                <button type="button" class="step-btn" data-act="credit" data-rid="${esc(rec.rid)}"
                        data-item="${item.id}" data-d="1" aria-label="החזרה" ${r >= it.t ? 'disabled' : ''}>+</button>
              </span>
            </li>`;
        })
        .join('');
      return `
        <article class="rec ${out > 0 ? 'live' : 'done'}">
          <header class="rec-head">
            <div>
              <div class="rec-name">${esc(d.name)}</div>
              <div class="rec-meta">מ״א <span class="num">${esc(d.pn)}</span> · ${esc(deptName(d.dept))}</div>
              <div class="rec-meta">אושר ${esc(fmtDate(d.approvedAt))}</div>
              <div class="rec-meta">${
                d.notified
                  ? '<span class="sent">✓ הודעת החתמה נשלחה</span>'
                  : '<span class="unsent">הודעת החתמה טרם נשלחה</span>'
              }${
                d.returnNotified ? ' · <span class="sent">✓ הודעת זיכוי נשלחה</span>' : ''
              }</div>
            </div>
            ${out > 0
              ? `<span class="state live">ציוד בחוץ</span>`
              : `<span class="state done">הוחזר במלואו</span>`}
          </header>
          ${phoneRow(rec)}
          ${extrasRow(rec)}
          <ul>${rows}</ul>
          <div class="rec-actions">
            ${out > 0
              ? `<button class="btn primary" data-act="creditall" data-rid="${esc(rec.rid)}">זיכוי מלא</button>`
              : ''}
            <a class="btn wa" href="${esc(waLink(d, rec.rid))}" data-act="wa-sign"
               data-rid="${esc(rec.rid)}" target="_blank" rel="noopener noreferrer">${
                 d.notified ? 'שליחה חוזרת' : 'שליחה בוואטסאפ'
               }</a>
            ${(d.items && Object.values(d.items).some((it) => (it.r || 0) > 0))
              ? `<a class="btn wa ghost-wa" href="${esc(returnWaLink(d, rec.rid))}" data-act="wa-ret"
                    data-rid="${esc(rec.rid)}" target="_blank" rel="noopener noreferrer">${
                      d.returnNotified ? 'זיכוי — שליחה חוזרת' : 'הודעת זיכוי'
                    }</a>`
              : ''}
            <button class="btn danger" data-act="del" data-rid="${esc(rec.rid)}">מחיקה</button>
          </div>
          ${fpStrip(rec.rid)}
        </article>`;
  };

  const broken = approved.filter((r) => r.damaged).map(damagedCard).join('');
  const p = paged('track', visible);
  return `
    ${searchBar(approved.length, visible.length)}
    <div class="filters">${filters}</div>
    ${broken}
    ${deptSections(p.slice, card, 'אין רשומות שתואמות את החיפוש והסינון.')}
    ${pager('track', p)}`;
}

function renderSummaryTab() {
  const approved = S.recs.filter((r) => r.status === 'approved' && !r.damaged);
  const c = counts();
  const totals = ITEMS.map((item) => {
    let t = 0, r = 0;
    for (const rec of approved) {
      const it = rec.data.items[item.id];
      if (it) { t += it.t; r += it.r || 0; }
    }
    return { id: item.id, name: item.name, icon: item.icon, t, r, out: t - r };
  });
  const inv = S.inv || emptyInv();
  const rows = totals
    .map((x) => {
      const open = Number(inv.open[x.id]) || 0;
      const shelf = open - x.out;
      const short = open > 0 && shelf < 0;
      return `<tr${short ? ' class="row-short"' : ''}>
        <td><span class="tbl-ico" aria-hidden="true">${x.icon}</span>${esc(x.name)}</td>
        <td class="num">${open || '—'}</td>
        <td class="num">${x.t}</td>
        <td class="num">${x.r}</td>
        <td class="num ${x.out > 0 ? 'warn' : 'ok'}">${x.out}</td>
        <td class="num ${!open ? '' : short ? 'bad' : shelf === 0 ? 'warn' : 'ok'}">${open ? shelf : '—'}</td>
      </tr>`;
    })
    .join('');
  const soldiersOut = approved.filter((rec) => outstanding(rec.data) > 0).length;
  const shortages = totals.filter((x) => {
    const open = Number(inv.open[x.id]) || 0;
    return open > 0 && open - x.out < 0;
  });

  const shownAll = applyFilters(approved).length;
  return `
    <section class="panel">
      <h2 class="panel-title">חיפוש בדוחות</h2>
      <p class="panel-sub">החיפוש והסינון חלים על שלוש הטבלאות שמתחת — רישיונות, נשקים ומי חתום על מה.</p>
      ${searchBar(approved.length, shownAll)}
    </section>

    <section class="panel">
      <h2 class="panel-title">סיכום מלאי</h2>
      <p class="panel-sub">רשומות מאושרות בלבד. <span class="num">${c.pending}</span> ממתינות לאישור.</p>
      ${shortages.length
        ? `<div class="callout alert">
             <p class="callout-title">⚠ חוסרים במלאי</p>
             <p class="mb0">${shortages
               .map((x) => {
                 const open = Number(inv.open[x.id]) || 0;
                 return `<strong>${esc(x.name)}</strong> — חסרים <span class="num">${x.out - open}</span>`;
               })
               .join(' · ')}</p>
           </div>`
        : ''}
      <div class="tbl-scroll">
        <table class="tbl">
          <thead><tr>
            <th>פריט</th><th class="num">מלאי פתיחה</th><th class="num">הונפק</th>
            <th class="num">הוחזר</th><th class="num">בחוץ</th><th class="num">במחסן</th>
          </tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      <p class="mt muted-txt">
        <span class="num">${approved.length}</span> חיילים מאושרים ·
        <span class="num">${soldiersOut}</span> עם ציוד בחוץ
        ${c.damaged ? ` · <span class="num">${c.damaged}</span> רשומות פגומות` : ''}
      </p>
      <button class="btn ghost wide mt" data-act="export">ייצוא CSV</button>
    </section>

    ${licencePanel(approved)}
    ${weaponsPanel(approved)}
    ${ledgerPanel(approved)}`;
}

// Driving-licence register. Anyone without a licence in force is flagged red —
// the state is spelled out in words as well as coloured, and the same wording
// goes into the CSV.
const LIC_LABEL = {
  valid:   'בתוקף',
  soon:    'פג בקרוב',
  expired: 'פג תוקף',
  nodate:  'ללא תאריך',
  none:    'אין רישיון',
};

function licenceRows(approved) {
  return applyFilters(approved).map((rec) => {
    const d = rec.data;
    const civ = (d.lic || {}).civil;
    const st = civ && civ.has ? licState(civ.exp) : 'none';
    return {
      rid: rec.rid,
      name: d.name,
      pn: d.pn,
      dept: deptName(d.dept),
      no: (civ && civ.no) || '',
      exp: (civ && civ.exp) || '',
      st,
      doc: !!(civ && civ.doc),
      mil: !!((d.lic || {}).military && d.lic.military.has),
    };
  });
}

const LIC_RANK = { expired: 0, none: 1, nodate: 2, soon: 3, valid: 4 };

function licencePanel(approved) {
  const rows = licenceRows(approved);
  const bad = rows.filter((r) => r.st === 'none' || r.st === 'expired' || r.st === 'nodate');
  const soon = rows.filter((r) => r.st === 'soon');
  const ok = rows.filter((r) => r.st === 'valid');

  const body = rows
    .slice()
    .sort((a, b) => LIC_RANK[a.st] - LIC_RANK[b.st] || a.name.localeCompare(b.name, 'he'))
    .map((r) => {
      const alarm = r.st === 'expired' || r.st === 'none' || r.st === 'nodate';
      return `<tr${alarm ? ' class="row-short"' : ''}>
          <td>${esc(r.name)}</td>
          <td class="num">${esc(r.pn)}</td>
          <td>${esc(r.dept)}</td>
          <td class="num">${r.no ? esc(r.no) : '—'}</td>
          <td class="num">${r.exp ? esc(fmtDay(r.exp)) : '—'}</td>
          <td class="${alarm ? 'bad' : r.st === 'soon' ? 'warn' : 'ok'}">${
            alarm ? '⚠ ' : r.st === 'valid' ? '✓ ' : ''
          }${LIC_LABEL[r.st]}</td>
          <td>${r.mil ? '✓' : '—'}</td>
          <td>${r.doc
            ? `<button class="linkbtn" data-act="doc" data-rid="${esc(r.rid)}" data-kind="civil">${
                S.docs[`${r.rid}:civil`] ? 'הסתרה' : 'צפייה'
              }</button>`
            : '—'}</td>
        </tr>
        ${S.docs[`${r.rid}:civil`]
          ? `<tr><td colspan="8"><img class="doc-img" src="${S.docs[`${r.rid}:civil`]}" alt="צילום רישיון של ${esc(r.name)}"></td></tr>`
          : ''}`;
    })
    .join('');

  return `
    <section class="panel">
      <h2 class="panel-title">רישיונות נהיגה</h2>
      <p class="panel-sub">מי מחזיק רישיון אזרחי בתוקף ומי לא. פג תוקף או חסר — מסומן באדום. מכבד את החיפוש והסינון.</p>
      <div class="stat-row">
        <div class="stat"><span class="stat-n num">${ok.length}</span><span class="stat-l">✓ בתוקף</span></div>
        <div class="stat"><span class="stat-n num">${soon.length}</span><span class="stat-l">פגים בקרוב</span></div>
        <div class="stat"><span class="stat-n num">${bad.length}</span><span class="stat-l">⚠ לא בתוקף</span></div>
      </div>
      ${bad.length
        ? `<div class="callout alert"><p class="mb0"><strong class="num">${bad.length}</strong> חיילים ללא רישיון אזרחי בתוקף — ראו את השורות האדומות.</p></div>`
        : ''}
      ${rows.length
        ? `<div class="tbl-scroll">
             <table class="tbl">
               <thead><tr>
                 <th>שם</th><th class="num">מ״א</th><th>מחלקה</th>
                 <th class="num">מס׳ רישיון</th><th class="num">בתוקף עד</th>
                 <th>סטטוס</th><th>צבאי</th><th>צילום</th>
               </tr></thead>
               <tbody>${body}</tbody>
             </table>
           </div>
           <button class="btn ghost wide mt" data-act="export-lic">ייצוא רישיונות ל-CSV</button>`
        : '<p class="empty">אין רשומות מאושרות.</p>'}
    </section>`;
}

function exportLicCsv() {
  if (!window.confirm('הקובץ אינו מוצפן ומכיל פרטים אישיים. להמשיך?')) return;
  const approved = S.recs.filter((r) => r.status === 'approved' && !r.damaged);
  const rows = licenceRows(approved)
    .slice()
    .sort((a, b) => LIC_RANK[a.st] - LIC_RANK[b.st] || a.name.localeCompare(b.name, 'he'));
  const lines = [
    ['שם', 'מספר אישי', 'מחלקה', 'מספר רישיון', 'בתוקף עד', 'סטטוס', 'רישיון צבאי', 'צילום מצורף'],
    ...rows.map((r) => [
      r.name, r.pn, r.dept, r.no, r.exp ? fmtDay(r.exp) : '',
      LIC_LABEL[r.st], r.mil ? 'כן' : 'לא', r.doc ? 'כן' : 'לא',
    ]),
  ];
  downloadCsv(lines.map((l) => l.map(csvCell).join(',')), 'tzayad-licences.csv');
}

// Weapon register: serial → holder. The one table a logistics NCO reaches for
// when a serial turns up and they need to know whose it is.
function weaponsPanel(approved) {
  const visible = applyFilters(approved);
  const armed = visible.filter((r) => r.data.weapon);
  const unarmed = visible.filter((r) => !r.data.weapon);

  const rows = armed
    .slice()
    .sort((a, b) => String(a.data.weapon).localeCompare(String(b.data.weapon), 'en', { numeric: true }))
    .map((rec) => {
      const d = rec.data;
      const shown = S.revealed.has(rec.rid);
      return `<tr>
          <td class="num wpn">${esc(d.weapon)}</td>
          <td>${esc(d.name)}</td>
          <td class="num">${esc(d.pn)}</td>
          <td>${esc(deptName(d.dept))}</td>
          <td class="num">
            ${esc(shown ? d.phone : maskPhone(d.phone))}
            <button class="linkbtn" data-act="reveal" data-rid="${esc(rec.rid)}">${shown ? 'הסתרה' : 'הצגה'}</button>
          </td>
        </tr>`;
    })
    .join('');

  return `
    <section class="panel">
      <h2 class="panel-title">רשימת נשקים</h2>
      <p class="panel-sub">מספר סידורי מול מחזיק הנשק, ממוין לפי מספר. מכבד את החיפוש והסינון.</p>
      <div class="stat-row">
        <div class="stat"><span class="stat-n num">${armed.length}</span><span class="stat-l">נשקים משויכים</span></div>
        <div class="stat"><span class="stat-n num">${unarmed.length}</span><span class="stat-l">ללא נשק רשום</span></div>
      </div>
      ${armed.length
        ? `<div class="tbl-scroll">
             <table class="tbl">
               <thead><tr><th class="num">מס׳ סידורי</th><th>שם</th><th class="num">מ״א</th><th>מחלקה</th><th class="num">טלפון</th></tr></thead>
               <tbody>${rows}</tbody>
             </table>
           </div>
           <button class="btn ghost wide mt" data-act="export-weapons">ייצוא רשימת נשקים ל-CSV</button>`
        : '<p class="empty">אף חייל לא רשם מספר נשק עדיין.</p>'}
    </section>`;
}

function exportWeaponsCsv() {
  if (!window.confirm('הקובץ אינו מוצפן ומכיל פרטים אישיים. להמשיך?')) return;
  const lines = [['מספר סידורי', 'שם', 'מספר אישי', 'מחלקה', 'טלפון'].map(csvCell).join(',')];
  const armed = S.recs
    .filter((r) => r.status === 'approved' && !r.damaged && r.data && r.data.weapon)
    .sort((a, b) => String(a.data.weapon).localeCompare(String(b.data.weapon), 'en', { numeric: true }));
  for (const rec of armed) {
    const d = rec.data;
    lines.push([d.weapon, d.name, d.pn, deptName(d.dept), d.phone].map(csvCell).join(','));
  }
  downloadCsv(lines, 'tzayad-weapons.csv');
}

// The ledger, flattened: one row per soldier, two columns per item.
function exportLedgerCsv() {
  if (!window.confirm('הקובץ אינו מוצפן ומכיל פרטים אישיים. להמשיך?')) return;
  const head = [
    'שם', 'מספר אישי', 'מחלקה', 'מספר נשק',
    ...ITEMS.flatMap((i) => [`${i.name} — הוחתם`, `${i.name} — אצלו כעת`]),
    'סה״כ בחוץ',
  ];
  const lines = [head.map(csvCell).join(',')];
  for (const rec of S.recs) {
    if (rec.status !== 'approved' || rec.damaged || !rec.data) continue;
    const d = rec.data;
    lines.push([
      d.name, d.pn, deptName(d.dept), d.weapon || '',
      ...ITEMS.flatMap((i) => {
        const it = d.items[i.id];
        return it ? [it.t, it.t - (it.r || 0)] : ['', ''];
      }),
      outstanding(d),
    ].map(csvCell).join(','));
  }
  downloadCsv(lines, 'tzayad-ledger.csv');
}

// Excel-safe CSV cell: always quoted, embedded quotes doubled.
const csvCell = (v) => '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"';

function downloadCsv(lines, filename) {
  const blob = new Blob(['\uFEFF' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
}

// The quartermaster's ledger: one row per soldier, one column per item, so
// "who is signed for what" is answerable at a glance. Respects the active
// search and department filter.
function ledgerPanel(approved) {
  const visible = applyFilters(approved);
  const heads = ITEMS.map(
    (i) => `<th class="num lg-col" title="${esc(i.name)}"><span class="tbl-ico" aria-hidden="true">${i.icon}</span><span class="lg-h">${esc(i.name)}</span></th>`
  ).join('');

  const pgLg = paged('ledger', visible);
  const body = pgLg.slice
    .map((rec) => {
      const d = rec.data;
      const out = outstanding(d);
      const cells = ITEMS.map((i) => {
        const it = d.items[i.id];
        if (!it) return '<td class="num dim">·</td>';
        const held = it.t - (it.r || 0);
        return `<td class="num ${held > 0 ? 'held' : 'back'}">${held > 0 ? held : '✓'}<span class="lg-of">/${it.t}</span></td>`;
      }).join('');
      return `<tr>
        <td class="lg-name">
          <span class="lg-nm">${esc(d.name)}</span>
          <span class="lg-sub num">${esc(d.pn)}</span>
          <span class="lg-sub">${esc(deptName(d.dept))}</span>
          ${d.weapon ? `<span class="lg-sub">נשק <span class="num">${esc(d.weapon)}</span></span>` : ''}
        </td>
        ${cells}
        <td class="num ${out > 0 ? 'warn' : 'ok'}">${out}</td>
      </tr>`;
    })
    .join('');

  return `
    <section class="panel">
      <h2 class="panel-title">מי חתום על מה</h2>
      <p class="panel-sub">כל שורה היא חייל, כל עמודה פריט. המספר הוא מה שעדיין אצלו, מתוך מה שהוחתם. ✓ = הוחזר במלואו.</p>
      ${visible.length
        ? `<div class="tbl-scroll">
             <table class="tbl lg">
               <thead><tr><th class="lg-name">חייל</th>${heads}<th class="num">בחוץ</th></tr></thead>
               <tbody>${body}</tbody>
             </table>
           </div>
           ${pager('ledger', pgLg)}
           <button class="btn ghost wide mt" data-act="export-ledger">ייצוא הטבלה ל-CSV</button>`
        : '<p class="empty">אין חיילים שתואמים את החיפוש.</p>'}
    </section>`;
}

/* ── Inventory (מלאי) ──────────────────────────────────────────────── */

const emptyInv = () => ({
  open: {}, extra: [], notes: '',
  armon: [], armonLog: [], ammo: [], ammoLog: [], vehicles: [], countedAt: {},
});

// The two counting registers are the same thing with different names, so they
// share one implementation and differ only by these descriptors.

// Issued/returned totals per catalog item across all approved records.
function issuedTotals() {
  const out = {};
  for (const item of ITEMS) out[item.id] = { t: 0, r: 0 };
  for (const rec of S.recs) {
    if (rec.status !== 'approved' || rec.damaged || !rec.data) continue;
    for (const item of ITEMS) {
      const it = rec.data.items[item.id];
      if (it) {
        out[item.id].t += it.t;
        out[item.id].r += it.r || 0;
      }
    }
  }
  return out;
}

function renderInvTab() {
  const inv = S.inv || emptyInv();
  const iss = issuedTotals();

  const rows = ITEMS.map((item) => {
    const open = Number(inv.open[item.id]) || 0;
    const held = iss[item.id].t - iss[item.id].r;   // still out with soldiers
    const left = open - held;                        // should be on the shelf
    return `<tr>
        <td>
          <span class="tbl-ico" aria-hidden="true">${item.icon}</span>
          ${esc(item.name)}
        </td>
        <td>
          <input class="input mini num" type="text" inputmode="numeric" maxlength="4" value="${open}"
                 data-act="inv-open" data-item="${item.id}" aria-label="מלאי פתיחה ${esc(item.name)}">
        </td>
        <td class="num">${held}</td>
        <td class="num ${left < 0 ? 'bad' : left === 0 ? 'warn' : 'ok'}">${left}</td>
      </tr>`;
  }).join('');

  // keep each row's true index so editing still targets the right entry
  const extraNeedle = S.invQ.trim().toLowerCase();
  const extraVisible = inv.extra
    .map((x, i) => ({ x, i }))
    .filter(({ x }) => !extraNeedle || (x.name || '').toLowerCase().includes(extraNeedle));

  const extraRows = extraVisible
    .map(
      ({ x, i }) => `<tr>
        <td><input class="input mini" type="text" maxlength="40" value="${esc(x.name)}"
                   data-act="inv-xname" data-i="${i}" aria-label="שם פריט" placeholder="שם הפריט"></td>
        <td><input class="input mini num" type="text" inputmode="numeric" maxlength="4" value="${Number(x.open) || 0}"
                   data-act="inv-xopen" data-i="${i}" aria-label="מלאי פתיחה"></td>
        <td><input class="input mini num" type="text" inputmode="numeric" maxlength="4" value="${Number(x.out) || 0}"
                   data-act="inv-xout" data-i="${i}" aria-label="בשימוש"></td>
        <td class="num ${(x.open - x.out) < 0 ? 'bad' : 'ok'}">${(Number(x.open) || 0) - (Number(x.out) || 0)}</td>
        <td><button class="linkbtn danger-link" data-act="inv-xdel" data-i="${i}" aria-label="מחיקת שורה">✕</button></td>
      </tr>`
    )
    .join('');

  const anyNeg =
    ITEMS.some((i) => (Number(inv.open[i.id]) || 0) - (iss[i.id].t - iss[i.id].r) < 0) ||
    inv.extra.some((x) => (Number(x.open) || 0) - (Number(x.out) || 0) < 0);

  return `
    <section class="panel">
      <h2 class="panel-title">מלאי ציוד</h2>
      <p class="panel-sub">הזינו כמה קיבלתם מכל פריט ביום קליטת הציוד. היתרה מחושבת אוטומטית מההחתמות המאושרות: <strong>פתיחה − אצל החיילים = נותר במחסן</strong>.</p>
      ${anyNeg
        ? '<div class="callout alert"><p class="mb0"><strong>יתרה שלילית</strong> — הוחתם יותר ממה שנרשם במלאי הפתיחה. בדקו את מלאי הפתיחה או את ההחתמות.</p></div>'
        : ''}
      <div class="tbl-scroll">
        <table class="tbl">
          <thead><tr><th>פריט</th><th>מלאי פתיחה</th><th class="num">אצל חיילים</th><th class="num">נותר במחסן</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </section>

    <section class="panel">
      <h2 class="panel-title">פריטים נוספים</h2>
      <p class="panel-sub">ציוד שהחיילים לא חותמים עליו בטופס (מזרנים, אוהלים וכו'). כאן הספירה ידנית — הזינו כמה יש וכמה בשימוש.</p>
      ${inv.extra.length > 4
        ? plainSearch('inv-search', 'inv-qclear', S.invQ, 'חיפוש פריט', inv.extra.length, extraVisible.length)
        : ''}
      ${inv.extra.length
        ? extraVisible.length
          ? `<div class="tbl-scroll">
             <table class="tbl">
               <thead><tr><th>פריט</th><th>סה״כ</th><th>בשימוש</th><th class="num">נותר</th><th></th></tr></thead>
               <tbody>${extraRows}</tbody>
             </table>
           </div>`
          : '<p class="empty">אין פריט שתואם את החיפוש.</p>'
        : '<p class="empty">אין פריטים נוספים. הוסיפו את הראשון למטה.</p>'}
      <button class="btn ghost wide mt" data-act="inv-xadd">+ הוספת פריט</button>
    </section>

    <section class="panel">
      <h2 class="panel-title">הערות</h2>
      <p class="panel-sub">טקסט חופשי — מה שצריך לזכור על המלאי. נשמר מוצפן כמו כל השאר.</p>
      <textarea class="input area" data-act="inv-notes" rows="5" maxlength="4000"
                placeholder="לדוגמה: 3 קסדות פגומות הוחזרו לאפסנאות ביום ג׳…">${esc(inv.notes || '')}</textarea>
      <button class="btn primary wide mt" data-act="inv-save">שמירת המלאי</button>
      ${inv.updatedAt ? `<p class="muted-txt mt center">עודכן לאחרונה ${esc(fmtDate(inv.updatedAt))}</p>` : ''}
    </section>`;
}

/* ── Overview dashboard ────────────────────────────────────────────── */

const pct = (n, d) => (d > 0 ? Math.round((n / d) * 100) : 0);

// A KPI tile. `tone` drives a colour edge, but the label and number always
// carry the meaning on their own — colour is never the sole signal.
function kpi(n, label, tone, sub) {
  return `
    <div class="kpi${tone ? ` is-${tone}` : ''}">
      <span class="kpi-n num">${n}</span>
      <span class="kpi-l">${label}</span>
      ${sub ? `<span class="kpi-sub">${sub}</span>` : ''}
    </div>`;
}

// Horizontal magnitude bar. Single hue for comparison, warning/critical tones
// reserved for actual state. Every bar is directly labelled.
function brkBar(name, valLabel, segs, title) {
  // Widths ride on a data attribute and are applied through the CSSOM after
  // render — the strict CSP forbids inline style attributes.
  const fills = segs
    .filter((s) => s.w > 0)
    .map((s) => `<span class="brk-fill${s.cls ? ` ${s.cls}` : ''}" data-w="${s.w.toFixed(2)}"></span>`)
    .join('');
  return `
    <div class="brk"${title ? ` title="${esc(title)}"` : ''}>
      <div class="brk-head">
        <span class="brk-name">${esc(name)}</span>
        <span class="brk-val">${valLabel}</span>
      </div>
      <div class="brk-track">${fills}</div>
    </div>`;
}

function renderOverviewTab() {
  const approved = S.recs.filter((r) => r.status === 'approved' && !r.damaged);
  const c = counts();
  const inv = S.inv || emptyInv();
  const iss = issuedTotals();

  let issued = 0, returned = 0;
  for (const i of ITEMS) { issued += iss[i.id].t; returned += iss[i.id].r; }
  const held = issued - returned;

  const shortItems = ITEMS.filter((i) => {
    const open = Number(inv.open[i.id]) || 0;
    return open > 0 && open - (iss[i.id].t - iss[i.id].r) < 0;
  });
  const armed = approved.filter((r) => r.data.weapon).length;
  const openReps = openReports();

  // licences are their own subject — kept apart from the weapon count
  const licRows = licenceRows(approved);
  const licOk = licRows.filter((r) => r.st === 'valid').length;
  const licBad = licRows.filter((r) => r.st !== 'valid' && r.st !== 'soon').length;
  const licSoon = licRows.filter((r) => r.st === 'soon').length;

  const tiles = [
    kpi(approved.length, 'חיילים מאושרים', null, `${c.pending} ממתינים לאישור`),
    kpi(held, 'פריטים בחוץ', held > 0 ? 'warn' : 'ok', `מתוך ${issued} שהוחתמו`),
    kpi(`${pct(returned, issued)}%`, 'אחוז החזרה', pct(returned, issued) === 100 ? 'ok' : null, `${returned} הוחזרו`),
    kpi(shortItems.length, 'פריטים בחוסר', shortItems.length ? 'bad' : 'ok',
        shortItems.length ? shortItems.map((i) => i.name).join(', ') : 'המלאי מכסה'),
    kpi(openReps, 'בקשות חוסר פתוחות', openReps ? 'warn' : 'ok'),
    kpi(armed, 'נשקים משויכים', null, `${approved.length - armed} ללא נשק רשום`),
    kpi(licBad, 'רישיונות לא בתוקף', licBad ? 'bad' : 'ok',
        `${licOk} בתוקף${licSoon ? ` · ${licSoon} פגים בקרוב` : ''}`),
  ].join('');

  // Per-department table. This used to be a stacked bar whose length compared
  // departments while its label read as a ratio — two different meanings in one
  // mark, which nobody could parse. Explicit columns say exactly what they say.
  const deptRows = DEPTS.map((dp) => {
    const recs = approved.filter((r) => r.data.dept === dp.id);
    let t = 0, r = 0;
    for (const rec of recs) {
      for (const i of ITEMS) {
        const it = rec.data.items[i.id];
        if (it) { t += it.t; r += it.r || 0; }
      }
    }
    return { ...dp, n: recs.length, t, r, out: t - r, pct: pct(r, t) };
  }).filter((d) => d.n);

  const deptTable = deptRows
    .map(
      (d) => `<tr>
        <td>${esc(d.name)}</td>
        <td class="num">${d.n}</td>
        <td class="num">${d.t}</td>
        <td class="num">${d.r}</td>
        <td class="num ${d.out > 0 ? 'warn' : 'ok'}">${d.out}</td>
        <td>
          <div class="minibar" title="${d.pct}% הוחזר">
            <span class="minibar-fill" data-w="${d.pct}"></span>
          </div>
          <span class="minibar-lbl num">${d.pct}%</span>
        </td>
      </tr>`
    )
    .join('');

  // per-item utilisation against opening stock
  const itemBars = ITEMS.map((i) => {
    const open = Number(inv.open[i.id]) || 0;
    const out = iss[i.id].t - iss[i.id].r;
    const shelf = open - out;
    const short = open > 0 && shelf < 0;
    const denom = Math.max(open, out, 1);
    return brkBar(
      i.name,
      open
        ? `<span class="num">${out}</span> בחוץ · <span class="num">${shelf}</span> במחסן${short ? ' ⚠ חוסר' : ''}`
        : `<span class="num">${out}</span> בחוץ · מלאי פתיחה לא הוזן`,
      [{ w: (out / denom) * 100, cls: short ? 'bad' : 'out' }],
      `${i.name}: פתיחה ${open || '—'}, בחוץ ${out}`
    );
  }).join('');

  return `
    <section class="panel">
      <h2 class="panel-title">סקירה כללית</h2>
      <p class="panel-sub">תמונת מצב מלאה. הנתונים מחושבים מרשומות מאושרות בלבד.</p>
      <div class="kpis">${tiles}</div>
      ${shortItems.length
        ? `<div class="callout alert">
             <p class="callout-title">⚠ חוסרים פעילים</p>
             <p class="mb0">${shortItems
               .map((i) => {
                 const open = Number(inv.open[i.id]) || 0;
                 const out = iss[i.id].t - iss[i.id].r;
                 return `<strong>${esc(i.name)}</strong> — חסרים <span class="num">${out - open}</span>`;
               })
               .join(' · ')}</p>
           </div>`
        : ''}
    </section>

    <section class="panel">
      <h2 class="panel-title">פילוח לפי מחלקה</h2>
      <p class="panel-sub">כמה פריטים הוחתמו בכל מחלקה, כמה מהם כבר הוחזרו, וכמה עדיין בחוץ.</p>
      ${deptRows.length
        ? `<div class="tbl-scroll">
             <table class="tbl">
               <thead><tr>
                 <th>מחלקה</th><th class="num">חיילים</th><th class="num">הוחתם</th>
                 <th class="num">הוחזר</th><th class="num">בחוץ</th><th>% הוחזר</th>
               </tr></thead>
               <tbody>${deptTable}</tbody>
             </table>
           </div>`
        : '<p class="empty">אין רשומות מאושרות.</p>'}
    </section>

    <section class="panel">
      <h2 class="panel-title">ניצולת מלאי לפי פריט</h2>
      <p class="panel-sub">כמה מכל פריט נמצא כרגע אצל החיילים.</p>
      <div class="brk-legend">
        <span class="lgnd out">בחוץ</span>
        <span class="lgnd bad">חוסר — הוחתם מעבר למלאי</span>
      </div>
      ${itemBars}
    </section>`;
}

/* ── Armoury (ארמון) ───────────────────────────────────────────────── */

function armonVisible() {
  const rows = (S.inv && S.inv.armon) || [];
  const q = (S.regQ.armon || '').trim().toLowerCase();
  return rows
    .map((x, i) => ({ x, i }))
    .filter(({ x }) => S.armKind === 'all' || x.kind === S.armKind)
    .filter(({ x }) =>
      !q ||
      (x.name || '').toLowerCase().includes(q) ||
      (x.serial || '').toLowerCase().includes(q) ||
      (x.owner || '').toLowerCase().includes(q)
    );
}

function renderArmonTab() {
  const all = (S.inv && S.inv.armon) || [];
  const log = (S.inv && S.inv.armonLog) || [];
  const vis = armonVisible();
  const p = paged('armon', vis);
  const weapons = all.filter((x) => x.kind === 'weapon').length;
  const tzelem = all.filter((x) => x.kind === 'tzelem').length;

  const kindChips = [['all', 'הכל'], ...ARM_KINDS.map((k) => [k.id, k.name])]
    .map(([id, label]) =>
      `<button class="filter" aria-pressed="${S.armKind === id}" data-act="arm-kind" data-k="${id}">${esc(label)}</button>`)
    .join('');

  const rows = p.slice.map(({ x, i }) => `
    <tr>
      <td>${esc(nameOf(ARM_KINDS, x.kind))}</td>
      <td>${esc(x.name)}</td>
      <td class="num wpn">${esc(x.serial)}</td>
      <td>${esc(x.owner)}</td>
      <td>
        <select class="input mini select-mini" data-act="arm-loc" data-i="${i}" aria-label="מיקום">
          ${ARM_LOCS.map((l) => `<option value="${l.id}"${x.loc === l.id ? ' selected' : ''}>${esc(l.name)}</option>`).join('')}
        </select>
      </td>
      <td class="num">${x.addedAt ? esc(fmtDay(new Date(x.addedAt).toISOString().slice(0, 10))) : '—'}</td>
      <td><button class="btn danger small" data-act="arm-remove" data-i="${i}">הסרה</button></td>
    </tr>`).join('');

  const logRows = log.slice(0, 200).map((e) => `
    <tr>
      <td class="num">${esc(fmtDate(e.t))}</td>
      <td class="${e.action === 'add' ? 'ok' : 'bad'}">${e.action === 'add' ? '+ הוספה' : '− הסרה'}</td>
      <td>${esc(nameOf(ARM_KINDS, e.kind))}</td>
      <td>${esc(e.name)}</td>
      <td class="num wpn">${esc(e.serial)}</td>
      <td>${esc(e.owner || '—')}</td>
      <td>${e.dest ? esc(nameOf(ARM_DESTS, e.dest)) : '—'}</td>
      <td>${esc(e.note || '')}</td>
    </tr>`).join('');

  return `
    <section class="panel">
      <h2 class="panel-title">הוספת פריט לארמון</h2>
      <p class="panel-sub">כל פריט נכנס עם סוג, מספר סידורי ושם מלא של מי שהוא רשום עליו. כל הוספה והסרה נרשמות ביומן.</p>
      <form data-form="arm-add" novalidate>
        <div class="grid2">
          <label class="field">
            <span class="field-label">סוג פריט <span class="req">*</span></span>
            <select class="input select" name="kind" required>
              ${ARM_KINDS.map((k) => `<option value="${k.id}">${esc(k.name)}</option>`).join('')}
            </select>
          </label>
          <label class="field">
            <span class="field-label">שם הפריט <span class="req">*</span></span>
            <input class="input" name="name" maxlength="60" placeholder="לדוגמה: M4 / משקפת לילה" required>
          </label>
          <label class="field">
            <span class="field-label">מספר סידורי <span class="req">*</span></span>
            <input class="input num" name="serial" maxlength="40" placeholder="M4-10021" required>
          </label>
          <label class="field">
            <span class="field-label">שם מלא של בעל הפריט <span class="req">*</span></span>
            <input class="input" name="owner" maxlength="60" placeholder="ישראל ישראלי" required>
          </label>
        </div>
        <p class="form-err" data-err></p>
        <button class="btn primary wide" type="submit">הוספה לארמון</button>
      </form>
    </section>

    <section class="panel">
      <h2 class="panel-title">פריטים בארמון</h2>
      <p class="panel-sub">כל הפריטים הרשומים בארמון. שינוי מיקום נשמר עם "שמירת השינויים".</p>
      <div class="kpis">
        ${kpi(all.length, 'סה״כ פריטים')}
        ${kpi(weapons, 'נשקים')}
        ${kpi(tzelem, 'פריטי צל״ם')}
      </div>
      ${all.length > 4
        ? plainSearch('arm-search', 'arm-qclear', S.regQ.armon || '',
                      'חיפוש לפי שם, מספר סידורי או בעלים', all.length, vis.length)
        : ''}
      <div class="filters">${kindChips}</div>
      ${vis.length
        ? `<div class="tbl-scroll">
             <table class="tbl">
               <thead><tr>
                 <th>סוג</th><th>פריט</th><th class="num">מס׳ סידורי</th><th>בעלים</th>
                 <th>מיקום</th><th class="num">נוסף</th><th></th>
               </tr></thead>
               <tbody>${rows}</tbody>
             </table>
           </div>
           ${pager('armon', p)}
           <div class="rec-actions mt">
             <button class="btn ghost" data-act="arm-export">ייצוא ל-CSV</button>
             <button class="btn primary" data-act="inv-save">שמירת השינויים</button>
           </div>`
        : `<p class="empty">${all.length ? 'אין פריט שתואם את החיפוש.' : 'הארמון ריק. הוסיפו פריט למעלה.'}</p>`}
    </section>

    <section class="panel">
      <h2 class="panel-title">יומן פעולות</h2>
      <p class="panel-sub">כל הוספה והסרה, עם כל הפרטים והתאריך. ${log.length > 200 ? 'מוצגות 200 הפעולות האחרונות.' : ''}</p>
      ${log.length
        ? `<div class="tbl-scroll">
             <table class="tbl">
               <thead><tr>
                 <th class="num">תאריך</th><th>פעולה</th><th>סוג</th><th>פריט</th>
                 <th class="num">מס׳ סידורי</th><th>בעלים</th><th>יעד</th><th>הערה</th>
               </tr></thead>
               <tbody>${logRows}</tbody>
             </table>
           </div>
           <button class="btn ghost wide mt" data-act="arm-log-export">ייצוא היומן ל-CSV</button>`
        : '<p class="empty">טרם בוצעו פעולות.</p>'}
    </section>`;
}

/* ── Tzelem report ─────────────────────────────────────────────────── */

function renderTzelemTab() {
  const all = (S.inv && S.inv.armon) || [];
  const q = (S.regQ.tzelem || '').trim().toLowerCase();
  const vis = all.filter(
    (x) =>
      !q ||
      (x.name || '').toLowerCase().includes(q) ||
      (x.serial || '').toLowerCase().includes(q) ||
      (x.owner || '').toLowerCase().includes(q)
  );
  const byLoc = ARM_LOCS.map((l) => ({ ...l, n: all.filter((x) => x.loc === l.id).length }));

  const rows = vis.map((x) => `
    <tr>
      <td>${esc(nameOf(ARM_KINDS, x.kind))}</td>
      <td>${esc(x.name)}</td>
      <td class="num wpn">${esc(x.serial)}</td>
      <td>${esc(x.owner)}</td>
      <td class="${x.loc === 'armon' ? 'ok' : 'warn'}">${esc(nameOf(ARM_LOCS, x.loc))}</td>
    </tr>`).join('');

  return `
    <section class="panel">
      <h2 class="panel-title">דו״ח צלם</h2>
      <p class="panel-sub">כל הפריטים הרשומים בארמון — נשקים וצל״ם — והיכן כל אחד נמצא. המיקום נקבע בלשונית ארמון.</p>
      <div class="kpis">
        ${kpi(all.length, 'סה״כ פריטים')}
        ${byLoc.map((l) => kpi(l.n, l.name, l.id === 'armon' ? 'ok' : 'warn')).join('')}
      </div>
      ${all.length > 4
        ? plainSearch('tz-search', 'tz-qclear', S.regQ.tzelem || '',
                      'חיפוש לפי שם, מספר סידורי או בעלים', all.length, vis.length)
        : ''}
      ${vis.length
        ? `<div class="tbl-scroll">
             <table class="tbl" id="tzTable">
               <thead><tr><th>סוג</th><th>פריט</th><th class="num">מס׳ סידורי</th><th>בעלים</th><th>מיקום</th></tr></thead>
               <tbody>${rows}</tbody>
             </table>
           </div>
           <div class="rec-actions mt">
             <button class="btn primary" data-act="tz-pdf">הפקת PDF</button>
             <button class="btn wa ghost-wa" data-act="tz-wa">שליחת סיכום בוואטסאפ</button>
             <button class="btn ghost" data-act="tz-export">ייצוא ל-CSV</button>
           </div>
           <p class="field-hint mt center">"הפקת PDF" פותחת את חלון ההדפסה — בחרו <strong>שמירה כ-PDF</strong>. וואטסאפ מקבל טקסט בלבד, ולכן הכפתור שולח סיכום ומצרפים את ה-PDF ידנית.</p>`
        : `<p class="empty">${all.length ? 'אין פריט שתואם את החיפוש.' : 'אין פריטים בארמון עדיין.'}</p>`}
    </section>`;
}

/* ── Ammunition & alpha ────────────────────────────────────────────── */

function renderAmmoTab() {
  const all = (S.inv && S.inv.ammo) || [];
  const log = (S.inv && S.inv.ammoLog) || [];
  const q = (S.regQ.ammo || '').trim().toLowerCase();
  const vis = all.map((x, i) => ({ x, i })).filter(({ x }) => !q || (x.name || '').toLowerCase().includes(q));
  const total = all.reduce((n, x) => n + x.qty, 0);

  const rows = vis.map(({ x, i }) => `
    <tr${x.qty === 0 ? ' class="row-short"' : ''}>
      <td>${esc(x.name)}</td>
      <td class="num ${x.qty === 0 ? 'bad' : 'ok'}">${x.qty}</td>
      <td>
        <button class="btn ghost small" data-act="ammo-issue" data-i="${i}" ${x.qty === 0 ? 'disabled' : ''}>הוצאה</button>
        <button class="btn ghost small" data-act="ammo-add-qty" data-i="${i}">הוספה</button>
        <button class="linkbtn danger-link" data-act="ammo-del" data-i="${i}">✕</button>
      </td>
    </tr>`).join('');

  const logRows = log.slice(0, 200).map((e) => `
    <tr>
      <td class="num">${esc(fmtDate(e.t))}</td>
      <td class="${e.action === 'add' ? 'ok' : 'bad'}">${e.action === 'add' ? '+ כניסה' : '− הוצאה'}</td>
      <td>${esc(e.name)}</td>
      <td class="num">${e.qty}</td>
      <td>${e.dest ? esc(nameOf(AMMO_DESTS, e.dest)) : '—'}</td>
      <td>${esc(e.who || '')}</td>
    </tr>`).join('');

  return `
    <section class="panel">
      <h2 class="panel-title">הוספת פריט תחמושת</h2>
      <p class="panel-sub">פריט חדש נכנס עם כמות התחלתית. הוצאות וכניסות נרשמות ביומן.</p>
      <form data-form="ammo-add" novalidate>
        <div class="grid2">
          <label class="field">
            <span class="field-label">שם הפריט <span class="req">*</span></span>
            <input class="input" name="name" maxlength="60" placeholder="לדוגמה: 5.56 / רימון עשן" required>
          </label>
          <label class="field">
            <span class="field-label">כמות <span class="req">*</span></span>
            <input class="input num" name="qty" type="number" min="1" max="999999" placeholder="100" required>
          </label>
        </div>
        <p class="form-err" data-err></p>
        <button class="btn primary wide" type="submit">הוספה למלאי</button>
      </form>
    </section>

    <section class="panel">
      <h2 class="panel-title">מלאי תחמושת ואלפא</h2>
      <div class="kpis">
        ${kpi(all.length, 'סוגי פריטים')}
        ${kpi(total, 'סה״כ יחידות')}
        ${kpi(all.filter((x) => x.qty === 0).length, 'אזלו מהמלאי', all.some((x) => x.qty === 0) ? 'bad' : 'ok')}
      </div>
      ${all.length > 4
        ? plainSearch('ammo-search', 'ammo-qclear', S.regQ.ammo || '', 'חיפוש פריט', all.length, vis.length)
        : ''}
      ${vis.length
        ? `<div class="tbl-scroll">
             <table class="tbl">
               <thead><tr><th>פריט</th><th class="num">כמות</th><th></th></tr></thead>
               <tbody>${rows}</tbody>
             </table>
           </div>
           <button class="btn ghost wide mt" data-act="ammo-export">ייצוא ל-CSV</button>`
        : `<p class="empty">${all.length ? 'אין פריט שתואם את החיפוש.' : 'המלאי ריק. הוסיפו פריט למעלה.'}</p>`}
    </section>

    <section class="panel">
      <h2 class="panel-title">יומן תנועות</h2>
      ${log.length
        ? `<div class="tbl-scroll">
             <table class="tbl">
               <thead><tr><th class="num">תאריך</th><th>פעולה</th><th>פריט</th><th class="num">כמות</th><th>יעד</th><th>למי</th></tr></thead>
               <tbody>${logRows}</tbody>
             </table>
           </div>
           <button class="btn ghost wide mt" data-act="ammo-log-export">ייצוא היומן ל-CSV</button>`
        : '<p class="empty">טרם בוצעו תנועות.</p>'}
    </section>`;
}

/* ── Vehicles ──────────────────────────────────────────────────────── */

function renderVehTab() {
  const all = (S.inv && S.inv.vehicles) || [];
  const q = (S.regQ.veh || '').trim().toLowerCase();
  const vis = all
    .map((x, i) => ({ x, i }))
    .filter(({ x }) => !q || (x.plate || '').toLowerCase().includes(q) || (x.company || '').toLowerCase().includes(q));
  const today = new Date().toISOString().slice(0, 10);
  const overdue = all.filter((v) => v.service && v.service < today).length;
  const incomplete = all.filter((v) => VEH_KIT.some((k) => !v[k.id])).length;

  const rows = vis.map(({ x, i }) => {
    const late = x.service && x.service < today;
    const missing = VEH_KIT.filter((k) => !x[k.id]);
    return `<tr${late || missing.length ? ' class="row-short"' : ''}>
      <td><input class="input mini num" type="text" maxlength="20" value="${esc(x.plate)}"
                 data-act="veh-plate" data-i="${i}" aria-label="מספר רכב" placeholder="12-345-67"></td>
      <td><input class="input mini" type="text" maxlength="40" value="${esc(x.company)}"
                 data-act="veh-company" data-i="${i}" aria-label="חברת השכרה" placeholder="חברה"></td>
      <td><input class="input mini num" type="text" inputmode="numeric" maxlength="7" value="${x.km}"
                 data-act="veh-km" data-i="${i}" aria-label="ק״מ עדכני"></td>
      <td><input class="input mini" type="date" value="${esc(x.service)}"
                 data-act="veh-service" data-i="${i}" aria-label="מועד טיפול"></td>
      ${VEH_KIT.map((k) => `
        <td class="num">
          <input type="checkbox" class="kitbox" data-act="veh-kit" data-i="${i}" data-k="${k.id}"
                 ${x[k.id] ? 'checked' : ''} aria-label="${esc(k.name)} ברכב ${esc(x.plate || i + 1)}">
        </td>`).join('')}
      <td class="${late ? 'bad' : missing.length ? 'warn' : 'ok'}">${
        late ? '⚠ טיפול עבר' : missing.length ? `חסר: ${missing.map((k) => k.name).join(', ')}` : '✓ תקין'
      }</td>
      <td><button class="linkbtn danger-link" data-act="veh-del" data-i="${i}" aria-label="מחיקת רכב">✕</button></td>
    </tr>`;
  }).join('');

  return `
    <section class="panel">
      <h2 class="panel-title">רכבים</h2>
      <p class="panel-sub">מספר רכב, חברת השכרה, ק״מ עדכני ומועד טיפול. סמנו מה קיים ברכב — שורה עם חוסר או טיפול שעבר נצבעת באדום.</p>
      <div class="kpis">
        ${kpi(all.length, 'רכבים')}
        ${kpi(overdue, 'טיפול עבר', overdue ? 'bad' : 'ok')}
        ${kpi(incomplete, 'חסר ציוד', incomplete ? 'warn' : 'ok')}
      </div>
      ${all.length > 4
        ? plainSearch('veh-search', 'veh-qclear', S.regQ.veh || '', 'חיפוש לפי מספר רכב או חברה', all.length, vis.length)
        : ''}
      ${vis.length
        ? `<div class="tbl-scroll">
             <table class="tbl">
               <thead><tr>
                 <th class="num">מספר רכב</th><th>חברת השכרה</th><th class="num">ק״מ</th><th class="num">טיפול</th>
                 ${VEH_KIT.map((k) => `<th class="num lg-col"><span class="lg-h">${esc(k.name)}</span></th>`).join('')}
                 <th>סטטוס</th><th></th>
               </tr></thead>
               <tbody>${rows}</tbody>
             </table>
           </div>`
        : `<p class="empty">${all.length ? 'אין רכב שתואם את החיפוש.' : 'אין רכבים. הוסיפו את הראשון למטה.'}</p>`}
      <div class="rec-actions mt">
        <button class="btn ghost" data-act="veh-add">+ הוספת רכב</button>
        <button class="btn ghost" data-act="veh-export">ייצוא ל-CSV</button>
        <button class="btn primary" data-act="inv-save">שמירת השינויים</button>
      </div>
    </section>`;
}

/* ── Armoury / ammunition / vehicle actions ───────────────────────── */

const logPush = (key, entry) => {
  S.inv[key] = [entry, ...(S.inv[key] || [])].slice(0, 5000);
};

function armAdd(form) {
  const kind = form.kind.value;
  const name = form.name.value.trim();
  const serial = form.serial.value.trim();
  const owner = form.owner.value.trim();
  if (!ARM_KINDS.some((k) => k.id === kind)) return setFormErr(form, 'נא לבחור סוג פריט');
  if (name.length < 2) return setFormErr(form, 'נא למלא שם פריט');
  if (serial.length < 2) return setFormErr(form, 'נא למלא מספר סידורי');
  if (owner.length < 2) return setFormErr(form, 'נא למלא שם מלא של בעל הפריט');
  const dup = (S.inv.armon || []).find((x) => x.serial.toLowerCase() === serial.toLowerCase());
  if (dup) return setFormErr(form, `מספר סידורי ${serial} כבר קיים בארמון (${dup.name})`);
  setFormErr(form, '');
  const now = Date.now();
  S.inv.armon = [...(S.inv.armon || []), { id: rndId(), kind, name, serial, owner, loc: 'armon', note: '', addedAt: now }];
  logPush('armonLog', { t: now, action: 'add', kind, name, serial, owner, dest: '', note: '' });
  invSave();
}

function armRemove(i) {
  const it = (S.inv.armon || [])[i];
  if (!it) return;
  const opts = ARM_DESTS.map((d, n) => `${n + 1} — ${d.name}`).join('\n');
  const pick = window.prompt(`לאן מועבר "${it.name}" (${it.serial})?\n${opts}`, '1');
  if (pick === null) return;
  const dest = ARM_DESTS[parseInt(pick, 10) - 1];
  if (!dest) { toast('בחירה לא תקינה — לא בוצעה הסרה', true); return; }
  const note = window.prompt('הערה (רשות):', '') || '';
  S.inv.armon = S.inv.armon.filter((_, n) => n !== i);
  logPush('armonLog', {
    t: Date.now(), action: 'remove', kind: it.kind, name: it.name,
    serial: it.serial, owner: it.owner, dest: dest.id, note: note.slice(0, 120),
  });
  invSave();
}

function ammoAdd(form) {
  const name = form.name.value.trim();
  const qty = parseInt(form.qty.value, 10);
  if (name.length < 2) return setFormErr(form, 'נא למלא שם פריט');
  if (!Number.isFinite(qty) || qty < 1) return setFormErr(form, 'נא למלא כמות חיובית');
  setFormErr(form, '');
  const now = Date.now();
  const existing = (S.inv.ammo || []).find((x) => x.name.toLowerCase() === name.toLowerCase());
  if (existing) existing.qty = Math.min(999999, existing.qty + qty);
  else S.inv.ammo = [...(S.inv.ammo || []), { id: rndId(), name, qty }];
  logPush('ammoLog', { t: now, action: 'add', name, qty, dest: '', who: '' });
  invSave();
}

function ammoMove(i, issue) {
  const it = (S.inv.ammo || [])[i];
  if (!it) return;
  const n = parseInt(window.prompt(`${issue ? 'הוצאה' : 'הוספה'} — ${it.name} (במלאי: ${it.qty})\nכמות:`, '1'), 10);
  if (!Number.isFinite(n) || n < 1) return;
  if (issue && n > it.qty) { toast(`אין מספיק במלאי — יש ${it.qty}`, true); return; }
  let dest = '', who = '';
  if (issue) {
    const opts = AMMO_DESTS.map((d, k) => `${k + 1} — ${d.name}`).join('\n');
    const pick = window.prompt(`לאן?\n${opts}`, '1');
    if (pick === null) return;
    const d = AMMO_DESTS[parseInt(pick, 10) - 1];
    if (!d) { toast('בחירה לא תקינה', true); return; }
    dest = d.id;
    who = (window.prompt('שם מלא / פרטי המשימה (רשות):', '') || '').slice(0, 60);
  }
  it.qty = Math.max(0, Math.min(999999, it.qty + (issue ? -n : n)));
  logPush('ammoLog', { t: Date.now(), action: issue ? 'issue' : 'add', name: it.name, qty: n, dest, who });
  invSave();
}

/* — exports — */

function exportArmonCsv() {
  if (!window.confirm('הקובץ אינו מוצפן. להמשיך?')) return;
  const lines = [['סוג', 'פריט', 'מספר סידורי', 'בעלים', 'מיקום', 'תאריך הוספה'].map(csvCell).join(',')];
  for (const x of S.inv.armon || []) {
    lines.push([nameOf(ARM_KINDS, x.kind), x.name, x.serial, x.owner, nameOf(ARM_LOCS, x.loc),
      x.addedAt ? fmtDate(x.addedAt) : ''].map(csvCell).join(','));
  }
  downloadCsv(lines, 'tzayad-armon.csv');
}

function exportArmLogCsv() {
  if (!window.confirm('הקובץ אינו מוצפן. להמשיך?')) return;
  const lines = [['תאריך', 'פעולה', 'סוג', 'פריט', 'מספר סידורי', 'בעלים', 'יעד', 'הערה'].map(csvCell).join(',')];
  for (const e of S.inv.armonLog || []) {
    lines.push([fmtDate(e.t), e.action === 'add' ? 'הוספה' : 'הסרה', nameOf(ARM_KINDS, e.kind),
      e.name, e.serial, e.owner, e.dest ? nameOf(ARM_DESTS, e.dest) : '', e.note].map(csvCell).join(','));
  }
  downloadCsv(lines, 'tzayad-armon-log.csv');
}

function exportTzelemCsv() {
  if (!window.confirm('הקובץ אינו מוצפן. להמשיך?')) return;
  const lines = [
    ['דו״ח צלם', fmtDate(Date.now())].map(csvCell).join(','),
    '',
    ['סוג', 'פריט', 'מספר סידורי', 'בעלים', 'מיקום'].map(csvCell).join(','),
  ];
  for (const x of S.inv.armon || []) {
    lines.push([nameOf(ARM_KINDS, x.kind), x.name, x.serial, x.owner, nameOf(ARM_LOCS, x.loc)].map(csvCell).join(','));
  }
  downloadCsv(lines, 'tzayad-tzelem.csv');
}

function exportAmmoCsv() {
  if (!window.confirm('הקובץ אינו מוצפן. להמשיך?')) return;
  const lines = [['פריט', 'כמות'].map(csvCell).join(',')];
  for (const x of S.inv.ammo || []) lines.push([x.name, x.qty].map(csvCell).join(','));
  downloadCsv(lines, 'tzayad-ammo.csv');
}

function exportAmmoLogCsv() {
  if (!window.confirm('הקובץ אינו מוצפן. להמשיך?')) return;
  const lines = [['תאריך', 'פעולה', 'פריט', 'כמות', 'יעד', 'למי'].map(csvCell).join(',')];
  for (const e of S.inv.ammoLog || []) {
    lines.push([fmtDate(e.t), e.action === 'add' ? 'כניסה' : 'הוצאה', e.name, e.qty,
      e.dest ? nameOf(AMMO_DESTS, e.dest) : '', e.who].map(csvCell).join(','));
  }
  downloadCsv(lines, 'tzayad-ammo-log.csv');
}

function exportVehCsv() {
  if (!window.confirm('הקובץ אינו מוצפן. להמשיך?')) return;
  const today = new Date().toISOString().slice(0, 10);
  const lines = [
    ['מספר רכב', 'חברת השכרה', 'ק״מ עדכני', 'מועד טיפול',
      ...VEH_KIT.map((k) => k.name), 'סטטוס'].map(csvCell).join(','),
  ];
  for (const v of S.inv.vehicles || []) {
    const late = v.service && v.service < today;
    const missing = VEH_KIT.filter((k) => !v[k.id]);
    lines.push([
      v.plate, v.company, v.km, v.service ? fmtDay(v.service) : '',
      ...VEH_KIT.map((k) => (v[k.id] ? 'כן' : 'לא')),
      late ? 'טיפול עבר' : missing.length ? `חסר: ${missing.map((k) => k.name).join(', ')}` : 'תקין',
    ].map(csvCell).join(','));
  }
  downloadCsv(lines, 'tzayad-vehicles.csv');
}

/* — Tzelem PDF + WhatsApp summary — */

// No PDF library can be loaded under this CSP, and Hebrew needs font embedding,
// so the report is laid out for print and the browser's "Save as PDF" makes the
// actual file. That keeps it dependency-free and renders Hebrew correctly.
function tzelemPdf() {
  const rows = (S.inv.armon || []);
  if (!rows.length) { toast('אין פריטים להפקה', true); return; }
  const host = document.createElement('section');
  host.className = 'printdoc';
  host.innerHTML = `
    <header class="pd-head">
      <img class="pd-logo" src="/logo.png" alt="">
      <div>
        <h1 class="pd-title">דו״ח צלם — מסייעת 951</h1>
        <p class="pd-date">הופק ${esc(fmtDate(Date.now()))} · ${rows.length} פריטים</p>
      </div>
    </header>
    <table class="pd-tbl">
      <thead><tr><th>#</th><th>סוג</th><th>פריט</th><th>מספר סידורי</th><th>בעלים</th><th>מיקום</th></tr></thead>
      <tbody>
        ${rows.map((x, i) => `<tr>
          <td>${i + 1}</td>
          <td>${esc(nameOf(ARM_KINDS, x.kind))}</td>
          <td>${esc(x.name)}</td>
          <td>${esc(x.serial)}</td>
          <td>${esc(x.owner)}</td>
          <td>${esc(nameOf(ARM_LOCS, x.loc))}</td>
        </tr>`).join('')}
      </tbody>
    </table>
    <footer class="pd-foot">
      ${ARM_LOCS.map((l) => `${l.name}: ${rows.filter((x) => x.loc === l.id).length}`).join(' · ')}
      <span class="pd-sign">חתימת אחראי: ____________________</span>
    </footer>`;
  document.body.appendChild(host);
  document.body.classList.add('printing');
  const cleanup = () => {
    document.body.classList.remove('printing');
    host.remove();
    window.removeEventListener('afterprint', cleanup);
  };
  window.addEventListener('afterprint', cleanup);
  window.print();
  setTimeout(cleanup, 60000);   // belt and braces if afterprint never fires
}

function tzelemWa() {
  const rows = (S.inv.armon || []);
  if (!rows.length) { toast('אין פריטים לשליחה', true); return; }
  const counts = ARM_LOCS.map((l) => `${l.name}: ${rows.filter((x) => x.loc === l.id).length}`).join('\n');
  const offsite = rows.filter((x) => x.loc !== 'armon');
  const msg =
    `*דו״ח צלם — מסייעת 951*\n${fmtDate(Date.now())}\n\n` +
    `סה״כ פריטים: ${rows.length}\n${counts}\n` +
    (offsite.length
      ? `\n*לא בארמון:*\n${offsite.slice(0, 40).map((x) => `• ${x.name} (${x.serial}) — ${nameOf(ARM_LOCS, x.loc)}, ${x.owner}`).join('\n')}`
      : '\nכל הפריטים בארמון.');
  window.open(`https://wa.me/?text=${encodeURIComponent(msg)}`, '_blank', 'noopener');
}

/* ── Shortage reports (admin) ──────────────────────────────────────── */

// 'open' and 'partial' both still need the admin's attention.
const openReports = () => S.reports.filter((r) => r.status !== 'done' && !r.damaged).length;

const armonCount = () => ((S.inv && S.inv.armon) || []).length;

// Vehicles missing any kit item, or overdue for service.
function vehAlerts() {
  const today = new Date().toISOString().slice(0, 10);
  return ((S.inv && S.inv.vehicles) || []).filter(
    (v) => VEH_KIT.some((k) => !v[k.id]) || (v.service && v.service < today)
  ).length;
}

const REP_LABEL = { open: 'טרם טופל', partial: 'טופל חלקית', done: '✓ טופל' };

// Reply to a soldier whose request was handled. Sent from the admin's device,
// like every other message here — the server never learns the phone number.
function repWaLink(d, st) {
  const msg =
    '*עדכון בקשת ציוד — מסייעת 951*\n\n' +
    `שלום ${d.name},\n` +
    (st === 'done'
      ? 'הבקשה שלך טופלה במלואה.\n\n'
      : 'הבקשה שלך טופלה חלקית — יתרת הפריטים תושלם בהמשך.\n\n') +
    `*הבקשה שהגשת:*\n${d.text}\n\n` +
    'לפרטים נוספים פנו למנהל הציוד.';
  return `https://wa.me/${waPhone(d.phone)}?text=${encodeURIComponent(msg)}`;
}

function renderReportsTab() {
  const filters = [
    ['open', 'דורש טיפול'],
    ['partial', 'טופל חלקית'],
    ['done', 'טופלו'],
    ['all', 'הכל'],
  ]
    .map(
      ([id, label]) =>
        `<button class="filter" aria-pressed="${S.repFilter === id}" data-act="rep-filter" data-f="${id}">${label}</button>`
    )
    .join('');

  const byStatus = S.reports.filter((r) => {
    if (r.damaged || S.repFilter === 'all') return true;
    if (S.repFilter === 'open') return r.status !== 'done';   // open + partial
    return r.status === S.repFilter;
  });
  const needle = S.repQ.trim().toLowerCase();
  const visible = byStatus.filter((r) => {
    if (!needle) return true;
    if (r.damaged || !r.data) return false;
    return (
      (r.data.name || '').toLowerCase().includes(needle) ||
      (r.data.text || '').toLowerCase().includes(needle)
    );
  });

  const pgReports = paged('reports', visible);
  const cards = pgReports.slice
    .map((rec) => {
      if (rec.damaged) {
        return `<article class="rec broken">
            <header class="rec-head"><div class="rec-name">דיווח פגום</div><span class="state live">שגיאה</span></header>
            <p class="muted-txt">לא ניתן לפענח את הדיווח.</p>
            <div class="rec-actions"><button class="btn danger" data-act="rep-del" data-id="${esc(rec.id)}">מחיקה</button></div>
          </article>`;
      }
      const d = rec.data;
      const st = rec.status === 'done' ? 'done' : rec.status === 'partial' ? 'partial' : 'open';
      const canMsg = !!d.phone;
      return `
        <article class="rec ${st === 'done' ? 'done' : st === 'partial' ? 'live' : 'wait'}">
          <header class="rec-head">
            <div>
              <div class="rec-name">${esc(d.name)}</div>
              <div class="rec-meta">דווח ${esc(fmtDate(d.createdAt))}</div>
              ${d.pn || d.dept
                ? `<div class="rec-meta">${d.pn ? `מ״א <span class="num">${esc(d.pn)}</span>` : ''}${d.pn && d.dept ? ' · ' : ''}${d.dept ? esc(deptName(d.dept)) : ''}</div>`
                : ''}
            </div>
            <span class="state ${st === 'done' ? 'done' : st === 'partial' ? 'live' : 'wait'}">${REP_LABEL[st]}</span>
          </header>
          ${d.phone
            ? `<div class="rec-meta">טלפון:
                 <span class="num">${esc(S.revealed.has(rec.id) ? d.phone : maskPhone(d.phone))}</span>
                 <button class="linkbtn" data-act="rep-reveal" data-id="${esc(rec.id)}">${S.revealed.has(rec.id) ? 'הסתרה' : 'הצגה'}</button>
               </div>`
            : '<div class="rec-meta muted-txt">לא הושאר טלפון — אי אפשר לעדכן את החייל</div>'}
          <blockquote class="rep-text">${esc(d.text)}</blockquote>

          <fieldset class="rep-states">
            <legend class="field-label">סטטוס טיפול</legend>
            ${['open', 'partial', 'done'].map((v) => `
              <label class="rep-state ${st === v ? 'on' : ''}">
                <input type="radio" name="st-${esc(rec.id)}" data-act="rep-state"
                       data-id="${esc(rec.id)}" data-st="${v}" ${st === v ? 'checked' : ''}>
                <span class="rep-tick" aria-hidden="true"></span>
                <span>${REP_LABEL[v]}</span>
              </label>`).join('')}
          </fieldset>

          <div class="rec-actions">
            ${canMsg && st !== 'open'
              ? `<a class="btn wa" href="${esc(repWaLink(d, st))}" data-act="rep-sent"
                    data-id="${esc(rec.id)}" target="_blank" rel="noopener noreferrer">${
                      d.replied ? 'שליחה חוזרת' : 'עדכון החייל בוואטסאפ'
                    }</a>`
              : ''}
            ${canMsg && st === 'open'
              ? `<a class="btn wa ghost-wa" href="https://wa.me/${waPhone(d.phone)}" target="_blank" rel="noopener noreferrer">וואטסאפ</a>`
              : ''}
            <button class="btn danger" data-act="rep-del" data-id="${esc(rec.id)}">מחיקה</button>
          </div>
        </article>`;
    })
    .join('');

  return `
    <section class="panel">
      <h2 class="panel-title">בקשות ודיווחי חוסר</h2>
      <p class="panel-sub">בקשות שחיילים שלחו בעצמם דרך <span class="code-inline">#report</span>. לא קשור למאגר ההחתמות. סמנו ✓ אחרי הטיפול.</p>
      ${plainSearch('rep-search', 'rep-qclear', S.repQ, 'חיפוש לפי שם או תוכן הבקשה', byStatus.length, visible.length)}
      <div class="filters">${filters}</div>
      ${cards || '<p class="empty">אין בקשות שתואמות את החיפוש והסינון.</p>'}
      ${pager('reports', pgReports)}
    </section>`;
}

function renderSecurityTab() {
  return `
    <div class="callout">
      <p class="callout-title">מה מוצפן</p>
      <p>שם, מספר אישי, טלפון, מספר נשק, פירוט הציוד <strong>וצילומי הרישיונות</strong> מוצפנים במכשיר לפני השליחה. השרת, קלאודפלייר, וכל מי שמשיג גישה לחשבון או למסד — רואים צופן בלבד.</p>
      <p class="mb0">מה השרת כן רואה: מספר הרשומות, סטטוס (ממתין/מאושר) וחותמות זמן. לא זהות ולא פירוט ציוד.</p>
    </div>
    <div class="callout risk">
      <p class="callout-title">שליחה אוטומטית בוואטסאפ</p>
      <p class="mb0">אם הופעלה שליחה אוטומטית, ברגע האישור עוברים שם החייל, הטלפון ופירוט הציוד דרך השרת אל Meta. הם אינם נשמרים במסד הנתונים, אך Meta מקבלת עותק. בשליחה הידנית שום דבר מזה לא קורה.</p>
    </div>
    <div class="callout risk">
      <p class="callout-title">אין שחזור סיסמה</p>
      <p class="mb0">איבוד הסיסמה משמעו איבוד כל הנתונים. הדרך היחידה להמשיך היא מחיקה מלאה והתחלה מחדש.</p>
    </div>
    <section class="panel">
      <h2 class="panel-title">החלפת סיסמה</h2>
      <p class="panel-sub">ההחלפה מיידית ואינה מצפינה מחדש רשומות. כל החיבורים הפעילים ינותקו.</p>
      <form data-form="rotate" novalidate>
        <label class="field">
          <span class="field-label">סיסמה חדשה (10 תווים לפחות)</span>
          <input class="input" type="password" name="pw" autocomplete="new-password" required>
        </label>
        <label class="field">
          <span class="field-label">אימות סיסמה חדשה</span>
          <input class="input" type="password" name="pw2" autocomplete="new-password" required>
        </label>
        <p class="form-err" data-err></p>
        <button class="btn primary wide" type="submit">החלפת סיסמה</button>
      </form>
    </section>
    <section class="panel">
      <h2 class="panel-title">מחיקת כל הנתונים</h2>
      <p class="panel-sub">מוחק רשומות, מפתחות, חיבורים והגדרות — לצמיתות. לביצוע בסוף התרגיל בלבד.</p>
      <button class="btn danger wide" data-act="wipe">מחיקת כל הנתונים</button>
    </section>`;
}

/* ── Admin data operations ─────────────────────────────────────────── */

async function loadRecords() {
  const { records } = await api('/admin/records');
  const out = [];
  for (const row of records) {
    try {
      const data = await openRecord(S.priv, row);
      out.push({ ...row, data, damaged: false });
    } catch {
      out.push({ ...row, data: null, damaged: true });
    }
  }
  S.recs = out;
}

const findRec = (rid) => S.recs.find((r) => r.rid === rid);

// Re-seal the record's full payload with a fresh content key and PUT it.
async function saveRec(rec) {
  const sealed = await seal(S.pubKey, rec.data);
  await api(`/admin/records/${rec.rid}`, { method: 'PUT', body: { ...sealed, status: rec.status } });
}

async function loadReports() {
  const { reports } = await api('/admin/reports');
  const out = [];
  for (const row of reports) {
    try {
      out.push({ ...row, data: await openRecord(S.priv, row, cleanReport), damaged: false });
    } catch {
      out.push({ ...row, data: null, damaged: true });
    }
  }
  S.reports = out;
}

const repSetState = (id, next) =>
  withBusy(async () => {
    const rec = S.reports.find((r) => r.id === id);
    if (!rec || rec.status === next) return;
    const prev = rec.status;
    rec.status = next;                       // optimistic, rolled back on failure
    renderConsole();
    try {
      await api(`/admin/reports/${id}`, { method: 'PUT', body: { status: next } });
    } catch (e) {
      rec.status = prev;
      renderConsole();
      throw e;
    }
    toast(
      next === 'done'
        ? (rec.data && rec.data.phone ? 'סומן כטופל — אפשר לעדכן את החייל' : 'סומן כטופל')
        : next === 'partial'
          ? (rec.data && rec.data.phone ? 'סומן כטופל חלקית — אפשר לעדכן את החייל' : 'סומן כטופל חלקית')
          : 'הוחזר לטיפול'
    );
  });

// Records that the admin actually opened the reply link.
function repMarkSent(id) {
  const rec = S.reports.find((r) => r.id === id);
  if (!rec || !rec.data || rec.data.replied) return;
  rec.data.replied = Date.now();
  renderConsole();
}

const repDelete = (id) =>
  withBusy(async () => {
    if (!window.confirm('למחוק את הדיווח? הפעולה אינה הפיכה.')) return;
    await api(`/admin/reports/${id}`, { method: 'DELETE' });
    S.reports = S.reports.filter((r) => r.id !== id);
    renderConsole();
    toast('הדיווח נמחק');
  });

// The inventory blob rides the same envelope as records.
async function loadInv() {
  try {
    const { vault } = await api('/admin/vault');
    if (!vault) { S.inv = emptyInv(); return; }
    S.inv = await openRecord(S.priv, vault, cleanInv);
  } catch {
    S.inv = emptyInv();
    toast('לא ניתן לפענח את נתוני המלאי', true);
  }
}

async function saveInv() {
  S.inv.updatedAt = Date.now();
  const sealed = await seal(S.pubKey, S.inv);
  await api('/admin/vault', { method: 'PUT', body: sealed });
}

/* ── Action handlers ───────────────────────────────────────────────── */

// Serialises mutations: one at a time, errors surface as toasts. A click that
// lands mid-save used to vanish silently, leaving the admin unsure whether it
// registered — now it says so.
async function withBusy(fn) {
  if (S.busy) {
    toast('פעולה קודמת עדיין מתבצעת — נסו שוב בעוד רגע', true);
    return;
  }
  S.busy = true;
  try {
    await fn();
  } catch (e) {
    toast(e.message || 'שגיאה', true);
  } finally {
    S.busy = false;
  }
}

function setFormErr(form, msg) {
  const el = form.querySelector('[data-err]');
  if (el) el.textContent = msg || '';
}

/* — soldier actions — */

async function soldierIdentSubmit(form) {
  const pn = form.pn.value.trim();
  const name = form.name.value.trim();
  const phone = form.phone.value.trim();
  const dept = form.dept.value;
  const weapon = form.weapon.value.trim();
  const amral = form.amral.value.trim();
  const scope = form.scope.value.trim();
  if (!/^\d{5,9}$/.test(pn)) return setFormErr(form, 'מספר אישי: 5–9 ספרות');
  if (name.length < 2) return setFormErr(form, 'נא למלא שם מלא');
  if (!/^\d{9,10}$/.test(phone)) return setFormErr(form, 'טלפון: 9–10 ספרות, ללא מקפים');
  if (!DEPTS.some((d) => d.id === dept)) return setFormErr(form, 'נא לבחור מחלקה');
  const serialRe = /^[A-Za-z0-9\-/]{3,20}$/;
  if (weapon && !serialRe.test(weapon)) {
    return setFormErr(form, 'מספר נשק: 3–20 תווים (ספרות, אותיות באנגלית, - או /)');
  }
  if (amral && !serialRe.test(amral)) {
    return setFormErr(form, 'מספר אמר״ל: 3–20 תווים (ספרות, אותיות באנגלית, - או /)');
  }
  if (scope && !serialRe.test(scope)) {
    return setFormErr(form, 'מספר כוונת: 3–20 תווים (ספרות, אותיות באנגלית, - או /)');
  }
  setFormErr(form, '');
  const btn = form.querySelector('button[type=submit]');
  btn.disabled = true;
  btn.textContent = 'בודק…';
  await withBusy(async () => {
    const rid = await deriveRid(pn, S.config.idSalt);
    const st = await api(`/status/${rid}`);
    S.ident = { pn, name, phone, dept, weapon, amral, scope };
    if (st.exists && st.status === 'approved') {
      // main record already approved → supplement mode: the soldier registers
      // only the additional gear, and the admin merges it on approval
      const suppRid = await deriveRid(`${pn}:supp`, S.config.idSalt);
      const suppSt = await api(`/status/${suppRid}`);
      S.suppMode = true;
      S.rid = suppRid;
      S.existingPending = !!suppSt.exists;
    } else {
      S.suppMode = false;
      S.rid = rid;
      S.existingPending = !!st.exists;
    }
    if (!Object.keys(S.sel).length) S.sel = {};
    S.sStep = 2;
    renderSoldier();
  });
  if (S.sStep === 1) {
    btn.disabled = false;
    btn.textContent = 'המשך';
  }
}

/* — licence capture (step 1) — */

// Ticking a box or attaching a photo re-renders step 1, so whatever the
// soldier has already typed must be preserved first.
function captureIdentForm() {
  const f = $app.querySelector('form[data-form="ident"]');
  if (!f) return;
  S.ident = {
    ...(S.ident || {}),
    pn: f.pn.value.trim(),
    name: f.name.value.trim(),
    phone: f.phone.value.trim(),
    dept: f.dept.value,
    weapon: f.weapon.value.trim(),
    amral: f.amral.value.trim(),
    scope: f.scope.value.trim(),
  };
  const no = $app.querySelector('[data-act="lic-no"]');
  const exp = $app.querySelector('[data-act="lic-exp"]');
  if (no) S.licNo = no.value.trim();
  if (exp) S.licExp = exp.value;
}

function licToggle(kind) {
  captureIdentForm();
  S.lic[kind] = !S.lic[kind];
  if (!S.lic[kind]) {
    delete S.licPhoto[kind];                   // unticking discards the photo
    if (kind === 'civil') { S.licNo = ''; S.licExp = ''; }
  }
  renderSoldier();
}

function licClear(kind) {
  captureIdentForm();
  delete S.licPhoto[kind];
  renderSoldier();
}

async function licFile(kind, input) {
  const file = input.files && input.files[0];
  if (!file) return;
  captureIdentForm();
  if (!/^image\//.test(file.type)) {
    toast('יש לבחור קובץ תמונה', true);
    return;
  }
  toast('מעבד את התמונה…');
  try {
    const { bytes, size } = await compressImage(file);
    let bin = '';
    for (const b of bytes) bin += String.fromCharCode(b);
    S.licPhoto[kind] = { bytes, size, preview: `data:image/jpeg;base64,${btoa(bin)}` };
    renderSoldier();
    toast('התמונה נקלטה');
  } catch (e) {
    toast(e.message || 'עיבוד התמונה נכשל', true);
  }
}

function soldierToggle(itemId) {
  const item = itemById(itemId);
  if (itemId in S.sel) delete S.sel[itemId];
  else S.sel[itemId] = item.qty ? item.min : 1;
  renderSoldier();
}

function soldierStep(itemId, delta) {
  const item = itemById(itemId);
  const cur = S.sel[itemId] || item.min;
  S.sel[itemId] = Math.min(item.max, Math.max(item.min, cur + delta));
  renderSoldier();
}

async function soldierSubmit() {
  const errEl = $app.querySelector('[data-err]');
  if (!Object.keys(S.sel).length) {
    if (errEl) errEl.textContent = 'יש לסמן פריט אחד לפחות';
    return;
  }
  await withBusy(async () => {
    const now = Date.now();
    const items = {};
    for (const [id, q] of Object.entries(S.sel)) items[id] = { t: q, r: 0 };
    const payload = {
      pn: S.ident.pn,
      name: S.ident.name,
      phone: S.ident.phone,
      dept: S.ident.dept,
      items,
      createdAt: now,
      log: [{ a: 'submit', t: now }],
    };
    if (S.ident.weapon) payload.weapon = S.ident.weapon;
    if (S.ident.amral) payload.amral = S.ident.amral;
    if (S.ident.scope) payload.scope = S.ident.scope;
    // which licences were declared, and which of them have a photo attached
    const lic = {};
    for (const k of LIC_KINDS) {
      if (!S.lic[k.id]) continue;
      lic[k.id] = { has: true, doc: !!S.licPhoto[k.id] };
      if (k.id === 'civil') {
        if (S.licNo) lic.civil.no = S.licNo;
        if (S.licExp) lic.civil.exp = S.licExp;
      }
    }
    if (Object.keys(lic).length) payload.lic = lic;
    if (S.suppMode) payload.supp = true;

    const pubKey = await importPubKey(S.config.pub);
    const sealed = await seal(pubKey, payload);
    await api('/records', { body: { rid: S.rid, ...sealed } });

    // Photos ride separately so listing soldiers never pulls image data.
    for (const k of LIC_KINDS) {
      const shot = S.licPhoto[k.id];
      if (!S.lic[k.id] || !shot) continue;
      const sealedDoc = await sealBytes(pubKey, shot.bytes);
      await api('/docs', { body: { rid: S.rid, kind: k.id, ...sealedDoc } });
    }
    S.sStep = 4;
    renderSoldier();
  });
}

/* — admin auth — */

async function setupSubmit(form) {
  const pw = form.pw.value;
  const pw2 = form.pw2.value;
  const token = form.token.value.trim();
  if (pw.length < 10) return setFormErr(form, 'הסיסמה חייבת להכיל 10 תווים לפחות');
  if (pw !== pw2) return setFormErr(form, 'הסיסמאות אינן תואמות');
  if (!form.ack.checked) return setFormErr(form, 'יש לאשר את סעיף אי-השחזור');
  setFormErr(form, '');
  const btn = form.querySelector('button[type=submit]');
  btn.disabled = true;
  btn.textContent = 'מקים…';
  await withBusy(async () => {
    const pair = await crypto.subtle.generateKey(
      { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,
      ['encrypt', 'decrypt']
    );
    const pubJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
    const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
    const idSalt = b64(crypto.getRandomValues(new Uint8Array(16)));
    const keyIv = crypto.getRandomValues(new Uint8Array(12));
    const { kek, verifier } = await deriveAuth(pw, salt);
    const wrapped = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: keyIv }, kek, pkcs8);
    const headers = token ? { 'X-Setup-Token': token } : undefined;
    await api('/setup', {
      body: {
        pub: JSON.stringify(pubJwk),
        salt,
        idSalt,
        verifier,
        keyIv: b64(keyIv),
        wrappedKey: b64(wrapped),
      },
      headers,
    });
    await api('/admin/login', { body: { verifier } });
    S.config = await api('/config');
    S.pkcs8 = pkcs8;
    S.priv = pair.privateKey;
    S.pubKey = await importPubKey(S.config.pub);
    await loadRecords();
    await loadInv();
    await loadReports();
    S.tab = 'over';
    armIdle();
    renderConsole();
    toast('המערכת הוקמה — שמרו את הסיסמה במקום בטוח');
  });
  if (!S.priv) {
    btn.disabled = false;
    btn.textContent = 'הקמה וכניסה';
  }
}

async function loginSubmit(form) {
  const pw = form.pw.value;
  if (!pw) return setFormErr(form, 'נא להזין סיסמה');
  setFormErr(form, '');
  const btn = form.querySelector('button[type=submit]');
  btn.disabled = true;
  btn.textContent = 'מתחבר…';
  await withBusy(async () => {
    try {
      const { salt } = await api('/admin/challenge');
      const { kek, verifier } = await deriveAuth(pw, salt);
      const { keyIv, wrappedKey } = await api('/admin/login', { body: { verifier } });
      const pkcs8 = new Uint8Array(
        await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ub64(keyIv) }, kek, ub64(wrappedKey))
      );
      S.priv = await crypto.subtle.importKey(
        'pkcs8', pkcs8, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']
      );
      S.pkcs8 = pkcs8;
      S.pubKey = await importPubKey(S.config.pub);
      await loadRecords();
      await loadInv();
      await loadReports();
      S.tab = 'over';
      armIdle();
      renderConsole();
    } catch (e) {
      setFormErr(form, e.status === 401 ? 'סיסמה שגויה' : e.message);
    }
  });
  if (!S.priv) {
    btn.disabled = false;
    btn.textContent = 'כניסה';
  }
}

/* — admin record mutations — */

const adminAdjust = (rid, itemId, delta) =>
  withBusy(async () => {
    const rec = findRec(rid);
    if (!rec || rec.damaged) return;
    const item = itemById(itemId);
    const it = rec.data.items[itemId];
    if (!it) return;
    const next = Math.min(item.max || 99, Math.max(item.min || 1, it.t + delta));
    if (next === it.t) return;
    it.t = next;
    rec.data.log.push({ a: 'adjust', t: Date.now() });
    await saveRec(rec);
    renderConsole();
  });

const adminApprove = (rid) =>
  withBusy(async () => {
    const rec = findRec(rid);
    if (!rec || rec.damaged) return;
    const now = Date.now();
    if (rec.data.supp) {
      // supplement: merge into the soldier's main record (matched by pn)
      const parent = S.recs.find(
        (r) => r !== rec && !r.damaged && r.data && !r.data.supp && r.data.pn === rec.data.pn
      );
      if (parent) {
        for (const [id, it] of Object.entries(rec.data.items)) {
          if (parent.data.items[id]) parent.data.items[id].t += it.t;
          else parent.data.items[id] = { t: it.t, r: 0 };
        }
        parent.data.name = rec.data.name;
        parent.data.phone = rec.data.phone;
        if (rec.data.dept) parent.data.dept = rec.data.dept;
        if (rec.data.amral) parent.data.amral = rec.data.amral;
        if (rec.data.scope) parent.data.scope = rec.data.scope;
        parent.data.log.push({ a: 'supplement', t: now });
        const suppFailed = await notifySoldier(parent.data);
        if (!suppFailed) {
          parent.data.notified = now;
          parent.data.log.push({ a: 'notify', t: now });
        }
        await saveRec(parent);
        await api(`/admin/records/${rec.rid}`, { method: 'DELETE' });
        S.recs = S.recs.filter((r) => r.rid !== rec.rid);
        renderConsole();
        toast(
          suppFailed
            ? `ההשלמה מוזגה לרישום של ${parent.data.name} — ההודעה לא נשלחה אוטומטית`
            : `ההשלמה מוזגה ונשלחה הודעה ל${parent.data.name}`,
          !!suppFailed
        );
        return;
      }
      // main record was deleted meanwhile — approve as a standalone record
      delete rec.data.supp;
    }
    rec.data.approvedAt = now;
    rec.data.log.push({ a: 'approve', t: now });
    rec.status = 'approved';
    const failed = await notifySoldier(rec.data);
    if (!failed) {
      rec.data.notified = now;
      rec.data.log.push({ a: 'notify', t: now });
    }
    await saveRec(rec);
    renderConsole();
    toast(
      failed
        ? `אושר: ${rec.data.name} — ההודעה לא נשלחה אוטומטית, שלחו ידנית במעקב ציוד`
        : `אושר: ${rec.data.name} — הודעת וואטסאפ נשלחה`,
      !!failed
    );
  });

const adminCredit = (rid, itemId, delta) =>
  withBusy(async () => {
    const rec = findRec(rid);
    if (!rec || rec.damaged) return;
    const it = rec.data.items[itemId];
    if (!it) return;
    const next = Math.min(it.t, Math.max(0, (it.r || 0) + delta));
    if (next === (it.r || 0)) return;
    it.r = next;
    rec.data.log.push({ a: 'credit', t: Date.now() });
    await saveRec(rec);
    renderConsole();
  });

const adminCreditAll = (rid) =>
  withBusy(async () => {
    const rec = findRec(rid);
    if (!rec || rec.damaged) return;
    for (const it of Object.values(rec.data.items)) it.r = it.t;
    rec.data.log.push({ a: 'credit', t: Date.now() });
    await saveRec(rec);
    renderConsole();
    toast(`זוכה במלואו: ${rec.data.name}`);
  });

const adminDelete = (rid) =>
  withBusy(async () => {
    const rec = findRec(rid);
    if (!rec) return;
    const who = rec.damaged ? 'הרשומה הפגומה' : `הרשומה של ${rec.data.name}`;
    if (!window.confirm(`למחוק את ${who}? הפעולה אינה הפיכה.`)) return;
    await api(`/admin/records/${rid}`, { method: 'DELETE' });
    S.recs = S.recs.filter((r) => r.rid !== rid);
    renderConsole();
    toast('הרשומה נמחקה');
  });

const adminRefresh = () =>
  withBusy(async () => {
    await loadRecords();
    await loadInv();
    await loadReports();
    renderConsole();
    toast('עודכן');
  });

const invSave = () =>
  withBusy(async () => {
    await saveInv();
    renderConsole();
    toast('המלאי נשמר');
  });

// Fetches and decrypts one licence photo the first time it is asked for;
// afterwards the toggle just hides the copy already held in memory.
const toggleDoc = (rid, kind) =>
  withBusy(async () => {
    const key = `${rid}:${kind}`;
    if (S.docs[key]) {
      delete S.docs[key];
      renderConsole();
      return;
    }
    const { docs } = await api(`/admin/docs/${rid}`);
    const row = (docs || []).find((x) => x.kind === kind);
    if (!row) {
      toast('הצילום לא נמצא', true);
      return;
    }
    try {
      const bytes = new Uint8Array(await openBytes(S.priv, row));
      let bin = '';
      for (const b of bytes) bin += String.fromCharCode(b);
      S.docs[key] = `data:image/jpeg;base64,${btoa(bin)}`;
      renderConsole();
    } catch {
      toast('פענוח הצילום נכשל — ייתכן שהנתונים שובשו', true);
    }
  });

async function rotateSubmit(form) {
  const pw = form.pw.value;
  const pw2 = form.pw2.value;
  if (pw.length < 10) return setFormErr(form, 'הסיסמה חייבת להכיל 10 תווים לפחות');
  if (pw !== pw2) return setFormErr(form, 'הסיסמאות אינן תואמות');
  setFormErr(form, '');
  await withBusy(async () => {
    const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
    const keyIv = crypto.getRandomValues(new Uint8Array(12));
    const { kek, verifier } = await deriveAuth(pw, salt);
    const wrapped = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: keyIv }, kek, S.pkcs8);
    await api('/admin/rotate', {
      body: { salt, verifier, keyIv: b64(keyIv), wrappedKey: b64(wrapped) },
    });
    // rotate invalidated every session — establish a fresh one with the new verifier
    await api('/admin/login', { body: { verifier } });
    renderConsole();
    toast('הסיסמה הוחלפה');
  });
}

const adminWipe = () =>
  withBusy(async () => {
    if (!window.confirm('למחוק את כל הנתונים? כל הרשומות והמפתחות יימחקו לצמיתות.')) return;
    if (!window.confirm('אישור אחרון: אין דרך לשחזר את הנתונים לאחר המחיקה. להמשיך?')) return;
    await api('/admin/wipe', { method: 'POST', body: {} });
    if (S.pkcs8) S.pkcs8.fill(0);
    S.pkcs8 = null;
    S.priv = null;
    S.pubKey = null;
    S.recs = [];
    S.inv = null;
    S.reports = [];
    S.q = '';
    S.repQ = '';
    S.invQ = '';
    S.dept = 'all';
    S.collapsed.clear();
    S.revealed.clear();
    clearTimeout(idleTimer);
    S.config = { ready: false };
    S.adminView = 'setup';
    renderRoute();
    toast('כל הנתונים נמחקו');
  });

/* — CSV export — */

function exportCsv() {
  if (!window.confirm('שימו לב: קובץ הייצוא אינו מוצפן ומכיל פרטים אישיים. להמשיך?')) return;
  const q = csvCell;
  const head = [
    'מספר אישי', 'שם', 'טלפון', 'מחלקה', 'מספר נשק', 'מספר אמר״ל', 'מספר כוונת',
    ...ITEMS.flatMap((i) => [`${i.name} נלקח`, `${i.name} הוחזר`]),
    'רישיון אזרחי', 'רישיון צבאי',
    'סטטוס', 'נשלח', 'אושר',
  ];
  const licCell = (d, kind) => {
    const l = (d.lic || {})[kind];
    if (!l || !l.has) return '';
    return l.doc ? 'כן (עם צילום)' : 'כן';
  };
  const lines = [head.map(q).join(',')];
  for (const rec of S.recs) {
    if (rec.damaged) continue;
    const d = rec.data;
    lines.push(
      [
        d.pn, d.name, d.phone, deptName(d.dept), d.weapon || '', d.amral || '', d.scope || '',
        ...ITEMS.flatMap((i) => {
          const it = d.items[i.id];
          return it ? [it.t, it.r || 0] : ['', ''];
        }),
        licCell(d, 'civil'), licCell(d, 'military'),
        rec.status === 'approved' ? 'מאושר' : 'ממתין',
        fmtDate(d.createdAt),
        d.approvedAt ? fmtDate(d.approvedAt) : '',
      ].map(q).join(',')
    );
  }
  downloadCsv(lines, 'tzayad-export.csv');
}

/* ── Event delegation ──────────────────────────────────────────────── */

$app.addEventListener('click', (e) => {
  const el = e.target.closest('[data-act]');
  if (!el || !$app.contains(el)) return;
  const act = el.dataset.act;
  // toggling an equipment row shouldn't fire when a stepper button inside it was hit
  if (act === 's-toggle' && e.target.closest('.step-btn')) return;
  dispatch(act, el);
});

$app.addEventListener('keydown', (e) => {
  if (e.key !== 'Enter' && e.key !== ' ') return;
  const el = e.target.closest('[role="checkbox"][data-act]');
  if (!el) return;
  e.preventDefault();
  dispatch(el.dataset.act, el);
});

// Number inputs whose derived columns are recomputed when the field is left.
const NUM_COMMIT = new Set(['inv-open', 'inv-xopen', 'inv-xout', 'veh-km']);

// Live-typed fields: search and the inventory grid. Re-rendering on each
// keystroke would drop focus, so the caret is restored afterwards.
function rerenderKeepFocus(el) {
  const a = el.dataset;
  let sel = `[data-act="${a.act}"]`;
  if (a.item) sel += `[data-item="${a.item}"]`;
  if (a.i) sel += `[data-i="${a.i}"]`;
  let start = null, end = null;
  try { start = el.selectionStart; end = el.selectionEnd; } catch { /* number inputs */ }
  renderConsole();
  const next = $app.querySelector(sel);
  if (!next) return;
  next.focus();
  if (start !== null) {
    try { next.setSelectionRange(start, end); } catch { /* unsupported type */ }
  }
}

$app.addEventListener('input', (e) => {
  const el = e.target.closest('[data-act]');
  if (!el || !$app.contains(el)) return;
  const act = el.dataset.act;
  const i = parseInt(el.dataset.i, 10);
  const num = () => Math.max(0, Math.min(9999, parseInt(String(el.value).replace(/\D/g, ''), 10) || 0));
  switch (act) {
    case 'search': S.q = el.value; S.page = {}; rerenderKeepFocus(el); break;
    case 'rep-search': S.repQ = el.value; S.page = {}; rerenderKeepFocus(el); break;
    case 'inv-search': S.invQ = el.value; rerenderKeepFocus(el); break;
    case 'inv-open': S.inv.open[el.dataset.item] = num(); break;
    case 'inv-xopen': S.inv.extra[i].open = num(); break;
    case 'inv-xout': S.inv.extra[i].out = num(); break;
    // name and notes don't affect any computed figure — no re-render needed
    case 'inv-xname': S.inv.extra[i].name = el.value; break;
    case 'inv-notes': S.inv.notes = el.value; break;
    case 'arm-search':  S.regQ = { ...S.regQ, armon: el.value };  S.page = {}; rerenderKeepFocus(el); break;
    case 'tz-search':   S.regQ = { ...S.regQ, tzelem: el.value }; rerenderKeepFocus(el); break;
    case 'ammo-search': S.regQ = { ...S.regQ, ammo: el.value };   rerenderKeepFocus(el); break;
    case 'veh-search':  S.regQ = { ...S.regQ, veh: el.value };    rerenderKeepFocus(el); break;
    case 'veh-plate':   S.inv.vehicles[+el.dataset.i].plate = el.value; break;
    case 'veh-company': S.inv.vehicles[+el.dataset.i].company = el.value; break;
    case 'veh-km':
      S.inv.vehicles[+el.dataset.i].km =
        Math.max(0, Math.min(9999999, parseInt(String(el.value).replace(/\D/g, ''), 10) || 0));
      break;
    case 'lic-no': S.licNo = el.value.trim(); break;
    case 'lic-exp': S.licExp = el.value; break;   // re-render happens on 'change'
  }
});

// Checkboxes and file pickers report via 'change', not 'input'.
$app.addEventListener('change', (e) => {
  const el = e.target.closest('[data-act]');
  if (!el || !$app.contains(el)) return;
  if (el.dataset.act === 'rep-state') { repSetState(el.dataset.id, el.dataset.st); return; }
  // number fields refresh their computed columns on commit, not per keystroke
  if (NUM_COMMIT.has(el.dataset.act)) { renderConsole(); return; }
  if (el.dataset.act === 'arm-loc') { S.inv.armon[+el.dataset.i].loc = el.value; renderConsole(); return; }
  if (el.dataset.act === 'veh-service') { S.inv.vehicles[+el.dataset.i].service = el.value; renderConsole(); return; }
  if (el.dataset.act === 'veh-kit') { S.inv.vehicles[+el.dataset.i][el.dataset.k] = el.checked; renderConsole(); return; }
  if (el.dataset.act === 'lic-toggle') licToggle(el.dataset.kind);
  else if (el.dataset.act === 'lic-file') licFile(el.dataset.kind, el);
  // committed date → re-render so the validity hint updates
  else if (el.dataset.act === 'lic-exp') { S.licExp = el.value; captureIdentForm(); renderSoldier(); }
});

$app.addEventListener('submit', (e) => {
  const form = e.target.closest('form[data-form]');
  if (!form) return;
  e.preventDefault();
  const kind = form.dataset.form;
  if (kind === 'ident') soldierIdentSubmit(form);
  else if (kind === 'setup') setupSubmit(form);
  else if (kind === 'login') loginSubmit(form);
  else if (kind === 'rotate') rotateSubmit(form);
  else if (kind === 'report') reportSubmit(form);
  else if (kind === 'arm-add') armAdd(form);
  else if (kind === 'ammo-add') ammoAdd(form);
});

function dispatch(act, el) {
  const rid = el.dataset.rid;
  const item = el.dataset.item;
  const d = parseInt(el.dataset.d || '0', 10);
  switch (act) {
    // soldier
    case 's-toggle': soldierToggle(item); break;
    case 's-inc': soldierStep(item, 1); break;
    case 's-dec': soldierStep(item, -1); break;
    case 's-submit': soldierSubmit(); break;
    case 's-back': S.sStep = 1; renderSoldier(); break;
    case 's-edit': S.sStep = 2; renderSoldier(); break;
    case 's-review':
      if (!Object.keys(S.sel).length) {
        const e = $app.querySelector('[data-err]');
        if (e) e.textContent = 'יש לסמן פריט אחד לפחות';
        return;
      }
      S.sStep = 3;
      renderSoldier();
      break;
    case 's-remove':
      delete S.sel[el.dataset.item];
      if (!Object.keys(S.sel).length) S.sStep = 2;
      renderSoldier();
      break;
    case 's-reset': resetSoldier(); renderSoldier(); break;
    case 'lic-clear': licClear(el.dataset.kind); break;
    // admin console
    case 'tab': S.tab = el.dataset.tab; renderConsole(); break;
    case 'filter': S.filter = el.dataset.filter; S.page = {}; renderConsole(); break;
    case 'refresh': adminRefresh(); break;
    case 'lock': lock(); break;
    case 'reveal':
      if (S.revealed.has(rid)) S.revealed.delete(rid);
      else S.revealed.add(rid);
      renderConsole();
      break;
    case 'adj': adminAdjust(rid, item, d); break;
    case 'approve': adminApprove(rid); break;
    case 'credit': adminCredit(rid, item, d); break;
    case 'creditall': adminCreditAll(rid); break;
    case 'del': adminDelete(rid); break;
    case 'export': exportCsv(); break;
    case 'export-weapons': exportWeaponsCsv(); break;
    case 'export-lic': exportLicCsv(); break;
    case 'export-ledger': exportLedgerCsv(); break;
    case 'wipe': adminWipe(); break;
    // search & grouping
    case 'dept': S.dept = el.dataset.dept; S.page = {}; renderConsole(); break;
    case 'qclear': S.q = ''; S.page = {}; renderConsole(); break;
    case 'rep-qclear': S.repQ = ''; S.page = {}; renderConsole(); break;
    case 'inv-qclear': S.invQ = ''; renderConsole(); break;
    case 'reg-qclear-tzelem': S.regQ = { ...S.regQ, tzelem: '' }; S.page = {}; renderConsole(); break;
    case 'reg-qclear-armon':  S.regQ = { ...S.regQ, armon: '' };  S.page = {}; renderConsole(); break;
    case 'fold': {
      const id = el.dataset.dept;
      if (S.collapsed.has(id)) S.collapsed.delete(id);
      else S.collapsed.add(id);
      renderConsole();
      break;
    }
    // inventory
    case 'inv-xadd':
      S.inv.extra.push({ name: '', open: 0, out: 0 });
      renderConsole();
      focusLast('[data-act="inv-xname"]');
      break;
    case 'inv-xdel':
      S.inv.extra.splice(parseInt(el.dataset.i, 10), 1);
      renderConsole();
      break;
    case 'inv-save': invSave(); break;
    // armoury
    case 'arm-kind': S.armKind = el.dataset.k; S.page = {}; renderConsole(); break;
    case 'arm-remove': armRemove(+el.dataset.i); break;
    case 'arm-export': exportArmonCsv(); break;
    case 'arm-log-export': exportArmLogCsv(); break;
    case 'arm-qclear': S.regQ = { ...S.regQ, armon: '' }; S.page = {}; renderConsole(); break;
    // tzelem report
    case 'tz-qclear': S.regQ = { ...S.regQ, tzelem: '' }; renderConsole(); break;
    case 'tz-pdf': tzelemPdf(); break;
    case 'tz-wa': tzelemWa(); break;
    case 'tz-export': exportTzelemCsv(); break;
    // ammunition
    case 'ammo-issue': ammoMove(+el.dataset.i, true); break;
    case 'ammo-add-qty': ammoMove(+el.dataset.i, false); break;
    case 'ammo-del':
      if (window.confirm('למחוק את הפריט מהמלאי?')) { S.inv.ammo.splice(+el.dataset.i, 1); invSave(); }
      break;
    case 'ammo-export': exportAmmoCsv(); break;
    case 'ammo-log-export': exportAmmoLogCsv(); break;
    case 'ammo-qclear': S.regQ = { ...S.regQ, ammo: '' }; renderConsole(); break;
    // vehicles
    case 'veh-add':
      S.inv.vehicles = [...(S.inv.vehicles || []), cleanVehicle({})];
      S.regQ = { ...S.regQ, veh: '' };
      renderConsole();
      focusLast('[data-act="veh-plate"]');
      break;
    case 'veh-del':
      if (window.confirm('למחוק את הרכב?')) { S.inv.vehicles.splice(+el.dataset.i, 1); renderConsole(); }
      break;
    case 'veh-kit':
      S.inv.vehicles[+el.dataset.i][el.dataset.k] = el.checked;
      renderConsole();
      break;
    case 'veh-export': exportVehCsv(); break;
    case 'veh-qclear': S.regQ = { ...S.regQ, veh: '' }; renderConsole(); break;
    case 'page':
      S.page = { ...S.page, [el.dataset.key]: parseInt(el.dataset.page, 10) };
      renderConsole();
      $app.scrollIntoView({ block: 'start', behavior: 'smooth' });
      break;
    case 'doc': toggleDoc(rid, el.dataset.kind); break;
    // shortage reports
    case 'rep-filter': S.repFilter = el.dataset.f; S.page = {}; renderConsole(); break;
    case 'rep-sent': repMarkSent(el.dataset.id); break;
    case 'rep-del': repDelete(el.dataset.id); break;
    case 'rep-reveal': {
      const id = el.dataset.id;
      if (S.revealed.has(id)) S.revealed.delete(id);
      else S.revealed.add(id);
      renderConsole();
      break;
    }
    case 'rep-again': S.repSent = false; S.rep = null; renderReport(); break;
    // the link itself still opens WhatsApp; this only records that it was used
    case 'wa-sign': markSent(rid, 'notified'); break;
    case 'wa-ret': markSent(rid, 'returnNotified'); break;
  }
}

// Marks a manual WhatsApp send on the record so the card reflects it.
function markSent(rid, field) {
  const rec = findRec(rid);
  if (!rec || rec.damaged || rec.data[field]) return;
  const now = Date.now();
  const entry = { a: field === 'notified' ? 'notify-manual' : 'return-notify', t: now };
  rec.data[field] = now;
  rec.data.log.push(entry);
  saveRec(rec)
    .then(() => renderConsole())
    .catch(() => {
      // roll the whole optimistic update back, log entry included
      rec.data[field] = null;
      const i = rec.data.log.lastIndexOf(entry);
      if (i >= 0) rec.data.log.splice(i, 1);
      renderConsole();
      toast('שמירת סימון השליחה נכשלה', true);
    });
}

// After a re-render, put the cursor in the newly added row.
function focusLast(sel) {
  const nodes = $app.querySelectorAll(sel);
  if (nodes.length) nodes[nodes.length - 1].focus();
}

/* ── Routing & boot ────────────────────────────────────────────────── */

window.addEventListener('hashchange', () => {
  const route = routeFromHash();
  if (route === S.route) return;
  if (S.route === 'admin' && S.priv) lock();
  S.route = route;
  resetSoldier();
  renderRoute();
});

async function boot() {
  if (!window.crypto || !window.crypto.subtle) {
    render('<section class="panel"><p class="mb0">הדפדפן לא תומך בהצפנה הנדרשת. יש לפתוח את הקישור בדפדפן עדכני דרך HTTPS.</p></section>');
    return;
  }
  render('<p class="loading">טוען…</p>');
  try {
    S.config = await api('/config');
  } catch (e) {
    render(`
      <section class="panel center">
        <h1 class="panel-title">שגיאת התחברות</h1>
        <p class="panel-sub">${esc(e.message)}</p>
        <button class="btn primary" data-act="retry">ניסיון חוזר</button>
      </section>`);
    $app.querySelector('[data-act="retry"]').addEventListener('click', boot);
    return;
  }
  renderRoute();
}

boot();
