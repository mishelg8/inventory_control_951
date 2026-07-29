'use strict';

/* ════════════════════════════════════════════════════════════════════
   רישום ראשוני — client logic. All plaintext personal data lives only in
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
    amral: asText(raw.amral, 20),
    scope: asText(raw.scope, 20),
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

// Shortage reports and armoury deposits share the /reports pipe — the server
// stores an opaque blob either way, so telling them apart is a client concern.
function cleanReport(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('bad payload');
  return {
    kind: raw.kind === 'deposit' || raw.kind === 'fault' ? raw.kind : 'report',
    name: asText(raw.name, 60),
    text: asText(raw.text, 1500),
    // legacy reports carried identity fields; keep them if present
    pn: asText(raw.pn, 9),
    phone: asText(raw.phone, 15),
    dept: DEPTS.some((d) => d.id === raw.dept) ? raw.dept : '',
    // deposit-only: the weapon being handed in, plus optional accessory catalogue numbers
    weapon: asText(raw.weapon, 20),
    amral: asText(raw.amral, 20),
    scope: asText(raw.scope, 20),
    filed: !!raw.filed,          // already pushed into the armoury register
    createdAt: asTime(raw.createdAt) || Date.now(),
  };
}

/* ── Armoury domain ────────────────────────────────────────────────── */

// Each kind carries the locations it is allowed to be in. Only צל״ם can go out
// on a mission, and when it does the mission has to be named — an item that is
// "somewhere on an operation" with no name attached is an item you have lost.
const LIFECYCLE = ['repair', 'lost', 'decom'];
const ARM_KINDS = [
  { id: 'weapon', name: 'נשק', locs: ['armon', 'soldier', ...LIFECYCLE] },
  { id: 'amral', name: 'אמר״ל', locs: ['armon', 'soldier', ...LIFECYCLE] },
  { id: 'dscope', name: 'כוונת יום', locs: ['armon', 'soldier', ...LIFECYCLE] },
  { id: 'nscope', name: 'כוונת לילה', locs: ['armon', 'soldier', ...LIFECYCLE] },
  { id: 'tzelem', name: 'צל״ם', locs: ['armon', 'soldier', 'mission', ...LIFECYCLE] },
];
// A weapon or piece of kit is not only "here" or "with someone" — it can be at
// the workshop, written off, or genuinely missing. Without these states a
// broken item is deleted from the register and the shortage becomes invisible.
const ARM_LOCS = [
  { id: 'armon', name: 'ארמון' },
  { id: 'soldier', name: 'אצל חייל' },
  { id: 'mission', name: 'במשימה' },
  { id: 'repair', name: 'בתיקון' },
  { id: 'lost', name: 'אבוד' },
  { id: 'decom', name: 'מושבת' },
];
// States that mean the item is not usable, as opposed to merely elsewhere.
const ARM_BAD_LOCS = new Set(['lost', 'decom']);
const kindLocs = (kind) => {
  const k = ARM_KINDS.find((x) => x.id === kind);
  return ARM_LOCS.filter((l) => (k ? k.locs : ['armon', 'soldier']).includes(l.id));
};
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

const cleanArmItem = (x) => {
  const kind = ARM_KINDS.some((k) => k.id === (x && x.kind)) ? x.kind : 'weapon';
  // A location the kind is not allowed in falls back to 'soldier', never to
  // 'armon' — an item that was out must not read as present in the cupboard.
  const allowed = kindLocs(kind).map((l) => l.id);
  const raw = x && x.loc;
  return {
    id: asText(x && x.id, 40) || rndId(),
    kind,
    name: asText(x && x.name, 60),
    serial: asText(x && x.serial, 40),
    owner: asText(x && x.owner, 60),
    loc: allowed.includes(raw) ? raw : (raw && raw !== 'armon' ? 'soldier' : 'armon'),
    mission: asText(x && x.mission, 60),
    note: asText(x && x.note, 120),
    addedAt: asTime(x && x.addedAt),
  };
};

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
];

const cleanVehicle = (x) => {
  const v = {
    id: asText(x && x.id, 40) || rndId(),
    plate: asText(x && x.plate, 20),
    company: asText(x && x.company, 40),
    km: asCount(x && x.km, 9999999),
    service: asText(x && x.service, 10),
    code: asText(x && x.code, 12),        // door keypad (קודן)
    fuelCode: asText(x && x.fuelCode, 12), // fuel dispenser (דלקן)
    note: asText(x && x.note, 120),
  };
  for (const k of VEH_KIT) v[k.id] = !!(x && x[k.id]);
  return v;
};

const FUEL_KINDS = [
  { id: 'diesel', name: 'דיזל' },
  { id: 'petrol', name: 'בנזין' },
  { id: 'urea', name: 'אוריאה' },
];

// Cards arrive holding 50 litres, so 15 is the point at which one needs
// replacing rather than merely watching.
const FUEL_LOW = 15;
const FUEL_OFFICE = 'במשרד';

// A refuelling card. Each receipt is a random 32-hex id naming an image in the
// docs table — pictures never enter the vault, which has a size cap.
const cleanFuel = (x) => ({
  id: asText(x && x.id, 40) || rndId(),
  kind: FUEL_KINDS.some((k) => k.id === (x && x.kind)) ? x.kind : 'diesel',
  no: asText(x && x.no, 30),
  litres: asCount(x && x.litres, 99999),
  holder: asText(x && x.holder, 60),        // soldier's name, or FUEL_OFFICE
  receipts: (Array.isArray(x && x.receipts) ? x.receipts : [])
    .slice(0, 60)
    .filter((r) => r && /^[0-9a-f]{32}$/.test(r.id))
    .map((r) => ({ id: r.id, at: asTime(r.at) })),
  uses: (Array.isArray(x && x.uses) ? x.uses : []).slice(0, 300).map((u) => ({
    t: asTime(u && u.t),
    who: asText(u && u.who, 60),
    litres: asCount(u && u.litres, 99999),
    plate: asText(u && u.plate, 20),
  })),
  credited: !!(x && x.credited),            // settled with the vehicle officer
  creditedAt: asTime(x && x.creditedAt),
  note: asText(x && x.note, 120),
});

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
    fuel: arr(src.fuel, cleanFuel, 300),
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
  if (h === '#deposit') return 'deposit';
  if (h === '#fault') return 'fault';
  if (h === '#sign') return 'soldier';
  return 'home';   // the link a soldier is given lands on the chooser
}

const S = {
  config: null,                 // { ready, pub?, idSalt? }
  route: routeFromHash(),

  // shortage reporting (soldier-facing, separate flow)
  rep: null,                    // draft { pn, name, phone, dept, text }
  repSent: false,

  // armoury deposit (soldier-facing, separate flow)
  dep: null,                    // draft { pn, name, phone, weapon, amral, scope }
  depSent: false,
  depQ: '',                     // admin search over deposits
  depFilter: 'open',            // 'open' | 'done' | 'all'

  // building faults (soldier-facing, separate flow)
  flt: null,                    // draft { name, phone, text }
  fltSent: false,
  fltQ: '',                     // admin search over faults
  fltFilter: 'open',            // 'open' | 'partial' | 'done' | 'all'

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
  role: 'admin',                // 'admin' | 'viewer' — viewer cannot write
  me: '',                       // username of the signed-in user
  tabs: '*',                    // '*' or the list of screens this user may see
  users: [],                    // roster, admin only
  trash: null,                  // soft-deleted rows, loaded on demand
  audit: null,                  // admin action log, loaded on demand
  userTabs: new Set(),          // screens ticked in the new-user form
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
  fuelOpen: new Set(),          // fuel card ids with their detail row expanded
  expanded: new Set(),          // record rids expanded in the pending/track tables
  picked: new Set(),            // rids ticked for a bulk action
  sort: { key: 'date', dir: 'desc' },   // roster table ordering
  invVersion: 0,                // vault updated_at at load, for conflict detection
  invBytes: 0,                  // sealed vault size, for the headroom gauge
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
  S.depQ = '';
  S.fltQ = '';
  S.invQ = '';
  S.regQ = {};
  S.role = 'admin';
  S.me = '';
  S.tabs = '*';
  S.users = [];
  S.trash = null;
  S.audit = null;
  S.revealed.clear();
  S.fuelOpen.clear();
  S.expanded.clear();
  S.picked.clear();
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

// Identifies a control well enough to find it again after the DOM is replaced.
// The console re-renders wholesale on every state change; without this the
// caret and the scroll position jump on every click, which is unusable when
// you are working down a long table.
function fieldKey(el) {
  if (!el || !el.dataset || !el.dataset.act) return null;
  const d = el.dataset;
  return [d.act, d.i, d.item, d.rid, d.id, d.k, d.r, d.n].filter((x) => x !== undefined).join('|');
}

const render = (html, focusKey) => {
  // remember where the user was before the DOM underneath them is replaced
  const active = document.activeElement;
  const keep = $app.contains(active) ? {
    key: fieldKey(active),
    start: active.selectionStart,
    end: active.selectionEnd,
  } : null;
  const scrollY = window.scrollY;

  $app.innerHTML = html;

  if (keep && keep.key) {
    const back = [...$app.querySelectorAll('[data-act]')].find((e) => fieldKey(e) === keep.key);
    if (back && typeof back.focus === 'function') {
      back.focus({ preventScroll: true });
      // setSelectionRange throws on inputs that do not support it (number, date)
      if (keep.start != null) {
        try { back.setSelectionRange(keep.start, keep.end); } catch { /* not a text field */ }
      }
      window.scrollTo({ top: scrollY });
    }
  }

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
  else if (S.route === 'deposit') renderDeposit();
  else if (S.route === 'fault') renderFault();
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
          <span class="choice-t">רישום ראשוני</span>
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
      <a class="choice" href="#deposit">
        <span class="choice-ico arm" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"
               stroke-linecap="round" stroke-linejoin="round">
            <rect x="3.5" y="3" width="17" height="18" rx="2"/>
            <path d="M12 3v18"/>
            <path d="M9.6 11.4h.01M14.4 11.4h.01"/>
          </svg>
        </span>
        <span class="choice-txt">
          <span class="choice-t">אפסון נשק בארמון</span>
          <span class="choice-s">מוסרים נשק לאחסון? רשמו את הפרטים ומנהל הארמון יקלוט אותו.</span>
        </span>
        <span class="choice-go" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"
               stroke-linecap="round" stroke-linejoin="round"><path d="M15 5l-7 7 7 7"/></svg>
        </span>
      </a>
      <a class="choice" href="#fault">
        <span class="choice-ico bld" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"
               stroke-linecap="round" stroke-linejoin="round">
            <path d="M3 21h18"/>
            <path d="M5.5 21V6.5l7-3.5v18"/>
            <path d="M12.5 10.5H19V21"/>
            <path d="M8.6 9.2h.01M8.6 13h.01M15.6 14h.01"/>
          </svg>
        </span>
        <span class="choice-txt">
          <span class="choice-t">דיווח תקלות בינוי</span>
          <span class="choice-s">דלת שבורה, נזילה, חשמל, מזגן? דווחו כאן ונטפל.</span>
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
    await api('/reports', {
      body: { id: hex(crypto.getRandomValues(new Uint8Array(16))), ticket: await getTicket(), ...sealed },
    });
    S.repSent = true;
    S.rep = null;
    renderReport();
  });
  if (!S.repSent) {
    btn.disabled = false;
    btn.textContent = 'שליחת הבקשה';
  }
}

/* ── Building faults (soldier-facing, separate from sign-out) ──────── */

function renderFault() {
  if (!S.config || !S.config.ready) {
    render(`
      <section class="panel center">
        <h1 class="panel-title">המערכת עדיין לא הוגדרה</h1>
        <p class="panel-sub mb0">מנהל הציוד צריך להשלים את ההקמה לפני שאפשר לדווח.</p>
      </section>`);
    return;
  }
  if (S.fltSent) {
    render(`
      <section class="panel center">
        <div class="big-ok" aria-hidden="true"></div>
        <h1 class="panel-title">התקלה דווחה</h1>
        <p class="panel-sub">הדיווח נקלט ויטופל. אין צורך לשלוח שוב על אותה תקלה.</p>
        <button class="btn ghost wide mt" data-act="flt-again">דיווח תקלה נוספת</button>
        <p class="muted-txt mt mb0"><a class="foot-link" href="#">חזרה לתפריט</a></p>
      </section>`);
    return;
  }
  const v = S.flt || { name: '', phone: '', text: '' };
  render(`
    <section class="panel center-head">
      <img class="unit-badge" src="/logo.png" alt="סמל מסייעת 951">
      <h1 class="panel-title center">דיווח תקלות בינוי</h1>
      <p class="panel-sub center">משהו שבור במבנה? נזילה, חשמל, מזגן, דלת, חלון. כתבו מה ואיפה, ונטפל.</p>
      <form data-form="fault" novalidate>
        <div class="grid2">
          <label class="field">
            <span class="field-label">שם המדווח <span class="req">*</span></span>
            <input class="input" name="name" autocomplete="off" maxlength="60"
                   value="${esc(v.name)}" required>
          </label>
          <label class="field">
            <span class="field-label">טלפון המדווח <span class="req">*</span></span>
            <input class="input num" name="phone" inputmode="tel" autocomplete="tel"
                   maxlength="10" value="${esc(v.phone)}" placeholder="0501234567" required>
          </label>
        </div>
        <label class="field">
          <span class="field-label">תיאור התקלה <span class="req">*</span></span>
          <textarea class="input area" name="text" rows="7" maxlength="1500"
                    placeholder="לדוגמה: נזילה מהתקרה במקלחות בבניין 4, מתחת לחלון. המים מגיעים עד המסדרון." required>${esc(v.text)}</textarea>
          <span class="field-hint">כתבו איפה בדיוק ומה קרה — ככל שיש יותר פרטים כך הטיפול מהיר יותר.</span>
        </label>
        <p class="form-err" data-err></p>
        <button class="btn primary wide" type="submit">שליחת הדיווח</button>
      </form>
      <p class="muted-txt mt mb0 center"><a class="foot-link" href="#">חזרה לתפריט</a></p>
    </section>`);
}

async function faultSubmit(form) {
  const name = form.name.value.trim();
  const phone = form.phone.value.trim();
  const text = form.text.value.trim();
  if (name.length < 2) return setFormErr(form, 'נא למלא את שם המדווח');
  if (!/^\d{9,10}$/.test(phone)) return setFormErr(form, 'טלפון: 9–10 ספרות, ללא מקפים');
  if (text.length < 5) return setFormErr(form, 'נא לתאר את התקלה');
  setFormErr(form, '');
  S.flt = { name, phone, text };
  const btn = form.querySelector('button[type=submit]');
  btn.disabled = true;
  btn.textContent = 'שולח…';
  await withBusy(async () => {
    const sealed = await seal(await importPubKey(S.config.pub), {
      kind: 'fault', name, phone, text, createdAt: Date.now(),
    });
    await api('/reports', {
      body: { id: hex(crypto.getRandomValues(new Uint8Array(16))), ticket: await getTicket(), ...sealed },
    });
    S.fltSent = true;
    S.flt = null;
    renderFault();
  });
  if (!S.fltSent) {
    btn.disabled = false;
    btn.textContent = 'שליחת הדיווח';
  }
}

/* ── Armoury deposit (soldier-facing, separate from sign-out) ──────── */

function renderDeposit() {
  if (!S.config || !S.config.ready) {
    render(`
      <section class="panel center">
        <h1 class="panel-title">המערכת עדיין לא הוגדרה</h1>
        <p class="panel-sub mb0">מנהל הציוד צריך להשלים את ההקמה לפני שאפשר לאפסן.</p>
      </section>`);
    return;
  }
  if (S.depSent) {
    render(`
      <section class="panel center">
        <div class="big-ok" aria-hidden="true"></div>
        <h1 class="panel-title">בקשת האפסון נשלחה</h1>
        <p class="panel-sub">האפסון נקלט במצב <span class="state wait">ממתין לאישור</span>. מנהל הארמון יאשר אותו והנשק ייכנס לרישום הארמון. אל תעזבו את הנשק לפני שקיבלתם אישור.</p>
        <button class="btn ghost wide mt" data-act="dep-again">אפסון נוסף</button>
        <p class="muted-txt mt mb0"><a class="foot-link" href="#">חזרה לתפריט</a></p>
      </section>`);
    return;
  }
  const v = S.dep || { pn: '', name: '', phone: '', weapon: '', amral: '', scope: '' };
  render(`
    <section class="panel center-head">
      <img class="unit-badge" src="/logo.png" alt="סמל מסייעת 951">
      <h1 class="panel-title center">אפסון נשק בארמון</h1>
      <p class="panel-sub center">מוסרים נשק לאחסון בארמון? מלאו את הפרטים. ארבעת השדות הראשונים הם חובה.</p>
      <form data-form="deposit" novalidate>
        <div class="grid2">
          <label class="field">
            <span class="field-label">מספר אישי <span class="req">*</span></span>
            <input class="input num" name="pn" inputmode="numeric" autocomplete="off"
                   maxlength="9" value="${esc(v.pn)}" placeholder="1234567" required>
          </label>
          <label class="field">
            <span class="field-label">שם החייל <span class="req">*</span></span>
            <input class="input" name="name" autocomplete="off" maxlength="60"
                   value="${esc(v.name)}" required>
          </label>
          <label class="field">
            <span class="field-label">מספר טלפון <span class="req">*</span></span>
            <input class="input num" name="phone" inputmode="tel" autocomplete="tel"
                   maxlength="10" value="${esc(v.phone)}" placeholder="0501234567" required>
          </label>
          <label class="field">
            <span class="field-label">מספר נשק <span class="req">*</span></span>
            <input class="input num" name="weapon" autocomplete="off" maxlength="20"
                   value="${esc(v.weapon)}" placeholder="7145732" required>
          </label>
        </div>
        <fieldset class="lic-set">
          <legend class="field-label">אמצעים נלווים <span class="opt-tag">רק אם קיימים</span></legend>
          <div class="grid2">
            <label class="field">
              <span class="field-label">מק״ט אמר״ל</span>
              <input class="input num" name="amral" autocomplete="off" maxlength="20"
                     value="${esc(v.amral)}">
            </label>
            <label class="field">
              <span class="field-label">מק״ט כוונת יום</span>
              <input class="input num" name="scope" autocomplete="off" maxlength="20"
                     value="${esc(v.scope)}">
            </label>
          </div>
          <span class="field-hint">אם לא מסרתם אמר״ל או כוונת — השאירו ריק.</span>
        </fieldset>
        <p class="form-err" data-err></p>
        <button class="btn primary wide" type="submit">שליחת בקשת אפסון</button>
      </form>
      <p class="muted-txt mt mb0 center"><a class="foot-link" href="#">חזרה לתפריט</a></p>
    </section>`);
}

async function depositSubmit(form) {
  const pn = form.pn.value.trim();
  const name = form.name.value.trim();
  const phone = form.phone.value.trim();
  const weapon = form.weapon.value.trim();
  const amral = form.amral.value.trim();
  const scope = form.scope.value.trim();
  if (!/^\d{5,9}$/.test(pn)) return setFormErr(form, 'מספר אישי: 5–9 ספרות');
  if (name.length < 2) return setFormErr(form, 'נא למלא את שם החייל');
  if (!/^\d{9,10}$/.test(phone)) return setFormErr(form, 'טלפון: 9–10 ספרות, ללא מקפים');
  const serialRe = /^[A-Za-z0-9\-/]{3,20}$/;
  if (!serialRe.test(weapon)) {
    return setFormErr(form, 'מספר נשק: 3–20 תווים (ספרות, אותיות באנגלית, - או /)');
  }
  if (amral && !serialRe.test(amral)) {
    return setFormErr(form, 'מק״ט אמר״ל: 3–20 תווים (ספרות, אותיות באנגלית, - או /)');
  }
  if (scope && !serialRe.test(scope)) {
    return setFormErr(form, 'מק״ט כוונת יום: 3–20 תווים (ספרות, אותיות באנגלית, - או /)');
  }
  setFormErr(form, '');
  S.dep = { pn, name, phone, weapon, amral, scope };
  const btn = form.querySelector('button[type=submit]');
  btn.disabled = true;
  btn.textContent = 'שולח…';
  await withBusy(async () => {
    const sealed = await seal(await importPubKey(S.config.pub), {
      kind: 'deposit', pn, name, phone, weapon, amral, scope, createdAt: Date.now(),
    });
    await api('/reports', {
      body: { id: hex(crypto.getRandomValues(new Uint8Array(16))), ticket: await getTicket(), ...sealed },
    });
    S.depSent = true;
    S.dep = null;
    renderDeposit();
  });
  if (!S.depSent) {
    btn.disabled = false;
    btn.textContent = 'שליחת בקשת אפסון';
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
        ${licLine}
      </dl>

      ${v.weapon || v.amral || v.scope ? `
      <div class="serial-check">
        <p class="serial-check-t">בדקו ספרה-ספרה — אין ברקוד ואין צילום, מה שנרשם כאן הוא הרישום היחיד</p>
        ${[['מספר נשק', v.weapon], ['מספר אמר״ל', v.amral], ['מספר כוונת', v.scope]]
          .filter(([, n]) => n)
          .map(([k, n]) => `
            <div class="serial-row">
              <span class="serial-lbl">${k}</span>
              <span class="serial-val num">${esc(n)}</span>
            </div>`).join('')}
        <button type="button" class="linkbtn" data-act="s-edit-ident">תיקון המספרים</button>
      </div>` : ''}

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
  // The serials are part of what was signed for, so they belong on the receipt.
  const v = S.ident || {};
  const serials = [['נשק', v.weapon], ['אמר״ל', v.amral], ['כוונת', v.scope]]
    .filter(([, n]) => n)
    .map(([k, n]) => `<span class="tagi">${k} <span class="num">${esc(n)}</span></span>`)
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
      ${serials ? `<div class="tags center">${serials}</div>` : ''}
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
      <h1 class="panel-title">כניסה למערכת</h1>
      <p class="panel-sub">הסיסמה פותחת את מפתח ההצפנה בדפדפן — היא לעולם לא נשלחת לשרת.</p>
      <form data-form="login" novalidate>
        <label class="field">
          <span class="field-label">שם משתמש</span>
          <input class="input" type="text" name="username" autocomplete="username"
                 spellcheck="false" autocapitalize="off" maxlength="31" required>
        </label>
        <label class="field">
          <span class="field-label">סיסמה</span>
          <input class="input" type="password" name="pw" autocomplete="current-password" required>
        </label>
        <p class="form-err" data-err></p>
        <button class="btn primary wide" type="submit">כניסה</button>
      </form>
    </section>`, 'login');
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

/* ── Screens & permissions ─────────────────────────────────────────── */

// Mirrors TAB_NEEDS in the Worker. `needs` is what the screen reads, and the
// server denies those endpoints to a user whose screens do not include them —
// which is why screens sharing a source cannot be separated any finer.
const TABS = [
  { id: 'over',    name: 'סקירה',        needs: ['records', 'vault', 'reports'] },
  { id: 'pending', name: 'ממתין לאישור', needs: ['records'] },
  { id: 'track',   name: 'מעקב ציוד',    needs: ['records'] },
  { id: 'reports', name: 'בקשות חוסר',   needs: ['reports'] },
  { id: 'faults',  name: 'תקלות בינוי',  needs: ['reports'] },
  { id: 'inv',     name: 'מלאי',         needs: ['records', 'vault'] },
  { id: 'armon',   name: 'ארמון',        needs: ['vault', 'reports'] },
  { id: 'tzelem',  name: 'דו״ח צלם',     needs: ['vault'] },
  { id: 'ammo',    name: 'תחמושת ואלפא', needs: ['vault'] },
  { id: 'veh',     name: 'רכבים',        needs: ['vault'] },
  { id: 'sum',     name: 'דוחות',        needs: ['records'] },
  { id: 'sec',     name: 'אבטחה',        needs: [], adminOnly: true },
];

const tabName = (id) => (TABS.find((t) => t.id === id) || {}).name || id;

function allowedTabs() {
  if (S.role === 'admin') return TABS.map((t) => t.id);
  let list = [];
  if (S.tabs === '*') list = TABS.filter((t) => !t.adminOnly).map((t) => t.id);
  else { try { list = JSON.parse(S.tabs) || []; } catch { list = []; } }
  return TABS.filter((t) => !t.adminOnly && list.includes(t.id)).map((t) => t.id);
}

function allowedScopes() {
  const out = new Set();
  for (const id of allowedTabs()) {
    for (const n of (TABS.find((t) => t.id === id) || { needs: [] }).needs) out.add(n);
  }
  return out;
}

function renderConsole() {
  $app.classList.add('wide');
  const c = counts();
  const openReps = openReports();
  const permitted = new Set(allowedTabs());
  if (!permitted.has(S.tab)) S.tab = allowedTabs()[0] || 'over';
  const SECTIONS = [
    ['over',    'סקירה',        null],
    ['pending', 'ממתין לאישור', c.pending],
    ['track',   'מעקב ציוד',    c.approved],
    ['reports', 'בקשות חוסר',   openReps, openReps > 0],
    ['faults',  'תקלות בינוי',  openFaults() || null, openFaults() > 0],
    ['inv',     'מלאי',         null],
    // a deposit waiting for approval outranks the item count — it needs action
    ['armon',   'ארמון',        openDeposits() || armonCount() || null, openDeposits() > 0],
    ['tzelem',  'דו״ח צלם',     null],
    ['ammo',    'תחמושת ואלפא', null],
    ['veh',     'רכבים',        vehAlerts() || null, true],
    ['sum',     'דוחות',        null],
    ['sec',     'אבטחה',        null],
  ];

  const nav = SECTIONS.filter(([id]) => permitted.has(id)).map(
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
  else if (S.tab === 'faults') body = renderFaultsTab();
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
        <span class="who-tag">${esc(S.me || '')}</span>
        ${S.role === 'viewer' ? '<span class="ro-tag">צפייה בלבד</span>' : ''}
        <button class="btn ghost small" data-act="refresh">רענון</button>
        <button class="btn ghost small" data-act="lock">נעילה</button>
      </div>
    </div>
    ${S.role === 'viewer'
      ? `<div class="callout"><p class="mb0">אתם מחוברים כ<strong>משתמש צפייה</strong> (${esc(S.me)}) עם גישה ל${
          allowedTabs().length === 1 ? 'מסך ' : `-${allowedTabs().length} מסכים: `
        }<strong>${allowedTabs().map((t) => esc(tabName(t))).join(', ')}</strong>. אי אפשר לאשר, לערוך או למחוק — השרת דוחה כל ניסיון שינוי וכל בקשת מידע ממסך שאינו מורשה.</p></div>`
      : ''}
    ${c.damaged
      ? `<div class="callout risk"><p class="mb0"><strong class="num">${c.damaged}</strong> רשומות פגומות — הפענוח נכשל (חשד לשיבוש נתונים בשרת).</p></div>`
      : ''}
    <div class="console">
      <aside class="side">
        <div class="navlist" role="tablist">${nav}</div>
      </aside>
      <div class="cmain">${body}</div>
    </div>`);
  if (S.role === 'viewer') stripWriteControls();
}

// Everything a viewer is allowed to touch. Anything else that can be clicked or
// typed into is removed after render — an allowlist rather than a list of
// forbidden actions, so a new write control is locked out by default rather
// than by remembering to add it. The server refuses the writes regardless;
// this only keeps the screen honest about what is possible.
const READ_ACTS = new Set([
  'tab', 'refresh', 'lock', 'page', 'filter', 'search', 'dept', 'collapse',
  'reveal', 'rep-reveal', 'doc', 'expand', 'rep-filter', 'dep-filter',
  'flt-filter', 'arm-kind', 'fuel-open', 'fuel-doc', 'fuel-dl-one', 'fuel-dl-all',
  'rep-csv', 'rep-pdf', 'tz-wa',
]);

function stripWriteControls() {
  for (const el of $app.querySelectorAll('[data-act]')) {
    const act = el.dataset.act;
    if (READ_ACTS.has(act) || /(^|-)(search|qclear|export)$/.test(act)) continue;
    if (el.matches('input, select, textarea')) {
      el.disabled = true;
    } else {
      el.remove();
    }
  }
  for (const el of $app.querySelectorAll('form[data-form]')) el.remove();
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

// Matches a record against the free-text query: name, personal number, phone,
// or any of the serials the soldier registered (weapon / amral / scope) — a
// serial that turns up in the field is often all you have to go on.
function matchesQuery(d, q) {
  if (!q) return true;
  const needle = q.trim().toLowerCase();
  if (!needle) return true;
  const digits = needle.replace(/\D/g, '');
  return (
    (d.name || '').toLowerCase().includes(needle) ||
    (!!digits && (d.pn || '').includes(digits)) ||
    (!!digits && (d.phone || '').includes(digits)) ||
    (d.weapon || '').toLowerCase().includes(needle) ||
    (d.amral || '').toLowerCase().includes(needle) ||
    (d.scope || '').toLowerCase().includes(needle)
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
  // Serials the soldier registered — they are signed for just like the kit.
  const serials = [['נשק', d.weapon], ['אמר״ל', d.amral], ['כוונת', d.scope]]
    .filter(([, n]) => n)
    .map(([k, n]) => `• ${k}: ${n}`)
    .join('\n');
  const msg =
    '*אישור רישום ראשוני — מסייעת 951*\n\n' +
    `שלום ${d.name},\n` +
    'רישום הציוד שלך אושר והוחתמת על:\n\n' +
    `${lines}\n\n` +
    (serials ? `*מספרים סידוריים:*\n${serials}\n\n` : '') +
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

/* ── Roster tables (PLAN §7.2 — must stay readable at 100+ soldiers) ──
   Cards were fine for a handful of soldiers and unusable past that: one screen
   held three people and nothing could be compared down a column. Both tabs are
   now one row per soldier — scannable, sortable, and expandable in place for
   the detail — with bulk approval so a whole intake is not 60 separate clicks. */

const SORTS = {
  name: (a, b) => (a.data.name || '').localeCompare(b.data.name || '', 'he'),
  pn: (a, b) => String(a.data.pn || '').localeCompare(String(b.data.pn || ''), 'en', { numeric: true }),
  dept: (a, b) => deptName(a.data.dept).localeCompare(deptName(b.data.dept), 'he'),
  date: (a, b) => (a.data.createdAt || 0) - (b.data.createdAt || 0),
  approved: (a, b) => (a.data.approvedAt || 0) - (b.data.approvedAt || 0),
  items: (a, b) => totalItems(a.data) - totalItems(b.data),
  out: (a, b) => outstanding(a.data) - outstanding(b.data),
};

const totalItems = (d) => Object.values(d.items || {}).reduce((s, it) => s + it.t, 0);

function sortRecs(recs, key) {
  const cmp = SORTS[key] || SORTS.name;
  const dir = S.sort.dir === 'desc' ? -1 : 1;
  return recs.slice().sort((a, b) => cmp(a, b) * dir);
}

// A sortable column header. Clicking the active column flips the direction.
function sortTh(key, label, cls = '') {
  const on = S.sort.key === key;
  return `<th class="${cls} th-sort${on ? ' on' : ''}">
    <button class="th-btn" data-act="sort" data-k="${key}">
      ${label}<span class="th-arrow" aria-hidden="true">${on ? (S.sort.dir === 'desc' ? '▾' : '▴') : ''}</span>
    </button>
  </th>`;
}

// The compact per-item summary that lets one column stand in for five.
function itemChips(d, mode) {
  return ITEMS.filter((i) => d.items[i.id])
    .map((i) => {
      const it = d.items[i.id];
      const held = it.t - (it.r || 0);
      if (mode === 'track') {
        return `<span class="chip ${held > 0 ? 'held' : 'back'}" title="${esc(i.name)}">
          ${esc(i.name)} <span class="num">${held > 0 ? `${held}/${it.t}` : '✓'}</span></span>`;
      }
      return `<span class="chip" title="${esc(i.name)}">${esc(i.name)} <span class="num">${it.t}</span></span>`;
    })
    .join('');
}

function renderPendingTab() {
  const all = S.recs.filter((r) => r.status === 'pending');
  if (!all.length) return '<p class="empty">אין הגשות ממתינות. לחצו רענון כדי לבדוק שוב.</p>';
  const broken = all.filter((r) => r.damaged).map(damagedCard).join('');
  const visible = sortRecs(applyFilters(all), S.sort.key === 'approved' ? 'date' : S.sort.key);
  const p = paged('pending', visible);

  // Ticks only survive while the row is on screen, so the count never claims
  // more than the admin can actually see.
  const pickable = p.slice.map((r) => r.rid);
  const picked = pickable.filter((rid) => S.picked.has(rid));
  const allPicked = pickable.length > 0 && picked.length === pickable.length;

  const rows = p.slice.map((rec) => {
    const d = rec.data;
    const open = S.expanded.has(rec.rid);
    return `
      <tr class="${open ? 'is-open' : ''}">
        <td><input type="checkbox" class="kitbox" data-act="pick" data-rid="${esc(rec.rid)}"
                   ${S.picked.has(rec.rid) ? 'checked' : ''} aria-label="בחירת ${esc(d.name)}"></td>
        <td class="lg-name">
          <button class="rowlink" data-act="expand" data-rid="${esc(rec.rid)}">
            ${esc(d.name)}<span class="row-caret" aria-hidden="true">${open ? '▾' : '◂'}</span>
          </button>
          ${d.supp ? '<span class="tagi supp">השלמה</span>' : ''}
        </td>
        <td class="num">${esc(d.pn)}</td>
        <td>${esc(deptName(d.dept))}</td>
        <td class="num">
          ${esc(S.revealed.has(rec.rid) ? d.phone : maskPhone(d.phone))}
          <button class="linkbtn" data-act="reveal" data-rid="${esc(rec.rid)}">${S.revealed.has(rec.rid) ? 'הסתרה' : 'הצגה'}</button>
        </td>
        <td class="chips">${itemChips(d, 'pending') || '<span class="dim">—</span>'}</td>
        <td class="num">${d.weapon ? esc(d.weapon) : '<span class="dim">—</span>'}</td>
        <td class="num">${esc(fmtDate(d.createdAt))}</td>
        <td class="nowrap">
          <button class="btn primary small" data-act="approve" data-rid="${esc(rec.rid)}">אישור</button>
          <button class="linkbtn danger-link" data-act="del" data-rid="${esc(rec.rid)}">מחיקה</button>
        </td>
      </tr>
      ${open ? `<tr class="sub"><td colspan="9">${pendingDetail(rec)}</td></tr>` : ''}`;
  }).join('');

  return `
    ${searchBar(all.length, visible.length)}
    ${broken}
    <section class="panel">
      <h2 class="panel-title">ממתינים לאישור</h2>
      <p class="panel-sub">שורה לכל חייל. לחיצה על השם פותחת את הפירוט ומאפשרת לתקן כמויות לפני האישור. סמנו כמה שורות כדי לאשר אותן יחד.</p>
      <div class="bulkbar${picked.length ? ' on' : ''}">
        <label class="bulk-all">
          <input type="checkbox" class="kitbox" data-act="pick-all" ${allPicked ? 'checked' : ''}
                 aria-label="בחירת כל השורות בעמוד">
          <span>בחירת כל השורות בעמוד</span>
        </label>
        ${picked.length
          ? `<span class="bulk-n"><span class="num">${picked.length}</span> מסומנים</span>
             <button class="btn primary small" data-act="bulk-approve">אישור המסומנים</button>
             <button class="btn danger small" data-act="bulk-del">מחיקת המסומנים</button>
             <button class="linkbtn" data-act="pick-clear">ניקוי הבחירה</button>`
          : '<span class="muted-txt">סמנו שורות כדי לאשר או למחוק כמה יחד</span>'}
      </div>
      ${p.slice.length
        ? `<div class="tbl-scroll">
             <table class="tbl roster">
               <thead><tr>
                 <th class="col-pick"></th>
                 ${sortTh('name', 'שם')}
                 ${sortTh('pn', 'מ״א', 'num')}
                 ${sortTh('dept', 'מחלקה')}
                 <th class="num">טלפון</th>
                 ${sortTh('items', 'ציוד')}
                 <th class="num">נשק</th>
                 ${sortTh('date', 'נשלח', 'num')}
                 <th></th>
               </tr></thead>
               <tbody>${rows}</tbody>
             </table>
           </div>
           ${pager('pending', p)}`
        : '<p class="empty">אין הגשות שתואמות את החיפוש.</p>'}
    </section>`;
}

// The expanded row: quantities are adjustable here, where there is room for the
// steppers, instead of every row carrying them all the time.
function pendingDetail(rec) {
  const d = rec.data;
  const rows = ITEMS.filter((i) => d.items[i.id]).map((item) => {
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
  }).join('');
  return `
    <div class="rowdetail">
      ${d.supp
        ? '<p class="muted-txt">השלמת ציוד — באישור, הפריטים יתווספו לרישום המאושר הקיים של החייל.</p>'
        : ''}
      ${extrasRow(rec)}
      <ul>${rows}</ul>
      ${fpStrip(rec.rid)}
    </div>`;
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

  const visible = sortRecs(
    applyFilters(approved).filter((rec) => {
      const out = outstanding(rec.data) > 0;
      return S.filter === 'all' || (S.filter === 'out' ? out : !out);
    }),
    S.sort.key === 'date' ? 'approved' : S.sort.key
  );

  const broken = approved.filter((r) => r.damaged).map(damagedCard).join('');
  const p = paged('track', visible);

  const rows = p.slice.map((rec) => {
    const d = rec.data;
    const out = outstanding(d);
    const open = S.expanded.has(rec.rid);
    return `
      <tr class="${open ? 'is-open' : ''}${out > 0 ? '' : ' row-done'}">
        <td class="lg-name">
          <button class="rowlink" data-act="expand" data-rid="${esc(rec.rid)}">
            ${esc(d.name)}<span class="row-caret" aria-hidden="true">${open ? '▾' : '◂'}</span>
          </button>
        </td>
        <td class="num">${esc(d.pn)}</td>
        <td>${esc(deptName(d.dept))}</td>
        <td class="num">
          ${esc(S.revealed.has(rec.rid) ? d.phone : maskPhone(d.phone))}
          <button class="linkbtn" data-act="reveal" data-rid="${esc(rec.rid)}">${S.revealed.has(rec.rid) ? 'הסתרה' : 'הצגה'}</button>
        </td>
        <td class="chips">${itemChips(d, 'track') || '<span class="dim">—</span>'}</td>
        <td class="num ${out > 0 ? 'warn' : 'ok'}">${out > 0 ? out : '✓'}</td>
        <td class="num">${d.weapon ? esc(d.weapon) : '<span class="dim">—</span>'}</td>
        <td class="num">${esc(fmtDate(d.approvedAt))}</td>
        <td>${d.notified
          ? '<span class="sent">✓ נשלחה</span>'
          : '<span class="unsent">טרם נשלחה</span>'}</td>
        <td class="nowrap">
          ${out > 0
            ? `<button class="btn ghost small" data-act="creditall" data-rid="${esc(rec.rid)}">זיכוי מלא</button>`
            : ''}
          <a class="btn wa small" href="${esc(waLink(d, rec.rid))}" data-act="wa-sign"
             data-rid="${esc(rec.rid)}" target="_blank" rel="noopener noreferrer">וואטסאפ</a>
        </td>
      </tr>
      ${open ? `<tr class="sub"><td colspan="10">${trackDetail(rec)}</td></tr>` : ''}`;
  }).join('');

  return `
    ${searchBar(approved.length, visible.length)}
    <div class="filters">${filters}</div>
    ${broken}
    <section class="panel">
      <h2 class="panel-title">מעקב ציוד</h2>
      <p class="panel-sub">שורה לכל חייל. עמודת הציוד מראה כמה עדיין אצלו מתוך מה שהוחתם; ✓ = הוחזר במלואו. לחיצה על השם פותחת את הזיכוי פריט־פריט.</p>
      ${p.slice.length
        ? `<div class="tbl-scroll">
             <table class="tbl roster">
               <thead><tr>
                 ${sortTh('name', 'שם')}
                 ${sortTh('pn', 'מ״א', 'num')}
                 ${sortTh('dept', 'מחלקה')}
                 <th class="num">טלפון</th>
                 <th>ציוד — אצלו כעת / הוחתם</th>
                 ${sortTh('out', 'בחוץ', 'num')}
                 <th class="num">נשק</th>
                 ${sortTh('approved', 'אושר', 'num')}
                 <th>הודעה</th>
                 <th></th>
               </tr></thead>
               <tbody>${rows}</tbody>
             </table>
           </div>
           ${pager('track', p)}`
        : '<p class="empty">אין רשומות שתואמות את החיפוש והסינון.</p>'}
    </section>`;
}

// The expanded row: the per-item return steppers and the messaging actions,
// which need more room than a table cell has.
function trackDetail(rec) {
  const d = rec.data;
  const rows = ITEMS.filter((i) => d.items[i.id]).map((item) => {
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
  }).join('');
  const anyBack = d.items && Object.values(d.items).some((it) => (it.r || 0) > 0);
  return `
    <div class="rowdetail">
      <div class="rec-meta">${d.notified
        ? '<span class="sent">✓ הודעת רישום נשלחה</span>'
        : '<span class="unsent">הודעת רישום טרם נשלחה</span>'}${
        d.returnNotified ? ' · <span class="sent">✓ הודעת זיכוי נשלחה</span>' : ''}</div>
      ${extrasRow(rec)}
      <ul>${rows}</ul>
      <div class="rec-actions">
        ${anyBack
          ? `<a class="btn wa ghost-wa" href="${esc(returnWaLink(d, rec.rid))}" data-act="wa-ret"
                data-rid="${esc(rec.rid)}" target="_blank" rel="noopener noreferrer">${
                  d.returnNotified ? 'זיכוי — שליחה חוזרת' : 'הודעת זיכוי'
                }</a>`
          : ''}
        <button class="btn danger" data-act="del" data-rid="${esc(rec.rid)}">מחיקת הרשומה</button>
      </div>
      ${fpStrip(rec.rid)}
    </div>`;
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
      ${reportButtons('summary')}
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

// The overview has no search box of its own, so it must not inherit the search
// and department filter left behind on another tab — it passes `false`.
function licenceRows(approved, filtered = true) {
  return (filtered ? applyFilters(approved) : approved).map((rec) => {
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
           ${reportButtons('licences')}`
        : '<p class="empty">אין רשומות מאושרות.</p>'}
    </section>`;
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
          <td class="num">${d.amral ? esc(d.amral) : '<span class="dim">·</span>'}</td>
          <td class="num">${d.scope ? esc(d.scope) : '<span class="dim">·</span>'}</td>
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
      <p class="panel-sub">מספר סידורי של הנשק, האמר״ל והכוונת מול המחזיק, ממוין לפי מספר הנשק. מכבד את החיפוש והסינון.</p>
      <div class="stat-row">
        <div class="stat"><span class="stat-n num">${armed.length}</span><span class="stat-l">נשקים משויכים</span></div>
        <div class="stat"><span class="stat-n num">${armed.filter((r) => r.data.amral).length}</span><span class="stat-l">אמר״ל רשום</span></div>
        <div class="stat"><span class="stat-n num">${armed.filter((r) => r.data.scope).length}</span><span class="stat-l">כוונת רשומה</span></div>
        <div class="stat"><span class="stat-n num">${unarmed.length}</span><span class="stat-l">ללא נשק רשום</span></div>
      </div>
      ${armed.length
        ? `<div class="tbl-scroll">
             <table class="tbl">
               <thead><tr><th class="num">מס׳ נשק</th><th class="num">אמר״ל</th><th class="num">כוונת</th><th>שם</th><th class="num">מ״א</th><th>מחלקה</th><th class="num">טלפון</th></tr></thead>
               <tbody>${rows}</tbody>
             </table>
           </div>
           ${reportButtons('weapons')}`
        : '<p class="empty">אף חייל לא רשם מספר נשק עדיין.</p>'}
    </section>`;
}

/* ── Reports: one definition per table, two outputs ────────────────────
   Every exportable table is described once — name, columns, rows — and both
   the CSV and the printable PDF are generated from that description. Adding a
   column to a report can no longer leave its PDF behind. */

const REPORTS = {
  stock: {
    name: 'מלאי ציוד', file: 'tzayad-stock',
    build() {
      const inv = S.inv || emptyInv();
      const iss = issuedTotals();
      return {
        head: ['פריט', 'מלאי פתיחה', 'אצל חיילים', 'נותר במחסן', 'סטטוס'],
        rows: ITEMS.map((item) => {
          const open = Number(inv.open[item.id]) || 0;
          const held = iss[item.id].t - iss[item.id].r;
          const left = open - held;
          return [item.name, open, held, left,
            left < 0 ? 'חוסר' : left === 0 ? 'אזל' : 'תקין'];
        }),
      };
    },
  },

  stockExtra: {
    name: 'פריטים נוספים', file: 'tzayad-stock-extra',
    build() {
      const rows = (S.inv && S.inv.extra) || [];
      return {
        head: ['פריט', 'סה״כ', 'בשימוש', 'נותר', 'סטטוס'],
        rows: rows.map((x) => {
          const open = Number(x.open) || 0;
          const out = Number(x.out) || 0;
          return [x.name, open, out, open - out, open - out < 0 ? 'חוסר' : 'תקין'];
        }),
      };
    },
  },

  summary: {
    name: 'סיכום מלאי והחתמות', file: 'tzayad-summary', sensitive: true,
    build() {
      const licCell = (d, kind) => {
        const l = (d.lic || {})[kind];
        if (!l || !l.has) return '';
        return l.doc ? 'כן (עם צילום)' : 'כן';
      };
      return {
        head: [
          'מספר אישי', 'שם', 'טלפון', 'מחלקה', 'מספר נשק', 'מספר אמר״ל', 'מספר כוונת',
          ...ITEMS.flatMap((i) => [`${i.name} נלקח`, `${i.name} הוחזר`]),
          'רישיון אזרחי', 'רישיון צבאי', 'סטטוס', 'נשלח', 'אושר',
        ],
        rows: S.recs.filter((r) => !r.damaged).map((rec) => {
          const d = rec.data;
          return [
            d.pn, d.name, d.phone, deptName(d.dept), d.weapon || '', d.amral || '', d.scope || '',
            ...ITEMS.flatMap((i) => {
              const it = d.items[i.id];
              return it ? [it.t, it.r || 0] : ['', ''];
            }),
            licCell(d, 'civil'), licCell(d, 'military'),
            rec.status === 'approved' ? 'מאושר' : 'ממתין',
            fmtDate(d.createdAt),
            d.approvedAt ? fmtDate(d.approvedAt) : '',
          ];
        }),
      };
    },
  },

  licences: {
    name: 'רישיונות נהיגה', file: 'tzayad-licences', sensitive: true,
    build() {
      const approved = S.recs.filter((r) => r.status === 'approved' && !r.damaged);
      const rows = licenceRows(approved).slice()
        .sort((a, b) => LIC_RANK[a.st] - LIC_RANK[b.st] || a.name.localeCompare(b.name, 'he'));
      return {
        head: ['שם', 'מספר אישי', 'מחלקה', 'מספר רישיון', 'בתוקף עד', 'סטטוס', 'רישיון צבאי', 'צילום מצורף'],
        rows: rows.map((r) => [
          r.name, r.pn, r.dept, r.no, r.exp ? fmtDay(r.exp) : '',
          LIC_LABEL[r.st], r.mil ? 'כן' : 'לא', r.doc ? 'כן' : 'לא',
        ]),
        summary: `${rows.filter((r) => r.st === 'valid').length} בתוקף · ` +
          `${rows.filter((r) => r.st === 'soon').length} פגים בקרוב · ` +
          `${rows.filter((r) => r.st !== 'valid' && r.st !== 'soon').length} לא בתוקף`,
      };
    },
  },

  weapons: {
    name: 'רשימת נשקים', file: 'tzayad-weapons', sensitive: true,
    build() {
      const armed = S.recs
        .filter((r) => r.status === 'approved' && !r.damaged && r.data && r.data.weapon)
        .sort((a, b) => String(a.data.weapon).localeCompare(String(b.data.weapon), 'en', { numeric: true }));
      return {
        head: ['מספר נשק', 'מספר אמר״ל', 'מספר כוונת', 'שם', 'מספר אישי', 'מחלקה', 'טלפון'],
        rows: armed.map((rec) => {
          const d = rec.data;
          return [d.weapon, d.amral || '', d.scope || '', d.name, d.pn, deptName(d.dept), d.phone];
        }),
      };
    },
  },

  ledger: {
    name: 'מי חתום על מה', file: 'tzayad-ledger', sensitive: true,
    build() {
      return {
        head: [
          'שם', 'מספר אישי', 'מחלקה', 'מספר נשק', 'מספר אמר״ל', 'מספר כוונת',
          ...ITEMS.flatMap((i) => [`${i.name} — הוחתם`, `${i.name} — אצלו כעת`]),
          'סה״כ בחוץ',
        ],
        rows: S.recs
          .filter((r) => r.status === 'approved' && !r.damaged && r.data)
          .map((rec) => {
            const d = rec.data;
            return [
              d.name, d.pn, deptName(d.dept), d.weapon || '', d.amral || '', d.scope || '',
              ...ITEMS.flatMap((i) => {
                const it = d.items[i.id];
                return it ? [it.t, it.t - (it.r || 0)] : ['', ''];
              }),
              outstanding(d),
            ];
          }),
      };
    },
  },

  deposits: {
    name: 'בקשות אפסון נשק', file: 'tzayad-deposits', sensitive: true,
    build() {
      const rows = depositReports();
      return {
        head: ['נשלח', 'שם החייל', 'מספר אישי', 'טלפון', 'מספר נשק', 'מק״ט אמר״ל', 'מק״ט כוונת יום', 'סטטוס'],
        rows: rows.map((r) => {
          const d = r.data;
          return [fmtDate(d.createdAt), d.name, d.pn, d.phone, d.weapon,
            d.amral || '', d.scope || '', r.status === 'done' ? 'אושר ונקלט' : 'ממתין לאישור'];
        }),
      };
    },
  },

  faults: {
    name: 'תקלות בינוי', file: 'tzayad-faults', sensitive: true,
    build() {
      const rows = faultReports();
      return {
        head: ['דווח', 'שם המדווח', 'טלפון', 'סטטוס', 'תיאור התקלה'],
        rows: rows.map((r) => {
          const d = r.data;
          const st = r.status === 'done' ? 'done' : r.status === 'partial' ? 'partial' : 'open';
          return [fmtDate(d.createdAt), d.name, d.phone, FLT_LABEL[st], d.text];
        }),
      };
    },
  },

  armon: {
    name: 'פריטים בארמון', file: 'tzayad-armon',
    build() {
      const all = (S.inv && S.inv.armon) || [];
      return {
        head: ['סוג', 'פריט', 'מספר סידורי', 'בעלים', 'מיקום', 'משימה', 'תאריך הוספה'],
        rows: all.map((x) => [
          nameOf(ARM_KINDS, x.kind), x.name, x.serial, x.owner, nameOf(ARM_LOCS, x.loc),
          x.loc === 'mission' ? (x.mission || '(ללא שם)') : '',
          x.addedAt ? fmtDate(x.addedAt) : '',
        ]),
        summary: `${all.filter((x) => x.loc === 'armon').length} נמצאים בארמון · ` +
          `${all.filter((x) => x.loc !== 'armon').length} בחוץ · ${all.length} רשומים`,
      };
    },
  },

  armonLog: {
    name: 'יומן פעולות ארמון', file: 'tzayad-armon-log',
    build: () => ({
      head: ['תאריך', 'פעולה', 'סוג', 'פריט', 'מספר סידורי', 'בעלים', 'יעד', 'הערה'],
      rows: ((S.inv && S.inv.armonLog) || []).map((e) => [
        fmtDate(e.t), e.action === 'add' ? 'הוספה' : 'הסרה', nameOf(ARM_KINDS, e.kind),
        e.name, e.serial, e.owner, e.dest ? nameOf(ARM_DESTS, e.dest) : '', e.note,
      ]),
    }),
  },

  tzelem: {
    name: 'דו״ח צלם', file: 'tzayad-tzelem',
    build() {
      const rows = tzelemScope();
      const held = ((S.inv && S.inv.armon) || []).filter((x) => x.kind === 'weapon' && x.loc !== 'armon').length;
      return {
        head: ['סוג', 'פריט', 'מספר סידורי', 'בעלים', 'מיקום', 'משימה'],
        rows: rows.map((x) => [
          nameOf(ARM_KINDS, x.kind), x.name, x.serial, x.owner, nameOf(ARM_LOCS, x.loc),
          x.loc === 'mission' ? (x.mission || '(ללא שם)') : '',
        ]),
        summary: ARM_LOCS.map((l) => `${l.name}: ${rows.filter((x) => x.loc === l.id).length}`).join(' · ') +
          (held ? ` · ${held} נשקים אינם בארמון ואינם נכללים` : ''),
      };
    },
  },

  ammo: {
    name: 'מלאי תחמושת ואלפא', file: 'tzayad-ammo',
    build() {
      const all = (S.inv && S.inv.ammo) || [];
      return {
        head: ['פריט', 'כמות'],
        rows: all.map((x) => [x.name, x.qty]),
        summary: `${all.length} סוגים · ${all.reduce((s, x) => s + x.qty, 0)} יחידות סה״כ`,
      };
    },
  },

  ammoLog: {
    name: 'יומן תנועות תחמושת', file: 'tzayad-ammo-log',
    build: () => ({
      head: ['תאריך', 'פעולה', 'פריט', 'כמות', 'יעד', 'למי'],
      rows: ((S.inv && S.inv.ammoLog) || []).map((e) => [
        fmtDate(e.t), e.action === 'add' ? 'כניסה' : 'הוצאה', e.name, e.qty,
        e.dest ? nameOf(AMMO_DESTS, e.dest) : '', e.who,
      ]),
    }),
  },

  vehicles: {
    name: 'רכבים', file: 'tzayad-vehicles',
    build() {
      const today = new Date().toISOString().slice(0, 10);
      const all = (S.inv && S.inv.vehicles) || [];
      return {
        head: ['מספר רכב', 'חברת השכרה', 'ק״מ עדכני', 'מועד טיפול', 'קוד קודן', 'קוד דלקן',
          ...VEH_KIT.map((k) => k.name), 'סטטוס'],
        rows: all.map((v) => {
          const late = v.service && v.service < today;
          const missing = VEH_KIT.filter((k) => !v[k.id]);
          return [
            v.plate, v.company, v.km, v.service ? fmtDay(v.service) : '', v.code || '', v.fuelCode || '',
            ...VEH_KIT.map((k) => (v[k.id] ? 'כן' : 'לא')),
            late ? 'טיפול עבר' : missing.length ? `חסר: ${missing.map((k) => k.name).join(', ')}` : 'תקין',
          ];
        }),
      };
    },
  },

  fuel: {
    name: 'כרטיסי תדלוק', file: 'tzayad-fuel',
    build() {
      const rows = (S.inv && S.inv.fuel) || [];
      return {
        head: ['סוג כרטיס', 'מספר כרטיס', 'ליטרים שנותרו', 'סטטוס', 'אצל מי',
          'שימושים', 'ליטרים שנוצלו', 'שימוש אחרון', 'מספר קבלות', 'זוכה אצל קצין רכב'],
        rows: rows.map((x) => {
          const used = x.uses.reduce((s, u) => s + u.litres, 0);
          return [
            nameOf(FUEL_KINDS, x.kind), x.no, x.litres,
            x.litres < FUEL_LOW ? 'מלאי נמוך' : 'תקין', x.holder || '',
            x.uses.length, used, x.uses[0] ? fmtDate(x.uses[0].t) : '',
            x.receipts.length, x.credited ? `כן — ${fmtDate(x.creditedAt)}` : 'לא',
          ];
        }),
      };
    },
  },

  fuelUses: {
    name: 'יומן שימוש בכרטיסי תדלוק', file: 'tzayad-fuel-uses',
    build() {
      const uses = ((S.inv && S.inv.fuel) || []).flatMap((c) => c.uses.map((u) => ({ ...u, card: c })));
      uses.sort((a, b) => b.t - a.t);
      return {
        head: ['תאריך', 'מספר כרטיס', 'סוג דלק', 'מי השתמש', 'ליטרים', 'מספר רכב'],
        rows: uses.map((u) => [
          fmtDate(u.t), u.card.no, nameOf(FUEL_KINDS, u.card.kind), u.who, u.litres, u.plate || '',
        ]),
        summary: `${uses.length} שימושים · ${uses.reduce((s, u) => s + u.litres, 0)} ליטר סה״כ`,
      };
    },
  },
};

// The two output buttons every report carries, side by side.
function reportButtons(id, extra = '') {
  return `
    <div class="rec-actions mt">
      <button class="btn ghost" data-act="rep-csv" data-r="${id}">ייצוא ל-CSV</button>
      <button class="btn ghost" data-act="rep-pdf" data-r="${id}">הפקת PDF</button>
      ${extra}
    </div>`;
}

function reportCsv(id) {
  const def = REPORTS[id];
  const { head, rows } = def.build();
  if (!rows.length) { toast('אין נתונים לייצוא', true); return; }
  if (def.sensitive && !window.confirm('הקובץ אינו מוצפן ומכיל פרטים אישיים. להמשיך?')) return;
  if (!def.sensitive && !window.confirm('הקובץ אינו מוצפן. להמשיך?')) return;
  downloadCsv([head, ...rows].map((l) => l.map(csvCell).join(',')), `${def.file}.csv`);
}

// No PDF library can be loaded under this CSP, and Hebrew needs font embedding,
// so the report is laid out for print and the browser's "Save as PDF" makes the
// actual file. Dependency-free, and Hebrew renders correctly.
function reportPdf(id) {
  const def = REPORTS[id];
  const { head, rows, summary } = def.build();
  if (!rows.length) { toast('אין נתונים להפקה', true); return; }
  printDoc({
    title: def.name,
    meta: `הופק ${fmtDate(Date.now())} · ${rows.length} שורות${S.me ? ` · הופק על ידי ${S.me}` : ''}`,
    head, rows, summary,
  });
}

// Builds the printable sheet: unit emblem, title, repeating table header, a
// summary line, and a signature block — then hands over to the print dialog.
function printDoc({ title, meta, head, rows, summary }) {
  const host = document.createElement('section');
  host.className = 'printdoc';
  host.innerHTML = `
    <header class="pd-head">
      <img class="pd-logo" src="/logo.png" alt="">
      <div class="pd-headtxt">
        <h1 class="pd-title">${esc(title)} — מסייעת 951</h1>
        <p class="pd-date">${esc(meta)}</p>
      </div>
    </header>
    <table class="pd-tbl">
      <thead><tr><th class="pd-n">#</th>${head.map((h) => `<th>${esc(h)}</th>`).join('')}</tr></thead>
      <tbody>
        ${rows.map((r, i) => `<tr>
          <td class="pd-n">${i + 1}</td>
          ${r.map((c) => `<td>${esc(c == null ? '' : String(c))}</td>`).join('')}
        </tr>`).join('')}
      </tbody>
    </table>
    ${summary ? `<p class="pd-summary">${esc(summary)}</p>` : ''}
    <footer class="pd-foot">
      <div class="pd-sigs">
        <div class="pd-sig">
          <span class="pd-sig-l">שם עורך הדו״ח</span>
          <span class="pd-sig-line"></span>
        </div>
        <div class="pd-sig">
          <span class="pd-sig-l">חתימה</span>
          <span class="pd-sig-line"></span>
        </div>
        <div class="pd-sig">
          <span class="pd-sig-l">תאריך</span>
          <span class="pd-sig-line"></span>
        </div>
      </div>
      <div class="pd-sigs">
        <div class="pd-sig">
          <span class="pd-sig-l">שם המאשר / דרגה ותפקיד</span>
          <span class="pd-sig-line"></span>
        </div>
        <div class="pd-sig">
          <span class="pd-sig-l">חתימה</span>
          <span class="pd-sig-line"></span>
        </div>
        <div class="pd-sig">
          <span class="pd-sig-l">תאריך</span>
          <span class="pd-sig-line"></span>
        </div>
      </div>
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
          ${d.amral ? `<span class="lg-sub">אמר״ל <span class="num">${esc(d.amral)}</span></span>` : ''}
          ${d.scope ? `<span class="lg-sub">כוונת <span class="num">${esc(d.scope)}</span></span>` : ''}
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
           ${reportButtons('ledger')}`
        : '<p class="empty">אין חיילים שתואמים את החיפוש.</p>'}
    </section>`;
}

/* ── Inventory (מלאי) ──────────────────────────────────────────────── */

const emptyInv = () => ({
  open: {}, extra: [], notes: '',
  armon: [], armonLog: [], ammo: [], ammoLog: [], vehicles: [], fuel: [], countedAt: {},
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
      <p class="panel-sub">הזינו כמה קיבלתם מכל פריט ביום קליטת הציוד. היתרה מחושבת אוטומטית מהרישומים המאושרים: <strong>פתיחה − אצל החיילים = נותר במחסן</strong>.</p>
      ${anyNeg
        ? '<div class="callout alert"><p class="mb0"><strong>יתרה שלילית</strong> — הוחתם יותר ממה שנרשם במלאי הפתיחה. בדקו את מלאי הפתיחה או את הרישומים.</p></div>'
        : ''}
      <div class="tbl-scroll">
        <table class="tbl">
          <thead><tr><th>פריט</th><th>מלאי פתיחה</th><th class="num">אצל חיילים</th><th class="num">נותר במחסן</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      ${reportButtons('stock')}
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
      <div class="rec-actions mt">
        <button class="btn ghost" data-act="inv-xadd">+ הוספת פריט</button>
        ${inv.extra.length ? `<button class="btn ghost" data-act="rep-csv" data-r="stockExtra">ייצוא ל-CSV</button>
             <button class="btn ghost" data-act="rep-pdf" data-r="stockExtra">הפקת PDF</button>` : ''}
      </div>
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
  const licRows = licenceRows(approved, false);
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

  // Everything the armoury, ammunition, vehicle and fuel registers know, in the
  // same glance as the equipment numbers — otherwise those pages are invisible
  // from here and only get looked at when something has already gone wrong.
  const armon = inv.armon || [];
  const armOut = armon.filter((x) => x.kind === 'weapon' && x.loc !== 'armon');
  const ammo = inv.ammo || [];
  const ammoEmpty = ammo.filter((x) => x.qty <= 0);
  const vehicles = inv.vehicles || [];
  const today = new Date().toISOString().slice(0, 10);
  const vehLate = vehicles.filter((v) => v.service && v.service < today);
  const vehKitShort = vehicles.filter((v) => VEH_KIT.some((k) => !v[k.id]));
  const fuel = inv.fuel || [];
  const fuelLow = fuel.filter((x) => x.litres < FUEL_LOW);

  const logistics = [
    kpi(armon.filter((x) => x.loc === 'armon').length, 'פריטים בארמון', null,
        `${armon.length} רשומים · ${armon.length - armon.filter((x) => x.loc === 'armon').length} בחוץ`),
    kpi(ammo.reduce((s, x) => s + x.qty, 0), 'יחידות תחמושת', ammoEmpty.length ? 'warn' : null,
        ammoEmpty.length ? `${ammoEmpty.length} פריטים אזלו` : `${ammo.length} סוגים`),
    kpi(vehicles.length, 'רכבים', vehLate.length ? 'bad' : vehKitShort.length ? 'warn' : 'ok',
        vehLate.length ? `${vehLate.length} טיפול עבר` : vehKitShort.length ? `${vehKitShort.length} חסר ציוד` : 'הכול תקין'),
    kpi(fuel.reduce((s, x) => s + x.litres, 0), 'ליטרים בכרטיסים', fuelLow.length ? 'warn' : null,
        fuelLow.length ? `${fuelLow.length} כרטיסים במלאי נמוך` : `${fuel.length} כרטיסים`),
  ].join('');

  // One board for everything waiting on the quartermaster, ordered by urgency.
  // Each row jumps straight to the page that clears it.
  const actions = [
    c.pending && { n: c.pending, tone: 'warn', tab: 'pending',
      t: 'רישומים ממתינים לאישור', s: 'חיילים ששלחו רישום ועדיין לא אושרו' },
    openDeposits() && { n: openDeposits(), tone: 'bad', tab: 'armon',
      t: 'אפסוני נשק ממתינים', s: 'נשק שנמסר ועדיין לא נקלט לרישום הארמון' },
    openFaults() && { n: openFaults(), tone: 'warn', tab: 'faults',
      t: 'תקלות בינוי פתוחות', s: 'דווחו ועדיין לא סומנו כטופלו' },
    openReps && { n: openReps, tone: 'warn', tab: 'reports',
      t: 'בקשות חוסר פתוחות', s: 'חיילים שמחכים לתשובה' },
    shortItems.length && { n: shortItems.length, tone: 'bad', tab: 'inv',
      t: 'פריטים בחוסר', s: shortItems.map((i) => i.name).join(', ') },
    licBad && { n: licBad, tone: 'bad', tab: 'sum',
      t: 'רישיונות לא בתוקף', s: 'חיילים שאסור שינהגו' },
    licSoon && { n: licSoon, tone: 'warn', tab: 'sum',
      t: 'רישיונות פגים בקרוב', s: 'כדאי לחדש לפני שיפוג' },
    vehLate.length && { n: vehLate.length, tone: 'bad', tab: 'veh',
      t: 'רכבים עם טיפול שעבר', s: vehLate.map((v) => v.plate).filter(Boolean).join(', ') || 'ללא מספר רכב' },
    vehKitShort.length && { n: vehKitShort.length, tone: 'warn', tab: 'veh',
      t: 'רכבים עם ציוד חסר', s: VEH_KIT.map((k) => k.name).join(', ') },
    fuelLow.length && { n: fuelLow.length, tone: 'warn', tab: 'veh',
      t: 'כרטיסי תדלוק במלאי נמוך', s: `מתחת ל-${FUEL_LOW} ליטר` },
    ammoEmpty.length && { n: ammoEmpty.length, tone: 'warn', tab: 'ammo',
      t: 'פריטי תחמושת שאזלו', s: ammoEmpty.map((x) => x.name).join(', ') },
    armOut.length && { n: armOut.length, tone: 'warn', tab: 'armon',
      t: 'נשקים שאינם בארמון', s: 'רשומים אצל חיילים — לא ייכללו בדו״ח צלם' },
    armon.filter((x) => ARM_BAD_LOCS.has(x.loc)).length && {
      n: armon.filter((x) => ARM_BAD_LOCS.has(x.loc)).length, tone: 'bad', tab: 'armon',
      t: 'פריטים אבודים או מושבתים', s: 'דורשים דיווח או החלפה' },
    armon.filter((x) => x.loc === 'repair').length && {
      n: armon.filter((x) => x.loc === 'repair').length, tone: 'warn', tab: 'armon',
      t: 'פריטים בתיקון', s: 'ממתינים לחזרה מהמעבדה' },
    c.damaged && { n: c.damaged, tone: 'bad', tab: 'sec',
      t: 'רשומות פגומות', s: 'הפענוח נכשל — חשד לשיבוש נתונים' },
  ].filter(Boolean);

  const actionRows = actions.map((a) => `
    <button class="todo is-${a.tone}" data-act="tab" data-tab="${a.tab}">
      <span class="todo-n num">${a.n}</span>
      <span class="todo-txt">
        <span class="todo-t">${esc(a.t)}</span>
        <span class="todo-s">${esc(a.s)}</span>
      </span>
      <span class="todo-go" aria-hidden="true">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"
             stroke-linecap="round" stroke-linejoin="round"><path d="M15 5l-7 7 7 7"/></svg>
      </span>
    </button>`).join('');

  // Who is holding the most, so the person to chase is named rather than
  // hunted for across the ledger.
  const topHolders = approved
    .map((rec) => ({ d: rec.data, out: outstanding(rec.data) }))
    .filter((x) => x.out > 0)
    .sort((a, b) => b.out - a.out)
    .slice(0, 5);

  const holderRows = topHolders.map((x) => `
    <tr>
      <td>${esc(x.d.name)}</td>
      <td class="num">${esc(x.d.pn)}</td>
      <td>${esc(deptName(x.d.dept))}</td>
      <td class="num warn">${x.out}</td>
    </tr>`).join('');

  // Latest movements across both registers, merged into one timeline.
  const feed = [
    ...(inv.armonLog || []).slice(0, 12).map((e) => ({
      t: e.t, tone: e.action === 'add' ? 'ok' : 'bad',
      txt: `${e.action === 'add' ? 'נכנס לארמון' : 'יצא מהארמון'}: ${e.name} (${e.serial})${e.owner ? ` — ${e.owner}` : ''}${e.dest ? ` → ${nameOf(ARM_DESTS, e.dest)}` : ''}`,
    })),
    ...(inv.ammoLog || []).slice(0, 12).map((e) => ({
      t: e.t, tone: e.action === 'add' ? 'ok' : 'bad',
      txt: `${e.action === 'add' ? 'נוספה תחמושת' : 'הונפקה תחמושת'}: ${e.name} ×${e.qty}${e.who ? ` — ${e.who}` : ''}`,
    })),
  ].sort((a, b) => b.t - a.t).slice(0, 10);

  const feedRows = feed.map((e) => `
    <li class="feed-row">
      <span class="feed-dot is-${e.tone}" aria-hidden="true"></span>
      <span class="feed-txt">${esc(e.txt)}</span>
      <span class="feed-t num">${esc(fmtDate(e.t))}</span>
    </li>`).join('');

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
    const armedN = recs.filter((x) => x.data.weapon).length;
    const badLic = licRows.filter((l) => l.dept === dp.name && l.st !== 'valid' && l.st !== 'soon').length;
    return { ...dp, n: recs.length, t, r, out: t - r, pct: pct(r, t), armedN, badLic };
  }).filter((d) => d.n);

  const deptTable = deptRows
    .map(
      (d) => `<tr>
        <td>${esc(d.name)}</td>
        <td class="num">${d.n}</td>
        <td class="num">${d.t}</td>
        <td class="num">${d.r}</td>
        <td class="num ${d.out > 0 ? 'warn' : 'ok'}">${d.out}</td>
        <td class="num">${d.armedN}</td>
        <td class="num ${d.badLic ? 'bad' : 'ok'}">${d.badLic || '—'}</td>
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

  const counted = inv.countedAt || {};
  const stamp = (ms) => (ms ? fmtDate(ms) : 'טרם נספר');

  return `
    <section class="panel${actions.length ? ' alert' : ''}">
      <h2 class="panel-title">דורש טיפול${actions.length ? ` <span class="pill bad num">${actions.length}</span>` : ''}</h2>
      <p class="panel-sub">כל מה שממתין לך כרגע, לפי דחיפות. לחיצה על שורה פותחת את הדף שמטפל בה.</p>
      ${actions.length
        ? `<div class="todos">${actionRows}</div>`
        : '<p class="empty">אין משימות פתוחות — הכול מטופל.</p>'}
    </section>

    <section class="panel">
      <h2 class="panel-title">ציוד אישי</h2>
      <p class="panel-sub">מחושב מרשומות מאושרות בלבד. רשומות שממתינות לאישור אינן נספרות.</p>
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
      <h2 class="panel-title">ארמון, תחמושת ורכבים</h2>
      <p class="panel-sub">מצב הרישומים הלוגיסטיים שמנוהלים בדפים הייעודיים.</p>
      <div class="kpis">${logistics}</div>
      <p class="field-hint mb0">
        ספירת צל״ם אחרונה: <strong>${esc(stamp(counted.tzelem))}</strong> ·
        ספירת ארמון אחרונה: <strong>${esc(stamp(counted.armon))}</strong> ·
        עדכון אחרון של המלאי: <strong>${esc(inv.updatedAt ? fmtDate(inv.updatedAt) : 'לא נשמר עדיין')}</strong>
      </p>
    </section>

    ${topHolders.length
      ? `<section class="panel">
           <h2 class="panel-title">מי מחזיק הכי הרבה</h2>
           <p class="panel-sub">חמשת החיילים עם הכי הרבה פריטים שטרם הוחזרו — מכאן מתחילים כשצריך לסגור חשבון.</p>
           <div class="tbl-scroll">
             <table class="tbl">
               <thead><tr><th>שם</th><th class="num">מ״א</th><th>מחלקה</th><th class="num">פריטים בחוץ</th></tr></thead>
               <tbody>${holderRows}</tbody>
             </table>
           </div>
         </section>`
      : ''}

    ${feed.length
      ? `<section class="panel">
           <h2 class="panel-title">תנועות אחרונות</h2>
           <p class="panel-sub">עשר הפעולות האחרונות בארמון ובתחמושת. היומן המלא נמצא בדפים עצמם.</p>
           <ul class="feed">${feedRows}</ul>
         </section>`
      : ''}

    <section class="panel">
      <h2 class="panel-title">פילוח לפי מחלקה</h2>
      <p class="panel-sub">כמה פריטים הוחתמו בכל מחלקה, כמה הוחזרו, כמה עדיין בחוץ, כמה נשקים משויכים וכמה רישיונות אינם בתוקף.</p>
      ${deptRows.length
        ? `<div class="tbl-scroll">
             <table class="tbl">
               <thead><tr>
                 <th>מחלקה</th><th class="num">חיילים</th><th class="num">הוחתם</th>
                 <th class="num">הוחזר</th><th class="num">בחוץ</th>
                 <th class="num">נשקים</th><th class="num">רישיון לא תקף</th><th>% הוחזר</th>
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

// Deposits a soldier filed from #deposit. They are not in the register until
// the armoury NCO approves them here — approval is what files the weapon.
function depositsPanel() {
  const all = depositReports();
  const q = S.depQ.trim().toLowerCase();
  const byStatus = all.filter((r) =>
    S.depFilter === 'all' ? true : S.depFilter === 'done' ? r.status === 'done' : r.status !== 'done'
  );
  const vis = byStatus.filter((r) => {
    if (!q) return true;
    const d = r.data;
    return (
      (d.name || '').toLowerCase().includes(q) ||
      (d.pn || '').includes(q) ||
      (d.phone || '').includes(q) ||
      (d.weapon || '').toLowerCase().includes(q) ||
      (d.amral || '').toLowerCase().includes(q) ||
      (d.scope || '').toLowerCase().includes(q)
    );
  });
  const p = paged('deps', vis);

  const filters = [['open', 'ממתין לאישור'], ['done', 'אושר'], ['all', 'הכל']]
    .map(([id, label]) =>
      `<button class="filter" aria-pressed="${S.depFilter === id}" data-act="dep-filter" data-f="${id}">${label}</button>`)
    .join('');

  const rows = p.slice.map((r) => {
    const d = r.data;
    const done = r.status === 'done';
    return `<tr>
      <td class="num">${esc(fmtDate(d.createdAt))}</td>
      <td>${esc(d.name)}</td>
      <td class="num">${esc(d.pn)}</td>
      <td class="num">
        ${esc(S.revealed.has(r.id) ? d.phone : maskPhone(d.phone))}
        <button class="linkbtn" data-act="rep-reveal" data-id="${esc(r.id)}">${S.revealed.has(r.id) ? 'הסתרה' : 'הצגה'}</button>
      </td>
      <td class="num wpn">${esc(d.weapon)}</td>
      <td class="num">${d.amral ? esc(d.amral) : '<span class="dim">·</span>'}</td>
      <td class="num">${d.scope ? esc(d.scope) : '<span class="dim">·</span>'}</td>
      <td><span class="state ${done ? 'done' : 'wait'}">${done ? 'אושר ונקלט' : 'ממתין'}</span></td>
      <td class="nowrap">
        ${done
          ? ''
          : `<button class="btn primary small" data-act="dep-approve" data-id="${esc(r.id)}">אישור וקליטה</button>`}
        <button class="btn danger small" data-act="rep-del" data-id="${esc(r.id)}">מחיקה</button>
      </td>
    </tr>`;
  }).join('');

  const waiting = openDeposits();
  return `
    <section class="panel${waiting ? ' alert' : ''}">
      <h2 class="panel-title">אפסון נשק — ממתין לאישור ${waiting ? `<span class="pill bad num">${waiting}</span>` : ''}</h2>
      <p class="panel-sub">בקשות אפסון ששלחו חיילים דרך <span class="code-inline">#deposit</span>. הנשק נכנס לרישום הארמון רק אחרי אישור כאן. האישור קולט גם את האמר״ל והכוונת אם נמסרו.</p>
      ${all.length > 4
        ? plainSearch('dep-search', 'dep-qclear', S.depQ,
                      'חיפוש לפי שם, מ״א, טלפון או מספר נשק', all.length, vis.length)
        : ''}
      <div class="filters">${filters}</div>
      ${vis.length
        ? `<div class="tbl-scroll">
             <table class="tbl">
               <thead><tr>
                 <th class="num">נשלח</th><th>שם החייל</th><th class="num">מ״א</th><th class="num">טלפון</th>
                 <th class="num">מס׳ נשק</th><th class="num">מק״ט אמר״ל</th><th class="num">מק״ט כוונת</th>
                 <th>סטטוס</th><th></th>
               </tr></thead>
               <tbody>${rows}</tbody>
             </table>
           </div>
           ${pager('deps', p)}`
        : `<p class="empty">${all.length ? 'אין בקשה שתואמת את החיפוש והסינון.' : 'אין בקשות אפסון.'}</p>`}
      ${all.length ? reportButtons('deposits') : ''}
    </section>`;
}

// Approval is the moment the weapon becomes the armoury's responsibility, so it
// writes the register and the log together, then closes the request.
const depApprove = (id) =>
  withBusy(async () => {
    const rec = S.reports.find((r) => r.id === id);
    if (!rec || !isDeposit(rec) || rec.status === 'done') return;
    if (!S.inv) { toast('נתוני המלאי עדיין נטענים', true); return; }
    const d = rec.data;
    const dup = (S.inv.armon || []).find(
      (x) => x.kind === 'weapon' && x.serial.toLowerCase() === d.weapon.toLowerCase()
    );
    if (dup) { toast(`מספר נשק ${d.weapon} כבר רשום בארמון על שם ${dup.owner}`, true); return; }
    const extra = [d.amral && `אמר״ל ${d.amral}`, d.scope && `כוונת ${d.scope}`].filter(Boolean).join(', ');
    if (!window.confirm(
      `לאשר אפסון של ${d.name} (מ״א ${d.pn})?\nנשק ${d.weapon}${extra ? `\nובנוסף: ${extra}` : ''}\n\nהפריטים ייקלטו לארמון.`
    )) return;

    const prevArmon = S.inv.armon || [];
    const prevLog = S.inv.armonLog || [];
    const now = Date.now();
    const note = `אפסון עצמי · מ״א ${d.pn}`;
    const added = [];
    const stage = (kind, name, serial) => {
      added.push({ id: rndId(), kind, name, serial, owner: d.name, loc: 'armon', note, addedAt: now });
    };
    stage('weapon', 'נשק אישי', d.weapon);
    if (d.amral) stage('amral', 'אמר״ל', d.amral);
    if (d.scope) stage('dscope', 'כוונת יום', d.scope);

    S.inv.armon = [...prevArmon, ...added];
    S.inv.armonLog = [
      ...added.map((x) => ({
        t: now, action: 'add', kind: x.kind, name: x.name,
        serial: x.serial, owner: x.owner, dest: '', note,
      })),
      ...prevLog,
    ].slice(0, 5000);

    try {
      await saveInv();
    } catch (e) {
      S.inv.armon = prevArmon;                 // register untouched if the save failed
      S.inv.armonLog = prevLog;
      renderConsole();
      throw e;
    }
    const prevStatus = rec.status;
    rec.status = 'done';
    renderConsole();
    try {
      await api(`/admin/reports/${id}`, { method: 'PUT', body: { status: 'done' } });
    } catch (e) {
      rec.status = prevStatus;                 // the items are filed; only the flag failed
      renderConsole();
      toast('הפריטים נקלטו אך סימון הבקשה נכשל — רעננו ונסו שוב', true);
      throw e;
    }
    toast(`אפסון אושר — ${added.length} פריטים נקלטו לארמון`);
  });

// `where` splits the register into what is physically on the shelf and what has
// gone out. The true index is carried through so edits still target the right
// entry after filtering.
function armonVisible(where) {
  const rows = (S.inv && S.inv.armon) || [];
  const q = (S.regQ.armon || '').trim().toLowerCase();
  return rows
    .map((x, i) => ({ x, i }))
    .filter(({ x }) => (where === 'here' ? x.loc === 'armon' : x.loc !== 'armon'))
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
  const vis = armonVisible('here');
  const p = paged('armon', vis);
  const visOut = armonVisible('out');
  const pOut = paged('armonOut', visOut);
  const here = all.filter((x) => x.loc === 'armon');
  const out = all.filter((x) => x.loc !== 'armon');
  const byKind = ARM_KINDS.map((k) => ({
    ...k,
    here: here.filter((x) => x.kind === k.id).length,
    out: out.filter((x) => x.kind === k.id).length,
  }));
  const noMission = all.filter((x) => x.loc === 'mission' && !x.mission).length;
  const unusable = all.filter((x) => ARM_BAD_LOCS.has(x.loc));

  const kindChips = [['all', 'הכל'], ...ARM_KINDS.map((k) => [k.id, k.name])]
    .map(([id, label]) =>
      `<button class="filter" aria-pressed="${S.armKind === id}" data-act="arm-kind" data-k="${id}">${esc(label)}</button>`)
    .join('');

  const armRow = ({ x, i }) => `
    <tr>
      <td>${esc(nameOf(ARM_KINDS, x.kind))}</td>
      <td>${esc(x.name)}</td>
      <td class="num wpn">${esc(x.serial)}</td>
      <td>${esc(x.owner)}</td>
      <td>
        <select class="input mini select-mini" data-act="arm-loc" data-i="${i}" aria-label="מיקום">
          ${kindLocs(x.kind).map((l) => `<option value="${l.id}"${x.loc === l.id ? ' selected' : ''}>${esc(l.name)}</option>`).join('')}
        </select>
        ${x.loc === 'mission'
          ? `<input class="input mini mt-xs" type="text" maxlength="60" value="${esc(x.mission)}"
                    data-act="arm-mission" data-i="${i}" aria-label="שם המשימה" placeholder="שם המשימה">`
          : ''}
      </td>
      <td class="num">${x.addedAt ? esc(fmtDay(new Date(x.addedAt).toISOString().slice(0, 10))) : '—'}</td>
      <td><button class="btn danger small" data-act="arm-remove" data-i="${i}">הסרה</button></td>
    </tr>`;
  const rows = p.slice.map(armRow).join('');
  const rowsOut = pOut.slice.map(armRow).join('');

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
    ${depositsPanel()}

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
            <span class="field-label">מספר סידורי / מק״ט <span class="req">*</span></span>
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
      <h2 class="panel-title">מלאי הארמון <span class="pill ok num">${here.length}</span></h2>
      <p class="panel-sub">רק מה שנמצא פיזית בארמון עכשיו. ברגע שמסמנים פריט "אצל חייל" או "במשימה" הוא יורד מהרשימה הזו ועובר לטבלה שמתחת. המיקומים האפשריים תלויים בסוג הפריט — רק צל״ם יכול לצאת למשימה, ואז חובה לרשום איזו. שינוי מיקום נשמר עם "שמירת השינויים".</p>
      <div class="kpis">
        ${kpi(here.length, 'נמצאים בארמון', 'ok', `${all.length} רשומים · ${out.length} בחוץ`)}
        ${byKind.map((k) => kpi(k.here, k.name, k.out ? 'warn' : null, k.out ? `${k.out} בחוץ` : 'הכול בארמון')).join('')}
      </div>
      ${noMission
        ? `<div class="callout risk"><p class="mb0"><strong class="num">${noMission}</strong> פריטים מסומנים "במשימה" בלי שם משימה — מלאו את שם המשימה בשורה.</p></div>`
        : ''}
      ${unusable.length
        ? `<div class="callout risk"><p class="mb0"><strong class="num">${unusable.length}</strong> פריטים אבודים או מושבתים: ${unusable.slice(0, 6).map((x) => `${esc(x.name)} (${esc(x.serial)}) — ${esc(nameOf(ARM_LOCS, x.loc))}`).join(' · ')}${unusable.length > 6 ? ' …' : ''}</p></div>`
        : ''}
      ${all.length > 4
        ? plainSearch('arm-search', 'arm-qclear', S.regQ.armon || '',
                      'חיפוש לפי שם, מספר סידורי או בעלים', all.length, vis.length + visOut.length)
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
           ${pager('armon', p)}`
        : `<p class="empty">${here.length ? 'אין פריט בארמון שתואם את החיפוש.' : all.length ? 'אין פריטים בארמון — כולם בחוץ.' : 'הארמון ריק. הוסיפו פריט למעלה.'}</p>`}
      <div class="rec-actions mt">
        <button class="btn ghost" data-act="rep-csv" data-r="armon">ייצוא ל-CSV</button>
        <button class="btn ghost" data-act="rep-pdf" data-r="armon">הפקת PDF</button>
        <button class="btn primary" data-act="inv-save">שמירת השינויים</button>
      </div>
    </section>

    ${out.length ? `
    <section class="panel">
      <h2 class="panel-title">פריטים שאינם בארמון <span class="pill bad num">${out.length}</span></h2>
      <p class="panel-sub">פריטים שיצאו מהארמון ורשומים על מישהו. הם אינם נספרים במלאי הארמון, אך נשארים ברישום. החזרת המיקום ל"ארמון" מחזירה אותם לרשימה למעלה.</p>
      ${visOut.length
        ? `<div class="tbl-scroll">
             <table class="tbl">
               <thead><tr>
                 <th>סוג</th><th>פריט</th><th class="num">מס׳ סידורי</th><th>אצל מי</th>
                 <th>מיקום</th><th class="num">נוסף</th><th></th>
               </tr></thead>
               <tbody>${rowsOut}</tbody>
             </table>
           </div>
           ${pager('armonOut', pOut)}
           <div class="rec-actions mt">
             <button class="btn primary" data-act="inv-save">שמירת השינויים</button>
           </div>`
        : '<p class="empty">אין פריט בחוץ שתואם את החיפוש.</p>'}
    </section>` : ''}

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
           ${reportButtons('armonLog')}`
        : '<p class="empty">טרם בוצעו פעולות.</p>'}
    </section>`;
}

/* ── Tzelem report ─────────────────────────────────────────────────── */

// The count is of what physically sits in the armoury, so weapons appear only
// while they are there. אמר״ל and צל״ם are tracked wherever they are, because
// the report is what proves they are accounted for at all.
function tzelemScope() {
  return ((S.inv && S.inv.armon) || [])
    .filter((x) => !ARM_BAD_LOCS.has(x.loc))          // written off or missing is not stock
    .filter((x) => x.kind !== 'weapon' || x.loc === 'armon');
}

function renderTzelemTab() {
  const all = tzelemScope();
  const q = (S.regQ.tzelem || '').trim().toLowerCase();
  const vis = all.filter(
    (x) =>
      !q ||
      (x.name || '').toLowerCase().includes(q) ||
      (x.serial || '').toLowerCase().includes(q) ||
      (x.owner || '').toLowerCase().includes(q)
  );
  const byLoc = ARM_LOCS.map((l) => ({ ...l, n: all.filter((x) => x.loc === l.id).length }));
  const held = ((S.inv && S.inv.armon) || []).filter((x) => x.kind === 'weapon' && x.loc !== 'armon').length;

  const rows = vis.map((x) => `
    <tr>
      <td>${esc(nameOf(ARM_KINDS, x.kind))}</td>
      <td>${esc(x.name)}</td>
      <td class="num wpn">${esc(x.serial)}</td>
      <td>${esc(x.owner)}</td>
      <td class="${x.loc === 'armon' ? 'ok' : 'warn'}">
        ${esc(nameOf(ARM_LOCS, x.loc))}
        ${x.loc === 'mission'
          ? `<span class="lg-sub">${x.mission ? esc(x.mission) : '<span class="bad">משימה ללא שם</span>'}</span>`
          : ''}
      </td>
    </tr>`).join('');

  // A מיקום of 'mission' with no mission named is an item nobody can go and find.
  const unnamed = all.filter((x) => x.loc === 'mission' && !x.mission).length;

  return `
    <section class="panel">
      <h2 class="panel-title">דו״ח צלם</h2>
      <p class="panel-sub"><strong>נשקים</strong> מוצגים רק כשהם נמצאים בארמון. <strong>אמר״ל וצל״ם</strong> מוצגים בכל המצבים, כולל אצל חייל. המיקום נקבע בלשונית ארמון.</p>
      <div class="kpis">
        ${kpi(all.length, 'סה״כ בדו״ח')}
        ${kpi(all.filter((x) => x.kind === 'weapon').length, 'נשקים בארמון', 'ok')}
        ${kpi(all.filter((x) => x.kind === 'amral').length, 'אמר״ל')}
        ${kpi(all.filter((x) => x.kind === 'tzelem').length, 'צל״ם')}
        ${byLoc.map((l) => kpi(l.n, l.name, l.id === 'armon' ? 'ok' : 'warn')).join('')}
      </div>
      ${held
        ? `<div class="callout"><p class="mb0"><strong class="num">${held}</strong> נשקים אינם בארמון ולכן אינם בדו״ח. הם מופיעים בלשונית ארמון.</p></div>`
        : ''}
      ${unnamed
        ? `<div class="callout risk"><p class="mb0"><strong class="num">${unnamed}</strong> פריטי צל״ם מסומנים "במשימה" בלי שם משימה — השלימו בלשונית ארמון.</p></div>`
        : ''}
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
             <button class="btn primary" data-act="rep-pdf" data-r="tzelem">הפקת PDF</button>
             <button class="btn wa ghost-wa" data-act="tz-wa">שליחת סיכום בוואטסאפ</button>
             <button class="btn ghost" data-act="rep-csv" data-r="tzelem">ייצוא ל-CSV</button>
           </div>
           <p class="field-hint mt center">"הפקת PDF" פותחת את חלון ההדפסה — בחרו <strong>שמירה כ-PDF</strong>. וואטסאפ מקבל טקסט בלבד, ולכן הכפתור שולח סיכום ומצרפים את ה-PDF ידנית.</p>`
        : `<p class="empty">${all.length ? 'אין פריט שתואם את החיפוש.' : 'אין פריטים להצגה בדו״ח.'}</p>`}
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
           ${reportButtons('ammo')}`
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
           ${reportButtons('ammoLog')}`
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
      <td><input class="input mini num" type="text" maxlength="12" value="${esc(x.code)}"
                 data-act="veh-code" data-i="${i}" aria-label="קוד קודן" placeholder="קודן"></td>
      <td><input class="input mini num" type="text" maxlength="12" value="${esc(x.fuelCode)}"
                 data-act="veh-fuelcode" data-i="${i}" aria-label="קוד דלקן" placeholder="דלקן"></td>
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
                 <th class="num">קוד קודן</th><th class="num">קוד דלקן</th>
                 ${VEH_KIT.map((k) => `<th class="num lg-col"><span class="lg-h">${esc(k.name)}</span></th>`).join('')}
                 <th>סטטוס</th><th></th>
               </tr></thead>
               <tbody>${rows}</tbody>
             </table>
           </div>`
        : `<p class="empty">${all.length ? 'אין רכב שתואם את החיפוש.' : 'אין רכבים. הוסיפו את הראשון למטה.'}</p>`}
      <div class="rec-actions mt">
        <button class="btn ghost" data-act="veh-add">+ הוספת רכב</button>
        <button class="btn ghost" data-act="rep-csv" data-r="vehicles">ייצוא ל-CSV</button>
        <button class="btn ghost" data-act="rep-pdf" data-r="vehicles">הפקת PDF</button>
        <button class="btn primary" data-act="inv-save">שמירת השינויים</button>
      </div>
    </section>

    ${fuelPanel()}`;
}

/* ── Fuel cards ────────────────────────────────────────────────────── */

// Receipts live in the docs table, not the vault: the vault is one blob with a
// size cap, and a handful of photos would burst it.
function fuelPanel() {
  const all = (S.inv && S.inv.fuel) || [];
  const q = (S.regQ.fuel || '').trim().toLowerCase();
  const vis = all
    .map((x, i) => ({ x, i }))
    .filter(({ x }) =>
      !q ||
      (x.no || '').toLowerCase().includes(q) ||
      (x.holder || '').toLowerCase().includes(q) ||
      x.uses.some((u) => (u.who || '').toLowerCase().includes(q)) ||
      nameOf(FUEL_KINDS, x.kind).includes(q)
    );
  const p = paged('fuel', vis);
  const low = all.filter((x) => x.litres < FUEL_LOW).length;
  const credited = all.filter((x) => x.credited).length;

  const rows = p.slice.map(({ x, i }) => {
    const open = S.fuelOpen.has(x.id);
    const n = x.receipts.length;
    return `<tr${x.litres < FUEL_LOW ? ' class="row-short"' : ''}>
      <td>
        <select class="input mini select-mini" data-act="fuel-kind" data-i="${i}" aria-label="סוג כרטיס">
          ${FUEL_KINDS.map((k) => `<option value="${k.id}"${x.kind === k.id ? ' selected' : ''}>${esc(k.name)}</option>`).join('')}
        </select>
      </td>
      <td><input class="input mini num" type="text" maxlength="30" value="${esc(x.no)}"
                 data-act="fuel-no" data-i="${i}" aria-label="מספר כרטיס" placeholder="1234-5678"></td>
      <td>
        <input class="input mini" type="text" maxlength="60" value="${esc(x.holder)}"
               data-act="fuel-holder" data-i="${i}" aria-label="אצל מי הכרטיס" placeholder="שם החייל">
        <button class="linkbtn" data-act="fuel-office" data-i="${i}">${FUEL_OFFICE}</button>
      </td>
      <td><input class="input mini num" type="text" inputmode="numeric" maxlength="5" value="${x.litres}"
                 data-act="fuel-litres" data-i="${i}" aria-label="ליטרים שנותרו"></td>
      <td class="${x.litres < FUEL_LOW ? 'bad' : 'ok'}">${x.litres < FUEL_LOW ? '⚠ מלאי נמוך' : '✓ תקין'}</td>
      <td class="nowrap">
        <button class="btn ghost small" data-act="fuel-use" data-i="${i}">+ רישום שימוש</button>
        ${x.uses.length
          ? `<button class="linkbtn" data-act="fuel-open" data-id="${esc(x.id)}">${open ? 'סגירה' : `${x.uses.length} שימושים`}</button>`
          : '<span class="muted-txt">טרם נעשה שימוש</span>'}
      </td>
      <td class="nowrap">
        <label class="linkbtn">📷 צילום
          <input class="vis-hidden" type="file" accept="image/*" capture="environment" multiple
                 data-act="fuel-file" data-i="${i}"></label>
        <label class="linkbtn">🖼 גלריה
          <input class="vis-hidden" type="file" accept="image/*" multiple
                 data-act="fuel-file" data-i="${i}"></label>
        ${n
          ? `<button class="linkbtn" data-act="fuel-open" data-id="${esc(x.id)}">${open ? 'סגירה' : `${n} קבלות`}</button>
             <button class="linkbtn" data-act="fuel-dl-all" data-i="${i}">הורדת הכול</button>`
          : '<span class="muted-txt">אין קבלות</span>'}
      </td>
      <td class="nowrap">
        <button class="btn ${x.credited ? 'ghost' : 'primary'} small" data-act="fuel-credit" data-i="${i}">
          ${x.credited ? '✓ זוכה' : 'סימון זיכוי'}
        </button>
        ${x.credited ? `<span class="muted-txt">${esc(fmtDate(x.creditedAt))}</span>` : ''}
      </td>
      <td><button class="linkbtn danger-link" data-act="fuel-del" data-i="${i}" aria-label="מחיקת כרטיס">✕</button></td>
    </tr>
    ${open ? `<tr class="sub"><td colspan="9">${fuelDetail(x, i)}</td></tr>` : ''}`;
  }).join('');

  return `
    <section class="panel">
      <h2 class="panel-title">כרטיסי תדלוק</h2>
      <p class="panel-sub">מי מחזיק כל כרטיס, כמה נשאר בו, מי תדלק ומתי. רישום שימוש מוריד את הליטרים מהיתרה אוטומטית. אפשר לצרף כמה קבלות לכל כרטיס — כל צילום מוצפן ונשמר בנפרד מהטבלה. כרטיס מתחת ל-${FUEL_LOW} ליטר נצבע באדום.</p>
      <div class="kpis">
        ${kpi(all.length, 'כרטיסים')}
        ${FUEL_KINDS.map((k) => kpi(
          all.filter((x) => x.kind === k.id).reduce((s, x) => s + x.litres, 0),
          `ליטר ${k.name}`
        )).join('')}
        ${kpi(low, `מתחת ל-${FUEL_LOW} ליטר`, low ? 'bad' : 'ok')}
        ${kpi(credited, 'זוכו אצל קצין רכב', null, `${all.length - credited} טרם זוכו`)}
      </div>
      ${all.length > 4
        ? plainSearch('fuel-search', 'fuel-qclear', S.regQ.fuel || '',
                      'חיפוש לפי מספר כרטיס, מחזיק, משתמש או סוג דלק', all.length, vis.length)
        : ''}
      ${vis.length
        ? `<div class="tbl-scroll">
             <table class="tbl">
               <thead><tr>
                 <th>סוג כרטיס</th><th class="num">מספר כרטיס</th><th>אצל מי</th>
                 <th class="num">ליטרים שנותרו</th><th>סטטוס</th><th>שימושים</th>
                 <th>קבלות</th><th>זיכוי</th><th></th>
               </tr></thead>
               <tbody>${rows}</tbody>
             </table>
           </div>
           ${pager('fuel', p)}`
        : `<p class="empty">${all.length ? 'אין כרטיס שתואם את החיפוש.' : 'אין כרטיסי תדלוק. הוסיפו את הראשון למטה.'}</p>`}
      <div class="rec-actions mt">
        <button class="btn ghost" data-act="fuel-add">+ הוספת כרטיס</button>
        <button class="btn ghost" data-act="rep-csv" data-r="fuel">כרטיסים — CSV</button>
        <button class="btn ghost" data-act="rep-pdf" data-r="fuel">כרטיסים — PDF</button>
        <button class="btn ghost" data-act="rep-csv" data-r="fuelUses">יומן שימושים — CSV</button>
        <button class="btn ghost" data-act="rep-pdf" data-r="fuelUses">יומן שימושים — PDF</button>
        <button class="btn primary" data-act="inv-save">שמירת השינויים</button>
      </div>
    </section>`;
}

// The expanded row: who used the card, and the receipts. Thumbnails are fetched
// and decrypted one at a time, so opening a card with twenty receipts does not
// pull twenty images at once.
function fuelDetail(card, i) {
  const uses = card.uses.length
    ? `<table class="tbl compact">
         <thead><tr><th class="num">תאריך</th><th>מי השתמש</th><th class="num">ליטרים</th><th class="num">רכב</th><th></th></tr></thead>
         <tbody>${card.uses.map((u, n) => `
           <tr>
             <td class="num">${esc(fmtDate(u.t))}</td>
             <td>${esc(u.who)}</td>
             <td class="num">${u.litres}</td>
             <td class="num">${u.plate ? esc(u.plate) : '—'}</td>
             <td><button class="linkbtn danger-link" data-act="fuel-use-del" data-i="${i}" data-n="${n}">✕</button></td>
           </tr>`).join('')}</tbody>
       </table>`
    : '<p class="empty mb0">טרם נרשם שימוש בכרטיס.</p>';

  const rcpts = card.receipts.length
    ? `<div class="rcpts">
         ${card.receipts.map((r, n) => {
           const img = S.docs[`${r.id}:fuel`];
           return `
             <figure class="rcpt">
               ${img
                 ? `<img class="rcpt-img" src="${img}" alt="קבלה ${n + 1}">`
                 : `<button class="rcpt-ph" data-act="fuel-doc" data-r="${esc(r.id)}">
                      <span>קבלה ${n + 1}</span><span class="muted-txt">הצגה</span>
                    </button>`}
               <figcaption>
                 <span class="num">${esc(fmtDate(r.at))}</span>
                 <button class="linkbtn" data-act="fuel-dl-one" data-i="${i}" data-r="${esc(r.id)}">הורדה</button>
                 <button class="linkbtn danger-link" data-act="fuel-doc-del" data-i="${i}" data-r="${esc(r.id)}">מחיקה</button>
               </figcaption>
             </figure>`;
         }).join('')}
       </div>`
    : '';

  const used = card.uses.reduce((s, u) => s + u.litres, 0);
  return `
    <div class="fuel-detail">
      <h3 class="field-label">יומן שימושים — סה״כ <span class="num">${used}</span> ליטר</h3>
      ${uses}
      ${rcpts ? `<h3 class="field-label mt">קבלות (${card.receipts.length})</h3>${rcpts}` : ''}
    </div>`;
}

/* ── Fuel card actions ─────────────────────────────────────────────── */

// Deleting a card drops every receipt with it, so no orphan image is left
// sitting in the docs table with nothing pointing at it.
const fuelDelete = (i) =>
  withBusy(async () => {
    const card = (S.inv.fuel || [])[i];
    if (!card) return;
    const n = card.receipts.length;
    if (!window.confirm(`למחוק את כרטיס ${card.no || 'התדלוק'}${n ? ` ואת ${n} הקבלות המצורפות` : ''}?`)) return;
    for (const r of card.receipts) {
      await api(`/admin/docs/${r.id}/fuel`, { method: 'DELETE' }).catch(() => {});
      delete S.docs[`${r.id}:fuel`];
    }
    S.inv.fuel.splice(i, 1);
    await saveInv();
    renderConsole();
    toast('הכרטיס נמחק');
  });

// Accepts a whole selection at once — a month of receipts in one pick.
const fuelFile = (i, input) =>
  withBusy(async () => {
    const card = (S.inv.fuel || [])[i];
    const files = [...(input.files || [])].filter((f) => /^image\//.test(f.type));
    const rejected = (input.files || []).length - files.length;
    input.value = '';                       // let the same files be picked again
    if (!card) return;
    if (!files.length) { toast('יש לבחור קובצי תמונה', true); return; }
    if (card.receipts.length + files.length > 60) {
      toast('מקסימום 60 קבלות לכרטיס', true);
      return;
    }
    // Images go up first because they are the slow part, but nothing points at
    // them until the vault names them. If that save fails they are unreachable
    // rows nobody will ever find, so they are removed again.
    const uploaded = [];
    const before = card.receipts.slice();
    let done = 0;
    for (const file of files) {
      toast(`מעבד קבלה ${done + 1} מתוך ${files.length}…`);
      const { bytes } = await compressImage(file);
      const id = hex(crypto.getRandomValues(new Uint8Array(16)));
      await api(`/admin/docs/${id}/fuel`, { method: 'PUT', body: await sealBytes(S.pubKey, bytes) });
      uploaded.push(id);
      card.receipts.push({ id, at: Date.now() });
      done++;
    }
    try {
      await saveInv();
    } catch (e) {
      card.receipts = before;
      for (const id of uploaded) {
        await api(`/admin/docs/${id}/fuel`, { method: 'DELETE' }).catch(() => {});
      }
      renderConsole();
      throw e;
    }
    S.fuelOpen.add(card.id);
    renderConsole();
    toast(`${done} קבלות נשמרו${rejected ? ` · ${rejected} קבצים שאינם תמונה דולגו` : ''}`);
  });

// Pulls and decrypts one receipt. Cached afterwards, so re-opening is free.
async function fuelDocLoad(docId) {
  const key = `${docId}:fuel`;
  if (S.docs[key]) return S.docs[key];
  const { docs } = await api(`/admin/docs/${docId}`);
  const row = (docs || []).find((x) => x.kind === 'fuel');
  if (!row) throw new Error('הקבלה לא נמצאה');
  const bytes = await openBytes(S.priv, row);
  let bin = '';
  for (const b of new Uint8Array(bytes)) bin += String.fromCharCode(b);
  S.docs[key] = `data:image/jpeg;base64,${btoa(bin)}`;
  return S.docs[key];
}

const fuelDocShow = (docId) =>
  withBusy(async () => {
    await fuelDocLoad(docId);
    renderConsole();
  });

const fuelDocDelete = (i, docId) =>
  withBusy(async () => {
    const card = (S.inv.fuel || [])[i];
    if (!card) return;
    if (!window.confirm('למחוק את הקבלה? הפעולה אינה הפיכה.')) return;
    await api(`/admin/docs/${docId}/fuel`, { method: 'DELETE' });
    delete S.docs[`${docId}:fuel`];
    card.receipts = card.receipts.filter((r) => r.id !== docId);
    await saveInv();
    renderConsole();
    toast('הקבלה נמחקה');
  });

function saveDataUrl(dataUrl, name) {
  const a = document.createElement('a');
  a.href = dataUrl;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
}

const fuelFileStem = (card) =>
  `קבלה-${nameOf(FUEL_KINDS, card.kind)}-${(card.no || 'ללא-מספר').replace(/[^\w֐-׿-]/g, '')}`;

const fuelDownloadOne = (i, docId) =>
  withBusy(async () => {
    const card = (S.inv.fuel || [])[i];
    if (!card) return;
    const n = card.receipts.findIndex((r) => r.id === docId) + 1;
    saveDataUrl(await fuelDocLoad(docId), `${fuelFileStem(card)}-${n}.jpg`);
  });

// One click, every receipt on the card. Browsers throttle a burst of downloads,
// so they go out spaced rather than all at once.
const fuelDownloadAll = (i) =>
  withBusy(async () => {
    const card = (S.inv.fuel || [])[i];
    if (!card || !card.receipts.length) { toast('אין קבלות להורדה', true); return; }
    const stem = fuelFileStem(card);
    for (let n = 0; n < card.receipts.length; n++) {
      toast(`מוריד קבלה ${n + 1} מתוך ${card.receipts.length}…`);
      saveDataUrl(await fuelDocLoad(card.receipts[n].id), `${stem}-${n + 1}.jpg`);
      await new Promise((r) => setTimeout(r, 350));
    }
    renderConsole();
    toast(`${card.receipts.length} קבלות הורדו`);
  });

// Who took the card out and how much they burned. Deducting the litres here is
// what keeps the remaining balance honest without a second manual edit.
function fuelUse(i) {
  const card = (S.inv.fuel || [])[i];
  if (!card) return;
  const who = window.prompt('מי השתמש בכרטיס? (שם מלא)', card.holder === FUEL_OFFICE ? '' : card.holder);
  if (who === null) return;
  if (who.trim().length < 2) { toast('נא למלא שם', true); return; }
  const raw = window.prompt('כמה ליטרים תודלקו?', '');
  if (raw === null) return;
  const litres = Math.max(0, Math.min(99999, parseInt(String(raw).replace(/\D/g, ''), 10) || 0));
  if (!litres) { toast('נא למלא כמות ליטרים', true); return; }
  const plate = (window.prompt('מספר רכב (רשות):', '') || '').trim().slice(0, 20);
  card.uses = [{ t: Date.now(), who: who.trim().slice(0, 60), litres, plate }, ...card.uses].slice(0, 300);
  card.litres = Math.max(0, card.litres - litres);
  S.fuelOpen.add(card.id);
  invSave();
}

function fuelCredit(i) {
  const card = (S.inv.fuel || [])[i];
  if (!card) return;
  if (card.credited) {
    if (!window.confirm('לבטל את סימון הזיכוי?')) return;
    card.credited = false;
    card.creditedAt = 0;
  } else {
    if (!window.confirm(`לסמן שכרטיס ${card.no || 'זה'} זוכה אצל קצין רכב?`)) return;
    card.credited = true;
    card.creditedAt = Date.now();
  }
  invSave();
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
  // Weapon serials are unique. Accessories are logged by מק״ט — a catalogue
  // number shared by every unit of that model — so duplicates are expected there.
  if (kind === 'weapon') {
    const dup = (S.inv.armon || []).find(
      (x) => x.kind === 'weapon' && x.serial.toLowerCase() === serial.toLowerCase()
    );
    if (dup) return setFormErr(form, `מספר סידורי ${serial} כבר קיים בארמון (${dup.name})`);
  }
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

/* — Tzelem PDF + WhatsApp summary — */

function tzelemWa() {
  const rows = tzelemScope();
  if (!rows.length) { toast('אין פריטים לשליחה', true); return; }
  const counts = ARM_LOCS.map((l) => `${l.name}: ${rows.filter((x) => x.loc === l.id).length}`).join('\n');
  const offsite = rows.filter((x) => x.loc !== 'armon');
  const held = ((S.inv && S.inv.armon) || []).filter((x) => x.kind === 'weapon' && x.loc !== 'armon').length;
  const msg =
    `*דו״ח צלם — מסייעת 951*\n${fmtDate(Date.now())}\n\n` +
    `סה״כ פריטים בדו״ח: ${rows.length}\n${counts}\n` +
    (held ? `\n(${held} נשקים אינם בארמון ואינם נכללים)\n` : '') +
    (offsite.length
      ? `\n*לא בארמון:*\n${offsite.slice(0, 40).map((x) => `• ${x.name} (${x.serial}) — ${nameOf(ARM_LOCS, x.loc)}${x.loc === 'mission' ? ` (${x.mission || 'ללא שם'})` : ''}, ${x.owner}`).join('\n')}`
      : '\nכל הפריטים בארמון.');
  window.open(`https://wa.me/?text=${encodeURIComponent(msg)}`, '_blank', 'noopener');
}

/* ── Shortage reports (admin) ──────────────────────────────────────── */

// Deposits and building faults ride the same pipe as shortage reports; each
// tab sees only its own kind, and damaged rows stay with the shortage tab so
// they are never silently dropped.
const isKind = (r, k) => !r.damaged && !!r.data && r.data.kind === k;
const isDeposit = (r) => isKind(r, 'deposit');
const isFault = (r) => isKind(r, 'fault');
const shortageReports = () => S.reports.filter((r) => !isDeposit(r) && !isFault(r));
const depositReports = () => S.reports.filter(isDeposit);
const faultReports = () => S.reports.filter(isFault);

// 'open' and 'partial' both still need the admin's attention.
const openReports = () => shortageReports().filter((r) => r.status !== 'done' && !r.damaged).length;

// Deposits awaiting the armoury NCO's approval.
const openDeposits = () => depositReports().filter((r) => r.status !== 'done').length;

// Faults not yet closed — 'partial' means handed to the works team.
const openFaults = () => faultReports().filter((r) => r.status !== 'done').length;

// What is physically in the cupboard right now. An item logged as being with a
// soldier or out on a mission is off the armoury's shelf count — it is still
// registered, but counting it as present is how a shortage goes unnoticed.
const armonHere = () => ((S.inv && S.inv.armon) || []).filter((x) => x.loc === 'armon');
const armonCount = () => armonHere().length;

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

  const byStatus = shortageReports().filter((r) => {
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
      <p class="panel-sub">בקשות שחיילים שלחו בעצמם דרך <span class="code-inline">#report</span>. לא קשור למאגר הרישומים. סמנו ✓ אחרי הטיפול.</p>
      ${plainSearch('rep-search', 'rep-qclear', S.repQ, 'חיפוש לפי שם או תוכן הבקשה', byStatus.length, visible.length)}
      <div class="filters">${filters}</div>
      ${cards || '<p class="empty">אין בקשות שתואמות את החיפוש והסינון.</p>'}
      ${pager('reports', pgReports)}
    </section>`;
}

/* ── Building faults (admin) ───────────────────────────────────────── */

// A fault's life is: reported → handed to the works team → fixed. That maps
// onto the same three states the reports pipe already persists.
const FLT_LABEL = { open: 'נפתחה', partial: 'הועבר לטיפול', done: '✓ טופל' };

function renderFaultsTab() {
  const all = faultReports();
  const filters = [['open', 'פתוחות'], ['partial', 'בטיפול'], ['done', 'טופלו'], ['all', 'הכל']]
    .map(([id, label]) =>
      `<button class="filter" aria-pressed="${S.fltFilter === id}" data-act="flt-filter" data-f="${id}">${label}</button>`)
    .join('');

  const byStatus = all.filter((r) => {
    if (S.fltFilter === 'all') return true;
    if (S.fltFilter === 'open') return r.status !== 'done';   // open + in progress
    return r.status === S.fltFilter;
  });
  const q = S.fltQ.trim().toLowerCase();
  const vis = byStatus.filter((r) =>
    !q ||
    (r.data.name || '').toLowerCase().includes(q) ||
    (r.data.phone || '').includes(q) ||
    (r.data.text || '').toLowerCase().includes(q)
  );
  const p = paged('faults', vis);

  const cards = p.slice.map((r) => {
    const d = r.data;
    const st = r.status === 'done' ? 'done' : r.status === 'partial' ? 'partial' : 'open';
    return `
      <article class="rec ${st === 'done' ? 'done' : st === 'partial' ? 'live' : 'wait'}">
        <header class="rec-head">
          <div>
            <div class="rec-name">${esc(d.name)}</div>
            <div class="rec-meta">דווח ${esc(fmtDate(d.createdAt))}</div>
          </div>
          <span class="state ${st === 'done' ? 'done' : st === 'partial' ? 'live' : 'wait'}">${FLT_LABEL[st]}</span>
        </header>
        <div class="rec-meta">טלפון:
          <span class="num">${esc(S.revealed.has(r.id) ? d.phone : maskPhone(d.phone))}</span>
          <button class="linkbtn" data-act="rep-reveal" data-id="${esc(r.id)}">${S.revealed.has(r.id) ? 'הסתרה' : 'הצגה'}</button>
        </div>
        <blockquote class="rep-text">${esc(d.text)}</blockquote>

        <fieldset class="rep-states">
          <legend class="field-label">סטטוס טיפול</legend>
          ${['open', 'partial', 'done'].map((v) => `
            <label class="rep-state ${st === v ? 'on' : ''}">
              <input type="radio" name="flt-${esc(r.id)}" data-act="flt-state"
                     data-id="${esc(r.id)}" data-st="${v}" ${st === v ? 'checked' : ''}>
              <span class="rep-tick" aria-hidden="true"></span>
              <span>${FLT_LABEL[v]}</span>
            </label>`).join('')}
        </fieldset>

        <div class="rec-actions">
          <a class="btn wa ghost-wa" href="https://wa.me/${waPhone(d.phone)}"
             target="_blank" rel="noopener noreferrer">וואטסאפ למדווח</a>
          <button class="btn danger" data-act="rep-del" data-id="${esc(r.id)}">מחיקה</button>
        </div>
      </article>`;
  }).join('');

  const waiting = openFaults();
  return `
    <section class="panel">
      <h2 class="panel-title">תקלות בינוי</h2>
      <p class="panel-sub">תקלות מבנה שדווחו דרך <span class="code-inline">#fault</span>. סמנו "הועבר לטיפול" כשהתקלה נמסרה לגורם המטפל, ו-✓ כשתוקנה.</p>
      <div class="kpis">
        ${kpi(all.length, 'סה״כ דיווחים')}
        ${kpi(all.filter((r) => r.status !== 'done' && r.status !== 'partial').length, 'פתוחות', waiting ? 'warn' : null)}
        ${kpi(all.filter((r) => r.status === 'partial').length, 'הועברו לטיפול')}
        ${kpi(all.filter((r) => r.status === 'done').length, 'טופלו', 'ok')}
      </div>
      ${all.length > 4
        ? plainSearch('flt-search', 'flt-qclear', S.fltQ,
                      'חיפוש לפי שם המדווח, טלפון או תוכן', all.length, vis.length)
        : ''}
      <div class="filters">${filters}</div>
      ${cards || '<p class="empty">אין תקלות שתואמות את החיפוש והסינון.</p>'}
      ${pager('faults', p)}
      ${all.length ? reportButtons('faults') : ''}
    </section>`;
}

const fltSetState = (id, next) =>
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
    toast(next === 'done' ? 'התקלה סומנה כטופלה'
      : next === 'partial' ? 'סומן כהועבר לטיפול'
      : 'הוחזר למצב פתוח');
  });

// The wrapped private key, saved to a file. Without the password it is inert,
// which is exactly why it can be kept somewhere else: it turns "we lost the
// laptop" from total loss into an inconvenience. It does NOT rescue a
// forgotten password — nothing can.
const exportRecoveryKey = () =>
  withBusy(async () => {
    if (!window.confirm(
      'הקובץ מכיל את המפתח הפרטי עטוף בסיסמה שלכם. בלי הסיסמה הוא חסר ערך — אבל שמרו אותו במקום מוגן ולא באותו מקום עם הסיסמה. להמשיך?'
    )) return;
    const cfg = await api('/config');
    const blob = new Blob([JSON.stringify({
      note: 'גיבוי מפתח שחזור — מסייעת 951. דורש את סיסמת המנהל כדי להיפתח.',
      exportedAt: new Date().toISOString(),
      username: S.me,
      pub: cfg.pub,
      idSalt: cfg.idSalt,
    }, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `tzayad-recovery-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 5000);
    toast('קובץ השחזור הורד');
  });

const loadTrash = () =>
  withBusy(async () => {
    const { records, reports, keepMs } = await api('/admin/trash');
    const open = async (rows, clean) => {
      const out = [];
      for (const row of rows) {
        try { out.push({ ...row, data: await openRecord(S.priv, row, clean), damaged: false }); }
        catch { out.push({ ...row, data: null, damaged: true }); }
      }
      return out;
    };
    S.trash = {
      records: await open(records, cleanRecord),
      reports: await open(reports, cleanReport),
      keepDays: Math.round(keepMs / 86400000),
    };
    renderConsole();
  });

const trashRestore = (kind, id) =>
  withBusy(async () => {
    await api(`/admin/trash/${kind}/${id}`, { method: 'POST', body: {} });
    await loadTrash();
    await adminRefreshQuiet();
    toast('הפריט שוחזר');
  });

const adminRefreshQuiet = async () => {
  const scopes = allowedScopes();
  if (scopes.has('records')) await loadRecords();
  if (scopes.has('reports')) await loadReports();
};

const loadAudit = () =>
  withBusy(async () => {
    const { audit } = await api('/admin/audit');
    S.audit = audit || [];
    renderConsole();
  });

const AUDIT_LABEL = {
  approve: 'אישור רשומה', update: 'עדכון רשומה', 'delete-record': 'מחיקת רשומה',
  'delete-report': 'מחיקת דיווח', 'restore-record': 'שחזור רשומה',
  'restore-report': 'שחזור דיווח', vault: 'שמירת מלאי', 'user-create': 'יצירת משתמש',
  'user-update': 'עדכון משתמש', 'user-delete': 'מחיקת משתמש',
};

function trashPanel() {
  const t = S.trash;
  return `
    <section class="panel">
      <h2 class="panel-title">סל מיחזור</h2>
      <p class="panel-sub">רשומות ודיווחים שנמחקו נשמרים ${t ? t.keepDays : 30} יום וניתנים לשחזור. אחרי כן הם נמחקים לצמיתות.</p>
      ${!t
        ? '<button class="btn ghost wide" data-act="trash-load">טעינת סל המיחזור</button>'
        : (t.records.length + t.reports.length)
          ? `<div class="tbl-scroll">
               <table class="tbl">
                 <thead><tr><th>סוג</th><th>פרטים</th><th class="num">נמחק</th><th></th></tr></thead>
                 <tbody>
                   ${t.records.map((r) => `<tr>
                     <td>רשומת חייל</td>
                     <td>${r.damaged ? '<span class="bad">פגום</span>' : esc(r.data.name) + ' · ' + esc(r.data.pn)}</td>
                     <td class="num">${esc(fmtDate(r.deleted_at))}</td>
                     <td><button class="btn ghost small" data-act="trash-restore" data-kind="record" data-id="${esc(r.rid)}">שחזור</button></td>
                   </tr>`).join('')}
                   ${t.reports.map((r) => `<tr>
                     <td>${r.damaged ? 'דיווח' : r.data.kind === 'deposit' ? 'אפסון נשק' : r.data.kind === 'fault' ? 'תקלת בינוי' : 'בקשת חוסר'}</td>
                     <td>${r.damaged ? '<span class="bad">פגום</span>' : esc(r.data.name)}</td>
                     <td class="num">${esc(fmtDate(r.deleted_at))}</td>
                     <td><button class="btn ghost small" data-act="trash-restore" data-kind="report" data-id="${esc(r.id)}">שחזור</button></td>
                   </tr>`).join('')}
                 </tbody>
               </table>
             </div>
             <button class="btn ghost wide mt" data-act="trash-load">רענון</button>`
          : '<p class="empty">הסל ריק.</p>'}
    </section>`;
}

function auditPanel() {
  return `
    <section class="panel">
      <h2 class="panel-title">יומן פעולות מנהלים</h2>
      <p class="panel-sub">מי עשה מה ומתי. היומן אינו מוצפן ולכן אינו מכיל שמות חיילים או פרטים אישיים — רק סוג הפעולה והמזהה.</p>
      ${!S.audit
        ? '<button class="btn ghost wide" data-act="audit-load">טעינת היומן</button>'
        : S.audit.length
          ? `<div class="tbl-scroll">
               <table class="tbl">
                 <thead><tr><th class="num">מתי</th><th>משתמש</th><th>פעולה</th><th class="num">מזהה</th><th>פרטים</th></tr></thead>
                 <tbody>${S.audit.map((e) => `<tr>
                   <td class="num">${esc(fmtDate(e.at))}</td>
                   <td>${esc(e.username || '—')}</td>
                   <td>${esc(AUDIT_LABEL[e.action] || e.action)}</td>
                   <td class="num">${esc((e.target || '').slice(0, 12))}</td>
                   <td>${esc(e.detail || '')}</td>
                 </tr>`).join('')}</tbody>
               </table>
             </div>
             <button class="btn ghost wide mt" data-act="audit-load">רענון</button>`
          : '<p class="empty">לא נרשמו פעולות.</p>'}
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
    ${usersPanel()}

    ${trashPanel()}

    ${auditPanel()}

    <section class="panel">
      <h2 class="panel-title">גיבוי מפתח שחזור</h2>
      <p class="panel-sub">קובץ קטן עם המפתח הציבורי ומזהי המערכת, לשמירה בנפרד מהמכשיר. בלי סיסמת המנהל הוא חסר ערך, ולכן אפשר לשמור אותו במקום אחר — אבל <strong>הוא אינו מחליף את הסיסמה</strong>: אם היא תאבד, אין שחזור.</p>
      <button class="btn ghost wide" data-act="key-export">הורדת קובץ שחזור</button>
    </section>

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
    if (!vault) { S.inv = emptyInv(); S.invVersion = 0; return; }
    S.invVersion = vault.updated_at || 0;   // what a later save will be checked against
    S.inv = await openRecord(S.priv, vault, cleanInv);
  } catch {
    S.inv = emptyInv();
    S.invVersion = 0;
    toast('לא ניתן לפענח את נתוני המלאי', true);
  }
}

// The vault is one blob shared by every admin. Sending the version it was
// loaded at lets the server refuse a save that would overwrite someone else's
// work, instead of silently discarding it.
async function saveInv() {
  S.inv.updatedAt = Date.now();
  const sealed = await seal(S.pubKey, S.inv);
  try {
    const res = await api('/admin/vault', {
      method: 'PUT',
      body: { ...sealed, baseVersion: S.invVersion },
    });
    S.invVersion = res.updatedAt || S.inv.updatedAt;
    vaultSizeWarn(sealed.ct.length);
  } catch (e) {
    if (e.status === 409) {
      throw new Error('המלאי עודכן על ידי מנהל אחר בזמן שערכתם. לחצו "רענון", בדקו מה השתנה ובצעו את השינוי שוב — לא דרסנו את העבודה שלו.');
    }
    throw e;
  }
}

// The vault has a hard ceiling at the server. Silence until the save simply
// fails is not a warning, so the headroom is reported as it shrinks.
const VAULT_MAX = 600000;
function vaultSizeWarn(len) {
  S.invBytes = len;
  const pct = Math.round((len / VAULT_MAX) * 100);
  if (pct >= 90) toast(`שימו לב: נפח המלאי ${pct}% מהמותר — פנו מקום בקרוב`, true);
  else if (pct >= 80) toast(`נפח המלאי ${pct}% מהמותר`, true);
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

// A one-shot permit fetched just before submitting. The server will not accept
// a record or a report without one, which stops a script posting straight at
// the API with the (necessarily public) encryption key.
async function getTicket() {
  const { ticket } = await api('/ticket', { method: 'GET' });
  return ticket;
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
    await api('/records', { body: { rid: S.rid, ticket: await getTicket(), ...sealed } });

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
  const username = (form.username ? form.username.value : '').trim().toLowerCase();
  if (!username) return setFormErr(form, 'נא להזין שם משתמש');
  if (!pw) return setFormErr(form, 'נא להזין סיסמה');
  setFormErr(form, '');
  const btn = form.querySelector('button[type=submit]');
  btn.disabled = true;
  btn.textContent = 'מתחבר…';
  await withBusy(async () => {
    try {
      const { salt } = await api(`/admin/challenge?u=${encodeURIComponent(username)}`);
      const { kek, verifier } = await deriveAuth(pw, salt);
      const res = await api('/admin/login', { body: { verifier, username } });
      const { keyIv, wrappedKey } = res;
      S.role = res.role === 'viewer' ? 'viewer' : 'admin';
      S.me = res.username || username;
      S.tabs = res.tabs || '*';
      const pkcs8 = new Uint8Array(
        await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ub64(keyIv) }, kek, ub64(wrappedKey))
      );
      S.priv = await crypto.subtle.importKey(
        'pkcs8', pkcs8, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']
      );
      S.pkcs8 = pkcs8;
      S.pubKey = await importPubKey(S.config.pub);
      // only fetch what this user's screens actually need — the server
      // refuses the rest anyway, and a 403 must not break the login
      const scopes = allowedScopes();
      if (scopes.has('records')) await loadRecords();
      if (scopes.has('vault')) await loadInv();
      if (scopes.has('reports')) await loadReports();
      if (S.role === 'admin') await loadUsers();
      S.tab = allowedTabs()[0] || 'over';
      armIdle();
      renderConsole();
    } catch (e) {
      setFormErr(form, e.status === 401 ? 'שם משתמש או סיסמה שגויים' : e.message);
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

/* ── Serial-number safety ──────────────────────────────────────────────
   There is no barcode and no photograph, so a typed serial is the only record
   that exists. Two things can go wrong and both are silent: the same serial
   ends up on two soldiers, or one digit is mistyped and a weapon that does not
   exist enters the books. Neither is caught by field validation, so they are
   caught here — at approval, where a human is already looking. */

// Levenshtein distance, capped: we only care whether it is 0, 1 or "more".
function editDistance(a, b) {
  a = String(a); b = String(b);
  if (Math.abs(a.length - b.length) > 1) return 2;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) {
      cur[j] = a[i - 1] === b[j - 1]
        ? prev[j - 1]
        : 1 + Math.min(prev[j - 1], prev[j], cur[j - 1]);
    }
    prev = cur;
  }
  return prev[b.length];
}

const SERIAL_FIELDS = [['weapon', 'נשק'], ['amral', 'אמר״ל'], ['scope', 'כוונת']];

// Every serial already in use, excluding one record (the one being approved).
function serialIndex(exceptRid) {
  const out = [];
  for (const rec of S.recs) {
    if (rec.rid === exceptRid || rec.damaged || !rec.data || rec.status !== 'approved') continue;
    for (const [f, label] of SERIAL_FIELDS) {
      if (rec.data[f]) out.push({ v: String(rec.data[f]), label, who: rec.data.name, kind: 'חייל' });
    }
  }
  for (const x of (S.inv && S.inv.armon) || []) {
    if (x.kind === 'weapon' && x.serial) {
      out.push({ v: String(x.serial), label: 'נשק', who: x.owner, kind: 'ארמון' });
    }
  }
  return out;
}

// Returns [] when nothing is suspicious, otherwise a list of human sentences.
function serialWarnings(d, exceptRid) {
  const index = serialIndex(exceptRid);
  const out = [];
  for (const [f, label] of SERIAL_FIELDS) {
    const val = d[f];
    if (!val) continue;
    const lower = String(val).toLowerCase();
    for (const other of index) {
      const o = other.v.toLowerCase();
      if (o === lower) {
        out.push(`⛔ ${label} ${val} כבר רשום על ${other.who} (${other.kind}) — אותו מספר לא יכול להיות בשני מקומות`);
      } else if (editDistance(lower, o) === 1) {
        out.push(`⚠ ${label} ${val} שונה בתו אחד בלבד מ-${other.v} של ${other.who} (${other.kind}) — ודאו שאין טעות הקלדה`);
      }
    }
  }
  return out;
}

// Approving one record. Split out of the click handler so a bulk run can call
// it repeatedly without nesting withBusy or firing a toast per soldier.
// Returns a short outcome the caller turns into a message.
async function approveCore(rid) {
  const rec = findRec(rid);
  if (!rec || rec.damaged) return { skipped: true };
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
        if (rec.data.weapon) parent.data.weapon = rec.data.weapon;
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
        return { name: parent.data.name, merged: true, failed: !!suppFailed };
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
    return { name: rec.data.name, failed: !!failed };
}

const adminApprove = (rid) =>
  withBusy(async () => {
    const rec = findRec(rid);
    if (rec && !rec.damaged && rec.data) {
      const warns = serialWarnings(rec.data, rid);
      if (warns.length && !window.confirm(
        `בדיקת מספרים סידוריים עבור ${rec.data.name}:\n\n${warns.join('\n')}\n\nלאשר בכל זאת?`
      )) return;
    }
    const r = await approveCore(rid);
    S.picked.delete(rid);
    renderConsole();
    if (r.skipped) return;
    toast(
      r.merged
        ? (r.failed
            ? `ההשלמה מוזגה לרישום של ${r.name} — ההודעה לא נשלחה אוטומטית`
            : `ההשלמה מוזגה ונשלחה הודעה ל${r.name}`)
        : (r.failed
            ? `אושר: ${r.name} — ההודעה לא נשלחה אוטומטית, שלחו ידנית במעקב ציוד`
            : `אושר: ${r.name} — הודעת וואטסאפ נשלחה`),
      !!r.failed
    );
  });

// Bulk approval. Each record is saved on its own, so a failure part-way leaves
// everything before it approved rather than rolling the batch back.
const bulkApprove = () =>
  withBusy(async () => {
    const rids = [...S.picked];
    if (!rids.length) return;
    const flagged = [];
    for (const rid of rids) {
      const rec = findRec(rid);
      if (!rec || rec.damaged || !rec.data) continue;
      const w = serialWarnings(rec.data, rid);
      if (w.length) flagged.push(`${rec.data.name}: ${w[0]}`);
    }
    const head = flagged.length
      ? `⚠ ${flagged.length} מתוך ${rids.length} עם בעיה במספרים סידוריים:\n\n${flagged.slice(0, 8).join('\n')}${flagged.length > 8 ? `\n…ועוד ${flagged.length - 8}` : ''}\n\n`
      : '';
    if (!window.confirm(`${head}לאשר ${rids.length} רישומים? לכל חייל תישלח הודעה.`)) return;
    let ok = 0, noMsg = 0;
    const failedRids = [];
    for (const rid of rids) {
      toast(`מאשר ${ok + failedRids.length + 1} מתוך ${rids.length}…`);
      try {
        const r = await approveCore(rid);
        if (r.skipped) continue;
        ok++;
        if (r.failed) noMsg++;
        S.picked.delete(rid);
      } catch {
        failedRids.push(rid);
      }
    }
    renderConsole();
    toast(
      `${ok} רישומים אושרו` +
        (noMsg ? ` · ${noMsg} ללא הודעה אוטומטית` : '') +
        (failedRids.length ? ` · ${failedRids.length} נכשלו ונשארו מסומנים` : ''),
      failedRids.length > 0
    );
  });

const bulkDelete = () =>
  withBusy(async () => {
    const rids = [...S.picked];
    if (!rids.length) return;
    if (!window.confirm(`למחוק ${rids.length} רישומים? הפעולה אינה הפיכה.`)) return;
    let ok = 0;
    for (const rid of rids) {
      try {
        await api(`/admin/records/${rid}`, { method: 'DELETE' });
        S.recs = S.recs.filter((r) => r.rid !== rid);
        S.picked.delete(rid);
        ok++;
      } catch { /* leave it ticked so the failure is visible */ }
    }
    renderConsole();
    toast(`${ok} רישומים נמחקו`);
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
    const scopes = allowedScopes();
    if (scopes.has('records')) await loadRecords();
    if (scopes.has('vault')) await loadInv();
    if (scopes.has('reports')) await loadReports();
    if (S.role === 'admin') await loadUsers();
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

// Wraps the very same private key under another password. Only possible while
// an admin is signed in, because the unwrapped key lives in memory only then.
async function wrapKeyFor(pw) {
  const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
  const keyIv = crypto.getRandomValues(new Uint8Array(12));
  const { kek, verifier } = await deriveAuth(pw, salt);
  const wrapped = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: keyIv }, kek, S.pkcs8);
  return { salt, verifier, keyIv: b64(keyIv), wrappedKey: b64(wrapped) };
}

async function userAddSubmit(form) {
  const username = form.username.value.trim().toLowerCase();
  const pw = form.pw.value;
  if (!/^[a-z0-9][a-z0-9._-]{1,30}$/.test(username)) {
    return setFormErr(form, 'שם משתמש: אותיות אנגליות קטנות, ספרות, נקודה, מקף או קו תחתון (2–31 תווים)');
  }
  if (S.users.some((u) => u.username === username)) {
    return setFormErr(form, `שם המשתמש ${username} כבר קיים`);
  }
  if (pw.length < 10) return setFormErr(form, 'הסיסמה חייבת להכיל 10 תווים לפחות');
  if (!S.userTabs.size) return setFormErr(form, 'נא לסמן לפחות מסך אחד');
  if (!S.pkcs8) return setFormErr(form, 'המפתח אינו זמין — התחברו מחדש');
  setFormErr(form, '');
  await withBusy(async () => {
    await api(`/admin/users/${encodeURIComponent(username)}`, {
      method: 'PUT',
      body: { role: 'viewer', tabs: [...S.userTabs], ...(await wrapKeyFor(pw)) },
    });
    S.userTabs.clear();
    await loadUsers();
    renderConsole();
    toast(`המשתמש ${username} נוצר`);
  });
}

const userSetPassword = (username) =>
  withBusy(async () => {
    const u = S.users.find((x) => x.username === username);
    if (!u) return;
    if (!S.pkcs8) { toast('המפתח אינו זמין — התחברו מחדש', true); return; }
    const pw = window.prompt(`סיסמה חדשה עבור ${username} (10 תווים לפחות):`, '');
    if (pw === null) return;
    if (pw.length < 10) { toast('הסיסמה חייבת להכיל 10 תווים לפחות', true); return; }
    let tabs = [];
    if (u.role === 'viewer') {
      try { tabs = JSON.parse(u.tabs) || []; } catch { tabs = []; }
      if (u.tabs === '*') tabs = TABS.filter((t) => !t.adminOnly).map((t) => t.id);
    }
    await api(`/admin/users/${encodeURIComponent(username)}`, {
      method: 'PUT',
      body: { role: u.role, tabs, ...(await wrapKeyFor(pw)) },
    });
    await loadUsers();
    renderConsole();
    toast(
      username === S.me
        ? 'הסיסמה הוחלפה — התחברו מחדש בפעם הבאה'
        : `הסיסמה של ${username} הוחלפה — הוא נותק מכל המכשירים`
    );
  });

// Changing screens does not touch the password, so the user stays signed in
// with their permissions updated underneath them.
const userSetScreens = (username) =>
  withBusy(async () => {
    const u = S.users.find((x) => x.username === username);
    if (!u || u.role === 'admin') return;
    let current = [];
    try { current = JSON.parse(u.tabs) || []; } catch { current = []; }
    if (u.tabs === '*') current = TABS.filter((t) => !t.adminOnly).map((t) => t.id);
    const menu = TABS.filter((t) => !t.adminOnly)
      .map((t, n) => `${n + 1} — ${t.name}${current.includes(t.id) ? ' ✓' : ''}`)
      .join('\n');
    const raw = window.prompt(
      `אילו מסכים ${username} יראה?\nהקלידו מספרים מופרדים בפסיק.\n\n${menu}`,
      current.map((id) => TABS.filter((t) => !t.adminOnly).findIndex((t) => t.id === id) + 1)
        .filter((n) => n > 0).join(',')
    );
    if (raw === null) return;
    const pickable = TABS.filter((t) => !t.adminOnly);
    const tabs = [...new Set(
      raw.split(/[,\s]+/).map((x) => parseInt(x, 10)).filter((n) => n >= 1 && n <= pickable.length)
    )].map((n) => pickable[n - 1].id);
    if (!tabs.length) { toast('נא לבחור לפחות מסך אחד', true); return; }
    await api(`/admin/users/${encodeURIComponent(username)}`, {
      method: 'PUT',
      body: { role: 'viewer', tabs, tabsOnly: true },
    });
    await loadUsers();
    renderConsole();
    toast(`המסכים של ${username} עודכנו`);
  });

const userDelete = (username) =>
  withBusy(async () => {
    if (!window.confirm(`למחוק את המשתמש ${username}? הוא ינותק מיד ולא יוכל להתחבר.`)) return;
    await api(`/admin/users/${encodeURIComponent(username)}`, { method: 'DELETE' });
    await loadUsers();
    renderConsole();
    toast(`המשתמש ${username} נמחק`);
  });

async function loadUsers() {
  try {
    const { users, me } = await api('/admin/users');
    S.users = users || [];
    if (me) S.me = me;
  } catch {
    S.users = [];                          // older deployment without the table
  }
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
const NUM_COMMIT = new Set(['inv-open', 'inv-xopen', 'inv-xout', 'veh-km', 'fuel-litres']);

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
    case 'dep-search':  S.depQ = el.value; S.page = {}; rerenderKeepFocus(el); break;
    case 'arm-mission': S.inv.armon[+el.dataset.i].mission = el.value; break;
    case 'flt-search':  S.fltQ = el.value; S.page = {}; rerenderKeepFocus(el); break;
    case 'tz-search':   S.regQ = { ...S.regQ, tzelem: el.value }; rerenderKeepFocus(el); break;
    case 'ammo-search': S.regQ = { ...S.regQ, ammo: el.value };   rerenderKeepFocus(el); break;
    case 'veh-search':  S.regQ = { ...S.regQ, veh: el.value };    rerenderKeepFocus(el); break;
    case 'veh-plate':   S.inv.vehicles[+el.dataset.i].plate = el.value; break;
    case 'veh-company': S.inv.vehicles[+el.dataset.i].company = el.value; break;
    case 'veh-km':
      S.inv.vehicles[+el.dataset.i].km =
        Math.max(0, Math.min(9999999, parseInt(String(el.value).replace(/\D/g, ''), 10) || 0));
      break;
    case 'veh-code':     S.inv.vehicles[+el.dataset.i].code = el.value; break;
    case 'veh-fuelcode': S.inv.vehicles[+el.dataset.i].fuelCode = el.value; break;
    case 'fuel-search':  S.regQ = { ...S.regQ, fuel: el.value }; S.page = {}; rerenderKeepFocus(el); break;
    case 'fuel-no':      S.inv.fuel[+el.dataset.i].no = el.value; break;
    case 'fuel-holder':  S.inv.fuel[+el.dataset.i].holder = el.value; break;
    case 'fuel-litres':
      S.inv.fuel[+el.dataset.i].litres =
        Math.max(0, Math.min(99999, parseInt(String(el.value).replace(/\D/g, ''), 10) || 0));
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
  if (el.dataset.act === 'flt-state') { fltSetState(el.dataset.id, el.dataset.st); return; }
  // number fields refresh their computed columns on commit, not per keystroke
  if (NUM_COMMIT.has(el.dataset.act)) { renderConsole(); return; }
  if (el.dataset.act === 'arm-loc') {
    const it = S.inv.armon[+el.dataset.i];
    it.loc = el.value;
    if (it.loc !== 'mission') it.mission = '';   // the mission name belongs to the mission
    renderConsole();
    return;
  }
  if (el.dataset.act === 'veh-service') { S.inv.vehicles[+el.dataset.i].service = el.value; renderConsole(); return; }
  if (el.dataset.act === 'veh-kit') { S.inv.vehicles[+el.dataset.i][el.dataset.k] = el.checked; renderConsole(); return; }
  if (el.dataset.act === 'utab') {
    if (el.checked) S.userTabs.add(el.dataset.t);
    else S.userTabs.delete(el.dataset.t);
    renderConsole();
    return;
  }
  if (el.dataset.act === 'fuel-kind') { S.inv.fuel[+el.dataset.i].kind = el.value; renderConsole(); return; }
  if (el.dataset.act === 'fuel-file') { fuelFile(+el.dataset.i, el); return; }
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
  else if (kind === 'user-add') userAddSubmit(form);
  else if (kind === 'report') reportSubmit(form);
  else if (kind === 'deposit') depositSubmit(form);
  else if (kind === 'fault') faultSubmit(form);
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
    case 's-edit-ident': S.sStep = 1; renderSoldier(); break;
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
    // reports — one definition, two outputs
    case 'rep-csv': reportCsv(el.dataset.r); break;
    case 'rep-pdf': reportPdf(el.dataset.r); break;
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
    case 'arm-qclear': S.regQ = { ...S.regQ, armon: '' }; S.page = {}; renderConsole(); break;
    // tzelem report
    case 'tz-qclear': S.regQ = { ...S.regQ, tzelem: '' }; renderConsole(); break;
    case 'tz-wa': tzelemWa(); break;
    // ammunition
    case 'ammo-issue': ammoMove(+el.dataset.i, true); break;
    case 'ammo-add-qty': ammoMove(+el.dataset.i, false); break;
    case 'ammo-del':
      if (window.confirm('למחוק את הפריט מהמלאי?')) { S.inv.ammo.splice(+el.dataset.i, 1); invSave(); }
      break;
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
    case 'veh-qclear': S.regQ = { ...S.regQ, veh: '' }; renderConsole(); break;
    // fuel cards
    case 'fuel-add':
      S.inv.fuel = [...(S.inv.fuel || []), cleanFuel({})];
      S.regQ = { ...S.regQ, fuel: '' };
      renderConsole();
      focusLast('[data-act="fuel-no"]');
      break;
    case 'fuel-del': fuelDelete(+el.dataset.i); break;
    case 'fuel-doc': fuelDocShow(el.dataset.r); break;
    case 'fuel-doc-del': fuelDocDelete(+el.dataset.i, el.dataset.r); break;
    case 'fuel-dl-one': fuelDownloadOne(+el.dataset.i, el.dataset.r); break;
    case 'fuel-dl-all': fuelDownloadAll(+el.dataset.i); break;
    case 'fuel-use': fuelUse(+el.dataset.i); break;
    case 'fuel-use-del':
      if (window.confirm('למחוק את רישום השימוש? הליטרים לא יוחזרו ליתרה אוטומטית.')) {
        S.inv.fuel[+el.dataset.i].uses.splice(+el.dataset.n, 1);
        invSave();
      }
      break;
    case 'fuel-credit': fuelCredit(+el.dataset.i); break;
    case 'fuel-office':
      S.inv.fuel[+el.dataset.i].holder = FUEL_OFFICE;
      renderConsole();
      break;
    case 'fuel-open': {
      const id = el.dataset.id;
      if (S.fuelOpen.has(id)) S.fuelOpen.delete(id);
      else S.fuelOpen.add(id);
      renderConsole();
      break;
    }
    case 'fuel-qclear': S.regQ = { ...S.regQ, fuel: '' }; renderConsole(); break;
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
    // users, trash, audit
    case 'key-export': exportRecoveryKey(); break;
    case 'trash-load': loadTrash(); break;
    case 'trash-restore': trashRestore(el.dataset.kind, el.dataset.id); break;
    case 'audit-load': loadAudit(); break;
    case 'user-del': userDelete(el.dataset.u); break;
    case 'user-pw': userSetPassword(el.dataset.u); break;
    case 'user-screens': userSetScreens(el.dataset.u); break;
    case 'utab-all':
      S.userTabs = new Set(TABS.filter((t) => !t.adminOnly).map((t) => t.id));
      renderConsole();
      break;
    case 'utab-none': S.userTabs.clear(); renderConsole(); break;
    // roster tables
    case 'sort': {
      const k = el.dataset.k;
      S.sort = S.sort.key === k
        ? { key: k, dir: S.sort.dir === 'asc' ? 'desc' : 'asc' }
        : { key: k, dir: k === 'date' || k === 'approved' ? 'desc' : 'asc' };
      S.page = {};
      renderConsole();
      break;
    }
    case 'expand':
      if (S.expanded.has(rid)) S.expanded.delete(rid);
      else S.expanded.add(rid);
      renderConsole();
      break;
    case 'pick':
      if (S.picked.has(rid)) S.picked.delete(rid);
      else S.picked.add(rid);
      renderConsole();
      break;
    case 'pick-all': {
      const page = paged('pending', sortRecs(applyFilters(S.recs.filter((r) => r.status === 'pending')),
                                             S.sort.key === 'approved' ? 'date' : S.sort.key));
      const rids = page.slice.map((r) => r.rid);
      const allOn = rids.every((x) => S.picked.has(x));
      for (const x of rids) { if (allOn) S.picked.delete(x); else S.picked.add(x); }
      renderConsole();
      break;
    }
    case 'pick-clear': S.picked.clear(); renderConsole(); break;
    case 'bulk-approve': bulkApprove(); break;
    case 'bulk-del': bulkDelete(); break;
    case 'rep-again': S.repSent = false; S.rep = null; renderReport(); break;
    // armoury deposits
    case 'dep-again': S.depSent = false; S.dep = null; renderDeposit(); break;
    case 'dep-filter': S.depFilter = el.dataset.f; S.page = {}; renderConsole(); break;
    case 'dep-approve': depApprove(el.dataset.id); break;
    case 'dep-qclear': S.depQ = ''; S.page = {}; renderConsole(); break;
    // building faults
    case 'flt-again': S.fltSent = false; S.flt = null; renderFault(); break;
    case 'flt-filter': S.fltFilter = el.dataset.f; S.page = {}; renderConsole(); break;
    case 'flt-qclear': S.fltQ = ''; S.page = {}; renderConsole(); break;
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
