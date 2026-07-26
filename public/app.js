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

// Open: admin only (§4.5). Throws on tampered ciphertext — caller counts it.
async function openRecord(privKey, rec) {
  const rawCek = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privKey, ub64(rec.ek));
  const cek = await crypto.subtle.importKey('raw', rawCek, 'AES-GCM', false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ub64(rec.iv) }, cek, ub64(rec.ct));
  return JSON.parse(td.decode(pt));
}

/* ── State ─────────────────────────────────────────────────────────── */

const S = {
  config: null,                 // { ready, pub?, idSalt? }
  route: location.hash === '#admin' ? 'admin' : 'soldier',

  // soldier flow
  sStep: 1,
  ident: null,                  // { pn, name, phone, dept }
  rid: null,
  suppMode: false,              // main record approved → this is a supplement
  existingPending: false,
  sel: {},                      // itemId -> quantity

  // admin
  adminView: 'login',           // 'setup' | 'login' | 'console'
  priv: null,                   // CryptoKey (RSA private)
  pkcs8: null,                  // Uint8Array — kept for password rotation, zeroed on lock
  pubKey: null,                 // CryptoKey (RSA public, for re-sealing)
  recs: [],                     // { rid, status, created_at, updated_at, data|null, damaged }
  inv: null,                    // { open:{}, extra:[], notes } — decrypted inventory
  tab: 'pending',
  filter: 'out',
  q: '',                        // free-text search over name / pn / phone
  dept: 'all',                  // department filter
  collapsed: new Set(),         // department ids folded shut
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
  S.q = '';
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
}

/* ── Rendering ─────────────────────────────────────────────────────── */

const render = (html) => { $app.innerHTML = html; };

function renderRoute() {
  if (S.route === 'admin') renderAdmin();
  else renderSoldier();
}

/* ── Soldier views (PLAN §7.1) ─────────────────────────────────────── */

function stepsBar(n) {
  const labels = ['פרטים', 'ציוד', 'סיום'];
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
  else renderSoldierStep3();
}

function renderSoldierStep1() {
  const v = S.ident || { pn: '', name: '', phone: '', dept: '' };
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
        <p class="form-err" data-err></p>
        <button class="btn primary wide" type="submit">המשך</button>
      </form>
    </section>`);
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
      <button class="btn primary wide" data-act="s-submit">שליחה לאישור</button>
      <button class="btn ghost wide mt" data-act="s-back">חזרה לפרטים</button>
    </section>`);
}

function renderSoldierStep3() {
  const list = Object.entries(S.sel)
    .map(([id, q]) => {
      const item = itemById(id);
      return `<span class="tagi">${esc(item.name)}${item.qty ? ` <span class="num">×${q}</span>` : ''}</span>`;
    })
    .join('');
  render(`
    ${stepsBar(3)}
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
    </section>`);
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
  const c = counts();
  const tabs = [
    ['pending', 'ממתין לאישור', c.pending],
    ['track', 'מעקב ציוד', c.approved],
    ['inv', 'מלאי', null],
    ['sum', 'סיכום', null],
    ['sec', 'אבטחה', null],
  ]
    .map(
      ([id, label, count]) => `
      <button class="tab" role="tab" aria-selected="${S.tab === id}" data-act="tab" data-tab="${id}">
        ${label}${count !== null ? ` <span class="tab-count num">${count}</span>` : ''}
      </button>`
    )
    .join('');

  let body = '';
  if (S.tab === 'pending') body = renderPendingTab();
  else if (S.tab === 'track') body = renderTrackTab();
  else if (S.tab === 'inv') body = renderInvTab();
  else if (S.tab === 'sum') body = renderSummaryTab();
  else body = renderSecurityTab();

  render(`
    <div class="conbar">
      <span class="conbar-title">ניהול ציוד</span>
      <div class="conbar-actions">
        <button class="btn ghost small" data-act="refresh">רענון</button>
        <button class="btn ghost small" data-act="lock">נעילה</button>
      </div>
    </div>
    ${c.damaged
      ? `<div class="callout risk"><p class="mb0"><strong class="num">${c.damaged}</strong> רשומות פגומות — הפענוח נכשל (חשד לשיבוש נתונים בשרת). ראו בלשוניות לפי סטטוס.</p></div>`
      : ''}
    <div class="tabs" role="tablist">${tabs}</div>
    ${body}`);
}

function fpStrip(rid) {
  return `<footer class="fp"><span aria-hidden="true">🔒</span><span class="fp-code num">${esc(rid.slice(0, 16))}</span></footer>`;
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
  return `
    ${searchBar(all.length, visible.length)}
    ${broken}
    ${deptSections(visible, pendingCard, 'אין הגשות שתואמות את החיפוש.')}`;
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
  return `
    ${searchBar(approved.length, visible.length)}
    <div class="filters">${filters}</div>
    ${broken}
    ${deptSections(visible, card, 'אין רשומות שתואמות את החיפוש והסינון.')}`;
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
    return { name: item.name, t, r, out: t - r };
  });
  const rows = totals
    .map(
      (x) => `<tr>
        <td>${esc(x.name)}</td>
        <td class="num">${x.t}</td>
        <td class="num">${x.r}</td>
        <td class="num ${x.out > 0 ? 'warn' : 'ok'}">${x.out}</td>
      </tr>`
    )
    .join('');
  const soldiersOut = approved.filter((rec) => outstanding(rec.data) > 0).length;

  return `
    <section class="panel">
      <h2 class="panel-title">סיכום מלאי</h2>
      <p class="panel-sub">רשומות מאושרות בלבד. <span class="num">${c.pending}</span> ממתינות לאישור.</p>
      <div class="tbl-scroll">
        <table class="tbl">
          <thead><tr><th>פריט</th><th class="num">הונפק</th><th class="num">הוחזר</th><th class="num">בחוץ</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      <p class="mt muted-txt">
        <span class="num">${approved.length}</span> חיילים מאושרים ·
        <span class="num">${soldiersOut}</span> עם ציוד בחוץ
        ${c.damaged ? ` · <span class="num">${c.damaged}</span> רשומות פגומות` : ''}
      </p>
      <button class="btn ghost wide mt" data-act="export">ייצוא CSV</button>
    </section>`;
}

/* ── Inventory (מלאי) ──────────────────────────────────────────────── */

const emptyInv = () => ({ open: {}, extra: [], notes: '' });

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
          <input class="input mini num" type="number" min="0" max="9999" value="${open}"
                 data-act="inv-open" data-item="${item.id}" aria-label="מלאי פתיחה ${esc(item.name)}">
        </td>
        <td class="num">${held}</td>
        <td class="num ${left < 0 ? 'bad' : left === 0 ? 'warn' : 'ok'}">${left}</td>
      </tr>`;
  }).join('');

  const extraRows = inv.extra
    .map(
      (x, i) => `<tr>
        <td><input class="input mini" type="text" maxlength="40" value="${esc(x.name)}"
                   data-act="inv-xname" data-i="${i}" aria-label="שם פריט" placeholder="שם הפריט"></td>
        <td><input class="input mini num" type="number" min="0" max="9999" value="${Number(x.open) || 0}"
                   data-act="inv-xopen" data-i="${i}" aria-label="מלאי פתיחה"></td>
        <td><input class="input mini num" type="number" min="0" max="9999" value="${Number(x.out) || 0}"
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
      ${inv.extra.length
        ? `<div class="tbl-scroll">
             <table class="tbl">
               <thead><tr><th>פריט</th><th>סה״כ</th><th>בשימוש</th><th class="num">נותר</th><th></th></tr></thead>
               <tbody>${extraRows}</tbody>
             </table>
           </div>`
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

function renderSecurityTab() {
  return `
    <div class="callout">
      <p class="callout-title">מה מוצפן</p>
      <p>שם, מספר אישי, טלפון ופירוט הציוד מוצפנים במכשיר לפני השליחה. השרת, קלאודפלייר, וכל מי שמשיג גישה לחשבון או למסד — רואים צופן בלבד.</p>
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

// The inventory blob rides the same envelope as records.
async function loadInv() {
  try {
    const { vault } = await api('/admin/vault');
    if (!vault) { S.inv = emptyInv(); return; }
    const data = await openRecord(S.priv, vault);
    S.inv = { ...emptyInv(), ...data };
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

// Serialises mutations: one at a time, errors surface as toasts.
async function withBusy(fn) {
  if (S.busy) return;
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
  if (!/^\d{5,9}$/.test(pn)) return setFormErr(form, 'מספר אישי: 5–9 ספרות');
  if (name.length < 2) return setFormErr(form, 'נא למלא שם מלא');
  if (!/^\d{9,10}$/.test(phone)) return setFormErr(form, 'טלפון: 9–10 ספרות, ללא מקפים');
  if (!DEPTS.some((d) => d.id === dept)) return setFormErr(form, 'נא לבחור מחלקה');
  setFormErr(form, '');
  const btn = form.querySelector('button[type=submit]');
  btn.disabled = true;
  btn.textContent = 'בודק…';
  await withBusy(async () => {
    const rid = await deriveRid(pn, S.config.idSalt);
    const st = await api(`/status/${rid}`);
    S.ident = { pn, name, phone, dept };
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
    if (S.suppMode) payload.supp = true;
    const pubKey = await importPubKey(S.config.pub);
    const sealed = await seal(pubKey, payload);
    await api('/records', { body: { rid: S.rid, ...sealed } });
    S.sStep = 3;
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
    S.tab = 'pending';
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
      S.tab = 'pending';
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
    renderConsole();
    toast('עודכן');
  });

const invSave = () =>
  withBusy(async () => {
    await saveInv();
    renderConsole();
    toast('המלאי נשמר');
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
    S.q = '';
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
  const q = (v) => '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"';
  const head = [
    'מספר אישי', 'שם', 'טלפון', 'מחלקה',
    ...ITEMS.flatMap((i) => [`${i.name} נלקח`, `${i.name} הוחזר`]),
    'סטטוס', 'נשלח', 'אושר',
  ];
  const lines = [head.map(q).join(',')];
  for (const rec of S.recs) {
    if (rec.damaged) continue;
    const d = rec.data;
    lines.push(
      [
        d.pn, d.name, d.phone, deptName(d.dept),
        ...ITEMS.flatMap((i) => {
          const it = d.items[i.id];
          return it ? [it.t, it.r || 0] : ['', ''];
        }),
        rec.status === 'approved' ? 'מאושר' : 'ממתין',
        fmtDate(d.createdAt),
        d.approvedAt ? fmtDate(d.approvedAt) : '',
      ].map(q).join(',')
    );
  }
  const blob = new Blob(['\uFEFF' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'tzayad-export.csv';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
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
  const num = () => Math.max(0, Math.min(9999, parseInt(el.value, 10) || 0));
  switch (act) {
    case 'search': S.q = el.value; rerenderKeepFocus(el); break;
    case 'inv-open': S.inv.open[el.dataset.item] = num(); rerenderKeepFocus(el); break;
    case 'inv-xopen': S.inv.extra[i].open = num(); rerenderKeepFocus(el); break;
    case 'inv-xout': S.inv.extra[i].out = num(); rerenderKeepFocus(el); break;
    // name and notes don't affect any computed figure — no re-render needed
    case 'inv-xname': S.inv.extra[i].name = el.value; break;
    case 'inv-notes': S.inv.notes = el.value; break;
  }
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
    case 's-reset': resetSoldier(); renderSoldier(); break;
    // admin console
    case 'tab': S.tab = el.dataset.tab; renderConsole(); break;
    case 'filter': S.filter = el.dataset.filter; renderConsole(); break;
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
    case 'wipe': adminWipe(); break;
    // search & grouping
    case 'dept': S.dept = el.dataset.dept; renderConsole(); break;
    case 'qclear': S.q = ''; renderConsole(); break;
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
  rec.data[field] = now;
  rec.data.log.push({ a: field === 'notified' ? 'notify-manual' : 'return-notify', t: now });
  saveRec(rec)
    .then(() => renderConsole())
    .catch(() => { rec.data[field] = null; toast('שמירת סימון השליחה נכשלה', true); });
}

// After a re-render, put the cursor in the newly added row.
function focusLast(sel) {
  const nodes = $app.querySelectorAll(sel);
  if (nodes.length) nodes[nodes.length - 1].focus();
}

/* ── Routing & boot ────────────────────────────────────────────────── */

window.addEventListener('hashchange', () => {
  const route = location.hash === '#admin' ? 'admin' : 'soldier';
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
