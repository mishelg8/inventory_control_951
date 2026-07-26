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

const ITEMS = [
  { id: 'helmet', name: 'קסדה', qty: false },
  { id: 'vest', name: 'ווסט', qty: false },
  { id: 'mitznefet', name: 'מצנפת', qty: false },
  { id: 'knee', name: 'ברכיות', qty: false },
  { id: 'mags', name: 'מחסניות', qty: true, min: 1, max: 20 },
];
const itemById = (id) => ITEMS.find((i) => i.id === id);

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
  ident: null,                  // { pn, name, phone }
  rid: null,
  existingPending: false,
  sel: {},                      // itemId -> quantity

  // admin
  adminView: 'login',           // 'setup' | 'login' | 'console'
  priv: null,                   // CryptoKey (RSA private)
  pkcs8: null,                  // Uint8Array — kept for password rotation, zeroed on lock
  pubKey: null,                 // CryptoKey (RSA public, for re-sealing)
  recs: [],                     // { rid, status, created_at, updated_at, data|null, damaged }
  tab: 'pending',
  filter: 'out',
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
  return `<div class="steps" aria-hidden="true">${[1, 2, 3]
    .map((i) => `<span${i <= n ? ' class="on"' : ''}></span>`)
    .join('')}</div>`;
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
  const v = S.ident || { pn: '', name: '', phone: '' };
  render(`
    ${stepsBar(1)}
    <section class="panel">
      <h1 class="panel-title">רישום ציוד אישי</h1>
      <p class="panel-sub">מלאו פרטים, בחרו את הציוד שקיבלתם ושלחו לאישור. הפרטים מוצפנים במכשיר שלכם — רק מנהל הציוד יכול לקרוא אותם.</p>
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
        <span class="opt-name">${esc(item.name)}</span>
        ${stepper}
      </li>`;
  }).join('');

  render(`
    ${stepsBar(2)}
    <section class="panel">
      <h1 class="panel-title">איזה ציוד קיבלת?</h1>
      <p class="panel-sub">שלום ${esc(S.ident.name)} — סמנו את כל הפריטים שקיבלתם.</p>
      ${S.existingPending
        ? `<div class="callout"><p class="mb0">קיימת כבר הגשה ממתינה למספר אישי זה — שליחה חדשה תחליף אותה.</p></div>`
        : ''}
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
      <h1 class="panel-title">הרישום נשלח</h1>
      <p class="panel-sub">הרשומה נקלטה במצב <span class="state wait">ממתין לאישור</span> — מנהל הציוד יאשר אותה בהמשך.</p>
      <div class="tags center">${list}</div>
      <div class="fp num"><span aria-hidden="true">🔒</span><span class="fp-code">${esc(S.rid.slice(0, 16))}</span></div>
      <button class="btn primary wide mt" data-act="s-reset">סיום — לחייל הבא</button>
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

function damagedCard(rec) {
  return `
    <article class="rec">
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

function renderPendingTab() {
  const recs = S.recs.filter((r) => r.status === 'pending');
  if (!recs.length) return '<p class="empty">אין הגשות ממתינות. לחצו רענון כדי לבדוק שוב.</p>';
  return recs
    .map((rec) => {
      if (rec.damaged) return damagedCard(rec);
      const d = rec.data;
      const rows = ITEMS.filter((i) => d.items[i.id])
        .map((item) => {
          const t = d.items[item.id].t;
          const tools = item.qty
            ? `<span class="step">
                 <button type="button" class="step-btn" data-act="adj" data-rid="${esc(rec.rid)}"
                         data-item="${item.id}" data-d="-1" aria-label="פחות" ${t <= item.min ? 'disabled' : ''}>−</button>
                 <span class="step-val num">${t}</span>
                 <button type="button" class="step-btn" data-act="adj" data-rid="${esc(rec.rid)}"
                         data-item="${item.id}" data-d="1" aria-label="עוד" ${t >= item.max ? 'disabled' : ''}>+</button>
               </span>`
            : `<span class="step-val num">${t}</span>`;
          return `<li class="rec-row">
              <span class="rec-row-name">${esc(item.name)}</span>
              <span class="rec-row-tools">${tools}</span>
            </li>`;
        })
        .join('');
      return `
        <article class="rec">
          <header class="rec-head">
            <div>
              <div class="rec-name">${esc(d.name)}</div>
              <div class="rec-meta">מ״א <span class="num">${esc(d.pn)}</span> · נשלח ${esc(fmtDate(d.createdAt))}</div>
            </div>
            <span class="state wait">ממתין</span>
          </header>
          ${phoneRow(rec)}
          <ul>${rows}</ul>
          <div class="rec-actions">
            <button class="btn primary" data-act="approve" data-rid="${esc(rec.rid)}">אישור</button>
            <button class="btn danger" data-act="del" data-rid="${esc(rec.rid)}">מחיקה</button>
          </div>
          ${fpStrip(rec.rid)}
        </article>`;
    })
    .join('');
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

  const visible = approved.filter((rec) => {
    if (rec.damaged) return true;
    const out = outstanding(rec.data) > 0;
    return S.filter === 'all' || (S.filter === 'out' ? out : !out);
  });

  const cards = visible
    .map((rec) => {
      if (rec.damaged) return damagedCard(rec);
      const d = rec.data;
      const out = outstanding(d);
      const rows = ITEMS.filter((i) => d.items[i.id])
        .map((item) => {
          const it = d.items[item.id];
          const r = it.r || 0;
          const returned = r >= it.t;
          return `<li class="rec-row">
              <span>
                <span class="tagi${returned ? ' done' : ''}">${esc(item.name)}</span>
                <span class="rec-row-sub">הוחזרו <span class="num">${r}</span> מתוך <span class="num">${it.t}</span></span>
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
        <article class="rec">
          <header class="rec-head">
            <div>
              <div class="rec-name">${esc(d.name)}</div>
              <div class="rec-meta">מ״א <span class="num">${esc(d.pn)}</span> · אושר ${esc(fmtDate(d.approvedAt))}</div>
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
            <button class="btn danger" data-act="del" data-rid="${esc(rec.rid)}">מחיקה</button>
          </div>
          ${fpStrip(rec.rid)}
        </article>`;
    })
    .join('');

  return `
    <div class="filters">${filters}</div>
    ${cards || '<p class="empty">אין רשומות בסינון הזה.</p>'}`;
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

function renderSecurityTab() {
  return `
    <div class="callout">
      <p class="callout-title">מה מוצפן</p>
      <p>שם, מספר אישי, טלפון ופירוט הציוד מוצפנים במכשיר לפני השליחה. השרת, קלאודפלייר, וכל מי שמשיג גישה לחשבון או למסד — רואים צופן בלבד.</p>
      <p class="mb0">מה השרת כן רואה: מספר הרשומות, סטטוס (ממתין/מאושר) וחותמות זמן. לא זהות ולא פירוט ציוד.</p>
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
  if (!/^\d{5,9}$/.test(pn)) return setFormErr(form, 'מספר אישי: 5–9 ספרות');
  if (name.length < 2) return setFormErr(form, 'נא למלא שם מלא');
  if (!/^\d{9,10}$/.test(phone)) return setFormErr(form, 'טלפון: 9–10 ספרות, ללא מקפים');
  setFormErr(form, '');
  const btn = form.querySelector('button[type=submit]');
  btn.disabled = true;
  btn.textContent = 'בודק…';
  await withBusy(async () => {
    const rid = await deriveRid(pn, S.config.idSalt);
    const st = await api(`/status/${rid}`);
    if (st.exists && st.status === 'approved') {
      setFormErr(form, 'הרשומה שלך כבר אושרה. לעדכון או תיקון — פנו למנהל הציוד.');
      btn.disabled = false;
      btn.textContent = 'המשך';
      return;
    }
    S.ident = { pn, name, phone };
    S.rid = rid;
    S.existingPending = !!st.exists;
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
      items,
      createdAt: now,
      log: [{ a: 'submit', t: now }],
    };
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
    rec.data.approvedAt = now;
    rec.data.log.push({ a: 'approve', t: now });
    rec.status = 'approved';
    await saveRec(rec);
    renderConsole();
    toast(`אושר: ${rec.data.name}`);
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
    renderConsole();
    toast('עודכן');
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
    'מספר אישי', 'שם', 'טלפון',
    ...ITEMS.flatMap((i) => [`${i.name} נלקח`, `${i.name} הוחזר`]),
    'סטטוס', 'נשלח', 'אושר',
  ];
  const lines = [head.map(q).join(',')];
  for (const rec of S.recs) {
    if (rec.damaged) continue;
    const d = rec.data;
    lines.push(
      [
        d.pn, d.name, d.phone,
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
  }
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
