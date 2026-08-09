/* ════════════════════════════════════════════════════════════════════
   רישום ראשוני — client logic. All plaintext personal data lives only in
   this browser's memory; everything sent to the server is ciphertext or
   a one-way derivation. See PLAN.md §4 for the cryptographic design.
   ════════════════════════════════════════════════════════════════════ */

import {
  SVG_OPEN, ITEMS, itemById, DEPTS, deptName, SERIAL_FIELDS, LIFECYCLE, ARM_KINDS, ARM_LOCS,
  COMMS_PLACES, COMMS_KINDS, COMMS_LOCS, ARM_BAD_LOCS, NAMED_LOCS, AMMO_DESTS, ARM_DESTS,
  nameOf, REGISTERS, kindLocs, VEH_KIT, FUEL_KINDS, FUEL_LOW, FUEL_OFFICE, LIC_KINDS,
  DAY_MS, EXPIRING_SOON_DAYS, LOAN_LOCS, ARM_ACTIONS, AMMO_ACTIONS, canLoan,
} from './lib/catalog.js';
import {
  te, td, b64, ub64, hex, rndId, deriveAuth, deriveRid, normSerial, deriveSerialTag,
  serialTags, importPubKey, seal, sealBytes, openRecord, openBytes,
} from './lib/crypto.js';
import {
  asText, asCount, asTime, cleanRecord, cleanReport, cleanRegItem, cleanArmLog,
  cleanAmmo, cleanAmmoLog, cleanVehicle, cleanFuel, cleanInv,
} from './lib/clean.js';

const $app = document.getElementById('app');
const $toast = document.getElementById('toast');

/* ── Equipment catalog ─────────────────────────────────────────────── */



/* ── Departments ───────────────────────────────────────────────────── */


/* ── Small helpers ─────────────────────────────────────────────────── */

const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[c]);




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
































/* ── Licence photos ────────────────────────────────────────────────── */



/* The bounds of a date anybody could mean. A native date field will happily
   hold the year 62, and a mistyped year is the single most common way to get
   one — so the field is told to refuse it, and so is everything downstream. */
const DATE_MIN = '1990-01-01';
const DATE_MAX = '2099-12-31';

const inDateRange = (iso) => typeof iso === 'string' && iso >= DATE_MIN && iso <= DATE_MAX;

// 'valid' | 'soon' | 'expired' | 'nodate' — drives the red/amber/green states.
function licState(expiry) {
  if (!expiry) return 'nodate';
  /* A year outside the range is not an expired licence, it is a typo. Calling
     it 'expired' put a red "the licence has expired" under a field the soldier
     was still in the middle of filling in. */
  if (!inDateRange(expiry)) return 'nodate';
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

// The gallery button keeps `accept="image/*"`, and three attempts to improve on
// that are recorded here so nobody spends the afternoon a fourth time.
//
// A web page cannot choose which app Android opens: `accept` and `capture` are
// the only levers HTML has, and the OS resolves the intent. What `accept` does
// control is the intent's MIME type, and that decides which apps are even
// offered — `image/*` is what a gallery registers for. Samsung Gallery is not
// in the list for anything else.
//
//   naming the image types explicitly   no change. Chrome asks only whether the
//                                       list is image-only, and it still was.
//   dropping `accept` altogether        intent becomes */*, so the chooser
//                                       offered Camera, My Files and Files —
//                                       no gallery, because a gallery does not
//                                       claim */*. Verified on a Samsung.
//   offering both as two buttons        the second button could not reach the
//                                       gallery, so it was only clutter.
//
// When `image/*` opens Google Photos rather than the gallery, that is the
// phone's default handler for image picking, and it is cleared in Android
// settings — not from here.
//
// notAnImage() stays because it is the better guard regardless: files can
// arrive with an empty `type`, and rejecting those would throw away real
// photos. Only a type the browser positively reports as something else is
// refused, and compressImage() fails loudly on the rest.
const notAnImage = (file) => !!file.type && !/^image\//.test(file.type);

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
  if (h === '#refuel') return 'refuel';
  if (h === '#sign') return 'soldier';
  // The sign-up split into the three things it always was: being written down,
  // being issued a weapon, and signing for kit. They happen on three different
  // days, so they are three different pages rather than three steps of one.
  if (h === '#weapon') return 'weapon';
  if (h === '#gear') return 'gear';
  return 'home';   // the link a soldier is given lands on the chooser
}

const S = {
  config: null,                 // { ready, pub?, idSalt? }
  route: routeFromHash(),

  // refuelling report (soldier-facing, filed against a fuel card by the admin)
  sig: null,                    // the soldier's signature: { bytes, size, preview }
  rf: null,                     // draft { name, phone, card, litres, plate }
  rfSent: false,
  rfPhoto: null,                // the receipt the soldier attached, before sending
  cards: [],                    // fuel cards a soldier may report against
  fleet: [],                    // vehicles a soldier may report against
  rfPick: {},                   // report id -> the card the admin picked for it
  rfFilter: 'open',             // 'open' | 'done' | 'all' in the console's list

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
  sharedPhoto: null,            // a picture handed over by Android's share sheet
  wa: { loaded: false, enabled: false, missing: [], reachable: false, state: '',
        qr: null, err: null, to: '', body: '', busy: false },

  creditAsk: '',                // rid whose "credit everything" question is open

  // correcting a licence from the console: which row is open, and its draft
  licEdit: '',                  // rid, '' when nothing is being corrected
  licDraft: null,               // { civil, no, exp, military, pic: {kind -> obj|null} }

  // admin
  adminView: 'login',           // 'setup' | 'login' | 'console'
  role: 'admin',                // 'admin' | 'viewer' — viewer cannot write
  me: '',                       // username of the signed-in user
  tabs: '*',                    // '*' or the list of screens this user may see
  users: [],                    // roster, admin only
  trash: null,                  // soft-deleted rows, loaded on demand
  audit: null,                  // admin action log, loaded on demand
  userTabs: new Set(),          // screens ticked in the new-user form
  userRole: 'editor',           // permission chosen in the new-user form
  userEdit: null,               // username whose inline editor is open
  userEditDraft: null,          // that editor's pending changes
  priv: null,                   // CryptoKey (RSA private)
  pkcs8: null,                  // Uint8Array — kept for password rotation, zeroed on lock
  pubKey: null,                 // CryptoKey (RSA public, for re-sealing)
  recs: [],                     // { rid, status, created_at, updated_at, data|null, damaged }
  recsSince: 0,                 // newest updated_at held, so a tick asks only for what moved
  inv: null,                    // { open:{}, extra:[], notes } — decrypted inventory
  docs: {},                     // "rid:kind" -> data URL, fetched on demand
  docBig: new Set(),            // which of them are open at full size
  docTried: new Set(),          // already asked for, so an auto-load runs once
  docOrder: [],                 // those keys, least recently shown first
  reports: [],                  // { id, status, created_at, data|null, damaged }
  repsSince: 0,                 // as recsSince, for reports
  repFilter: 'open',            // 'open' | 'done' | 'all'
  repQ: '',                     // search over request name + body
  invQ: '',                     // search over the extra-inventory rows
  regQ: {},                     // section key -> search query
  regKind: {},                  // register id -> item-type filter ('all' or a kind)
  tab: 'over',
  /* The tracking screen opens on everybody. It used to open on 'ציוד בחוץ',
     which is the right question to ask about kit and the wrong one to ask of
     a screen people open to look somebody up: a soldier who had signed for
     nothing was not in the list, and nothing on the screen said a filter was
     the reason. The counts on the filters say so now, and narrowing is one
     press away. */
  filter: 'all',
  q: '',                        // free-text search over name / pn / phone
  dept: 'all',                  // department filter
  collapsed: new Set(),         // department ids folded shut
  page: {},                     // list key -> current page index (0-based)
  revealed: new Set(),          // rids with phone shown
  fuelOpen: new Set(),          // fuel card ids with their detail row expanded
  ammoDraft: {},                // per-row movement being composed in the ammo table
  fuelDraft: {},                // per-row refuelling being composed in the fuel table
  armDraft: {},                 // per-row removal being composed in the armoury table
  openRows: new Set(),          // rows whose folded-away columns are open on a phone
  expanded: new Set(),          // record rids expanded in the pending/track tables
  picked: new Set(),            // rids ticked for a bulk action
  serialWarn: {},               // serial field -> "already taken" message, or ''
  serialSeen: {},               // serial field -> the value last checked
  tabHist: [],                  // screens visited, so "חזרה" retraces them
  askDel: '',                   // the one row currently asking "delete?"
  armEdit: '',                  // register item id whose fields are open for correction
  recEdit: '',                  // rid whose identity fields are open for correction
  recDraft: null,               // that editor's pending changes
  repEdit: '',                  // report id whose fields are open for correction
  repDraft: null,
  sort: { key: 'date', dir: 'desc' },   // roster table ordering
  invVer: {},                   // part -> updated_at at load, for conflict detection
  invBase: {},                  // part -> its content when loaded, for the dirty check
  invBytes: 0,                  // sealed size of the largest part, for the headroom gauge
  /* The WhatsApp gateway, as far as this browser knows it. Everything here
     comes from a poll of /admin/wa/status and is display-only — the console
     never holds the gateway's secret, and the gateway never holds the key to
     anything in the vault. `enabled: false` is the normal state of a site that
     has not set one up, and it must look like a setting, not a failure. */
  wa: {
    loaded: false, enabled: false, reachable: false,
    state: 'stopped', qr: null, me: null, lastError: null,
    queue: null, events: [], messages: [], counts: null,
    testTo: '', testBody: '', busy: false,
  },
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
  S.recsSince = 0;              // the next sign-in starts from a full load, not a merge
  S.inv = null;
  S.reports = [];
  S.repsSince = 0;
  S.docs = {};                  // decrypted licence images must not outlive the session
  S.docOrder = [];
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
  S.userEdit = null;
  S.userEditDraft = null;
  S.revealed.clear();
  S.fuelOpen.clear();
  S.expanded.clear();
  S.picked.clear();
  clearTimeout(idleTimer);
  stopPulse();
  api('/admin/logout', { method: 'POST', body: {} }).catch(() => {});
  if (S.route === 'admin') {
    S.adminView = S.config && S.config.ready ? 'login' : 'setup';
    renderRoute();
  }
}

function resetSoldier() {
  S.sStep = 1;
  S.flow = 'details';           // which of the three pages is being filled
  S.ident = null;
  S.rid = null;
  S.suppMode = false;
  S.existingPending = false;
  S.sel = {};
  S.lic = { civil: false, military: false };
  S.licNo = '';
  S.licExp = '';
  S.licPhoto = {};
  S.sig = null;                 // the next soldier signs for themselves
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

  // Every form's error line becomes a live region the moment it is drawn,
  // rather than in eleven separate templates that a twelfth form would
  // forget. The role has to be on the element *before* the text arrives —
  // an alert added at the same moment as its message is announced by some
  // screen readers and not others — which is exactly why it is set here, on
  // render, and not in setFormErr.
  for (const err of $app.querySelectorAll('[data-err]')) {
    err.setAttribute('role', 'alert');
    err.tabIndex = -1;
  }

  // Folding moves cells around, and moving a node drops focus — so reshape
  // the tables first and hand focus back to the settled DOM.
  fitTables();

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

/* ── Fitting a table to the screen ─────────────────────────────────────
   A register is a table, and it has to stay one at every width. The
   columns are what let you run your eye down a list and compare rows;
   stacking each row into a card throws that away and turns a screenful
   into a scroll.

   But twelve columns will never fit across 375px — nor across the 620px a
   narrow laptop window leaves this panel. So a table that cannot afford
   all its columns sheds the ones it can spare: each names the two or three
   that carry it in `data-phone`, and the rest fold into a panel under the
   row that opens with the row's chevron. The cells are moved, not copied,
   so an input in a folded column is still the same live control.

   Whether it can afford them is measured, not guessed at a breakpoint —
   a table of five columns is comfortable where one of twelve is not. */

// What a column needs before its content starts stacking a word per line.
function colNeed(th) {
  if (th.classList.contains('col-pick')) return 34;
  if (th.classList.contains('kit-col') || th.classList.contains('lg-col')) return 46;
  if (th.classList.contains('num')) return 72;
  return 100;
}

function fitTables() {
  let ti = 0;
  for (const table of $app.querySelectorAll('table.tbl')) {
    if (!table.tHead || !table.tHead.rows[0] || !table.tBodies[0]) continue;
    const hcells = [...table.tHead.rows[0].cells];
    // A header may carry an abbreviation for the desktop column and the full
    // name in its title; the folded panel has room for the full name. What it
    // must not carry is the sort arrow or an icon — those are decoration for
    // the column heading, and a label reading "נשלח▾" is just wrong.
    const heads = hcells.map((c) => (c.title || '').trim() || headText(c));
    for (const row of table.tBodies[0].rows) {
      if (row.cells.length === 1 && row.cells[0].colSpan > 1) continue;   // detail row
      [...row.cells].forEach((cell, i) => {
        if (heads[i]) cell.dataset.label = heads[i];
      });
    }

    const box = table.parentElement;
    const room = box ? box.clientWidth : 0;
    // Two questions, both of which must come out well. Would the columns be
    // too cramped to read? — that is the estimate. Does the table actually
    // reach past its panel? — that is the measurement, and it catches what
    // an estimate per column cannot: a cell whose contents will not break.
    const wants = hcells.reduce((sum, th) => sum + colNeed(th), 0);
    const banned = new Set();
    const keep = room && (wants > room || table.scrollWidth > room + 1)
      ? keepCols(table, heads.length, banned) : null;
    if (keep) {
      // The estimate proposes; the table disposes. Buying columns back by
      // estimate alone once put twelve of them into space enough for nine,
      // because a cell holding a thirteen-digit card number does not care
      // what its heading is called. So the proposal is tried on — hiding a
      // column is only a class — and columns are handed back until it fits.
      const bought = spend(keep, hcells, room, banned);
      hideCols(table, keep);
      while (bought.length && table.scrollWidth > room + 1) {
        keep.delete(bought.pop());
        hideCols(table, keep);
      }
      if (keep.size < heads.length) {
        foldTable(table, keep, ti);
        // Even folded, a few columns whose content will not break — a
        // username, a button caption — can still ask for more than the
        // screen. Then, and only then, the columns share the width equally
        // and the text wraps inside them. Measured, because at ten columns
        // an equal share is exactly what broke Hebrew a letter per line.
        if (table.scrollWidth > room + 1) table.classList.add('even');
      } else {
        hideCols(table, null);        // it fits after all — show everything
      }
    }
    ti += 1;
  }
}

function headText(th) {
  const copy = th.cloneNode(true);
  for (const dec of copy.querySelectorAll('[aria-hidden="true"], svg')) dec.remove();
  return copy.textContent.trim();
}

/* Where a phone stops being a narrow desktop. Matches the breakpoint the
   stylesheet uses for the same decision, so the layout and the folding never
   disagree about which one this is. */
const PHONE_W = 560;

/* Which columns survive when there is not room for all of them. A table says
   so itself; a negative index counts from the end, so the actions column is
   -1 however many columns precede it.

   On a phone that column is the most expensive thing in the row. Two buttons
   cannot share 123px, so they stack, and a row of the tracking list stood
   195px tall — six soldiers to a screen, most of it button, the name crushed
   onto two lines beside all that air. Folded in with everything else it costs
   nothing until you open the row, and the row becomes a line in a list: 55px,
   eleven soldiers to a screen. Nothing is removed; the buttons move one tap
   away, into the drawer that already holds the rest of the record.

   `banned` is what may not be bought back by `spend` — without it the column
   would simply be repurchased with the width folding it away had freed. */
function keepCols(table, n, banned) {
  const spec = (table.dataset.phone || '').trim();
  let keep;
  let actions = -1;
  if (spec) {
    const parts = spec.split(',').map((s) => parseInt(s, 10));
    keep = new Set(parts
      .map((v) => (v < 0 ? n + v : v))
      .filter((v) => Number.isInteger(v) && v >= 0 && v < n));
    const fromEnd = parts.find((v) => v < 0);
    if (fromEnd !== undefined) actions = n + fromEnd;
  } else {
    keep = new Set([0, 1, n - 1]);
    actions = n - 1;
  }
  // Never the only thing left: a row that folds away everything including its
  // own identity is a chevron and nothing else.
  if (actions >= 0 && keep.size > 1 && window.innerWidth <= PHONE_W) {
    keep.delete(actions);
    banned.add(actions);
  }
  return keep.size && keep.size < n ? keep : null;
}

// `data-phone` names the columns a table cannot do without — what it keeps at
// 375px. A laptop window too narrow for all thirteen usually has room for
// eight, and showing three there would be throwing away the screen. So the
// room left over buys back as many of the folded columns as it will hold.
// Returns what it bought, in the order it bought it, so the caller can hand
// the last ones back when the table turns out to need more than was estimated.
function spend(keep, hcells, room, banned = new Set()) {
  const bought = [];
  let used = 40;                                   // the chevron's own column
  for (const i of keep) used += colNeed(hcells[i]);
  for (let i = 0; i < hcells.length; i += 1) {
    if (keep.has(i) || banned.has(i)) continue;
    const need = colNeed(hcells[i]);
    if (used + need > room) continue;
    keep.add(i);
    bought.push(i);
    used += need;
  }
  return bought;
}

// Try a column set on without committing to it: hiding a cell is a class,
// where folding moves it into the row's panel and cannot be undone. Passing
// null shows every column again.
function hideCols(table, keep) {
  const rows = [table.tHead.rows[0], ...table.tBodies[0].rows];
  for (const row of rows) {
    if (!row || (row.cells.length === 1 && row.cells[0].colSpan > 1)) continue;
    [...row.cells].forEach((c, i) => c.classList.toggle('folded-out', !!keep && !keep.has(i)));
  }
}

// Identifies a row across re-renders, so a panel the user opened stays open.
// Index alone would follow the position rather than the row once a list is
// re-sorted or filtered.
function rowKey(row, ri) {
  const el = row.querySelector('[data-act]');
  const d = el ? el.dataset : null;
  const k = d ? (d.rid || d.id || d.item || d.i) : null;
  return k == null || k === '' ? `#${ri}` : k;
}

function foldTable(table, keep, ti) {
  table.classList.add('folded');
  const hrow = table.tHead.rows[0];
  [...hrow.cells].forEach((c, i) => { if (!keep.has(i)) c.classList.add('folded-out'); });
  const hexp = document.createElement('th');
  hexp.className = 'exp-col';
  hrow.appendChild(hexp);

  /* Every physical column, not every surviving one. A folded-away column is
     hidden, not removed, so the row still has all its cells and a colspan of
     `keep.size + 1` covers the first few of them — which are the right ones
     only when the kept columns happen to sit at the front. Keep the first and
     the last and the drawer spans the first two instead, ending halfway across
     the table. Spanning the lot is always right: the hidden ones are zero
     wide, so they cost nothing and cannot be miscounted. */
  const span = hrow.cells.length;
  [...table.tBodies[0].rows].forEach((row, ri) => {
    if (row.cells.length === 1 && row.cells[0].colSpan > 1) {
      row.cells[0].colSpan = span;      // an existing detail row spans the new width
      return;
    }
    const folded = [...row.cells].filter((_, i) => !keep.has(i));
    if (!folded.length) return;

    // before the cells move — the identifying control may be in a folded one
    const key = `${S.tab}:${ti}:${rowKey(row, ri)}`;

    const grid = document.createElement('div');
    grid.className = 'det-grid';
    for (const cell of folded) {
      const field = document.createElement('div');
      const lbl = document.createElement('span');
      lbl.className = 'det-l';
      lbl.textContent = cell.dataset.label || '';
      // An actions column has no heading, so its field has nothing to label
      // and the control takes the row rather than sitting beside a blank.
      field.className = lbl.textContent ? 'det-f' : 'det-f is-bare';
      const val = document.createElement('div');
      val.className = `det-v${cell.classList.contains('num') ? ' num' : ''}`;
      while (cell.firstChild) val.appendChild(cell.firstChild);
      cell.remove();
      if (!lbl.textContent && !val.textContent.trim() && !val.children.length) continue;
      field.append(lbl, val);
      grid.appendChild(field);
    }

    const panel = document.createElement('tr');
    panel.className = 'det';
    const holder = document.createElement('td');
    holder.colSpan = span;
    holder.appendChild(grid);
    panel.appendChild(holder);

    const tog = document.createElement('td');
    tog.className = 'exp-col';
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'exp-btn';
    // Was the character ⌄, which every platform draws at a different weight and
    // a different advance width — on Android it overflowed the button it sat
    // in. A drawn chevron, on the same 24-grid and stroke as every other icon
    // here, is the same shape everywhere and fits the box it is given.
    btn.innerHTML = `${SVG_OPEN}<path d="M6 9l6 6 6-6"/></svg>`;
    tog.appendChild(btn);
    row.appendChild(tog);
    row.after(panel);

    /* One row, one drawer.

       A roster row can already open a drawer of its own — the return
       steppers, the messaging, the record — off the soldier's name. Folding
       then added a second one, for the columns it had taken away, with its
       own chevron and its own state. On a phone that is two controls a
       centimetre apart that look alike and do different things: press the
       obvious one and you get the department and the date, and nothing tells
       you the steppers are behind the name instead. Every soldier needed two
       taps in two places, and the second was unfindable.

       Where a row has its own drawer, the chevron drives that, and the folded
       columns simply open with it. Where it has none — a register, a ledger —
       the chevron keeps its own state as before. */
    const own = row.querySelector('[data-act="expand"][data-rid]');
    const paint = (on) => {
      panel.classList.toggle('on', on);
      row.classList.toggle('exp', on);
      btn.setAttribute('aria-expanded', String(on));
      btn.setAttribute('aria-label', on ? 'סגירת שאר הפרטים' : 'הצגת שאר הפרטים');
    };
    if (own) {
      paint(S.expanded.has(own.dataset.rid));
      btn.addEventListener('click', () => own.click());
    } else {
      paint(S.openRows.has(key));
      btn.addEventListener('click', () => {
        const on = !panel.classList.contains('on');
        paint(on);
        if (on) S.openRows.add(key); else S.openRows.delete(key);
      });
    }
  });
}

// A width change can put a table either side of what it can afford, and the
// folding mutates the DOM — so rebuild from state rather than try to undo it.
// Height-only changes (a phone's address bar sliding away, a soft keyboard)
// must not, or the console would rebuild under the user's finger.
let lastWidth = window.innerWidth;
let fitTimer = null;
window.addEventListener('resize', () => {
  if (window.innerWidth === lastWidth) return;
  lastWidth = window.innerWidth;
  clearTimeout(fitTimer);
  fitTimer = setTimeout(() => renderRoute(), 150);
});

// The way out of every soldier page.
//
// It used to be a small button pinned to the top-right corner, which is the
// one part of a phone screen a thumb has to travel furthest to reach and the
// part a form is least about. It sits at the foot of the panel now, with the
// other things you can press — where you look when you have decided not to
// fill this in — and it is a full-width target rather than a link the width
// of its own text. There is one per page instead of the two there were.
const backToMenu = (label = 'חזרה לתפריט') => `
  <a class="btn ghost wide mt backbtn" href="#">${ICO.back}${esc(label)}</a>`;

// The console's own controls. Drawn rather than written, because a row of
// three identical grey rectangles is read by shape and there is no shape to
// read — an arrow, a cycle and a padlock are told apart before the words are.
// Same 24-grid and stroke as the equipment icons, so they belong to the same
// hand; sized down to sit beside a caption rather than replace it.
const btnIco = (paths) => `<span class="btn-ico" aria-hidden="true">${SVG_OPEN}${paths}</svg></span>`;

const ICO = {
  back: btnIco('<path d="M4 12h16"/><path d="m14 6 6 6-6 6"/>'),
  refresh: btnIco('<path d="M20.5 12a8.5 8.5 0 1 1-2.49-6.01"/><path d="M20.5 3.5v5h-5"/>'),
  lock: btnIco('<rect x="4.5" y="10.5" width="15" height="9.5" rx="2.5"/><path d="M8 10.5V7a4 4 0 0 1 8 0v3.5"/>'),
};

// The banner names the page you are on, not the half of the app it belongs
// to. It used to read "רישום ראשוני" above the refuelling form and above the
// shortage form and above the menu — the one line that could have told you
// where you were, spent on telling you which door you came in by. The unit
// stays underneath, where it identifies the app without competing.
const ADMIN_TITLE = 'לוגיסטיקה פלוגה ג';
const ADMIN_SUB = 'מסייעת 951 · ניהול ציוד, ארמון, קשר ורכב';
const SOLDIER_SUB = 'מסייעת 951 · רישום ומעקב ציוד אישי';
const HOME_SUB = 'רישום ומעקב ציוד אישי';

/* What a pending submission is, on the admin's screen. A row that says only
   "ממתין" tells them there is something to do and not what — and with three
   pages feeding one list, "what" is the first thing they need. */
const KIND_TAG = {
  details: 'פרטים אישיים',
  weapon: 'רישום נשק',
  gear: 'חתימה על ציוד',
};

const KIND_NOTE = {
  weapon: 'רישום נשק — באישור, המספרים יתווספו לרישום הקיים של החייל.',
  gear: 'חתימה על ציוד — באישור, הפריטים יתווספו לרישום הקיים של החייל.',
};

const ROUTE_TITLE = {
  home: 'מסייעת 951',
  soldier: 'רישום פרטים אישיים',
  weapon: 'רישום נשק',
  gear: 'חתימה על ציוד',
  report: 'בקשת ציוד / דיווח חוסר',
  deposit: 'אפסון נשק בארמון',
  fault: 'דיווח תקלות בינוי',
  refuel: 'דיווח תדלוק',
};

function setBanner(route) {
  const admin = route === 'admin';
  const title = admin ? ADMIN_TITLE : (ROUTE_TITLE[route] || ROUTE_TITLE.home);
  const t = document.getElementById('topTitle');
  const s = document.getElementById('topSub');
  if (t) t.textContent = title;
  // On every other screen the strap names the unit, because the title is the
  // name of a form and the unit is the context. On the landing page the title
  // *is* the unit, and repeating it there put the same three words twice in
  // one bar, an inch apart.
  if (s) s.textContent = admin ? ADMIN_SUB : (route === 'home' ? HOME_SUB : SOLDIER_SUB);
  // The tab, too: a soldier with three of these open should be able to tell
  // them apart without opening each one.
  document.title = title;
  setFooterNav(route);
}

// The footer says where you can go; this says where you are. A link back to
// the page you are already on is a small lie a screen reader has no way to
// see through, so the current one is marked and stops being a link.
function setFooterNav(route) {
  for (const a of document.querySelectorAll('.foot-link')) {
    const here = a.getAttribute('href') === `#${route === 'soldier' ? 'sign' : route}`;
    a.toggleAttribute('aria-current', here);
    if (here) a.setAttribute('aria-current', 'page');
  }
  // Already inside the console: the door you are standing in is not a way out.
  const admin = document.getElementById('adminLink');
  if (admin) admin.hidden = route === 'admin' && !!S.priv;
}

function renderRoute() {
  setBanner(S.route);
  // The console needs a wide column for tables; soldier pages stay narrow.
  // The banner and the footer are separate elements from the content, so the
  // width has to be said somewhere they can all hear it — otherwise the emblem
  // sat centred in a 640px column above content 1240px wide, and on a large
  // monitor the header floated 300px inside the page it was supposed to head.
  const wide = S.route === 'admin' && !!S.priv;
  $app.classList.toggle('wide', wide);
  document.body.classList.toggle('is-console', wide);
  if (S.route === 'admin') renderAdmin();
  else if (S.route === 'report') renderReport();
  else if (S.route === 'deposit') renderDeposit();
  else if (S.route === 'fault') renderFault();
  else if (S.route === 'refuel') renderRefuel();
  else if (S.route === 'weapon') renderWeaponPage();
  else if (S.route === 'gear') renderGearPage();
  else if (S.route === 'home') renderHome();
  else renderSoldier();
}

/* ── Landing: what does the soldier want to do? ────────────────────── */

function renderHome() {
  render(`
    <!-- The bar above already carries the emblem and the unit's name. This
         card used to repeat both, so "מסייעת 951" appeared three times inside
         the first two inches of a phone screen and the first thing a soldier
         could actually press started below the fold. The heading is a level-1
         for the page and stays, spoken to a screen reader and hidden from a
         sighted reader who has just read it in the bar. -->
    <section class="panel center-head hero">
      <img class="unit-badge" src="/logo.png" alt="סמל מסייעת 951">
      <h1 class="panel-title center hide-phone">מסייעת 951</h1>
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
          <span class="choice-t">רישום פרטים אישיים</span>
          <span class="choice-s">מתחילים כאן — שם, מספר אישי, מחלקה ורישיונות נהיגה.</span>
        </span>
        <span class="choice-go" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"
               stroke-linecap="round" stroke-linejoin="round"><path d="M15 5l-7 7 7 7"/></svg>
        </span>
      </a>
      <a class="choice" href="#weapon">
        <span class="choice-ico arm" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"
               stroke-linecap="round" stroke-linejoin="round">
            <path d="M3 9h15l3 3-3 3h-4l-2-3H3z"/>
            <path d="M7 15v3"/>
          </svg>
        </span>
        <span class="choice-txt">
          <span class="choice-t">רישום נשק</span>
          <span class="choice-s">המספרים שעל הנשק, האקילה והכוונת שקיבלתם.</span>
        </span>
        <span class="choice-go" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"
               stroke-linecap="round" stroke-linejoin="round"><path d="M15 5l-7 7 7 7"/></svg>
        </span>
      </a>
      <a class="choice" href="#gear">
        <span class="choice-ico" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"
               stroke-linecap="round" stroke-linejoin="round">
            <path d="M4 17c2.5-4 5-4 7.5 0"/>
            <path d="M3 20h18"/>
            <path d="M14 13l3.5-3.5a2 2 0 0 1 3 2.6L17 16"/>
          </svg>
        </span>
        <span class="choice-txt">
          <span class="choice-t">חתימה על ציוד</span>
          <span class="choice-s">קסדה, ווסט, מחסניות ועוד — בחירה וחתימה באצבע.</span>
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
      <a class="choice" href="#refuel">
        <span class="choice-ico fuel" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"
               stroke-linecap="round" stroke-linejoin="round">
            <path d="M4 21V5a2 2 0 0 1 2-2h5a2 2 0 0 1 2 2v16"/>
            <path d="M3 21h11"/>
            <path d="M5.5 8.5h6"/>
            <path d="M13 12h3.5a1.5 1.5 0 0 1 1.5 1.5V17a1.5 1.5 0 0 0 3 0V9l-2.5-2.5"/>
          </svg>
        </span>
        <span class="choice-txt">
          <span class="choice-t">דיווח תדלוק</span>
          <span class="choice-s">תדלקתם רכב בכרטיס תדלוק? רשמו כמה וכרטיס איזה, וזה ייקלט אצל מנהל הרכב.</span>
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
        ${backToMenu()}
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
      ${backToMenu()}
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
        ${backToMenu()}
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
            <span class="field-label">שם המדווח <span class="req" aria-hidden="true">*</span></span>
            <input class="input" name="name" autocomplete="off" maxlength="60"
                   value="${esc(v.name)}" required>
          </label>
          <label class="field">
            <span class="field-label">טלפון המדווח <span class="req" aria-hidden="true">*</span></span>
            <input class="input num" name="phone" inputmode="tel" autocomplete="tel"
                   maxlength="10" value="${esc(v.phone)}" placeholder="0501234567" required>
          </label>
        </div>
        <label class="field">
          <span class="field-label">תיאור התקלה <span class="req" aria-hidden="true">*</span></span>
          <textarea class="input area" name="text" rows="7" maxlength="1500"
                    placeholder="לדוגמה: נזילה מהתקרה במקלחות בבניין 4, מתחת לחלון. המים מגיעים עד המסדרון." required>${esc(v.text)}</textarea>
          <span class="field-hint">כתבו איפה בדיוק ומה קרה — ככל שיש יותר פרטים כך הטיפול מהיר יותר.</span>
        </label>
        <p class="form-err" data-err></p>
        <button class="btn primary wide" type="submit">שליחת הדיווח</button>
      </form>
      ${backToMenu()}
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

/* ── Refuelling report (soldier-facing) ────────────────────────────────
   The soldier who fills the tank is the only one who knows how much went
   in, and until now that reached the office as a message someone had to
   retype. Here it arrives as a report, and the vehicle officer files it
   against the card in one press — the litres come off the balance and the
   use is logged, exactly as if it had been typed in the console.

   It cannot write to the card directly: the fuel register lives in the
   admin's encrypted vault, which only a key-holder can rewrite. That is
   the same reason a weapon deposit waits for approval, and it is a feature
   — a report from an anonymous page is a claim, not a fact. */

// The roster is fetched once when the page opens and the form re-renders with
// it. Asking inside the render itself would refetch on every keystroke.
let cardsAsked = false;
function renderRefuel() {
  if (!cardsAsked && S.config && S.config.ready) {
    cardsAsked = true;
    api('/cards')
      .then((r) => {
        S.cards = r.cards || [];
        S.fleet = r.vehicles || [];
        // The roster can land after the soldier has started typing.
        if (S.route === 'refuel') { captureRefuelForm(); renderRefuel(); }
      })
      .catch(() => { /* the form already says there is nothing to pick */ });
  }
  if (!S.config || !S.config.ready) {
    render(`
      <section class="panel center">
        <h1 class="panel-title">המערכת עדיין לא הוגדרה</h1>
        <p class="panel-sub mb0">מנהל הציוד צריך להשלים את ההקמה לפני שאפשר לדווח.</p>
      </section>`);
    return;
  }
  if (S.rfSent) {
    render(`
      <section class="panel center">
        <div class="big-ok" aria-hidden="true"></div>
        <h1 class="panel-title">התדלוק דווח</h1>
        <p class="panel-sub">הדיווח נקלט. מנהל הרכב יאשר אותו והליטרים יירדו מיתרת הכרטיס.</p>
        <button class="btn ghost wide mt" data-act="rf-again">דיווח תדלוק נוסף</button>
        ${backToMenu()}
      </section>`);
    return;
  }
  const v = S.rf || { name: '', phone: '', card: '', litres: '', plate: '' };
  render(`
    <section class="panel center-head">
      <img class="unit-badge" src="/logo.png" alt="סמל מסייעת 951">
      <h1 class="panel-title center">דיווח תדלוק</h1>
      <p class="panel-sub center">תדלקתם רכב בכרטיס תדלוק? רשמו כאן מיד אחרי התדלוק — כך היתרה בכרטיס נשארת נכונה.</p>
      <form data-form="refuel" novalidate>
        <div class="grid2">
          <label class="field">
            <span class="field-label">שם המתדלק <span class="req" aria-hidden="true">*</span></span>
            <input class="input" name="name" autocomplete="off" maxlength="60"
                   value="${esc(v.name)}" required>
          </label>
          <label class="field">
            <span class="field-label">טלפון <span class="req" aria-hidden="true">*</span></span>
            <input class="input num" name="phone" inputmode="tel" autocomplete="tel"
                   maxlength="10" value="${esc(v.phone)}" placeholder="0501234567" required>
          </label>
          <label class="field">
            <span class="field-label">כרטיס התדלוק <span class="req" aria-hidden="true">*</span></span>
            <select class="input select" name="card" required>
              <option value="">בחרו כרטיס…</option>
              ${(S.cards || []).map((c) =>
                `<option value="${esc(c.id)}"${v.card === c.id ? ' selected' : ''}>${esc(c.label)}</option>`).join('')}
            </select>
            <span class="field-hint">${(S.cards || []).length
              ? 'הכרטיסים שמופיעים כאן הם אלה שפעילים כרגע. כרטיס שזוכה או הוסר לא יופיע.'
              : 'אין כרגע כרטיסים פעילים במערכת — פנו למנהל הרכב.'}</span>
          </label>
          <label class="field">
            <span class="field-label">כמה ליטרים <span class="req" aria-hidden="true">*</span></span>
            <input class="input num" name="litres" inputmode="numeric" maxlength="4"
                   value="${esc(v.litres)}" placeholder="0" required>
          </label>
        </div>
        <label class="field">
          <span class="field-label">מספר הרכב שתודלק <span class="req" aria-hidden="true">*</span></span>
          ${(S.fleet || []).length
            ? `<select class="input select" name="plate" required>
                 <option value="">בחרו רכב…</option>
                 ${S.fleet.map((x) =>
                   `<option value="${esc(x.id)}"${v.plate === x.id ? ' selected' : ''}>${esc(x.label)}</option>`).join('')}
               </select>
               <span class="field-hint">הרכבים שרשומים אצל מנהל הרכב. לא מוצאים את הרכב? פנו אליו.</span>`
            : `<input class="input num" name="plate" inputmode="numeric" maxlength="20"
                      value="${esc(v.plate)}" placeholder="12-345-67" required>
               <span class="field-hint">אין כרגע רכבים רשומים במערכת — רשמו את מספר הרכב.</span>`}
        </label>

        <fieldset class="lic-set">
          <legend class="field-label">קבלת התדלוק <span class="req" aria-hidden="true">*</span></legend>
          <p class="field-hint">בלי קבלה אי אפשר להצדיק את הליטרים מול קצין הרכב, ולכן היא חובה.</p>
          <div class="rec-actions">
            <label class="btn ghost small">📷 צילום הקבלה
              <input class="vis-hidden" type="file" accept="image/*" capture="environment"
                     data-act="rf-photo"></label>
            <label class="btn ghost small">🖼 בחירה מהגלריה
              <input class="vis-hidden" type="file" accept="image/*" data-act="rf-photo"></label>
          </div>
          ${S.rfPhoto
            ? `<div class="fp">
                 <span>✓ קבלה מצורפת (${Math.round(S.rfPhoto.size / 1024)}KB)</span>
                 <button type="button" class="linkbtn danger-link" data-act="rf-photo-clear">הסרה</button>
               </div>`
            : `<p class="field-hint">אין גלריה ברשימה שנפתחת? בחרו <strong>הקבצים שלי</strong> ← <strong>תמונות</strong>.</p>
               <p class="field-hint mb0">טרם צורפה קבלה.</p>`}
        </fieldset>

        <p class="form-err" data-err></p>
        <button class="btn primary wide" type="submit">שליחת הדיווח</button>
      </form>
      ${backToMenu()}
    </section>`);
}

async function refuelSubmit(form) {
  const name = form.name.value.trim();
  const phone = form.phone.value.trim();
  const card = form.card.value.trim();
  const plateVal = form.plate.value.trim();
  const litres = parseInt(String(form.litres.value).replace(/\D/g, ''), 10);
  if (name.length < 2) return setFormErr(form, 'נא למלא את שם המתדלק');
  if (!/^\d{9,10}$/.test(phone)) return setFormErr(form, 'טלפון: 9–10 ספרות, ללא מקפים');
  const picked = (S.cards || []).find((c) => c.id === card);
  if (!picked) return setFormErr(form, 'נא לבחור כרטיס תדלוק מהרשימה');
  if (!Number.isFinite(litres) || litres < 1) return setFormErr(form, 'נא למלא כמות ליטרים');
  if (litres > 500) return setFormErr(form, 'כמות הליטרים נראית שגויה — בדקו שוב');
  // With a fleet published the field is a picker, so the value is an id and
  // what the office should read is the plate; without one it is still typed.
  const veh = (S.fleet || []).find((x) => x.id === plateVal);
  if ((S.fleet || []).length && !veh) return setFormErr(form, 'נא לבחור את הרכב שתודלק');
  if (!veh && plateVal.length < 5) return setFormErr(form, 'נא למלא את מספר הרכב');
  const plate = veh ? veh.label.split(' · ')[0] : plateVal;
  if (!S.rfPhoto) return setFormErr(form, 'נא לצרף צילום של הקבלה');
  setFormErr(form, '');
  S.rf = { name, phone, card, litres: String(litres), plate: plateVal };
  const btn = form.querySelector('button[type=submit]');
  btn.disabled = true;
  btn.textContent = 'שולח…';
  await withBusy(async () => {
    const pubKey = await importPubKey(S.config.pub);
    const id = hex(crypto.getRandomValues(new Uint8Array(16)));
    // `card` is the id the admin's browser can resolve; the label rides along
    // so the office can read the report without opening the vault first.
    const sealed = await seal(pubKey, {
      kind: 'refuel', name, phone, card, cardLabel: picked.label,
      litres, plate, text: '', createdAt: Date.now(),
    });
    await api('/reports', { body: { id, ticket: await getTicket(), ...sealed } });
    // The receipt goes separately, like a licence photo, so the report list
    // never drags image data around with it.
    await api('/docs', {
      body: { rid: id, kind: 'refuel', ...(await sealBytes(pubKey, S.rfPhoto.bytes)) },
    });
    S.rfSent = true;
    S.rf = null;
    S.rfPhoto = null;
    renderRefuel();
  });
  if (!S.rfSent) {
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
        ${backToMenu()}
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
            <span class="field-label">מספר אישי <span class="req" aria-hidden="true">*</span></span>
            <input class="input num" name="pn" inputmode="numeric" autocomplete="off"
                   maxlength="9" value="${esc(v.pn)}" placeholder="1234567" required>
          </label>
          <label class="field">
            <span class="field-label">שם החייל <span class="req" aria-hidden="true">*</span></span>
            <input class="input" name="name" autocomplete="off" maxlength="60"
                   value="${esc(v.name)}" placeholder="ישראל ישראלי" required>
          </label>
          <label class="field">
            <span class="field-label">מספר טלפון <span class="req" aria-hidden="true">*</span></span>
            <input class="input num" name="phone" inputmode="tel" autocomplete="tel"
                   maxlength="10" value="${esc(v.phone)}" placeholder="0501234567" required>
          </label>
          <label class="field">
            <span class="field-label">מספר נשק <span class="req" aria-hidden="true">*</span></span>
            <input class="input num" name="weapon" data-act="ser-chk" data-f="weapon" autocomplete="off" maxlength="20"
                   value="${esc(v.weapon)}" placeholder="7145732" required>
            ${serialWarnBox('weapon')}
          </label>
        </div>
        <fieldset class="lic-set">
          <legend class="field-label">אמצעים נלווים <span class="opt-tag">רק אם קיימים</span></legend>
          <div class="grid2">
            <label class="field">
              <span class="field-label">מק״ט אקילה</span>
              <input class="input num" name="amral" data-act="ser-chk" data-f="amral" autocomplete="off" maxlength="20"
                     value="${esc(v.amral)}">
              ${serialWarnBox('amral')}
            </label>
            <label class="field">
              <span class="field-label">מק״ט כוונת יום</span>
              <input class="input num" name="scope" data-act="ser-chk" data-f="scope" autocomplete="off" maxlength="20"
                     value="${esc(v.scope)}">
              ${serialWarnBox('scope')}
            </label>
          </div>
          <span class="field-hint">אם לא מסרתם אקילה או כוונת — השאירו ריק.</span>
        </fieldset>
        <p class="form-err" data-err></p>
        <button class="btn primary wide" type="submit">שליחת בקשת אפסון</button>
      </form>
      ${backToMenu()}
    </section>`);
}

/* ── Telling a soldier the number is taken, before they press send ──────
   The server refuses a duplicate either way, but finding that out after
   filling in a whole form is no way to find it out. Each serial field
   checks itself once the soldier leaves it: the number is masked in the
   browser and only the mask is sent, so the answer costs nothing.

   What comes back is a state, never a name — "already with a soldier" is
   what someone needs in order to tell their own mistyping from someone
   else's rifle, and whose it is stays encrypted. */

const SERIAL_STATE_HE = {
  pending: 'ממתין לאישור', approved: 'רשום על חייל אחר',
  deposit: 'הופקד בארמון וממתין לקליטה', armoury: 'רשום בארמון',
};

async function checkSerial(field, value, label) {
  const v = normSerial(value);
  if (!S.config || !S.config.idSalt) return;
  if (S.serialSeen[field] === v) return;              // already answered for this value
  S.serialSeen = { ...S.serialSeen, [field]: v };
  if (!v) { S.serialWarn = { ...S.serialWarn, [field]: '' }; paintSerialWarnings(); return; }
  try {
    const tag = await deriveSerialTag(value, S.config.idSalt);
    const r = await api(`/serial?tag=${tag}`);
    S.serialWarn = {
      ...S.serialWarn,
      [field]: r.taken
        ? `⛔ ${label} ${value} כבר קיים במערכת — ${SERIAL_STATE_HE[r.state] || r.state}. ` +
          'בדקו שלא טעיתם בהקלדה; אם המספר באמת שלכם, פנו למנהל הציוד.'
        : '',
    };
  } catch {
    S.serialWarn = { ...S.serialWarn, [field]: '' };   // a failed check must not block
  }
  paintSerialWarnings();
}

// Written straight into the DOM rather than through a re-render: the soldier
// is in the middle of a form, and rebuilding it under their hands is exactly
// the kind of thing this feature exists to spare them.
function paintSerialWarnings() {
  for (const [field] of SERIAL_FIELDS) {
    const box = $app.querySelector(`[data-warn="${field}"]`);
    if (!box) continue;
    const msg = (S.serialWarn || {})[field] || '';
    box.textContent = msg;
    box.hidden = !msg;
    const input = $app.querySelector(`[name="${field}"]`);
    if (input) input.classList.toggle('is-bad', !!msg);
  }
  const form = $app.querySelector('form[data-form="deposit"]');
  if (!form) return;
  const btn = form.querySelector('button[type=submit]');
  if (btn) btn.disabled = SERIAL_FIELDS.some(([f]) => (S.serialWarn || {})[f]);
}

const serialWarnBox = (field) => `<span class="field-bad" data-warn="${field}" hidden></span>`;

const anySerialTaken = () => SERIAL_FIELDS.some(([f]) => (S.serialWarn || {})[f]);

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
    return setFormErr(form, 'מק״ט אקילה: 3–20 תווים (ספרות, אותיות באנגלית, - או /)');
  }
  if (scope && !serialRe.test(scope)) {
    return setFormErr(form, 'מק״ט כוונת יום: 3–20 תווים (ספרות, אותיות באנגלית, - או /)');
  }
  // The field checks already said so in red; this is the gate that acts on it.
  if (anySerialTaken()) {
    return setFormErr(form, 'אחד המספרים כבר קיים במערכת — תקנו אותו לפני השליחה');
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
      body: {
        id: hex(crypto.getRandomValues(new Uint8Array(16))), ticket: await getTicket(), ...sealed,
        tags: await serialTags({ weapon, amral, scope }, S.config.idSalt),
      },
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

/* Only the kit-signing page has steps worth counting. Registering details or a
   weapon is one form and a confirmation, and a four-dot progress bar over a
   single form promises a journey that is not there. */
function stepsBar(n, labels = ['זיהוי', 'ציוד', 'אישור', 'סיום']) {
  // Only the kit page has more than one step. The other two showed a four-dot
  // bar over a single form, and then again on the "sent" screen — counting a
  // journey nobody made.
  if (S.flow !== 'gear') return '';
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

/* Redraw whichever of the three pages is being filled.
   The kit page reuses the list and the signature screens, and those screens
   redraw themselves after every tick of a checkbox — through this, now. When
   they called renderSoldier directly, ticking the first item on the kit page
   threw the soldier back to the personal-details form, because that is what
   renderSoldier draws. */
const renderFlow = () => {
  if (S.flow === 'weapon') renderWeaponPage();
  else if (S.flow === 'gear') renderGearPage();
  else renderSoldier();
};

function notConfigured() {
  if (S.config && S.config.ready) return false;
  render(`
    <section class="panel center">
      <h1 class="panel-title">המערכת עדיין לא הוגדרה</h1>
      <p class="panel-sub mb0">מנהל הציוד צריך להשלים את ההקמה לפני שאפשר להירשם.</p>
    </section>`);
  return true;
}

// Page one: who you are. Nothing is signed for here, so there is no signature
// and no list — a form and a confirmation.
function renderSoldier() {
  if (notConfigured()) return;
  S.flow = 'details';
  if (S.sStep >= 4) renderSoldierDone();
  else renderSoldierStep1();
}

// Page two: the numbers on the weapon you were issued.
function renderWeaponPage() {
  if (notConfigured()) return;
  S.flow = 'weapon';
  if (S.sStep >= 4) renderSoldierDone();
  else renderWeaponForm();
}

// Page three: what you took, and your signature under it. This is the only one
// of the three that is a slip rather than a note, so it keeps the steps.
function renderGearPage() {
  if (notConfigured()) return;
  S.flow = 'gear';
  if (S.sStep === 1) renderGearIdent();
  else if (S.sStep === 2) renderSoldierStep2();
  else if (S.sStep === 3) renderSoldierConfirm();
  else renderSoldierDone();
}

/* The two later pages attach to a soldier who is already written down, which
   is why they ask for a personal number and not for a life story. If nobody
   has been registered under that number the answer is not an error message
   about a missing record — it is the page that fixes it. */
async function findSoldier(form, pn) {
  const rid = await deriveRid(pn, S.config.idSalt);
  const st = await api(`/status/${rid}`);
  if (!st.exists) {
    setFormErr(form, 'המספר האישי הזה עוד לא רשום — מלאו קודם "רישום פרטים אישיים" בתפריט');
    return null;
  }
  return rid;
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
      ${S.sharedPhoto && !shot
        ? `<button type="button" class="btn ghost lic-pick" data-act="lic-shared" data-kind="${kind.id}">
             📥 התמונה ששיתפתם
           </button>`
        : ''}
    </div>
    ${shot ? '' : `<p class="field-hint center">אין גלריה ברשימה שנפתחת? בחרו <strong>הקבצים שלי</strong> ← <strong>תמונות</strong>.</p>
         <p class="field-hint center mb0">התמונה מוצפנת במכשיר שלכם לפני השליחה — רק מנהל הציוד יוכל לפתוח אותה.</p>`}`;
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
          <span class="field-label">מספר רישיון <span class="req" aria-hidden="true">*</span></span>
          <input class="input num" data-act="lic-no" inputmode="numeric" autocomplete="off"
                 maxlength="20" value="${esc(S.licNo)}" placeholder="12345678">
        </label>
        <label class="field">
          <span class="field-label">בתוקף עד <span class="req" aria-hidden="true">*</span></span>
          <input class="input" type="date" data-act="lic-exp" value="${esc(S.licExp)}"
                 min="${DATE_MIN}" max="${DATE_MAX}">
          ${S.licExp && !inDateRange(S.licExp)
            ? '<span class="field-hint bad-hint">⚠ התאריך אינו תקין — בדקו את השנה.</span>'
            : S.licExp && st === 'expired'
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
    <section class="panel center-head">
      <img class="unit-badge" src="/logo.png" alt="סמל מסייעת 951">
      <h1 class="panel-title center">רישום פרטים אישיים</h1>
      <p class="panel-sub center">זה הרישום הראשון, ורק אחריו אפשר לרשום נשק או לחתום על ציוד. הפרטים מוצפנים במכשיר שלכם — רק מנהל הציוד יכול לקרוא אותם.</p>
      <form data-form="ident" novalidate>
        <!-- The weapon and accessory numbers below have always shown the shape
             they expect. These three did not, so the form opened with three
             empty boxes above three hinted ones and read as unfinished — and
             the phone field in particular gave no sign whether it wanted
             dashes, a country code or neither. -->
        <label class="field">
          <span class="field-label">מספר אישי</span>
          <input class="input num" name="pn" inputmode="numeric" autocomplete="off"
                 maxlength="9" value="${esc(v.pn)}" placeholder="1234567" required>
        </label>
        <label class="field">
          <span class="field-label">שם מלא</span>
          <input class="input" name="name" autocomplete="off" maxlength="60"
                 value="${esc(v.name)}" placeholder="ישראל ישראלי" required>
        </label>
        <label class="field">
          <span class="field-label">טלפון נייד</span>
          <input class="input num" name="phone" inputmode="tel" autocomplete="off"
                 maxlength="10" value="${esc(v.phone)}" placeholder="0501234567" required>
        </label>
        <label class="field">
          <span class="field-label">מחלקה</span>
          <select class="input select" name="dept" required>
            <option value="">— בחרו מחלקה —</option>
            ${deptOpts}
          </select>
        </label>
        <fieldset class="lic-set">
          <legend class="field-label">רישיונות נהיגה</legend>
          ${LIC_KINDS.map(licBlock).join('')}
        </fieldset>

        <p class="form-err" data-err></p>
        <button class="btn primary wide" type="submit">שליחה לאישור</button>
      </form>
      ${backToMenu()}
    </section>`, 'sign-1');
}

/* Registering a weapon. The numbers used to sit halfway down the sign-up form,
   between a soldier's phone number and their driving licence, and were filled
   in by people who had not been issued a weapon yet because the form asked. */
function renderWeaponForm() {
  const v = S.ident || { pn: '', name: '', weapon: '', amral: '', scope: '' };
  render(`
    <section class="panel center-head">
      <h1 class="panel-title center">רישום נשק</h1>
      <p class="panel-sub center">המספרים שעל הנשק והאמצעים שקיבלתם. אפשר למלא רק את מה שקיבלתם ולהשאיר את השאר ריק.</p>
      <form data-form="weapon" novalidate>
        <div class="grid2">
          <label class="field">
            <span class="field-label">מספר אישי</span>
            <input class="input num" name="pn" inputmode="numeric" autocomplete="off"
                   maxlength="9" value="${esc(v.pn)}" placeholder="1234567" required>
          </label>
          <label class="field">
            <span class="field-label">שם מלא</span>
            <input class="input" name="name" autocomplete="off" maxlength="60"
                   value="${esc(v.name)}" placeholder="ישראל ישראלי" required>
          </label>
        </div>
        <fieldset class="lic-set">
          <legend class="field-label">נשק ואמצעים נלווים</legend>
          <div class="grid2">
            <label class="field">
              <span class="field-label">מספר סידורי של הנשק</span>
              <input class="input num" name="weapon" data-act="ser-chk" data-f="weapon" autocomplete="off" maxlength="20"
                     value="${esc(v.weapon || '')}" placeholder="1234567">
              ${serialWarnBox('weapon')}
            </label>
            <label class="field">
              <span class="field-label">מספר אקילה</span>
              <input class="input num" name="amral" data-act="ser-chk" data-f="amral" autocomplete="off" maxlength="20"
                     value="${esc(v.amral || '')}" placeholder="1234567">
              ${serialWarnBox('amral')}
            </label>
            <label class="field">
              <span class="field-label">מספר כוונת</span>
              <input class="input num" name="scope" data-act="ser-chk" data-f="scope" autocomplete="off" maxlength="20"
                     value="${esc(v.scope || '')}" placeholder="1234567">
              ${serialWarnBox('scope')}
            </label>
          </div>
          <span class="field-hint">אם לא קיבלתם — אפשר להשאיר ריק.</span>
        </fieldset>
        <p class="form-err" data-err></p>
        <button class="btn primary wide" type="submit">שליחה לאישור</button>
      </form>
      ${backToMenu()}
    </section>`, 'weapon-1');
}

// Signing for kit starts by saying who is signing.
function renderGearIdent() {
  const v = S.ident || { pn: '', name: '' };
  render(`
    ${stepsBar(1)}
    <section class="panel center-head">
      <h1 class="panel-title center">חתימה על ציוד</h1>
      <p class="panel-sub center">מי חותם, מה קיבלתם, וחתימה. אפשר לחתום שוב בכל פעם שמקבלים ציוד נוסף.</p>
      <form data-form="gear-ident" novalidate>
        <label class="field">
          <span class="field-label">מספר אישי</span>
          <input class="input num" name="pn" inputmode="numeric" autocomplete="off"
                 maxlength="9" value="${esc(v.pn)}" placeholder="1234567" required>
        </label>
        <label class="field">
          <span class="field-label">שם מלא</span>
          <input class="input" name="name" autocomplete="off" maxlength="60"
                 value="${esc(v.name)}" placeholder="ישראל ישראלי" required>
        </label>
        <p class="form-err" data-err></p>
        <button class="btn primary wide" type="submit">המשך</button>
      </form>
      ${backToMenu()}
    </section>`, 'gear-1');
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
        ${[['מספר נשק', v.weapon], ['מספר אקילה', v.amral], ['מספר כוונת', v.scope]]
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
      ${signPad()}

      <p class="form-err" data-err></p>
      <button class="btn primary wide" data-act="s-submit">אישור ושליחה</button>
      <button class="btn ghost wide mt" data-act="s-edit">חזרה לעריכת הציוד</button>
    </section>`, 'sign-3');
  mountSignPad();
}

/* ── Signing for it ────────────────────────────────────────────────────
   A finger on the screen, on the last page, next to the list of what is
   being signed for. It is the soldier's own hand and it is what makes the
   slip a slip rather than a form somebody filled in.

   The drawing is sealed like a licence photo and rides in the docs table:
   the console never pulls it while listing soldiers, and the server holds a
   picture it cannot see. It is a PNG because a signature is line art — black
   on white compresses to a few kilobytes and stays sharp, which JPEG does
   not manage at that size.

   Nothing here is a verified signature in the cryptographic sense, and it is
   not sold as one. It is the paper equivalent: a mark the person made, held
   next to what they made it on. */
function signPad() {
  return `
    <fieldset class="lic-set">
      <legend class="field-label">חתימה <span class="req" aria-hidden="true">*</span></legend>
      <p class="field-hint">חתמו באצבע במסגרת. זו החתימה שלכם על הציוד שלמעלה.</p>
      <div class="sigwrap">
        <canvas class="sigpad" width="600" height="220"
                aria-label="שדה חתימה — ציירו את חתימתכם באצבע"></canvas>
        ${S.sig ? '' : '<span class="sig-hint" aria-hidden="true">חתמו כאן</span>'}
      </div>
      <div class="rec-actions">
        <button type="button" class="btn ghost small" data-act="sig-clear">ניקוי החתימה</button>
        ${S.sig ? '<span class="fp mb0">✓ נחתם</span>' : ''}
      </div>
    </fieldset>`;
}

/* The canvas has to be wired after the HTML lands, and it draws with pointer
   events so a finger, a stylus and a mouse are all the same thing. The page
   must not scroll under the finger while it draws — that is `touch-action`,
   set in the stylesheet, and it is the whole reason this works on a phone. */
function mountSignPad() {
  const pad = $app.querySelector('.sigpad');
  if (!pad) return;
  const ctx = pad.getContext('2d');
  // The canvas is a fixed 600×220 buffer shown at whatever width the phone
  // has; drawing in buffer coordinates keeps the line the same weight on
  // every screen instead of hairline on a big one and fat on a small one.
  const scale = () => pad.width / pad.getBoundingClientRect().width;
  ctx.lineWidth = 2.5;
  ctx.lineCap = 'round';
  ctx.lineJoin = 'round';
  ctx.strokeStyle = '#14210f';
  if (S.sig && S.sig.preview) {
    const img = new Image();
    img.onload = () => ctx.drawImage(img, 0, 0);
    img.src = S.sig.preview;                       // came back from a re-render
  }

  let drawing = false;
  const at = (e) => {
    const r = pad.getBoundingClientRect();
    const k = scale();
    return [(e.clientX - r.left) * k, (e.clientY - r.top) * k];
  };
  pad.addEventListener('pointerdown', (e) => {
    drawing = true;
    pad.setPointerCapture(e.pointerId);
    const [x, y] = at(e);
    ctx.beginPath();
    ctx.moveTo(x, y);
    ctx.lineTo(x + 0.1, y);                        // a dot, so a tap leaves a mark
    ctx.stroke();
    hideSigHint();
  });
  pad.addEventListener('pointermove', (e) => {
    if (!drawing) return;
    const [x, y] = at(e);
    ctx.lineTo(x, y);
    ctx.stroke();
  });
  const end = () => {
    if (!drawing) return;
    drawing = false;
    captureSignature(pad);
  };
  pad.addEventListener('pointerup', end);
  pad.addEventListener('pointercancel', end);
  pad.addEventListener('pointerleave', end);
}

function hideSigHint() {
  const hint = $app.querySelector('.sig-hint');
  if (hint) hint.remove();
}

// Is there anything on it, or did a stray tap leave a single dot?
function padInk(pad) {
  const d = pad.getContext('2d').getImageData(0, 0, pad.width, pad.height).data;
  let n = 0;
  for (let i = 3; i < d.length; i += 4) if (d[i] > 0) n++;
  return n;
}

// Held as PNG bytes plus a data URL, so a re-render of the page can put the
// drawing back rather than asking for it again.
function captureSignature(pad) {
  return new Promise((resolve) => {
    if (padInk(pad) < 40) { resolve(null); return; }   // blank, or an accidental dot
    pad.toBlob(async (blob) => {
      if (!blob) { resolve(null); return; }
      const bytes = new Uint8Array(await blob.arrayBuffer());
      S.sig = { bytes, size: bytes.length, preview: pad.toDataURL('image/png') };
      resolve(S.sig);
    }, 'image/png');
  });
}

/* Reading the pad at the moment of sending, rather than trusting what the
   last stroke left behind. Turning a canvas into bytes is asynchronous, so a
   soldier who signs and presses send in the same breath could otherwise be
   told to sign — with their signature on the screen in front of them. */
async function ensureSignature() {
  const pad = $app.querySelector('.sigpad');
  if (pad) await captureSignature(pad);
  return S.sig;
}

function clearSignature() {
  S.sig = null;
  renderFlow();
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
  const serials = [['נשק', v.weapon], ['אקילה', v.amral], ['כוונת', v.scope]]
    .filter(([, n]) => n)
    .map(([k, n]) => `<span class="tagi">${k} <span class="num">${esc(n)}</span></span>`)
    .join('');
  /* Finishing one of the three pages is rarely finishing. Somebody who has
     just been written down is standing there to be issued a weapon, and the
     screen used to say "you may close this page" and offer no way anywhere —
     not even back to the menu, so the only way on was the browser's back
     button. Each page now points at the one that usually follows it. */
  const next = {
    details: [['#weapon', 'רישום נשק'], ['#gear', 'חתימה על ציוד']],
    weapon: [['#gear', 'חתימה על ציוד']],
    gear: [],
  }[S.flow] || [];
  const heading = { weapon: 'רישום הנשק נשלח', gear: 'החתימה נשלחה' }[S.flow] || 'הרישום נשלח';

  render(`
    ${stepsBar(4)}
    <section class="panel center">
      <div class="big-ok" aria-hidden="true"></div>
      <h1 class="panel-title">${esc(heading)}</h1>
      <p class="panel-sub">הרשומה נקלטה במצב <span class="state wait">ממתין לאישור</span> — מנהל הציוד יאשר אותה ויעדכן אתכם.</p>
      <div class="tags center">${list}</div>
      ${serials ? `<div class="tags center">${serials}</div>` : ''}
      <div class="fp num"><span aria-hidden="true">🔒</span><span class="fp-code">${esc(S.rid.slice(0, 16))}</span></div>
      ${next.length
        ? `<p class="muted-txt mt">${S.flow === 'details' ? 'קיבלתם נשק או ציוד? המשיכו מכאן:' : 'קיבלתם גם ציוד?'}</p>
           ${next.map(([href, label]) => `<a class="btn primary wide mt" href="${href}">${esc(label)}</a>`).join('')}`
        : '<p class="muted-txt mt">סיימנו — אפשר לסגור את הדף.</p>'}
      <button class="btn ghost wide mt" data-act="s-reset">תיקון ורישום מחדש</button>
      ${backToMenu()}
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
      ${backToMenu()}
    </section>`, 'login');
}

/* — console — */

const outstanding = (data) =>
  Object.values(data.items || {}).reduce((sum, it) => sum + (it.t - (it.r || 0)), 0);

/* Where a soldier stands on kit, in three states rather than two.
   Never having taken anything is not the same as having brought it back, and
   the tracking screen could only tell the difference by asking whether
   anything was outstanding — which is 'no' for both.

   It cost nothing while the sign-up was one form that asked for details and
   kit together: every approved record had items, so an empty one did not
   exist. Since the split it is the ordinary case — a soldier registers their
   details on Sunday and signs for kit whenever the quartermaster is free —
   and those soldiers were filed under 'הוחזר במלואו', behind a filter that
   opens on 'ציוד בחוץ'. They were on the roster and on no screen. */
const gearState = (data) =>
  (Object.keys(data.items || {}).length === 0 ? 'none' : outstanding(data) > 0 ? 'out' : 'done');

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
  { id: 'comms',   name: 'דוח קשר',      needs: ['vault'] },
  { id: 'tzelem',  name: 'דו״ח צלם',     needs: ['vault'] },
  { id: 'ammo',    name: 'תחמושת ואלפא', needs: ['vault'] },
  { id: 'veh',     name: 'רכבים',        needs: ['vault'] },
  { id: 'lic',     name: 'רישיונות נהיגה', needs: ['records'] },
  { id: 'sum',     name: 'דוחות',        needs: ['records'] },
  { id: 'wa',      name: 'וואטסאפ',      needs: [], adminOnly: true },
  { id: 'sec',     name: 'אבטחה',        needs: [], adminOnly: true },
];

const tabName = (id) => (TABS.find((t) => t.id === id) || {}).name || id;

// admin  — everything; editor — read and change, on granted screens only;
// viewer — read only, on granted screens only.
const ROLES = [
  { id: 'editor', name: 'קריאה ועריכה', hint: 'רואה ומשנה — אך רק במסכים שסימנתם' },
  { id: 'viewer', name: 'צפייה בלבד', hint: 'רואה בלבד, בלי לאשר, לערוך או למחוק' },
];
const roleName = (r) => r === 'admin' ? 'מנהל' : (ROLES.find((x) => x.id === r) || {}).name || r;
const canEdit = () => S.role !== 'viewer';

function allowedTabs() {
  if (S.role === 'admin') return TABS.map((t) => t.id);
  // editors and viewers alike see only what they were granted, never 'sec'
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
  // Signing in does not go back through the router — loginSubmit renders the
  // console directly — so the footer would still be offering the admin door
  // to someone standing inside it.
  document.body.classList.add('is-console');
  setFooterNav('admin');
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
    ['comms',   'דוח קשר',      commsAlerts() || commsCount() || null, commsAlerts() > 0],
    ['tzelem',  'דו״ח צלם',     null],
    ['ammo',    'תחמושת ואלפא', null],
    ['veh',     'רכבים',        (openRefuels() + vehAlerts()) || null, openRefuels() > 0],
    ['lic',     'רישיונות',     licAlerts() || null, licAlerts() > 0],
    ['sum',     'דוחות',        null],
    ['wa',      'וואטסאפ',      S.wa.loaded && S.wa.state !== 'authorized' ? '!' : null,
                                 S.wa.loaded && S.wa.enabled && S.wa.state !== 'authorized'],
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
  else if (S.tab === 'comms') body = renderCommsTab();
  else if (S.tab === 'tzelem') body = renderTzelemTab();
  else if (S.tab === 'ammo') body = renderAmmoTab();
  else if (S.tab === 'veh') body = renderVehTab();
  else if (S.tab === 'lic') body = renderLicTab();
  else if (S.tab === 'sum') body = renderSummaryTab();
  else if (S.tab === 'wa') body = renderWaTab();
  else body = renderSecurityTab();

  /* Asked afresh every time the screen is opened, then kept asking while a
     line is still being linked — see waPollStart(). Asking only once meant a
     line that had dropped since sign-in went on being reported as connected
     for as long as the console stayed open, and the row buttons went on
     claiming they would send. */
  if (S.tab === 'wa') {
    if (!waTabOpen) { waTabOpen = true; waRefresh(); }
    else if (S.wa.enabled && S.wa.state !== 'authorized') waPollStart();
    else waPollStop();
  } else {
    waTabOpen = false;
    waPollStop();
  }

  render(`
    <div class="conbar">
      <span class="conbar-title">${esc(title)}</span>
      <span class="who-tag">מחובר · ${esc(S.me || '')}</span>
      ${S.role !== 'admin' ? `<span class="ro-tag">${esc(roleName(S.role))}</span>` : ''}
      <div class="conbar-actions">
        ${S.tabHist.length
          ? `<button class="btn ghost small backbtn" data-act="tab-back">${ICO.back}חזרה</button>`
          : ''}
        <button class="btn ghost small" data-act="refresh">${ICO.refresh}רענון</button>
        <button class="btn ghost small" data-act="lock">${ICO.lock}נעילה</button>
      </div>
    </div>
    ${S.role !== 'admin'
      ? `<div class="callout"><p class="mb0">אתם מחוברים כ<strong>${esc(roleName(S.role))}</strong> (${esc(S.me)}) עם גישה ל${
          allowedTabs().length === 1 ? 'מסך ' : `-${allowedTabs().length} מסכים: `
        }<strong>${allowedTabs().map((t) => esc(tabName(t))).join(', ')}</strong>. ${
          S.role === 'viewer'
            ? 'אי אפשר לאשר, לערוך או למחוק'
            : 'אפשר לערוך במסכים האלה בלבד'
        } — השרת דוחה כל בקשה מחוץ להרשאה, לרבות ניהול משתמשים ואבטחה.</p></div>`
      : ''}
    ${c.damaged
      ? `<div class="callout risk"><p class="mb0"><strong class="num">${c.damaged}</strong> רשומות פגומות — הפענוח נכשל (חשד לשיבוש נתונים בשרת).</p></div>`
      : ''}
    <div class="console">
      <aside class="side">
        <div class="navlist" role="tablist">${nav}</div>
      </aside>
      <div class="cmain">${body}</div>
    </div>
    ${creditDialog()}`);
  if (S.role === 'viewer') stripWriteControls();
  autoDocs();
}

/* Photographs are fetched and decrypted only when asked for — a roster of a
   hundred soldiers must not drag a hundred images behind it. Opening one
   soldier's record is asking, though, so both their licences come down at
   once and appear as thumbnails, rather than making somebody press twice per
   licence to find out what is in them.

   Only buttons marked `data-auto` are fetched on sight, and only the record
   card marks them. The licence screen lists everybody at once, and the
   decrypted cache holds twelve images: auto-loading a table of a hundred
   soldiers would spend a hundred round trips to end up showing the last
   twelve. There you press, and the press brings both of that soldier's
   licences down together.

   Bounded by `docTried`: one attempt per photo per session, so a render
   triggered by the arrival of an image cannot ask for it again. */
function autoDocs() {
  for (const btn of $app.querySelectorAll('[data-act="doc"][data-auto][data-rid][data-kind]')) {
    const key = `${btn.dataset.rid}:${btn.dataset.kind}`;
    if (S.docs[key] || S.docTried.has(key)) continue;
    S.docTried.add(key);
    toggleDoc(btn.dataset.rid, btn.dataset.kind);
    return;                     // one at a time: each arrival re-renders anyway
  }
}

// Everything a viewer is allowed to touch. Anything else that can be clicked or
// typed into is removed after render — an allowlist rather than a list of
// forbidden actions, so a new write control is locked out by default rather
// than by remembering to add it. The server refuses the writes regardless;
// this only keeps the screen honest about what is possible.
const READ_ACTS = new Set([
  'tab', 'refresh', 'lock', 'page', 'filter', 'search', 'dept', 'collapse',
  'reveal', 'rep-reveal', 'doc', 'doc-zoom', 'lic-docs', 'expand', 'rep-filter', 'dep-filter', 'rf-filter',
  'flt-filter', 'arm-kind', 'fuel-open', 'fuel-doc', 'fuel-dl-one', 'fuel-dl-all',
  'rep-csv', 'rep-pdf', 'tz-wa',
]);

/* A viewer's screen, with everything they may not do taken off it.

   The question a button asks before it acts is not itself an action, so what
   matters is the action behind it: exporting a CSV stays, because a viewer
   may export; the ✕ on a row goes, because a viewer may not delete. Without
   that distinction every armed control would look the same to this and a
   viewer would lose their export buttons. */
function stripWriteControls() {
  for (const el of $app.querySelectorAll('[data-act]')) {
    const act = el.dataset.for || el.dataset.act;   // what it will do, not that it asks
    if (READ_ACTS.has(act) || /(^|-)(search|qclear|export)$/.test(act)) continue;
    if (act === 'ask-cancel') continue;
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

/* Two letters in a circle, in front of the name.

   A roster is read by looking for one soldier in a column of forty, and forty
   names in the same weight and the same colour give the eye nothing to aim
   at. An initial is found by shape before it is read, which is what makes the
   second pass down a list faster than the first. */
const initials = (name) => {
  const parts = String(name || '').trim().split(/\s+/).filter(Boolean);
  if (!parts.length) return '··';
  return parts[0].slice(0, 1) + (parts[1] ? parts[1].slice(0, 1) : '');
};

const avatar = (name) => `<span class="ava" aria-hidden="true">${esc(initials(name))}</span>`;

// A department reads as a label, not as prose: a soldier belongs to one, it is
// the same word on every row, and it wants a shape rather than another line in
// the same weight as the name beside it.
const deptPill = (dept) => {
  const name = deptName(dept);
  return name ? `<span class="pill">${esc(name)}</span>` : '<span class="dim">—</span>';
};

/* ── The cards a record's drawer is made of ────────────────────────────
   Same 24-grid and stroke as every other icon here, so a heading in a
   drawer weighs the same as the chevron that opened it. */
const DICO = {
  person: `${SVG_OPEN}<circle cx="12" cy="8" r="3.6"/><path d="M5 20a7 7 0 0 1 14 0"/></svg>`,
  box: `${SVG_OPEN}<path d="M3.5 7.5 12 3l8.5 4.5v9L12 21l-8.5-4.5z"/><path d="M3.5 7.5 12 12l8.5-4.5M12 12v9"/></svg>`,
  folder: `${SVG_OPEN}<path d="M3 6.5h6l2 2.5h10v9.5a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 18.5z"/></svg>`,
  bolt: `${SVG_OPEN}<path d="M13 2 4.5 13.5H11L10 22l8.5-11.5H12z"/></svg>`,
  wa: `${SVG_OPEN}<path d="M20.5 11.5a8.5 8.5 0 0 1-12.6 7.4L3.5 20.5l1.6-4.3A8.5 8.5 0 1 1 20.5 11.5z"/></svg>`,
  check: `${SVG_OPEN}<path d="M4 12.5 9.5 18 20 6.5"/></svg>`,
  pen: `${SVG_OPEN}<path d="M4 20h4L19 9a2.1 2.1 0 0 0-3-3L5 17z"/><path d="M14.5 6.5 17.5 9.5"/></svg>`,
};

// A titled box in the drawer's grid. `body` is already-built HTML.
const dcard = (title, icon, body, cls = '') => `
  <section class="dcard${cls ? ` ${cls}` : ''}">
    <h4 class="dcard-h"><span class="dcard-i" aria-hidden="true">${icon}</span>${esc(title)}</h4>
    <div class="dcard-b">${body}</div>
  </section>`;

// A labelled line inside one. The label is text and is escaped here; the value
// is markup the caller has already escaped, because most of them carry a
// `.num` span or a button and would otherwise have to be assembled twice.
const dfield = (label, value) =>
  `<div class="dfield"><span class="dfield-l">${esc(label)}</span><span class="dfield-v">${value}</span></div>`;

// Weapon serial + licence chips, with an on-demand viewer for the photos.
// Images are fetched and decrypted only when the admin asks for one.
function extrasRow(rec) {
  const serials = [
    ['נשק', rec.data.weapon], ['אקילה', rec.data.amral], ['כוונת', rec.data.scope],
  ].filter(([, v]) => v);
  return (serials.length
    ? `<div class="rec-meta">${serials
      .map(([k, v]) => `${k} <span class="num">${esc(v)}</span>`)
      .join(' · ')}</div>`
    : '') + docsRow(rec);
}

/* The licences and the signature on their own, without the serials in front
   of them. The drawer's cards print the serials under the soldier's personal
   details, where they belong, and printing them twice made the documents card
   open on two catalogue numbers. The pending screen still wants both together,
   which is what extrasRow is now. */
function docsRow(rec) {
  const d = rec.data;
  const bits = [];
  const lic = d.lic || {};
  const chips = LIC_KINDS.filter((k) => lic[k.id] && lic[k.id].has).map((k) => {
    const key = `${rec.rid}:${k.id}`;
    const shown = S.docs[key];
    const hasDoc = lic[k.id].doc;
    /* The soldier types a licence number and an expiry date, and this card
       showed neither — only a tick and a link to a photograph. To read the two
       facts the form had asked for, an admin had to open the image and read
       them off it, or go to another tab entirely. They are printed here now,
       and the date carries its own verdict: a licence that has run out is not
       a date, it is a problem, and it should not need arithmetic to see. */
    const info = k.id === 'civil' ? lic.civil : null;
    const st = info ? licState(info.exp) : null;
    const stTone = { expired: 'bad', soon: 'warn' }[st] || '';
    const stWord = { expired: 'פג תוקף', soon: 'פג בקרוב', nodate: 'ללא תאריך' }[st] || '';
    /* Two lines, not one wrapping run. What it is and whether it is valid
       belong together on top; the number, the date and the photograph are
       details underneath. Left as a single flex row it broke wherever the
       words happened to end on a phone — the verdict landing between the date
       and the photo link, reading as three unrelated fragments. */
    return `
      <div class="licv">
        <div class="licv-head">
          <span class="tagi lic-chip">✓ ${esc(k.short)}</span>
          ${stWord ? `<span class="state ${stTone === 'bad' ? 'live' : stTone === 'warn' ? 'wait' : 'done'}">${esc(stWord)}</span>` : ''}
        </div>
        <div class="licv-body">
          ${info && info.no ? `<span class="lic-f">מס׳ <span class="num">${esc(info.no)}</span></span>` : ''}
          ${info && info.exp
            ? `<span class="lic-f">בתוקף עד <span class="num">${esc(fmtDay(info.exp))}</span></span>`
            : info ? '<span class="lic-f muted-txt">ללא תאריך תוקף</span>' : ''}
          ${hasDoc
            ? (shown
                ? ''
                : `<button class="linkbtn" data-act="doc" data-auto="1" data-rid="${esc(rec.rid)}" data-kind="${k.id}">הצגת צילום</button>`)
            : '<span class="muted-txt">ללא צילום</span>'}
        </div>
        ${shown
          ? `<button class="lic-shot-btn" type="button" data-act="doc-zoom"
                     data-rid="${esc(rec.rid)}" data-kind="${k.id}"
                     aria-label="${S.docBig.has(key) ? 'הקטנת' : 'הגדלת'} צילום ${esc(k.short)}">
               <img class="doc-img${S.docBig.has(key) ? ' big' : ''}" src="${shown}"
                    alt="צילום ${esc(k.short)}">
             </button>`
          : ''}
      </div>`;
  });
  if (chips.length) bits.push(`<div class="licv-wrap">${chips.join('')}</div>`);

  // The soldier's own hand on the slip. Opened only when asked for, like the
  // licences — it is an image, and a roster should not drag images around.
  if (d.signed) {
    const key = `${rec.rid}:signature`;
    const shown = S.docs[key];
    bits.push(`
      <div class="licv">
        <span class="tagi lic-chip">✍ נחתם ${esc(fmtDate(d.signed))}</span>
        <button class="linkbtn" data-act="doc" data-rid="${esc(rec.rid)}" data-kind="signature">${
          shown ? 'הסתרה' : 'הצגת החתימה'
        }</button>
        ${shown ? `<img class="doc-img sig-img" src="${shown}" alt="חתימת ${esc(d.name)}">` : ''}
      </div>`);
  }
  return bits.join('');
}

/* ── Correcting what a soldier typed ───────────────────────────────────
   The form is filled in on a phone, in the dark, by someone in a hurry, so
   a wrong digit in a personal number or a weapon serial is routine. The
   editor lives inside the record's own drawer and re-seals the record on
   save; nothing is written until then, so closing it changes nothing.

   `rid` is derived from the personal number and is what stops the same
   soldier filing twice, so it cannot follow a correction — the record
   keeps the id it was created under. That matters only if the number was
   wrong from the start, and the note in the editor says so. */

function recEditor(rec) {
  const d = S.recDraft || {};
  if (S.recEdit !== rec.rid) {
    return `<div class="rec-meta">
      <button class="linkbtn" data-act="rec-edit" data-rid="${esc(rec.rid)}">✎ תיקון פרטים</button>
    </div>`;
  }
  const f = (name, label, value, extra = '') => `
    <label class="field mb0">
      <span class="field-label">${esc(label)}</span>
      <input class="input mini${extra.includes('num') ? ' num' : ''}" type="text"
             value="${esc(value)}" data-act="rec-f" data-k="${name}" maxlength="60"
             aria-label="${esc(label)}">
    </label>`;
  return `
    <div class="receditor">
      <div class="fuel-entry">
        ${f('name', 'שם מלא', d.name)}
        ${f('pn', 'מספר אישי', d.pn, 'num')}
        ${f('phone', 'טלפון', d.phone, 'num')}
        <label class="field mb0">
          <span class="field-label">מחלקה</span>
          <select class="input mini select-mini" data-act="rec-f-dept" aria-label="מחלקה">
            <option value="">—</option>
            ${DEPTS.map((x) => `<option value="${x.id}"${d.dept === x.id ? ' selected' : ''}>${esc(x.name)}</option>`).join('')}
          </select>
        </label>
      </div>
      <div class="fuel-entry">
        ${f('weapon', 'מספר נשק', d.weapon, 'num')}
        ${f('amral', 'מק״ט אקילה', d.amral, 'num')}
        ${f('scope', 'מק״ט כוונת', d.scope, 'num')}
      </div>
      <p class="field-hint">המספר האישי מזהה את הרשומה במערכת. תיקון שלו משנה את מה שמוצג ומיוצא לדוחות, אך הרשומה נשארת תחת המזהה שנוצר בהרשמה.</p>
      <div class="rec-actions">
        <button class="btn primary small" data-act="rec-save" data-rid="${esc(rec.rid)}">שמירת התיקון</button>
        <button class="btn ghost small" data-act="rec-cancel">ביטול</button>
      </div>
    </div>`;
}

/* The same correction for a report, a deposit or a building fault. Which
   fields it offers follows the kind — a deposit carries serial numbers, a
   fault carries none — and the free text is always correctable, since that
   is where a soldier in a hurry gets it wrong most often. */
// The link that opens it sits with the row's other actions; the form itself
// needs a block of its own, so they are separate pieces.
const repEditLink = (rec) =>
  `<button class="linkbtn" data-act="${S.repEdit === rec.id ? 'rep-cancel' : 'rep-edit'}"
           data-id="${esc(rec.id)}">${S.repEdit === rec.id ? 'סגירה' : '✎ תיקון פרטים'}</button>`;

function repEditor(rec) {
  if (S.repEdit !== rec.id) return '';
  const d = S.repDraft || {};
  const f = (name, label, num = false) => `
    <label class="field mb0">
      <span class="field-label">${esc(label)}</span>
      <input class="input mini${num ? ' num' : ''}" type="text" maxlength="60"
             value="${esc(d[name] || '')}" data-act="rep-f" data-k="${name}" aria-label="${esc(label)}">
    </label>`;
  return `
    <div class="receditor">
      <div class="fuel-entry">
        ${f('name', 'שם המדווח')}
        ${f('phone', 'טלפון', true)}
        ${d.kind === 'report' ? f('pn', 'מספר אישי', true) : ''}
      </div>
      ${d.kind === 'deposit'
        ? `<div class="fuel-entry">
             ${f('weapon', 'מספר נשק', true)}
             ${f('amral', 'מק״ט אקילה', true)}
             ${f('scope', 'מק״ט כוונת', true)}
           </div>`
        : ''}
      <label class="field">
        <span class="field-label">${d.kind === 'fault' ? 'תיאור התקלה' : 'תוכן הדיווח'}</span>
        <textarea class="input area" rows="3" maxlength="1500"
                  data-act="rep-f" data-k="text">${esc(d.text || '')}</textarea>
      </label>
      <div class="rec-actions">
        <button class="btn primary small" data-act="rep-save" data-id="${esc(rec.id)}">שמירת התיקון</button>
        <button class="btn ghost small" data-act="rep-cancel">ביטול</button>
      </div>
    </div>`;
}

function phoneRow(rec) {
  const shown = S.revealed.has(rec.rid);
  return `<div class="rec-meta">טלפון:
    <span class="num">${esc(shown ? rec.data.phone : maskPhone(rec.data.phone))}</span>
    <button class="linkbtn" data-act="reveal" data-rid="${esc(rec.rid)}">${shown ? 'הסתרה' : 'הצגה'}</button>
  </div>`;
}

// Dense tables show the day only — the clock time is in the expanded row.
const fmtShort = (ms) => {
  if (!ms) return '—';
  const d = new Date(ms);
  return `${d.getDate()}.${d.getMonth() + 1}.${String(d.getFullYear()).slice(2)}`;
};

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
// `data` carries whatever the handler needs to know which list it is searching
// — two registers share one search action and are told apart by it.
/* ── Removing a row ────────────────────────────────────────────────────
   Anything entered by hand can be entered wrongly, so every row in the
   console can be deleted — and the row itself is what asks, never a
   browser dialog. The first press arms that one row; the confirm is a
   second, differently labelled control, so a mis-tap on ✕ cannot delete
   anything. Arming a row disarms whichever was armed before, so there is
   never more than one live "yes" on the screen. */

function delCell(key, act, data = {}, label = '✕', aria = 'מחיקה', note = '') {
  if (S.askDel !== key) {
    return `<button class="linkbtn danger-link" data-act="ask-del" data-key="${esc(key)}"
                    data-for="${esc(act)}" aria-label="${esc(aria)}" title="${esc(aria)}">${label}</button>`;
  }
  const attrs = Object.entries(data).map(([k, v]) => ` data-${k}="${esc(v)}"`).join('');
  return `<span class="delask">
      <span class="delask-q">${esc(note || 'למחוק?')}</span>
      <button class="btn danger small" data-act="${esc(act)}"${attrs}>כן, למחוק</button>
      <button class="linkbtn" data-act="ask-cancel">ביטול</button>
    </span>`;
}

/* The same question, for a button that is not a row.

   Bulk approval, wiping the database, marking a fuel card credited, exporting
   a file that is not encrypted — all of these asked with window.confirm, a
   browser dialog nobody asked for and which on a phone covers the screen it
   is asking about. This is the row-delete pattern widened: the button turns
   into the question, in the place the button was, and answering it is a
   second, differently labelled control.

   `tone` picks the confirm button's colour, because "yes, wipe everything"
   and "yes, export" do not deserve the same red. */
function askBtn(key, act, label, note, { data = {}, yes = 'אישור', tone = 'primary', cls = 'btn ghost' } = {}) {
  if (S.askDel !== key) {
    return `<button class="${cls}" data-act="ask-del" data-key="${esc(key)}"
                    data-for="${esc(act)}">${label}</button>`;
  }
  const attrs = Object.entries(data).map(([k, v]) => ` data-${k}="${esc(v)}"`).join('');
  return `<span class="delask">
      <span class="delask-q">${esc(note)}</span>
      <button class="btn ${tone} small" data-act="${esc(act)}"${attrs}>${esc(yes)}</button>
      <button class="linkbtn" data-act="ask-cancel">ביטול</button>
    </span>`;
}

function plainSearch(act, clearAct, value, placeholder, total, shown, data = {}) {
  const attrs = Object.entries(data).map(([k, v]) => ` data-${k}="${esc(v)}"`).join('');
  return `
    <div class="search">
      <input class="input search-in" type="search" data-act="${act}"${attrs} value="${esc(value)}"
             placeholder="${esc(placeholder)}" autocomplete="off" enterkeyhint="search">
      ${value ? `<button class="linkbtn search-clear" data-act="${clearAct}"${attrs}>ניקוי</button>` : ''}
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
// sees the phone number, so this is the only way to notify a soldier that
// keeps the encryption intact. Opened in a new tab so the console keeps its
// in-memory key.
//
// There used to be a second path here: the Worker calling Meta's Cloud API so
// the message went out by itself on approval. It is gone. It required a
// business registration this unit cannot get, so it never sent anything —
// every approval spent a network round trip to be told 'not_configured' and
// then apologised for it on screen. It was also the one place where a name, a
// phone number and an equipment list left the browser in the clear. Removing
// it means nothing readable leaves this system at all.
/* The text and the way it travels are two different things. The same message
   either opens in the sender's own WhatsApp (wa.me) or goes out over the
   unit's linked line (GREEN-API) — so it is built once, here, and the caller
   decides how it leaves.

   Every one of these says what happened and nothing else. They used to carry
   kit lists, serial numbers and registration numbers, which was defensible
   while a message only ever opened in the sender's own WhatsApp. They go out
   over a third party's servers now, so a message says only what a soldier
   needs in order to know where they stand. Whoever needs the detail has the
   console.

   One heading per subject, deliberately: a soldier who gets four of these in a
   week has to be able to tell at a glance which is which. */
const WA_HEAD = {
  full:     'אישור רישום ראשוני',
  details:  'עדכון פרטים אישיים',
  weapon:   'רישום נשק',
  gear:     'חתימה על ציוד',
  deposit:  'אפסון נשק',
  credit:   'זיכוי ציוד',
  fault:    'תקלת בינוי',
  report:   'בקשת ציוד',
};

const waMsg = (topic, name, body) =>
  `*${WA_HEAD[topic]} — מסייעת 951*\n\nשלום ${name},\n${body}`;

// Approval of a submission. Which submission it was decides what it says —
// "הרישום בוצע בהצלחה" under a weapon registration would tell the soldier
// nothing about the thing they actually sent in.
const SIGN_BODY = {
  full:    'הרישום בוצע בהצלחה',
  details: 'הפרטים האישיים שלך עודכנו בהצלחה',
  weapon:  'רישום הנשק נקלט בהצלחה',
  gear:    'החתימה על הציוד נקלטה בהצלחה',
};

const waSignMsg = (d) =>
  waMsg(SIGN_BODY[d.kind] ? d.kind : 'full', d.name, SIGN_BODY[d.kind] || SIGN_BODY.full);

// The weapon reached the armoury and is no longer the soldier's responsibility.
const waDepositMsg = (d) =>
  waMsg('deposit', d.name, 'הנשק שאפסנת נקלט בארמון ורשום שם על שמך');

// A building fault, once somebody has actually dealt with it.
const waFaultMsg = (d, st) =>
  waMsg('fault', d.name, st === 'done'
    ? 'התקלה שדיווחת טופלה'
    : 'התקלה שדיווחת הועברה לטיפול');

// A shortage request. Partial is its own answer: something arrived, the rest
// has not, and saying "טופל" would be a lie the soldier finds out about later.
const waReportMsg = (d, st) =>
  waMsg('report', d.name, st === 'done'
    ? 'הבקשה שהגשת טופלה במלואה'
    : 'הבקשה שהגשת טופלה חלקית — היתרה תושלם בהמשך');

const waLink = (d) =>
  `https://wa.me/${waPhone(d.phone)}?text=${encodeURIComponent(waSignMsg(d))}`;

/* Return receipt. Whether anything is still outstanding is the one fact worth
   carrying — it is what the soldier would otherwise have to come and ask, and
   it is a count, not an inventory. */
function waReturnMsg(d) {
  const left = ITEMS.filter((i) => d.items[i.id])
    .reduce((n, i) => n + (d.items[i.id].t - (d.items[i.id].r || 0)), 0);
  return waMsg('credit', d.name, left > 0
    ? `הציוד שהחזרת זוכה על שמך. עדיין רשומים עליך ${left} פריטים`
    : 'הציוד שהחזרת זוכה על שמך. אין ציוד נוסף הרשום עליך — החשבון סגור');
}

const returnWaLink = (d) =>
  `https://wa.me/${waPhone(d.phone)}?text=${encodeURIComponent(waReturnMsg(d))}`;

function damagedCard(rec) {
  return `
    <article class="rec broken">
      <header class="rec-head">
        <div class="rec-name">רשומה פגומה</div>
        <span class="state live">שגיאה</span>
      </header>
      <p class="muted-txt">לא ניתן לפענח את הרשומה — ייתכן שהנתונים שובשו בצד השרת.</p>
      <div class="rec-actions">
        ${delCell(`rec:${rec.rid}`, 'del', { rid: rec.rid }, 'מחיקה', 'מחיקת הרשומה')}
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
        <span class="state wait">${esc(KIND_TAG[d.kind] || (d.supp ? 'השלמה' : 'ממתין'))}</span>
      </header>
      ${d.supp
        ? `<p class="muted-txt">${esc(KIND_NOTE[d.kind] || 'השלמת ציוד — באישור, הפריטים יתווספו לרישום המאושר הקיים של החייל.')}</p>`
        : ''}
      ${phoneRow(rec)}
      ${extrasRow(rec)}
      ${recEditor(rec)}
      <ul>${rows}</ul>
      <div class="rec-actions">
        ${approveBtn(rec, 'btn primary')}
        ${delCell(`rec:${rec.rid}`, 'del', { rid: rec.rid }, 'מחיקה', 'מחיקת הרשומה')}
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
            ${avatar(d.name)}<span class="rowlink-n">${esc(d.name)}</span><span class="row-caret" aria-hidden="true">${open ? '▾' : '◂'}</span>
          </button>
          ${d.supp ? `<span class="tagi supp">${esc(KIND_TAG[d.kind] || 'השלמה')}</span>` : ''}
        </td>
        <td class="num">${esc(d.pn)}</td>
        <td>${esc(deptName(d.dept))}</td>
        <td class="chips">${itemChips(d, 'pending') || '<span class="dim">—</span>'}</td>
        <td class="num">${esc(fmtShort(d.createdAt))}</td>
        <td class="nowrap">
          ${approveBtn(rec, 'btn primary small')}
          ${delCell(`rec:${rec.rid}`, 'del', { rid: rec.rid }, 'מחיקה', 'מחיקת הרשומה')}
        </td>
      </tr>
      ${open ? `<tr class="sub"><td colspan="7">${pendingDetail(rec)}</td></tr>` : ''}`;
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
             ${askBtn('bulk-approve', 'bulk-approve', 'אישור המסומנים',
               bulkApproveNote(), { yes: 'כן, לאשר', cls: 'btn primary small' })}
             ${askBtn('bulk-del', 'bulk-del', 'מחיקת המסומנים',
               `למחוק ${S.picked.size} רישומים? הפעולה אינה הפיכה.`,
               { yes: 'כן, למחוק', tone: 'danger', cls: 'btn danger small' })}
             <button class="linkbtn" data-act="pick-clear">ניקוי הבחירה</button>`
          : '<span class="muted-txt">סמנו שורות כדי לאשר או למחוק כמה יחד</span>'}
      </div>
      ${p.slice.length
        ? `<div class="tbl-scroll">
             <table class="tbl roster" data-phone="0,1,-1">
               <thead><tr>
                 <th class="col-pick"></th>
                 ${sortTh('name', 'שם')}
                 ${sortTh('pn', 'מ״א', 'num')}
                 ${sortTh('dept', 'מחלקה')}
                 ${sortTh('items', 'ציוד')}
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
  if (S.recEdit === rec.rid) {
    return `<div class="rowdetail">${recEditor(rec)}${fpStrip(rec.rid)}</div>`;
  }

  const shown = S.revealed.has(rec.rid);
  const serials = [['נשק', d.weapon], ['אקילה', d.amral], ['כוונת יום', d.scope]]
    .filter(([, v]) => v);
  const docs = docsRow(rec);

  /* Only the fields this submission actually carries.
     The sign-up is three forms now, and each asks for a third of what the old
     one did — so a soldier signing for kit sends no telephone number, and the
     drawer printed an empty one anyway, next to a mask with nothing behind it
     and a הצגה that revealed the same nothing. A form that was not asked is
     not a blank to be filled in later; it is not part of this submission, and
     the card it would have gone in does not appear either. */
  const who = [
    d.name && dfield('שם מלא', esc(d.name)),
    d.pn && dfield('מספר אישי', `<span class="num">${esc(d.pn)}</span>`),
    d.dept && dfield('מחלקה', esc(deptName(d.dept))),
    d.phone && dfield('טלפון', `<span class="num">${esc(shown ? d.phone : maskPhone(d.phone))}</span>
      <button class="linkbtn" data-act="reveal" data-rid="${esc(rec.rid)}">${shown ? 'הסתרה' : 'הצגה'}</button>`),
    dfield('נשלח', esc(fmtDate(d.createdAt))),
  ].filter(Boolean).join('');

  const cards = [
    dcard('פרטי החייל', DICO.person, who),
    serials.length
      ? dcard('נשק ואמצעים', DICO.bolt,
        serials.map(([k, v]) => dfield(k, `<span class="num">${esc(v)}</span>`)).join(''))
      : '',
    rows ? dcard('ציוד לאישור', DICO.box, `<ul class="dkit">${rows}</ul>`) : '',
    docs ? dcard('מסמכים ורישיונות', DICO.folder, docs) : '',
    dcard('פעולות', DICO.pen, `
      <button class="dact" data-act="rec-edit" data-rid="${esc(rec.rid)}">
        ${DICO.pen}<span>תיקון פרטים</span></button>
      <p class="dempty">האישור והמחיקה נמצאים בשורה עצמה.</p>`, 'is-acts'),
  ].filter(Boolean).join('');

  return `
    <div class="rowdetail">
      ${d.kind && d.kind !== 'full'
        ? `<p class="dkind">${esc(KIND_TAG[d.kind] || '')}${
            KIND_NOTE[d.kind] ? ` · ${esc(KIND_NOTE[d.kind].split(' — ')[1] || '')}` : ''
          }</p>`
        : ''}
      ${d.supp && !KIND_NOTE[d.kind]
        ? '<p class="dkind">השלמת ציוד — באישור, הפריטים יתווספו לרישום המאושר הקיים של החייל.</p>'
        : ''}
      <div class="dgrid">${cards}</div>
      ${fpStrip(rec.rid)}
    </div>`;
}

function renderTrackTab() {
  const approved = S.recs.filter((r) => r.status === 'approved');
  // Counted before the filter is applied, so each button can say how many are
  // behind it — including the one you are not looking at.
  const tally = { out: 0, none: 0, done: 0 };
  for (const rec of approved) tally[gearState(rec.data)] += 1;

  const filters = [
    ['out', 'ציוד בחוץ', tally.out],
    ['none', 'טרם חתם על ציוד', tally.none],
    ['done', 'הוחזר במלואו', tally.done],
    ['all', 'הכל', approved.length],
  ]
    .map(
      ([id, label, n]) =>
        `<button class="filter" aria-pressed="${S.filter === id}" data-act="filter" data-filter="${id}">${label}${
          n ? ` <span class="filter-n num">${n}</span>` : ''
        }</button>`
    )
    .join('');

  const visible = sortRecs(
    applyFilters(approved).filter(
      (rec) => S.filter === 'all' || gearState(rec.data) === S.filter
    ),
    S.sort.key === 'date' ? 'approved' : S.sort.key
  );

  const broken = approved.filter((r) => r.damaged).map(damagedCard).join('');
  const p = paged('track', visible);

  const rows = p.slice.map((rec) => {
    const d = rec.data;
    const out = outstanding(d);
    const st = gearState(d);
    const open = S.expanded.has(rec.rid);
    return `
      <tr class="${open ? 'is-open' : ''}${st === 'done' ? ' row-done' : st === 'none' ? ' row-nokit' : ''}">
        <td class="lg-name">
          <button class="rowlink" data-act="expand" data-rid="${esc(rec.rid)}">
            ${avatar(d.name)}<span class="rowlink-n">${esc(d.name)}</span><span class="row-caret" aria-hidden="true">${open ? '▾' : '◂'}</span>
          </button>
        </td>
        <td class="num">${esc(d.pn)}</td>
        <td>${deptPill(d.dept)}</td>
        <td class="chips">${
          st === 'none'
            ? '<span class="nokit">טרם חתם על ציוד</span>'
            : itemChips(d, 'track') || '<span class="dim">—</span>'
        }</td>
        <td class="num ${st === 'out' ? 'warn' : st === 'none' ? 'dim' : 'ok'}">${
          st === 'out' ? out : st === 'none' ? '·' : '✓'
        }</td>
        <td class="num">${esc(fmtShort(d.approvedAt))}</td>
        <td class="num">${d.notified ? '<span class="sent">✓</span>' : '<span class="unsent">—</span>'}</td>
        <td class="nowrap">
          <span class="rowacts">
            ${out > 0
              ? `<button class="iconbtn ok" data-act="creditall" data-rid="${esc(rec.rid)}"
                         title="זיכוי מלא" aria-label="זיכוי מלא — ${esc(d.name)}">${DICO.check}</button>`
              : ''}
            <a class="iconbtn wa" href="${esc(waLink(d))}" data-act="wa-sign"
               data-rid="${esc(rec.rid)}" target="_blank" rel="noopener noreferrer"
               title="${waAuto() ? 'שליחת וואטסאפ מהקו — יוצא מיד' : 'שליחת וואטסאפ'}"
               aria-label="שליחת וואטסאפ ל${esc(d.name)}">${DICO.wa}</a>
            ${delCell(`rec:${rec.rid}`, 'del', { rid: rec.rid }, '✕', 'מחיקת הרשומה',
                      'למחוק את הרשומה?')}
          </span>
        </td>
      </tr>
      ${open ? `<tr class="sub"><td colspan="8">${trackDetail(rec)}</td></tr>` : ''}`;
  }).join('');

  return `
    ${searchBar(approved.length, visible.length)}
    <div class="filters">${filters}</div>
    ${broken}
    <section class="panel">
      <h2 class="panel-title">מעקב ציוד</h2>
      <p class="panel-sub">שורה לכל חייל. עמודת הציוד מראה כמה עדיין אצלו מתוך מה שהוחתם; ✓ = הוחזר במלואו, · = טרם חתם על ציוד כלל. לחיצה על השם פותחת את הזיכוי פריט־פריט.</p>
      ${p.slice.length
        ? `<div class="tbl-scroll">
             <table class="tbl roster" data-phone="0,4,-1">
               <thead><tr>
                 ${sortTh('name', 'שם')}
                 ${sortTh('pn', 'מ״א', 'num')}
                 ${sortTh('dept', 'מחלקה')}
                 <th>ציוד — אצלו / הוחתם</th>
                 ${sortTh('out', 'בחוץ', 'num')}
                 ${sortTh('approved', 'אושר', 'num')}
                 <th class="num" title="הודעה נשלחה">הודעה</th>
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
    /* One line per item. It used to be three — a pill for the name, which wrapped
       to three more lines on a narrow drawer for anything called "חסם עורקים
       (CAT)", and "הוחזרו 1 מתוך 1" spelled out underneath it. A soldier with
       eight items filled the screen twice over for a fact that is two numbers.
       The steppers keep their size: they are what a thumb has to hit. */
    return `<li class="kit-row${returned ? ' is-back' : ''}">
        <span class="row-ico" aria-hidden="true">${item.icon}</span>
        <span class="kit-name">${returned ? '✓ ' : ''}${esc(item.name)}</span>
        <span class="kit-count num" aria-label="הוחזרו ${r} מתוך ${it.t}">${r}/${it.t}</span>
        <span class="rec-row-tools step">
          <button type="button" class="step-btn" data-act="credit" data-rid="${esc(rec.rid)}"
                  data-item="${item.id}" data-d="-1" aria-label="ביטול החזרה — ${esc(item.name)}" ${r <= 0 ? 'disabled' : ''}>−</button>
          <button type="button" class="step-btn" data-act="credit" data-rid="${esc(rec.rid)}"
                  data-item="${item.id}" data-d="1" aria-label="החזרה — ${esc(item.name)}" ${r >= it.t ? 'disabled' : ''}>+</button>
        </span>
      </li>`;
  }).join('');
  const anyBack = d.items && Object.values(d.items).some((it) => (it.r || 0) > 0);
  const shown = S.revealed.has(rec.rid);
  const serials = [['נשק', d.weapon], ['אקילה', d.amral], ['כוונת יום', d.scope]]
    .filter(([, v]) => v);

  /* Editing takes the whole drawer. It is a form, it wants the width, and
     it has its own save and cancel — leaving the cards up beside it invited
     somebody to press a stepper halfway through typing a name. */
  if (S.recEdit === rec.rid) {
    return `<div class="rowdetail">${recEditor(rec)}${fpStrip(rec.rid)}</div>`;
  }
  /* The licence correction takes the drawer for the same reason, and it is the
     same editor the licences screen opens. One soldier is reached from either
     side, and two ways to replace a blurred photograph would drift apart. */
  if (S.licEdit === rec.rid) {
    return `<div class="rowdetail">${licEditor(licRow(rec))}${fpStrip(rec.rid)}</div>`;
  }

  const personal = [
    dfield('שם מלא', esc(d.name)),
    dfield('מספר אישי', `<span class="num">${esc(d.pn)}</span>`),
    dfield('מחלקה', esc(deptName(d.dept))),
    dfield('טלפון', `<span class="num">${esc(shown ? d.phone : maskPhone(d.phone))}</span>
      <button class="linkbtn" data-act="reveal" data-rid="${esc(rec.rid)}">${shown ? 'הסתרה' : 'הצגה'}</button>`),
    dfield('תאריך אישור', esc(fmtDate(d.approvedAt))),
    ...serials.map(([k, v]) => dfield(k, `<span class="num">${esc(v)}</span>`)),
  ].join('');

  const notes = `
    <p class="dnote ${d.notified ? 'ok' : 'warn'}">${
      d.notified ? '✓ הודעת רישום נשלחה' : 'הודעת רישום טרם נשלחה'
    }</p>
    ${anyBack
      ? `<p class="dnote ${d.returnNotified ? 'ok' : 'warn'}">${
          d.returnNotified ? '✓ הודעת זיכוי נשלחה' : 'הודעת זיכוי טרם נשלחה'
        }</p>`
      : ''}`;

  const kit = rows
    ? `<ul class="dkit">${rows}</ul>`
    : '<p class="dempty">טרם חתם על ציוד. הפריטים יופיעו כאן אחרי החתימה.</p>';

  const actions = `
    <a class="dact" href="${esc(waLink(d))}" data-act="wa-sign"
       data-rid="${esc(rec.rid)}" target="_blank" rel="noopener noreferrer">
      ${DICO.wa}<span>${d.notified ? 'הודעת רישום — שליחה חוזרת' : 'שליחת הודעת רישום'}${
        waAuto() ? ' <small class="dact-via">מהקו · יוצא מיד</small>' : ''}</span></a>
    ${anyBack
      ? `<a class="dact" href="${esc(returnWaLink(d))}" data-act="wa-ret"
            data-rid="${esc(rec.rid)}" target="_blank" rel="noopener noreferrer">
           ${DICO.wa}<span>${d.returnNotified ? 'הודעת זיכוי — שליחה חוזרת' : 'שליחת הודעת זיכוי'}${
             waAuto() ? ' <small class="dact-via">מהקו · יוצא מיד</small>' : ''}</span></a>`
      : ''}
    ${outstanding(d) > 0
      ? `<button class="dact" data-act="creditall" data-rid="${esc(rec.rid)}">
           ${DICO.check}<span>זיכוי מלא</span></button>`
      : ''}
    <button class="dact" data-act="rec-edit" data-rid="${esc(rec.rid)}">
      ${DICO.pen}<span>עריכת פרטים</span></button>
    <button class="dact" data-act="lic-edit" data-rid="${esc(rec.rid)}">
      ${DICO.folder}<span>תיקון רישיונות וצילומים</span></button>
    <div class="dact-del">${
      delCell(`rec:${rec.rid}`, 'del', { rid: rec.rid }, 'מחיקת הרשומה', 'מחיקת הרשומה')
    }</div>`;

  /* The drawer as cards rather than one column of lines.
     It had grown into a strip of meta rows, a list, and a row of buttons —
     everything the same size and the same colour, so finding the phone number
     meant reading the whole thing. The same facts in four boxes, each with a
     heading, are found by looking rather than by reading; and on a phone the
     grid is one column, which is the same list it always was, only labelled. */
  return `
    <div class="rowdetail">
      <div class="dgrid">
        ${dcard('פרטים אישיים', DICO.person, personal + notes)}
        ${dcard('ציוד — אצלו / הוחתם', DICO.box, kit)}
        ${dcard('מסמכים ורישיונות', DICO.folder, docsRow(rec) || '<p class="dempty">לא צורפו רישיונות או צילומים.</p>')}
        ${dcard('פעולות', DICO.bolt, actions, 'is-acts')}
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
        <table class="tbl" data-phone="0,4,5">
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
/* One record reduced to what a licence screen needs. Split out of
   licenceRows() because the equipment drawer offers the same correction and
   needs the same shape for one soldier rather than a filtered list. */
function licRow(rec) {
  const d = rec.data;
  const civ = (d.lic || {}).civil;
  return {
    rid: rec.rid,
    name: d.name,
    pn: d.pn,
    dept: deptName(d.dept),
    no: (civ && civ.no) || '',
    exp: (civ && civ.exp) || '',
    st: civ && civ.has ? licState(civ.exp) : 'none',
    doc: !!(civ && civ.doc),
    mil: !!((d.lic || {}).military && d.lic.military.has),
    // The military licence is a photograph and nothing else — there is no
    // number and no expiry to type — so whether one was attached is the only
    // thing the screen can say about it.
    milDoc: !!((d.lic || {}).military && d.lic.military.doc),
  };
}

function licenceRows(approved, filtered = true) {
  return (filtered ? applyFilters(approved) : approved).map(licRow);
}

/* ── Correcting a licence from the console ─────────────────────────────
   A licence is photographed on a phone, at night, by someone who is being
   waited for, and the result is found to be out of focus — or missing
   altogether — days later, once the record is already approved. `POST /docs`
   refuses an approved record on purpose, which is the right rule for a soldier
   and the wrong one for the office, so the correction lives here.

   Nothing is written until save. A replacement photograph is held in the draft
   and uploaded only when the correction is committed, so closing the editor
   leaves neither an orphan image in the vault nor a record pointing at one
   that is not there.

   The personal number is not offered. It is what the record's id was derived
   from, and correcting it belongs with the rest of the identity in the record
   drawer, where the note about that already lives. */

// The link sits with the row's other actions; the form needs the full width of
// the table, so they are separate pieces — same split as the report editor.
const licEditLink = (r) =>
  `<button class="linkbtn" data-act="${S.licEdit === r.rid ? 'lic-cancel' : 'lic-edit'}"
           data-rid="${esc(r.rid)}">${S.licEdit === r.rid ? 'סגירה' : 'תיקון רשומה'}</button>`;

function licEditor(r) {
  if (S.licEdit !== r.rid) return '';
  const d = S.licDraft || {};
  const pic = d.pic || {};
  const st = licState(d.exp);

  // What the photo column will look like after saving: a fresh pick, an
  // explicit removal, or whatever is on file now.
  const shotState = (kindId) => {
    if (pic[kindId]) return 'new';
    if (pic[kindId] === null) return 'gone';
    return (kindId === 'civil' ? r.doc : r.milDoc) ? 'kept' : 'none';
  };

  const shotBlock = (k) => {
    const state = shotState(k.id);
    const label = { new: '✓ צילום חדש ממתין לשמירה', kept: '✓ יש צילום', gone: 'הצילום יימחק בשמירה', none: 'אין צילום' }[state];
    return `
      <div class="licedit-shot">
        <span class="field-label">${esc(k.short)}</span>
        <span class="field-hint mb0 ${state === 'gone' ? 'bad-hint' : ''}">${label}</span>
        ${pic[k.id]
          ? `<img class="lic-thumb" src="${pic[k.id].preview}" alt="הצילום החדש של ${esc(k.short)}">`
          : ''}
        <div class="lic-actions">
          <label class="btn ghost small lic-pick">
            <span>📷 צילום</span>
            <input class="vis-hidden" type="file" accept="image/*" capture="environment"
                   data-act="lic-ed-file" data-rid="${esc(r.rid)}" data-kind="${k.id}">
          </label>
          <label class="btn ghost small lic-pick">
            <span>🖼 מהגלריה</span>
            <input class="vis-hidden" type="file" accept="image/*"
                   data-act="lic-ed-file" data-rid="${esc(r.rid)}" data-kind="${k.id}">
          </label>
          ${state === 'kept' || state === 'new'
            ? `<button type="button" class="btn ghost small" data-act="lic-ed-nopic" data-kind="${k.id}">הסרת צילום</button>`
            : ''}
          ${state === 'gone'
            ? `<button type="button" class="btn ghost small" data-act="lic-ed-keep" data-kind="${k.id}">ביטול המחיקה</button>`
            : ''}
        </div>
      </div>`;
  };

  return `
    <div class="receditor">
      <p class="field-hint">${esc(r.name)} · מ״א ${esc(r.pn)}. שם, מספר אישי ומחלקה מתקנים בכרטיס הרשומה.</p>

      <label class="check">
        <input type="checkbox" data-act="lic-ed-has" data-kind="civil" ${d.civil ? 'checked' : ''}>
        <span>רישיון נהיגה אזרחי בתוקף</span>
      </label>
      ${d.civil
        ? `<div class="fuel-entry">
             <label class="field mb0">
               <span class="field-label">מספר רישיון <span class="req" aria-hidden="true">*</span></span>
               <input class="input mini num" type="text" inputmode="numeric" maxlength="20"
                      value="${esc(d.no || '')}" data-act="lic-ed-no" aria-label="מספר רישיון">
             </label>
             <label class="field mb0">
               <span class="field-label">בתוקף עד <span class="req" aria-hidden="true">*</span></span>
               <input class="input mini" type="date" value="${esc(d.exp || '')}"
                      min="${DATE_MIN}" max="${DATE_MAX}" data-act="lic-ed-exp" aria-label="בתוקף עד">
             </label>
           </div>
           ${d.exp && !inDateRange(d.exp)
             ? '<p class="field-hint bad-hint">⚠ התאריך אינו תקין — בדקו את השנה.</p>'
             : d.exp && st === 'expired'
               ? '<p class="field-hint bad-hint">⚠ התאריך שהוזן כבר עבר — הרישיון אינו בתוקף.</p>'
               : d.exp && st === 'soon'
                 ? '<p class="field-hint warn-hint">הרישיון פג בקרוב — כדאי לחדש.</p>'
                 : ''}
           ${shotBlock(LIC_KINDS.find((k) => k.id === 'civil'))}`
        : ''}

      <label class="check">
        <input type="checkbox" data-act="lic-ed-has" data-kind="military" ${d.military ? 'checked' : ''}>
        <span>רישיון נהיגה צבאי בתוקף</span>
      </label>
      ${d.military ? shotBlock(LIC_KINDS.find((k) => k.id === 'military')) : ''}

      <p class="field-hint">הסרת הסימון מוחקת גם את הצילום של אותו רישיון.</p>
      <div class="rec-actions">
        <button class="btn primary small" data-act="lic-save" data-rid="${esc(r.rid)}">שמירת התיקון</button>
        <button class="btn ghost small" data-act="lic-cancel">ביטול</button>
      </div>
    </div>`;
}

const LIC_RANK = { expired: 0, none: 1, nodate: 2, soon: 3, valid: 4 };

/* "לא בתוקף" says one thing and one thing only: the date written on the licence
   has already passed. A soldier who never had a licence has nothing that could
   expire, and counting the two together made the console announce people as
   "רישיון לא בתוקף" who simply never held one — a different problem, chased in
   a different way. Both are still forbidden to drive, so both rows stay red;
   they are counted and named apart.

   A licence marked as held with no expiry date on it is neither: nothing
   expired, but there is no valid licence on file either. It sits with the
   missing ones, under a name that fits both — "חסר". */
const licExpired = (r) => r.st === 'expired';
const licMissing = (r) => r.st === 'none' || r.st === 'nodate';
const licBlocked = (r) => licExpired(r) || licMissing(r);

/* How many licences need attention: expired, missing, or with no date on them
   at all. Drives the count on the tab, so the sidebar says there is something
   here without anyone having to open the screen. */
function licAlerts() {
  return licenceRows(S.recs.filter((r) => r.status === 'approved' && !r.damaged), false)
    .filter(licBlocked).length;
}

/* Driving licences, on a screen of their own.

   They were a table at the bottom of the reports tab, beneath two others —
   which is where you put something consulted once a month, not something with
   an expiry date on it. Chasing a renewal meant scrolling past the weapons
   list to find it, and nothing anywhere said how many had lapsed. */
function renderLicTab() {
  // licencePanel already carries the heading, the figures and the table. A
  // wrapper around it only said "רישיונות נהיגה" twice, with two sets of
  // counts under two identical titles.
  return licencePanel(S.recs.filter((r) => r.status === 'approved' && !r.damaged));
}

function licencePanel(approved) {
  const rows = licenceRows(approved);
  const gone = rows.filter(licExpired);
  const missing = rows.filter(licMissing);
  const bad = rows.filter(licBlocked);
  const soon = rows.filter((r) => r.st === 'soon');
  const ok = rows.filter((r) => r.st === 'valid');

  const body = rows
    .slice()
    .sort((a, b) => LIC_RANK[a.st] - LIC_RANK[b.st] || a.name.localeCompare(b.name, 'he'))
    .map((r) => {
      const alarm = licBlocked(r);
      /* Holding the civilian licence and not the military one is not a fault —
         the soldier may drive, just not the unit's vehicles — so it cannot be
         red. It is still the thing a מפל״ג needs to see at a glance when
         handing out keys, hence its own tint. A missing or expired civilian
         licence outranks it: red first. */
      const civOnly = !alarm && !r.mil;
      /* A soldier has two licences and the screen only ever offered one of
         them, so seeing the military one meant leaving this table and opening
         the record. Both are here now, side by side and small: one press
         brings the pair down — they travel in the same request — and pressing
         a thumbnail opens it to the size you can actually read a licence at. */
      const shots = LIC_KINDS
        .filter((k) => (k.id === 'civil' ? r.doc : r.milDoc))
        .map((k) => ({ k, key: `${r.rid}:${k.id}`, src: S.docs[`${r.rid}:${k.id}`] }));
      const open = shots.filter((s) => s.src);
      return `<tr${alarm ? ' class="row-short"' : civOnly ? ' class="row-civonly"' : ''}>
          <td>${esc(r.name)}</td>
          <td class="num">${esc(r.pn)}</td>
          <td>${esc(r.dept)}</td>
          <td class="num">${r.no ? esc(r.no) : '—'}</td>
          <td class="num">${r.exp ? esc(fmtDay(r.exp)) : '—'}</td>
          <td class="${alarm ? 'bad' : r.st === 'soon' ? 'warn' : 'ok'}">${
            alarm ? '⚠ ' : r.st === 'valid' ? '✓ ' : ''
          }${LIC_LABEL[r.st]}</td>
          <td>${r.mil ? '✓' : '—'}</td>
          <td class="lic-acts">${shots.length
            ? `<button class="linkbtn" data-act="lic-docs" data-rid="${esc(r.rid)}">${
                open.length ? 'הסתרה' : 'צפייה ברשומה'
              }</button>`
            : ''}${licEditLink(r)}</td>
        </tr>
        ${S.licEdit === r.rid
          ? `<tr class="sub"><td colspan="8">${licEditor(r)}</td></tr>`
          : ''}
        ${open.length
          ? `<tr class="lic-shots"><td colspan="8"><div class="licshots">${open
              .map(({ k, key, src }) => `
                <figure class="licshot">
                  <button class="lic-shot-btn" type="button" data-act="doc-zoom"
                          data-rid="${esc(r.rid)}" data-kind="${k.id}"
                          aria-label="${S.docBig.has(key) ? 'הקטנת' : 'הגדלת'} ${esc(k.short)} של ${esc(r.name)}">
                    <img class="doc-img${S.docBig.has(key) ? ' big' : ''}" src="${src}"
                         alt="${esc(k.short)} של ${esc(r.name)}">
                  </button>
                  <figcaption class="licshot-cap">${esc(k.short)}</figcaption>
                </figure>`)
              .join('')}</div></td></tr>`
          : ''}`;
    })
    .join('');

  return `
    <section class="panel">
      <h2 class="panel-title">רישיונות נהיגה</h2>
      <p class="panel-sub">מי מחזיק רישיון אזרחי בתוקף ומי לא. ״פג תוקף״ הוא רישיון שהתאריך שלו כבר עבר; מי שאין לו רישיון כלל מסומן ״אין רישיון״ — שניהם באדום, ושניהם אסורים בנהיגה. אזרחי בלבד, בלי רישיון צבאי — מסומן בצהוב. בעמודת הצילום נפתחים שני הרישיונות יחד, האזרחי והצבאי; לחיצה על תמונה מגדילה אותה. מכבד את החיפוש והסינון.</p>
      <div class="stat-row quad">
        <div class="stat"><span class="stat-n num">${ok.length}</span><span class="stat-l">✓ בתוקף</span></div>
        <div class="stat"><span class="stat-n num">${soon.length}</span><span class="stat-l">פגים בקרוב</span></div>
        <div class="stat"><span class="stat-n num">${gone.length}</span><span class="stat-l">⚠ פג תוקף</span></div>
        <div class="stat"><span class="stat-n num">${missing.length}</span><span class="stat-l">⚠ אין רישיון</span></div>
      </div>
      ${bad.length
        ? `<div class="callout alert"><p class="mb0">${[
            gone.length ? `<strong class="num">${gone.length}</strong> ${
              gone.length === 1 ? 'רישיון שפג תוקפו' : 'רישיונות שפג תוקפם'}` : '',
            missing.length ? `<strong class="num">${missing.length}</strong> ${
              missing.length === 1 ? 'חייל ללא רישיון רשום' : 'חיילים ללא רישיון רשום'}` : '',
          ].filter(Boolean).join(' · ')} — ראו את השורות האדומות. אסור שינהגו.</p></div>`
        : ''}
      ${rows.length
        ? `<div class="tbl-scroll">
             <table class="tbl" data-phone="0,5,7">
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
      <p class="panel-sub">מספר סידורי של הנשק, האקילה והכוונת מול המחזיק, ממוין לפי מספר הנשק. מכבד את החיפוש והסינון.</p>
      <div class="stat-row">
        <div class="stat"><span class="stat-n num">${armed.length}</span><span class="stat-l">נשקים משויכים</span></div>
        <div class="stat"><span class="stat-n num">${armed.filter((r) => r.data.amral).length}</span><span class="stat-l">אקילה רשום</span></div>
        <div class="stat"><span class="stat-n num">${armed.filter((r) => r.data.scope).length}</span><span class="stat-l">כוונת רשומה</span></div>
        <div class="stat"><span class="stat-n num">${unarmed.length}</span><span class="stat-l">ללא נשק רשום</span></div>
      </div>
      ${armed.length
        ? `<div class="tbl-scroll">
             <table class="tbl" data-phone="0,3">
               <thead><tr><th class="num">מס׳ נשק</th><th class="num">אקילה</th><th class="num">כוונת</th><th>שם</th><th class="num">מ״א</th><th>מחלקה</th><th class="num">טלפון</th></tr></thead>
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

// A register's stock report and its movement log, built from the register's
// own kinds and locations — so the armoury and the signals store each get a
// correct one without either being written twice.
const regReport = (reg, name, file) => ({
  name, file,
  build() {
    const all = (S.inv && S.inv[reg.key]) || [];
    return {
      head: ['סוג', 'פריט', 'מספר סידורי', 'בעלים', 'מיקום', 'אצל מי / משימה',
             'בחוץ מאז', 'תאריך הוספה'],
      rows: all.map((x) => [
        nameOf(reg.kinds, x.kind), x.name, x.serial, x.owner, nameOf(reg.locs, x.loc),
        NAMED_LOCS[x.loc] ? (x.mission || '(ללא שם)') : '',
        LOAN_LOCS.has(x.loc) && x.since ? fmtDate(x.since) : '',
        x.addedAt ? fmtDate(x.addedAt) : '',
      ]),
      summary: `${all.filter((x) => x.loc === reg.home).length} נמצאים ${reg.placeIn} · ` +
        `${all.filter((x) => x.loc !== reg.home).length} בחוץ · ${all.length} רשומים`,
    };
  },
});

const regLogReport = (reg, name, file) => ({
  name, file,
  build: () => ({
    head: ['תאריך', 'פעולה', 'סוג', 'פריט', 'מספר סידורי', 'בעלים', 'מ־', 'אל', 'אצל מי', 'ימים', 'יעד', 'הערה'],
    rows: ((S.inv && S.inv[reg.logKey]) || []).map((e) => [
      fmtDate(e.t), nameOf(ARM_ACTIONS, e.action), nameOf(reg.kinds, e.kind),
      e.name, e.serial, e.owner,
      e.from ? nameOf(reg.locs, e.from) : '', e.to ? nameOf(reg.locs, e.to) : '',
      e.who || '', e.action === 'return' && e.days ? e.days : '',
      e.dest ? nameOf(ARM_DESTS, e.dest) : '', e.note,
    ]),
  }),
});

// What is out and owed, on one sheet — the list you read out at a handover.
const regLoanReport = (reg, name, file) => ({
  name, file,
  build() {
    const rows = loansOf(reg);
    return {
      head: ['סוג', 'פריט', 'מספר סידורי', 'בעלים', 'מיקום', 'אצל מי', 'מאז', 'בחוץ'],
      rows: rows.map((x) => [
        nameOf(reg.kinds, x.kind), x.name, x.serial, x.owner, nameOf(reg.locs, x.loc),
        x.mission || '(ללא שם)',
        x.since ? fmtDate(x.since) : '', outFor(x),
      ]),
      summary: `${rows.length} בהשאלה · ${rows.filter((x) => !x.mission).length} ללא שם`,
    };
  },
});

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
          'מספר אישי', 'שם', 'טלפון', 'מחלקה', 'מספר נשק', 'מספר אקילה', 'מספר כוונת',
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
          `${rows.filter(licExpired).length} פג תוקף · ` +
          `${rows.filter(licMissing).length} אין רישיון`,
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
        head: ['מספר נשק', 'מספר אקילה', 'מספר כוונת', 'שם', 'מספר אישי', 'מחלקה', 'טלפון'],
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
          'שם', 'מספר אישי', 'מחלקה', 'מספר נשק', 'מספר אקילה', 'מספר כוונת',
          ...ITEMS.flatMap((i) => [`${i.name} — הוחתם`, `${i.name} — אצלו כעת`]),
          'סה״כ בחוץ',
        ],
        // The same soldiers the screen shows: those holding something. An
        // export that listed everybody would have contradicted the table it
        // sits under, which is worse than either answer on its own.
        rows: S.recs
          .filter((r) => r.status === 'approved' && !r.damaged && r.data && outstanding(r.data) > 0)
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
        head: ['נשלח', 'שם החייל', 'מספר אישי', 'טלפון', 'מספר נשק', 'מק״ט אקילה', 'מק״ט כוונת יום', 'סטטוס'],
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

  armon: regReport(REGISTERS.armon, 'פריטים בארמון', 'tzayad-armon'),
  armonLog: regLogReport(REGISTERS.armon, 'יומן פעולות ארמון', 'tzayad-armon-log'),
  armonLoans: regLoanReport(REGISTERS.armon, 'השאלות פתוחות — ארמון', 'tzayad-armon-loans'),
  comms: regReport(REGISTERS.comms, 'ציוד קשר', 'tzayad-comms'),
  commsLog: regLogReport(REGISTERS.comms, 'יומן פעולות קשר', 'tzayad-comms-log'),
  commsLoans: regLoanReport(REGISTERS.comms, 'השאלות פתוחות — קשר', 'tzayad-comms-loans'),

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

  ammoOut: {
    name: 'תחמושת בהשאלה', file: 'tzayad-ammo-out',
    build() {
      const rows = ammoOut();
      return {
        head: ['פריט', 'אצל מי', 'יעד', 'כמות', 'תנועה אחרונה'],
        rows: rows.map((r) => [r.name, r.who, nameOf(AMMO_DESTS, r.dest), r.n, fmtDate(r.last)]),
        summary: (() => {
          const who = new Set(rows.map((r) => r.who)).size;
          return `${rows.reduce((n, r) => n + r.n, 0)} פריטים בהשאלה אצל ${who === 1 ? 'גורם אחד' : `${who} גורמים`}`;
        })(),
      };
    },
  },

  ammo: {
    name: 'מלאי תחמושת ואלפא', file: 'tzayad-ammo',
    build() {
      const all = (S.inv && S.inv.ammo) || [];
      return {
        head: ['פריט', 'כמות התחלתית', 'כמות נוכחית', 'נוצל', 'סטטוס'],
        rows: all.map((x) => [
          x.name, x.open, x.qty, Math.max(0, x.open - x.qty),
          x.qty === 0 ? 'אזל' : 'תקין',
        ]),
        summary: `${all.length} סוגים · התחלתי ${all.reduce((s, x) => s + x.open, 0)} · ` +
          `נוכחי ${all.reduce((s, x) => s + x.qty, 0)} · ` +
          `נוצל ${all.reduce((s, x) => s + Math.max(0, x.open - x.qty), 0)}`,
      };
    },
  },

  ammoLog: {
    name: 'יומן תנועות תחמושת', file: 'tzayad-ammo-log',
    build: () => ({
      head: ['תאריך', 'פעולה', 'פריט', 'כמות', 'יעד', 'למי', 'הערה'],
      rows: ((S.inv && S.inv.ammoLog) || []).map((e) => [
        fmtDate(e.t), nameOf(AMMO_ACTIONS, e.action), e.name, e.qty,
        e.dest ? nameOf(AMMO_DESTS, e.dest) : '', e.who, e.note || '',
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
      ${csvBtn(id, 'ייצוא ל-CSV')}
      <button class="btn ghost" data-act="rep-pdf" data-r="${id}">הפקת PDF</button>
      ${extra}
    </div>`;
}

// A CSV leaves the encryption behind — that is what a spreadsheet is — so the
// button says so before it writes one, and says it louder when the file holds
// personal details.
function csvBtn(id, label) {
  const def = REPORTS[id];
  return askBtn(`csv:${id}`, 'rep-csv', label,
    def && def.sensitive ? 'הקובץ אינו מוצפן ומכיל פרטים אישיים. לייצא?' : 'הקובץ אינו מוצפן. לייצא?',
    { data: { r: id }, yes: 'ייצוא', tone: 'primary' });
}

function reportCsv(id) {
  const def = REPORTS[id];
  const { head, rows } = def.build();
  if (!rows.length) { toast('אין נתונים לייצוא', true); return; }
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
    meta: `הופק ${fmtDate(Date.now())} · ${rows.length} שורות`,
    head, rows, summary,
  });
}

/* Builds the sheet: unit emblem, title, repeating table header, a summary line
   and a signature block.

   This used to build the sheet invisibly and call window.print() on it, which
   works on a desktop and does nothing at all on a phone: in Safari on iOS, and
   in every browser that opens inside another app — which is how a link sent on
   WhatsApp is opened — window.print() is missing or silently ignored. The
   button appeared to do nothing, and the report could not be produced at all.

   So the sheet is now a screen you land on. The print dialog is still offered
   and still opens where it can, but when it cannot, the document is in front
   of you and the browser's own share menu will print it or save it as a PDF.
   Nothing is in a popup, which is also the rule for this app. */
function printDoc({ title, meta, head, rows, summary }) {
  const host = document.createElement('section');
  host.className = 'printdoc';
  host.innerHTML = `
    <div class="pd-bar no-print">
      <button class="btn primary" type="button" data-pd="print">הדפסה / שמירה כ-PDF</button>
      <button class="btn ghost" type="button" data-pd="close">סגירה</button>
    </div>
    <p class="pd-hint no-print">
      אם חלון ההדפסה לא נפתח — זה תקין בטלפון. פתחו את תפריט השיתוף של הדפדפן,
      בחרו <strong>הדפסה</strong> ואז <strong>שמירה כקובץ PDF</strong>.
      המסמך שלמטה הוא בדיוק מה שיישמר.
    </p>
    <header class="pd-head">
      <img class="pd-logo" src="/logo.png" alt="">
      <div class="pd-headtxt">
        <h1 class="pd-title">${esc(title)} — מסייעת 951</h1>
        <p class="pd-date">${esc(meta)}</p>
      </div>
    </header>
    <div class="pd-scroll">
      <table class="pd-tbl${head.length > 12 ? ' pd-wide' : ''}">
        <thead><tr><th class="pd-n">#</th>${head.map((h) => `<th>${esc(h)}</th>`).join('')}</tr></thead>
        <tbody>
          ${rows.map((r, i) => `<tr>
            <td class="pd-n">${i + 1}</td>
            ${r.map((c) => `<td>${esc(c == null ? '' : String(c))}</td>`).join('')}
          </tr>`).join('')}
        </tbody>
      </table>
    </div>
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
  const wasScrolled = window.scrollY;
  window.scrollTo(0, 0);

  const close = () => {
    document.body.classList.remove('printing');
    host.remove();
    document.removeEventListener('keydown', onKey);
    window.scrollTo(0, wasScrolled);
  };
  function onKey(e) { if (e.key === 'Escape') close(); }
  document.addEventListener('keydown', onKey);

  // The sheet is outside #app, so it carries its own two listeners rather than
  // going through the console's delegated dispatcher.
  host.querySelector('[data-pd="close"]').addEventListener('click', close);
  const ask = () => {
    // Absent in in-app browsers, and a no-op in some others. Either way the
    // document stays on screen and the browser's own share menu can print it,
    // so a failure here is not a dead end.
    if (typeof window.print !== 'function') { toast('השתמשו בתפריט השיתוף של הדפדפן ← הדפסה', true); return; }
    try { window.print(); } catch { toast('השתמשו בתפריט השיתוף של הדפדפן ← הדפסה', true); }
  };
  host.querySelector('[data-pd="print"]').addEventListener('click', ask);

  // Offered straight away where it works — a desktop still gets one click, as
  // it always did — but the screen no longer depends on it having worked.
  // Two frames, so the sheet is laid out and painted before the browser is
  // asked to photograph it; printing it in the same tick can yield a blank
  // preview.
  requestAnimationFrame(() => requestAnimationFrame(ask));
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
  /* Who is signed for something — not everyone who has ever been approved.

     The table answers one question, and it was listing two kinds of soldier
     who are not an answer to it: one who has brought everything back, and one
     who never signed for anything at all. Both showed a row of dots and a
     zero, which reads as a soldier holding nothing rather than as a soldier
     who does not belong on this page; and the first kind is worse, because
     crediting a soldier in full is meant to take them off it, and did not.

     They are counted underneath instead, so it is clear they were left out
     rather than lost. */
  const inScope = applyFilters(approved);
  const visible = inScope.filter((rec) => outstanding(rec.data) > 0);
  const settled = inScope.filter((rec) => gearState(rec.data) === 'done').length;
  const never = inScope.filter((rec) => gearState(rec.data) === 'none').length;
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
          <span class="lg-nm">${avatar(d.name)}${esc(d.name)}</span>
          <span class="lg-sub num">${esc(d.pn)}</span>
          <span class="lg-sub">${esc(deptName(d.dept))}</span>
          ${d.weapon ? `<span class="lg-sub">נשק <span class="num">${esc(d.weapon)}</span></span>` : ''}
          ${d.amral ? `<span class="lg-sub">אקילה <span class="num">${esc(d.amral)}</span></span>` : ''}
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
      <p class="panel-sub">רק חיילים שמחזיקים ציוד כרגע. כל שורה היא חייל, כל עמודה פריט; המספר הוא מה שעדיין אצלו, מתוך מה שהוחתם.</p>
      ${settled || never
        ? `<p class="lg-left">${[
            settled ? `<span class="num">${settled}</span> ${settled === 1 ? 'חייל החזיר' : 'חיילים החזירו'} הכל` : '',
            never ? `<span class="num">${never}</span> ${never === 1 ? 'טרם חתם' : 'טרם חתמו'} על ציוד` : '',
          ].filter(Boolean).join(' · ')} — אינם מופיעים כאן. הם נמצאים במעקב ציוד.</p>`
        : ''}
      ${visible.length
        ? `<div class="tbl-scroll">
             <table class="tbl lg" data-phone="0,-1">
               <thead><tr><th class="lg-name">חייל</th>${heads}<th class="num">בחוץ</th></tr></thead>
               <tbody>${body}</tbody>
             </table>
           </div>
           ${pager('ledger', pgLg)}
           ${reportButtons('ledger')}`
        : `<p class="empty">${
            inScope.length ? 'אף חייל לא מחזיק ציוד כרגע.' : 'אין חיילים שתואמים את החיפוש.'
          }</p>`}
    </section>`;
}

/* ── Inventory (מלאי) ──────────────────────────────────────────────── */

const emptyInv = () => ({
  open: {}, extra: [], notes: '',
  armon: [], armonLog: [], comms: [], commsLog: [],
  ammo: [], ammoLog: [], vehicles: [], fuel: [], countedAt: {},
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
        <td>${delCell(`inv-x:${i}`, 'inv-xdel', { i }, '✕', 'מחיקת שורה')}</td>
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
             <table class="tbl" data-phone="0,3,4">
               <thead><tr><th>פריט</th><th>סה״כ</th><th>בשימוש</th><th class="num">נותר</th><th></th></tr></thead>
               <tbody>${extraRows}</tbody>
             </table>
           </div>`
          : '<p class="empty">אין פריט שתואם את החיפוש.</p>'
        : '<p class="empty">אין פריטים נוספים. הוסיפו את הראשון למטה.</p>'}
      <div class="rec-actions mt">
        <button class="btn ghost" data-act="inv-xadd">+ הוספת פריט</button>
        ${inv.extra.length ? `${csvBtn('stockExtra', 'ייצוא ל-CSV')}
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
  const licGone = licRows.filter(licExpired).length;
  const licNone = licRows.filter(licMissing).length;
  const licBad = licGone + licNone;
  const licSoon = licRows.filter((r) => r.st === 'soon').length;

  const tiles = [
    kpi(approved.length, 'חיילים מאושרים', null, `${c.pending} ממתינים לאישור`),
    kpi(held, 'פריטים בחוץ', held > 0 ? 'warn' : 'ok', `מתוך ${issued} שהוחתמו`),
    kpi(`${pct(returned, issued)}%`, 'אחוז החזרה', pct(returned, issued) === 100 ? 'ok' : null, `${returned} הוחזרו`),
    kpi(shortItems.length, 'פריטים בחוסר', shortItems.length ? 'bad' : 'ok',
        shortItems.length ? shortItems.map((i) => i.name).join(', ') : 'המלאי מכסה'),
    kpi(openReps, 'בקשות חוסר פתוחות', openReps ? 'warn' : 'ok'),
    kpi(armed, 'נשקים משויכים', null, `${approved.length - armed} ללא נשק רשום`),
    /* One tile, because the answer a מפל״ג wants at a glance is "how many may
       not drive" — but the reason is spelled out underneath, so the number
       never claims a licence expired when there was never a licence. */
    kpi(licBad, 'חיילים שאסור שינהגו', licBad ? 'bad' : 'ok',
        [licGone ? `${licGone} פג תוקף` : '', licNone ? `${licNone} אין רישיון` : '',
         licSoon ? `${licSoon} פגים בקרוב` : ''].filter(Boolean).join(' · ')
        || `${licOk} בתוקף`),
  ].join('');

  // Everything the armoury, ammunition, vehicle and fuel registers know, in the
  // same glance as the equipment numbers — otherwise those pages are invisible
  // from here and only get looked at when something has already gone wrong.
  const armon = inv.armon || [];
  const armOut = armon.filter((x) => x.kind === 'weapon' && x.loc !== 'armon');
  const comms = inv.comms || [];
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
    kpi(comms.filter((x) => x.loc === 'store').length, 'פריטי קשר במחסן', commsAlerts() ? 'warn' : null,
        `${comms.length} רשומים · ${comms.length - comms.filter((x) => x.loc === 'store').length} בחוץ`),
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
    // Licences have a screen of their own now; these two still sent you to the
    // reports tab, where the table they were pointing at no longer is.
    licGone && { n: licGone, tone: 'bad', tab: 'lic',
      t: 'רישיונות שפג תוקפם', s: 'התאריך עבר — אסור שינהגו עד חידוש' },
    licNone && { n: licNone, tone: 'bad', tab: 'lic',
      t: 'חיילים ללא רישיון רשום', s: 'לא הוגש רישיון אזרחי — אסור שינהגו' },
    licSoon && { n: licSoon, tone: 'warn', tab: 'lic',
      t: 'רישיונות פגים בקרוב', s: 'כדאי לחדש לפני שיפוג' },
    vehLate.length && { n: vehLate.length, tone: 'bad', tab: 'veh',
      t: 'רכבים עם טיפול שעבר', s: vehLate.map((v) => v.plate).filter(Boolean).join(', ') || 'ללא מספר רכב' },
    vehKitShort.length && { n: vehKitShort.length, tone: 'warn', tab: 'veh',
      t: 'רכבים עם ציוד חסר', s: VEH_KIT.map((k) => k.name).join(', ') },
    openRefuels() && { n: openRefuels(), tone: 'bad', tab: 'veh',
      t: 'דיווחי תדלוק ממתינים לקליטה', s: 'עד שייקלטו, היתרה בכרטיסים אינה מעודכנת' },
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
    comms.filter((x) => ARM_BAD_LOCS.has(x.loc)).length && {
      n: comms.filter((x) => ARM_BAD_LOCS.has(x.loc)).length, tone: 'bad', tab: 'comms',
      t: 'ציוד קשר אבוד או מושבת', s: 'דורש דיווח או החלפה' },
    comms.filter((x) => x.loc === 'repair').length && {
      n: comms.filter((x) => x.loc === 'repair').length, tone: 'warn', tab: 'comms',
      t: 'ציוד קשר בתיקון', s: 'ממתין לחזרה מהמעבדה' },
    comms.filter((x) => NAMED_LOCS[x.loc] && !x.mission).length && {
      n: comms.filter((x) => NAMED_LOCS[x.loc] && !x.mission).length, tone: 'warn', tab: 'comms',
      t: 'ציוד קשר בלי ציון מקום', s: 'מסומן ברכב או במשימה בלי לרשום איזה' },
    // A loan with nobody's name on it: the equipment left and there is no
    // record of who has it.
    ...[REGISTERS.armon, REGISTERS.comms].map((reg) => {
      const blank = loansOf(reg).filter((x) => !x.mission);
      return blank.length && { n: blank.length, tone: 'bad', tab: reg.tab,
        t: `השאלות ללא שם — ${reg.title}`, s: 'הציוד יצא ואין רשום מי לקח' };
    }),
    ...(() => {
      const out = ammoOut();
      const who = new Set(out.map((r) => r.who)).size;
      return [out.length && { n: out.reduce((n, r) => n + r.n, 0), tone: 'warn', tab: 'ammo',
        t: 'תחמושת בהשאלה', s: `אצל ${who === 1 ? 'גורם אחד' : `${who} גורמים`} — טרם הוחזרה` }];
    })(),
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

  // Latest movements across every register, merged into one timeline. A loan
  // and a return are movements too, and they are the ones somebody glancing at
  // this screen is most likely to be looking for.
  const regFeed = (log, place, from) => (log || []).slice(0, 12).map((e) => {
    const tone = { add: 'ok', return: 'ok', move: 'warn', remove: 'bad' }[e.action] || 'ok';
    const what = `${e.name} (${e.serial})`;
    const lead = {
      add: `נכנס ${place}`,
      move: `יצא ${from}`,
      return: `הוחזר ${place}`,
      remove: `הוסר ${from}`,
    }[e.action] || '';
    const tail = e.action === 'remove'
      ? (e.dest ? ` → ${nameOf(ARM_DESTS, e.dest)}` : '')
      : e.who ? ` — ${e.who}${e.action === 'return' && e.days ? ` (${e.days} ימים)` : ''}` : '';
    return { t: e.t, tone, txt: `${lead}: ${what}${tail}` };
  });

  const feed = [
    ...regFeed(inv.armonLog, 'לארמון', 'מהארמון'),
    ...regFeed(inv.commsLog, 'למחסן קשר', 'ממחסן קשר'),
    ...(inv.ammoLog || []).slice(0, 12).map((e) => ({
      t: e.t, tone: e.action === 'issue' ? 'bad' : 'ok',
      txt: `${{ add: 'נוספה תחמושת', issue: 'הונפקה תחמושת', return: 'הוחזרה תחמושת' }[e.action] || 'תחמושת'}: ${e.name} ×${e.qty}${e.who ? ` — ${e.who}` : ''}`,
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
    const badLic = licRows.filter((l) => l.dept === dp.name && licBlocked(l)).length;
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
             <table class="tbl" data-phone="0,1,4">
               <thead><tr>
                 <th>מחלקה</th><th class="num">חיילים</th><th class="num">הוחתם</th>
                 <th class="num">הוחזר</th><th class="num">בחוץ</th>
                 <th class="num">נשקים</th><th class="num">פג תוקף / אין רישיון</th><th>% הוחזר</th>
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
          : askBtn(`dep:${r.id}`, 'dep-approve', 'אישור וקליטה',
              `לקלוט לארמון את נשק ${d.weapon} של ${d.name}?`,
              { data: { id: r.id }, yes: 'כן, לקלוט', cls: 'btn primary small' })}
        ${repEditLink(r)}
        ${delCell(`rep:${r.id}`, 'rep-del', { id: r.id }, 'מחיקה', 'מחיקת הדיווח')}
      </td>
    </tr>
    ${S.repEdit === r.id ? `<tr class="sub"><td colspan="9">${repEditor(r)}</td></tr>` : ''}`;
  }).join('');

  const waiting = openDeposits();
  return `
    <section class="panel${waiting ? ' alert' : ''}">
      <h2 class="panel-title">אפסון נשק — ממתין לאישור ${waiting ? `<span class="pill bad num">${waiting}</span>` : ''}</h2>
      <p class="panel-sub">בקשות אפסון ששלחו חיילים דרך <span class="code-inline">#deposit</span>. הנשק נכנס לרישום הארמון רק אחרי אישור כאן. האישור קולט גם את האקילה והכוונת אם נמסרו.</p>
      ${all.length > 4
        ? plainSearch('dep-search', 'dep-qclear', S.depQ,
                      'חיפוש לפי שם, מ״א, טלפון או מספר נשק', all.length, vis.length)
        : ''}
      <div class="filters">${filters}</div>
      ${vis.length
        ? `<div class="tbl-scroll">
             <table class="tbl" data-phone="1,7,-1">
               <thead><tr>
                 <th class="num">נשלח</th><th>שם החייל</th><th class="num">מ״א</th><th class="num">טלפון</th>
                 <th class="num">מס׳ נשק</th><th class="num">מק״ט אקילה</th><th class="num">מק״ט כוונת</th>
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
    // Every number on the slip has to be free — the weapon and each accessory
    // — and the deposit itself is excluded so it does not collide with itself.
    for (const [f, label] of SERIAL_FIELDS) {
      const clash = serialTaken(d[f], rec.id);
      if (clash) { toast(`${label}: ${clash}`, true); return; }
    }
    S.askDel = '';

    const prevArmon = S.inv.armon || [];
    const prevLog = S.inv.armonLog || [];
    const now = Date.now();
    const note = `אפסון עצמי · מ״א ${d.pn}`;
    const added = [];
    const stage = (kind, name, serial) => {
      added.push({ id: rndId(), kind, name, serial, owner: d.name, loc: 'armon', note, addedAt: now });
    };
    stage('weapon', 'נשק אישי', d.weapon);
    // The soldier's own device files as אקילה, not as the unit's אמר״ל. The
    // payload key is still `amral` — that is what was sealed into every record
    // already written — but what lands in the register is the personal kind,
    // and the personal kind is not lent to anybody.
    if (d.amral) stage('akila', 'אקילה', d.amral);
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
    const w = await waNotify(d.phone, waDepositMsg(d));
    toast(`אפסון אושר — ${added.length} פריטים נקלטו לארמון${waNote(w)}`);
  });

// `where` splits the register into what is physically on the shelf and what has
// gone out. The true index is carried through so edits still target the right
// entry after filtering.
function regVisible(reg, where) {
  const rows = (S.inv && S.inv[reg.key]) || [];
  const q = (S.regQ[reg.key] || '').trim().toLowerCase();
  const kind = S.regKind[reg.id] || 'all';
  return rows
    .map((x, i) => ({ x, i }))
    .filter(({ x }) => (where === 'here' ? x.loc === reg.home : x.loc !== reg.home))
    .filter(({ x }) => kind === 'all' || x.kind === kind)
    .filter(({ x }) =>
      !q ||
      (x.name || '').toLowerCase().includes(q) ||
      (x.serial || '').toLowerCase().includes(q) ||
      (x.owner || '').toLowerCase().includes(q)
    );
}

const renderArmonTab = () => renderRegisterTab(REGISTERS.armon);
const renderCommsTab = () => renderRegisterTab(REGISTERS.comms);

/* ── Loans ─────────────────────────────────────────────────────────────
   An item that is at the workshop, written off or lost is also "not here",
   but nobody is going to bring it back. A loan is the other kind of absence:
   somebody took it, and it is owed. Only that kind gets a clock, a due date
   and a return button. */

const loansOf = (reg) => ((S.inv && S.inv[reg.key]) || []).filter((x) => LOAN_LOCS.has(x.loc));

const daysOut = (x) => (x.since ? Math.max(0, Math.round((Date.now() - x.since) / DAY_MS)) : null);

/* There was a "return by" date here, and an overdue alarm built on it. It is
   gone at the unit's request: nobody was going to fill in a date for a scope
   taken for the afternoon, and a due column that is always empty is a column
   that teaches people to ignore columns. What is out and how long it has been
   out are still on the screen, and those are answers nobody has to type.
   `due` stays in the sanitiser so records written while the field existed
   still open cleanly. */

// How long it has been gone, in the words someone would actually use.
function outFor(x) {
  const d = daysOut(x);
  if (d === null) return '—';
  if (d === 0) return 'היום';
  if (d === 1) return 'אתמול';
  return `${d} ימים`;
}

// Taking an item out used to mean finding its row among hundreds and changing
// a select in it. This asks the three questions the act actually consists of —
// what, to whom, until when — and does the rest.
function loanPanel(reg) {
  const open = loansOf(reg);
  const nameless = open.filter((x) => !x.mission);
  const shelf = ((S.inv && S.inv[reg.key]) || [])
    .filter((x) => x.loc === reg.home && canLoan(reg, x.kind))
    .sort((a, b) => a.name.localeCompare(b.name, 'he'));

  const rows = open
    .slice()
    .sort((a, b) => (a.since || 0) - (b.since || 0))
    .map((x) => {
      const i = S.inv[reg.key].indexOf(x);
      return `<tr>
        <td>${esc(x.name)}<span class="dim"> · ${esc(nameOf(reg.kinds, x.kind))}</span></td>
        <td class="num wpn">${esc(x.serial)}</td>
        <td>
          ${x.mission
            ? `<strong>${esc(x.mission)}</strong>`
            : `<input class="input mini" type="text" maxlength="60" value=""
                      data-act="arm-mission" data-reg="${reg.id}" data-i="${i}"
                      placeholder="${esc((NAMED_LOCS[x.loc] || {}).label || 'שם')}"
                      aria-label="${esc((NAMED_LOCS[x.loc] || {}).label || 'שם')}">`}
          <span class="dim"> · ${esc(nameOf(reg.locs, x.loc))}</span>
        </td>
        <td class="num">${esc(outFor(x))}</td>
        <td class="nowrap">
          ${askBtn(`ret:${x.id}`, 'arm-return', '↩ החזרה',
                   `להחזיר את ${x.name} (${x.serial}) ${reg.placeTo}?`,
                   { data: { reg: reg.id, i }, yes: 'כן, הוחזר', cls: 'btn primary small' })}
        </td>
      </tr>`;
    }).join('');

  return `
    <section class="panel">
      <h2 class="panel-title">השאלות פתוחות ${open.length ? `<span class="pill warn num">${open.length}</span>` : ''}</h2>
      <p class="panel-sub">ציוד שיצא מ${esc(reg.place)} ואמור לחזור — אצל חייל, במשימה או ברכב. כל השאלה והחזרה נרשמות ביומן עם השם והתאריך.</p>

      <form data-form="arm-loan" data-reg="${reg.id}" novalidate>
        <div class="grid2">
          <label class="field">
            <span class="field-label">הפריט <span class="req" aria-hidden="true">*</span></span>
            <select class="input select" name="item" required>
              <option value="">— בחרו פריט ${esc(reg.placeIn)} —</option>
              ${shelf.map((x) => `<option value="${esc(x.id)}">${esc(nameOf(reg.kinds, x.kind))} · ${esc(x.name)} · ${esc(x.serial)}</option>`).join('')}
            </select>
          </label>
          <label class="field">
            <span class="field-label">לאן <span class="req" aria-hidden="true">*</span></span>
            <select class="input select" name="loc" required>
              ${reg.locs.filter((l) => LOAN_LOCS.has(l.id)).map((l) => `<option value="${l.id}">${esc(l.name)}</option>`).join('')}
            </select>
          </label>
          <label class="field span2">
            <span class="field-label">אצל מי / איזו משימה <span class="req" aria-hidden="true">*</span></span>
            <input class="input" name="who" maxlength="60" placeholder="ישראל ישראלי" required>
          </label>
        </div>
        <p class="form-err" data-err></p>
        <button class="btn primary wide" type="submit"${shelf.length ? '' : ' disabled'}>
          ${shelf.length ? 'רישום השאלה' : `אין פריטים ${esc(reg.placeIn)} להשאלה`}
        </button>
      </form>

      ${nameless.length
        ? `<div class="callout risk"><p class="mb0"><strong class="num">${nameless.length}</strong> ${nameless.length === 1 ? 'פריט בהשאלה בלי שם' : 'פריטים בהשאלה בלי שם'} של מי שלקח. מלאו בטבלה — בלי שם אין את מי לשאול.</p></div>`
        : ''}

      ${open.length
        ? `<div class="tbl-scroll">
             <table class="tbl" data-phone="0,2,-1">
               <thead><tr>
                 <th>פריט</th><th class="num">מס׳ סידורי</th><th>אצל מי</th>
                 <th class="num">בחוץ</th><th></th>
               </tr></thead>
               <tbody>${rows}</tbody>
             </table>
           </div>
           <div class="rec-actions mt">
             ${csvBtn(`${reg.key}Loans`, 'ייצוא ל-CSV')}
             <button class="btn ghost" data-act="rep-pdf" data-r="${reg.key}Loans">הפקת PDF</button>
             <button class="btn primary" data-act="inv-save" data-reg="${reg.id}">שמירת השינויים</button>
           </div>`
        : `<p class="empty">אין השאלות פתוחות — כל הציוד ${esc(reg.placeIn)} או בטיפול.</p>`}
    </section>`;
}

function renderRegisterTab(reg) {
  const all = (S.inv && S.inv[reg.key]) || [];
  const log = (S.inv && S.inv[reg.logKey]) || [];
  const vis = regVisible(reg, 'here');
  const p = paged(reg.key, vis);
  const visOut = regVisible(reg, 'out');
  const pOut = paged(`${reg.key}Out`, visOut);
  const here = all.filter((x) => x.loc === reg.home);
  const out = all.filter((x) => x.loc !== reg.home);
  const byKind = reg.kinds.map((k) => ({
    ...k,
    here: here.filter((x) => x.kind === k.id).length,
    out: out.filter((x) => x.kind === k.id).length,
  }));
  // A location that means nothing without a name, left unnamed.
  const unnamed = all.filter((x) => NAMED_LOCS[x.loc] && !x.mission);
  const unusable = all.filter((x) => ARM_BAD_LOCS.has(x.loc));
  const kindSel = S.regKind[reg.id] || 'all';

  const kindChips = [['all', 'הכל'], ...reg.kinds.map((k) => [k.id, k.name])]
    .map(([id, label]) =>
      `<button class="filter" aria-pressed="${kindSel === id}" data-act="arm-kind" data-reg="${reg.id}" data-k="${id}">${esc(label)}</button>`)
    .join('');

  const armRow = ({ x, i }) => {
    const named = NAMED_LOCS[x.loc];
    // A row is read until you say otherwise. Correcting a mistyped serial is
    // rarer than reading the register, so the fields appear only for the one
    // row being corrected — otherwise every row is a form again.
    const ed = S.armEdit === x.id;
    return `
    <tr${ed ? ' class="is-open"' : ''}>
      <td>${ed
        ? `<select class="input mini select-mini" data-act="arm-e-kind" data-reg="${reg.id}" data-i="${i}" aria-label="סוג">
             ${reg.kinds.map((k) => `<option value="${k.id}"${x.kind === k.id ? ' selected' : ''}>${esc(k.name)}</option>`).join('')}
           </select>`
        : esc(nameOf(reg.kinds, x.kind))}</td>
      <td>${ed
        ? `<input class="input mini" type="text" maxlength="60" value="${esc(x.name)}"
                  data-act="arm-e-name" data-reg="${reg.id}" data-i="${i}" aria-label="שם הפריט">`
        : esc(x.name)}</td>
      <td class="num wpn">${ed
        ? `<input class="input mini num wide" type="text" maxlength="40" value="${esc(x.serial)}"
                  data-act="arm-e-serial" data-reg="${reg.id}" data-i="${i}" aria-label="מספר סידורי">`
        : esc(x.serial)}</td>
      <td>${ed
        ? `<input class="input mini" type="text" maxlength="60" value="${esc(x.owner)}"
                  data-act="arm-e-owner" data-reg="${reg.id}" data-i="${i}" aria-label="בעלים">`
        : esc(x.owner)}</td>
      <td>
        <select class="input mini select-mini" data-act="arm-loc" data-reg="${reg.id}" data-i="${i}" aria-label="מיקום">
          ${kindLocs(reg, x.kind).map((l) => `<option value="${l.id}"${x.loc === l.id ? ' selected' : ''}>${esc(l.name)}</option>`).join('')}
        </select>
        ${named
          ? `<input class="input mini mt-xs" type="text" maxlength="60" value="${esc(x.mission)}"
                    data-act="arm-mission" data-reg="${reg.id}" data-i="${i}"
                    aria-label="${esc(named.label)}" placeholder="${esc(named.label)}">`
          : ''}
      </td>
      <td class="num">${x.addedAt ? esc(fmtDay(new Date(x.addedAt).toISOString().slice(0, 10))) : '—'}</td>
      <td>
        <select class="input mini select-mini" data-act="arm-dest" data-id="${esc(x.id)}" aria-label="לאן מועבר">
          <option value="">להסרה — לאן?</option>
          ${ARM_DESTS.map((dd) => `<option value="${dd.id}"${(S.armDraft[x.id] || {}).dest === dd.id ? ' selected' : ''}>${esc(dd.name)}</option>`).join('')}
        </select>
        ${(S.armDraft[x.id] || {}).dest ? `
          <input class="input mini mt-xs" type="text" maxlength="120"
                 value="${esc((S.armDraft[x.id] || {}).note || '')}"
                 data-act="arm-note" data-id="${esc(x.id)}" placeholder="הערה (רשות)" aria-label="הערה">
          <button class="btn danger small mt-xs" data-act="arm-remove" data-reg="${reg.id}" data-i="${i}">אישור הסרה</button>` : ''}
      </td>
      <td class="nowrap">
        ${ed
          ? `<button class="btn primary small" data-act="arm-e-done" data-reg="${reg.id}">סיום עריכה</button>`
          : `<button class="linkbtn" data-act="arm-edit" data-id="${esc(x.id)}" title="תיקון פרטי הפריט">✎ עריכה</button>`}
        ${delCell(`arm:${x.id}`, 'arm-del', { reg: reg.id, i }, '✕', 'מחיקת השורה',
                  'למחוק את השורה לגמרי?')}
      </td>
    </tr>`;
  };
  const rows = p.slice.map(armRow).join('');
  const rowsOut = pOut.slice.map(armRow).join('');

  // Four kinds of movement now, not two, so the colour says what happened
  // rather than merely whether the register grew: coming home is good news,
  // going out is not bad news, and leaving for good is.
  const LOG_TONE = { add: 'ok', return: 'ok', move: 'warn', remove: 'bad' };
  const logRows = log.slice(0, 200).map((e, n) => {
    const act = ARM_ACTIONS.find((a) => a.id === e.action) || ARM_ACTIONS[0];
    const travel = e.action === 'remove'
      ? (e.dest ? nameOf(ARM_DESTS, e.dest) : '')
      : (e.from || e.to ? `${nameOf(reg.locs, e.from)} ← ${nameOf(reg.locs, e.to)}` : '');
    return `
    <tr>
      <td class="num">${esc(fmtDate(e.t))}</td>
      <td class="${LOG_TONE[e.action] || ''}">${esc(`${act.sign} ${act.name}`)}</td>
      <td>${esc(nameOf(reg.kinds, e.kind))}</td>
      <td>${esc(e.name)}</td>
      <td class="num wpn">${esc(e.serial)}</td>
      <td>${esc(e.owner || '—')}</td>
      <td>${travel ? esc(travel) : '<span class="dim">·</span>'}</td>
      <td>${e.who ? esc(e.who) : '<span class="dim">·</span>'}${
        e.action === 'return' && e.days ? `<span class="dim"> · ${e.days} ימים</span>` : ''}</td>
      <td>${esc(e.note || '')}</td>
      <td>${delCell(`${reg.logKey}:${n}`, 'arm-log-del', { reg: reg.id, n }, '✕',
                    'מחיקת שורת היומן', 'למחוק את שורת היומן?')}</td>
    </tr>`;
  }).join('');

  return `
    ${reg.deposits ? depositsPanel() : ''}

    ${loanPanel(reg)}

    <section class="panel">
      <h2 class="panel-title">${esc(reg.addTitle)}</h2>
      <p class="panel-sub">כל פריט נכנס עם סוג, מספר סידורי ושם מלא של מי שהוא רשום עליו. כל הוספה והסרה נרשמות ביומן.</p>
      <form data-form="arm-add" data-reg="${reg.id}" novalidate>
        <div class="grid2">
          <label class="field">
            <span class="field-label">סוג פריט <span class="req" aria-hidden="true">*</span></span>
            <select class="input select" name="kind" required>
              ${reg.kinds.map((k) => `<option value="${k.id}">${esc(k.name)}</option>`).join('')}
            </select>
          </label>
          <label class="field">
            <span class="field-label">שם הפריט <span class="req" aria-hidden="true">*</span></span>
            <input class="input" name="name" maxlength="60" placeholder="${esc(reg.namePh)}" required>
          </label>
          <label class="field">
            <span class="field-label">מספר סידורי / מק״ט <span class="req" aria-hidden="true">*</span></span>
            <input class="input num" name="serial" maxlength="40" placeholder="${esc(reg.serialPh)}" required>
          </label>
          <label class="field">
            <span class="field-label">שם מלא של בעל הפריט <span class="req" aria-hidden="true">*</span></span>
            <input class="input" name="owner" maxlength="60" placeholder="ישראל ישראלי" required>
          </label>
        </div>
        <p class="form-err" data-err></p>
        <button class="btn primary wide" type="submit">הוספה ${esc(reg.placeTo)}</button>
      </form>
    </section>

    <section class="panel">
      <h2 class="panel-title">מלאי ${esc(reg.place)} <span class="pill ok num">${here.length}</span></h2>
      <p class="panel-sub">${esc(reg.stockNote)}</p>
      <div class="kpis">
        ${kpi(here.length, `נמצאים ${reg.placeIn}`, 'ok', `${all.length} רשומים · ${out.length} בחוץ`)}
        ${byKind.map((k) => kpi(k.here, k.name, k.out ? 'warn' : null, k.out ? `${k.out} בחוץ` : `הכול ${reg.placeIn}`)).join('')}
      </div>
      ${unnamed.length
        ? `<div class="callout risk"><p class="mb0"><strong class="num">${unnamed.length}</strong> פריטים מסומנים במיקום שדורש שם — ${esc([...new Set(unnamed.map((x) => NAMED_LOCS[x.loc].label))].join(' / '))} — בלי שמילאו אותו. השלימו בשורה.</p></div>`
        : ''}
      ${unusable.length
        ? `<div class="callout risk"><p class="mb0"><strong class="num">${unusable.length}</strong> פריטים אבודים או מושבתים: ${unusable.slice(0, 6).map((x) => `${esc(x.name)} (${esc(x.serial)}) — ${esc(nameOf(reg.locs, x.loc))}`).join(' · ')}${unusable.length > 6 ? ' …' : ''}</p></div>`
        : ''}
      ${all.length > 4
        ? plainSearch('arm-search', 'arm-qclear', S.regQ[reg.key] || '',
                      'חיפוש לפי שם, מספר סידורי או בעלים', all.length, vis.length + visOut.length,
                      { reg: reg.id })
        : ''}
      <div class="filters">${kindChips}</div>
      ${vis.length
        ? `<div class="tbl-scroll">
             <table class="tbl" data-phone="2,4,-1">
               <thead><tr>
                 <th>סוג</th><th>פריט</th><th class="num">מס׳ סידורי</th><th>בעלים</th>
                 <th>מיקום</th><th class="num">נוסף</th><th>הסרה</th><th></th>
               </tr></thead>
               <tbody>${rows}</tbody>
             </table>
           </div>
           ${pager(reg.key, p)}`
        : `<p class="empty">${here.length ? `אין פריט ${reg.placeIn} שתואם את החיפוש.` : all.length ? `אין פריטים ${reg.placeIn} — כולם בחוץ.` : `${reg.place} ריק. הוסיפו פריט למעלה.`}</p>`}
      <div class="rec-actions mt">
        ${csvBtn(reg.key, 'ייצוא ל-CSV')}
        <button class="btn ghost" data-act="rep-pdf" data-r="${reg.key}">הפקת PDF</button>
        <button class="btn primary" data-act="inv-save" data-reg="${reg.id}">שמירת השינויים</button>
      </div>
    </section>

    ${out.length ? `
    <section class="panel">
      <h2 class="panel-title">פריטים שאינם ${esc(reg.placeIn)} <span class="pill bad num">${out.length}</span></h2>
      <p class="panel-sub">פריטים שיצאו מ${esc(reg.place)} ורשומים על מישהו. הם אינם נספרים במלאי, אך נשארים ברישום. החזרת המיקום ל"${esc(nameOf(reg.locs, reg.home))}" מחזירה אותם לרשימה למעלה.</p>
      ${visOut.length
        ? `<div class="tbl-scroll">
             <table class="tbl" data-phone="2,3,-1">
               <thead><tr>
                 <th>סוג</th><th>פריט</th><th class="num">מס׳ סידורי</th><th>אצל מי</th>
                 <th>מיקום</th><th class="num">נוסף</th><th>הסרה</th><th></th>
               </tr></thead>
               <tbody>${rowsOut}</tbody>
             </table>
           </div>
           ${pager(`${reg.key}Out`, pOut)}
           <div class="rec-actions mt">
             <button class="btn primary" data-act="inv-save" data-reg="${reg.id}">שמירת השינויים</button>
           </div>`
        : '<p class="empty">אין פריט בחוץ שתואם את החיפוש.</p>'}
    </section>` : ''}

    <section class="panel">
      <h2 class="panel-title">יומן פעולות</h2>
      <p class="panel-sub">כל הוספה, השאלה, החזרה והסרה — עם המיקום שממנו ואליו, שם מי שלקח והתאריך. ${log.length > 200 ? 'מוצגות 200 הפעולות האחרונות.' : ''}</p>
      ${log.length
        ? `<div class="tbl-scroll">
             <table class="tbl" data-phone="0,1,4">
               <thead><tr>
                 <th class="num">תאריך</th><th>פעולה</th><th>סוג</th><th>פריט</th>
                 <th class="num">מס׳ סידורי</th><th>בעלים</th><th>תנועה</th><th>אצל מי</th>
                 <th>הערה</th><th></th>
               </tr></thead>
               <tbody>${logRows}</tbody>
             </table>
           </div>
           ${reportButtons(reg.logKey)}`
        : '<p class="empty">טרם בוצעו פעולות.</p>'}
    </section>`;
}

/* ── Tzelem report ─────────────────────────────────────────────────── */

// The count is of what physically sits in the armoury, so weapons appear only
// while they are there. אקילה and צל״ם are tracked wherever they are, because
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
      <p class="panel-sub"><strong>נשקים</strong> מוצגים רק כשהם נמצאים בארמון. <strong>אקילה וצל״ם</strong> מוצגים בכל המצבים, כולל אצל חייל. המיקום נקבע בלשונית ארמון.</p>
      <div class="kpis">
        ${kpi(all.length, 'סה״כ בדו״ח')}
        ${kpi(all.filter((x) => x.kind === 'weapon').length, 'נשקים בארמון', 'ok')}
        ${kpi(all.filter((x) => x.kind === 'amral').length, 'אקילה')}
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
             <table class="tbl" data-phone="1,2,4" id="tzTable">
               <thead><tr><th>סוג</th><th>פריט</th><th class="num">מס׳ סידורי</th><th>בעלים</th><th>מיקום</th></tr></thead>
               <tbody>${rows}</tbody>
             </table>
           </div>
           <div class="rec-actions mt">
             <button class="btn primary" data-act="rep-pdf" data-r="tzelem">הפקת PDF</button>
             <button class="btn wa ghost-wa" data-act="tz-wa">שליחת סיכום בוואטסאפ</button>
             ${csvBtn('tzelem', 'ייצוא ל-CSV')}
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

  // Everything a movement needs sits in the row: how much, where it went and
  // for whom. No dialog chain — you read the shelf count and act on the same
  // line, which is what someone standing at the shelf actually does.
  const rows = vis.map(({ x, i }) => {
    const draft = S.ammoDraft[x.id] || { dest: 'used', qty: '', who: '' };
    const dest = AMMO_DESTS.find((d) => d.id === draft.dest) || AMMO_DESTS[0];
    const usedUp = Math.max(0, x.open - x.qty);
    return `<tr${x.qty === 0 ? ' class="row-short"' : ''}>
      <td><input class="input mini" type="text" maxlength="60" value="${esc(x.name)}"
                 data-act="ammo-name" data-i="${i}" aria-label="שם הפריט"></td>
      <td class="num">
        <input class="input mini num" type="text" inputmode="numeric" maxlength="6"
               value="${x.open}" data-act="ammo-open" data-i="${i}" aria-label="כמות התחלתית ${esc(x.name)}">
      </td>
      <td class="num ${x.qty === 0 ? 'bad' : 'ok'}"><strong>${x.qty}</strong></td>
      <td class="num ${usedUp ? 'warn' : ''}">${usedUp || '—'}</td>
      <td>
        <select class="input mini select-mini" data-act="ammo-dest" data-id="${esc(x.id)}" aria-label="יעד">
          ${AMMO_DESTS.map((d) => `<option value="${d.id}"${draft.dest === d.id ? ' selected' : ''}>${esc(d.name)}</option>`).join('')}
        </select>
        ${dest.noWho ? '' : `<input class="input mini mt-xs" type="text" maxlength="60"
               value="${esc(draft.who)}" data-act="ammo-who" data-id="${esc(x.id)}"
               placeholder="${dest.id === 'soldier' ? 'שם החייל' : 'שם המשימה'}" aria-label="למי">`}
      </td>
      <td>
        <input class="input mini" type="text" maxlength="120" value="${esc(draft.note || '')}"
               data-act="ammo-note" data-id="${esc(x.id)}" placeholder="הערה חופשית" aria-label="הערה">
      </td>
      <td class="num">
        <input class="input mini num" type="text" inputmode="numeric" maxlength="6"
               value="${esc(draft.qty)}" data-act="ammo-qty" data-id="${esc(x.id)}"
               placeholder="0" aria-label="כמות לתנועה">
      </td>
      <td class="nowrap btn-row">
        <button class="btn ghost small" data-act="ammo-issue" data-i="${i}" ${x.qty === 0 ? 'disabled' : ''}>− הוצאה</button>
        <button class="btn ghost small" data-act="ammo-return" data-i="${i}"${dest.loan ? '' : ' disabled'}>↩ החזרה</button>
        <button class="btn ghost small" data-act="ammo-add-qty" data-i="${i}">+ הוספה</button>
        ${delCell(`ammo:${x.id}`, 'ammo-del', { i }, '✕', 'מחיקת הפריט')}
      </td>
    </tr>`;
  }).join('');

  const AMMO_TONE = { add: 'ok', return: 'ok', issue: 'bad' };
  const logRows = log.slice(0, 200).map((e, n) => {
    const act = AMMO_ACTIONS.find((a) => a.id === e.action) || AMMO_ACTIONS[0];
    return `
    <tr>
      <td class="num">${esc(fmtDate(e.t))}</td>
      <td class="${AMMO_TONE[e.action] || ''}">${esc(`${act.sign} ${act.name}`)}</td>
      <td>${esc(e.name)}</td>
      <td class="num">${e.qty}</td>
      <td>${e.dest ? esc(nameOf(AMMO_DESTS, e.dest)) : '—'}</td>
      <td>${esc(e.who || '')}</td>
      <td>${esc(e.note || '')}</td>
      <td>${delCell(`ammoLog:${n}`, 'ammo-log-del', { n }, '✕',
                    'מחיקת שורת היומן', 'למחוק את שורת היומן?')}</td>
    </tr>`;
  }).join('');

  // Who is holding what, right now.
  const out = ammoOut();
  const onShelf = (name) => (S.inv.ammo || []).some((x) => x.name === name);
  const outRows = out.map((r, i) => `
    <tr>
      <td>${esc(r.name)}${onShelf(r.name) ? '' : '<span class="dim"> · אינו במלאי</span>'}</td>
      <td><strong>${esc(r.who)}</strong><span class="dim"> · ${esc(nameOf(AMMO_DESTS, r.dest))}</span></td>
      <td class="num warn"><strong>${r.n}</strong></td>
      <td class="num">${esc(fmtDate(r.last))}</td>
      <td class="nowrap">
        ${askBtn(`aout:${i}`, 'ammo-out-return', '↩ החזרה',
                 onShelf(r.name)
                   ? `להחזיר ${r.n} × ${r.name} מ${r.who} למלאי?`
                   : `${r.name} כבר לא במלאי — לסגור את ההשאלה של ${r.who} בלי להחזיר?`,
                 { data: { i }, yes: 'כן', cls: 'btn primary small' })}
      </td>
    </tr>`).join('');

  return `
    <section class="panel">
      <h2 class="panel-title">הוספת פריט תחמושת</h2>
      <p class="panel-sub">פריט חדש נכנס עם כמות התחלתית. הוצאות וכניסות נרשמות ביומן.</p>
      <form data-form="ammo-add" novalidate>
        <div class="grid2">
          <label class="field">
            <span class="field-label">שם הפריט <span class="req" aria-hidden="true">*</span></span>
            <input class="input" name="name" maxlength="60" placeholder="לדוגמה: 5.56 / רימון עשן" required>
          </label>
          <label class="field">
            <span class="field-label">כמות <span class="req" aria-hidden="true">*</span></span>
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
        ${kpi(all.reduce((n, x) => n + x.open, 0), 'כמות התחלתית')}
        ${kpi(total, 'כמות נוכחית')}
        ${kpi(all.reduce((n, x) => n + Math.max(0, x.open - x.qty), 0), 'נוצל')}
        ${kpi(all.filter((x) => x.qty === 0).length, 'אזלו מהמלאי', all.some((x) => x.qty === 0) ? 'bad' : 'ok')}
      </div>
      ${all.length > 4
        ? plainSearch('ammo-search', 'ammo-qclear', S.regQ.ammo || '', 'חיפוש פריט', all.length, vis.length)
        : ''}
      ${vis.length
        ? `<div class="tbl-scroll">
             <table class="tbl" data-phone="0,2,-1">
               <thead><tr>
                 <th>פריט</th><th class="num">כמות התחלתית</th><th class="num">כמות נוכחית</th>
                 <th class="num">נוצל</th><th>יעד</th><th>הערה</th><th class="num">כמות</th><th></th>
               </tr></thead>
               <tbody>${rows}</tbody>
             </table>
           </div>
           ${reportButtons('ammo')}`
        : `<p class="empty">${all.length ? 'אין פריט שתואם את החיפוש.' : 'המלאי ריק. הוסיפו פריט למעלה.'}</p>`}
    </section>

    <section class="panel${out.length ? ' alert' : ''}">
      <h2 class="panel-title">בהשאלה עכשיו ${out.length ? `<span class="pill warn num">${out.reduce((n, r) => n + r.n, 0)}</span>` : ''}</h2>
      <p class="panel-sub">מה שנמסר לחייל או למשימה וטרם הוחזר, מחושב מהיומן. ↩ החזרה בשורה מחזירה את הכמות למלאי וסוגרת את ההשאלה. פריט שכבר נמחק מהמלאי — ההשאלה נסגרת בלבד, בלי להוסיף למלאי שאינו קיים.</p>
      ${out.length
        ? `<div class="tbl-scroll">
             <table class="tbl" data-phone="0,1,-1">
               <thead><tr><th>פריט</th><th>אצל מי</th><th class="num">כמות</th><th class="num">תנועה אחרונה</th><th></th></tr></thead>
               <tbody>${outRows}</tbody>
             </table>
           </div>
           <div class="rec-actions mt">
             ${csvBtn('ammoOut', 'ייצוא ל-CSV')}
             <button class="btn ghost" data-act="rep-pdf" data-r="ammoOut">הפקת PDF</button>
             ${askBtn('aout-all', 'ammo-out-all', 'סגירת כל ההשאלות',
                      `לסגור את ${out.length === 1 ? 'ההשאלה הפתוחה' : `${out.length} ההשאלות הפתוחות`}? מה שקיים במלאי יוחזר אליו, והשאר ייסגר ביומן.`,
                      { yes: 'כן, לסגור הכול', tone: 'danger', cls: 'btn danger' })}
           </div>`
        : '<p class="empty">אין תחמושת בהשאלה — הכול הוחזר או נוצל.</p>'}
    </section>

    <section class="panel">
      <h2 class="panel-title">יומן תנועות</h2>
      ${log.length
        ? `<div class="tbl-scroll">
             <table class="tbl" data-phone="0,2,3">
               <thead><tr><th class="num">תאריך</th><th>פעולה</th><th>פריט</th><th class="num">כמות</th><th>יעד</th><th>למי</th><th>הערה</th><th></th></tr></thead>
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
      <td><input class="input mini num wide" type="text" maxlength="20" value="${esc(x.plate)}"
                 data-act="veh-plate" data-i="${i}" aria-label="מספר רכב" placeholder="12-345-67"></td>
      <td><input class="input mini" type="text" maxlength="40" value="${esc(x.company)}"
                 data-act="veh-company" data-i="${i}" aria-label="חברת השכרה" placeholder="חברה"></td>
      <td><input class="input mini num" type="text" inputmode="numeric" maxlength="7" value="${x.km}"
                 data-act="veh-km" data-i="${i}" aria-label="ק״מ עדכני"></td>
      <td><input class="input mini" type="date" value="${esc(x.service)}" min="${DATE_MIN}" max="${DATE_MAX}"
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
      <td>${delCell(`veh:${i}`, 'veh-del', { i }, '✕', 'מחיקת הרכב')}</td>
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
             <table class="tbl" data-phone="0,-2,-1">
               <thead><tr>
                 <th class="num">מספר רכב</th><th>חברת השכרה</th><th class="num">ק״מ</th><th class="num">טיפול</th>
                 <th class="num">קוד קודן</th><th class="num">קוד דלקן</th>
                 ${VEH_KIT.map((k) => `<th class="num kit-col" title="${esc(k.name)}"><span class="lg-h">${esc(k.short)}</span></th>`).join('')}
                 <th>סטטוס</th><th></th>
               </tr></thead>
               <tbody>${rows}</tbody>
             </table>
           </div>`
        : `<p class="empty">${all.length ? 'אין רכב שתואם את החיפוש.' : 'אין רכבים. הוסיפו את הראשון למטה.'}</p>`}
      <div class="rec-actions mt">
        <button class="btn ghost" data-act="veh-add">+ הוספת רכב</button>
        ${csvBtn('vehicles', 'ייצוא ל-CSV')}
        <button class="btn ghost" data-act="rep-pdf" data-r="vehicles">הפקת PDF</button>
        <button class="btn primary" data-act="inv-save">שמירת השינויים</button>
      </div>
    </section>

    ${refuelPanel()}
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

  // One control per cell. The row is the card — what it is, who holds it, how
  // much is left — and everything you *do* to a card happens in the drawer
  // below it. Refuelling used to be a three-field form inside a cell, which
  // made every row six lines tall and the table wider than any screen.
  const rows = p.slice.map(({ x, i }) => {
    const open = S.fuelOpen.has(x.id);
    const n = x.receipts.length;
    const parts = [
      x.uses.length === 1 ? 'שימוש אחד' : x.uses.length ? `${x.uses.length} שימושים` : '',
      n === 1 ? 'קבלה אחת' : n ? `${n} קבלות` : '',
    ].filter(Boolean);
    const cls = [x.litres < FUEL_LOW ? 'row-short' : '', open ? 'is-open' : ''].filter(Boolean);
    return `<tr${cls.length ? ` class="${cls.join(' ')}"` : ''}>
      <td>
        <select class="input mini select-mini" data-act="fuel-kind" data-i="${i}" aria-label="סוג כרטיס">
          ${FUEL_KINDS.map((k) => `<option value="${k.id}"${x.kind === k.id ? ' selected' : ''}>${esc(k.name)}</option>`).join('')}
        </select>
      </td>
      <td><input class="input mini num wide" type="text" maxlength="30" value="${esc(x.no)}"
                 data-act="fuel-no" data-i="${i}" aria-label="מספר כרטיס" placeholder="1234-5678"></td>
      <td>
        <div class="cellrow">
          <input class="input mini" type="text" maxlength="60" value="${esc(x.holder)}"
                 data-act="fuel-holder" data-i="${i}" aria-label="אצל מי הכרטיס" placeholder="שם החייל">
          <button class="linkbtn" data-act="fuel-office" data-i="${i}"
                  title="העברה למשרד">${FUEL_OFFICE}</button>
        </div>
      </td>
      <td><input class="input mini num" type="text" inputmode="numeric" maxlength="5" value="${x.litres}"
                 data-act="fuel-litres" data-i="${i}" aria-label="ליטרים שנותרו"></td>
      <td class="${x.litres < FUEL_LOW ? 'bad' : 'ok'}">${x.litres < FUEL_LOW ? '⚠ נמוך' : '✓ תקין'}</td>
      <td class="nowrap">
        <button class="btn ghost small" data-act="fuel-open" data-id="${esc(x.id)}"
                aria-expanded="${open}">${open ? 'סגירה' : esc(parts.join(' · ') || 'פתיחה')}</button>
      </td>
      <td class="nowrap">
        ${askBtn(`credit:${i}`, 'fuel-credit',
          x.credited ? '✓ זוכה' : 'סימון זיכוי',
          x.credited ? 'לבטל את סימון הזיכוי?' : `לסמן שכרטיס ${x.no || 'זה'} זוכה אצל קצין רכב?`,
          { data: { i }, yes: x.credited ? 'כן, לבטל' : 'כן, זוכה',
            cls: `btn ${x.credited ? 'ghost' : 'primary'} small` })}
        ${x.credited && x.creditedAt
          ? `<span class="muted-txt num">${esc(new Date(x.creditedAt).toLocaleDateString('he-IL'))}</span>`
          : ''}
      </td>
      <td>${delCell(`fuel:${x.id}`, 'fuel-del', { i }, '✕', 'מחיקת הכרטיס')}</td>
    </tr>
    ${open ? `<tr class="sub"><td colspan="8">${fuelDetail(x, i)}</td></tr>` : ''}`;
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
             <table class="tbl" data-phone="1,5">
               <thead><tr>
                 <th>סוג</th><th class="num">מספר כרטיס</th><th>אצל מי</th>
                 <th class="num" title="ליטרים שנותרו">ליטרים</th><th>סטטוס</th>
                 <th>שימושים וקבלות</th><th>זיכוי</th><th></th>
               </tr></thead>
               <tbody>${rows}</tbody>
             </table>
           </div>
           ${pager('fuel', p)}`
        : `<p class="empty">${all.length ? 'אין כרטיס שתואם את החיפוש.' : 'אין כרטיסי תדלוק. הוסיפו את הראשון למטה.'}</p>`}
      <div class="rec-actions mt">
        <button class="btn ghost" data-act="fuel-add">+ הוספת כרטיס</button>
        ${csvBtn('fuel', 'כרטיסים — CSV')}
        <button class="btn ghost" data-act="rep-pdf" data-r="fuel">כרטיסים — PDF</button>
        ${csvBtn('fuelUses', 'יומן שימושים — CSV')}
        <button class="btn ghost" data-act="rep-pdf" data-r="fuelUses">יומן שימושים — PDF</button>
        <button class="btn primary" data-act="inv-save">שמירת השינויים</button>
      </div>
    </section>`;
}

// The expanded row: who used the card, and the receipts. Thumbnails are fetched
// and decrypted one at a time, so opening a card with twenty receipts does not
// pull twenty images at once.
/* Refuelling reports waiting to be filed against a card. The soldier picked a
   card, but an older report carries a typed number and a typo there must not
   quietly take litres off the wrong card — so the number is matched, and where
   it does not match exactly the admin picks the card before anything moves.

   A filed report is not thrown away. It stays here, marked with the card it
   went to, because "who reported this and what did I do with it" is a question
   that gets asked weeks later. The list opens on what still needs doing. */
function refuelPanel() {
  const all = refuelReports();
  const open = all.filter((r) => r.status !== 'done');
  if (!all.length) return '';

  const cards = (S.inv && S.inv.fuel) || [];
  const norm = (v) => String(v || '').replace(/\D/g, '');
  const vis = all.filter((r) =>
    S.rfFilter === 'all' ? true : S.rfFilter === 'done' ? r.status === 'done' : r.status !== 'done');

  const filters = [['open', 'ממתין לקליטה'], ['done', 'נקלטו'], ['all', 'הכל']]
    .map(([id, label]) =>
      `<button class="filter" aria-pressed="${S.rfFilter === id}" data-act="rf-filter" data-f="${id}">${label}</button>`)
    .join('');

  const rows = vis.map((r) => {
    const d = r.data;
    const done = r.status === 'done';
    // The form sends the card's own id. Older reports carry a typed number,
    // so those still fall back to matching on the digits.
    const match = cards.find((c) => c.id === d.card)
      || cards.find((c) => norm(c.no) && norm(c.no) === norm(d.card));
    const picked = S.rfPick[r.id] || (match ? match.id : '');
    const target = cards.find((c) => c.id === picked);
    return `
      <tr${done || target ? '' : ' class="row-short"'}>
        <td class="num">${esc(fmtDate(d.createdAt))}</td>
        <td>${esc(d.name)}</td>
        <td class="num">
          ${esc(S.revealed.has(r.id) ? d.phone : maskPhone(d.phone))}
          <button class="linkbtn" data-act="rep-reveal" data-id="${esc(r.id)}">${S.revealed.has(r.id) ? 'הסתרה' : 'הצגה'}</button>
        </td>
        <td>${esc(d.cardLabel || d.card)}</td>
        <td class="num"><strong>${d.litres}</strong></td>
        <td class="num">${esc(d.plate)}</td>
        <td>
          ${done
            ? `<span class="state done">✓ נקלט${match ? ` — ${esc(nameOf(FUEL_KINDS, match.kind))} ${esc(match.no || '')}` : ''}</span>`
            : match && !S.rfPick[r.id]
              ? `<span class="ok">✓ ${esc(nameOf(FUEL_KINDS, match.kind))}</span>`
              : `<select class="input mini select-mini" data-act="rf-pick" data-id="${esc(r.id)}" aria-label="לאיזה כרטיס">
                   <option value="">כרטיס לא זוהה — בחרו</option>
                   ${cards.map((c) => `<option value="${esc(c.id)}"${picked === c.id ? ' selected' : ''}>${esc(nameOf(FUEL_KINDS, c.kind))} · ${esc(c.no || 'ללא מספר')}</option>`).join('')}
                 </select>`}
        </td>
        <td class="nowrap">
          ${done
            ? `<button class="btn ghost small" data-act="rf-reopen" data-id="${esc(r.id)}">החזרה לטיפול</button>`
            : `<button class="btn primary small" data-act="rf-file" data-id="${esc(r.id)}"
                       ${target ? '' : 'disabled'}>קליטה לכרטיס</button>`}
          ${delCell(`rep:${r.id}`, 'rep-del', { id: r.id }, '✕', 'מחיקת הדיווח', 'למחוק את הדיווח?')}
        </td>
      </tr>`;
  }).join('');

  return `
    <section class="panel">
      <h2 class="panel-title">דיווחי תדלוק ${open.length ? `<span class="pill bad num">${open.length}</span>` : ''}</h2>
      <p class="panel-sub">מה שחיילים דיווחו מהשטח דרך "דיווח תדלוק". קליטה מורידה את הליטרים מיתרת הכרטיס ורושמת את השימוש בכרטיס, יחד עם הקבלה. הדיווח נשאר כאן גם אחרי הקליטה. שורה באדום — מספר הכרטיס לא זוהה, בחרו כרטיס לפני הקליטה.</p>
      <div class="filters">${filters}</div>
      ${vis.length
        ? `<div class="tbl-scroll">
             <table class="tbl" data-phone="1,4,-1">
               <thead><tr>
                 <th class="num">דווח</th><th>מי תדלק</th><th class="num">טלפון</th>
                 <th class="num">מספר כרטיס</th><th class="num">ליטרים</th><th class="num">רכב</th>
                 <th>כרטיס במערכת</th><th></th>
               </tr></thead>
               <tbody>${rows}</tbody>
             </table>
           </div>`
        : `<p class="empty">${S.rfFilter === 'done' ? 'טרם נקלט דיווח.' : 'כל הדיווחים נקלטו.'}</p>`}
    </section>`;
}

// Filing one report against a card: the litres come off the balance and the
// use is logged with the soldier's own name, so the card's history reads the
// same whether it was typed here or reported from the field.
const refuelFile = (id) =>
  withBusy(async () => {
    const rec = S.reports.find((r) => r.id === id);
    if (!rec || !rec.data) return;
    const cards = S.inv.fuel || [];
    const norm = (v) => String(v || '').replace(/\D/g, '');
    const picked = S.rfPick[id];
    const card = picked
      ? cards.find((c) => c.id === picked)
      : (cards.find((c) => c.id === rec.data.card)
        || cards.find((c) => norm(c.no) && norm(c.no) === norm(rec.data.card)));
    if (!card) { toast('לא נבחר כרטיס', true); return; }

    const d = rec.data;
    const before = { uses: card.uses, litres: card.litres, receipts: card.receipts };
    card.uses = [{ t: d.createdAt || Date.now(), who: d.name, litres: d.litres, plate: d.plate }, ...(card.uses || [])];
    card.litres = Math.max(0, card.litres - d.litres);
    // The soldier's receipt was filed against the report; filing moves it onto
    // the card, where the vehicle officer will look for it. The image is never
    // decrypted on the way — the same envelope is written under a new id.
    const got = await api(`/admin/docs/${id}`).catch(() => ({ docs: [] }));
    const shot = (got.docs || []).find((x) => x.kind === 'refuel');
    if (shot) {
      const docId = hex(crypto.getRandomValues(new Uint8Array(16)));   // the docs route wants 32 hex
      await api(`/admin/docs/${docId}/fuel`, {
        method: 'PUT',
        body: { ek: shot.ek, iv: shot.iv, ct: shot.ct },
      }).catch(() => {});
      card.receipts = [...(card.receipts || []), { id: docId, at: d.createdAt || Date.now() }];
    }
    // saveInv, not invSave: this is already inside withBusy, and invSave is
    // itself wrapped in it — so calling it here would find the flag up, decline
    // to run, and return as though it had saved. The litres would come off the
    // card on screen and nowhere else, and the next refresh would put them
    // back. Nothing is marked filed until the vault actually took the write.
    try {
      await saveInv();
    } catch (e) {
      Object.assign(card, before);                 // the screen goes back to the truth
      renderConsole();
      throw e;
    }
    await api(`/admin/reports/${id}`, { method: 'PUT', body: { status: 'done' } });
    rec.status = 'done';
    delete S.rfPick[id];
    renderConsole();
    toast(`נקלט — ${d.litres} ליטר ירדו מהכרטיס`);
  });

// Putting a filed report back in the queue. Filing writes to the card, and a
// card is only ever written by hand — so when it went to the wrong card, or
// went nowhere because the save did not land, the way back is to file it
// again. This only moves the report; whatever reached the card stays there
// and is removed from the card itself.
const refuelReopen = (id) =>
  withBusy(async () => {
    const rec = S.reports.find((r) => r.id === id);
    if (!rec) return;
    await api(`/admin/reports/${id}`, { method: 'PUT', body: { status: 'open' } });
    rec.status = 'open';
    renderConsole();
    toast('הדיווח חזר לטיפול — בדקו את הכרטיס לפני קליטה חוזרת');
  });

function fuelDetail(card, i) {
  const draft = S.fuelDraft[card.id] || {};

  // Recording a refuelling: the three things you have to say, on one line,
  // with room to type them. This is the work the drawer exists for.
  const entry = `
    <div class="fuel-entry">
      <label class="field mb0">
        <span class="field-label">מי תדלק</span>
        <input class="input mini" type="text" maxlength="60" value="${esc(draft.who || '')}"
               data-act="fuel-use-who" data-id="${esc(card.id)}" placeholder="שם החייל">
      </label>
      <label class="field mb0">
        <span class="field-label">ליטרים</span>
        <input class="input mini num" type="text" inputmode="numeric" maxlength="5"
               value="${esc(draft.litres || '')}" data-act="fuel-use-litres" data-id="${esc(card.id)}"
               placeholder="0">
      </label>
      <label class="field mb0">
        <span class="field-label">רכב</span>
        <input class="input mini num" type="text" maxlength="20" value="${esc(draft.plate || '')}"
               data-act="fuel-use-plate" data-id="${esc(card.id)}" placeholder="12-345-67">
      </label>
      <button class="btn primary small" data-act="fuel-use" data-i="${i}">רישום שימוש</button>
    </div>
    <p class="field-hint mb0">הליטרים יורדו מיתרת הכרטיס אוטומטית.</p>`;

  const upload = `
    <div class="fuel-entry">
      <label class="btn ghost small">📷 צילום קבלה
        <input class="vis-hidden" type="file" accept="image/*" capture="environment" multiple
               data-act="fuel-file" data-i="${i}"></label>
      <label class="btn ghost small">🖼 בחירה מהגלריה
        <input class="vis-hidden" type="file" accept="image/*" multiple
               data-act="fuel-file" data-i="${i}"></label>
      ${card.receipts.length
        ? `<button class="btn ghost small" data-act="fuel-dl-all" data-i="${i}">הורדת כל הקבלות</button>`
        : ''}
    </div>`;

  const uses = card.uses.length
    ? `<table class="tbl compact" data-phone="0,1,2">
         <thead><tr><th class="num">תאריך</th><th>מי השתמש</th><th class="num">ליטרים</th><th class="num">רכב</th><th></th></tr></thead>
         <tbody>${card.uses.map((u, n) => `
           <tr>
             <td class="num">${esc(fmtDate(u.t))}</td>
             <td>${esc(u.who)}</td>
             <td class="num">${u.litres}</td>
             <td class="num">${u.plate ? esc(u.plate) : '—'}</td>
             <td>${delCell(`fuse:${card.id}:${n}`, 'fuel-use-del', { i, n }, '✕', 'מחיקת השימוש')}</td>
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
                 ${delCell(`frcpt:${r.id}`, 'fuel-doc-del', { i, r: r.id }, 'מחיקה', 'מחיקת הקבלה')}
               </figcaption>
             </figure>`;
         }).join('')}
       </div>`
    : '';

  const used = card.uses.reduce((s, u) => s + u.litres, 0);
  return `
    <div class="fuel-detail">
      <h3 class="fuel-h">רישום תדלוק</h3>
      ${entry}
      <h3 class="fuel-h mt">יומן שימושים — סה״כ <span class="num">${used}</span> ליטר</h3>
      ${uses}
      <h3 class="fuel-h mt">קבלות${card.receipts.length ? ` (${card.receipts.length})` : ''}</h3>
      ${upload}
      ${rcpts || '<p class="empty mb0">טרם צורפו קבלות לכרטיס.</p>'}
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
    for (const r of card.receipts) {
      await api(`/admin/docs/${r.id}/fuel`, { method: 'DELETE' }).catch(() => {});
      docForget(`${r.id}:fuel`);
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
    const files = [...(input.files || [])].filter((f) => !notAnImage(f));
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

/* Decrypted photographs, and how many of them to keep.

   A licence or a receipt is a few hundred kilobytes once it is decrypted, and
   nothing ever released one: a session spent going through a month of
   receipts held every one of them until the console was locked. They are kept
   to a working set now — open the twelfth and the one you looked at longest
   ago is dropped. Re-opening it costs one fetch, which is what it cost the
   first time.

   They are still never written anywhere. The cache is memory, it dies with
   the tab, and lock() empties it as before. */
const DOC_CACHE_MAX = 12;

function docCache(key, dataUrl) {
  S.docs[key] = dataUrl;
  S.docOrder = S.docOrder.filter((k) => k !== key);
  S.docOrder.push(key);
  while (S.docOrder.length > DOC_CACHE_MAX) {
    const oldest = S.docOrder.shift();
    delete S.docs[oldest];
    // An evicted photo must be allowed back. `docTried` exists to stop an
    // auto-load looping, not to make eviction permanent — leaving the key in
    // it means the thumbnail vanishes on the thirteenth soldier and never
    // comes back for the rest of the session.
    S.docTried.delete(oldest);
    S.docBig.delete(oldest);
  }
  return dataUrl;
}

const docForget = (key) => {
  delete S.docs[key];
  S.docOrder = S.docOrder.filter((k) => k !== key);
  S.docTried.delete(key);
  S.docBig.delete(key);
};

// Pulls and decrypts one receipt. Cached afterwards, so re-opening is free.
async function fuelDocLoad(docId) {
  const key = `${docId}:fuel`;
  if (S.docs[key]) return docCache(key, S.docs[key]);   // also marks it recently used
  const { docs } = await api(`/admin/docs/${docId}`);
  const row = (docs || []).find((x) => x.kind === 'fuel');
  if (!row) throw new Error('הקבלה לא נמצאה');
  const bytes = await openBytes(S.priv, row);
  let bin = '';
  for (const b of new Uint8Array(bytes)) bin += String.fromCharCode(b);
  return docCache(key, `data:image/jpeg;base64,${btoa(bin)}`);
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
    await api(`/admin/docs/${docId}/fuel`, { method: 'DELETE' });
    docForget(`${docId}:fuel`);
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

// Who took the card out and how much they burned. The details are typed into
// the row itself, so recording a refuelling is one line of the table rather
// than a chain of dialogs.
function fuelUse(i) {
  const card = (S.inv.fuel || [])[i];
  if (!card) return;
  const d = S.fuelDraft[card.id] || {};
  const who = (d.who || '').trim();
  const litres = Math.max(0, Math.min(99999, parseInt(String(d.litres || '').replace(/\D/g, ''), 10) || 0));
  if (who.length < 2) { toast('נא למלא מי השתמש בכרטיס', true); return; }
  if (!litres) { toast('נא למלא כמות ליטרים', true); return; }
  if (litres > card.litres) { toast(`בכרטיס יש ${card.litres} ליטר בלבד`, true); return; }
  card.uses = [{
    t: Date.now(), who: who.slice(0, 60), litres, plate: (d.plate || '').trim().slice(0, 20),
  }, ...card.uses].slice(0, 300);
  card.litres = Math.max(0, card.litres - litres);
  S.fuelDraft[card.id] = {};
  S.fuelOpen.add(card.id);
  invSave();
}

function fuelCredit(i) {
  const card = (S.inv.fuel || [])[i];
  if (!card) return;
  S.askDel = '';
  card.credited = !card.credited;
  card.creditedAt = card.credited ? Date.now() : 0;
  invSave();
}

/* ── Armoury / ammunition / vehicle actions ───────────────────────── */

const logPush = (key, entry) => {
  S.inv[key] = [entry, ...(S.inv[key] || [])].slice(0, 5000);
};

// Which register a control belongs to. Unknown or missing falls back to the
// armoury, which is what every one of these controls meant before there were
// two registers — and it is a read of a screen the user is already on, never
// a privilege decision.
const regOf = (el) => REGISTERS[(el && el.dataset && el.dataset.reg) || ''] || REGISTERS.armon;

function armAdd(form) {
  const reg = regOf(form);
  const kind = form.kind.value;
  const name = form.name.value.trim();
  const serial = form.serial.value.trim();
  const owner = form.owner.value.trim();
  if (!reg.kinds.some((k) => k.id === kind)) return setFormErr(form, 'נא לבחור סוג פריט');
  if (name.length < 2) return setFormErr(form, 'נא למלא שם פריט');
  if (serial.length < 2) return setFormErr(form, 'נא למלא מספר סידורי');
  if (owner.length < 2) return setFormErr(form, 'נא למלא שם מלא של בעל הפריט');
  // A number identifies one physical item, so it may exist once across the
  // whole unit — not once per register, and not once per kind. A מק״ט typed
  // twice is either the same item entered twice or a transcription error, and
  // both are worth stopping at the point of entry.
  const taken = serialTaken(serial);
  if (taken) return setFormErr(form, taken);
  setFormErr(form, '');
  const now = Date.now();
  S.inv[reg.key] = [...(S.inv[reg.key] || []), { id: rndId(), kind, name, serial, owner, loc: reg.home, note: '', addedAt: now }];
  logPush(reg.logKey, { t: now, action: 'add', kind, name, serial, owner, dest: '', note: '' });
  invSave();
}

// Removing an item from the register needs to say where it went. The
// destination and the note are chosen in the row, next to the item they
// describe, so the answer is given before the button is pressed rather than
// after it in a dialog.
function armRemove(reg, i) {
  const it = (S.inv[reg.key] || [])[i];
  if (!it) return;
  const d = S.armDraft[it.id] || {};
  const dest = ARM_DESTS.find((x) => x.id === d.dest);
  if (!dest) { toast('נא לבחור לאן הפריט מועבר', true); return; }
  S.inv[reg.key] = S.inv[reg.key].filter((_, n) => n !== i);
  logPush(reg.logKey, {
    t: Date.now(), action: 'remove', kind: it.kind, name: it.name,
    serial: it.serial, owner: it.owner, dest: dest.id, note: (d.note || '').slice(0, 120),
  });
  delete S.armDraft[it.id];
  invSave();
}

// Lending an item out: the three questions the act actually consists of —
// what, to whom, until when — asked once, in the order somebody asks them out
// loud. Before this, taking a scope out of the armoury meant finding its row
// among hundreds and changing a select inside it, which is why so many rows
// said "אצל חייל" and nothing else. The movement itself is not written here:
// logMoves sees it at the save, as it sees every other way an item can move.
function armLoan(form) {
  const reg = regOf(form);
  const it = (S.inv[reg.key] || []).find((x) => x.id === form.item.value);
  const loc = form.loc.value;
  const who = form.who.value.trim();
  if (!it) return setFormErr(form, 'נא לבחור פריט');
  // The picker does not offer these, but the picker is a screen and this is
  // the gate: a weapon leaves the armoury through the deposit flow, not here.
  if (!canLoan(reg, it.kind)) {
    return setFormErr(form, `${nameOf(reg.kinds, it.kind)} אינו מושאל מכאן — שנו את המיקום ברישום`);
  }
  if (!LOAN_LOCS.has(loc)) return setFormErr(form, 'נא לבחור לאן הפריט יוצא');
  // A kind that may not go there is refused rather than quietly corrected —
  // only צל״ם goes out on an operation, and the register is where that is said.
  if (!kindLocs(reg, it.kind).some((l) => l.id === loc)) {
    return setFormErr(form,
      `${nameOf(reg.kinds, it.kind)} לא יכול לצאת ל"${nameOf(reg.locs, loc)}"`);
  }
  if (who.length < 2) return setFormErr(form, 'נא למלא את שם מי שלוקח את הפריט');
  setFormErr(form, '');
  it.loc = loc;
  it.mission = who;
  it.since = Date.now();
  invSave();
}

// The other half. One press, because the alternative — reopen the row, set the
// location back, clear the name — is three chances to leave a returned weapon
// reading as still out.
function armReturn(reg, i) {
  const it = (S.inv[reg.key] || [])[i];
  if (!it) return;
  S.askDel = '';
  it.loc = reg.home;
  it.mission = '';
  invSave();          // logMoves writes the return, and how long it was gone
}

function ammoAdd(form) {
  const name = form.name.value.trim();
  const qty = parseInt(form.qty.value, 10);
  if (name.length < 2) return setFormErr(form, 'נא למלא שם פריט');
  if (!Number.isFinite(qty) || qty < 1) return setFormErr(form, 'נא למלא כמות חיובית');
  setFormErr(form, '');
  const now = Date.now();
  const existing = (S.inv.ammo || []).find((x) => x.name.toLowerCase() === name.toLowerCase());
  if (existing) {
    existing.qty = Math.min(999999, existing.qty + qty);
    existing.open = Math.min(999999, existing.open + qty);
  } else {
    S.inv.ammo = [...(S.inv.ammo || []), { id: rndId(), name, open: qty, qty }];
  }
  logPush('ammoLog', { t: now, action: 'add', name, qty, dest: '', who: '', note: '' });
  invSave();
}

// Reads the row's own fields rather than asking a chain of questions.
// Three movements, not two: rounds arrive, rounds go out, and rounds that went
// out to a soldier or an operation come back. The third one used to be filed as
// an arrival, which is the bug behind "someone takes it for a mission and then
// returns it" having no answer here.
function ammoMove(i, action) {
  const it = (S.inv.ammo || [])[i];
  if (!it) return;
  const draft = S.ammoDraft[it.id] || {};
  const n = Math.max(0, parseInt(String(draft.qty || '').replace(/\D/g, ''), 10) || 0);
  if (!n) { toast('נא למלא כמות בשורה', true); return; }
  if (action === 'issue' && n > it.qty) { toast(`אין מספיק במלאי — יש ${it.qty}`, true); return; }

  let dest = '', who = '';
  if (action !== 'add') {
    const d = AMMO_DESTS.find((x) => x.id === draft.dest) || AMMO_DESTS[0];
    // What was thrown or credited is gone. Asking for it back is not a
    // movement, it is a mistake, and it is refused where it is made.
    if (action === 'return' && !d.loan) {
      toast('החזרה אפשרית רק ממה שנמסר לחייל או למשימה', true);
      return;
    }
    dest = d.id;
    who = d.noWho ? '' : (draft.who || '').trim().slice(0, 60);
    if (!d.noWho && who.length < 2) {
      toast(d.id === 'soldier' ? 'נא למלא שם חייל' : 'נא למלא שם משימה', true);
      return;
    }
  }
  it.qty = Math.max(0, Math.min(999999, it.qty + (action === 'issue' ? -n : n)));
  // A delivery raises the baseline so that "used" stays a true difference. A
  // return does not: those rounds were counted as issued once already, and
  // counting them again would quietly erase the consumption they came out of.
  if (action === 'add') it.open = Math.max(0, Math.min(999999, it.open + n));
  logPush('ammoLog', {
    t: Date.now(), action, name: it.name, qty: n, dest, who,
    note: (draft.note || '').trim().slice(0, 120),
  });
  S.ammoDraft[it.id] = { ...draft, qty: '', note: '' };
  invSave();
}

/* Closing an outstanding loan from the panel that shows it.

   The return used to live only in the stock row above: fill a quantity, pick
   the same destination, retype the same name, press. That works while the item
   is still on the shelf — and it is unreachable the moment somebody deletes
   the stock line, because then there is no row to fill in. The loan stays open
   for ever, on a screen with no button on it, which is exactly where this was
   found: forty-four rounds owed by people, against items that no longer exist.

   So the loan closes from its own row. If the item is still stocked the rounds
   go back on the shelf; if it is not, the movement is written and nothing is
   added to a stock line that is not there. Either way the debt is settled and
   the log says what happened. */
function ammoCloseLoan(row, now) {
  const it = (S.inv.ammo || []).find((x) => x.name === row.name);
  if (it) it.qty = Math.max(0, Math.min(999999, it.qty + row.n));
  logPush('ammoLog', {
    t: now, action: 'return', name: row.name, qty: row.n,
    dest: row.dest, who: row.who,
    note: it ? '' : 'הפריט אינו במלאי — ההשאלה נסגרה',
  });
}

function ammoOutReturn(i) {
  const row = ammoOut()[i];
  if (!row) return;
  S.askDel = '';
  ammoCloseLoan(row, Date.now());
  invSave();
}

function ammoOutAll() {
  const rows = ammoOut();          // snapshot: closing them changes the reading
  if (!rows.length) return;
  S.askDel = '';
  const now = Date.now();
  for (const row of rows) ammoCloseLoan(row, now);
  invSave();
}

/* What is still out, per item and per holder.
   Derived from the log rather than kept as a counter, because a counter and a
   log can disagree and then neither of them is worth reading. The log is the
   record; this is a reading of it. */
function ammoOut() {
  const by = new Map();
  for (const e of (S.inv && S.inv.ammoLog) || []) {
    if (e.action !== 'issue' && e.action !== 'return') continue;
    const d = AMMO_DESTS.find((x) => x.id === e.dest);
    if (!d || !d.loan) continue;                 // consumed or credited, not owed
    const who = (e.who || '').trim();
    if (!who) continue;
    const key = `${e.name} ${who}`;
    const row = by.get(key) || { name: e.name, who, dest: e.dest, n: 0, last: 0 };
    row.n += e.action === 'issue' ? e.qty : -e.qty;
    row.last = Math.max(row.last, e.t || 0);
    by.set(key, row);
  }
  return [...by.values()].filter((r) => r.n > 0).sort((a, b) => b.n - a.n || a.who.localeCompare(b.who, 'he'));
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
// What each kind of report is called when it is listed outside its own tab.
const REPORT_KIND = {
  deposit: 'אפסון נשק', fault: 'תקלת בינוי', refuel: 'דיווח תדלוק', report: 'בקשת חוסר',
};

const isKind = (r, k) => !r.damaged && !!r.data && r.data.kind === k;
const isDeposit = (r) => isKind(r, 'deposit');
const isFault = (r) => isKind(r, 'fault');
const isRefuel = (r) => isKind(r, 'refuel');
const shortageReports = () => S.reports.filter((r) => !isDeposit(r) && !isFault(r) && !isRefuel(r));
const depositReports = () => S.reports.filter(isDeposit);
const faultReports = () => S.reports.filter(isFault);
const refuelReports = () => S.reports.filter(isRefuel);
const openRefuels = () => refuelReports().filter((r) => r.status !== 'done').length;

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

const commsCount = () => ((S.inv && S.inv.comms) || []).filter((x) => x.loc === 'store').length;
// What the signals store needs someone to look at: kit that is unusable, out
// for repair, or filed somewhere unnamed.
const commsAlerts = () => ((S.inv && S.inv.comms) || []).filter(
  (x) => ARM_BAD_LOCS.has(x.loc) || x.loc === 'repair' || (NAMED_LOCS[x.loc] && !x.mission)
).length;

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
            <div class="rec-actions">${delCell(`rep:${rec.id}`, 'rep-del', { id: rec.id }, 'מחיקה', 'מחיקת הדיווח')}</div>
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
            ${repEditLink(rec)}
            ${delCell(`rep:${rec.id}`, 'rep-del', { id: rec.id }, 'מחיקה', 'מחיקת הדיווח')}
          </div>
          ${repEditor(rec)}
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
          ${repEditLink(r)}
          ${delCell(`rep:${r.id}`, 'rep-del', { id: r.id }, 'מחיקה', 'מחיקת הדיווח')}
        </div>
        ${repEditor(r)}
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
    // Only the two states that are an answer to the soldier are worth a
    // message. Reopening is an internal move and nobody is waiting to hear it.
    const w = (next === 'done' || next === 'partial')
      ? await waNotify(rec.data && rec.data.phone, waFaultMsg(rec.data || {}, next))
      : { sent: false, why: 'skip' };
    toast((next === 'done' ? 'התקלה סומנה כטופלה'
      : next === 'partial' ? 'סומן כהועבר לטיפול'
      : 'הוחזר למצב פתוח') + waNote(w));
  });

// The wrapped private key, saved to a file. Without the password it is inert,
// which is exactly why it can be kept somewhere else: it turns "we lost the
// laptop" from total loss into an inconvenience. It does NOT rescue a
// forgotten password — nothing can.
const exportRecoveryKey = () =>
  withBusy(async () => {
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

// Ends every session this account has, including this one. The console then
// locks like any sign-out: the key is wiped from memory and the password is
// the only way back in. lock() calls /logout on a session the server has
// already deleted, which answers 401 and is caught — the point was to be gone,
// and it is.
const revokeSessions = () =>
  withBusy(async () => {
    const r = await api('/admin/sessions/revoke', { method: 'POST', body: {} });
    const n = (r && r.ended) || 1;
    lock();
    toast(n > 1 ? `${n} חיבורים נותקו` : 'החיבור נותק');
  });

// The plain fetch, with no busy guard on it, so an action that is already
// running can refresh the bin without the guard turning the call into a no-op.
const fetchTrash = async () => {
  const { records, reports, keepMs } = await api('/admin/trash');
  const open = async (rows, clean = cleanRecord) => {
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
};

const loadTrash = () =>
  withBusy(async () => {
    await fetchTrash();
    renderConsole();
  });

const trashRestore = (kind, id) =>
  withBusy(async () => {
    await api(`/admin/trash/${kind}/${id}`, { method: 'POST', body: {} });
    await fetchTrash();
    await adminRefreshQuiet();
    renderConsole();
    toast('הפריט שוחזר');
  });

const adminRefreshQuiet = async () => {
  const scopes = allowedScopes();
  if (scopes.has('records')) await loadRecords();
  if (scopes.has('reports')) await loadReports();
};

/* ── Watching for what arrives while you are looking at the screen ──────
   A soldier fills in a form and the desk should show it, not wait to be
   told to look. Every few seconds the console asks the server one small
   question — how many records and reports there are and when they last
   changed — and only when that answer moves does it fetch and decrypt
   anything. A quiet unit costs two aggregate queries a tick and nothing
   else; the expensive part happens exactly when there is news.

   It will not redraw under someone's hands: if a field has focus or an
   editor is open, the refresh waits for the next tick. */

const PULSE_MS = 3000;
let pulseTimer = null;
let pulseSig = null;
let pulseBusy = false;

const editorOpen = () =>
  !!(S.recEdit || S.repEdit || S.armEdit || S.userEdit || S.askDel);

// Typing, or a menu the user is part-way through — either way, not now.
const handsOn = () => {
  const a = document.activeElement;
  return !!a && $app.contains(a) && /^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName);
};

function startPulse() {
  stopPulse();
  pulseSig = null;
  pulseTimer = setInterval(pulseTick, PULSE_MS);
}

function stopPulse() {
  clearInterval(pulseTimer);
  pulseTimer = null;
}

async function pulseTick() {
  // Not while locked out, not on a soldier page, not on top of a slow tick,
  // and not while the tab is in the background burning someone's battery.
  if (!S.priv || S.route !== 'admin' || S.adminView !== 'console') return;
  if (pulseBusy || S.busy || document.hidden) return;
  pulseBusy = true;
  try {
    const p = await api('/admin/pulse');
    const sig = `${p.rn}:${p.rt}:${p.pn}:${p.pt}:${p.vt}`;
    if (pulseSig === null) { pulseSig = sig; return; }   // first tick just learns
    if (sig === pulseSig) return;
    if (handsOn() || editorOpen()) return;               // try again next tick
    pulseSig = sig;
    const scopes = allowedScopes();
    // Only what moved since the last tick — see loadRecords.
    if (scopes.has('records')) await loadRecords(true);
    if (scopes.has('reports')) await loadReports(true);
    // The vault is this admin's own writing, so a change is almost always
    // their own save echoing back; reloading it would fight with unsaved edits.
    renderConsole();
  } catch {
    /* a dropped tick is not worth a message — the next one will tell us */
  } finally {
    pulseBusy = false;
  }
}

// Coming back to the tab should feel instant rather than up to three seconds stale.
document.addEventListener('visibilitychange', () => { if (!document.hidden) pulseTick(); });

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
  'edit-report': 'תיקון דיווח',
  // Who came in, who tried and failed, and who was locked out for trying too
  // often. The trail recorded everything an account did except how it got in.
  login: 'כניסה', 'login-fail': 'כניסה נכשלה', 'login-lock': 'נעילה זמנית',
  logout: 'יציאה', 'sessions-revoke': 'ניתוק כל המכשירים',
  wipe: 'מחיקת כל הנתונים', 'wa-send': 'שליחת וואטסאפ מהקו',
};

// Users. Every account carries its own copy of the private key, wrapped under
// its own password — which is why an account can only be created while an
// admin is signed in and holding the unwrapped key in memory.
function usersPanel() {
  const rows = S.users.map((u) => {
    const isMe = u.username === S.me;
    const screens = u.role === 'admin'
      ? '<span class="ok">כל המסכים</span>'
      : tabsLabel(u.tabs);
    const tone = u.role === 'admin' ? 'done' : u.role === 'editor' ? 'live' : 'wait';
    return `<tr>
      <td class="lg-name">${esc(u.username)}${isMe ? ' <span class="tagi">אתם</span>' : ''}</td>
      <td><span class="state ${tone}">${esc(roleName(u.role))}</span></td>
      <td class="screens">${screens}</td>
      <td class="num">${u.last_seen ? esc(fmtDate(u.last_seen)) : '—'}</td>
      <td class="nowrap">
        <button class="btn ghost small" data-act="uedit-open" data-u="${esc(u.username)}">
          ${S.userEdit === u.username ? 'סגירה' : 'עריכה'}
        </button>
        ${isMe ? '' : `${delCell(`user:${u.username}`, 'user-del', { u: u.username }, 'מחיקה', 'מחיקת המשתמש')}`}
      </td>
    </tr>
    ${S.userEdit === u.username ? `<tr class="sub"><td colspan="5">${userEditRow(u)}</td></tr>` : ''}`;
  }).join('');

  const picks = TABS.filter((t) => !t.adminOnly).map((t) => `
    <label class="screenpick ${S.userTabs.has(t.id) ? 'on' : ''}">
      <input type="checkbox" class="kitbox" data-act="utab" data-t="${t.id}"
             ${S.userTabs.has(t.id) ? 'checked' : ''}>
      <span>${esc(t.name)}</span>
    </label>`).join('');

  return `
    <section class="panel">
      <h2 class="panel-title">משתמשים</h2>
      <p class="panel-sub">מנהל רואה ועושה הכול. <strong>קריאה ועריכה</strong> — רואה ומשנה, אך רק במסכים שסימנתם. <strong>צפייה בלבד</strong> — רואה את אותם מסכים בלי לשנות דבר. ניהול משתמשים, יומן הפעולות והאבטחה נשארים אצל המנהל בלבד.</p>
      <div class="tbl-scroll">
        <table class="tbl" data-phone="0,1,-1">
          <thead><tr><th>שם משתמש</th><th>הרשאה</th><th>מסכים</th><th class="num">כניסה אחרונה</th><th></th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </section>

    <section class="panel">
      <h2 class="panel-title">הוספת משתמש</h2>
      <p class="panel-sub">שם משתמש באותיות אנגליות קטנות, ספרות, נקודה, מקף או קו תחתון. סמנו אילו מסכים המשתמש יראה.</p>
      <form data-form="user-add" novalidate>
        <div class="grid2">
          <label class="field">
            <span class="field-label">שם משתמש <span class="req" aria-hidden="true">*</span></span>
            <input class="input" name="username" maxlength="31" spellcheck="false"
                   placeholder="sagan.a" required>
          </label>
          <label class="field">
            <span class="field-label">סיסמה (10 תווים לפחות) <span class="req" aria-hidden="true">*</span></span>
            <input class="input" type="password" name="pw" autocomplete="new-password" required>
          </label>
        </div>
        <fieldset class="lic-set">
          <legend class="field-label">סוג הרשאה <span class="req" aria-hidden="true">*</span></legend>
          <div class="rolepicks">
            ${ROLES.map((r) => `
              <label class="rolepick ${S.userRole === r.id ? 'on' : ''}">
                <input type="radio" name="role" value="${r.id}" class="kitbox"
                       data-act="urole" ${S.userRole === r.id ? 'checked' : ''}>
                <span>
                  <span class="rolepick-t">${esc(r.name)}</span>
                  <span class="rolepick-s">${esc(r.hint)}</span>
                </span>
              </label>`).join('')}
          </div>
        </fieldset>
        <fieldset class="lic-set">
          <legend class="field-label">מסכים מותרים <span class="req" aria-hidden="true">*</span></legend>
          <div class="screenpicks">${picks}</div>
          <div class="rec-actions mt">
            <button class="btn ghost small" type="button" data-act="utab-all">סימון הכול</button>
            <button class="btn ghost small" type="button" data-act="utab-none">ניקוי</button>
          </div>
          <span class="field-hint">שימו לב: מסך הסקירה מציג נתונים מכל המקורות, ולכן סימונו נותן גישה לכל המידע.</span>
        </fieldset>
        <p class="form-err" data-err></p>
        <button class="btn primary wide" type="submit">יצירת משתמש</button>
      </form>
    </section>

    <div class="callout risk">
      <p class="callout-title">מה הרשאת הצפייה כן עושה ומה לא</p>
      <p>המערכת מוצפנת מקצה לקצה, ולכן לכל משתמש יש עותק משלו של מפתח הפענוח. במסכים שהוא כן רואה — הוא רואה <strong>הכול</strong>: שמות, טלפונים, מספרים אישיים וצילומי רישיונות.</p>
      <p class="mb0">מה שהוא לא יכול: <strong>לשנות שום דבר</strong>, ולא למשוך נתונים ממסכים שלא סומנו לו — השרת דוחה גם את בקשות הכתיבה וגם את בקשות המידע שמחוץ להרשאה, לא רק מסתיר כפתורים. מסכים שחולקים מקור מידע אחד אינם ניתנים להפרדה עדינה יותר.</p>
    </div>`;
}

function tabsLabel(tabs) {
  if (tabs === '*') return '<span class="ok">כל המסכים</span>';
  let list = [];
  try { list = JSON.parse(tabs) || []; } catch { list = []; }
  if (!list.length) return '<span class="bad">ללא מסכים</span>';
  return list.map((t) => `<span class="chip">${esc(tabName(t))}</span>`).join(' ');
}

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
                     <td>${r.damaged ? 'דיווח' : REPORT_KIND[r.data.kind] || 'בקשת חוסר'}</td>
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
               <table class="tbl" data-phone="0,1,2">
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

/* ── וואטסאפ ──────────────────────────────────────────────────────── */

/* A hosted service holds the session, so this screen is thin on purpose:
   is a line linked, the code that links one, and a way to prove it works
   before anyone sends to a real soldier.

   None of it is load-bearing. With the service unconfigured this says so and
   the wa.me buttons elsewhere carry on exactly as they always have — they open
   a chat from the admin's own device, with no detail passing through anyone's
   server, which is still the safer of the two. */

const WA_STATE = {
  authorized:    { label: 'מחובר',        tone: 'ok',   hint: 'הקו מקושר. אפשר לשלוח.' },
  notAuthorized: { label: 'לא מחובר',     tone: 'warn', hint: 'סרקו את הקוד מהטלפון של הקו שישמש לשליחה.' },
  starting:      { label: 'מתחיל…',       tone: 'warn', hint: 'המופע עולה אצל הספק. המתינו כמה שניות ורעננו.' },
  blocked:       { label: 'חסום',         tone: 'bad',  hint: 'המופע חסום אצל הספק — בדקו את החשבון שלכם שם.' },
  sleepMode:     { label: 'במצב שינה',    tone: 'warn', hint: 'המופע נרדם מחוסר שימוש. רעננו כדי להעיר אותו.' },
  yellowCard:    { label: 'הוגבל זמנית',  tone: 'bad',  hint: 'הספק הגביל את המופע זמנית בשל קצב שליחה.' },
  unknown:       { label: 'לא ידוע',      tone: 'off',  hint: 'הספק החזיר מצב שאיננו מכירים.' },
};
const waState = () => WA_STATE[S.wa.state] || WA_STATE.unknown;

/* The screen used to ask once and then sit there, on the theory that whoever
   scans is standing in front of it. They are — and that is exactly the moment
   nothing tells the screen anything: the phone links the line at the provider,
   and the console goes on showing a QR and "המשך לסרוק" until somebody thinks
   to press רענון. So it asks again every few seconds, but only while this tab
   is open and only until a line is linked. Once it says מחובר, the timer is
   gone. */
const WA_POLL_MS = 5000;
let waPoll = null;
let waTabOpen = false;   // the wa screen is showing, so its state was asked for

function waPollStop() {
  if (waPoll) { clearInterval(waPoll); waPoll = null; }
}

function waPollStart() {
  if (waPoll) return;
  waPoll = setInterval(() => {
    if (S.tab !== 'wa' || !S.wa.enabled || S.wa.state === 'authorized') return waPollStop();
    if (!S.wa.busy) waRefresh();
  }, WA_POLL_MS);
}

async function waRefresh() {
  S.wa.busy = true;
  try {
    const r = await api('/admin/wa/status');
    S.wa.loaded = true;
    S.wa.enabled = r.enabled !== false;
    S.wa.missing = Array.isArray(r.missing) ? r.missing : [];
    S.wa.reachable = r.reachable !== false;
    S.wa.state = r.state || '';
    S.wa.err = r.error || null;
    // The code is only worth fetching when there is nothing linked; asking for
    // it while a line is connected returns "alreadyLogged" and nothing useful.
    S.wa.qr = null;
    if (S.wa.enabled && S.wa.reachable && S.wa.state === 'notAuthorized') await waQr();
  } catch (e) {
    S.wa.loaded = true;
    S.wa.reachable = false;
    S.wa.err = (e && e.message) || 'השירות אינו מגיב';
  }
  S.wa.busy = false;
  renderConsole();
}

async function waQr() {
  try {
    const r = await api('/admin/wa/qr');
    S.wa.qr = r && r.type === 'qrCode' && r.message ? `data:image/png;base64,${r.message}` : null;
  } catch { S.wa.qr = null; }
}

/* Whether the row buttons send by themselves or hand the message to the
   sender's own WhatsApp. Only an administrator can send on the line — the
   server refuses everyone else — and only when a line is actually linked, so
   anyone else, or any hitch, still gets the wa.me behaviour that has always
   been there rather than a button that does nothing. */
const waAuto = () =>
  S.role === 'admin' && S.wa.loaded && S.wa.enabled && S.wa.reachable
  && S.wa.state === 'authorized';

/* Asked once at sign-in so the buttons know which of the two they are before
   anybody presses one. Quiet on failure: not having an answer is the same as
   "no automatic line", which is the safe direction to be wrong in. */
async function waProbe() {
  if (S.role !== 'admin') return;
  try {
    const r = await api('/admin/wa/status');
    S.wa.loaded = true;
    S.wa.enabled = r.enabled !== false;
    S.wa.missing = Array.isArray(r.missing) ? r.missing : [];
    S.wa.reachable = r.reachable !== false;
    S.wa.state = r.state || '';
  } catch { /* leaves waAuto() false, which is the wa.me path */ }
}

/* Fired by an approval rather than by somebody pressing a message button, so
   it must never be the reason an approval appears to fail: the approval is
   already saved by the time this runs, and a line that is down — or a soldier
   with no phone number on file — is not an error in the approval. It reports
   what happened and returns; the manual button is still there. */
async function waNotify(phone, message) {
  /* Why it did not send matters as much as that it did not. "שלחו הודעה
     במעקב ציוד" was the whole answer whatever the reason, so an approval that
     silently skipped the message looked identical to one that never had a
     line to send on — and the person approving had no way to tell that the
     line had dropped an hour ago. */
  if (!waAuto()) {
    return { sent: false, why: S.wa.loaded && S.wa.enabled ? 'noline' : 'unconfigured' };
  }
  const to = String(phone || '').trim();
  if (!to) return { sent: false, why: 'nophone' };
  try {
    await api('/admin/wa/send', { method: 'POST', body: { phone: to, message } });
    return { sent: true };
  } catch (e) {
    return { sent: false, why: 'failed', err: (e && e.message) || 'השליחה נכשלה' };
  }
}

/* What to add to the toast an approval already shows. Silent when there is no
   line at all — that is the ordinary state, and announcing it on every
   approval is noise. A failure while a line is up is worth the interruption. */
const waNote = (r) =>
  r.sent ? ' · הודעה נשלחה'
    : r.why === 'nophone' ? ' · אין טלפון ברשומה — לא נשלחה הודעה'
      : r.why === 'failed' ? ` · ההודעה לא נשלחה (${r.err})`
        : r.why === 'noline' ? ' · הקו אינו מחובר — ההודעה לא נשלחה'
          : r.why === 'unconfigured' ? ' — שלחו הודעה ידנית'
            : '';                      // 'skip': nothing was meant to be sent

/* One soldier's message, out over the unit's line. The record is marked sent
   only after the provider has accepted it — a message that failed must not
   leave a ✓ behind, because the next person to look at the row would believe
   it and never send. */
const waSendRec = (rid, kind) =>
  withBusy(async () => {
    const rec = findRec(rid);
    if (!rec || rec.damaged) return;
    const d = rec.data;
    const phone = String(d.phone || '').trim();
    if (!phone) { toast('אין מספר טלפון ברשומה', true); return; }
    const message = kind === 'notified' ? waSignMsg(d) : waReturnMsg(d);
    try {
      await api('/admin/wa/send', { method: 'POST', body: { phone, message } });
    } catch (e) {
      // The line can drop between the probe and the press. Say so plainly and
      // leave the record untouched.
      await waProbe();
      renderConsole();
      toast((e && e.message) || 'השליחה נכשלה', true);
      return;
    }
    markSent(rid, kind, 'auto');
    toast('ההודעה נשלחה');
  });

const waTestSend = () =>
  withBusy(async () => {
    const phone = (S.wa.to || '').trim();
    const message = (S.wa.body || '').trim();
    if (!/^0\d{8,9}$/.test(phone)) { toast('מספר טלפון — ספרות בלבד, למשל 0501234567', true); return; }
    if (!message) { toast('נא לכתוב טקסט', true); return; }
    await api('/admin/wa/send', { method: 'POST', body: { phone, message } });
    S.wa.body = '';
    renderConsole();
    toast('נשלח');
  });

function renderWaTab() {
  if (!S.wa.loaded) return '<p class="loading">טוען…</p>';

  if (!S.wa.enabled) {
    return `
      <section class="panel">
        <h2 class="panel-title">וואטסאפ</h2>
        <div class="callout">
          <p class="callout-title">אינו מוגדר</p>
          <p class="mb0">${S.wa.missing && S.wa.missing.length
            ? `${S.wa.missing.length === 1 ? 'חסר' : 'חסרים'} ${S.wa.missing
                .map((k) => `<code>${esc(k)}</code>`).join(', ')} בהגדרות הפרויקט בקלאודפלייר.`
            : 'שירות הוואטסאפ אינו מוגדר בהגדרות הפרויקט בקלאודפלייר.'
          } עד שיוגדר, כפתורי הוואטסאפ במסכים האחרים עובדים כרגיל.</p>
        </div>
      </section>`;
  }

  const st = waState();
  return `
    <section class="panel">
      <h2 class="panel-title">וואטסאפ</h2>
      <p class="panel-sub">הקו שממנו נשלחות הודעות השירות. וואטסאפ־ווב רץ אצל הספק, לא כאן.</p>

      <div class="wa-status">
        <span class="wa-dot ${st.tone}" aria-hidden="true"></span>
        <span class="wa-status-text">
          <strong>${esc(st.label)}</strong>
          <span class="muted">${esc(S.wa.reachable ? st.hint : 'השירות אינו מגיב.')}</span>
          ${S.wa.err ? `<span class="bad">${esc(S.wa.err)}</span>` : ''}
        </span>
      </div>

      ${S.wa.qr
        ? `<div class="wa-qr">
             <img class="wa-qr-img" src="${S.wa.qr}" alt="קוד QR לקישור הקו">
             <p class="field-hint mb0">בטלפון של הקו: וואטסאפ ← הגדרות ← מכשירים מקושרים ← קישור מכשיר. הקוד מתחלף — אם פג, לחצו רענון.</p>
           </div>`
        : ''}

      <div class="rec-actions">
        <button class="btn ghost small" data-act="wa-refresh">רענון</button>
      </div>
    </section>

    ${S.wa.state === 'authorized'
      ? `<section class="panel">
           <h2 class="panel-title">הודעת בדיקה</h2>
           <p class="panel-sub">הדרך לוודא שהקו עובד, לפני ששולחים למישהו אמיתי.</p>
           <label class="field">
             <span class="field-label">אל מספר</span>
             <input class="input num" inputmode="numeric" maxlength="10" data-act="wa-test-to"
                    value="${esc(S.wa.to)}" placeholder="0501234567">
           </label>
           <label class="field">
             <span class="field-label">טקסט</span>
             <textarea class="input area" rows="3" maxlength="1200" data-act="wa-test-body"
                       placeholder="בדיקה מהמסייעת">${esc(S.wa.body)}</textarea>
           </label>
           <button class="btn primary" data-act="wa-test-send">שליחה</button>
         </section>`
      : ''}

    <div class="callout risk">
      <p class="callout-title">שתי אזהרות</p>
      <p>שליחה כזאת אינה שירות רשמי של וואטסאפ והיא מנוגדת לתנאי השימוש. חשבון ששולח כך עלול להיחסם, לפעמים לצמיתות. השתמשו בקו ייעודי — לא במספר אישי.</p>
      <p class="mb0">טקסט ההודעה ומספר הנמען עוברים דרך שרתי הספק. ${S.wa.state === 'authorized'
        ? 'כל עוד הקו מקושר, גם כפתורי ההודעות במסך מעקב הציוד שולחים דרכו — שם החייל ופירוט הציוד בכלל זה. ניתוק הקו מחזיר אותם לפתוח צ\'אט מהמכשיר שלכם.'
        : 'כל עוד אין קו מקושר, כפתורי ההודעות במסכים האחרים פותחים צ\'אט מהמכשיר שלכם ואינם עוברים כאן.'}</p>
    </div>`;
}

function renderSecurityTab() {
  return `
    <div class="callout">
      <p class="callout-title">מה מוצפן</p>
      <p>שם, מספר אישי, טלפון, מספר נשק, פירוט הציוד <strong>וצילומי הרישיונות</strong> מוצפנים במכשיר לפני השליחה. השרת, קלאודפלייר, וכל מי שמשיג גישה לחשבון או למסד — רואים צופן בלבד.</p>
      <p class="mb0">מה השרת כן רואה: מספר הרשומות, סטטוס (ממתין/מאושר) וחותמות זמן. לא זהות ולא פירוט ציוד.</p>
    </div>
    <div class="callout">
      <p class="callout-title">הודעות לחיילים</p>
      ${waAuto()
        ? `<p class="mb0">קו וואטסאפ מקושר, ולכן כפתורי ההודעות <strong>שולחים מהקו של המסייעת</strong> בלחיצה אחת. <strong>שם החייל, הטלפון ופירוט הציוד עוברים דרך שרתי הספק</strong> — הם רואים למי נשלח ומה נכתב. זה המסלול היחיד שבו פרטים יוצאים מהמערכת בטקסט גלוי. לניתוק: קונסולה ← וואטסאפ, ואז הכפתורים חוזרים לפתוח צ'אט מהמכשיר שלכם בלבד.</p>`
        : `<p class="mb0">כפתורי הוואטסאפ פותחים צ'אט <strong>מהמכשיר שלכם</strong> עם הודעה מוכנה. שום שרת לא מעורב ושום פרט לא עובר לצד שלישי. אם יקושר קו בלשונית וואטסאפ, הם יעברו לשלוח דרכו — והפרטים יעברו אצל הספק.</p>`}
    </div>
    <div class="callout risk">
      <p class="callout-title">אין שחזור סיסמה</p>
      <p class="mb0">איבוד הסיסמה משמעו איבוד כל הנתונים. הדרך היחידה להמשיך היא מחיקה מלאה והתחלה מחדש.</p>
    </div>
    ${usersPanel()}

    ${trashPanel()}

    ${auditPanel()}

    <section class="panel">
      <h2 class="panel-title">חיבורים פעילים</h2>
      <p class="panel-sub">חיבור נסגר מעצמו כעבור שעה ללא פעילות, ובכל מקרה 12 שעות מרגע הכניסה. אם נשארתם מחוברים במכשיר אחר — נתקו הכל מכאן, וגם החיבור הנוכחי ייסגר.</p>
      <button class="btn ghost wide" data-act="sessions-revoke">ניתוק מכל המכשירים</button>
    </section>

    <section class="panel">
      <h2 class="panel-title">גיבוי מפתח שחזור</h2>
      <p class="panel-sub">קובץ קטן עם המפתח הציבורי ומזהי המערכת, לשמירה בנפרד מהמכשיר. בלי סיסמת המנהל הוא חסר ערך, ולכן אפשר לשמור אותו במקום אחר — אבל <strong>הוא אינו מחליף את הסיסמה</strong>: אם היא תאבד, אין שחזור.</p>
      ${askBtn('key-export', 'key-export', 'הורדת קובץ שחזור',
        'הקובץ מכיל את המפתח הפרטי עטוף בסיסמה שלכם — שמרו אותו לא באותו מקום עם הסיסמה. להוריד?',
        { yes: 'הורדה', cls: 'btn ghost wide' })}
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
      ${askBtn('wipe', 'wipe', 'מחיקת כל הנתונים',
        'כל הרשומות, הצילומים והמפתחות יימחקו לצמיתות. אין שחזור.',
        { yes: 'כן, למחוק הכול', tone: 'danger', cls: 'btn danger wide' })}
    </section>`;
}

/* ── Admin data operations ─────────────────────────────────────────── */

/* Opening one encrypted row into what the screen shows. A row that will not
   open is kept and flagged rather than dropped: something is there, and the
   console should say so instead of quietly showing one soldier fewer. */
const openRow = async (row, clean = cleanRecord) => {
  try {
    return { ...row, data: await openRecord(S.priv, row, clean), damaged: false };
  } catch {
    return { ...row, data: null, damaged: true };
  }
};

// The newest thing we hold. The next request asks for this and later, so a
// row written in the same millisecond as the last one cannot fall through the
// gap; the cost is re-fetching one row we already have.
const highWater = (rows) => rows.reduce((m, r) => Math.max(m, r.updated_at || 0), 0);

/* Merges what changed into what we already have.

   The console asks every few seconds whether anything moved, and until now
   the answer "yes" meant downloading and decrypting every record again — the
   whole set, every time one soldier pressed send, which is exactly what
   ninety soldiers do at once during a sign-out. Now it asks for what changed
   since the last answer and merges that.

   Everything else is unchanged: a full load still happens when the console
   opens or someone presses refresh, and that is also the way back if this
   ever drifts. */
function mergeRows(list, incoming, gone, key) {
  const goneSet = new Set(gone || []);
  const next = list.filter((r) => !goneSet.has(r[key]));
  for (const row of incoming) {
    const at = next.findIndex((r) => r[key] === row[key]);
    if (at === -1) next.push(row);
    else next[at] = row;
  }
  return next;
}

async function loadRecords(incremental) {
  const since = incremental && S.recsSince ? `?since=${S.recsSince}` : '';
  const { records, gone, partial } = await api(`/admin/records${since}`);
  const out = [];
  for (const row of records) out.push(await openRow(row));
  S.recs = partial ? mergeRows(S.recs, out, gone, 'rid') : out;
  S.recsSince = Math.max(S.recsSince || 0, highWater(records));
}

const findRec = (rid) => S.recs.find((r) => r.rid === rid);

// Re-seal the record's full payload with a fresh content key and PUT it.
async function saveRec(rec) {
  const sealed = await seal(S.pubKey, rec.data);
  await api(`/admin/records/${rec.rid}`, { method: 'PUT', body: { ...sealed, status: rec.status } });
}

async function loadReports(incremental) {
  const since = incremental && S.repsSince ? `?since=${S.repsSince}` : '';
  const { reports, gone, partial } = await api(`/admin/reports${since}`);
  const out = [];
  for (const row of reports) out.push(await openRow(row, cleanReport));
  S.reports = partial ? mergeRows(S.reports, out, gone, 'id') : out;
  S.repsSince = Math.max(S.repsSince || 0, highWater(reports));
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
    const w = (next === 'done' || next === 'partial')
      ? await waNotify(rec.data && rec.data.phone, waReportMsg(rec.data || {}, next))
      : { sent: false, why: 'skip' };
    if (w.sent) repMarkSent(id);
    const head = next === 'done' ? 'סומן כטופל'
      : next === 'partial' ? 'סומן כטופל חלקית'
        : 'הוחזר לטיפול';
    toast(head + (next === 'open' ? '' : waNote(w)));
  });

// Records that the admin actually opened the reply link.
function repMarkSent(id) {
  const rec = S.reports.find((r) => r.id === id);
  if (!rec || !rec.data || rec.data.replied) return;
  rec.data.replied = Date.now();
  renderConsole();
}

// Saving a corrected report. It is re-sealed here, in the browser, exactly as
// the soldier's original was — the server receives a new envelope and learns
// nothing from the correction.
const repSave = (id) =>
  withBusy(async () => {
    const rec = S.reports.find((r) => r.id === id);
    if (!rec || !S.repDraft) return;
    if ((S.repDraft.name || '').trim().length < 2) { toast('נא למלא שם מדווח', true); return; }

    const next = cleanReport({ ...rec.data, ...S.repDraft, name: S.repDraft.name.trim() });
    const prev = rec.data;
    rec.data = next;
    try {
      await api(`/admin/reports/${id}`, { method: 'PUT', body: await seal(S.pubKey, next) });
    } catch {
      rec.data = prev;
      toast('השמירה נכשלה — הדיווח לא שונה', true);
      return;
    }
    S.repEdit = '';
    S.repDraft = null;
    renderConsole();
    toast('הדיווח עודכן');
  });

const repDelete = (id) =>
  withBusy(async () => {
    await api(`/admin/reports/${id}`, { method: 'DELETE' });
    S.reports = S.reports.filter((r) => r.id !== id);
    renderConsole();
    toast('הדיווח נמחק');
  });

/* ── The vault, one domain at a time ───────────────────────────────────
   The logistics side used to be one encrypted blob: every save rewrote all
   of it, so two admins working on unrelated screens collided, and the
   movement logs — the only thing here that grows without end — shared a
   ceiling with everything else.

   It is now a row per domain, sealed exactly as before. This map is the
   whole definition of the split: which keys of the inventory object live in
   which row. A test fails if a key is ever added to the inventory without
   being given a home here, because a key with no home is a key that is
   quietly never saved. */
const VAULT_PARTS = [
  ['stock', ['open', 'extra', 'notes']],
  ['countedAt', ['countedAt']],
  ['armon', ['armon']],
  ['armonLog', ['armonLog']],
  ['comms', ['comms']],
  ['commsLog', ['commsLog']],
  ['ammo', ['ammo']],
  ['ammoLog', ['ammoLog']],
  ['vehicles', ['vehicles']],
  ['fuel', ['fuel']],
];

const partSlice = (inv, keys) => {
  const out = {};
  for (const k of keys) out[k] = inv[k];
  return out;
};

// What each part looked like when it was loaded, or last saved. A save writes
// the parts whose content differs from this and no others — which is why not
// one of the fifteen call sites had to learn what it was changing.
function markVaultClean() {
  S.invBase = {};
  for (const [part, keys] of VAULT_PARTS) {
    S.invBase[part] = JSON.stringify(partSlice(S.inv, keys));
  }
}

async function loadInv() {
  try {
    const { vault, parts } = await api('/admin/vault');
    const rows = parts || [];
    // The split writes ten rows one after another, and a connection that dies
    // in the middle would leave some of them behind. Half a split plus the old
    // blob must not be read as "this vault has been split", or the domains
    // that never made it would come up empty and the next save would write
    // that emptiness over the shadow copy too. So while the blob is still
    // there, the split only counts once every part has arrived.
    const whole = VAULT_PARTS.every(([p]) => rows.some((r) => r.part === p));
    if (rows.length && (whole || !vault)) {
      const inv = emptyInv();
      S.invVer = {};
      for (const row of rows) {
        const def = VAULT_PARTS.find(([p]) => p === row.part);
        if (!def) continue;                     // a part this client does not know
        // Each part opens on its own, so one damaged row costs one domain
        // rather than the whole console.
        try {
          Object.assign(inv, partSlice(await openRecord(S.priv, row, cleanInv), def[1]));
          S.invVer[row.part] = row.updated_at || 0;
        } catch (e) {
          // Which failure it was matters: a decryption error means the part was
          // sealed to another key, a parse error means the bytes are damaged.
          // The toast cannot say that; the console can, and this is the one
          // message worth having when someone reports a domain gone blank.
          console.error('vault part failed to open', row.part, e && e.name);
          toast(`לא ניתן לפענח חלק מנתוני המלאי (${row.part})`, true);
        }
      }
      S.inv = inv;
      // "Last updated" is now the newest part, taken from the server's own
      // clock rather than from whichever browser happened to save last.
      S.inv.updatedAt = Math.max(0, ...Object.values(S.invVer));
      markVaultClean();
    } else if (vault) {
      // Nothing split yet: read the old blob and, if this browser may write,
      // split it now. Only a browser can do this — the server holds the parts
      // but cannot read the blob in order to divide it.
      S.inv = await openRecord(S.priv, vault, cleanInv);
      // Any parts an interrupted attempt already wrote keep their versions, so
      // finishing the job is not mistaken for a conflict with it.
      S.invVer = {};
      for (const row of rows) S.invVer[row.part] = row.updated_at || 0;
      S.invBase = {};                           // with no baseline, everything is dirty
      if (S.role !== 'viewer') {
        await saveInv();
        toast('נתוני המלאי חולקו לפי תחומים');
      } else {
        markVaultClean();
      }
    } else {
      S.inv = emptyInv();
      S.invVer = {};
      markVaultClean();
    }
    // Publishing on save alone left the soldiers' list empty until somebody
    // happened to save — including right after this feature shipped, when
    // nothing had been saved yet. Opening the console now republishes it, so
    // the list is right from the first time an admin signs in.
    if (S.role !== 'viewer') await publishCards();
  } catch {
    S.inv = emptyInv();
    S.invVer = {};
    markVaultClean();
    toast('לא ניתן לפענח את נתוני המלאי', true);
  }
}

// The vault is one blob shared by every admin. Sending the version it was
// loaded at lets the server refuse a save that would overwrite someone else's
// work, instead of silently discarding it.
/* The cards and the vehicles the refuelling form may offer. Only this browser
   can read the vault, so only this browser can publish them — which happens on
   every save, so crediting a card or striking a vehicle takes it off the
   soldiers' form at the same moment it leaves the table.

   A card's label is masked. A fuel card is a payment instrument and the form
   it appears on is open to anyone with the link, so what goes out is the fuel
   type and the last four digits — enough for a soldier holding the card to
   recognise it, and not enough to use it.

   A vehicle's label is the plate as written on the vehicle. Masking it would
   defeat the point: the soldier is standing at the pump looking at the plate,
   and has to find that plate in the list. A plate is visible to anyone who
   walks past the vehicle, which a card number is not. */
const cardLabel = (c) => {
  const no = String(c.no || '').replace(/\s+/g, '');
  const tail = no.length > 4 ? `••${no.slice(-4)}` : no || 'ללא מספר';
  return `${nameOf(FUEL_KINDS, c.kind)} · ${tail}`;
};

const vehLabel = (v) => (v.company ? `${v.plate} · ${v.company}` : v.plate);

async function publishCards() {
  const cards = ((S.inv && S.inv.fuel) || [])
    .filter((c) => !c.credited)          // credited at the vehicle office — done with
    .map((c) => ({ id: c.id, label: cardLabel(c) }));
  const vehicles = ((S.inv && S.inv.vehicles) || [])
    .filter((v) => String(v.plate || '').trim().length >= 5)   // a blank new row is not a vehicle
    .map((v) => ({ id: v.id, label: vehLabel(v).slice(0, 60) }));
  await api('/admin/cards', { method: 'PUT', body: { cards, vehicles } }).catch(() => {});
}

// Hebrew names for the parts, for the one message that has to name one.
const PART_HE = {
  stock: 'המלאי', countedAt: 'מועדי הספירה', armon: 'הארמון', armonLog: 'יומן הארמון',
  comms: 'מחסן הקשר', commsLog: 'יומן הקשר', ammo: 'התחמושת', ammoLog: 'יומן התחמושת',
  vehicles: 'הרכבים', fuel: 'כרטיסי התדלוק',
};

/* Saves the domains that actually changed.

   Each part carries its own version, so a save is refused only when someone
   else touched that same domain — editing vehicles while a second admin
   counts rifles no longer costs either of them their work. When a part is
   refused the rest are still saved: the domains are independent of one
   another, so a partial save leaves each of them whole, which the single
   blob could never promise.

   The old blob is written afterwards as a shadow copy, so a browser still
   running yesterday's code — or a rollback — finds current data rather than
   a snapshot from before the split. It is best-effort and never blocks the
   save; once every client is on this code it can go. */
/* Every movement, written down.
   A register row is edited in place — you pick a new location from the row's
   own select, then type who has it — so there is no single moment to hang a
   log entry on: the pick, the name and the date are three separate events, and
   hanging it on the first would file half a sentence. The save is that moment.
   Comparing what is about to be written against what was last written names
   every item that moved, however it was moved, and will keep naming them if a
   sixth way to move an item is added later without anyone remembering this. */
function logMoves() {
  const now = Date.now();
  for (const reg of Object.values(REGISTERS)) {
    let base = null;
    try { base = JSON.parse(S.invBase[reg.key] || 'null'); } catch { base = null; }
    // No baseline is not "everything moved" — it is "we do not know", which is
    // the state right after the vault is split. Inventing a movement for every
    // item then would be worse than recording none.
    if (!base || !Array.isArray(base[reg.key])) continue;
    const was = new Map(base[reg.key].map((x) => [x.id, x]));
    for (const it of S.inv[reg.key] || []) {
      const before = was.get(it.id);
      if (!before) continue;                         // added, and already logged as such
      const moved = before.loc !== it.loc;
      // Passed straight from one soldier to the next: the place did not change
      // but the holder did, and that is exactly the handover a register exists
      // to record.
      const handed = !moved && LOAN_LOCS.has(it.loc) &&
        (before.mission || '') !== (it.mission || '');
      if (!moved && !handed) continue;

      const home = it.loc === reg.home;
      const since = before.since || before.addedAt || now;
      logPush(reg.logKey, {
        t: now,
        action: home ? 'return' : 'move',
        kind: it.kind, name: it.name, serial: it.serial, owner: it.owner,
        dest: '', from: before.loc, to: it.loc,
        // Coming back, the name that matters is whose hands it left; going
        // out, it is whose hands it is entering.
        who: (home ? before.mission : it.mission) || '',
        days: home ? Math.max(0, Math.round((now - since) / DAY_MS)) : 0,
        note: '',
      });
      // The clock starts when it leaves and stops when it comes back, so a
      // loan never inherits the date of the one before it.
      it.since = home ? null : now;
      if (home) it.due = '';
    }
  }
}

async function saveInv() {
  logMoves();
  S.inv.updatedAt = Date.now();
  const dirty = VAULT_PARTS.filter(
    ([part, keys]) => JSON.stringify(partSlice(S.inv, keys)) !== S.invBase[part]
  );
  if (!dirty.length) return;

  let biggest = 0;
  const refused = [];
  for (const [part, keys] of dirty) {
    const sealed = await seal(S.pubKey, partSlice(S.inv, keys));
    biggest = Math.max(biggest, sealed.ct.length);
    try {
      const res = await api(`/admin/vault/${part}`, {
        method: 'PUT',
        body: { ...sealed, baseVersion: S.invVer[part] },
      });
      S.invVer[part] = res.updatedAt || Date.now();
      S.invBase[part] = JSON.stringify(partSlice(S.inv, keys));
    } catch (e) {
      if (e.status === 409) { refused.push(part); continue; }
      throw e;
    }
  }
  vaultSizeWarn(biggest);
  await shadowVault();
  await publishCards();
  if (refused.length) {
    throw new Error(
      `${refused.map((p) => PART_HE[p] || p).join(' ו')} עודכנו על ידי מנהל אחר בזמן שערכתם — ` +
      'השאר נשמר. לחצו "רענון", בדקו מה השתנה ובצעו את השינוי הזה שוב.'
    );
  }
}

// The whole inventory in the old single-blob row, kept current for a client
// that has not been reloaded since the split. No version check: it is a copy,
// not a source, and a stale copy is the one thing it must never be. Skipped
// rather than failed if the inventory has outgrown the old ceiling — which is
// exactly the ceiling the split exists to remove.
async function shadowVault() {
  try {
    const sealed = await seal(S.pubKey, S.inv);
    if (sealed.ct.length > VAULT_MAX) return;
    await api('/admin/vault', { method: 'PUT', body: { ...sealed, baseVersion: -1, force: true } });
  } catch { /* the parts are the record; this is a courtesy copy */ }
}

// Each part has a ceiling at the server. Silence until a save simply fails is
// not a warning, so the fullest part is reported as its headroom shrinks.
const VAULT_MAX = 600000;
const VAULT_PART_MAX = 400000;
function vaultSizeWarn(len) {
  S.invBytes = len;
  const pct = Math.round((len / VAULT_PART_MAX) * 100);
  if (pct >= 90) toast(`שימו לב: החלק הגדול במלאי ${pct}% מהמותר — פנו מקום בקרוב`, true);
  else if (pct >= 80) toast(`החלק הגדול במלאי ${pct}% מהמותר`, true);
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
  // Approving a record is a network round trip and two decryptions, and until
  // now it looked exactly like nothing. The admin pressed again, and got told
  // off for it. A line under the banner says the work is happening; it blocks
  // nothing, covers nothing, and needs no dismissing.
  setBusyUI(true);
  try {
    await fn();
  } catch (e) {
    toast(e.message || 'שגיאה', true);
  } finally {
    S.busy = false;
    setBusyUI(false);
  }
}

function setBusyUI(on) {
  document.body.classList.toggle('is-busy', on);
  // Assistive tech is told the region is in flux rather than being read the
  // half-updated state underneath it.
  $app.setAttribute('aria-busy', on ? 'true' : 'false');
}

// Refusing a form used to be silent unless you happened to be looking at the
// right line. On the sign-out form that line is below the fold, so a soldier
// pressed send, nothing visibly happened, and they pressed it again; someone
// using a screen reader was told nothing at all. The message now announces
// itself and brings itself on screen.
function setFormErr(form, msg) {
  const el = form.querySelector('[data-err]');
  if (!el) return;
  el.textContent = msg || '';
  if (!msg) return;                     // clearing before a submit: say nothing
  el.focus({ preventScroll: true });
  bringIntoView(el);
}

// Scrolling that respects someone who asked for less of it. The CSS media
// query cannot reach a scroll started from script, so it is asked here.
function bringIntoView(el, block = 'center') {
  const still = matchMedia('(prefers-reduced-motion: reduce)').matches;
  el.scrollIntoView({ block, behavior: still ? 'auto' : 'smooth' });
}

/* — soldier actions — */

/* Sealing and posting a record, shared by all three pages. Each seals its own
   fields; what they have in common is the envelope, the ticket, the blind
   indexes of any serial numbers, and the photos that travel separately so that
   listing soldiers never drags image data along with it. */
async function sendRecord(rid, payload, docs = []) {
  const pubKey = await importPubKey(S.config.pub);
  const sealed = await seal(pubKey, payload);
  await api('/records', {
    body: {
      rid, ticket: await getTicket(), ...sealed,
      tags: await serialTags(payload, S.config.idSalt),
    },
  });
  for (const [kind, bytes] of docs) {
    await api('/docs', { body: { rid, kind, ...await sealBytes(pubKey, bytes) } });
  }
}

const identOk = (form, pn, name) => {
  if (!/^\d{5,9}$/.test(pn)) { setFormErr(form, 'מספר אישי: 5–9 ספרות'); return false; }
  if (name.length < 2) { setFormErr(form, 'נא למלא שם מלא'); return false; }
  return true;
};

// Page one. Nothing is signed for, so nothing is signed.
async function soldierIdentSubmit(form) {
  const pn = form.pn.value.trim();
  const name = form.name.value.trim();
  const phone = form.phone.value.trim();
  const dept = form.dept.value;
  if (!identOk(form, pn, name)) return;
  if (!/^\d{9,10}$/.test(phone)) return setFormErr(form, 'טלפון: 9–10 ספרות, ללא מקפים');
  if (!DEPTS.some((d) => d.id === dept)) return setFormErr(form, 'נא לבחור מחלקה');
  /* Ticking the civilian box is a claim about a licence with a number and an
     expiry, and a claim with neither is not worth filing: the office cannot
     chase a renewal it has no date for, and cannot match a photo to a licence
     it has no number for. The military box asks for no fields, so it is not
     held to this. */
  if (S.lic.civil) {
    if (!/^\d+$/.test(S.licNo.trim())) {
      return setFormErr(form, 'רישיון נהיגה אזרחי: יש למלא מספר רישיון (ספרות בלבד)');
    }
    if (!S.licExp) {
      return setFormErr(form, 'רישיון נהיגה אזרחי: יש למלא תאריך תוקף');
    }
  }
  /* Sent rather than dropped: a nonsense expiry is worth stopping on, because
     silently discarding it would file the licence as having no expiry at all. */
  if (S.licExp && !inDateRange(S.licExp)) {
    return setFormErr(form, 'תאריך תוקף הרישיון אינו תקין — בדקו את השנה');
  }
  setFormErr(form, '');
  const btn = form.querySelector('button[type=submit]');
  btn.disabled = true;
  btn.textContent = 'שולח…';
  await withBusy(async () => {
    const now = Date.now();
    const rid = await deriveRid(pn, S.config.idSalt);
    S.ident = { pn, name, phone, dept };
    S.rid = rid;
    const payload = {
      kind: 'details', pn, name, phone, dept,
      createdAt: now, log: [{ a: 'submit', t: now }],
    };
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
    const docs = LIC_KINDS
      .filter((k) => S.lic[k.id] && S.licPhoto[k.id])
      .map((k) => [k.id, S.licPhoto[k.id].bytes]);
    await sendRecord(rid, payload, docs);
    S.sStep = 4;
    renderFlow();
  });
  if (S.sStep === 1) {
    btn.disabled = false;
    btn.textContent = 'שליחה לאישור';
  }
}

/* Page two. It merges into the soldier's record on approval, which is what
   `supp` has always meant here — the flag is the merge, the kind is the label,
   and reusing the flag means reusing a merge that already works. */
async function weaponSubmit(form) {
  const pn = form.pn.value.trim();
  const name = form.name.value.trim();
  const weapon = form.weapon.value.trim();
  const amral = form.amral.value.trim();
  const scope = form.scope.value.trim();
  if (!identOk(form, pn, name)) return;
  const serialRe = /^[A-Za-z0-9\-/]{3,20}$/;
  for (const [val, label] of [[weapon, 'מספר נשק'], [amral, 'מספר אקילה'], [scope, 'מספר כוונת']]) {
    if (val && !serialRe.test(val)) {
      return setFormErr(form, `${label}: 3–20 תווים (ספרות, אותיות באנגלית, - או /)`);
    }
  }
  if (!weapon && !amral && !scope) return setFormErr(form, 'נא למלא לפחות מספר אחד');
  // A number already on the books stops the soldier here, not after the send.
  for (const [f, label] of SERIAL_FIELDS) {
    await checkSerial(f, { weapon, amral, scope }[f], label);
  }
  if (anySerialTaken()) {
    return setFormErr(form, SERIAL_FIELDS.map(([f]) => S.serialWarn[f]).find(Boolean));
  }
  setFormErr(form, '');
  S.ident = { pn, name, weapon, amral, scope };
  const btn = form.querySelector('button[type=submit]');
  btn.disabled = true;
  btn.textContent = 'שולח…';
  await withBusy(async () => {
    if (!(await findSoldier(form, pn))) return;
    const now = Date.now();
    const rid = await deriveRid(`${pn}:weapon`, S.config.idSalt);
    S.rid = rid;
    const payload = {
      kind: 'weapon', supp: true, pn, name,
      createdAt: now, log: [{ a: 'submit', t: now }],
    };
    if (weapon) payload.weapon = weapon;
    if (amral) payload.amral = amral;
    if (scope) payload.scope = scope;
    await sendRecord(rid, payload);
    S.sStep = 4;
    renderWeaponPage();
  });
  if (S.sStep === 1) {
    btn.disabled = false;
    btn.textContent = 'שליחה לאישור';
  }
}

// Page three, step one: who is signing. The kit list and the signature follow.
async function gearIdentSubmit(form) {
  const pn = form.pn.value.trim();
  const name = form.name.value.trim();
  if (!identOk(form, pn, name)) return;
  setFormErr(form, '');
  const btn = form.querySelector('button[type=submit]');
  btn.disabled = true;
  btn.textContent = 'בודק…';
  await withBusy(async () => {
    if (!(await findSoldier(form, pn))) return;
    const rid = await deriveRid(`${pn}:gear`, S.config.idSalt);
    const st = await api(`/status/${rid}`);
    S.ident = { pn, name };
    S.rid = rid;
    S.existingPending = !!st.exists;
    S.sStep = 2;
    renderGearPage();
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
  // The serial numbers moved to their own page, so this form no longer has
  // those fields to read — asking for them by name would throw here, on the
  // way to re-rendering after a licence box is ticked.
  S.ident = {
    ...(S.ident || {}),
    pn: f.pn.value.trim(),
    name: f.name.value.trim(),
    phone: f.phone.value.trim(),
    dept: f.dept.value,
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
  renderFlow();
}

function licClear(kind) {
  captureIdentForm();
  delete S.licPhoto[kind];
  renderFlow();
}

// A photo that arrived through Android's share sheet. It is already compressed
// — claimSharedPhoto() did that on the way in — so this only decides which
// licence it belongs to, which is the one thing the share sheet cannot say.
function licUseShared(kind) {
  if (!S.sharedPhoto) return;
  captureIdentForm();
  S.licPhoto[kind] = S.sharedPhoto;
  S.sharedPhoto = null;
  renderFlow();
  toast('התמונה צורפה');
}

async function licFile(kind, input) {
  const file = input.files && input.files[0];
  if (!file) return;
  captureIdentForm();
  if (notAnImage(file)) {
    toast('יש לבחור קובץ תמונה', true);
    return;
  }
  toast('מעבד את התמונה…');
  try {
    const { bytes, size } = await compressImage(file);
    let bin = '';
    for (const b of bytes) bin += String.fromCharCode(b);
    S.licPhoto[kind] = { bytes, size, preview: `data:image/jpeg;base64,${btoa(bin)}` };
    renderFlow();
    toast('התמונה נקלטה');
  } catch (e) {
    toast(e.message || 'עיבוד התמונה נכשל', true);
  }
}

// Attaching or removing the receipt re-renders the form, so whatever the
// soldier has already typed has to be read out of the live form first —
// otherwise the photo lands and the name, the litres and the rest are blank
// again. Same reason step 1 of the sign-out captures before re-rendering.
function captureRefuelForm() {
  const f = $app.querySelector('form[data-form="refuel"]');
  if (!f) return;
  S.rf = {
    name: f.name.value.trim(),
    phone: f.phone.value.trim(),
    card: f.card.value,
    litres: String(f.litres.value).replace(/\D/g, ''),
    plate: f.plate.value.trim(),
  };
}

// The refuelling receipt, compressed and held in memory until the report is
// sent. Same path as a licence photo — the office should never have to take
// a soldier's word for the litres.
async function refuelPhoto(input) {
  const file = input.files && input.files[0];
  if (!file) return;
  captureRefuelForm();
  if (notAnImage(file)) { toast('יש לבחור קובץ תמונה', true); return; }
  toast('מעבד את התמונה…');
  try {
    const { bytes, size } = await compressImage(file);
    S.rfPhoto = { bytes, size };
    renderRefuel();
    toast('הקבלה נקלטה');
  } catch (e) {
    toast(e.message || 'עיבוד התמונה נכשל', true);
  }
}

function soldierToggle(itemId) {
  const item = itemById(itemId);
  if (itemId in S.sel) delete S.sel[itemId];
  else S.sel[itemId] = item.qty ? item.min : 1;
  renderFlow();
}

function soldierStep(itemId, delta) {
  const item = itemById(itemId);
  const cur = S.sel[itemId] || item.min;
  S.sel[itemId] = Math.min(item.max, Math.max(item.min, cur + delta));
  renderFlow();
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
  // Without a signature it is a form, not a slip.
  if (!(await ensureSignature())) {
    if (errEl) errEl.textContent = 'נא לחתום באצבע במסגרת החתימה';
    const pad = $app.querySelector('.sigwrap');
    if (pad) bringIntoView(pad);
    return;
  }
  await withBusy(async () => {
    const now = Date.now();
    const items = {};
    for (const [id, q] of Object.entries(S.sel)) items[id] = { t: q, r: 0 };
    // Kit and a signature, and the name so the admin can read the row without
    // going to fetch it. Everything else about this soldier is already on their
    // record, put there by the page that asks for it.
    const payload = {
      kind: 'gear', supp: true,
      pn: S.ident.pn,
      name: S.ident.name,
      items,
      signed: now,                    // the console shows there is one to open
      createdAt: now,
      log: [{ a: 'submit', t: now }],
    };
    await sendRecord(S.rid, payload, [['signature', S.sig.bytes]]);
    S.sStep = 4;
    renderGearPage();
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

/* Proof that the key this session seals with and the key it opens with are two
   halves of the same pair. One RSA operation, once, at sign-in — against a
   whole domain of the vault written to a key nobody holds, which is silent,
   permanent, and looks exactly like working software until somebody reloads. */
async function keysAgree(pubKey, priv) {
  try {
    const probe = { t: Date.now() };
    const back = await openRecord(priv, await seal(pubKey, probe), (x) => x);
    return !!back && back.t === probe.t;
  } catch {
    return false;
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
      // Take the role the server assigned. Collapsing anything-but-viewer to
      // 'admin' made an editor request screens they have no right to, and the
      // login died on the 403 that correctly came back.
      S.role = ['admin', 'editor', 'viewer'].includes(res.role) ? res.role : 'viewer';
      S.me = res.username || username;
      S.tabs = res.tabs || '*';
      const pkcs8 = new Uint8Array(
        await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ub64(keyIv) }, kek, ub64(wrappedKey))
      );
      S.priv = await crypto.subtle.importKey(
        'pkcs8', pkcs8, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']
      );
      S.pkcs8 = pkcs8;
      /* The public key has to come from the server now, not from whatever this
         page fetched when it was opened.

         A tab left open across a key rotation — or across the first setup —
         still holds the old public key in S.config. Signing in again from that
         tab, which is what happens every time the console auto-locks, gave the
         new private key and the old public key. Everything saved after that was
         sealed to a key nobody holds any more: the ciphertext was perfectly
         well formed, the server accepted it, and the next admin to open the
         vault got "לא ניתן לפענח" on a domain whose data was gone. Nothing in
         between could notice, because sealing does not need the private key.

         So: fetch it, then prove the two halves are a pair before this session
         is allowed to write anything at all. */
      S.config = await api('/config');
      S.pubKey = await importPubKey(S.config.pub);
      if (!(await keysAgree(S.pubKey, S.priv))) {
        throw new Error('מפתחות ההצפנה אינם תואמים — רעננו את הדף ונסו שוב');
      }
      // only fetch what this user's screens actually need — the server
      // refuses the rest anyway, and a 403 must not break the login
      const scopes = allowedScopes();
      if (scopes.has('records')) await loadRecords();
      if (scopes.has('vault')) await loadInv();
      if (scopes.has('reports')) await loadReports();
      if (S.role === 'admin') await loadUsers();
      // Not awaited: the console must not wait on a third party to open, and
      // until the answer lands the buttons behave exactly as they always did.
      waProbe().then(() => renderConsole());
      S.tab = allowedTabs()[0] || 'over';
      armIdle();
      startPulse();
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


// Every serial already in use, excluding one record (the one being approved).
// Every serial the unit already has on its books, from wherever it is held.
// A number identifies one physical thing, so it may appear once — a weapon
// serial, a מק״ט of an אקילה, a sight, an item in either register. `except`
// drops the row being edited, so a record does not collide with itself.
function serialIndex(except) {
  const out = [];
  for (const rec of S.recs) {
    if (rec.rid === except || rec.damaged || !rec.data || rec.status !== 'approved') continue;
    for (const [f, label] of SERIAL_FIELDS) {
      if (rec.data[f]) out.push({ v: String(rec.data[f]), label, who: rec.data.name, kind: 'חייל' });
    }
  }
  for (const reg of Object.values(REGISTERS)) {
    for (const x of (S.inv && S.inv[reg.key]) || []) {
      if (x.id === except || !x.serial) continue;
      out.push({ v: String(x.serial), label: nameOf(reg.kinds, x.kind), who: x.owner, kind: reg.title });
    }
  }
  // A deposit that has been filed is already in the register; one still
  // waiting is not, and its numbers are just as taken.
  for (const r of S.reports) {
    if (r.id === except || r.damaged || !r.data) continue;
    if (r.data.kind !== 'deposit' || r.status === 'done') continue;
    for (const [f, label] of SERIAL_FIELDS) {
      if (r.data[f]) out.push({ v: String(r.data[f]), label, who: r.data.name, kind: 'אפסון ממתין' });
    }
  }
  return out;
}

// The blocking half of the check: an exact match anywhere is a refusal, not
// a warning. Returns the message to show, or '' if the number is free.
function serialTaken(value, except) {
  const v = String(value || '').trim().toLowerCase();
  if (!v) return '';
  const hit = serialIndex(except).find((o) => o.v.trim().toLowerCase() === v);
  return hit ? `⛔ ${value} כבר רשום על ${hit.who || 'ללא שם'} (${hit.kind}) — מספר חייב להיות ייחודי` : '';
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

// Saving a correction. The same duplicate and near-miss checks the approval
// path runs apply here — a serial corrected into someone else's serial is the
// mistake this whole feature exists to catch, not one to wave through.
const recSave = (rid) =>
  withBusy(async () => {
    const rec = findRec(rid);
    if (!rec || !S.recDraft) return;
    const d = S.recDraft;
    if ((d.name || '').trim().length < 2) { toast('נא למלא שם', true); return; }
    if (!/^\d{5,9}$/.test(String(d.pn || '').trim())) { toast('מספר אישי — 5 עד 9 ספרות', true); return; }

    const next = cleanRecord({ ...rec.data, ...d, pn: String(d.pn).trim(), name: d.name.trim() });
    const warns = serialWarnings(next, rid);
    const blocking = warns.filter((w) => w.startsWith('⛔'));
    if (blocking.length) { toast(blocking[0], true); return; }

    const prev = rec.data;
    rec.data = next;
    try {
      await saveRec(rec);
    } catch {
      rec.data = prev;                       // the server refused; the screen must not lie
      toast('השמירה נכשלה — הנתונים לא שונו', true);
      return;
    }
    S.recEdit = '';
    S.recDraft = null;
    renderConsole();
    toast(warns.length ? `נשמר · ${warns[0]}` : 'הפרטים עודכנו');
  });

/* A replacement licence photograph, chosen in the console. Compressed here and
   held in the draft — it does not reach the vault until the correction is
   saved, so an admin who changes their mind leaves nothing behind. */
const licEdFile = (kind, input) =>
  withBusy(async () => {
    const file = input.files && input.files[0];
    input.value = '';                        // let the same file be picked again
    if (!file || !S.licDraft) return;
    if (notAnImage(file)) { toast('יש לבחור קובץ תמונה', true); return; }
    const { bytes, size } = await compressImage(file);
    let bin = '';
    for (const b of bytes) bin += String.fromCharCode(b);
    S.licDraft.pic[kind] = { bytes, size, preview: `data:image/jpeg;base64,${btoa(bin)}` };
    renderConsole();
    toast('הצילום מוכן — לחצו על שמירת התיקון');
  });

/* Committing the correction.
   The photographs go up first and the record last, because the record is what
   claims a photograph exists. In the other order a failed upload would leave a
   row saying there is a licence photo and a vault with nothing to show. */
const licSave = (rid) =>
  withBusy(async () => {
    const rec = findRec(rid);
    if (!rec || !rec.data || !S.licDraft) return;
    const d = S.licDraft;

    if (d.civil) {
      if (!/^\d+$/.test(String(d.no || '').trim())) {
        toast('רישיון אזרחי: מספר רישיון — ספרות בלבד', true);
        return;
      }
      if (!d.exp) { toast('רישיון אזרחי: יש למלא תאריך תוקף', true); return; }
      if (!inDateRange(d.exp)) { toast('תאריך התוקף אינו תקין — בדקו את השנה', true); return; }
    }

    /* Unticking a licence takes its photograph with it: the picture is of that
       licence, and keeping it would leave the vault holding a document for
       something the record says the soldier does not have. */
    const wanted = { civil: d.civil, military: d.military };
    const touched = [];
    for (const k of LIC_KINDS) {
      const had = !!((rec.data.lic || {})[k.id] || {}).doc;
      const pick = d.pic[k.id];
      if (!wanted[k.id]) { if (had) touched.push([k.id, null]); continue; }
      if (pick) touched.push([k.id, pick.bytes]);
      else if (pick === null && had) touched.push([k.id, null]);
    }

    const done = [];
    const added = [];                        // uploads that created a doc from nothing
    try {
      for (const [kind, bytes] of touched) {
        if (bytes) {
          const had = !!((rec.data.lic || {})[kind] || {}).doc;
          await api(`/admin/docs/${rid}/${kind}`, { method: 'PUT', body: await sealBytes(S.pubKey, bytes) });
          if (!had) added.push(kind);
        } else {
          await api(`/admin/docs/${rid}/${kind}`, { method: 'DELETE' });
        }
        done.push(kind);
      }
    } catch {
      toast('העלאת הצילום נכשלה — לא בוצע שינוי ברשומה', true);
      return;
    }

    const lic = {};
    for (const k of LIC_KINDS) {
      if (!wanted[k.id]) continue;
      const pick = d.pic[k.id];
      const had = !!((rec.data.lic || {})[k.id] || {}).doc;
      lic[k.id] = { has: true, doc: pick ? true : pick === null ? false : had };
      if (k.id === 'civil') {
        lic.civil.no = String(d.no).trim();
        lic.civil.exp = d.exp;
      }
    }

    const prev = rec.data;
    rec.data = { ...rec.data };
    if (Object.keys(lic).length) rec.data.lic = lic;
    else delete rec.data.lic;

    try {
      await saveRec(rec);
    } catch {
      rec.data = prev;                       // the server refused; the screen must not lie
      /* The photographs went up first, and the record that would have pointed
         at them did not. One that was added where there was none before is now
         a licence sitting in the vault under nobody's name, so it goes back.
         A replacement cannot be undone — the picture it overwrote is gone —
         and the message says as much rather than pretending otherwise. */
      for (const kind of added) {
        await api(`/admin/docs/${rid}/${kind}`, { method: 'DELETE' }).catch(() => {});
      }
      toast(
        done.length > added.length
          ? 'השמירה נכשלה — הרשומה לא שונתה, אך צילום שהוחלף אינו ניתן לשחזור'
          : 'השמירה נכשלה — הרשומה לא שונתה',
        true
      );
      return;
    }

    // The thumbnails on this screen are cached by rid and kind, and every one
    // that was replaced or removed is now a picture of the past.
    for (const kind of done) docForget(`${rid}:${kind}`);
    S.licEdit = '';
    S.licDraft = null;
    renderConsole();
    toast('הרישיון עודכן');
  });

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
        await saveRec(parent);
        await api(`/admin/records/${rec.rid}`, { method: 'DELETE' });
        S.recs = S.recs.filter((r) => r.rid !== rec.rid);
        return { name: parent.data.name, merged: true };
      }
      // main record was deleted meanwhile — approve as a standalone record
      delete rec.data.supp;
    }
    rec.data.approvedAt = now;
    rec.data.log.push({ a: 'approve', t: now });
    rec.status = 'approved';
    await saveRec(rec);
    return { name: rec.data.name };
}

/* Approving is one press unless a number on the slip is already on the books,
   and then it is a question with the reason in it. The check runs while the
   button is drawn rather than after it is pressed, so the warning is on the
   screen before the press instead of in a dialog after it. */
function approveBtn(rec, cls) {
  const warns = rec && !rec.damaged && rec.data ? serialWarnings(rec.data, rec.rid) : [];
  if (!warns.length) {
    return `<button class="${cls}" data-act="approve" data-rid="${esc(rec.rid)}">אישור</button>`;
  }
  return askBtn(`approve:${rec.rid}`, 'approve', '⚠ אישור',
    `${warns[0]}${warns.length > 1 ? ` (ועוד ${warns.length - 1})` : ''} — לאשר בכל זאת?`,
    { data: { rid: rec.rid }, yes: 'כן, לאשר', cls });
}

const adminApprove = (rid) =>
  withBusy(async () => {
    S.askDel = '';
    const rec = findRec(rid);
    const d = rec && rec.data ? { ...rec.data } : null;
    const r = await approveCore(rid);
    S.picked.delete(rid);
    renderConsole();
    if (r.skipped) return;
    // The approval is saved; the message is a consequence of it, not a
    // condition for it. Sent from the copy taken before approval, because
    // approveCore may have merged the submission away.
    const w = d ? await waNotify(d.phone, waSignMsg(d)) : { sent: false, why: 'skip' };
    if (w.sent) markSent(rid, 'notified', 'auto');
    renderConsole();
    toast((r.merged
      ? `ההשלמה מוזגה לרישום של ${r.name}`
      : `אושר: ${r.name}`) + waNote(w));
  });

// Bulk approval. Each record is saved on its own, so a failure part-way leaves
// everything before it approved rather than rolling the batch back.
// What the bulk question says depends on what is about to be approved: the
// count always, and any serial number that is already on the books — which is
// exactly the moment to see it, not after.
function bulkApproveNote() {
  const rids = [...S.picked];
  const flagged = [];
  for (const rid of rids) {
    const rec = findRec(rid);
    if (!rec || rec.damaged || !rec.data) continue;
    const w = serialWarnings(rec.data, rid);
    if (w.length) flagged.push(`${rec.data.name}: ${w[0]}`);
  }
  const head = flagged.length
    ? `⚠ ${flagged.length} מתוך ${rids.length} עם בעיה במספרים סידוריים — ${flagged.slice(0, 3).join(' · ')}${flagged.length > 3 ? ' ועוד' : ''}. `
    : '';
  return `${head}לאשר ${rids.length} רישומים? ההודעות לחיילים נשלחות בנפרד ממעקב ציוד.`;
}

const bulkApprove = () =>
  withBusy(async () => {
    const rids = [...S.picked];
    if (!rids.length) return;
    S.askDel = '';
    let ok = 0;
    const failedRids = [];
    for (const rid of rids) {
      toast(`מאשר ${ok + failedRids.length + 1} מתוך ${rids.length}…`);
      try {
        const r = await approveCore(rid);
        if (r.skipped) continue;
        ok++;
        S.picked.delete(rid);
      } catch {
        failedRids.push(rid);
      }
    }
    renderConsole();
    toast(
      `${ok} רישומים אושרו` +
        (failedRids.length ? ` · ${failedRids.length} נכשלו ונשארו מסומנים` : ''),
      failedRids.length > 0
    );
  });

const bulkDelete = () =>
  withBusy(async () => {
    const rids = [...S.picked];
    if (!rids.length) return;
    S.askDel = '';
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

/* "זיכוי מלא" writes off every item a soldier is holding in one press, and it
   is next to the delete button on a phone. The row's arm-then-confirm was not
   enough: it asks in a strip the width of a table cell and it does not say
   what is about to be written off. This is the one action in the console that
   has to be read before it is answered, so it takes the middle of the screen
   and puts the list in front of the person pressing it. */
function creditDialog() {
  if (!S.creditAsk) return '';
  const rec = findRec(S.creditAsk);
  if (!rec || rec.damaged) return '';
  const d = rec.data;
  const held = ITEMS.filter((i) => d.items[i.id])
    .map((i) => ({ i, out: d.items[i.id].t - (d.items[i.id].r || 0) }))
    .filter((x) => x.out > 0);
  const done = ITEMS.filter((i) => d.items[i.id]).length - held.length;
  return `
    <div class="modal-back" data-act="credit-cancel">
      <div class="modal" role="dialog" aria-modal="true" aria-labelledby="creditq">
        <h2 class="modal-title" id="creditq">האם ${esc(d.name)} החזיר את כל הציוד?</h2>
        <p class="modal-sub">אישור מזכה את כל הפריטים שלמטה בבת אחת. הפעולה נרשמת ביומן הרשומה, ומבטלים אותה רק פריט־פריט.</p>
        ${held.length
          ? `<ul class="modal-list">${held.map(({ i, out }) => `
              <li class="kit-row">
                <span class="row-ico" aria-hidden="true">${i.icon}</span>
                <span class="kit-name">${esc(i.name)}</span>
                <span class="kit-count num">${out}</span>
              </li>`).join('')}</ul>
             <p class="modal-note"><span class="num">${held.length}</span> פריטים ייסגרו${
               done ? ` · <span class="num">${done}</span> כבר הוחזרו` : ''}</p>`
          : '<p class="modal-note">אין פריטים פתוחים — הכל כבר מזוכה.</p>'}
        <div class="modal-acts">
          <button class="btn ghost" type="button" data-act="credit-cancel">ביטול</button>
          ${held.length
            ? `<button class="btn primary" type="button" data-act="credit-ok"
                       data-rid="${esc(rec.rid)}">כן, החזיר הכל</button>`
            : ''}
        </div>
      </div>
    </div>`;
}

const adminCreditAll = (rid) =>
  withBusy(async () => {
    const rec = findRec(rid);
    if (!rec || rec.damaged) return;
    for (const it of Object.values(rec.data.items)) it.r = it.t;
    rec.data.log.push({ a: 'credit', t: Date.now() });
    await saveRec(rec);
    renderConsole();
    const w = await waNotify(rec.data.phone, waReturnMsg(rec.data));
    if (w.sent) markSent(rid, 'returnNotified', 'auto');
    renderConsole();
    toast(`זוכה במלואו: ${rec.data.name}${waNote(w)}`);
  });

const adminDelete = (rid) =>
  withBusy(async () => {
    const rec = findRec(rid);
    if (!rec) return;
    const who = rec.damaged ? 'הרשומה הפגומה' : `הרשומה של ${rec.data.name}`;
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

/* One request already carries every photograph a record has — the civil
   licence, the military one and the signature come back together — so asking
   for one and throwing the rest away meant a second round trip to see the
   other side of the same soldier. Everything that arrives is kept, and the
   caller says which one it was actually waiting for so a missing photo can
   still be reported. A single bad decrypt does not cost the others. */
async function fetchDocs(rid, want) {
  const { docs } = await api(`/admin/docs/${rid}`);
  for (const row of docs || []) {
    const key = `${rid}:${row.kind}`;
    if (S.docs[key]) continue;
    try {
      const bytes = new Uint8Array(await openBytes(S.priv, row));
      let bin = '';
      for (const b of bytes) bin += String.fromCharCode(b);
      docCache(key, `data:image/jpeg;base64,${btoa(bin)}`);
    } catch {
      // One unreadable photo must not cost the others their trip; only the one
      // that was actually asked for is worth interrupting anybody about.
      if (row.kind === want) toast('פענוח הצילום נכשל — ייתכן שהנתונים שובשו', true);
    }
  }
}

// Fetches and decrypts a record's photographs the first time one is asked for;
// afterwards the toggle just hides the copies already held in memory.
const toggleDoc = (rid, kind) =>
  withBusy(async () => {
    const key = `${rid}:${kind}`;
    if (S.docs[key]) {
      docForget(key);
      renderConsole();
      return;
    }
    await fetchDocs(rid, kind);
    if (!S.docs[key]) toast('הצילום לא נמצא', true);
    renderConsole();
  });

/* The licence screen shows a soldier's photographs side by side, so it opens
   and closes them as a pair rather than one at a time. Closing drops only the
   licences — a signature the card below is showing stays where it is. */
const toggleLicDocs = (rid) => {
  const keys = LIC_KINDS.map((k) => `${rid}:${k.id}`);
  const has = () => keys.some((k) => S.docs[k]);
  if (has()) {
    for (const k of keys) docForget(k);
    renderConsole();
    return;
  }
  withBusy(async () => {
    await fetchDocs(rid);
    if (!has()) toast('הצילום לא נמצא', true);
    renderConsole();
  });
};

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
      body: { role: S.userRole, tabs: [...S.userTabs], ...(await wrapKeyFor(pw)) },
    });
    S.userTabs.clear();
    await loadUsers();
    renderConsole();
    toast(`המשתמש ${username} נוצר`);
  });
}

// Password change and permission change both edit one user, so they share one
// inline editor that opens under the row — no dialog, and the screens are
// tick boxes rather than numbers typed into a prompt.
const userSave = (username) =>
  withBusy(async () => {
    const u = S.users.find((x) => x.username === username);
    const d = S.userEditDraft;
    if (!u || !d) return;
    const changingPw = !!d.pw;
    if (changingPw && d.pw.length < 10) { toast('הסיסמה חייבת להכיל 10 תווים לפחות', true); return; }
    if (changingPw && d.pw !== d.pw2) { toast('הסיסמאות אינן תואמות', true); return; }

    const role = u.role === 'admin' ? 'admin' : d.role;
    const tabs = role === 'admin' ? [] : [...d.tabs];
    if (role !== 'admin' && !tabs.length) { toast('נא לסמן לפחות מסך אחד', true); return; }

    if (changingPw) {
      if (!S.pkcs8) { toast('המפתח אינו זמין — התחברו מחדש', true); return; }
      await api(`/admin/users/${encodeURIComponent(username)}`, {
        method: 'PUT',
        body: { role, tabs, ...(await wrapKeyFor(d.pw)) },
      });
    } else {
      await api(`/admin/users/${encodeURIComponent(username)}`, {
        method: 'PUT',
        body: { role, tabs, tabsOnly: true },
      });
    }
    S.userEdit = null;
    S.userEditDraft = null;
    await loadUsers();
    renderConsole();
    toast(changingPw
      ? `הסיסמה של ${username} הוחלפה — הוא נותק מכל המכשירים`
      : `ההרשאה של ${username} עודכנה`);
  });

function userEditRow(u) {
  const d = S.userEditDraft || {};
  return `
    <div class="useredit">
      ${u.role === 'admin'
        ? '<p class="muted-txt">למנהל יש גישה לכל המסכים — אפשר להחליף רק סיסמה.</p>'
        : `
        <fieldset class="lic-set">
          <legend class="field-label">סוג הרשאה</legend>
          <div class="rolepicks">
            ${ROLES.map((r) => `
              <label class="rolepick ${d.role === r.id ? 'on' : ''}">
                <input type="radio" name="erole-${esc(u.username)}" value="${r.id}" class="kitbox"
                       data-act="uedit-role" ${d.role === r.id ? 'checked' : ''}>
                <span>
                  <span class="rolepick-t">${esc(r.name)}</span>
                  <span class="rolepick-s">${esc(r.hint)}</span>
                </span>
              </label>`).join('')}
          </div>
        </fieldset>
        <fieldset class="lic-set">
          <legend class="field-label">מסכים מותרים</legend>
          <div class="screenpicks">
            ${TABS.filter((t) => !t.adminOnly).map((t) => `
              <label class="screenpick ${d.tabs && d.tabs.has(t.id) ? 'on' : ''}">
                <input type="checkbox" class="kitbox" data-act="uedit-tab" data-t="${t.id}"
                       ${d.tabs && d.tabs.has(t.id) ? 'checked' : ''}>
                <span>${esc(t.name)}</span>
              </label>`).join('')}
          </div>
        </fieldset>`}
      <fieldset class="lic-set">
        <legend class="field-label">סיסמה חדשה <span class="opt-tag">רשות — השאירו ריק כדי לא לשנות</span></legend>
        <div class="grid2">
          <label class="field">
            <span class="field-label">סיסמה (10 תווים לפחות)</span>
            <input class="input" type="password" autocomplete="new-password"
                   value="${esc(d.pw || '')}" data-act="uedit-pw">
          </label>
          <label class="field">
            <span class="field-label">אימות סיסמה</span>
            <input class="input" type="password" autocomplete="new-password"
                   value="${esc(d.pw2 || '')}" data-act="uedit-pw2">
          </label>
        </div>
      </fieldset>
      <div class="rec-actions">
        <button class="btn primary" data-act="uedit-save" data-u="${esc(u.username)}">שמירה</button>
        <button class="btn ghost" data-act="uedit-cancel">ביטול</button>
      </div>
    </div>`;
}

const userDelete = (username) =>
  withBusy(async () => {
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
    S.askDel = '';
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
  /* The backdrop closes the question; the card standing on it does not. Both
     carry the same action because the backdrop wraps the card, so the press
     has to have landed on the backdrop itself. */
  if (act === 'credit-cancel' && el.classList.contains('modal-back') && e.target !== el) return;
  /* The two message buttons stay anchors carrying a wa.me address, and that
     address is still what happens when there is no line to send on. When there
     is one, the navigation is cancelled here and the message goes out over it
     instead. Deciding at the click, from state already in hand, is what keeps
     the fallback a plain link the browser opens itself. */
  if ((act === 'wa-sign' || act === 'wa-ret') && waAuto()) {
    e.preventDefault();
    waSendRec(el.dataset.rid, act === 'wa-sign' ? 'notified' : 'returnNotified');
    return;
  }
  // An armed row stays armed only for the press that answers it. Anything
  // else the user does is an answer of "no", which is the safe default and
  // saves every delete handler from having to remember to disarm.
  if (S.askDel && act !== 'ask-del' && !el.closest('.delask')) {
    S.askDel = '';
    renderConsole();
    if (act === 'ask-cancel') return;
  }
  dispatch(act, el);
});

// Escape answers "no" to the credit question, which is the safe answer.
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && S.creditAsk) {
    S.creditAsk = '';
    renderConsole();
  }
});

$app.addEventListener('keydown', (e) => {
  if (e.key !== 'Enter' && e.key !== ' ') return;
  const el = e.target.closest('[role="checkbox"][data-act]');
  if (!el) return;
  e.preventDefault();
  dispatch(el.dataset.act, el);
});

// Number inputs whose derived columns are recomputed when the field is left.
const NUM_COMMIT = new Set(['inv-open', 'inv-xopen', 'inv-xout', 'veh-km', 'fuel-litres', 'ammo-open']);

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
    case 'arm-search':  S.regQ = { ...S.regQ, [regOf(el).key]: el.value }; S.page = {}; rerenderKeepFocus(el); break;
    case 'dep-search':  S.depQ = el.value; S.page = {}; rerenderKeepFocus(el); break;
    case 'arm-mission': S.inv[regOf(el).key][+el.dataset.i].mission = el.value; break;
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
    case 'ammo-qty':
      S.ammoDraft[el.dataset.id] = { ...(S.ammoDraft[el.dataset.id] || { dest: 'used' }), qty: el.value };
      break;
    case 'ammo-who':
      S.ammoDraft[el.dataset.id] = { ...(S.ammoDraft[el.dataset.id] || { dest: 'used' }), who: el.value };
      break;
    case 'uedit-pw':  S.userEditDraft = { ...S.userEditDraft, pw: el.value }; break;
    case 'uedit-pw2': S.userEditDraft = { ...S.userEditDraft, pw2: el.value }; break;
    case 'ammo-note':
      S.ammoDraft[el.dataset.id] = { ...(S.ammoDraft[el.dataset.id] || { dest: 'used' }), note: el.value };
      break;
    case 'fuel-use-who':
      S.fuelDraft[el.dataset.id] = { ...(S.fuelDraft[el.dataset.id] || {}), who: el.value };
      break;
    case 'fuel-use-litres':
      S.fuelDraft[el.dataset.id] = { ...(S.fuelDraft[el.dataset.id] || {}), litres: el.value };
      break;
    case 'fuel-use-plate':
      S.fuelDraft[el.dataset.id] = { ...(S.fuelDraft[el.dataset.id] || {}), plate: el.value };
      break;
    case 'arm-note':
      S.armDraft[el.dataset.id] = { ...(S.armDraft[el.dataset.id] || {}), note: el.value };
      break;
    // correcting a register row in place — saved when the editor is closed
    case 'arm-e-name':   S.inv[regOf(el).key][+el.dataset.i].name = el.value; break;
    case 'arm-e-serial': S.inv[regOf(el).key][+el.dataset.i].serial = el.value; break;
    case 'arm-e-owner':  S.inv[regOf(el).key][+el.dataset.i].owner = el.value; break;
    case 'ammo-name':    S.inv.ammo[+el.dataset.i].name = el.value; break;
    case 'rec-f':        if (S.recDraft) S.recDraft[el.dataset.k] = el.value; break;
    case 'lic-ed-no':    if (S.licDraft) S.licDraft.no = el.value.trim(); break;
    case 'wa-test-to':   S.wa.to = el.value; break;
    case 'wa-test-body': S.wa.body = el.value; break;
    case 'rep-f':        if (S.repDraft) S.repDraft[el.dataset.k] = el.value; break;
    case 'ammo-open':
      S.inv.ammo[+el.dataset.i].open =
        Math.max(0, Math.min(999999, parseInt(String(el.value).replace(/\D/g, ''), 10) || 0));
      break;
    case 'fuel-no':      S.inv.fuel[+el.dataset.i].no = el.value; break;
    case 'fuel-holder':  S.inv.fuel[+el.dataset.i].holder = el.value; break;
    case 'fuel-litres':
      S.inv.fuel[+el.dataset.i].litres =
        Math.max(0, Math.min(99999, parseInt(String(el.value).replace(/\D/g, ''), 10) || 0));
      break;
    case 'lic-no': S.licNo = el.value.trim(); break;
    case 'lic-exp': S.licExp = el.value; break;   // re-render happens on 'change'
    // The test-message box. Held in state so the four-second poll's re-render
    // does not wipe what is being typed.
  }
});

// A serial is checked when the soldier leaves the field, not per keystroke:
// a half-typed number is nearly always free, and saying so would be noise.
$app.addEventListener('focusout', (e) => {
  const el = e.target.closest('[data-act="ser-chk"]');
  if (!el || !$app.contains(el)) return;
  const label = (SERIAL_FIELDS.find(([f]) => f === el.dataset.f) || [, ''])[1];
  checkSerial(el.dataset.f, el.value.trim(), label);
});

// Checkboxes and file pickers report via 'change', not 'input'.
$app.addEventListener('change', (e) => {
  const el = e.target.closest('[data-act]');
  if (!el || !$app.contains(el)) return;
  if (el.dataset.act === 'rep-state') { repSetState(el.dataset.id, el.dataset.st); return; }
  if (el.dataset.act === 'flt-state') { fltSetState(el.dataset.id, el.dataset.st); return; }
  // number fields refresh their computed columns on commit, not per keystroke
  if (NUM_COMMIT.has(el.dataset.act)) { renderConsole(); return; }
  if (el.dataset.act === 'rf-photo') { refuelPhoto(el); return; }
  if (el.dataset.act === 'rf-pick') {
    S.rfPick = { ...S.rfPick, [el.dataset.id]: el.value };
    renderConsole();
    return;
  }
  // The licence editor re-renders on these: the date drives its own validity
  // hint, and the ticks decide which half of the form is on screen at all.
  if (el.dataset.act === 'lic-ed-exp') {
    if (S.licDraft) { S.licDraft.exp = el.value; renderConsole(); }
    return;
  }
  if (el.dataset.act === 'lic-ed-has') {
    if (S.licDraft) { S.licDraft[el.dataset.kind] = el.checked; renderConsole(); }
    return;
  }
  if (el.dataset.act === 'lic-ed-file') { licEdFile(el.dataset.kind, el); return; }
  if (el.dataset.act === 'rec-f-dept') {
    if (S.recDraft) S.recDraft.dept = el.value;
    return;
  }
  if (el.dataset.act === 'arm-e-kind') {
    const reg = regOf(el);
    const it = S.inv[reg.key][+el.dataset.i];
    it.kind = el.value;
    // the new kind may not allow where the item currently is
    if (!kindLocs(reg, it.kind).some((l) => l.id === it.loc)) it.loc = reg.home;
    renderConsole();
    return;
  }
  if (el.dataset.act === 'arm-loc') {
    const it = S.inv[regOf(el).key][+el.dataset.i];
    it.loc = el.value;
    // the name belongs to the place: move it out of a mission or a vehicle and
    // the mission's name or the vehicle's number means nothing any more
    if (!NAMED_LOCS[it.loc]) it.mission = '';
    renderConsole();
    return;
  }
  if (el.dataset.act === 'veh-service') { S.inv.vehicles[+el.dataset.i].service = el.value; renderConsole(); return; }
  if (el.dataset.act === 'veh-kit') { S.inv.vehicles[+el.dataset.i][el.dataset.k] = el.checked; renderConsole(); return; }
  if (el.dataset.act === 'urole') { S.userRole = el.value; renderConsole(); return; }
  if (el.dataset.act === 'uedit-role') {
    S.userEditDraft = { ...S.userEditDraft, role: el.value };
    renderConsole();
    return;
  }
  if (el.dataset.act === 'uedit-tab') {
    const t = el.dataset.t;
    if (el.checked) S.userEditDraft.tabs.add(t);
    else S.userEditDraft.tabs.delete(t);
    renderConsole();
    return;
  }
  if (el.dataset.act === 'arm-dest') {
    const id = el.dataset.id;
    S.armDraft[id] = { ...(S.armDraft[id] || {}), dest: el.value };
    renderConsole();
    return;
  }
  if (el.dataset.act === 'ammo-dest') {
    const id = el.dataset.id;
    S.ammoDraft[id] = { ...(S.ammoDraft[id] || {}), dest: el.value };
    renderConsole();
    return;
  }
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
  else if (el.dataset.act === 'lic-exp') { S.licExp = el.value; captureIdentForm(); renderFlow(); }
});

$app.addEventListener('submit', (e) => {
  const form = e.target.closest('form[data-form]');
  if (!form) return;
  e.preventDefault();
  const kind = form.dataset.form;
  if (kind === 'ident') soldierIdentSubmit(form);
  else if (kind === 'weapon') weaponSubmit(form);
  else if (kind === 'gear-ident') gearIdentSubmit(form);
  else if (kind === 'setup') setupSubmit(form);
  else if (kind === 'login') loginSubmit(form);
  else if (kind === 'rotate') rotateSubmit(form);
  else if (kind === 'user-add') userAddSubmit(form);
  else if (kind === 'report') reportSubmit(form);
  else if (kind === 'deposit') depositSubmit(form);
  else if (kind === 'fault') faultSubmit(form);
  else if (kind === 'refuel') refuelSubmit(form);
  else if (kind === 'arm-add') armAdd(form);
  else if (kind === 'arm-loan') armLoan(form);
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
    case 's-back': S.sStep = 1; renderFlow(); break;
    case 's-edit': S.sStep = 2; renderFlow(); break;
    case 's-edit-ident': S.sStep = 1; renderFlow(); break;
    case 's-review':
      if (!Object.keys(S.sel).length) {
        const e = $app.querySelector('[data-err]');
        if (e) e.textContent = 'יש לסמן פריט אחד לפחות';
        return;
      }
      S.sStep = 3;
      renderFlow();
      break;
    case 's-remove':
      delete S.sel[el.dataset.item];
      if (!Object.keys(S.sel).length) S.sStep = 2;
      renderFlow();
      break;
    case 's-reset': resetSoldier(); renderFlow(); break;
    case 'lic-clear': licClear(el.dataset.kind); break;
    case 'lic-shared': licUseShared(el.dataset.kind); break;
    case 'wa-refresh': waRefresh(); break;
    case 'wa-test-send': waTestSend(); break;
    // admin console
    // Moving between screens keeps a trail, so "חזרה" goes back the way you
    // came rather than always to the overview. Re-picking the screen you are
    // already on is not a move and must not stack up.
    case 'tab':
      if (el.dataset.tab !== S.tab) {
        S.tabHist = [...S.tabHist, S.tab].slice(-20);
        S.tab = el.dataset.tab;
        S.page = {};
      }
      renderConsole();
      break;
    case 'tab-back':
      if (S.tabHist.length) {
        S.tab = S.tabHist[S.tabHist.length - 1];
        S.tabHist = S.tabHist.slice(0, -1);
        S.page = {};
      }
      renderConsole();
      break;
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
    case 'creditall': S.askDel = ''; S.creditAsk = rid; renderConsole(); break;
    case 'credit-cancel': S.creditAsk = ''; renderConsole(); break;
    case 'credit-ok': S.creditAsk = ''; adminCreditAll(rid); break;
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
    case 'ask-del':    S.askDel = el.dataset.key; renderConsole(); break;
    case 'ask-cancel': S.askDel = ''; renderConsole(); break;
    // correcting a soldier's record
    case 'rec-edit': {
      const rec = findRec(el.dataset.rid);
      if (!rec || !rec.data) break;
      S.recEdit = el.dataset.rid;
      const { name, pn, phone, dept, weapon, amral, scope } = rec.data;
      S.recDraft = { name, pn, phone, dept, weapon, amral, scope };
      renderConsole();
      break;
    }
    case 'rec-cancel': S.recEdit = ''; S.recDraft = null; renderConsole(); break;
    case 'lic-edit': {
      const rec = findRec(el.dataset.rid);
      if (!rec || !rec.data) break;
      const lic = rec.data.lic || {};
      S.licEdit = el.dataset.rid;
      S.licDraft = {
        civil: !!(lic.civil && lic.civil.has),
        no: (lic.civil && lic.civil.no) || '',
        exp: (lic.civil && lic.civil.exp) || '',
        military: !!(lic.military && lic.military.has),
        pic: {},
      };
      renderConsole();
      break;
    }
    case 'lic-cancel': S.licEdit = ''; S.licDraft = null; renderConsole(); break;
    case 'lic-ed-nopic': if (S.licDraft) { S.licDraft.pic[el.dataset.kind] = null; renderConsole(); } break;
    case 'lic-ed-keep': if (S.licDraft) { delete S.licDraft.pic[el.dataset.kind]; renderConsole(); } break;
    case 'lic-save': licSave(el.dataset.rid); break;
    case 'rec-save': recSave(el.dataset.rid); break;
    // correcting a shortage request, a deposit or a building fault
    case 'rep-edit': {
      const rep = S.reports.find((r) => r.id === el.dataset.id);
      if (!rep || !rep.data) break;
      S.repEdit = el.dataset.id;
      const { kind, name, pn, phone, text, weapon, amral, scope } = rep.data;
      S.repDraft = { kind, name, pn, phone, text, weapon, amral, scope };
      renderConsole();
      break;
    }
    case 'rep-cancel': S.repEdit = ''; S.repDraft = null; renderConsole(); break;
    case 'rep-save': repSave(el.dataset.id); break;
    case 'rf-file': refuelFile(el.dataset.id); break;
    case 'rf-reopen': refuelReopen(el.dataset.id); break;
    case 'inv-xdel':
      S.inv.extra.splice(parseInt(el.dataset.i, 10), 1);
      S.askDel = '';
      renderConsole();
      break;
    case 'inv-save': {
      // A loan with nobody's name on it is the exact thing that was being
      // asked for, so the save that would file one is refused — and it names
      // the item, rather than only saying that something somewhere is blank.
      const reg = el.dataset.reg ? REGISTERS[el.dataset.reg] : null;
      const blank = reg && loansOf(reg).find((x) => !x.mission);
      if (blank) {
        toast(`${blank.name} (${blank.serial}) מסומן "${nameOf(reg.locs, blank.loc)}" בלי שם — רשמו מי לקח`, true);
        break;
      }
      invSave();
      break;
    }
    // armoury
    case 'arm-kind':
      S.regKind = { ...S.regKind, [regOf(el).id]: el.dataset.k };
      S.page = {}; renderConsole(); break;
    case 'arm-remove': armRemove(regOf(el), +el.dataset.i); break;
    case 'arm-return': armReturn(regOf(el), +el.dataset.i); break;
    case 'arm-edit':   S.armEdit = el.dataset.id; renderConsole(); break;
    case 'arm-e-done': {
      // A serial corrected into one that already exists is the collision this
      // check exists for, so the editor stays open until it is resolved.
      const reg = regOf(el);
      const it = (S.inv[reg.key] || []).find((x) => x.id === S.armEdit);
      const clash = it ? serialTaken(it.serial, it.id) : '';
      if (clash) { toast(clash, true); break; }
      S.armEdit = '';
      invSave();
      break;
    }
    // Deleting the row outright, as opposed to moving the item somewhere:
    // this is for a line that should never have been written, so it leaves
    // no movement in the log either.
    case 'arm-del': {
      const reg = regOf(el);
      S.inv[reg.key].splice(+el.dataset.i, 1);
      S.askDel = '';
      invSave();
      break;
    }
    case 'arm-log-del': {
      const reg = regOf(el);
      S.inv[reg.logKey].splice(+el.dataset.n, 1);
      S.askDel = '';
      invSave();
      break;
    }
    case 'ammo-log-del':
      S.inv.ammoLog.splice(+el.dataset.n, 1);
      S.askDel = '';
      invSave();
      break;
    case 'arm-qclear': S.regQ = { ...S.regQ, [regOf(el).key]: '' }; S.page = {}; renderConsole(); break;
    // tzelem report
    case 'tz-qclear': S.regQ = { ...S.regQ, tzelem: '' }; renderConsole(); break;
    case 'tz-wa': tzelemWa(); break;
    // ammunition
    case 'ammo-issue': ammoMove(+el.dataset.i, 'issue'); break;
    case 'ammo-add-qty': ammoMove(+el.dataset.i, 'add'); break;
    case 'ammo-return': ammoMove(+el.dataset.i, 'return'); break;
    case 'ammo-out-return': ammoOutReturn(+el.dataset.i); break;
    case 'ammo-out-all': ammoOutAll(); break;
    case 'ammo-del':
      S.inv.ammo.splice(+el.dataset.i, 1); S.askDel = ''; invSave();
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
      S.inv.vehicles.splice(+el.dataset.i, 1); S.askDel = ''; renderConsole();
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
      S.inv.fuel[+el.dataset.i].uses.splice(+el.dataset.n, 1);
      S.askDel = '';
      invSave();
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
      bringIntoView($app, 'start');
      break;
    case 'doc': toggleDoc(rid, el.dataset.kind); break;
    // Both of a soldier's licences at once — they arrive in the same response,
    // so showing one and hiding the other only costs a second look.
    case 'lic-docs': toggleLicDocs(rid); break;
    // The photo is already decrypted and on screen as a thumbnail; this only
    // decides how big it is drawn, so it never goes back to the server.
    case 'doc-zoom': {
      const key = `${rid}:${el.dataset.kind}`;
      if (S.docBig.has(key)) S.docBig.delete(key);
      else S.docBig.add(key);
      renderConsole();
      break;
    }
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
    case 'sessions-revoke': revokeSessions(); break;
    case 'trash-load': loadTrash(); break;
    case 'trash-restore': trashRestore(el.dataset.kind, el.dataset.id); break;
    case 'audit-load': loadAudit(); break;
    // the WhatsApp gateway
    case 'user-del': userDelete(el.dataset.u); break;
    case 'uedit-open': {
      const name = el.dataset.u;
      if (S.userEdit === name) { S.userEdit = null; S.userEditDraft = null; }
      else {
        const u = S.users.find((x) => x.username === name);
        let tabs = [];
        try { tabs = JSON.parse(u.tabs) || []; } catch { tabs = []; }
        if (u.tabs === '*') tabs = TABS.filter((t) => !t.adminOnly).map((t) => t.id);
        S.userEdit = name;
        S.userEditDraft = {
          role: u.role === 'admin' ? 'admin' : u.role,
          tabs: new Set(tabs), pw: '', pw2: '',
        };
      }
      renderConsole();
      break;
    }
    case 'uedit-cancel': S.userEdit = null; S.userEditDraft = null; renderConsole(); break;
    case 'uedit-save': userSave(el.dataset.u); break;
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
    case 'rf-filter': S.rfFilter = el.dataset.f; renderConsole(); break;
    case 'dep-approve': depApprove(el.dataset.id); break;
    case 'dep-qclear': S.depQ = ''; S.page = {}; renderConsole(); break;
    // building faults
    case 'flt-again': S.fltSent = false; S.flt = null; renderFault(); break;
    case 'rf-again': S.rfSent = false; S.rf = null; S.rfPhoto = null; renderRefuel(); break;
    case 'sig-clear': clearSignature(); break;
    case 'rf-photo-clear': captureRefuelForm(); S.rfPhoto = null; renderRefuel(); break;
    case 'flt-filter': S.fltFilter = el.dataset.f; S.page = {}; renderConsole(); break;
    case 'flt-qclear': S.fltQ = ''; S.page = {}; renderConsole(); break;
    // the link itself still opens WhatsApp; this only records that it was used
    case 'wa-sign': markSent(rid, 'notified'); break;
    case 'wa-ret': markSent(rid, 'returnNotified'); break;
  }
}

/* Marks a WhatsApp send on the record so the card reflects it. The log keeps
   the two apart: a message the console sent on the unit's line is a different
   fact from one somebody typed out of their own WhatsApp, and only one of them
   can be proven from here. */
function markSent(rid, field, via = 'manual') {
  const rec = findRec(rid);
  if (!rec || rec.damaged || rec.data[field]) return;
  const now = Date.now();
  const entry = {
    a: field === 'notified' ? `notify-${via}` : `return-notify${via === 'auto' ? '-auto' : ''}`,
    t: now,
  };
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

/* ── Arriving from the gallery ─────────────────────────────────────────
   On phones whose gallery ignores the intent a file input sends — Samsung's,
   among others — no `accept` value can reach it, because the gallery never
   offers to answer. So the app registers as a share target and the soldier
   goes the other way round: gallery, שיתוף, מסייעת 951.

   Android POSTs the picture to /share-target, the service worker parks it and
   redirects here, and this claims it. The photo is compressed on arrival like
   any other, held in memory only, and never attached to anything by itself —
   the soldier still says which licence it belongs to. */

function registerShareTarget() {
  if (!('serviceWorker' in navigator)) return;
  navigator.serviceWorker.register('/sw.js').catch(() => {
    /* No worker means no share sheet entry, and nothing else. Both upload
       buttons keep working exactly as they did. */
  });
}

async function claimSharedPhoto() {
  const url = new URL(location.href);
  if (url.searchParams.get('shared') !== '1') return;

  /* Off the address bar before anything can go wrong, so a reload does not
     look like a second share and the flag cannot survive into a bookmark. */
  url.searchParams.delete('shared');
  history.replaceState(null, '', url.pathname + url.search + url.hash);

  if (!('caches' in window)) return;
  try {
    const cache = await caches.open('tzayad-share-v1');
    const res = await cache.match('/__shared-photo');
    if (!res) return;
    const blob = await res.blob();
    if (!blob.size) return;

    const file = new File([blob], 'shared', { type: blob.type || 'image/jpeg' });
    if (notAnImage(file)) { toast('הקובץ ששותף אינו תמונה', true); return; }

    const { bytes, size } = await compressImage(file);
    let bin = '';
    for (const b of bytes) bin += String.fromCharCode(b);
    S.sharedPhoto = { bytes, size, preview: `data:image/jpeg;base64,${btoa(bin)}` };

    /* Claimed, so the worker's copy goes now rather than sitting in a cache
       on somebody's phone until the next share overwrites it. */
    if (navigator.serviceWorker.controller) {
      navigator.serviceWorker.controller.postMessage('shared-photo-taken');
    } else {
      await cache.delete('/__shared-photo');
    }
    toast('התמונה ששיתפתם מוכנה — בחרו לאיזה רישיון לצרף אותה');
  } catch (e) {
    toast(e.message || 'לא הצלחנו לקרוא את התמונה ששותפה', true);
  }
}

async function boot() {
  if (!window.crypto || !window.crypto.subtle) {
    render('<section class="panel"><p class="mb0">הדפדפן לא תומך בהצפנה הנדרשת. יש לפתוח את הקישור בדפדפן עדכני דרך HTTPS.</p></section>');
    return;
  }
  render('<p class="loading">טוען…</p>');
  registerShareTarget();
  await claimSharedPhoto();
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

/* ── Noticing that this tab is running yesterday's code ────────────────
   Every page here is one document that swaps its own contents, and the
   menu links are hashes — so a tab opened this morning never fetches
   anything again and keeps running the code it booted with. After a
   deploy that means looking at a bug that was fixed hours ago, which is
   a miserable way to use a tool and an even worse way to report one.

   So the tab watches its own script. `app.js` carries an ETag; if the
   one on the server stops matching the one this tab booted with, there
   is a newer version and it says so. It never reloads on its own — a
   soldier half-way through a form would lose it — it offers. */

const VERSION_CHECK_MS = 5 * 60 * 1000;
let bootTag = null;

// Every file the browser loads, not just the entry one: a fix that lands
// entirely inside a module would leave app.js untouched, and a tab running
// yesterday's code would never be told.
const SCRIPTS = ['/app.js', '/lib/catalog.js', '/lib/crypto.js', '/lib/clean.js'];

async function scriptTag() {
  try {
    const tags = await Promise.all(SCRIPTS.map(async (src) => {
      const r = await fetch(src, { method: 'HEAD', cache: 'no-store' });
      return r.headers.get('etag') || r.headers.get('last-modified') || '';
    }));
    return tags.join('|');
  } catch {
    return null;   // offline: nothing to say
  }
}

function offerReload() {
  if (document.getElementById('newver')) return;
  const bar = document.createElement('div');
  bar.id = 'newver';
  bar.className = 'newver';
  bar.innerHTML = `
    <span>גרסה חדשה של המערכת זמינה.</span>
    <button class="btn primary small" data-act="reload-now">רענון</button>
    <button class="linkbtn" data-act="reload-later">לא עכשיו</button>`;
  bar.addEventListener('click', (e) => {
    const b = e.target.closest('button');
    if (!b) return;
    if (b.dataset.act === 'reload-now') location.reload();
    else bar.remove();
  });
  document.body.appendChild(bar);
}

async function versionWatch() {
  bootTag = await scriptTag();
  if (!bootTag) return;
  const look = async () => {
    if (document.hidden) return;
    const now = await scriptTag();
    if (now && now !== bootTag) offerReload();
  };
  setInterval(look, VERSION_CHECK_MS);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) look(); });
}

boot();
versionWatch();
