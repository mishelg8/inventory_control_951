#!/usr/bin/env node
/* A console you can actually click.
 *
 * Everything below the sign-in screen — the approvals list, the armoury, the
 * signals store, the ammunition, the vehicles, the fuel cards, the reports,
 * the users, the trash, the audit trail — had only ever been checked by
 * reading it. The one console with data in it is the user's own, and I do not
 * have that password, and should not. So this builds a second console: a local
 * database, a throwaway administrator whose password is printed at the end,
 * and enough invented data that no screen comes up empty.
 *
 * It speaks to the dev server over HTTP exactly as a browser does, and it
 * imports the browser's own crypto module rather than a copy of it. If a
 * record it writes does not open in the console, the harness is wrong or the
 * app is — never a difference between two implementations of the same thing.
 *
 *   npx wrangler pages dev            # one terminal
 *   node scripts/dev-seed.mjs         # another
 *
 * The data is invented. The names are common Hebrew given names, the personal
 * numbers are seven digits starting at 8000000 (outside the real range), and
 * the phone numbers are the reserved 05X-000-XXXX block. Nothing here comes
 * from the production database, which this script cannot reach: it refuses any
 * address that is not localhost, and it is the only thing standing between a
 * mistyped flag and wiping the unit's records.
 */

import { execFileSync } from 'node:child_process';
import { webcrypto } from 'node:crypto';
import { deflateSync } from 'node:zlib';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const {
  b64, deriveAuth, deriveRid, hex, importPubKey, rndId, seal, sealBytes, serialTags,
} = await import('../public/lib/crypto.js');

/* ── arguments ─────────────────────────────────────────────────────── */

const args = process.argv.slice(2);
const argOf = (name, fallback) => {
  const hit = args.find((a) => a.startsWith(`--${name}=`));
  return hit ? hit.slice(name.length + 3) : fallback;
};

const BASE = argOf('url', 'http://127.0.0.1:8788').replace(/\/$/, '');
const PW = argOf('pw', 'dev-console-951');

// The whole safety of this script is one line. A seed run wipes what it finds,
// so it must never find production: only a loopback address is allowed, and
// the check is on the parsed hostname rather than on the string, because
// "http://127.0.0.1@tzayad.pages.dev/" contains "127.0.0.1" and is not it.
const host = new URL(BASE).hostname;
if (!['localhost', '127.0.0.1', '[::1]', '::1'].includes(host)) {
  console.error(`refusing to seed ${host} — this script only ever runs against localhost`);
  process.exit(1);
}

/* ── the back door, for when the front one is locked ───────────────── */

// The tables the wipe route clears, cleared the same way but from outside the
// application, for the one case the route cannot serve: a local database whose
// password nobody here knows. `--local` is not a flag to lose — it is what
// keeps this pointed at .wrangler/state rather than at Cloudflare — so it is
// passed as its own argument and the whole thing goes through execFile, never
// a shell.
const WIPE_TABLES = [
  'config', 'users', 'records', 'docs', 'reports', 'vault', 'vault_parts',
  'pub_pick', 'serial_tags', 'tickets', 'sessions', 'throttle', 'audit',
];

function resetTables() {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..');
  execFileSync(
    'npx',
    ['wrangler', 'd1', 'execute', 'tzayad', '--local', '--command',
      WIPE_TABLES.map((t) => `DELETE FROM ${t};`).join(' ')],
    { cwd: root, stdio: 'pipe' }
  );
}

/* ── the wire ──────────────────────────────────────────────────────── */

let cookie = '';

async function api(path, { method, body, headers } = {}) {
  const res = await fetch(`${BASE}/api${path}`, {
    method: method || (body ? 'POST' : 'GET'),
    headers: {
      ...(body ? { 'Content-Type': 'application/json' } : {}),
      ...(cookie ? { Cookie: cookie } : {}),
      ...headers,
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const set = res.headers.get('set-cookie');
  if (set) cookie = set.split(';')[0];
  const text = await res.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch { data = { error: text.slice(0, 200) }; }
  if (!res.ok) {
    const e = new Error(`${method || 'GET'} ${path} → ${res.status}: ${data.error || text.slice(0, 120)}`);
    e.status = res.status;
    throw e;
  }
  return data;
}

async function waitForServer() {
  for (let i = 0; i < 40; i += 1) {
    try {
      return await api('/config');
    } catch (e) {
      if (e.status) return await api('/config');       // answered, just not 200
      await new Promise((r) => setTimeout(r, 500));
    }
  }
  throw new Error(`no dev server at ${BASE} — start one with: npx wrangler pages dev`);
}

/* ── pictures, drawn without a canvas ──────────────────────────────── */

// A greyscale PNG with a scribble in it. The console shows the soldier's
// signature as an image; a blank one would prove the plumbing and nothing
// about the picture, so this draws a line that actually looks like a hand
// moved. PNG is the only image format that is short enough to write by hand.
function scribblePng(w = 320, h = 120) {
  const px = new Uint8Array(w * h).fill(255);
  const ink = (x, y) => {
    const xi = Math.round(x);
    const yi = Math.round(y);
    for (let dy = -1; dy <= 1; dy += 1) {
      for (let dx = -1; dx <= 1; dx += 1) {
        const p = (yi + dy) * w + (xi + dx);
        if (xi + dx >= 0 && xi + dx < w && yi + dy >= 0 && yi + dy < h) px[p] = 20;
      }
    }
  };
  for (let t = 0; t < 1200; t += 1) {
    const u = t / 1200;
    ink(20 + u * (w - 40), h / 2 + Math.sin(u * 18) * 28 * (1 - u * 0.6) - u * 10);
  }
  return greyPng(px, w, h);
}

/* A licence card. The console draws the civil and the military licence beside
   each other as thumbnails, and until now the seed attached neither — so the
   one part of that screen that could not be checked locally was whether a
   photograph appears at all, and whether the two can be told apart. These are
   deliberately unalike: same card, one pale and one dark, each with a portrait
   box and ruled lines where the writing goes. They are landscape, like the
   real thing, so the thumbnail crop is honest. */
function licencePng(dark, w = 340, h = 214) {
  const px = new Uint8Array(w * h).fill(dark ? 70 : 205);
  const rect = (x0, y0, x1, y1, v) => {
    for (let y = Math.max(0, y0); y < Math.min(h, y1); y += 1) {
      for (let x = Math.max(0, x0); x < Math.min(w, x1); x += 1) px[y * w + x] = v;
    }
  };
  rect(8, 8, w - 8, h - 8, dark ? 110 : 248);            // the card face
  rect(8, 8, w - 8, 34, dark ? 30 : 150);                // the header band
  rect(24, 52, 108, 168, dark ? 210 : 110);              // where the portrait goes
  for (let i = 0; i < 5; i += 1) {                       // the printed lines
    rect(124, 58 + i * 22, w - 30 - (i % 2) * 46, 70 + i * 22, dark ? 215 : 85);
  }
  return greyPng(px, w, h);
}

// One greyscale PNG encoder for both of them.
function greyPng(px, w, h) {
  const raw = new Uint8Array((w + 1) * h);
  for (let y = 0; y < h; y += 1) {
    raw[y * (w + 1)] = 0;                                  // filter: none
    raw.set(px.subarray(y * w, y * w + w), y * (w + 1) + 1);
  }

  const table = new Int32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c;
  }
  const crc = (buf) => {
    let c = 0xffffffff;
    for (const byte of buf) c = table[(c ^ byte) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  };
  const chunk = (type, data) => {
    const out = Buffer.alloc(data.length + 12);
    out.writeUInt32BE(data.length, 0);
    out.write(type, 4, 'ascii');
    Buffer.from(data).copy(out, 8);
    out.writeUInt32BE(crc(out.subarray(4, 8 + data.length)), 8 + data.length);
    return out;
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0);
  ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8;                                             // 8 bits
  ihdr[9] = 0;                                             // greyscale
  return new Uint8Array(Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(Buffer.from(raw))),
    chunk('IEND', Buffer.alloc(0)),
  ]));
}

/* ── the invented unit ─────────────────────────────────────────────── */

const DAY = 24 * 60 * 60 * 1000;
const ago = (days) => Date.now() - days * DAY;

const SOLDIERS = [
  ['אורי לוי', 'p1', 'weapon'], ['נועם ברק', 'p1', 'weapon'],
  ['איתי כהן', 'p1', ''], ['רועי אלמוג', 'p2', 'weapon'],
  ['שחר דוד', 'p2', ''], ['יונתן פרץ', 'p2', 'weapon'],
  ['עומר שגב', 'p3', 'weapon'], ['גיא מזרחי', 'p3', ''],
  ['אלון חדד', 'p3', 'weapon'], ['תומר אזולאי', 'mplag', ''],
  ['ליאור בן שושן', 'mplag', 'weapon'], ['ניר סבן', 'attached', ''],
];

// pending / approved / deleted — one of each state the console has a screen for
const STATE_OF = (i) => (i < 3 ? 'pending' : i === 11 ? 'deleted' : 'approved');

const soldierPayload = (i) => {
  const [name, dept, armed] = SOLDIERS[i];
  const pn = String(8000001 + i);
  const items = { helmet: { t: 1, r: 0 }, vest: { t: 1, r: 0 }, mags: { t: 4, r: i % 3 } };
  if (i % 2) items.knee = { t: 1, r: 0 };
  if (i % 4 === 0) items.mitznefet = { t: 1, r: 0 };
  const at = ago(30 - i * 2);
  return {
    pn,
    name,
    phone: `050000${String(1000 + i)}`,
    dept,
    weapon: armed ? `W${70000 + i * 7}` : '',
    amral: armed && i % 2 === 0 ? `A${31000 + i}` : '',
    scope: armed && i % 3 === 0 ? `S${9100 + i}` : '',
    items,
    /* Licences, in the three states the screen has to tell apart: a pair with
       photographs attached, a civil one on its own, and — through everybody
       else — none at all. An expiry in the past on one of them, because a
       licence screen that has never drawn a red row has not been looked at. */
    ...(i % 5 === 0
      ? {
        lic: {
          civil: { has: true, doc: true, no: `${5500000 + i}`, exp: i === 0 ? '2024-03-01' : '2029-06-30' },
          military: { has: true, doc: true },
        },
      }
      : i % 7 === 3
        ? { lic: { civil: { has: true, doc: true, no: `${5600000 + i}`, exp: '2027-11-15' } } }
        : {}),
    createdAt: at,
    approvedAt: STATE_OF(i) === 'approved' ? at + 2 * 60 * 60 * 1000 : null,
    notified: null,
    returnNotified: null,
    signed: at,
    supp: false,
    log: [],
  };
};

const REPORTS = [
  { kind: 'refuel', name: 'אורי לוי', litres: 42, text: 'תדלוק מלא לפני יציאה', days: 3 },
  { kind: 'refuel', name: 'רועי אלמוג', litres: 28, text: '', days: 6 },
  { kind: 'refuel', name: 'עומר שגב', litres: 50, text: 'כרטיס נגמר אחרי התדלוק', days: 11, filed: true },
  { kind: 'fault', name: 'שחר דוד', text: 'הרצועה של הקסדה קרועה, צריך החלפה', days: 2 },
  { kind: 'fault', name: 'גיא מזרחי', text: 'חסרות שתי מחסניות במחסן הפלוגתי', days: 8 },
  { kind: 'deposit', name: 'ניר סבן', weapon: 'W70099', amral: 'A31099', text: 'הפקדה לפני חופשה', days: 1 },
];

// The vault, one object per domain, exactly as the console slices it.
function vaultParts(vehicles, cards) {
  return {
    stock: {
      open: { helmet: 140, vest: 132, mitznefet: 95, knee: 88, mags: 610 },
      extra: [
        { name: 'אלונקה', open: 6, out: 2 },
        { name: 'ערכת עזרה ראשונה', open: 20, out: 11 },
        { name: 'פנס טקטי', open: 35, out: 19 },
      ],
      notes: 'ספירה אחרונה בוצעה מול טופס 15. חסרות 3 מצנפות מהמסירה של אוגוסט.',
    },
    countedAt: { countedAt: { tzelem: ago(9), armon: ago(4) } },
    armon: {
      armon: [
        ...SOLDIERS.filter((s) => s[2]).map((s, i) => ({
          id: rndId(), kind: 'weapon', name: 'M4', serial: `W${70000 + i * 7}`,
          owner: s[0], loc: 'soldier', mission: '', note: '', addedAt: ago(40),
        })),
        { id: rndId(), kind: 'weapon', name: 'M4', serial: 'W70450', owner: '', loc: 'armon', mission: '', note: '', addedAt: ago(60) },
        { id: rndId(), kind: 'weapon', name: 'נגב', serial: 'W70451', owner: '', loc: 'repair', mission: '', note: 'במוסך גדוד', addedAt: ago(60) },
        { id: rndId(), kind: 'amral', name: 'אמר״ל', serial: 'A31200', owner: '', loc: 'armon', mission: '', note: '', addedAt: ago(55) },
        { id: rndId(), kind: 'nscope', name: 'כוונת לילה', serial: 'S9500', owner: '', loc: 'lost', mission: '', note: 'דווח כאבוד בתרגיל', addedAt: ago(120) },
        { id: rndId(), kind: 'tzelem', name: 'משקפת', serial: 'T4400', owner: '', loc: 'mission', mission: 'סיור גבול', note: '', addedAt: ago(70) },
      ],
    },
    armonLog: {
      armonLog: [
        { t: ago(4), action: 'add', kind: 'weapon', name: 'M4', serial: 'W70450', owner: '', dest: 'armon', note: 'הוחזר מחייל' },
        { t: ago(12), action: 'remove', kind: 'nscope', name: 'כוונת לילה', serial: 'S9500', owner: '', dest: 'lost', note: 'דווח כאבוד' },
        { t: ago(20), action: 'add', kind: 'tzelem', name: 'משקפת', serial: 'T4400', owner: '', dest: 'armon', note: '' },
      ],
    },
    comms: {
      comms: [
        { id: rndId(), kind: 'radio', name: 'PRC-710', serial: 'R1201', owner: '', loc: 'store', mission: '', note: '', addedAt: ago(80) },
        { id: rndId(), kind: 'radio', name: 'PRC-710', serial: 'R1202', owner: '', loc: 'vehicle', mission: '7654321', note: '', addedAt: ago(80) },
        { id: rndId(), kind: 'radio', name: 'PRC-710', serial: 'R1203', owner: 'נועם ברק', loc: 'soldier', mission: '', note: '', addedAt: ago(80) },
        { id: rndId(), kind: 'battery', name: 'סוללה', serial: 'B4401', owner: '', loc: 'store', mission: '', note: '', addedAt: ago(75) },
        { id: rndId(), kind: 'battery', name: 'סוללה', serial: 'B4402', owner: '', loc: 'repair', mission: '', note: 'לא נטענת', addedAt: ago(75) },
        { id: rndId(), kind: 'antenna', name: 'אנטנה קצרה', serial: 'AN220', owner: '', loc: 'store', mission: '', note: '', addedAt: ago(75) },
        { id: rndId(), kind: 'headset', name: 'דיבורית', serial: 'H330', owner: '', loc: 'mission', mission: 'סיור גבול', note: '', addedAt: ago(75) },
      ],
    },
    commsLog: {
      commsLog: [
        { t: ago(3), action: 'add', kind: 'radio', name: 'PRC-710', serial: 'R1201', owner: '', dest: 'store', note: 'הוחזר' },
        { t: ago(14), action: 'remove', kind: 'battery', name: 'סוללה', serial: 'B4402', owner: '', dest: 'repair', note: '' },
      ],
    },
    ammo: {
      ammo: [
        { id: rndId(), name: '5.56 כדורים', open: 4000, qty: 3120 },
        { id: rndId(), name: 'רימון עשן', open: 40, qty: 22 },
        { id: rndId(), name: 'רימון הלם', open: 30, qty: 30 },
      ],
    },
    ammoLog: {
      ammoLog: [
        { t: ago(5), action: 'issue', name: '5.56 כדורים', qty: 600, note: 'מטווח פלוגתי', dest: 'mission', who: 'מחלקה 2' },
        { t: ago(15), action: 'issue', name: 'רימון עשן', qty: 18, note: '', dest: 'used', who: '' },
        { t: ago(30), action: 'add', name: '5.56 כדורים', qty: 4000, note: 'קליטה מהגדוד', dest: '', who: '' },
      ],
    },
    vehicles: { vehicles },
    fuel: { fuel: cards },
  };
}

function makeVehicles() {
  const rows = [
    ['7654321', 'האמר', 41200, '2026-11-01'],
    ['8123456', 'דוד', 88300, '2026-09-15'],
    ['6543219', 'סופה', 15400, '2027-01-20'],
    ['5432198', 'טנדר', 122900, '2026-08-30'],
    ['9876543', 'זאב', 60100, '2026-12-05'],
  ];
  return rows.map(([plate, company, km, service], i) => ({
    id: rndId(), plate, company, km, service,
    code: String(1000 + i * 11), fuelCode: String(4400 + i),
    note: i === 3 ? 'מגיע לטיפול 10,000' : '',
    jack: i !== 2, wrench: true, vest: i % 2 === 0, triangle: i !== 4,
  }));
}

function makeCards() {
  const rows = [
    ['diesel', '4580123412341111', 34, 'משרד הרכב'],
    ['diesel', '4580123412342222', 8, 'אורי לוי'],
    ['petrol', '4580123412343333', 46, 'משרד הרכב'],
    ['urea', '4580123412344444', 20, 'משרד הרכב'],
  ];
  return rows.map(([kind, no, litres, holder], i) => ({
    id: rndId(), kind, no, litres, holder,
    receipts: [], uses: i === 1
      ? [{ t: ago(6), who: 'אורי לוי', litres: 42, plate: '7654321' }]
      : [],
    credited: false, creditedAt: null, note: '',
  }));
}

const cardLabel = (c) => {
  const kind = { diesel: 'דיזל', petrol: 'בנזין', urea: 'אוריאה' }[c.kind] || c.kind;
  const no = String(c.no || '').replace(/\s+/g, '');
  return `${kind} · ${no.length > 4 ? `••${no.slice(-4)}` : no || 'ללא מספר'}`;
};

/* ── the run ───────────────────────────────────────────────────────── */

async function main() {
  process.stdout.write(`• dev server at ${BASE} … `);
  let cfg = await waitForServer();
  console.log('up');

  if (cfg.ready) {
    // Already set up. If it was set up by a previous seed run the password is
    // known, so the console can be emptied through its own wipe route — which
    // is also the only way this script ever deletes anything.
    process.stdout.write('• existing database — wiping via the console … ');
    const { salt } = await api(`/admin/challenge?u=admin.951`);
    const { verifier } = await deriveAuth(PW, salt);
    try {
      await api('/admin/login', { body: { username: 'admin.951', verifier } });
    } catch {
      // Set up by something other than a seed run — an older dev session, or
      // a console someone signed into by hand. The wipe route is out of reach
      // without the password, so the tables go directly, through wrangler.
      // Only ever with --reset: a run that cannot get in should stop rather
      // than reach past the front door on its own.
      if (!args.includes('--reset')) {
        console.log('');
        console.error(
          'the local database is set up with a password this script does not know.\n' +
          'to empty it and start over:  node scripts/dev-seed.mjs --reset'
        );
        process.exit(1);
      }
      resetTables();
      console.log('done (--reset)');
    }
    if (cookie) {
      await api('/admin/wipe', { method: 'POST' });
      console.log('done');
    }
    cookie = '';
    cfg = await api('/config');
    if (cfg.ready) throw new Error('the database is still configured after the wipe');
  }

  /* setup — the same six values setupSubmit sends, generated the same way */
  process.stdout.write('• generating a keypair and creating admin.951 … ');
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
  const { kek, verifier } = await deriveAuth(PW, salt);
  const wrapped = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: keyIv }, kek, pkcs8);
  await api('/setup', {
    body: {
      pub: JSON.stringify(pubJwk), salt, idSalt, verifier,
      keyIv: b64(keyIv), wrappedKey: b64(wrapped),
    },
  });
  await api('/admin/login', { body: { username: 'admin.951', verifier } });
  console.log('done');

  const pubKey = await importPubKey(pubJwk);
  const ticket = async () => (await api('/ticket')).ticket;

  /* the vault, one part at a time — the same ten rows the console writes */
  process.stdout.write('• vault … ');
  const vehicles = makeVehicles();
  const cards = makeCards();
  const parts = vaultParts(vehicles, cards);
  for (const [part, slice] of Object.entries(parts)) {
    await api(`/admin/vault/${part}`, { method: 'PUT', body: { ...await seal(pubKey, slice) } });
  }
  console.log(`${Object.keys(parts).length} parts`);

  /* what the soldier's refuelling form is allowed to offer */
  await api('/admin/cards', {
    method: 'PUT',
    body: {
      cards: cards.map((c) => ({ id: c.id, label: cardLabel(c) })),
      vehicles: vehicles.map((v) => ({ id: v.id, label: `${v.plate} · ${v.company}` })),
    },
  });

  /* records — submitted as a soldier would, then approved as an admin would */
  process.stdout.write('• records … ');
  const counts = { pending: 0, approved: 0, deleted: 0 };
  for (let i = 0; i < SOLDIERS.length; i += 1) {
    const d = soldierPayload(i);
    const rid = await deriveRid(d.pn, idSalt);
    const tags = await serialTags(d, idSalt);
    await api('/records', { body: { rid, ...await seal(pubKey, d), ticket: await ticket(), tags } });

    // the soldier's own hand, on the last page of the form
    await api('/docs', {
      body: { rid, kind: 'signature', ...await sealBytes(pubKey, scribblePng()) },
    });

    // and whichever licences they said they had a photograph of
    for (const kind of ['civil', 'military']) {
      if (!(d.lic && d.lic[kind] && d.lic[kind].doc)) continue;
      await api('/docs', {
        body: { rid, kind, ...await sealBytes(pubKey, licencePng(kind === 'military')) },
      });
    }

    const state = STATE_OF(i);
    if (state === 'approved') {
      await api(`/admin/records/${rid}`, {
        method: 'PUT',
        body: { ...await seal(pubKey, d), status: 'approved', tags },
      });
    } else if (state === 'deleted') {
      await api(`/admin/records/${rid}`, { method: 'DELETE' });
    }
    counts[state] += 1;
  }
  console.log(`${counts.pending} ממתינות, ${counts.approved} מאושרות, ${counts.deleted} בסל`);

  /* reports of each kind the console knows how to show */
  process.stdout.write('• reports … ');
  for (const [n, r] of REPORTS.entries()) {
    // Exactly what the soldier's form sends: the card's id for the console to
    // resolve, its printed number for the office to read, and the plate as
    // text rather than as the id behind the picker.
    const card = cards[r.filed ? 2 : 0];
    const veh = vehicles[n % vehicles.length];
    const payload = {
      kind: r.kind,
      card: r.kind === 'refuel' ? card.id : '',
      cardLabel: r.kind === 'refuel' ? cardLabel(card) : '',
      litres: r.litres || 0,
      plate: r.kind === 'refuel' ? veh.plate : '',
      name: r.name,
      text: r.text || '',
      pn: '', phone: `050000${String(2000 + n)}`, dept: '',
      weapon: r.weapon || '', amral: r.amral || '', scope: '',
      filed: !!r.filed,
      createdAt: ago(r.days),
    };
    const id = hex(crypto.getRandomValues(new Uint8Array(16)));
    const tags = r.kind === 'deposit' ? await serialTags(payload, idSalt) : [];
    await api('/reports', { body: { id, ...await seal(pubKey, payload), ticket: await ticket(), tags } });
  }
  console.log(`${REPORTS.length}`);

  /* a second account, so the users screen and the permission gates have
     something real to gate — an editor holding two screens out of nine */
  process.stdout.write('• a second account … ');
  const eSalt = b64(crypto.getRandomValues(new Uint8Array(16)));
  const eIv = crypto.getRandomValues(new Uint8Array(12));
  const { kek: eKek, verifier: eVer } = await deriveAuth(`${PW}-editor`, eSalt);
  await api('/admin/users/editor.951', {
    method: 'PUT',
    body: {
      role: 'editor',
      tabs: ['pending', 'reports'],
      salt: eSalt,
      verifier: eVer,
      keyIv: b64(eIv),
      wrappedKey: b64(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: eIv }, eKek, pkcs8)),
    },
  }).catch((e) => console.log(`(skipped: ${e.message})`));
  console.log('editor.951');

  console.log(`
────────────────────────────────────────────────────────
  ${BASE}/#admin

  admin.951    ${PW}
  editor.951   ${PW}-editor   (ממתינות ודיווחים בלבד)
────────────────────────────────────────────────────────
This database is local and disposable. The password above is
printed on purpose: it protects nothing real.
`);
}

main().catch((e) => {
  console.error(`\n${e.message}`);
  process.exit(1);
});
