// The trust boundary.
//
// The RSA public key is public by design — that is what lets any soldier
// submit without an account. The consequence is that ANYONE can encrypt an
// arbitrary payload and POST it, so a decrypted record is untrusted input,
// not our own data. Everything here coerces a payload to the shape the UI
// expects: strings are capped, numbers are real finite numbers, ids are
// whitelisted. Without this, a crafted quantity like "<img …>" flows into
// innerHTML in the admin console — where the private key lives.

import { ITEMS, MISSION_ITEMS, DEPTS, DIETS, LIC_KINDS, REGISTERS, VEH_KIT, FUEL_KINDS, kindLocs, LIFECYCLE, ARM_BAD_LOCS, NAMED_LOCS, ARM_ACTIONS, AMMO_ACTIONS } from './catalog.js';
import { rndId } from './crypto.js';

const asText = (v, max) => (typeof v === 'string' ? v.slice(0, max) : '');

// Non-negative integer, or 0. Rejects strings, NaN, Infinity, negatives.
const asCount = (v, max = 9999) => {
  const n = typeof v === 'number' ? v : NaN;
  if (!Number.isFinite(n)) return 0;
  return Math.min(max, Math.max(0, Math.floor(n)));
};

const asTime = (v) => (Number.isFinite(v) && v > 0 ? v : null);

// A calendar day, or nothing. Only the ISO shape is ever accepted — anything
// else would be compared against today as a string and quietly never match.
const asDate = (v) => (typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v) ? v : '');

// One of a whitelist of ids, or the first as the fallback.
const asId = (list, v) => (list.some((x) => x.id === v) ? v : list[0].id);

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
    /* What this submission is. The sign-up used to be one form that asked for
       everything at once; it is three now, because the three things happen on
       three different days — a soldier is written down, is issued a weapon,
       and signs for kit, and rarely all in one morning.

       'full' is the old combined form, and it is the fallback on purpose:
       every record sealed before this existed carries no kind at all, and must
       keep reading as what it was. */
    kind: ['details', 'weapon', 'gear'].includes(raw.kind) ? raw.kind : 'full',
    pn: asText(raw.pn, 9),
    name: asText(raw.name, 60),
    phone: asText(raw.phone, 15),
    dept: DEPTS.some((d) => d.id === raw.dept) ? raw.dept : '',
    /* Kitchen, not equipment — but it is asked once, on the form everybody
       fills in, rather than on a list somebody has to keep by hand.

       No default. `asId` would answer 'רגיל' for every record filed before
       this question existed, and for every weapon and kit slip that never
       asks it, which is a made-up answer dressed as a real one. Empty means
       nobody has said, and the screens say exactly that. */
    diet: DIETS.some((x) => x.id === raw.diet) ? raw.diet : '',
    // Free text on purpose: an allergy is a sentence, not a checkbox, and a
    // list of allergens we invented would be missing the one that matters.
    allergy: asText(raw.allergy, 300),
    weapon: asText(raw.weapon, 20),
    amral: asText(raw.amral, 20),
    scope: asText(raw.scope, 20),
    items,
    ...(Object.keys(lic).length ? { lic } : {}),
    /* The driving refresher. It is not a licence and not per licence — it is
       one course a soldier has either sat this year or has not, recorded by
       the office rather than claimed on the sign-up form, which is why it has
       no field on any soldier-facing page.

       The tick and the date are kept apart on purpose: an office that knows
       he sat it but not when must still be able to say so, and a date alone
       (with the tick cleared) must not read as "passed". */
    refresh: !!raw.refresh,
    refreshAt: /^\d{4}-\d{2}-\d{2}$/.test(raw.refreshAt) ? raw.refreshAt : '',
    createdAt: asTime(raw.createdAt) || Date.now(),
    approvedAt: asTime(raw.approvedAt),
    notified: asTime(raw.notified),
    returnNotified: asTime(raw.returnNotified),
    signed: asTime(raw.signed),          // when they signed; the signature itself is a doc
    supp: !!raw.supp,
    log: Array.isArray(raw.log) ? raw.log.slice(-50) : [],
  };
}

// Shortage reports and armoury deposits share the /reports pipe — the server
// stores an opaque blob either way, so telling them apart is a client concern.
function cleanReport(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('bad payload');
  return {
    kind: ['deposit', 'fault', 'refuel', 'mission'].includes(raw.kind) ? raw.kind : 'report',
    /* mission-only: the shift checklist, one entry per item. Whitelisting
       works by omission, and omitting this meant a shift report arrived with
       its kind flattened to 'report' and its items gone — it read as an empty
       shortage request. Every field is coerced here, because a checklist that
       came back from storage is no more trusted than one off a form.

       `shot` is which document slot holds the photograph, kept as a number so
       the console does not have to infer it from position when an item was
       answered out of order. */
    items: Array.isArray(raw.items)
      ? raw.items.slice(0, MISSION_ITEMS.length).map((it) => ({
        id: MISSION_ITEMS.some((m) => m.id === (it && it.id)) ? it.id : '',
        // 'na' — not required on this mission — is a real answer, and a
        // different one from 'no'. Anything unrecognised reads as held, which
        // is the reading that shows the most and hides the least.
        have: ['no', 'na'].includes(it && it.have) ? it.have : 'yes',
        mk: asText(it && it.mk, 40),
        why: asText(it && it.why, 120),
        shot: asCount(it && it.shot, MISSION_ITEMS.length - 1),
      })).filter((it) => it.id)
      : [],
    // mission-only: which shift or task this was filed for. Free text.
    shift: asText(raw.shift, 60),
    /* mission-only: the vehicle the shift drove and its odometer as the
       commander read it. The id is the vault's own vehicle id, so the console
       can match the reading back to the vehicle; the label rides along
       because a vehicle can leave the fleet and stop resolving, and a reading
       against "unknown vehicle" is worth less than one against a plate. */
    vehId: asText(raw.vehId, 40),
    vehLabel: asText(raw.vehLabel, 60),
    km: asCount(raw.km, 9999999),
    // refuelling: which card, how much, into which vehicle. The litres are a
    // count and nothing else — a soldier's browser is not trusted to send a
    // number, so it is coerced to one here as everything else is.
    card: asText(raw.card, 30),
    // What to call that card on screen. `card` is an id the admin's browser
    // resolves against the vault; this is the human number that came with it,
    // so the report reads as "דיזל · ••1111" rather than as thirty-two hex
    // digits. Whitelisting works by omission, and omitting this one meant the
    // form sent a label that was thrown away on arrival, every time.
    cardLabel: asText(raw.cardLabel, 60),
    litres: asCount(raw.litres, 9999),
    plate: asText(raw.plate, 20),
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
    /* fault-only: how many photographs of the fault came with the report. The
       pictures themselves live in `docs` under this report's id; this only
       says how many there are to go and fetch, so the console does not ask
       after every fault that has none.

       `photo` was the first version of this — one picture, a plain true — and
       reports filed under it are still in the console, so it is still read. */
    photo: !!raw.photo,
    photos: asCount(raw.photos, 4),
    createdAt: asTime(raw.createdAt) || Date.now(),
  };
}

/* ── Serialised registers: the armoury and the signals store ───────────
   Both are the same thing — a list of numbered items, each of which is
   either on the shelf or accounted for somewhere else, with a log of every
   movement. They differ in what they hold and where an item can be, so
   that is all a register declares; the screen, the reports and the
   handlers are one implementation driven by the declaration. */

const cleanRegItem = (reg) => (x) => {
  const kind = reg.kinds.some((k) => k.id === (x && x.kind)) ? x.kind : reg.kinds[0].id;
  // A location the kind is not allowed in falls back to 'soldier', never to
  // home — an item that was out must not read as present in the cupboard.
  const allowed = kindLocs(reg, kind).map((l) => l.id);
  const raw = x && x.loc;
  return {
    id: asText(x && x.id, 40) || rndId(),
    kind,
    name: asText(x && x.name, 60),
    serial: asText(x && x.serial, 40),
    owner: asText(x && x.owner, 60),
    /* Whose the item is, and who is holding it — as personal numbers rather
       than as names. A name typed twice is two different strings as often as
       it is one, and matching a register row to a soldier's record on spelling
       puts an item on the wrong card or on no card at all. Empty on everything
       filed before this existed and on anyone who is not in the records; for
       those a name is still all there is. */
    ownerPn: asText(x && x.ownerPn, 12),
    holderPn: asText(x && x.holderPn, 12),
    loc: allowed.includes(raw) ? raw : (raw && raw !== reg.home ? 'soldier' : reg.home),
    // Whose name the current location carries: the soldier holding it, the
    // operation it went out on, or the vehicle it is fitted in. One field,
    // because an item is in one place at a time.
    mission: asText(x && x.mission, 60),
    since: asTime(x && x.since),      // when it left the shelf — the loan's clock
    due: asDate(x && x.due),          // when it was promised back, if a date was given
    note: asText(x && x.note, 120),
    addedAt: asTime(x && x.addedAt),
  };
};

const cleanArmLog = (x) => ({
  t: asTime(x && x.t),
  action: asId(ARM_ACTIONS, x && x.action),
  kind: asText(x && x.kind, 20),
  name: asText(x && x.name, 60),
  serial: asText(x && x.serial, 40),
  owner: asText(x && x.owner, 60),
  dest: asText(x && x.dest, 20),
  // A movement has two ends. Without them the log could say that an item moved
  // but not out of where — which is the half of the sentence you need when you
  // are trying to work out where a weapon actually is.
  from: asText(x && x.from, 20),
  to: asText(x && x.to, 20),
  who: asText(x && x.who, 60),        // who took it, or which operation
  days: asCount(x && x.days, 99999),  // how long it was out, filled in on return
  note: asText(x && x.note, 120),
});

const cleanAmmo = (x) => ({
  id: asText(x && x.id, 40) || rndId(),
  name: asText(x && x.name, 60),
  open: asCount(x && x.open),      // what came in — the baseline to count against
  qty: asCount(x && x.qty),        // what is on the shelf now
});

const cleanAmmoLog = (x) => ({
  t: asTime(x && x.t),
  action: asId(AMMO_ACTIONS, x && x.action),
  name: asText(x && x.name, 60),
  qty: asCount(x && x.qty),
  note: asText(x && x.note, 120),
  dest: asText(x && x.dest, 20),
  who: asText(x && x.who, 60),
});

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
    armon: arr(src.armon, cleanRegItem(REGISTERS.armon), 4000),
    armonLog: arr(src.armonLog, cleanArmLog, 5000),
    comms: arr(src.comms, cleanRegItem(REGISTERS.comms), 4000),
    commsLog: arr(src.commsLog, cleanArmLog, 5000),
    ammo: arr(src.ammo, cleanAmmo, 1000),
    ammoLog: arr(src.ammoLog, cleanAmmoLog, 5000),
    vehicles: arr(src.vehicles, cleanVehicle, 500),
    fuel: arr(src.fuel, cleanFuel, 300),
    countedAt: { tzelem: asTime(counted.tzelem), armon: asTime(counted.armon) },
    updatedAt: asTime(src.updatedAt),
  };
}

export {
  asCount,
  asDate,
  asText,
  asTime,
  cleanAmmo,
  cleanAmmoLog,
  cleanArmLog,
  cleanFuel,
  cleanInv,
  cleanRecord,
  cleanRegItem,
  cleanReport,
  cleanVehicle,
};
