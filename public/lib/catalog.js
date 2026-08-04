// What the unit actually holds: the equipment a soldier signs for, the
// departments, and the two serialised registers (armoury and signals store)
// with the places an item in them can be. Data and pure lookups only — this
// file knows nothing about the screen or the server, which is why it can be
// read on its own to answer "what is in this system".

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

const DEPTS = [
  { id: 'p1', name: 'מחלקה 1' },
  { id: 'p2', name: 'מחלקה 2' },
  { id: 'p3', name: 'מחלקה 3' },
  { id: 'mplag', name: 'מפל״ג' },
  { id: 'attached', name: 'מסופחים' },
];

const deptName = (id) => (DEPTS.find((d) => d.id === id) || {}).name || 'ללא שיוך';

// The three numbers a soldier signs for. Named here because both the
// crypto helpers below and the duplicate checks further down need them.
const SERIAL_FIELDS = [['weapon', 'נשק'], ['amral', 'אמר״ל'], ['scope', 'כוונת']];

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

// Signals kit. Unlike a weapon, a radio is as often fitted in a vehicle as
// held by a soldier, and a battery or an antenna is worth counting on its own
// — a company with six radios and two working batteries has two radios.
const COMMS_PLACES = ['store', 'soldier', 'vehicle', 'mission', ...LIFECYCLE];

const COMMS_KINDS = [
  { id: 'radio', name: 'מכשיר קשר', locs: COMMS_PLACES },
  { id: 'antenna', name: 'אנטנה', locs: COMMS_PLACES },
  { id: 'battery', name: 'סוללה', locs: COMMS_PLACES },
  { id: 'charger', name: 'מטען', locs: COMMS_PLACES },
  { id: 'headset', name: 'דיבורית / אוזניות', locs: COMMS_PLACES },
  { id: 'cable', name: 'כבל / מתאם', locs: COMMS_PLACES },
  { id: 'commsAcc', name: 'אביזר נוסף', locs: COMMS_PLACES },
];

const COMMS_LOCS = [
  { id: 'store', name: 'מחסן קשר' },
  { id: 'soldier', name: 'אצל חייל' },
  { id: 'vehicle', name: 'ברכב' },
  { id: 'mission', name: 'במשימה' },
  { id: 'repair', name: 'בתיקון' },
  { id: 'lost', name: 'אבוד' },
  { id: 'decom', name: 'מושבת' },
];

// States that mean the item is not usable, as opposed to merely elsewhere.
const ARM_BAD_LOCS = new Set(['lost', 'decom']);

// Locations that are meaningless without a name: "on an operation" or "in a
// vehicle" is not an answer to where something is until you say which.
const NAMED_LOCS = {
  mission: { label: 'שם המשימה', of: 'משימה' },
  vehicle: { label: 'מספר הרכב', of: 'רכב' },
};

// where an item goes when it leaves the armoury for good
// 'used' is consumption: a gas or stun grenade that was thrown went nowhere
// and to nobody, so it needs no recipient — which is why it stops being a
// free-text field and becomes a choice.
const AMMO_DESTS = [
  { id: 'used', name: 'שומש', noWho: true },
  { id: 'mission', name: 'משימה' },
  { id: 'soldier', name: 'חייל' },
  { id: 'credit', name: 'זיכוי', noWho: true },
];

const ARM_DESTS = [
  { id: 'soldier', name: 'חייל' },
  { id: 'repair', name: 'תיקון' },
  { id: 'credit', name: 'זיכוי' },
];

const nameOf = (list, id) => (list.find((x) => x.id === id) || {}).name || '—';

// The two registers. `home` is the location that means "on our shelf"; it is
// what the stock count counts and what an item returns to. `unique` names the
// one kind whose serial may not repeat — weapons are serialised individually,
// while a battery or a scope is logged by מק״ט, a catalogue number every unit
// of that model shares, so duplicates there are correct.
const REGISTERS = {
  armon: {
    id: 'armon', tab: 'armon', key: 'armon', logKey: 'armonLog',
    kinds: ARM_KINDS, locs: ARM_LOCS, home: 'armon', unique: 'weapon',
    deposits: true,
    title: 'ארמון', place: 'הארמון', placeTo: 'לארמון', placeIn: 'בארמון',
    addTitle: 'הוספת פריט לארמון',
    namePh: 'לדוגמה: M4 / משקפת לילה', serialPh: 'M4-10021',
    stockNote: 'רק מה שנמצא פיזית בארמון עכשיו. ברגע שמסמנים פריט "אצל חייל" או "במשימה" הוא יורד מהרשימה הזו ועובר לטבלה שמתחת. המיקומים האפשריים תלויים בסוג הפריט — רק צל״ם יכול לצאת למשימה, ואז חובה לרשום איזו. שינוי מיקום נשמר עם "שמירת השינויים".',
  },
  comms: {
    id: 'comms', tab: 'comms', key: 'comms', logKey: 'commsLog',
    kinds: COMMS_KINDS, locs: COMMS_LOCS, home: 'store', unique: 'radio',
    deposits: false,
    title: 'מחסן קשר', place: 'המחסן', placeTo: 'למחסן', placeIn: 'במחסן',
    addTitle: 'הוספת פריט קשר',
    namePh: 'לדוגמה: מדף / אנטנה קצרה', serialPh: 'PRC-77012',
    stockNote: 'רק מה שנמצא פיזית במחסן הקשר עכשיו. ברגע שמסמנים פריט "אצל חייל", "ברכב" או "במשימה" הוא יורד מהרשימה הזו ועובר לטבלה שמתחת — ואז חובה לרשום ברכב או במשימה איזו. שינוי מיקום נשמר עם "שמירת השינויים".',
  },
};

const kindLocs = (reg, kind) => {
  const k = reg.kinds.find((x) => x.id === kind);
  return reg.locs.filter((l) => (k ? k.locs : [reg.home, 'soldier']).includes(l.id));
};

// `short` is what the column header shows — the full name stays as the title
// and the accessible label, so a checkbox column costs a few characters
// instead of an inch of table.
const VEH_KIT = [
  { id: 'jack', name: 'ג׳ק', short: 'ג׳ק' },
  { id: 'wrench', name: 'מפתח גלגלים', short: 'מפתח' },
  { id: 'vest', name: 'אפודה זוהרת', short: 'אפודה' },
  { id: 'triangle', name: 'משולש', short: 'משולש' },
];

const FUEL_KINDS = [
  { id: 'diesel', name: 'דיזל' },
  { id: 'petrol', name: 'בנזין' },
  { id: 'urea', name: 'אוריאה' },
];

// Cards arrive holding 50 litres, so 15 is the point at which one needs
// replacing rather than merely watching.
const FUEL_LOW = 15;

const FUEL_OFFICE = 'במשרד';

// Civilian licence is captured as typed fields (number + expiry) so the admin
// can actually sort and chase expiry dates; the military one stays a photo.
const LIC_KINDS = [
  { id: 'civil', label: 'רישיון נהיגה אזרחי בתוקף', short: 'רישיון אזרחי', mode: 'fields' },
  { id: 'military', label: 'רישיון נהיגה צבאי בתוקף', short: 'רישיון צבאי', mode: 'photo' },
];

const DAY_MS = 24 * 60 * 60 * 1000;

const EXPIRING_SOON_DAYS = 60;

export {
  AMMO_DESTS,
  ARM_BAD_LOCS,
  ARM_DESTS,
  ARM_KINDS,
  ARM_LOCS,
  COMMS_KINDS,
  COMMS_LOCS,
  COMMS_PLACES,
  DAY_MS,
  DEPTS,
  EXPIRING_SOON_DAYS,
  FUEL_KINDS,
  FUEL_LOW,
  FUEL_OFFICE,
  ITEMS,
  LIC_KINDS,
  LIFECYCLE,
  NAMED_LOCS,
  REGISTERS,
  SERIAL_FIELDS,
  SVG_OPEN,
  VEH_KIT,
  deptName,
  itemById,
  kindLocs,
  nameOf,
};
