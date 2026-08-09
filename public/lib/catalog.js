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
  // Lifesaving kit. A soldier carries these and is expected to be able to
  // account for them, so they are signed for like everything else — and unlike
  // everything else, one that has gone missing is worth noticing quickly.
  {
    // The strap, with the windlass across it.
    id: 'cat', name: 'חסם עורקים (CAT)', qty: true, min: 1, max: 10,
    icon: `${SVG_OPEN}<rect x="2.5" y="8.5" width="19" height="7" rx="2"/><path d="M8.5 5.2l7 13.6"/></svg>`,
  },
  {
    // A dressing pad, with the cross that says what it is for.
    id: 'dressing', name: 'תחבושת אישית (ת״א)', qty: true, min: 1, max: 10,
    icon: `${SVG_OPEN}<rect x="3.5" y="7" width="17" height="10" rx="2.5"/><path d="M12 9.8v4.4"/><path d="M9.8 12h4.4"/></svg>`,
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
/* The label changed to אקילה; the key did not, and must not. `amral` is the
   field name inside records that were sealed months ago — renaming it would
   make every one of them arrive at the cleaner with a field it does not
   whitelist, and the number would be dropped on the way in. What a thing is
   called on screen and what it is called in the ciphertext are two different
   decisions, and only one of them is safe to revisit. */
const SERIAL_FIELDS = [['weapon', 'נשק'], ['amral', 'אקילה'], ['scope', 'כוונת']];

// Each kind carries the locations it is allowed to be in. Only צל״ם can go out
// on a mission, and when it does the mission has to be named — an item that is
// "somewhere on an operation" with no name attached is an item you have lost.
const LIFECYCLE = ['repair', 'lost', 'decom'];

/* `noLoan` keeps a kind out of the lending form. A personal weapon and the day
   scope that lives on it are not borrowed from the armoury for an afternoon —
   they are signed for, deposited and drawn back through the deposit flow, and
   offering them in a list of things to lend put the wrong thing at the top of
   the most-used control on the screen. They still appear in the register, and
   their location can still be changed there; they are simply not what the
   lending form is for. */
const ARM_KINDS = [
  { id: 'weapon', name: 'נשק', locs: ['armon', 'soldier', ...LIFECYCLE], noLoan: true },
  // A soldier's own, handed in and drawn back through the deposit flow. It is
  // the item the sign-up form asks for a number for, and like the weapon and
  // the day scope it is nobody else's to borrow.
  { id: 'akila', name: 'אקילה', locs: ['armon', 'soldier', ...LIFECYCLE], noLoan: true },
  // The unit's own, kept on the shelf and lent out for a night — which is what
  // the armoury was asked for in the first place. Same sort of device, quite a
  // different thing to the register: this one comes back.
  { id: 'amral', name: 'אמר״ל', locs: ['armon', 'soldier', ...LIFECYCLE] },
  { id: 'dscope', name: 'כוונת יום', locs: ['armon', 'soldier', ...LIFECYCLE], noLoan: true },
  { id: 'nscope', name: 'כוונת לילה', locs: ['armon', 'soldier', ...LIFECYCLE] },
  { id: 'tzelem', name: 'צל״ם', locs: ['armon', 'soldier', 'mission', ...LIFECYCLE] },
];

// Whether this register's kind may be offered in the lending form at all.
const canLoan = (reg, kind) => !(reg.kinds.find((k) => k.id === kind) || {}).noLoan;

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

// Locations that are meaningless without a name: "on an operation", "in a
// vehicle" or "with a soldier" is not an answer to where something is until
// you say which one, or who. 'soldier' was the omission that mattered — it is
// the most common place for a weapon to be, and the register recorded it as a
// bare word. "אצל חייל" with no name is a rifle that has left the armoury and
// that nobody can go and ask for.
const NAMED_LOCS = {
  soldier: { label: 'שם החייל', of: 'חייל' },
  mission: { label: 'שם המשימה', of: 'משימה' },
  vehicle: { label: 'מספר הרכב', of: 'רכב' },
};

// Out, and expected back — as opposed to at the workshop, written off or lost,
// which are also "not here" but are not loans. This is the set the loan screen,
// the overdue alert and the return button all work from.
const LOAN_LOCS = new Set(['soldier', 'mission', 'vehicle']);

// A movement in a register's log. 'move' and 'return' were added when the
// registers learned to record where an item went: before them, a weapon could
// travel from the armoury to a soldier and back with the log saying nothing,
// because only entering and leaving the register itself was ever written down.
const ARM_ACTIONS = [
  { id: 'add', name: 'הוספה', sign: '+' },
  { id: 'move', name: 'השאלה / העברה', sign: '→' },
  { id: 'return', name: 'החזרה', sign: '↩' },
  { id: 'remove', name: 'הסרה', sign: '−' },
];

// The same three for a countable item. A return is not an arrival: it puts
// rounds back on the shelf without pretending the unit was issued more.
const AMMO_ACTIONS = [
  { id: 'add', name: 'כניסה', sign: '+' },
  { id: 'issue', name: 'הוצאה', sign: '−' },
  { id: 'return', name: 'החזרה', sign: '↩' },
];

// where an item goes when it leaves the armoury for good
// 'used' is consumption: a gas or stun grenade that was thrown went nowhere
// and to nobody, so it needs no recipient — which is why it stops being a
// free-text field and becomes a choice.
// `loan` marks the two that can come back. Rounds drawn by a soldier or for an
// operation are owed to the armoury until they are returned or accounted for;
// what was thrown or credited is gone, and asking for it back is meaningless.
const AMMO_DESTS = [
  { id: 'used', name: 'שומש', noWho: true },
  { id: 'mission', name: 'משימה', loan: true },
  { id: 'soldier', name: 'חייל', loan: true },
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
  AMMO_ACTIONS,
  AMMO_DESTS,
  ARM_ACTIONS,
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
  LOAN_LOCS,
  NAMED_LOCS,
  REGISTERS,
  SERIAL_FIELDS,
  SVG_OPEN,
  VEH_KIT,
  canLoan,
  deptName,
  itemById,
  kindLocs,
  nameOf,
};
