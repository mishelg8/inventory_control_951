/* When a handover was due, on an Israeli clock.
 *
 * Two things need this answer and they run in different places: the console,
 * which can decrypt the reports and knows exactly who filed what, and the
 * watcher Worker, which cannot decrypt anything and works from beats. They
 * must agree to the minute — a screen that says a shift is late while the
 * alert says it is fine is worse than either one alone — so the arithmetic
 * lives here once and both import it.
 *
 * The times are written by somebody in Israel, as wall-clock times. Encoding
 * them as UTC hours is correct for seven months of the year and an hour wrong
 * for the other five, silently, in the direction where the alert comes late.
 * So the conversion is done against the zone itself, at the instant in
 * question, rather than against a fixed offset.
 */

const TZ = 'Asia/Jerusalem';

const FMT = new Intl.DateTimeFormat('en-US', {
  timeZone: TZ, hour12: false,
  year: 'numeric', month: '2-digit', day: '2-digit',
  hour: '2-digit', minute: '2-digit', second: '2-digit',
});

const MIN = 60 * 1000;
const DAY = 24 * 60 * MIN;

// Israel's clock at a given instant, as numbers.
function wall(ms) {
  const p = {};
  for (const { type, value } of FMT.formatToParts(new Date(ms))) p[type] = value;
  // Some engines render midnight as hour 24 under hour12:false.
  return {
    y: +p.year, mo: +p.month, d: +p.day,
    h: +p.hour % 24, mi: +p.minute, s: +p.second,
  };
}

// How far Israel's wall clock is from UTC at that instant.
function offsetAt(ms) {
  const w = wall(ms);
  return Date.UTC(w.y, w.mo - 1, w.d, w.h, w.mi, w.s) - Math.floor(ms / 1000) * 1000;
}

/* The instant at which Israel's clock reads this date and time.
   Two passes, because the offset depends on the instant and the instant
   depends on the offset. One correction settles every case except a time
   inside the hour a spring-forward skips — 02:00 to 03:00, which is not an
   hour anybody schedules a handover in. */
function instantOf(y, mo, d, h, mi) {
  const naive = Date.UTC(y, mo - 1, d, h, mi, 0);
  const once = naive - offsetAt(naive);
  return naive - offsetAt(once);
}

/* Which handovers are now overdue.

   A handover is due at its time and overdue `grace` later. Anything older
   than `window` is left alone: something coming back after an outage should
   report this morning's silence, not last week's, and a burst of stale
   alarms is how somebody decides to ignore the whole thing. */
export function overdueSlots(times, now, grace, window) {
  const out = new Set();
  for (const t of times || []) {
    const m = /^(\d{1,2}):(\d{2})$/.exec(String(t || '').trim());
    if (!m) continue;
    const h = +m[1];
    const mi = +m[2];
    if (h > 23 || mi > 59) continue;
    // Today and yesterday, because at 00:30 the 23:00 handover is yesterday's
    // and is exactly the one worth raising.
    for (const back of [0, 1]) {
      const w = wall(now - back * DAY);
      const slot = instantOf(w.y, w.mo, w.d, h, mi);
      const age = now - slot;
      if (age >= grace && age < window) out.add(slot);
    }
  }
  return [...out].sort((a, b) => a - b);
}

/* When the shift that started at this handover ends.

   Needed because "was this handover reported?" was being answered with "did
   anything arrive after it", and anything that arrives is after every handover
   earlier in the day. One report at 22:40 therefore marked 05:00, 11:00 and
   17:00 all as reported, and a day of silence looked like a day of diligence.

   A shift ends when the next one begins. If a mission hands over at 05:00,
   11:00 and 17:00, the 11:00 report may arrive up to 17:00 and not a minute
   later — after that it belongs to the next shift, or to nobody. */
export function slotEnd(times, slot) {
  const mins = [...new Set((times || [])
    .map((t) => /^(\d{1,2}):(\d{2})$/.exec(String(t || '').trim()))
    .filter(Boolean)
    .map((m) => +m[1] * 60 + +m[2])
    .filter((v) => v < 24 * 60))].sort((a, b) => a - b);
  if (!mins.length) return slot + DAY;
  const w = wall(slot);
  const cur = w.h * 60 + w.mi;
  const next = mins.find((x) => x > cur);
  // Only one handover a day: the shift is the whole day.
  const gap = next === undefined ? (24 * 60 - cur + mins[0]) : (next - cur);
  return slot + (gap || 24 * 60) * MIN;
}

/* Did a report arrive for this handover?
   `stamps` are the times reports came in — beats to the watcher, decrypted
   reports to the console. Both ask the same question and must not answer it
   differently, so the rule lives here with the clock it depends on. */
export function slotCovered(times, slot, stamps, earlyMs) {
  const from = slot - earlyMs;
  const to = slotEnd(times, slot);
  return (stamps || []).some((t) => t >= from && t < to);
}

// The date as a person here would write it: 4.9.26.
export function dmy(ms) {
  const w = wall(ms);
  return `${w.d}.${w.mo}.${String(w.y).slice(-2)}`;
}

// The handover as a person would say it.
export function hhmm(ms) {
  const w = wall(ms);
  return `${String(w.h).padStart(2, '0')}:${String(w.mi).padStart(2, '0')}`;
}

export { wall };
