/* The watcher's clock.
 *
 * Everything else this Worker does is a database read. This is the part that
 * can be wrong without anybody noticing: a handover time is written in Israeli
 * wall-clock time by somebody in Israel, and the Worker wakes on UTC. Encode
 * the times as UTC hours and the whole schedule is silently an hour off for
 * five months of the year — in the direction where the alert fires late, at
 * the hour when being late matters.
 *
 * So the conversion is tested against both sides of the clock change, and
 * against midnight, which is where "yesterday's handover" lives.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const { overdueSlots } = await import(
  pathToFileURL(join(root, 'watcher/src/index.js')).href
);

const MIN = 60 * 1000;
const GRACE = 30 * MIN;
const WINDOW = 6 * 60 * MIN;

// A moment expressed the way a person in Israel would say it.
const il = (s) => new Date(s).getTime();

// What the Israeli clock reads at that instant — the thing under test, read
// back independently rather than recomputed with the code being tested.
const hourIL = (ms) => new Intl.DateTimeFormat('en-GB', {
  timeZone: 'Asia/Jerusalem', hour: '2-digit', minute: '2-digit', hour12: false,
}).format(new Date(ms));

test('a handover is overdue once the grace period has passed, not before', () => {
  // 05:00 Israel in August is 02:00 UTC — the clock is on IDT, UTC+3.
  const at0520 = il('2026-08-30T02:20:00Z');
  const at0531 = il('2026-08-30T02:31:00Z');
  assert.deepEqual(overdueSlots(['05:00'], at0520, GRACE, WINDOW), [],
    'twenty minutes late is a commander walking back to the office');
  assert.equal(overdueSlots(['05:00'], at0531, GRACE, WINDOW).length, 1,
    'half an hour late is a shift nobody has heard from');
});

/* The clock change. Israel moved off summer time on 25 October 2026, so the
   same 05:00 handover sits at a different UTC hour on either side of it —
   which is the whole reason the times are not stored as UTC. */
test('the same handover survives the end of summer time', () => {
  const summer = overdueSlots(['05:00'], il('2026-08-30T02:31:00Z'), GRACE, WINDOW);
  const winter = overdueSlots(['05:00'], il('2026-11-30T03:31:00Z'), GRACE, WINDOW);
  assert.equal(summer.length, 1, 'IDT: 05:00 local is 02:00 UTC');
  assert.equal(winter.length, 1, 'IST: 05:00 local is 03:00 UTC');

  // And each one really is 05:00 on the Israeli clock, not merely "one slot".
  assert.equal(hourIL(summer[0]), '05:00');
  assert.equal(hourIL(winter[0]), '05:00');
});

/* Midnight, where a naive "today at 23:00" is a handover four hours in the
   future and therefore never overdue — so the 23:00 shift could go missing
   every single night without a word. */
test("just after midnight, last night's handover is the one that is overdue", () => {
  const at0030 = il('2026-08-30T21:30:00Z');          // 00:30 Israel, 31 August
  const slots = overdueSlots(['23:00'], at0030, GRACE, WINDOW);
  assert.equal(slots.length, 1, 'the 23:00 that has just passed, not tonight’s');
  assert.ok(slots[0] < at0030, 'a handover in the future cannot be late');
  assert.ok(at0030 - slots[0] < 2 * 60 * MIN, 'it was an hour and a half ago');
});

test('a handover older than the window is left alone', () => {
  // Seven hours after 05:00 — the shift is long over and so is the point.
  const later = il('2026-08-30T09:31:00Z');
  assert.deepEqual(overdueSlots(['05:00'], later, GRACE, WINDOW), [],
    'a watcher coming back up must not shout about yesterday');
});

/* נחל שכם hands over every six hours, and the window is six hours, so each
   handover is judged alone: by the time the 17:00 is overdue the 11:00 has
   aged out. That is the intended shape — one silent shift, one message — and
   it is worth pinning, because widening the window quietly turns a missed
   morning into a second message at night. */
test('handovers six hours apart are never overdue at the same time', () => {
  const at1745 = il('2026-08-30T14:45:00Z');          // 17:45 Israel
  const times = ['05:00', '11:00', '17:00', '23:00'];
  const slots = overdueSlots(times, at1745, GRACE, WINDOW);
  assert.equal(slots.length, 1, 'only the 17:00 — the 11:00 is six and three quarter hours old');
  assert.equal(hourIL(slots[0]), '17:00');

  // Widen the window and the older one comes back, oldest first, which is
  // what a watcher returning from an outage should report.
  const wide = overdueSlots(times, at1745, GRACE, 12 * 60 * MIN);
  assert.deepEqual(wide.map(hourIL), ['11:00', '17:00']);
});

test('a time that is not a time is dropped, not guessed at', () => {
  const at1145 = il('2026-08-30T08:45:00Z');          // 11:45 Israel
  assert.deepEqual(overdueSlots(['', 'ערב', '25:00', '11:70', null], at1145, GRACE, WINDOW), []);
  // and a sloppy but unambiguous one still works
  assert.equal(overdueSlots([' 11:00 '], at1145, GRACE, WINDOW).length, 1);
});

test('a mission with no times is never watched', () => {
  assert.deepEqual(overdueSlots([], Date.now(), GRACE, WINDOW), []);
});
