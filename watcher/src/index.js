/* The watcher: a shift that never reported.
 *
 * Everything else in this system is asked a question by somebody who is
 * looking at it. This one is not asked anything — it wakes on its own, four
 * times an hour, and its whole job is to notice an absence.
 *
 * It lives outside the Pages project because Pages Functions have no cron
 * triggers; that is a Workers feature, so this is a Worker. It binds the same
 * D1 database and reads two things: the missions the console published, and
 * the beats the shift form left behind.
 *
 * What it cannot do is read a report. Reports are sealed with a key that only
 * the admin's browser holds, and this Worker holds nothing — which is why a
 * beat exists at all. A beat says "this mission filed something at this
 * moment" and says nothing else, and that is exactly enough to tell a silent
 * handover from a reported one.
 */

import { overdueSlots, hhmm, slotEnd } from '../../public/lib/schedule.js';
// The names the ids stand for. Read from the app's own catalogue rather than
// copied, so an item renamed there is renamed here too.
import { MISSION_ITEMS } from '../../public/lib/catalog.js';

const MIN = 60 * 1000;

/* The times a mission is watched at, out of the row the console published.
   Both shapes are read: a bare array is a row written before missions carried
   handover times, and it is simply not watched. */
function timesOf(data) {
  try {
    const p = JSON.parse(data || '{}');
    if (Array.isArray(p)) return [];
    return Array.isArray(p.times) ? p.times : [];
  } catch {
    return [];
  }
}

/* Who gets told. Read from a secret rather than the repository, which is
   public — a phone number is personal data and does not go in a commit. */
const recipients = (env) =>
  String(env.ALERT_TO || '')
    .split(/[\s,]+/)
    .map((n) => n.replace(/\D/g, ''))
    .filter((n) => n.length >= 9 && n.length <= 15);

/* The sentence itself, as a setting rather than a string in the source.

   The wording is the part somebody wants to change at ten at night without
   waiting for a deploy, so it is a variable with two placeholders in it. A
   template parameter may not contain a newline, so whatever is put here has
   to stay one line — anything longer is trimmed rather than sent and refused
   by Meta with an error nobody will be reading at that hour. */
const ALERT_DEFAULT = 'לא התקבל דוח משמרת מ{mission} למשמרת של {time}';

const alertText = (env, mission, at) =>
  String(env.ALERT_TEXT || ALERT_DEFAULT)
    .replace(/\{mission\}/g, mission)
    .replace(/\{time\}/g, at)
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 900);

/* One template message. Business-initiated messages must be templates, and
   tzayad_update is already approved: "שלום {{1}}, {{2}}". Newlines are not
   allowed inside a parameter, so the sentence stays one line. */
async function send(env, to, text) {
  const url = `https://graph.facebook.com/${env.META_GRAPH_API_VERSION || 'v26.0'}` +
              `/${env.WHATSAPP_PHONE_NUMBER_ID}/messages`;
  const body = {
    messaging_product: 'whatsapp',
    to,
    type: 'template',
    template: {
      /* The alert's own template, separate from the app's.

         tzayad_update is categorised MARKETING, and WhatsApp caps how many
         marketing templates one person may receive in a day — over the cap
         the API still returns a message id and the message is never
         delivered. A whole day of alerts read as sent and no phone rang.

         A shift that did not report is operational, not promotional, so the
         alert belongs in a UTILITY template, which carries no such cap. This
         is a variable rather than a constant so switching to it is a setting,
         not a deploy. */
      name: env.WA_TPL_ALERT || env.WA_TPL_UPDATE || 'tzayad_update',
      language: { code: env.WA_TPL_LANG || 'he' },
      /* How many parameters the template declares, which is not ours to choose
         — Meta refuses a message whose count does not match exactly.

         tzayad_update reads "שלום {{1}}, {{2}}", so it needs a name before the
         sentence and prints a greeting whether one is wanted or not. A
         template whose whole body is {{1}} takes the sentence alone and
         greets nobody. Setting WA_TPL_LEAD to an empty string selects that
         shape; leaving it alone keeps working with the template in use today. */
      components: [{
        type: 'body',
        parameters: [
          ...(env.WA_TPL_LEAD === '' ? [] : [{ type: 'text', text: env.WA_TPL_LEAD || 'מפקד' }]),
          { type: 'text', text: String(text).replace(/\s+/g, ' ').trim().slice(0, 900) },
        ],
      }],
    },
  };
  const res = await fetch(url, {
    method: 'POST',
    // The token travels in a header. It has never been in a URL and must not
    // start now: URLs are logged, by us and by everyone in between.
    headers: {
      Authorization: `Bearer ${env.WHATSAPP_ACCESS_TOKEN}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    // Never the token, never the recipient in full — this goes to a log.
    throw new Error(`graph ${res.status}: ${text.slice(0, 300)}`);
  }

  /* What "sent" actually meant, written down.

     It meant "Meta returned 200", and nothing else — the API accepts a message
     for a number that does not exist, is not on WhatsApp, or has blocked the
     sender, and only says otherwise in a delivery callback that arrives later
     and that nothing here was listening for. So a whole day of alerts could
     read as sent, in a table, while no phone rang.

     The id and the last four digits are enough to take to the Meta dashboard
     and ask what became of a specific message. The rest of the number is not
     logged: it identifies a person, and this line goes somewhere I do not
     control the retention of. */
  const id = await res.json().then((j) => (j.messages && j.messages[0] && j.messages[0].id) || '?')
    .catch(() => '?');
  console.log(`watch.send.ok to=••${String(to).slice(-4)} wamid=${id}`);
}

export { overdueSlots };

/* What the supervisor is sent when reports come in.

   One line each, joined with a separator rather than a newline: a template
   parameter may not contain one, and Meta refuses the whole message if it
   does. That constraint shapes the format — it is not a preference.

   Exported so it can be read and tested without a database behind it. */
/* The line's wording, as a setting rather than a string in the source — the
   same reason the alert's is. Asterisks are WhatsApp's own bold markers and
   survive a template parameter; newlines do not, which is why the lines are
   joined with a separator further down. */
const DIGEST_LINE = 'דוח משימה - *{mission}* · {time} · {who} · {state}';

// id -> the name a person reads.
const ITEM_NAME = Object.fromEntries(MISSION_ITEMS.map((m) => [m.id, m.name]));

/* The checklist spelled out: what was there, and what was not.

   "אחד חסר" is half an answer — the supervisor still has to open the console
   to find out whether it was a pair of binoculars or the night sight. The
   names cost a line and save the trip. */
function itemBreak(items) {
  const ok = [];
  const bad = [];
  for (const pair of String(items || '').split(',')) {
    const [id, st] = pair.split(':');
    const name = ITEM_NAME[id];
    if (!name) continue;
    if (st === 'y') ok.push(name);
    else bad.push(st === 'p' ? `${name} (חלקי)` : name);
  }
  return { ok, bad };
}

export function digestText(rows, env = {}) {
  const fmt = String(env.DIGEST_LINE || DIGEST_LINE);
  const line = (r) => {
    /* A tick or a cross, before the words.

       The supervisor is reading this on a phone, at speed, looking for the
       line that needs an answer. A mark carries that at a glance where "1
       חסר · 2 חלקי" has to be read. A partial count gets the cross too: two
       grenades where five were asked for is a shortage, not a detail. */
    const state = r.short || r.partial
      ? `❌ ${[r.short ? `${r.short} חסר` : '', r.partial ? `${r.partial} חלקי` : '']
        .filter(Boolean).join(' · ')}`
      : '✅ הכול תקין';
    const { ok, bad } = itemBreak(r.items);
    // The breakdown replaces the bare count when there is one to give: naming
    // three present items and one missing says everything the count did.
    const detail = (ok.length || bad.length)
      ? [ok.length ? `✅ ${ok.join(', ')}` : '', bad.length ? `❌ ${bad.join(', ')}` : '']
        .filter(Boolean).join(' · ')
      : state;
    return fmt
      .replace(/\{mission\}/g, r.mission_name || 'משימה')
      .replace(/\{time\}/g, hhmm(r.at))
      .replace(/\{who\}/g, r.who || 'ללא שם')
      .replace(/\{state\}/g, detail);
  };
  return rows.map(line).join(' | ');
}

/* One line per report that has come in since the last run.

   Batched on purpose. One message per report means a shift with four missions
   produces four notifications inside a minute, and WhatsApp's per-recipient
   limits are precisely what swallowed the first version of this feature. One
   message every quarter of an hour, listing what arrived, says the same thing
   and survives the trip.

   Nothing is claimed before the send: the rows are marked only once the
   message has actually gone, so a failure leaves them to be picked up next
   time rather than silently swallowing a shift's worth of reports. */
export async function runDigest(env, now = Date.now()) {
  const db = env.DB;
  const to = String(env.SUPERVISOR_TO || '')
    .split(/[\s,]+/).map((n) => n.replace(/\D/g, ''))
    .filter((n) => n.length >= 9 && n.length <= 15);
  if (!to.length) return { told: 0, why: 'no supervisor configured' };
  if (!env.WHATSAPP_ACCESS_TOKEN || !env.WHATSAPP_PHONE_NUMBER_ID) {
    return { told: 0, why: 'no token configured' };
  }

  const { results } = await db
    .prepare('SELECT rowid AS rid, mission_name, who, short, partial, items, at '
      + 'FROM shift_beats WHERE notified = 0 ORDER BY at LIMIT 20')
    .all()
    .catch(() => ({ results: [] }));
  const rows = results || [];
  if (!rows.length) return { told: 0 };

  /* Spelled out, three reports no longer fit in one parameter, so the batch
     is split at the limit rather than truncated. Truncating would drop the
     last shift silently, which is the one failure this feature exists to
     prevent. */
  const batches = [];
  let cur = [];
  for (const r of rows) {
    const next = [...cur, r];
    if (cur.length && digestText(next, env).length > 850) { batches.push(cur); cur = [r]; }
    else cur = next;
  }
  if (cur.length) batches.push(cur);


  let told = 0;
  for (const batch of batches) {
    let delivered = 0;
    for (const n of to) {
      try {
        await send(env, n, digestText(batch, env));
        delivered += 1;
      } catch (e) {
        console.log(`digest.send.fail: ${e.message}`);
      }
    }
    // Marked only once it has actually gone. A failure leaves the rows for the
    // next run rather than swallowing a shift's worth of reports.
    if (!delivered) break;
    for (const r of batch) {
      await db.prepare('UPDATE shift_beats SET notified = 1 WHERE rowid = ?1')
        .bind(r.rid).run().catch(() => {});
    }
    told += batch.length;
  }
  return told ? { told } : { told: 0, why: 'send failed' };
}

export async function runWatch(env, now = Date.now()) {
  const db = env.DB;
  const to = recipients(env);
  const grace = (Number(env.ALERT_GRACE_MIN) || 30) * MIN;
  const window = (Number(env.ALERT_WINDOW_HOURS) || 6) * 60 * MIN;
  // A report filed just before the handover counts for it — the commander who
  // signed off at 04:52 for the 05:00 did the thing being checked.
  const early = (Number(env.ALERT_EARLY_MIN) || 60) * MIN;

  const sent = [];
  /* Nothing is looked at, and nothing is claimed, until there is something to
     send with. A missing token is not one failed message — it is every message
     from now on, and the slot-claiming below would quietly mark each handover
     as dealt with on the way past. A watcher that cannot speak must stay
     silent about its slots too, so that fixing the token fixes the alerts. */
  if (!to.length) return { sent, why: 'no recipients configured' };
  if (!env.WHATSAPP_ACCESS_TOKEN) return { sent, why: 'no token configured' };
  if (!env.WHATSAPP_PHONE_NUMBER_ID) return { sent, why: 'no phone number id configured' };

  const { results } = await db
    .prepare("SELECT id, label, data FROM pub_pick WHERE kind = 'mission'")
    .all()
    .catch(() => ({ results: [] }));

  for (const m of results || []) {
    const times = timesOf(m.data);
    const slots = overdueSlots(times, now, grace, window);
    for (const slot of slots) {
      const already = await db
        .prepare('SELECT slot FROM shift_alerts WHERE mission_id = ?1 AND slot = ?2')
        .bind(m.id, slot).first();
      if (already) continue;

      /* Bounded at both ends. `<= now` let a beat from this evening answer for
         a handover at dawn, so one report a day silenced every alert. */
      const beat = await db
        .prepare('SELECT at FROM shift_beats WHERE mission_id = ?1 AND at >= ?2 AND at < ?3 LIMIT 1')
        .bind(m.id, slot - early, slotEnd(times, slot)).first();
      if (beat) continue;

      /* Claimed before it is sent, not after. Two overlapping runs would
         otherwise both find nothing recorded and both send, and the primary
         key is the only thing that can settle that. A send that then fails
         costs one missed alert; claiming afterwards costs a duplicate every
         quarter of an hour, and this number belongs to somebody asleep. */
      const claim = await db
        .prepare('INSERT OR IGNORE INTO shift_alerts (mission_id, slot, at) VALUES (?1, ?2, ?3)')
        .bind(m.id, slot, now).run();
      if (!claim.meta || !claim.meta.changes) continue;

      let delivered = 0;
      for (const n of to) {
        try {
          await send(env, n, alertText(env, m.label, hhmm(slot)));
          delivered += 1;
          sent.push({ mission: m.label, slot: hhmm(slot) });
        } catch (e) {
          console.log(`watch.send.fail ${m.id} ${slot}: ${e.message}`);
        }
      }
      /* Reached nobody: give the slot back so the next run tries again.
         Reaching one of two is not a retry — resending to the one who already
         has it is how an alert becomes noise — so the claim only lifts when
         the message went nowhere at all. */
      if (!delivered) {
        await db.prepare('DELETE FROM shift_alerts WHERE mission_id = ?1 AND slot = ?2')
          .bind(m.id, slot).run().catch(() => {});
      }
    }
  }
  return { sent };
}

export default {
  async scheduled(event, env, ctx) {
    // Two independent jobs on one clock: what never arrived, and what did.
    // Either may be switched off by leaving its recipient unset, and one
    // failing must not stop the other.
    ctx.waitUntil(Promise.allSettled([
      runWatch(env).catch((e) => console.log(`watch.fail: ${e.message}`)),
      runDigest(env).catch((e) => console.log(`digest.fail: ${e.message}`)),
    ]));
  },

  /* A way to see what it would do, without waiting for a handover to pass.
     Guarded by a secret rather than left open: it reads the schedule and it
     can send, and neither belongs to whoever finds the URL. */
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname !== '/run' || !env.WATCH_KEY ||
        request.headers.get('x-watch-key') !== env.WATCH_KEY) {
      return new Response('not found', { status: 404 });
    }
    const out = { watch: await runWatch(env), digest: await runDigest(env) };
    return Response.json(out);
  },
};
