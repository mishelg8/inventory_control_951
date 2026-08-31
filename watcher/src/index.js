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
async function send(env, to, mission, at) {
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
      components: [{
        type: 'body',
        parameters: [
          { type: 'text', text: 'מפקד' },
          { type: 'text', text: alertText(env, mission, at) },
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
          await send(env, n, m.label, hhmm(slot));
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
    ctx.waitUntil(runWatch(env).catch((e) => console.log(`watch.fail: ${e.message}`)));
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
    const out = await runWatch(env);
    return Response.json(out);
  },
};
