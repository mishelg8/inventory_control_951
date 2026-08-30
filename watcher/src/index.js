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

const TZ = 'Asia/Jerusalem';

const FMT = new Intl.DateTimeFormat('en-US', {
  timeZone: TZ, hour12: false,
  year: 'numeric', month: '2-digit', day: '2-digit',
  hour: '2-digit', minute: '2-digit', second: '2-digit',
});

const MIN = 60 * 1000;
const DAY = 24 * 60 * MIN;

/* Israel's clock at a given instant.
   The alternative was to write the handovers into the cron expression as UTC
   hours, which is correct for seven months of the year and an hour wrong for
   the other five — silently, and in the direction nobody checks. */
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
   inside the hour a spring-forward skips — which is 02:00 to 03:00, and not
   an hour anybody schedules a handover in. */
function instantOf(y, mo, d, h, mi) {
  const naive = Date.UTC(y, mo - 1, d, h, mi, 0);
  const once = naive - offsetAt(naive);
  return naive - offsetAt(once);
}

/* Which handovers are now overdue.

   A handover is due at its time and overdue `grace` later. Anything older
   than `window` is left alone: a watcher that was down for a day should
   report this morning's silence, not last week's, and a burst of stale alarms
   is how somebody decides to mute the number. */
export function overdueSlots(times, now, grace, window) {
  const out = new Set();
  for (const t of times) {
    const m = /^(\d{1,2}):(\d{2})$/.exec(String(t || '').trim());
    if (!m) continue;
    const h = +m[1];
    const mi = +m[2];
    if (h > 23 || mi > 59) continue;
    // Today and yesterday, because at 00:30 the 23:00 handover is yesterday's
    // and is exactly the one worth shouting about.
    for (const back of [0, 1]) {
      const w = wall(now - back * DAY);
      const slot = instantOf(w.y, w.mo, w.d, h, mi);
      const age = now - slot;
      if (age >= grace && age < window) out.add(slot);
    }
  }
  return [...out].sort((a, b) => a - b);
}

// The handover as a person would say it.
const hhmm = (ms) => {
  const w = wall(ms);
  return `${String(w.h).padStart(2, '0')}:${String(w.mi).padStart(2, '0')}`;
};

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
      name: env.WA_TPL_UPDATE || 'tzayad_update',
      language: { code: env.WA_TPL_LANG || 'he' },
      components: [{
        type: 'body',
        parameters: [
          { type: 'text', text: 'מפקד' },
          { type: 'text', text: `לא התקבל דוח משמרת מ${mission} לחילופים של ${at}` },
        ],
      }],
    },
  };
  const res = await fetch(url, {
    method: 'POST',
    // The token travels in a header. It has never been in a URL and must not
    // start now: URLs are logged, by us and by everyone in between.
    headers: {
      Authorization: `Bearer ${env.WHATSAPP_TOKEN}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    // Never the token, never the recipient in full — this goes to a log.
    throw new Error(`graph ${res.status}: ${text.slice(0, 300)}`);
  }
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
  if (!to.length) return { sent, why: 'no recipients configured' };

  const { results } = await db
    .prepare("SELECT id, label, data FROM pub_pick WHERE kind = 'mission'")
    .all()
    .catch(() => ({ results: [] }));

  for (const m of results || []) {
    const slots = overdueSlots(timesOf(m.data), now, grace, window);
    for (const slot of slots) {
      const already = await db
        .prepare('SELECT slot FROM shift_alerts WHERE mission_id = ?1 AND slot = ?2')
        .bind(m.id, slot).first();
      if (already) continue;

      const beat = await db
        .prepare('SELECT at FROM shift_beats WHERE mission_id = ?1 AND at >= ?2 AND at <= ?3 LIMIT 1')
        .bind(m.id, slot - early, now).first();
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

      for (const n of to) {
        try {
          await send(env, n, m.label, hhmm(slot));
          sent.push({ mission: m.label, slot: hhmm(slot) });
        } catch (e) {
          console.log(`watch.send.fail ${m.id} ${slot}: ${e.message}`);
        }
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
