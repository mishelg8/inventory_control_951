// WhatsApp restricted the unit's number once, for approving twenty rows at
// once and firing twenty first-contact messages inside a few seconds. These
// tests cover the two things that stop it happening again: the server's floor
// on how fast the line may send, and the client queue that spaces the
// messages out behind an approval that has already finished.
//
// Both are exercised against the real source — the Worker's own onRequest
// over an in-memory SQLite standing in for D1, and the queue block lifted out
// of app.js — because the failure being guarded against is not a wrong
// return value, it is a burst.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel) => readFileSync(join(root, rel), 'utf8');

/* ── The server's floor ───────────────────────────────────────────── */

// schema.sql and the migrations, into memory. Comments are stripped first:
// splitting on ';' would otherwise cut a comment in half and leave its tail
// looking like SQL.
function freshDb() {
  const sq = new DatabaseSync(':memory:');
  const run = (text) => {
    const bare = text.split('\n').filter((l) => !l.trim().startsWith('--')).join('\n');
    for (const stmt of bare.split(';')) {
      if (!stmt.trim()) continue;
      try { sq.exec(stmt + ';'); } catch { /* a migration already folded into schema.sql */ }
    }
  };
  run(read('schema.sql'));
  for (const f of readdirSync(join(root, 'migrations')).sort().filter((n) => n.endsWith('.sql'))) {
    run(read(join('migrations', f)));
  }
  return sq;
}

// The narrow slice of D1 the Worker actually uses.
function d1(sq) {
  const prepare = (sql) => ({
    args: [],
    bind(...a) { this.args = a; return this; },
    async first() { const r = sq.prepare(sql).get(...this.args); return r === undefined ? null : r; },
    async run() { sq.prepare(sql).run(...this.args); return { success: true }; },
    async all() { return { results: sq.prepare(sql).all(...this.args) }; },
  });
  return { prepare, async batch(list) { for (const s of list) await s.run(); return []; } };
}

const TOKEN = 'a'.repeat(64);

async function waHarness({ hourMax = 3, dayMax = 5, state = 'authorized' } = {}) {
  const { onRequest } = await import(join(root, 'functions/api/[[path]].js'));
  const sq = freshDb();
  sq.prepare('INSERT INTO sessions (token, expires, role, username, tabs) VALUES (?,?,?,?,?)')
    .run(TOKEN, Date.now() + 3600000, 'admin', 'admin.951', '*');

  const provider = [];
  globalThis.fetch = async (u) => {
    provider.push(String(u));
    const body = String(u).includes('getStateInstance') ? { stateInstance: state }
      : String(u).includes('getWaSettings') ? { suspendedUntil: Math.floor(Date.now() / 1000) + 21600 }
        : { idMessage: 'X' };
    return new Response(JSON.stringify(body), { status: 200 });
  };

  const env = {
    DB: d1(sq), GREEN_API_URL: 'https://x.example', GREEN_ID: '1', GREEN_TOKEN: 't',
    WA_GAP_MS: '15000', WA_HOUR_MAX: String(hourMax), WA_DAY_MAX: String(dayMax),
  };
  const hit = (path, method = 'GET', body) => onRequest({
    env,
    params: { path: path.split('/') },
    request: new Request('https://tzayad.pages.dev/api/' + path, {
      method,
      headers: { Cookie: 'sid=' + TOKEN, ...(body ? { 'Content-Type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    }),
  });
  return {
    provider,
    send: () => hit('admin/wa/send', 'POST', { phone: '0501234567', message: 'בדיקה' }),
    status: () => hit('admin/wa/status'),
    // The gap is real time; the tests move the clock rather than wait on it.
    lapse: () => sq.prepare("UPDATE throttle SET until = ? WHERE k = 'wa:gap'").run(Date.now() - 1),
  };
}

test('two messages cannot leave inside the same gap', async () => {
  const wa = await waHarness();
  assert.equal((await wa.send()).status, 200);
  const r = await wa.send();
  const j = await r.json();
  assert.equal(r.status, 429);
  assert.equal(j.paced, 'gap');
  // the answer says how long, so the caller can wait instead of hammering
  assert.ok(j.waitMs > 10000, `waitMs ${j.waitMs}`);
});

test('the hourly ceiling holds, and holds in the database', async () => {
  const wa = await waHarness({ hourMax: 3 });
  for (let i = 0; i < 3; i++) { wa.lapse(); assert.equal((await wa.send()).status, 200, `send ${i + 1}`); }
  wa.lapse();
  const r = await wa.send();
  assert.equal(r.status, 429);
  assert.equal((await r.json()).paced, 'hour');
});

test('a refusal never reaches the provider', async () => {
  const wa = await waHarness({ dayMax: 1 });
  await wa.send();
  const before = wa.provider.length;
  wa.lapse();
  const r = await wa.send();
  assert.equal(r.status, 429);
  assert.equal((await r.json()).paced, 'day');
  assert.equal(wa.provider.length, before, 'the provider was called on a refused send');
});

test('the console can see what is left of the hour and the day', async () => {
  const wa = await waHarness({ hourMax: 40, dayMax: 150 });
  await wa.send();
  const b = (await (await wa.status()).json()).budget;
  assert.deepEqual(
    { gapMs: b.gapMs, hourMax: b.hourMax, dayMax: b.dayMax, hour: b.hour, day: b.day },
    { gapMs: 15000, hourMax: 40, dayMax: 150, hour: 1, day: 1 }
  );
});

test("a suspended number reports when the restriction lifts, in milliseconds", async () => {
  const wa = await waHarness({ state: 'suspended' });
  const j = await (await wa.status()).json();
  assert.equal(j.state, 'suspended');
  const hours = (j.suspendedUntil - Date.now()) / 3600000;
  // the provider counts in unix seconds; everything on this side is in ms
  assert.ok(hours > 5.9 && hours < 6.1, `${hours} hours`);
});

/* ── The client's queue ───────────────────────────────────────────── */

// Lifted whole out of app.js, with everything it leans on passed in. The lead
// before the first message is shortened so the suite does not sit through it;
// nothing else about the block is altered.
function liftQueue(deps) {
  const src = read('public/app.js');
  const from = src.indexOf('const WQ = { jobs: []');
  const to = src.indexOf('/* What to add to the toast an approval already shows.');
  assert.ok(from > 0 && to > from, 'the queue block moved');
  const block = src.slice(from, to).replace('const WQ_LEAD = 2000;', 'const WQ_LEAD = 60;');
  const names = Object.keys(deps);
  return new Function(...names, `${block}\nreturn { waEnqueue, WQ };`)(...names.map((n) => deps[n]));
}

function queueHarness(plan, gapMs = 120) {
  const marks = [];
  const sends = [];
  const $toast = { hidden: true, textContent: '' };
  const deps = {
    S: { wa: { budget: { gapMs } } },
    $toast,
    toast: (m) => { $toast.hidden = false; $toast.textContent = m; },
    api: async () => {
      const step = plan.shift();
      sends.push(Date.now());
      if (step === 'gap') { const e = new Error('paced'); e.data = { paced: 'gap', waitMs: 80 }; throw e; }
      if (step === 'day') { const e = new Error('תקרה יומית'); e.data = { paced: 'day', waitMs: 1000 }; throw e; }
      if (step === 'fail') throw new Error('נפל');
      return { ok: true };
    },
    markSent: (rid) => marks.push(rid),
    renderConsole: () => {},
    waDur: (ms) => `${Math.round(ms / 1000)} שניות`,
  };
  const { waEnqueue, WQ } = liftQueue(deps);
  const jobs = (n) => Array.from({ length: n }, (_, i) => ({ rid: 'r' + i, kind: 'notified', phone: '05' + i, message: 'm' }));
  const idle = () => new Promise((r) => {
    const t = setInterval(() => { if (!WQ.running) { clearInterval(t); r(); } }, 20);
  });
  return { marks, sends, $toast, WQ, waEnqueue, jobs, idle };
}

test('queued messages leave one at a time, not all at once', async () => {
  const h = queueHarness(['ok', 'ok', 'ok'], 120);
  h.waEnqueue(h.jobs(3));
  await h.idle();
  assert.equal(h.sends.length, 3);
  const gaps = h.sends.slice(1).map((t, i) => t - h.sends[i]);
  for (const g of gaps) assert.ok(g >= 110, `two messages left ${g}ms apart`);
  assert.equal(h.marks.length, 3, 'every one marked as sent');
  assert.match(h.$toast.textContent, /3 מתוך 3/);
});

test('a slot taken by somebody else is waited out, not skipped', async () => {
  const h = queueHarness(['gap', 'ok', 'ok']);
  h.waEnqueue(h.jobs(2));
  await h.idle();
  assert.equal(h.sends.length, 3, 'the refused one was retried');
  assert.equal(h.marks.length, 2, 'both messages still went');
});

test('a ceiling stops the run and says how many are left to send by hand', async () => {
  const h = queueHarness(['ok', 'day', 'ok', 'ok']);
  h.waEnqueue(h.jobs(4));
  await h.idle();
  assert.match(h.$toast.textContent, /1 מתוך 4/);
  assert.match(h.$toast.textContent, /2 נשארו/);
});

test('one number that fails does not take the rest of the queue with it', async () => {
  const h = queueHarness(['ok', 'fail', 'ok']);
  h.waEnqueue(h.jobs(3));
  await h.idle();
  assert.equal(h.marks.length, 2);
  assert.match(h.$toast.textContent, /2 מתוך 3/);
});

test('the queue yields the toast to a line somebody else put there', async () => {
  const h = queueHarness(['ok', 'ok', 'ok'], 600);
  h.waEnqueue(h.jobs(3));
  await new Promise((r) => setTimeout(r, 300));       // the first has left; the wait is on
  h.$toast.hidden = false;
  h.$toast.textContent = 'הרשומה נמחקה';
  await new Promise((r) => setTimeout(r, 250));       // the queue ticks twice in here
  assert.equal(h.$toast.textContent, 'הרשומה נמחקה');
  await h.idle();
  assert.match(h.$toast.textContent, /3 מתוך 3/, 'its own summary still lands at the end');
});
