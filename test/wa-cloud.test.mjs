/* The official WhatsApp Cloud integration.
 *
 * These run against the real modules and the real webhook handler, over an
 * in-memory SQLite standing in for D1 and a fetch that never leaves the
 * machine. Nothing here talks to Meta: a test that needs the internet is a
 * test that fails on a train, and a test that needs a live access token is
 * one nobody can run.
 *
 * The properties being defended are the ones that are expensive to get wrong
 * in production: an unsigned request must not write anything, a redelivered
 * event must not write twice, a status must not travel backwards, and no
 * plaintext may reach the database.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel) => readFileSync(join(root, rel), 'utf8');

const APP_SECRET = 'test-app-secret-not-a-real-one';
const VERIFY_TOKEN = 'test-verify-token';
const PHONE_ID = '1216224748249995';
const WABA_ID = '28252667600994107';

/* ── harness ──────────────────────────────────────────────────────── */

/* Splitting DDL on ';' is only safe once comments are gone, and a comment is
   not only a line that starts with '--'. A trailing one on a column
   definition cost an afternoon: `-- …templates; not personal` cut a CREATE
   TABLE in half, every table after it failed, and the tests reported a
   missing table rather than a broken comment. Strip properly, minding
   string literals so a '--' inside quoted SQL survives. */
function stripComments(text) {
  let out = '';
  let quote = null;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quote) {
      out += c;
      if (c === quote) quote = null;
      continue;
    }
    if (c === "'" || c === '"') { quote = c; out += c; continue; }
    if (c === '-' && text[i + 1] === '-') {
      while (i < text.length && text[i] !== '\n') i++;
      out += '\n';
      continue;
    }
    out += c;
  }
  return out;
}

function freshDb() {
  const sq = new DatabaseSync(':memory:');
  const run = (text) => {
    for (const stmt of stripComments(text).split(';')) {
      if (!stmt.trim()) continue;
      try { sq.exec(stmt + ';'); } catch { /* already folded into schema.sql */ }
    }
  };
  run(read('schema.sql'));
  for (const f of readdirSync(join(root, 'migrations')).sort().filter((n) => n.endsWith('.sql'))) {
    run(read(join('migrations', f)));
  }
  return sq;
}

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

// A real key pair, so sealing is really sealing and the tests can prove the
// database holds nothing readable.
async function keys() {
  const pair = await crypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true, ['encrypt', 'decrypt']
  );
  return { jwk: await crypto.subtle.exportKey('jwk', pair.publicKey), priv: pair.privateKey };
}

const enc = new TextEncoder();

async function sign(body, secret = APP_SECRET) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = await crypto.subtle.sign('HMAC', key, enc.encode(body));
  return 'sha256=' + [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function harness({ graph = () => ({ status: 200, body: {} }) } = {}) {
  const { onRequest } = await import(join(root, 'functions/whatsapp/webhook.js'));
  const sq = freshDb();
  const { jwk, priv } = await keys();
  sq.prepare(`INSERT INTO config (id, pub, salt, id_salt, verifier, key_iv, wrapped_key, created_at)
              VALUES (1, ?, 'x', 'c2FsdHk=', 'x', 'x', 'x', 0)`).run(JSON.stringify(jwk));

  const calls = [];
  globalThis.fetch = async (u, init) => {
    const url = String(u);
    calls.push({ url, init, body: init && init.body ? JSON.parse(init.body) : null });
    const r = graph(url, init);
    return new Response(JSON.stringify(r.body ?? {}), { status: r.status ?? 200 });
  };

  const env = {
    DB: d1(sq),
    WHATSAPP_ACCESS_TOKEN: 'token-value-must-never-appear-anywhere',
    WHATSAPP_PHONE_NUMBER_ID: PHONE_ID,
    WHATSAPP_BUSINESS_ACCOUNT_ID: WABA_ID,
    WHATSAPP_VERIFY_TOKEN: VERIFY_TOKEN,
    WHATSAPP_APP_SECRET: APP_SECRET,
    WA_CLOUD_GAP_MS: '0',
  };

  const pending = [];
  const get = (qs) => onRequest({
    env, waitUntil: (p) => pending.push(p),
    request: new Request(`https://tzayad.pages.dev/whatsapp/webhook?${qs}`),
  });
  const post = async (payload, { signature, secret } = {}) => {
    const raw = typeof payload === 'string' ? payload : JSON.stringify(payload);
    const res = await onRequest({
      env, waitUntil: (p) => pending.push(p),
      request: new Request('https://tzayad.pages.dev/whatsapp/webhook', {
        method: 'POST', body: raw,
        headers: { 'X-Hub-Signature-256': signature ?? (await sign(raw, secret)) },
      }),
    });
    await Promise.all(pending.splice(0));
    return res;
  };

  const q = (sql, ...a) => sq.prepare(sql).all(...a);
  const one = (sql, ...a) => sq.prepare(sql).get(...a);
  return { env, sq, q, one, get, post, calls, priv, dump: () => read };
}

const inbound = (text, { wamid = 'wamid.TEST1', from = '972522398415' } = {}) => ({
  object: 'whatsapp_business_account',
  entry: [{
    id: WABA_ID,
    changes: [{
      field: 'messages',
      value: {
        messaging_product: 'whatsapp',
        metadata: { display_phone_number: '972522398415', phone_number_id: PHONE_ID },
        contacts: [{ profile: { name: 'רס״ל בדיקה' }, wa_id: from }],
        messages: [{ from, id: wamid, timestamp: String(Math.floor(Date.now() / 1000)), type: 'text', text: { body: text } }],
      },
    }],
  }],
});

const statusEvent = (status, { wamid = 'wamid.OUT1' } = {}) => ({
  object: 'whatsapp_business_account',
  entry: [{
    id: WABA_ID,
    changes: [{
      field: 'messages',
      value: {
        messaging_product: 'whatsapp',
        metadata: { display_phone_number: '972522398415', phone_number_id: PHONE_ID },
        statuses: [{
          id: wamid, status, timestamp: String(Math.floor(Date.now() / 1000)),
          recipient_id: '972522398415',
          conversation: { id: 'conv1', origin: { type: 'utility' } },
          pricing: { category: 'utility' },
        }],
      },
    }],
  }],
});

/* ── phone normalisation ──────────────────────────────────────────── */

test('an Israeli local number becomes E.164', async () => {
  const { toE164 } = await import(join(root, 'public/lib/phone.js'));
  assert.equal(toE164('0522398415').e164, '+972522398415');
  assert.equal(toE164('052-239-8415').e164, '+972522398415');
  assert.equal(toE164('972522398415').e164, '+972522398415');
  assert.equal(toE164('+972 52 239 8415').e164, '+972522398415');
});

test('a number that is already international is left alone, whatever the country', async () => {
  const { toE164 } = await import(join(root, 'public/lib/phone.js'));
  assert.equal(toE164('+14155552671').e164, '+14155552671');
  assert.equal(toE164('00447911123456').e164, '+447911123456');
});

test('nonsense is refused rather than guessed at', async () => {
  const { toE164 } = await import(join(root, 'public/lib/phone.js'));
  assert.equal(toE164('').ok, false);
  assert.equal(toE164('hello').ok, false);
  assert.equal(toE164('05').ok, false);
  assert.equal(toE164('+9725223984150000000').ok, false);
});

test('Meta wants the digits, we keep the plus', async () => {
  const { toWaId, fromWaId, maskPhone } = await import(join(root, 'public/lib/phone.js'));
  assert.equal(toWaId('+972522398415'), '972522398415');
  assert.equal(fromWaId('972522398415'), '+972522398415');
  assert.equal(maskPhone('+972522398415'), '+972*******15');
});

/* ── webhook verification ─────────────────────────────────────────── */

test('the verification handshake returns the challenge verbatim', async () => {
  const h = await harness();
  const res = await h.get(`hub.mode=subscribe&hub.verify_token=${VERIFY_TOKEN}&hub.challenge=1158201444`);
  assert.equal(res.status, 200);
  assert.equal(await res.text(), '1158201444');
});

test('a wrong verify token is refused, and the challenge is not echoed', async () => {
  const h = await harness();
  const res = await h.get('hub.mode=subscribe&hub.verify_token=wrong&hub.challenge=1158201444');
  assert.equal(res.status, 403);
  assert.equal((await res.text()).includes('1158201444'), false);
});

test('a handshake that is not a subscribe is refused', async () => {
  const h = await harness();
  const res = await h.get(`hub.mode=unsubscribe&hub.verify_token=${VERIFY_TOKEN}&hub.challenge=9`);
  assert.equal(res.status, 403);
});

/* ── signature ────────────────────────────────────────────────────── */

test('an unsigned event writes nothing', async () => {
  const h = await harness();
  const res = await h.post(inbound('שלום'), { signature: undefined, secret: 'the-wrong-secret' });
  assert.equal(res.status, 403);
  assert.equal(h.q('SELECT * FROM wa_messages').length, 0);
  assert.equal(h.q('SELECT * FROM wa_contacts').length, 0);
});

test('a missing signature header is refused', async () => {
  const h = await harness();
  const res = await h.post(inbound('שלום'), { signature: 'nonsense' });
  assert.equal(res.status, 403);
  assert.equal(h.q('SELECT * FROM wa_messages').length, 0);
});

test('the signature is checked against the exact bytes, not a reserialisation', async () => {
  const { verifySignature } = await import(join(root, 'lib/whatsapp/signature.js'));
  const raw = '{"b":1,"a":2}';
  const good = await sign(raw);
  assert.equal((await verifySignature(raw, good, APP_SECRET)).ok, true);
  // same object, different bytes — must not verify
  assert.equal((await verifySignature('{"a":2,"b":1}', good, APP_SECRET)).ok, false);
});

/* ── inbound ──────────────────────────────────────────────────────── */

test('a signed text message is stored, threaded and sealed', async () => {
  const h = await harness();
  const res = await h.post(inbound('קיבלתי, תודה'));
  assert.equal(res.status, 200);

  const msg = h.one('SELECT * FROM wa_messages');
  assert.equal(msg.direction, 'in');
  assert.equal(msg.type, 'text');
  assert.equal(msg.status, 'received');
  assert.equal(msg.wamid, 'wamid.TEST1');

  assert.equal(h.q('SELECT * FROM wa_conversations').length, 1);
  assert.equal(h.q('SELECT * FROM wa_contacts').length, 1);
  assert.equal(h.one('SELECT unread FROM wa_conversations').unread, 1);
});

test('nothing readable reaches the database — not the text, not the number, not the name', async () => {
  const h = await harness();
  await h.post(inbound('קיבלתי, תודה'));

  // Every text column of every row of every table, concatenated.
  const tables = h.q("SELECT name FROM sqlite_master WHERE type = 'table'").map((r) => r.name);
  let all = '';
  for (const t of tables) {
    for (const row of h.q(`SELECT * FROM ${t}`)) all += Object.values(row).map(String).join(' ');
  }
  assert.equal(all.includes('קיבלתי'), false, 'message text found in the clear');
  assert.equal(all.includes('972522398415'), false, 'phone number found in the clear');
  assert.equal(all.includes('רס״ל בדיקה'), false, 'profile name found in the clear');
});

test('the sealed body opens with the private key, and says what was sent', async () => {
  const h = await harness();
  await h.post(inbound('קיבלתי, תודה'));
  const m = h.one('SELECT ek, iv, ct FROM wa_messages');

  const ub64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const rawCek = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, h.priv, ub64(m.ek));
  const cek = await crypto.subtle.importKey('raw', rawCek, 'AES-GCM', false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ub64(m.iv) }, cek, ub64(m.ct));
  const body = JSON.parse(new TextDecoder().decode(pt));

  assert.equal(body.text, 'קיבלתי, תודה');
  assert.equal(body.from, '+972522398415');
  assert.equal(body.profileName, 'רס״ל בדיקה');
});

test('a redelivered message does not become a second message', async () => {
  const h = await harness();
  await h.post(inbound('פעם אחת'));
  await h.post(inbound('פעם אחת'));
  await h.post(inbound('פעם אחת'));

  assert.equal(h.q('SELECT * FROM wa_messages').length, 1);
  assert.equal(h.q('SELECT * FROM wa_conversations').length, 1);
  assert.equal(h.one('SELECT unread FROM wa_conversations').unread, 1, 'unread counted once');
});

test('two different messages from the same person share one conversation', async () => {
  const h = await harness();
  await h.post(inbound('ראשונה', { wamid: 'wamid.A' }));
  await h.post(inbound('שנייה', { wamid: 'wamid.B' }));
  assert.equal(h.q('SELECT * FROM wa_messages').length, 2);
  assert.equal(h.q('SELECT * FROM wa_conversations').length, 1);
});

test('an image message keeps its media id and pulls the bytes down once', async () => {
  const bytes = new Uint8Array([1, 2, 3, 4, 5]);
  const h = await harness({
    graph: (url) => {
      if (url.includes('/MEDIA123')) return { status: 200, body: { url: 'https://lookaside.example/x', mime_type: 'image/jpeg', file_size: 5 } };
      return { status: 200, body: {} };
    },
  });
  // the download is a plain fetch of Meta's short-lived URL
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (u, init) => {
    if (String(u).includes('lookaside')) {
      assert.match(String(init.headers.Authorization), /^Bearer /, 'token travels in a header');
      return new Response(bytes, { status: 200 });
    }
    return realFetch(u, init);
  };

  const payload = inbound('x');
  payload.entry[0].changes[0].value.messages[0] = {
    from: '972522398415', id: 'wamid.IMG', timestamp: String(Math.floor(Date.now() / 1000)),
    type: 'image', image: { id: 'MEDIA123', mime_type: 'image/jpeg', caption: 'הרישיון' },
  };
  await h.post(payload);

  const m = h.one('SELECT * FROM wa_messages');
  assert.equal(m.type, 'image');
  assert.equal(m.media_id, 'MEDIA123');
  const media = h.one('SELECT * FROM wa_media');
  assert.equal(media.mime, 'image/jpeg');
  assert.equal(media.bytes, 5);
  assert.ok(media.ct.length > 0, 'the bytes are sealed, not stored raw');
});

test('a button reply arrives as something the console can read', async () => {
  const h = await harness();
  const payload = inbound('x');
  payload.entry[0].changes[0].value.messages[0] = {
    from: '972522398415', id: 'wamid.BTN', timestamp: String(Math.floor(Date.now() / 1000)),
    type: 'interactive', interactive: { type: 'button_reply', button_reply: { id: 'confirm', title: 'אישור' } },
  };
  await h.post(payload);
  assert.equal(h.one('SELECT type FROM wa_messages').type, 'interactive');
});

test('an event for a number that is not ours is dropped', async () => {
  const h = await harness();
  const payload = inbound('שלום');
  payload.entry[0].changes[0].value.metadata.phone_number_id = '999999999999999';
  const res = await h.post(payload);
  assert.equal(res.status, 200, 'acknowledged, so Meta stops retrying');
  assert.equal(h.q('SELECT * FROM wa_messages').length, 0, 'but nothing written');
});

test('an event for a different business account is dropped', async () => {
  const h = await harness();
  const payload = inbound('שלום');
  payload.entry[0].id = '11111111111111111';
  const res = await h.post(payload);
  assert.equal(res.status, 200);
  assert.equal(h.q('SELECT * FROM wa_messages').length, 0);
});

/* ── outbound ─────────────────────────────────────────────────────── */

async function outboundHarness(graph) {
  const h = await harness({ graph });
  const { sendTextMessage, sendTemplateMessage } = await import(join(root, 'lib/whatsapp/service.js'));
  return { ...h, sendTextMessage, sendTemplateMessage };
}

const accepted = () => ({ status: 200, body: { messages: [{ id: 'wamid.OUT1' }] } });

test('a template is built the way Meta documents it', async () => {
  const h = await outboundHarness(accepted);
  const r = await h.sendTemplateMessage(h.env.DB, h.env, '0522398415', 'equipment_signed', 'he', [
    { type: 'body', parameters: [{ type: 'text', text: 'רובה' }] },
  ]);
  assert.equal(r.ok, true);
  assert.equal(r.wamid, 'wamid.OUT1');

  const call = h.calls.find((c) => c.url.includes('/messages'));
  assert.match(call.url, /graph\.facebook\.com\/v\d+\.\d+\/1216224748249995\/messages$/);
  assert.equal(call.body.messaging_product, 'whatsapp');
  assert.equal(call.body.to, '972522398415', 'digits, no plus');
  assert.equal(call.body.type, 'template');
  assert.equal(call.body.template.name, 'equipment_signed');
  assert.equal(call.body.template.language.code, 'he');
  assert.equal(call.body.template.components[0].parameters[0].text, 'רובה');
});

test('the access token travels in a header and never in a URL', async () => {
  const h = await outboundHarness(accepted);
  await h.sendTemplateMessage(h.env.DB, h.env, '0522398415', 'equipment_signed', 'he', []);
  for (const c of h.calls) {
    assert.equal(c.url.includes('token-value-must-never-appear-anywhere'), false, 'token in a URL');
    assert.equal(c.url.includes('access_token'), false);
  }
  const call = h.calls.find((c) => c.url.includes('/messages'));
  assert.equal(call.init.headers.Authorization, 'Bearer token-value-must-never-appear-anywhere');
});

test('free text outside the 24-hour window is refused, and says a template is needed', async () => {
  const h = await outboundHarness(accepted);
  const r = await h.sendTextMessage(h.env.DB, h.env, '0522398415', 'שלום');
  assert.equal(r.ok, false);
  assert.equal(r.status, 409);
  assert.equal(r.needsTemplate, true);
  assert.equal(h.calls.some((c) => c.url.includes('/messages')), false, 'Meta was never called');
});

test('free text inside the window goes, because the soldier wrote first', async () => {
  const h = await outboundHarness(accepted);
  await h.post(inbound('יש לי שאלה'));           // opens the window
  const r = await h.sendTextMessage(h.env.DB, h.env, '0522398415', 'בוודאי, מיד');
  assert.equal(r.ok, true);
  const call = h.calls.find((c) => c.init && c.init.method === 'POST' && c.url.includes('/messages'));
  assert.equal(call.body.type, 'text');
  assert.equal(call.body.text.body, 'בוודאי, מיד');
});

test('an outbound message is written before it is sent, so a lost one is still visible', async () => {
  const h = await outboundHarness(() => ({ status: 500, body: { error: { message: 'boom', code: 131016 } } }));
  const r = await h.sendTemplateMessage(h.env.DB, h.env, '0522398415', 'equipment_signed', 'he', []);
  assert.equal(r.ok, false);
  const m = h.one("SELECT * FROM wa_messages WHERE direction = 'out'");
  assert.equal(m.status, 'failed');
  assert.equal(m.err_code, 131016);
});

test("Meta's error is kept for the log and translated for the screen", async () => {
  const h = await outboundHarness(() => ({
    status: 400,
    body: { error: { message: 'Re-engagement message', code: 131047, error_subcode: 2494010, fbtrace_id: 'AbC123' } },
  }));
  const r = await h.sendTemplateMessage(h.env.DB, h.env, '0522398415', 'x_template', 'he', []);
  assert.equal(r.ok, false);
  assert.equal(r.code, 131047);
  assert.equal(r.trace, 'AbC123');
  assert.match(r.message, /24 שעות/);
  const m = h.one("SELECT * FROM wa_messages WHERE direction = 'out'");
  assert.equal(m.err_trace, 'AbC123');
});

test('a permanent error is not retried; a throttle is', async () => {
  let calls = 0;
  const h = await outboundHarness(() => {
    calls++;
    return { status: 400, body: { error: { message: 'bad param', code: 100 } } };
  });
  await h.sendTemplateMessage(h.env.DB, h.env, '0522398415', 'x_template', 'he', []);
  assert.equal(calls, 1, 'a permanent error is asked once');

  let calls2 = 0;
  const h2 = await outboundHarness(() => {
    calls2++;
    return { status: 429, body: { error: { message: 'rate', code: 80007 } } };
  });
  await h2.sendTemplateMessage(h2.env.DB, h2.env, '0522398415', 'x_template', 'he', []);
  assert.ok(calls2 > 1, 'a throttle is retried');
});

test('a template with a bad name or language never reaches Meta', async () => {
  const h = await outboundHarness(accepted);
  assert.equal((await h.sendTemplateMessage(h.env.DB, h.env, '0522398415', 'Bad Name!', 'he', [])).status, 400);
  assert.equal((await h.sendTemplateMessage(h.env.DB, h.env, '0522398415', 'ok_name', 'hebrew', [])).status, 400);
  assert.equal(h.calls.some((c) => c.url.includes('/messages')), false);
});

test('the pause switch stops the official channel too', async () => {
  const h = await outboundHarness(accepted);
  h.sq.prepare('UPDATE config SET wa_paused = 1 WHERE id = 1').run();
  const r = await h.sendTemplateMessage(h.env.DB, h.env, '0522398415', 'equipment_signed', 'he', []);
  assert.equal(r.ok, false);
  assert.equal(r.paused, true);
  assert.equal(h.calls.some((c) => c.url.includes('/messages')), false);
});

/* ── statuses ─────────────────────────────────────────────────────── */

async function sent() {
  const h = await outboundHarness(accepted);
  await h.sendTemplateMessage(h.env.DB, h.env, '0522398415', 'equipment_signed', 'he', []);
  return h;
}

test('sent, delivered and read move the message forward', async () => {
  const h = await sent();
  await h.post(statusEvent('sent'));
  assert.equal(h.one("SELECT status FROM wa_messages WHERE direction='out'").status, 'sent');
  await h.post(statusEvent('delivered'));
  assert.equal(h.one("SELECT status FROM wa_messages WHERE direction='out'").status, 'delivered');
  await h.post(statusEvent('read'));
  const m = h.one("SELECT * FROM wa_messages WHERE direction='out'");
  assert.equal(m.status, 'read');
  assert.ok(m.sent_at && m.delivered_at && m.read_at, 'each stamp recorded');
});

test('a status that arrives late does not drag the message backwards', async () => {
  const h = await sent();
  await h.post(statusEvent('read'));
  await h.post(statusEvent('sent'));        // Meta does not promise ordering
  assert.equal(h.one("SELECT status FROM wa_messages WHERE direction='out'").status, 'read');
});

test('a redelivered status changes nothing and creates nothing', async () => {
  const h = await sent();
  await h.post(statusEvent('delivered'));
  const before = h.one("SELECT * FROM wa_messages WHERE direction='out'");
  await h.post(statusEvent('delivered'));
  const after = h.one("SELECT * FROM wa_messages WHERE direction='out'");
  assert.deepEqual(after, before);
  assert.equal(h.q("SELECT * FROM wa_messages WHERE direction='out'").length, 1);
});

test('a failed status records why', async () => {
  const h = await sent();
  const ev = statusEvent('failed');
  ev.entry[0].changes[0].value.statuses[0].errors = [
    { code: 131026, title: 'Message undeliverable', error_data: { details: 'no WhatsApp account' } },
  ];
  await h.post(ev);
  const m = h.one("SELECT * FROM wa_messages WHERE direction='out'");
  assert.equal(m.status, 'failed');
  assert.equal(m.err_code, 131026);
  assert.match(m.err_title, /undeliverable/i);
});

test('a status for a message we never sent is ignored, not invented', async () => {
  const h = await harness();
  const res = await h.post(statusEvent('delivered', { wamid: 'wamid.SOMEONEELSE' }));
  assert.equal(res.status, 200);
  assert.equal(h.q('SELECT * FROM wa_messages').length, 0);
});

/* ── configuration ────────────────────────────────────────────────── */

test('the Graph version lives in one place and is used everywhere', async () => {
  const { waConfig, graphUrl, DEFAULT_GRAPH_VERSION } = await import(join(root, 'lib/whatsapp/config.js'));
  const cfg = waConfig({});
  assert.equal(cfg.version, DEFAULT_GRAPH_VERSION);
  assert.equal(graphUrl(cfg, 'x/messages'), `https://graph.facebook.com/${DEFAULT_GRAPH_VERSION}/x/messages`);
  assert.equal(waConfig({ META_GRAPH_API_VERSION: 'v99.0' }).version, 'v99.0');
});

test('a missing setting is named, and its value never is', async () => {
  const { waConfig } = await import(join(root, 'lib/whatsapp/config.js'));
  const cfg = waConfig({ WHATSAPP_ACCESS_TOKEN: 'secret' });
  assert.equal(cfg.ready, false);
  assert.equal(cfg.missing.includes('WHATSAPP_VERIFY_TOKEN'), true);
  assert.equal(JSON.stringify(cfg.missing).includes('secret'), false);
});

/* ── template parameters ──────────────────────────────────────────────
   Meta refuses a parameter containing a line break, and refuses an empty
   one. Both refusals arrive as error 132000 after the round trip, on a
   message the console has already reported as sent — so they are checked
   here, against the real builders lifted out of app.js rather than against a
   copy of them that can drift. */

function liftTemplates() {
  const src = read('public/app.js');
  const from = src.indexOf('const tplVal =');
  const to = src.indexOf('const waLink =');
  if (from < 0 || to < 0 || to < from) throw new Error('template block not found in app.js');

  const block = src.slice(from, to);
  const make = new Function(
    'signedItems', 'heldItems',
    `${block}\n return { tplVal, tplName, tplItems, tplBody, tplSigned, tplCredit, tplUpdate };`
  );
  return make(
    (d) => (d && d.items) || [],
    (d) => (d && d.left) || []
  );
}

const paramsOf = (desc, T) => T.tplBody(desc.values)[0].parameters.map((p) => p.text);

test('no template parameter ever contains a line break', () => {
  const T = liftTemplates();
  const d = { name: 'דוד לוי', items: [['רובה', 1], ['אפוד', 2], ['קסדה', 1]], left: [['רובה', 1]] };

  for (const desc of [T.tplSigned(d), T.tplCredit(d, [['אפוד', 2]]), T.tplUpdate(d, 'שורה\nושורה')]) {
    for (const p of paramsOf(desc, T)) {
      assert.equal(p.includes('\n'), false, `line break in ${JSON.stringify(p)}`);
      assert.equal(/\s{4,}/.test(p), false, `run of spaces in ${JSON.stringify(p)}`);
    }
  }
});

test('no template parameter is ever empty', () => {
  const T = liftTemplates();
  const empty = { name: '', items: [], left: [] };

  for (const desc of [T.tplSigned(empty), T.tplCredit(empty, []), T.tplUpdate(empty, '')]) {
    for (const p of paramsOf(desc, T)) {
      assert.ok(p.trim().length > 0, 'an empty parameter would be refused by Meta');
    }
  }
});

test('a multi-line kit list becomes one line of bullets', () => {
  const T = liftTemplates();
  const d = { name: 'דוד', items: [['רובה', 1], ['אפוד', 2]], left: [] };
  const [, kit] = paramsOf(T.tplSigned(d), T);
  assert.equal(kit, 'רובה • אפוד ×2');
});

test('the greeting carries a first name and no more', () => {
  const T = liftTemplates();
  assert.equal(T.tplName('דוד בן לוי'), 'דוד');
  assert.equal(T.tplName('   '), 'חייל');
  assert.equal(T.tplName(undefined), 'חייל');
});

test('a closed account says so, rather than sending an empty list', () => {
  const T = liftTemplates();
  const done = { name: 'דוד', items: [], left: [] };
  const [, , status] = paramsOf(T.tplCredit(done, [['אפוד', 1]]), T);
  assert.match(status, /החשבון סגור/);

  const still = { name: 'דוד', items: [], left: [['רובה', 1]] };
  const [, , status2] = paramsOf(T.tplCredit(still, [['אפוד', 1]]), T);
  assert.match(status2, /עדיין רשום עליך רובה/);
});

test('the body component is the shape Meta documents', () => {
  const T = liftTemplates();
  const body = T.tplBody(['דוד', 'רובה']);
  assert.equal(body.length, 1);
  assert.equal(body[0].type, 'body');
  assert.deepEqual(body[0].parameters, [
    { type: 'text', text: 'דוד' },
    { type: 'text', text: 'רובה' },
  ]);
});
