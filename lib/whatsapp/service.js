/* The seam between WhatsApp and the rest of the application.
 *
 * Above this line: "notify this soldier". Below it: envelopes, wamids, the
 * 24-hour window, Meta's error codes. The console imports this module and
 * nothing deeper, which is what keeps the equipment system from growing an
 * opinion about `messaging_product`.
 *
 * Two rules are enforced here rather than left to Meta:
 *
 *   the pause switch  one flag stops every channel, official and otherwise.
 *                     It is checked before anything else, because the moment
 *                     somebody reaches for it is the moment they want the
 *                     sending to stop, not to be argued with.
 *
 *   the 24-hour rule  free text is only legal for 24 hours after the person
 *                     last wrote. Outside it Meta returns 131047 and charges
 *                     nothing, but the round trip reads like a fault and the
 *                     message is silently lost. We refuse first, and say
 *                     which template would work instead.
 */

import { waConfig } from './config.js';
import { waClient } from './client.js';
import { sealer, phoneTag } from './seal.js';
import { userMessage } from './errors.js';
import { waLog, logPhone } from './log.js';
import { toE164 } from '../../public/lib/phone.js';
import {
  claimEvent, sweepEvents, upsertContact, ensureConversation, insertInbound,
  insertOutbound, markAccepted, markFailed, applyStatus, saveMedia, hasMedia,
  getConversation, WINDOW_MS,
} from './store.js';

/* ── pacing ────────────────────────────────────────────────────────────
   The official API has Meta's own limits, which are generous and rise with
   quality. These are not those: they are a ceiling so that a loop in the
   console cannot spend a day's budget in a minute. Separate keys from the
   gateway's, because the two channels have nothing to do with each other. */
async function paceClaim(db, cfg, now) {
  const { gapMs, hourMax, dayMax } = cfg.pace;

  if (gapMs > 0) {
    const won = await db
      .prepare(
        `INSERT INTO throttle (k, hits, until) VALUES ('wac:gap', 1, ?1)
         ON CONFLICT(k) DO UPDATE SET until = ?1, hits = throttle.hits + 1
           WHERE throttle.until <= ?2
         RETURNING until`
      )
      .bind(now + gapMs, now)
      .first();
    if (!won) {
      const cur = await db.prepare("SELECT until FROM throttle WHERE k = 'wac:gap'").first();
      return { ok: false, why: 'gap', waitMs: Math.max(0, ((cur && cur.until) || now) - now) };
    }
  }

  const count = async (k) => {
    const r = await db.prepare('SELECT hits, until FROM throttle WHERE k = ?1').bind(k).first();
    return r && r.until > now ? r.hits : 0;
  };
  const bump = (k, windowMs) =>
    db
      .prepare(
        `INSERT INTO throttle (k, hits, until) VALUES (?1, 1, ?2)
         ON CONFLICT(k) DO UPDATE SET
           hits  = CASE WHEN throttle.until > ?3 THEN throttle.hits + 1 ELSE 1 END,
           until = CASE WHEN throttle.until > ?3 THEN throttle.until ELSE ?2 END`
      )
      .bind(k, now + windowMs, now)
      .run();

  const day = await count('wac:day');
  if (day >= cfg.pace.dayMax) return { ok: false, why: 'day', waitMs: 0 };
  const hour = await count('wac:hour');
  if (hour >= cfg.pace.hourMax) return { ok: false, why: 'hour', waitMs: 0 };

  await bump('wac:hour', 3600000);
  await bump('wac:day', 86400000);
  return { ok: true, hour: hour + 1, day: day + 1, hourMax, dayMax, gapMs };
}

const isPaused = async (db) => {
  const row = await db.prepare('SELECT wa_paused FROM config WHERE id = 1').first();
  return !!(row && row.wa_paused);
};

const idSaltOf = async (db) => {
  const row = await db.prepare('SELECT id_salt FROM config WHERE id = 1').first();
  return (row && row.id_salt) || '';
};

/** Everything the console needs to build a request, gathered once. */
export async function waCloudContext(db, env) {
  const cfg = waConfig(env);
  return { cfg, client: cfg.ready ? waClient(cfg) : null, paused: await isPaused(db) };
}

/* ── outbound ─────────────────────────────────────────────────────────── */

async function prepare(db, env, to) {
  const cfg = waConfig(env);
  if (!cfg.ready) return { error: { status: 503, message: 'שירות הוואטסאפ הרשמי אינו מוגדר', missing: cfg.missing } };
  if (await isPaused(db)) {
    return { error: { status: 503, message: 'שליחת הוואטסאפ מושהית. בטלו את ההשהיה במסך וואטסאפ', paused: true } };
  }

  const norm = toE164(to, cfg.region);
  if (!norm.ok) return { error: { status: 400, message: 'מספר טלפון לא תקין' } };

  const seal = await sealer(db);
  if (!seal) return { error: { status: 503, message: 'המערכת אינה מאותחלת' } };

  const tag = await phoneTag(norm.e164, await idSaltOf(db));
  const conv = await ensureConversation(db, tag, cfg.phoneNumberId, Date.now());
  return { cfg, seal, tag, conv, e164: norm.e164, client: waClient(cfg) };
}

async function deliver(db, ctx, msgId, attempt) {
  const now = Date.now();
  const r = await attempt();
  if (!r.ok) {
    await markFailed(db, msgId, r.err, now);
    return {
      ok: false,
      status: 502,
      id: msgId,
      message: userMessage(r.err),
      code: r.err && r.err.code,
      trace: r.err && r.err.trace,
    };
  }
  await markAccepted(db, msgId, r.wamid, now);
  return { ok: true, id: msgId, wamid: r.wamid, conv: ctx.conv };
}

/**
 * Free text. Legal only inside the service window.
 *
 * `allowOutsideWindow` exists for one caller: the console's own diagnostic
 * send, where the operator is deliberately testing the pipe and would rather
 * see Meta's refusal than ours. It does not bypass anything at Meta.
 */
export async function sendTextMessage(db, env, to, text, opts = {}) {
  const ctx = await prepare(db, env, to);
  if (ctx.error) return { ok: false, ...ctx.error };

  const body = String(text == null ? '' : text);
  if (!body.trim()) return { ok: false, status: 400, message: 'הודעה ריקה' };
  if (body.length > ctx.cfg.maxTextLen) return { ok: false, status: 400, message: 'ההודעה ארוכה מדי' };

  const conv = await getConversation(db, ctx.conv);
  const open = conv && conv.window_expires > Date.now();
  if (!open && !opts.allowOutsideWindow) {
    return {
      ok: false,
      status: 409,
      needsTemplate: true,
      message: 'חלון 24 השעות סגור — לנמען הזה מותר לשלוח רק תבנית מאושרת',
    };
  }

  const pace = await paceClaim(db, ctx.cfg, Date.now());
  if (!pace.ok) return { ok: false, status: 429, paced: pace.why, waitMs: pace.waitMs, message: 'הקו בקצב מלא, נסו בעוד רגע' };

  const msgId = await insertOutbound(db, ctx.seal, ctx.conv, {
    type: 'text', body: { text: body, to: ctx.e164 },
  }, Date.now());

  waLog.info('outbound.queued', { to: logPhone(ctx.e164), type: 'text', id: msgId });
  return deliver(db, ctx, msgId, () => ctx.client.sendText(ctx.e164, body, { context: opts.replyTo }));
}

/**
 * An approved template. The only legal way to start a conversation, and the
 * only thing this application actually needs day to day: a soldier has not
 * written first, so every notification it sends is business-initiated.
 */
export async function sendTemplateMessage(db, env, to, templateName, languageCode, components, opts = {}) {
  const ctx = await prepare(db, env, to);
  if (ctx.error) return { ok: false, ...ctx.error };

  const name = String(templateName || '').trim();
  if (!/^[a-z0-9_]{1,512}$/.test(name)) return { ok: false, status: 400, message: 'שם תבנית לא תקין' };
  const lang = String(languageCode || '').trim();
  if (!/^[A-Za-z]{2}(_[A-Za-z]{2})?$/.test(lang)) return { ok: false, status: 400, message: 'קוד שפה לא תקין' };
  if (components != null && !Array.isArray(components)) return { ok: false, status: 400, message: 'רכיבי התבנית אינם תקינים' };

  const pace = await paceClaim(db, ctx.cfg, Date.now());
  if (!pace.ok) return { ok: false, status: 429, paced: pace.why, waitMs: pace.waitMs, message: 'הקו בקצב מלא, נסו בעוד רגע' };

  const msgId = await insertOutbound(db, ctx.seal, ctx.conv, {
    type: 'template',
    template: name,
    body: { templateName: name, language: lang, components: components || [], to: ctx.e164 },
  }, Date.now());

  waLog.info('outbound.queued', { to: logPhone(ctx.e164), type: 'template', template: name, id: msgId });
  return deliver(db, ctx, msgId, () =>
    ctx.client.sendTemplate(ctx.e164, name, lang, components || [], { context: opts.replyTo }));
}

/* ── inbound ──────────────────────────────────────────────────────────── */

/**
 * Apply a normalised webhook. Called from waitUntil, after the 200 has
 * already gone back to Meta — so every failure in here is logged and
 * swallowed. There is nobody left to return an error to, and throwing would
 * only lose the events that came in the same batch.
 */
export async function processWebhook(db, env, normalized, now = Date.now()) {
  const cfg = waConfig(env);
  const seal = await sealer(db);
  if (!seal) {
    waLog.error('inbound.no-key', { note: 'system not initialised; nothing can be sealed' });
    return { messages: 0, statuses: 0, skipped: 0 };
  }

  const idSalt = await idSaltOf(db);
  const client = cfg.ready ? waClient(cfg) : null;
  let messages = 0;
  let statuses = 0;
  let skipped = 0;

  for (const batch of normalized.batches) {
    /* An event for a number that is not ours is not ours to store. This is
       the check that makes "do not use the other WhatsApp account" true in
       code rather than in a note: a second WABA pointed at the same webhook
       is dropped here, loudly. */
    if (cfg.phoneNumberId && batch.meta.phoneNumberId !== cfg.phoneNumberId) {
      waLog.warn('inbound.foreign-number', {
        got: batch.meta.phoneNumberId, expected: cfg.phoneNumberId,
      });
      skipped += batch.messages.length + batch.statuses.length;
      continue;
    }

    for (const msg of batch.messages) {
      try {
        if (!(await claimEvent(db, `msg:${msg.wamid}`, now))) { skipped++; continue; }

        const tag = await phoneTag(msg.from, idSalt);
        await upsertContact(db, seal, tag, msg.from, msg.profileName, now);
        const conv = await ensureConversation(db, tag, msg.phoneNumberId, now);
        await insertInbound(db, seal, conv, msg, now);
        messages++;

        waLog.info('inbound.message', {
          type: msg.type, from: logPhone(msg.from), wamid: msg.wamid, conv,
          hasMedia: !!msg.mediaId,
        });

        if (msg.mediaId && client) await pullMedia(db, seal, client, cfg, msg.mediaId, now);
      } catch (e) {
        waLog.error('inbound.message-failed', { wamid: msg.wamid, note: String((e && e.message) || e) });
      }
    }

    for (const st of batch.statuses) {
      try {
        if (!(await claimEvent(db, `st:${st.wamid}:${st.status}`, now))) { skipped++; continue; }
        const r = await applyStatus(db, st, now);
        if (r.applied) statuses++;
        waLog.info('status.update', {
          wamid: st.wamid, status: st.status, applied: r.applied, reason: r.reason || null,
          category: st.category || null, code: st.error && st.error.code,
        });
      } catch (e) {
        waLog.error('status.failed', { wamid: st.wamid, note: String((e && e.message) || e) });
      }
    }
  }

  await sweepEvents(db, now);
  return { messages, statuses, skipped };
}

/** Fetch, seal and store one media object. Best effort by design. */
async function pullMedia(db, seal, client, cfg, mediaId, now) {
  if (await hasMedia(db, mediaId)) return;

  const meta = await client.getMedia(mediaId);
  if (!meta.ok || !meta.data || !meta.data.url) {
    waLog.warn('media.metadata-failed', { mediaId, status: meta.status });
    return;
  }
  const size = Number(meta.data.file_size) || 0;
  if (size > cfg.maxMediaBytes) {
    waLog.warn('media.too-large', { mediaId, size, limit: cfg.maxMediaBytes });
    return;
  }

  const dl = await client.downloadMedia(meta.data.url);
  if (!dl.ok || !dl.bytes) {
    waLog.warn('media.download-failed', { mediaId, status: dl.status });
    return;
  }
  if (dl.bytes.length > cfg.maxMediaBytes) {
    waLog.warn('media.too-large', { mediaId, size: dl.bytes.length, limit: cfg.maxMediaBytes });
    return;
  }

  await saveMedia(db, seal, mediaId, meta.data.mime_type, dl.bytes, now);
  waLog.info('media.stored', { mediaId, bytes: dl.bytes.length, mime: meta.data.mime_type });
}

export { WINDOW_MS };
