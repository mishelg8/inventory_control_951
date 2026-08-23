/* The only place in this codebase that talks to Meta.
 *
 * Everything above this file deals in intentions — send this text, fetch that
 * media — and never in URLs, tokens or Graph versions. That is what makes the
 * token replaceable by editing one environment variable, and the API version
 * bumpable by editing one constant.
 *
 * The token travels in an Authorization header and never in a URL. Meta will
 * accept ?access_token= on most endpoints; URLs end up in logs, in referrers
 * and in error messages, and a secret that can be logged eventually is.
 */

import { graphUrl } from './config.js';
import { metaError, isRetryable } from './errors.js';
import { waLog, logPhone } from './log.js';
import { toWaId } from '../../public/lib/phone.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* Backoff between attempts. Small, because a Worker has a wall clock and a
 * webhook on the other side of it; this is meant to ride out a blip, not to
 * wait out an outage. An outage is the caller's problem to report. */
const BACKOFF_MS = [400, 1200];

export function waClient(cfg) {
  /**
   * One request to Graph.
   *
   * `idempotent` decides whether a request with no answer may be repeated.
   * Reads are; a send is not, because "no answer" and "accepted, answer lost"
   * look identical from here and one of them ends with the same message
   * arriving twice.
   */
  async function call(path, { method = 'GET', body, idempotent = method === 'GET', raw = false } = {}) {
    const url = graphUrl(cfg, path);
    let last = null;

    for (let attempt = 0; attempt <= BACKOFF_MS.length; attempt++) {
      let res = null;
      try {
        res = await fetch(url, {
          method,
          headers: {
            Authorization: `Bearer ${cfg.token}`,
            ...(body ? { 'Content-Type': 'application/json' } : {}),
          },
          body: body ? JSON.stringify(body) : undefined,
          signal: AbortSignal.timeout(cfg.requestTimeoutMs),
        });
      } catch {
        last = metaError(0, null);
        if (attempt < BACKOFF_MS.length && isRetryable(last, { idempotent })) {
          await sleep(BACKOFF_MS[attempt]);
          continue;
        }
        return { ok: false, status: 0, data: null, err: last };
      }

      if (raw && res.ok) {
        return { ok: true, status: res.status, res, data: null, err: null };
      }

      const text = await res.text();
      let data = null;
      try { data = text ? JSON.parse(text) : null; } catch { data = null; }

      if (res.ok) return { ok: true, status: res.status, data, err: null };

      last = metaError(res.status, data);
      if (attempt < BACKOFF_MS.length && isRetryable(last, { idempotent })) {
        waLog.warn('graph.retry', { path, status: last.status, code: last.code, attempt });
        await sleep(BACKOFF_MS[attempt]);
        continue;
      }
      return { ok: false, status: res.status, data, err: last };
    }

    return { ok: false, status: last ? last.status : 0, data: null, err: last };
  }

  /* Every outbound message is this shape underneath; the two public helpers
   * differ only in the object they put beside the recipient. Keeping the
   * envelope in one place is what stops `messaging_product` from going
   * missing in the one path nobody tested. */
  async function send(to, payload, { context } = {}) {
    const body = {
      messaging_product: 'whatsapp',
      recipient_type: 'individual',
      to: toWaId(to),
      ...payload,
      ...(context ? { context: { message_id: context } } : {}),
    };

    waLog.info('outbound.request', {
      to: logPhone(to), type: payload.type, template: payload.template && payload.template.name,
    });

    const r = await call(`${cfg.phoneNumberId}/messages`, { method: 'POST', body, idempotent: false });

    if (!r.ok) {
      waLog.error('outbound.failed', {
        to: logPhone(to), type: payload.type, status: r.status,
        code: r.err && r.err.code, subcode: r.err && r.err.subcode, trace: r.err && r.err.trace,
      });
      return { ok: false, err: r.err, wamid: null };
    }

    const wamid = (r.data && r.data.messages && r.data.messages[0] && r.data.messages[0].id) || null;
    waLog.info('outbound.accepted', { to: logPhone(to), type: payload.type, wamid });
    return { ok: true, err: null, wamid };
  }

  return {
    cfg,
    call,

    /** Free text. Only legal inside the 24-hour window — the service checks. */
    sendText: (to, text, opts = {}) =>
      send(to, { type: 'text', text: { preview_url: false, body: String(text).slice(0, cfg.maxTextLen) } }, opts),

    /**
     * An approved template. Name, language and components all come from the
     * caller: nothing about a specific template is known to this layer.
     */
    sendTemplate: (to, name, language, components, opts = {}) =>
      send(to, {
        type: 'template',
        template: {
          name: String(name),
          language: { code: String(language) },
          ...(Array.isArray(components) && components.length ? { components } : {}),
        },
      }, opts),

    /** Blue ticks on the sender's side. Best-effort; a failure is not an error. */
    markRead: (wamid) =>
      call(`${cfg.phoneNumberId}/messages`, {
        method: 'POST', idempotent: false,
        body: { messaging_product: 'whatsapp', status: 'read', message_id: String(wamid) },
      }),

    /** Media metadata: a short-lived URL, the mime type, the size. */
    getMedia: (mediaId) => call(`${encodeURIComponent(mediaId)}?phone_number_id=${encodeURIComponent(cfg.phoneNumberId)}`),

    /**
     * The bytes. Meta's URL is on a different host and still needs the token
     * in a header, which is exactly why this never goes near a browser.
     */
    async downloadMedia(url) {
      try {
        const res = await fetch(url, {
          headers: { Authorization: `Bearer ${cfg.token}` },
          signal: AbortSignal.timeout(cfg.requestTimeoutMs),
        });
        if (!res.ok) return { ok: false, status: res.status, bytes: null };
        const buf = await res.arrayBuffer();
        return { ok: true, status: res.status, bytes: new Uint8Array(buf) };
      } catch {
        return { ok: false, status: 0, bytes: null };
      }
    },

    /** "Am I talking to the phone number I think I am." */
    getPhoneNumber: () =>
      call(`${cfg.phoneNumberId}?fields=id,display_phone_number,verified_name,quality_rating,platform_type,throughput`),

    /** "Is that phone number on the WABA I think it is." */
    listWabaNumbers: () =>
      call(`${cfg.wabaId}/phone_numbers?fields=id,display_phone_number,verified_name,quality_rating`),

    /** The templates Meta has approved, so the console can offer real ones. */
    listTemplates: () =>
      call(`${cfg.wabaId}/message_templates?fields=name,status,category,language,components&limit=100`),
  };
}
