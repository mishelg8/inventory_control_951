/* Phone numbers, in one place, for both sides.
 *
 * The browser imports this to build a wa.me link or to tag a conversation;
 * the Worker imports the same file so that a number normalised on one side is
 * the same string on the other. Two implementations of this drifted once
 * already — the console sent `972…` and the gateway wanted `0…` — and the
 * only durable fix is that there is one implementation.
 *
 * Storage format is E.164 with the leading plus: +972522398415. Not because
 * WhatsApp wants it that way (Meta wants the digits without the plus), but
 * because it is the only format that is unambiguous on its own, and the one
 * place that strips the plus is the client that talks to Meta.
 */

/* Countries are data, not code, so adding one is a line rather than a branch.
 *
 *   cc     country calling code
 *   trunk  the digit a domestic caller dials first and an international one
 *          does not — 0 across almost all of Europe and the Middle East
 *   nsn    allowed national significant number lengths, after the trunk
 *
 * IL is here because that is who uses this system today. The default is a
 * parameter, and nothing below assumes it. */
const COUNTRIES = {
  IL: { cc: '972', trunk: '0', nsn: [8, 9] },
  US: { cc: '1',   trunk: '1', nsn: [10] },
  GB: { cc: '44',  trunk: '0', nsn: [9, 10] },
};

const DEFAULT_REGION = 'IL';

// E.164 caps the whole thing at 15 digits, country code included.
const E164 = /^\+[1-9]\d{7,14}$/;

/* Everything a keyboard, a spreadsheet or a paste can add and a number can
 * survive without: spaces, dashes, dots, brackets, and the unicode marks that
 * an RTL editor drops around a run of digits. */
const strip = (raw) => String(raw == null ? '' : raw).replace(/[^\d+]/g, '');

/**
 * Normalise anything a human might type into E.164.
 *
 * Returns { ok: true, e164 } or { ok: false, reason } — never throws, because
 * the callers are a form field and a webhook, and neither wants a stack trace
 * for a typo.
 */
export function toE164(raw, region = DEFAULT_REGION) {
  let s = strip(raw);
  if (!s) return { ok: false, reason: 'empty' };

  // 00 is the international prefix nearly everywhere; + is the same intent.
  if (s.startsWith('00')) s = `+${s.slice(2)}`;

  // A plus already says which country, so no default applies.
  if (s.startsWith('+')) {
    // A plus anywhere but the front is someone's phone book, not a number.
    if (s.indexOf('+', 1) !== -1) return { ok: false, reason: 'malformed' };
    return E164.test(s) ? { ok: true, e164: s } : { ok: false, reason: 'length' };
  }

  const c = COUNTRIES[region] || COUNTRIES[DEFAULT_REGION];

  /* Bare national number. Two shapes reach us: with the trunk digit, as
   * written on a form (0522398415), and without it, as some systems store it
   * (522398415). Both are the same person. */
  let nsn = s;
  if (c.trunk && nsn.startsWith(c.trunk)) nsn = nsn.slice(c.trunk.length);

  /* A number that already begins with its own country code and no plus —
   * 972522398415, which is exactly what the old gateway spoke. Accept it,
   * rather than reading the 972 as part of the subscriber number. */
  if (s.startsWith(c.cc) && !c.nsn.includes(nsn.length)) {
    const rest = s.slice(c.cc.length);
    if (c.nsn.includes(rest.length)) nsn = rest;
  }

  if (!c.nsn.includes(nsn.length)) return { ok: false, reason: 'length' };
  const e164 = `+${c.cc}${nsn}`;
  return E164.test(e164) ? { ok: true, e164 } : { ok: false, reason: 'length' };
}

/** The digits Meta's API wants: E.164 without the plus. */
export const toWaId = (e164) => String(e164 || '').replace(/^\+/, '');

/** Meta hands back a wa_id with no plus. Same number, our format. */
export const fromWaId = (waId) => {
  const d = String(waId || '').replace(/\D/g, '');
  return d ? `+${d}` : '';
};

/* For logs and for anything that may end up on a screen that is not the
 * console. Keeps the country and the last two digits — enough to tell two
 * numbers apart while reading a log, not enough to call anybody. */
export function maskPhone(e164) {
  const s = String(e164 || '');
  const m = /^\+(\d{1,3})(\d+)$/.exec(s);
  if (!m) return '***';
  const [, cc, rest] = m;
  return `+${cc}${'*'.repeat(Math.max(0, rest.length - 2))}${rest.slice(-2)}`;
}

export const REGIONS = Object.keys(COUNTRIES);
