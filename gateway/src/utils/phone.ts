/* Turning what a person typed into what WhatsApp wants.
 *
 * WhatsApp addresses a chat as "<country><subscriber>@c.us" — no plus, no
 * separators, no leading zero. Everything a telephone number can look like in
 * the wild has to arrive at that one form: 050-123-4567, +972 50 123 4567,
 * 00972501234567, and the paste-accident +9720501234567 that carries both a
 * country code and a trunk zero.
 *
 * A number that cannot get there is rejected loudly. Sending a message to the
 * wrong person is worse than not sending it, so there is no best guess here.
 *
 * The country rule is a table rather than an `if` on Israel, because the
 * moment a second country appears the `if` becomes two, and then three.
 */
import { config } from '../config/index.js';
import { AppError, ErrorCode } from './errors.js';

export interface CountryRule {
  /** dialling code, without the plus */
  readonly code: string;
  /** valid subscriber lengths, counted after the trunk prefix is removed */
  readonly subscriberLengths: readonly number[];
  /** the digit a national number starts with and an international one does not */
  readonly trunkPrefix: string;
}

export const COUNTRIES: Readonly<Record<string, CountryRule>> = Object.freeze({
  '972': { code: '972', subscriberLengths: [8, 9], trunkPrefix: '0' },  // Israel
  '44': { code: '44', subscriberLengths: [10], trunkPrefix: '0' },      // United Kingdom
  '1': { code: '1', subscriberLengths: [10], trunkPrefix: '' },         // NANP: no trunk digit
});

export interface NormalizedPhone {
  /** digits only, country code first: 972501234567 */
  readonly e164: string;
  /** what WhatsApp Web addresses: 972501234567@c.us */
  readonly jid: string;
  readonly country: string;
}

const digitsOnly = (input: string) => input.replace(/\D+/g, '');

const stripTrunk = (rest: string, rule: CountryRule) =>
  (rule.trunkPrefix && rest.startsWith(rule.trunkPrefix) ? rest.slice(rule.trunkPrefix.length) : rest);

const build = (rule: CountryRule, subscriber: string): NormalizedPhone | null =>
  (rule.subscriberLengths.includes(subscriber.length)
    ? { e164: `${rule.code}${subscriber}`, jid: `${rule.code}${subscriber}@c.us`, country: rule.code }
    : null);

/**
 * Normalize a telephone number to WhatsApp's addressing form.
 * @throws AppError(INVALID_PHONE) when the input cannot be resolved to exactly one number.
 */
export function normalizePhone(
  input: unknown,
  defaultCountry: string = config.DEFAULT_COUNTRY_CODE,
): NormalizedPhone {
  if (typeof input !== 'string' || !input.trim()) {
    throw new AppError(ErrorCode.INVALID_PHONE, 'מספר טלפון חסר');
  }

  let digits = digitsOnly(input);
  if (digits.startsWith('00')) digits = digits.slice(2);   // 00 is the other way of writing +

  if (!digits) throw new AppError(ErrorCode.INVALID_PHONE, 'מספר הטלפון אינו מכיל ספרות');
  if (digits.length > 15) throw new AppError(ErrorCode.INVALID_PHONE, 'מספר הטלפון ארוך מדי');

  const home = COUNTRIES[defaultCountry];
  if (!home) throw new AppError(ErrorCode.INVALID_PHONE, `מדינה לא נתמכת: ${defaultCountry}`);

  /* A number in national form is claimed by the home country before any
     dialling code is considered. Read the other way round, an Israeli
     0501234567 begins with "1" once the zero is gone, and the NANP rule would
     take it for a perfectly good ten-digit American number. */
  if (home.trunkPrefix && digits.startsWith(home.trunkPrefix)) {
    const national = build(home, stripTrunk(digits, home));
    if (national) return national;
  }

  /* International. The longest matching dialling code wins, so 1 cannot claim
     a number that 972 also matches. */
  const codes = Object.keys(COUNTRIES).sort((a, b) => b.length - a.length);
  for (const code of codes) {
    const rule = COUNTRIES[code]!;
    if (!digits.startsWith(rule.code)) continue;
    const hit = build(rule, stripTrunk(digits.slice(rule.code.length), rule));
    if (hit) return hit;
  }

  // No dialling code and no trunk prefix — a bare subscriber number at home.
  const bare = build(home, digits);
  if (bare) return bare;

  throw new AppError(ErrorCode.INVALID_PHONE, 'מספר הטלפון אינו תקין');
}

/** Non-throwing form, for filtering a list. */
export function isValidPhone(input: unknown, defaultCountry?: string): boolean {
  try {
    normalizePhone(input, defaultCountry);
    return true;
  } catch {
    return false;
  }
}
