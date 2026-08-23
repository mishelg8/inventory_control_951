/* Meta's errors, turned into something a caller can act on.
 *
 * Two audiences, and they want opposite things. The console wants one short
 * Hebrew sentence that says what to do; the log wants the code, the subcode
 * and the fbtrace_id, because that is what Meta's support will ask for. So
 * every failure produces both, and the detailed half never reaches a screen.
 */

/** Pull Meta's error envelope out of whatever came back. */
export function metaError(status, body) {
  const e = (body && body.error) || {};
  const data = e.error_data || {};
  return {
    status,
    code: Number.isFinite(e.code) ? e.code : null,
    subcode: Number.isFinite(e.error_subcode) ? e.error_subcode : null,
    type: typeof e.type === 'string' ? e.type : null,
    title: typeof e.message === 'string' ? e.message.slice(0, 300) : null,
    detail: typeof data.details === 'string' ? data.details.slice(0, 300) : null,
    trace: typeof e.fbtrace_id === 'string' ? e.fbtrace_id : null,
  };
}

/* Retrying a permanent error is not resilience, it is a loop that spends a
 * budget and gets the same answer. Only two classes are worth a second try:
 * Meta throttling us, and Meta being briefly unwell.
 *
 * Deliberately absent: timeouts on a send. A request that timed out may have
 * been accepted, and the cost of being wrong is the soldier's phone buzzing
 * twice — which is the exact pattern that got this unit's number restricted
 * in the first place. A read may be retried on timeout; a send may not. */
const RETRY_CODES = new Set([
  4,       // application request limit reached
  80007,   // rate limit hit
  131056,  // pair rate limit hit
  133016,  // account temporarily locked
]);

export function isRetryable(err, { idempotent }) {
  if (!err) return false;
  if (err.status === 429) return true;
  if (err.status >= 500 && err.status <= 599) return true;
  if (err.code != null && RETRY_CODES.has(err.code)) return true;
  // status 0 is "no answer at all" — a timeout or a dropped connection.
  if (err.status === 0) return !!idempotent;
  return false;
}

/* What a person reading the console should see. Anything not listed falls
 * back to a sentence that says a send failed and that the detail is in the
 * log, which is true and is better than showing Meta's English. */
const HE = {
  190: 'הטוקן של Meta פג או בוטל. יש להנפיק טוקן חדש ולעדכן את המשתנה בקלאודפלייר',
  200: 'לחשבון אין הרשאה לשלוח מהמספר הזה. בדקו את הרשאות המשתמש המערכתי',
  100: 'הבקשה נדחתה על ידי Meta — פרמטר שגוי. הפרטים ביומן',
  131_008: 'חסר שדה חובה בבקשה',
  131_009: 'ערך לא תקין באחד השדות',
  131_016: 'השירות של Meta אינו זמין כרגע. נסו שוב בעוד רגע',
  131_021: 'אי אפשר לשלוח הודעה מהמספר אל עצמו',
  131_026: 'אי אפשר למסור את ההודעה — ייתכן שאין למספר הזה וואטסאפ',
  131_047: 'עברו יותר מ-24 שעות מההודעה האחרונה של הנמען. מחוץ לחלון הזה מותר לשלוח רק תבנית מאושרת',
  131_051: 'סוג ההודעה אינו נתמך',
  131_053: 'המדיה שנשלחה אינה נתמכת',
  132_000: 'מספר הפרמטרים בתבנית אינו תואם למה שאושר',
  132_001: 'התבנית לא נמצאה בשפה הזו, או שאינה מאושרת',
  132_005: 'טקסט התבנית ארוך מדי',
  132_007: 'התבנית נדחתה על ידי Meta',
  132_012: 'ערך פרמטר בתבנית אינו תואם לפורמט שאושר',
  132_015: 'התבנית מושהית',
  133_010: 'המספר אינו רשום ב-Cloud API',
  4:       'הגעתם לתקרת הבקשות של Meta. המתינו ונסו שוב',
  80_007:  'הגעתם לתקרת הבקשות של Meta. המתינו ונסו שוב',
  131_056: 'יותר מדי הודעות לאותו נמען בזמן קצר. המתינו ונסו שוב',
};

export function userMessage(err) {
  if (!err) return 'השליחה נכשלה';
  if (err.code != null && HE[err.code]) return HE[err.code];
  if (err.status === 0) return 'אין תשובה מ-Meta — פסק זמן או תקלת רשת';
  if (err.status === 401 || err.status === 403) return HE[190];
  if (err.status >= 500) return 'תקלה בצד של Meta. נסו שוב בעוד רגע';
  return 'השליחה נכשלה. הפרטים ביומן השרת';
}
