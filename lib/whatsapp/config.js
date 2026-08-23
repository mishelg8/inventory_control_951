/* Every setting the WhatsApp Cloud integration has, read in one place.
 *
 * Nothing below reaches into `env` again. That is the whole point: the Graph
 * version, the phone number id and the token are read here, and a call site
 * that wants one of them takes it from the object it was handed. A version
 * string scattered across a codebase is a version string that gets upgraded
 * in four places out of five.
 */

// Measured against the live API rather than taken from a changelog: v26.0 is
// the newest version that still resolves a versioned path. Override with
// META_GRAPH_API_VERSION when Meta moves on — that is the only change needed.
export const DEFAULT_GRAPH_VERSION = 'v26.0';

const GRAPH_HOST = 'https://graph.facebook.com';

/* How fast we are willing to talk to Meta.
 *
 * These are not the gateway's numbers and must not be confused with them. The
 * old floor of one message a minute exists because an unofficial gateway gets
 * a number restricted for looking automated; the official API is the
 * sanctioned way to look automated, and its limits are Meta's own messaging
 * tier (1K/10K/100K unique recipients a day, raised automatically on quality).
 * What is left for us to hold is a sane ceiling so a loop cannot spend a
 * budget, and a gap small enough to be invisible. */
const num = (v, dflt, min) => {
  const n = Number(v);
  return Number.isFinite(n) && n >= min ? n : dflt;
};

/**
 * Build the configuration, or say precisely what is missing.
 *
 * Missing is a normal state — the console runs without WhatsApp and always
 * has — so this returns { ready: false, missing: [...] } rather than throwing.
 * Names only. A value never leaves this function.
 */
export function waConfig(env = {}) {
  const token = String(env.WHATSAPP_ACCESS_TOKEN || '');
  const phoneNumberId = String(env.WHATSAPP_PHONE_NUMBER_ID || '');
  const wabaId = String(env.WHATSAPP_BUSINESS_ACCOUNT_ID || '');
  const verifyToken = String(env.WHATSAPP_VERIFY_TOKEN || '');
  const appSecret = String(env.WHATSAPP_APP_SECRET || '');

  const missing = [
    !token && 'WHATSAPP_ACCESS_TOKEN',
    !phoneNumberId && 'WHATSAPP_PHONE_NUMBER_ID',
    !wabaId && 'WHATSAPP_BUSINESS_ACCOUNT_ID',
    !verifyToken && 'WHATSAPP_VERIFY_TOKEN',
    !appSecret && 'WHATSAPP_APP_SECRET',
  ].filter(Boolean);

  const version = String(env.META_GRAPH_API_VERSION || DEFAULT_GRAPH_VERSION);

  return {
    ready: missing.length === 0,
    missing,
    token,
    phoneNumberId,
    wabaId,
    verifyToken,
    appSecret,
    version,
    graphHost: GRAPH_HOST,
    region: String(env.WHATSAPP_DEFAULT_REGION || 'IL'),
    // Cloud-channel pacing, separate from the gateway's.
    pace: {
      gapMs:   num(env.WA_CLOUD_GAP_MS, 1000, 0),
      hourMax: num(env.WA_CLOUD_HOUR_MAX, 200, 1),
      dayMax:  num(env.WA_CLOUD_DAY_MAX, 1000, 1),
    },
    // How long a message may be before we refuse it rather than Meta.
    maxTextLen: 4096,
    // Media we are willing to pull down and seal. Meta allows more; this is
    // a D1 row, and a row is not a blob store.
    maxMediaBytes: num(env.WA_CLOUD_MAX_MEDIA_BYTES, 4 * 1024 * 1024, 1024),
    requestTimeoutMs: num(env.WA_CLOUD_TIMEOUT_MS, 20000, 1000),
    /* Which template says what. Read here so the console can be told, and so
       that swapping a rejected template for its replacement is an environment
       change rather than a deploy of new code. */
    templates: {
      signed: String(env.WA_TPL_SIGNED || 'tzayad_signed'),
      credit: String(env.WA_TPL_CREDIT || 'tzayad_credit'),
      update: String(env.WA_TPL_UPDATE || 'tzayad_update'),
    },
    templateLang: String(env.WA_TPL_LANG || 'he'),
  };
}

/** The one place a Graph URL is built. */
export const graphUrl = (cfg, path) =>
  `${cfg.graphHost}/${cfg.version}/${String(path).replace(/^\/+/, '')}`;
