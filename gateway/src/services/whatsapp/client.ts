/* The one live WhatsApp session, and the state machine around it.
 *
 * Underneath this file is a real Chromium running a real WhatsApp Web tab. It
 * is slow to start, it can be logged out from the phone at any moment, and it
 * occasionally dies for reasons it does not explain. Everything above this
 * file is written as if none of that were true, which means all of it has to
 * be handled here.
 *
 * The states, and what each one means to a caller:
 *
 *   stopped        nothing is running; nobody asked for it yet
 *   starting       Chromium is coming up, or the session is being restored
 *   qr             waiting for a human to scan; not usable
 *   authenticated  the scan worked, the tab is still loading
 *   ready          messages can be sent
 *   disconnected   was ready, is not any more; a reconnect is scheduled
 *   auth_failure   the stored session is no longer valid; needs a new scan
 *
 * Only `ready` sends. Everything else queues, which is why the queue exists.
 */
import { EventEmitter } from 'node:events';
import { rm } from 'node:fs/promises';
import pkg from 'whatsapp-web.js';
import QRCode from 'qrcode';
import { config } from '../../config/index.js';
import { log } from '../../utils/logger.js';
import { AppError, ErrorCode } from '../../utils/errors.js';
import * as events from '../../repositories/events.js';

const { Client, LocalAuth } = pkg;
type WaClient = InstanceType<typeof Client>;

export type WaState =
  | 'stopped'
  | 'starting'
  | 'qr'
  | 'authenticated'
  | 'ready'
  | 'disconnected'
  | 'auth_failure';

export interface WaStatus {
  state: WaState;
  since: number;
  /** Present only while state is 'qr'. A PNG data URL, ready for an <img>. */
  qr: { dataUrl: string; expiresAt: number } | null;
  me: { phone: string; name: string | null } | null;
  lastError: string | null;
  restarts: number;
}

/* A QR code from WhatsApp Web is refreshed every twenty seconds or so. Sixty
   is generous enough that a slow scan is not punished and short enough that a
   stale image is not offered as if it worked. */
const QR_TTL_MS = 60_000;

const RECONNECT_BACKOFF_MS = [5_000, 15_000, 30_000, 60_000, 120_000, 300_000];

/* destroy() reaches into Chromium, and Chromium is not always listening. A
   shutdown must not hang on a browser that has already wandered off. */
const DESTROY_TIMEOUT_MS = 10_000;

const withTimeout = async <T>(p: Promise<T>, ms: number, what: string): Promise<T | null> => {
  let timer: NodeJS.Timeout;
  const guard = new Promise<null>((resolve) => {
    timer = setTimeout(() => {
      log.warn('wa.timeout', { what, ms });
      resolve(null);
    }, ms);
  });
  try {
    return await Promise.race([p, guard]);
  } finally {
    clearTimeout(timer!);
  }
};

class WhatsAppService extends EventEmitter {
  private client: WaClient | null = null;
  private state: WaState = 'stopped';
  private since = Date.now();
  private qr: { dataUrl: string; expiresAt: number } | null = null;
  private me: { phone: string; name: string | null } | null = null;
  private lastError: string | null = null;
  private restarts = 0;

  /** A deliberate stop or logout must not be undone by the reconnect timer. */
  private wanted = false;
  private reconnectAt: NodeJS.Timeout | null = null;
  private reconnectStep = 0;
  private starting: Promise<void> | null = null;

  status(): WaStatus {
    const qr = this.qr && this.qr.expiresAt > Date.now() ? this.qr : null;
    return {
      state: this.state,
      since: this.since,
      qr: this.state === 'qr' ? qr : null,
      me: this.me,
      lastError: this.lastError,
      restarts: this.restarts,
    };
  }

  get ready(): boolean {
    return this.state === 'ready';
  }

  private set(state: WaState, detail?: string) {
    if (this.state === state && !detail) return;
    this.state = state;
    this.since = Date.now();
    if (state !== 'qr') this.qr = null;
    log.info('wa.state', { state, detail });
    events.record(state, detail ?? null);
    this.emit('status', this.status());
  }

  /** Bring the session up. Safe to call when it is already up or coming up. */
  async start(): Promise<WaStatus> {
    this.wanted = true;
    if (this.client && this.state !== 'stopped' && this.state !== 'disconnected') {
      return this.status();
    }
    if (this.starting) {
      await this.starting;
      return this.status();
    }
    this.starting = this.boot().finally(() => {
      this.starting = null;
    });
    await this.starting;
    return this.status();
  }

  private async boot(): Promise<void> {
    this.clearReconnect();
    this.set('starting');

    const client = new Client({
      authStrategy: new LocalAuth({ dataPath: config.SESSION_PATH }),
      puppeteer: {
        headless: true,
        ...(config.PUPPETEER_EXECUTABLE_PATH
          ? { executablePath: config.PUPPETEER_EXECUTABLE_PATH }
          : {}),
        args: [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-dev-shm-usage',
          '--disable-gpu',
          '--no-first-run',
          '--no-default-browser-check',
        ],
      },
    });

    this.client = client;
    this.wire(client);

    try {
      /* initialize() resolves when the tab is up, not when it is authenticated.
         The 'ready' event is what says a message can be sent. */
      await client.initialize();
    } catch (e) {
      this.lastError = e instanceof Error ? e.message : String(e);
      log.error('wa.init_failed', { error: this.lastError });
      this.set('disconnected', 'initialize failed');
      this.scheduleReconnect();
    }
  }

  private wire(client: WaClient) {
    client.on('qr', (raw: string) => {
      QRCode.toDataURL(raw, { width: 320, margin: 2, errorCorrectionLevel: 'M' })
        .then((dataUrl) => {
          this.qr = { dataUrl, expiresAt: Date.now() + QR_TTL_MS };
          this.set('qr', 'new code');
        })
        .catch((e: unknown) => {
          log.error('wa.qr_render_failed', { error: e instanceof Error ? e.message : String(e) });
        });
    });

    client.on('authenticated', () => {
      this.lastError = null;
      this.set('authenticated');
    });

    client.on('auth_failure', (msg: string) => {
      /* The stored session was rejected. Reconnecting with the same files
         would only be rejected again, so the loop stops here and waits for a
         human to scan. */
      this.lastError = msg || 'authentication failed';
      this.clearReconnect();
      this.set('auth_failure', 'stored session rejected');
    });

    client.on('ready', () => {
      this.reconnectStep = 0;
      this.lastError = null;
      const info = (client as unknown as { info?: { wid?: { user?: string }; pushname?: string } }).info;
      this.me = info?.wid?.user
        ? { phone: info.wid.user, name: info.pushname ?? null }
        : null;
      this.set('ready');
    });

    client.on('disconnected', (reason: string) => {
      this.me = null;
      this.lastError = String(reason || 'disconnected');
      this.set('disconnected', String(reason || ''));
      /* LOGOUT means the phone unlinked this device. The files on disk are now
         worthless and reconnecting cannot help. */
      if (String(reason).toUpperCase().includes('LOGOUT')) {
        this.clearReconnect();
        this.set('auth_failure', 'unlinked from the phone');
        return;
      }
      this.scheduleReconnect();
    });

    client.on('change_state', (s: string) => {
      log.debug('wa.change_state', { waState: s });
    });
  }

  private clearReconnect() {
    if (this.reconnectAt) {
      clearTimeout(this.reconnectAt);
      this.reconnectAt = null;
    }
  }

  private scheduleReconnect() {
    if (!this.wanted || this.reconnectAt) return;
    const idx = Math.min(this.reconnectStep, RECONNECT_BACKOFF_MS.length - 1);
    const delay = RECONNECT_BACKOFF_MS[idx]!;
    this.reconnectStep += 1;
    log.info('wa.reconnect_scheduled', { inMs: delay, attempt: this.reconnectStep });
    this.reconnectAt = setTimeout(() => {
      this.reconnectAt = null;
      if (!this.wanted) return;
      this.restarts += 1;
      void this.restart();
    }, delay);
    this.reconnectAt.unref?.();
  }

  private async restart(): Promise<void> {
    await this.teardown();
    if (!this.wanted) return;
    await this.start();
  }

  private async teardown(): Promise<void> {
    const client = this.client;
    this.client = null;
    this.me = null;
    if (!client) return;
    client.removeAllListeners();
    await withTimeout(client.destroy(), DESTROY_TIMEOUT_MS, 'destroy');
  }

  /** Tear down and come back up, keeping the stored session. */
  async reconnect(): Promise<WaStatus> {
    this.clearReconnect();
    this.reconnectStep = 0;
    this.wanted = true;
    await this.teardown();
    return this.start();
  }

  /**
   * Unlink and forget. The stored session is deleted, so the next start needs
   * a fresh scan — which is the whole point of the button.
   */
  async logout(): Promise<WaStatus> {
    this.wanted = false;
    this.clearReconnect();
    const client = this.client;
    if (client) {
      try {
        await withTimeout(client.logout(), DESTROY_TIMEOUT_MS, 'logout');
      } catch (e) {
        log.warn('wa.logout_failed', { error: e instanceof Error ? e.message : String(e) });
      }
    }
    await this.teardown();
    try {
      await rm(config.SESSION_PATH, { recursive: true, force: true });
    } catch (e) {
      log.warn('wa.session_rm_failed', { error: e instanceof Error ? e.message : String(e) });
    }
    this.reconnectStep = 0;
    this.lastError = null;
    this.set('stopped', 'logged out');
    return this.status();
  }

  /** Stop without forgetting the session — for shutdown. */
  async stop(): Promise<void> {
    this.wanted = false;
    this.clearReconnect();
    await this.teardown();
    this.set('stopped');
  }

  private require(): WaClient {
    if (!this.client || this.state !== 'ready') {
      throw new AppError(
        ErrorCode.WHATSAPP_NOT_CONNECTED,
        this.state === 'auth_failure' || this.state === 'stopped'
          ? 'השער אינו מחובר לוואטסאפ — יש לסרוק את קוד ה-QR'
          : 'השער עדיין אינו מוכן לשליחה',
      );
    }
    return this.client;
  }

  /** @returns the WhatsApp message id, when it gives one. */
  async send(jid: string, body: string): Promise<string | null> {
    const client = this.require();
    try {
      const sent = await client.sendMessage(jid, body);
      return (sent as unknown as { id?: { _serialized?: string } })?.id?._serialized ?? null;
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      log.warn('wa.send_failed', { error: message });
      throw new AppError(ErrorCode.MESSAGE_FAILED, 'שליחת ההודעה נכשלה', { cause: message });
    }
  }

  /** Whether a number has WhatsApp at all. */
  async isRegistered(e164: string): Promise<boolean> {
    const client = this.require();
    try {
      return await client.isRegisteredUser(`${e164}@c.us`);
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      log.warn('wa.check_failed', { error: message });
      throw new AppError(ErrorCode.MESSAGE_FAILED, 'בדיקת המספר נכשלה', { cause: message });
    }
  }
}

export const whatsapp = new WhatsAppService();
