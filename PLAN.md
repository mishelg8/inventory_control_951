# PLAN.md — Equipment Sign-Out System (E2E Encrypted)

**Status:** implementation-ready specification
**Target platform:** GitHub → Cloudflare Pages + Pages Functions + D1
**Scale:** ~90 soldiers, one administrator, single unit, short-lived deployment
**UI language:** Hebrew (RTL). This document is English; all user-facing strings stay Hebrew.

---

## 1. Goal

A single link, shared with ~90 soldiers, that lets each soldier register the equipment they
received. The administrator approves each submission, tracks who holds what, and credits
equipment back — fully or partially — when it is returned.

Personal data (name, personal number, phone) must never be readable by the server, by
Cloudflare, or by anyone who gains access to the hosting account or the database.

### 1.1 Functional requirements

| # | Requirement |
|---|---|
| F1 | Soldier opens link → enters personal number, full name, phone |
| F2 | Soldier selects equipment: קסדה, ווסט, מצנפת, ברכיות, מחסניות (last one with quantity) |
| F3 | Submission is stored as `pending` and is not yet binding |
| F4 | Admin reviews pending submissions, may adjust quantities, then approves |
| F5 | Admin sees a tracking view of every approved soldier and their outstanding items |
| F6 | Admin can credit a returned item, a partial quantity, or everything at once |
| F7 | Admin sees aggregate totals per item: issued / returned / outstanding |
| F8 | Admin can export to CSV, rotate the password, and wipe all data |

### 1.2 Non-functional requirements

| # | Requirement |
|---|---|
| N1 | End-to-end encryption; server stores ciphertext only |
| N2 | No build step, no runtime dependencies, no third-party network calls |
| N3 | Mobile-first; usable one-handed outdoors on a phone |
| N4 | Deploys from a GitHub repo on push, with a shareable HTTPS link |
| N5 | Full flow (open link → submitted) under 60 seconds per soldier |

### 1.3 Non-goals

- User accounts, SSO, or per-soldier authentication. Anyone with the link can submit; this is
  deliberate, otherwise onboarding 90 people is impossible in the field.
- Multi-unit or multi-admin support. One config row, one administrator.
- Offline mode. The device needs connectivity at submission time.
- Password recovery. See §11.3 — by design there is none.

---

## 2. Architecture

```
Soldier phone / Admin phone
  ├── Static assets (HTML, CSS, JS) served by Cloudflare Pages
  ├── Web Crypto API: all encryption and decryption happens here
  └── fetch() → /api/*
                 ├── Pages Function (Worker), functions/api/[[path]].js
                 └── D1 (SQLite) — stores ciphertext, status flags, sessions, rate limits
```

**Trust boundary:** the browser. Plaintext exists only in browser memory. Everything crossing
the network is either ciphertext or a one-way derivation.

---

## 3. Repository layout

```
tzayad/
├── public/
│   ├── index.html            Static shell. No inline <script> or <style> (CSP requires this).
│   ├── styles.css            Design system + utility classes.
│   ├── app.js                All client logic: crypto, state, rendering, event delegation.
│   └── _headers              CSP and security headers applied by Pages.
├── functions/
│   └── api/
│       └── [[path]].js       Single catch-all API handler.
├── schema.sql                D1 tables.
├── wrangler.toml             Project config + D1 binding.
├── package.json              Scripts only; wrangler is the sole devDependency.
├── .gitignore
└── README.md                 Hebrew operator guide.
```

Rule: `public/` must remain deployable as-is. If a build step ever becomes necessary, it has
failed this constraint.

---

## 4. Cryptographic design

All primitives come from `window.crypto.subtle`. Nothing is hand-rolled.

### 4.1 Parameters

| Purpose | Algorithm | Parameters |
|---|---|---|
| Record content | AES-GCM | 256-bit key, 96-bit IV, fresh key + IV per write |
| Content-key wrapping | RSA-OAEP | 2048-bit modulus, SHA-256 |
| Password → keys | PBKDF2-HMAC-SHA256 | 310,000 iterations, 128-bit salt, 512 bits output |
| Record ID masking | PBKDF2-HMAC-SHA256 | 60,000 iterations, 128-bit salt, 256 bits → 32 hex chars |
| Server-side verifier | SHA-256 | over the auth half of the PBKDF2 output |

### 4.2 Key derivation (one PBKDF2 pass, split output)

```
bits        = PBKDF2(password, config.salt, 310_000, SHA-256, 512 bits)
KEK         = AES-GCM key from bits[0..31]      // never leaves the browser
authSecret  = bits[32..63]
verifier    = hex(SHA-256(authSecret))          // this is what the server sees
```

A single derivation produces both halves, so login costs one PBKDF2 pass (~0.2–1.5 s
depending on device). The server stores `verifier` only; it cannot derive the KEK from it.

### 4.3 System setup (first admin run)

1. Generate RSA-OAEP-2048 keypair.
2. Export the public key as JWK, the private key as PKCS#8.
3. Derive KEK and verifier from the chosen password (§4.2).
4. `wrappedKey = AES-GCM(KEK, keyIv, pkcs8)`.
5. POST `{pub, salt, idSalt, verifier, keyIv, wrappedKey}` to `/api/setup`.

The plaintext private key is discarded from storage; only the wrapped form persists.

### 4.4 Sealing a record (soldier, public key only)

```
cek     = random AES-GCM 256-bit key
ek      = RSA-OAEP(publicKey, rawCek)
iv      = random 96 bits
ct      = AES-GCM(cek, iv, JSON.stringify(payload))
→ store { ek, iv, ct } as base64
```

Soldiers never need any secret. They hold the public key only, so a compromised phone cannot
read anyone else's record — not even the one it just submitted.

### 4.5 Opening a record (admin)

```
rawCek  = RSA-OAEP-decrypt(privateKey, ek)
plain   = AES-GCM-decrypt(rawCek, iv, ct)
```

AES-GCM is authenticated: a tampered `ct` throws instead of returning corrupted data. The UI
counts such failures and displays them as "רשומות פגומות" rather than hiding them.

### 4.6 Record identifiers

```
rid = hex(PBKDF2(personalNumber, config.idSalt, 60_000, SHA-256, 256 bits))[0..31]
```

The primary key is never the personal number. The slow KDF makes enumerating the 7-digit
personal-number space computationally impractical even though `idSalt` is public.

### 4.7 Record payload (plaintext, inside `ct` only)

```jsonc
{
  "pn": "8123456",
  "name": "ישראל ישראלי",
  "phone": "0501234567",
  "items": { "helmet": { "t": 1, "r": 0 }, "mags": { "t": 6, "r": 2 } },
  "createdAt": 1750000000000,
  "approvedAt": 1750000600000,
  "log": [ { "a": "submit", "t": 1750000000000 }, { "a": "approve", "t": 1750000600000 } ]
}
```

`t` = taken, `r` = returned. Outstanding = `Σ(t − r)`.

### 4.8 What the server can still infer

Row count, per-row `status`, and timestamps. No identity, no equipment detail. Documented in
the UI under the "אבטחה" tab so the operator is not misled about the guarantee.

---

## 5. Data model (`schema.sql`)

```sql
CREATE TABLE IF NOT EXISTS config (
  id           INTEGER PRIMARY KEY CHECK (id = 1),
  pub          TEXT    NOT NULL,   -- RSA public key, JWK JSON
  salt         TEXT    NOT NULL,   -- PBKDF2 salt for KEK + verifier
  id_salt      TEXT    NOT NULL,   -- PBKDF2 salt for record IDs
  verifier     TEXT    NOT NULL,   -- SHA-256 of auth half, 64 hex chars
  key_iv       TEXT    NOT NULL,
  wrapped_key  TEXT    NOT NULL,   -- private key encrypted under KEK
  created_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS records (
  rid         TEXT PRIMARY KEY,    -- 32 hex chars, §4.6
  ek          TEXT NOT NULL,
  iv          TEXT NOT NULL,
  ct          TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'pending',   -- 'pending' | 'approved'
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_records_status ON records(status);

CREATE TABLE IF NOT EXISTS sessions (
  token   TEXT PRIMARY KEY,        -- 64 hex chars
  expires INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS throttle (
  k     TEXT PRIMARY KEY,          -- 'login:<ip>' | 'sub:<ip>'
  hits  INTEGER NOT NULL,
  until INTEGER NOT NULL
);
```

Single-row `config` enforced by the `CHECK` constraint — the system cannot be silently
re-initialised over an existing deployment.

---

## 6. API contract

Base path `/api`. All responses JSON, `Cache-Control: no-store`. Errors:
`{ "error": "<Hebrew message>" }`.

| Method | Path | Auth | Body / Params | Success | Notes |
|---|---|---|---|---|---|
| GET | `/config` | — | — | `{ready:false}` or `{ready:true, pub, idSalt}` | Never returns `wrapped_key` |
| POST | `/setup` | first-run only | `{pub, salt, idSalt, verifier, keyIv, wrappedKey}` | `{ok:true}` | 409 if config exists; 403 if `SETUP_TOKEN` set and header `X-Setup-Token` mismatches |
| GET | `/status/:rid` | — | `rid` = 32 hex | `{exists, status}` | Existence check only, no content |
| POST | `/records` | — | `{rid, ek, iv, ct}` | `{ok:true}` | Upsert allowed only while `status='pending'`; 409 once approved |
| GET | `/admin/challenge` | — | — | `{salt}` | Salt is not secret |
| POST | `/admin/login` | — | `{verifier}` | `{keyIv, wrappedKey}` + `Set-Cookie: sid` | Constant-time compare; 401 on mismatch; 429 when throttled |
| POST | `/admin/logout` | session | — | `{ok:true}` | Deletes session row, clears cookie |
| GET | `/admin/records` | session | — | `{records:[{rid, ek, iv, ct, status, created_at, updated_at}]}` | Decryption happens client-side |
| PUT | `/admin/records/:rid` | session | `{ek, iv, ct, status}` | `{ok:true}` | 404 if missing; `status` restricted to the two valid values |
| DELETE | `/admin/records/:rid` | session | — | `{ok:true}` | Hard delete |
| POST | `/admin/rotate` | session | `{salt, verifier, keyIv, wrappedKey}` | `{ok:true}` | Invalidates all sessions |
| POST | `/admin/wipe` | session | — | `{ok:true}` | Deletes records, sessions, throttle, config |

### 6.1 Server-side validation (reject before touching the database)

- `rid`: exactly 32 lowercase hex characters.
- `verifier`: exactly 64 lowercase hex characters.
- `ek`: base64, ≤ 1000 chars. `iv`, `salt`, `keyIv`: base64, ≤ 64 chars. `ct`, `wrappedKey`:
  base64, ≤ 8000 chars.
- `status`: `'pending' | 'approved'` only.
- Reject any POST/PUT whose `Origin` header host differs from the request host.

### 6.2 Sessions

Opaque 256-bit random token, stored server-side with a 1-hour expiry, refreshed on each
authenticated request. Cookie: `HttpOnly; Secure; SameSite=Strict; Path=/`.

---

## 7. Client behaviour

### 7.1 Soldier flow

```
[boot] ── GET /config ──► not ready ──► "המערכת עדיין לא הוגדרה"
                       └► ready
[step 1] identity form
   validate: personal number ≥ 5 digits, name ≥ 2 chars, phone 9–10 digits
   compute rid → GET /status/:rid
     status 'approved' → block with a message pointing to the admin
     otherwise         → [step 2]
[step 2] equipment picker (tap to toggle; stepper for מחסניות, 1–20)
   submit → seal → POST /records → [step 3]
[step 3] confirmation + "ממתין לאישור" + reset button for the next soldier
```

The reset button matters: in practice one phone is passed down a line of soldiers, so state
must clear completely between them.

### 7.2 Admin flow

```
[gate] no config → setup form (password ≥ 10 chars, confirmation, explicit
                   acknowledgement that there is no recovery)
       config    → password form → GET /admin/challenge → derive → POST /admin/login
                   → unwrap private key in memory
[console] tabs: ממתין לאישור · מעקב ציוד · סיכום · אבטחה
   GET /admin/records → decrypt each → render
   approve  : set approvedAt, append log, PUT with status='approved'
   adjust   : change quantity before approval, re-seal, PUT
   credit   : increment/decrement r per item, or credit everything, re-seal, PUT
   delete   : DELETE, with a confirmation prompt
   export   : CSV with UTF-8 BOM, behind an explicit "this file is not encrypted" warning
```

Every mutation re-seals the whole payload with a fresh content key. There is no partial
update path, which keeps the ciphertext atomic and avoids IV reuse entirely.

### 7.3 Session lock

Private key lives in a JS variable, never in `localStorage`, `sessionStorage`, or IndexedDB.
Cleared on: manual lock, 10 minutes of inactivity (`pointerdown`/`keydown`/`wheel` reset the
timer), password rotation, and tab close.

---

## 8. UI specification

### 8.1 Design tokens

| Token | Value | Use |
|---|---|---|
| `--paper` | `#F2F2EF` | Page background |
| `--surface` | `#FFFFFF` | Panels and record cards |
| `--ink` | `#15181A` | Primary text, top bar |
| `--muted` | `#767D7A` | Secondary text, metadata |
| `--line` | `#DBDBD3` | Borders |
| `--pine` | `#27503C` | Primary actions, confirmed state |
| `--amber` | `#8A6614` | Pending state |
| `--rust` | `#8B3220` | Outstanding equipment, destructive actions |

Light background is a field decision, not an aesthetic one: phone screens in daylight.
System font stack only — a webfont would mean a third-party request, which §1.2/N2 forbids.
Numeric data uses a monospace stack with `font-variant-numeric: tabular-nums` and
`direction: ltr; unicode-bidi: isolate` so Latin digits render correctly inside RTL text.

### 8.2 Components

`.panel` (form container) · `.opt` (equipment row, ≥62 px tap target) · `.step` (quantity
stepper) · `.rec` (record card) · `.state` (status chip: wait/live/done) · `.tagi` (item chip,
struck through when returned) · `.fp` (record fingerprint strip) · `.callout` (advisory,
`.risk` variant) · `.tbl` (summary table) · `.toast`.

### 8.3 Signature element

Each record card ends with a fingerprint strip: a lock glyph and the first 16 characters of
the record ID. It encodes something true — that identifier *is* the masked derivation of the
personal number, and it is what the database actually holds. It doubles as a way to reference
a specific record without speaking anyone's personal number aloud.

### 8.4 Accessibility floor

Visible focus rings, `role="checkbox"` with `aria-checked` and keyboard activation on
equipment rows, ≥44 px targets, text contrast ≥ 4.5:1, no meaning conveyed by colour alone
(every state chip carries a word).

---

## 9. Security requirements

### 9.1 Response headers (`public/_headers`)

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self';
  img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none';
  form-action 'none'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), camera=(), microphone=(), interest-cohort=()
Strict-Transport-Security: max-age=31536000; includeSubDomains
Cross-Origin-Opener-Policy: same-origin
```

`style-src 'self'` without `'unsafe-inline'` blocks inline `style` attributes as well.
Therefore **no inline styles anywhere in generated HTML** — use the utility classes in
`styles.css`. This is the single easiest way to silently break the UI; check it whenever
markup changes.

### 9.2 Application-level controls

| Threat | Control |
|---|---|
| Database or account compromise | Ciphertext only; no key material recoverable server-side |
| Password guessing | 310k-iteration KDF + 8 attempts per IP, then a 10-minute lockout |
| Submission flooding | 40 submissions per IP per hour |
| XSS via soldier-supplied name | Strict CSP + HTML-escape every interpolated value |
| CSRF | `SameSite=Strict` cookie + Origin check on POST/PUT |
| Session theft | `HttpOnly`, 1-hour expiry, 10-minute idle lock |
| Record enumeration | Slow-KDF record identifiers |
| Tampering with stored rows | AES-GCM authentication; failures surfaced, not swallowed |
| Shoulder surfing | Phone numbers masked by default, revealed per record on tap |
| Accidental data spread | CSV export gated behind an explicit unencrypted-file warning |

### 9.3 Residual risks — state them, do not paper over them

1. Anyone with the link can submit a record. Mitigated by rate limiting and by admin approval,
   not eliminated.
2. Whoever completes setup first becomes the administrator. Mitigate by running §10.4
   immediately after deploy, or by setting `SETUP_TOKEN` beforehand.
3. A soldier who knows another soldier's personal number can overwrite that soldier's record
   while it is still `pending`. The admin sees the name on the submission, and approval closes
   the window.
4. Lost password ⇒ permanent data loss. This is the deliberate cost of the guarantee in §1.

---

## 10. Deployment runbook

### 10.1 Prerequisites

```bash
npm install -g wrangler
wrangler login
```

### 10.2 Push to GitHub

```bash
cd tzayad
git init
git add .
git commit -m "Equipment sign-out system"
git branch -M main
git remote add origin git@github.com:USERNAME/tzayad.git
git push -u origin main
```

Use a private repository. The code holds no secrets, but there is no reason to publish it.

### 10.3 Create D1 and deploy

```bash
wrangler d1 create tzayad
# copy the returned database_id into wrangler.toml
wrangler d1 execute tzayad --remote --file=./schema.sql
git commit -am "Add D1 database id" && git push
```

Cloudflare dashboard → **Workers & Pages → Create → Pages → Connect to Git**:

| Setting | Value |
|---|---|
| Framework preset | None |
| Build command | *(empty)* |
| Build output directory | `public` |

Then **Settings → Bindings → Add → D1 database**: variable `DB`, database `tzayad`, added to
both Production and Preview. Redeploy so the binding takes effect.

### 10.4 First run (do this before sharing the link)

1. Open the deployment URL.
2. **כניסת מנהל** → choose a password of 10+ characters → confirm → acknowledge no-recovery.
3. Store the password in a password manager or a physical safe.
4. Optional: set `SETUP_TOKEN` in Pages environment variables *before* first deploy to require
   `X-Setup-Token` on `/api/setup`.
5. Optional: attach a custom domain under **Custom domains** — a short URL survives WhatsApp
   better than `*.pages.dev`.

### 10.5 Local development

```bash
npm install
npm run db:init:local
npm run dev          # wrangler pages dev public --d1 DB=tzayad
```

---

## 11. Operations

### 11.1 During the issue session

One phone passed down the line, or the link broadcast to the unit. Admin keeps the
"ממתין לאישור" tab open and approves in batches; **רענון** refetches.

### 11.2 Returns

"מעקב ציוד" → filter **ציוד בחוץ** → find the soldier → **זיכוי ציוד** for partial credit
(magazine counts) or **זיכוי מלא** when everything comes back at once.

### 11.3 Password rotation and loss

Rotation re-wraps the same private key under a new KEK and invalidates every session; records
are not re-encrypted, so it is instant regardless of record count. There is no recovery path
for a lost password — the only remedy is **מחיקת כל הנתונים** and starting over.

### 11.4 End of exercise

Export CSV if a paper trail is required, store it under whatever handling rules apply to
personal data in your unit, then run **מחיקת כל הנתונים** to clear records, keys, sessions,
and rate-limit rows.

---

## 12. Acceptance tests

Run all of these against a preview deployment before sharing the link.

### 12.1 Cryptography

- [ ] Seal → open round-trips a payload containing Hebrew text without corruption.
- [ ] The same personal number always derives the same `rid`; a different one derives a different `rid`.
- [ ] A wrong password fails to unwrap the private key (AES-GCM throws; no partial output).
- [ ] Flipping one bit of a stored `ct` causes a decryption failure that surfaces as a damaged record.

### 12.2 API

- [ ] `GET /config` returns `{ready:false}` before setup and never exposes `wrapped_key`.
- [ ] A second `POST /setup` returns 409.
- [ ] Resubmitting a `pending` record succeeds; resubmitting after approval returns 409.
- [ ] `GET /admin/records` without a session cookie returns 401.
- [ ] A wrong verifier returns 401; nine rapid attempts return 429.
- [ ] `PUT /admin/records/:rid` with `status:"hacked"` returns 400.
- [ ] A POST carrying a foreign `Origin` header returns 403.
- [ ] `POST /admin/rotate` invalidates existing sessions (subsequent calls return 401).

### 12.3 UI

- [ ] Full soldier flow on a phone, in Hebrew, one-handed, under 60 seconds.
- [ ] Equipment rows respond to keyboard activation and expose `aria-checked`.
- [ ] Admin approval moves a record from the pending tab to the tracking tab.
- [ ] Partial credit of magazines updates both the card and the summary totals.
- [ ] Full credit flips the record to "הוחזר במלואו" and it disappears under the "ציוד בחוץ" filter.
- [ ] CSV opens in Excel with Hebrew intact (BOM present).
- [ ] Idle for 10 minutes locks the console and clears the key.
- [ ] Browser console shows **no CSP violations** on any screen — this catches stray inline styles.

### 12.4 Data-leak checks

- [ ] `wrangler d1 execute tzayad --remote --command "SELECT * FROM records LIMIT 3"` shows no
      name, personal number, or phone in any column.
- [ ] Network tab during a soldier submission shows no plaintext personal data in any request body.
- [ ] No requests to any host other than the deployment origin.

---

## 13. Planned extensions (not in v1)

| Idea | Sketch |
|---|---|
| Finger signature | Capture a canvas signature, store the PNG as base64 inside the sealed payload — no schema change needed |
| Platoon / squad field | Add to the payload and to CSV; group the tracking view by it |
| Serial numbers | Extend `items` to `{t, r, sn: []}` for helmets and vests |
| Live status for soldiers | Requires per-soldier keys; deliberately deferred, it doubles the crypto surface |
| Print view | An A4 stylesheet of outstanding equipment for the quartermaster's clipboard |

Any extension that would put plaintext personal data on the server is out of scope by
definition — it breaks the guarantee the whole design exists to provide.
