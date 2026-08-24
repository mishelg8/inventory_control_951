// Unit tests for the pure logic that carries real consequences: serial-number
// safety, permission scoping, and the CSV encoding Excel needs. These are the
// parts where a silent regression means a lost weapon or a leaked screen.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel) => readFileSync(join(root, rel), 'utf8');

// The client is one entry file plus three leaf modules. The tests read the
// whole client as one string: what they check — that a register cannot be
// given another register's places, that every screen agrees with the Worker —
// is a property of the client as a whole, and should not have to know which
// file a declaration currently lives in.
const CLIENT = ['public/lib/catalog.js', 'public/lib/crypto.js', 'public/lib/clean.js', 'public/app.js'];
const app = CLIENT.map(read).join('\n');
const api = read('functions/api/[[path]].js');

// Lift a named function out of the bundle and evaluate it in isolation. The
// app has no build step and no module system, so this is how a pure helper
// gets tested without loading a browser.
function lift(src, name, deps = '') {
  const start = src.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} not found`);
  let depth = 0, i = src.indexOf('{', start), end = -1;
  for (; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}' && --depth === 0) { end = i + 1; break; }
  }
  return new Function(`${deps}\n${src.slice(start, end)}\nreturn ${name};`)();
}

test('editDistance flags a single mistyped digit', () => {
  const d = lift(app, 'editDistance');
  assert.equal(d('7145732', '7145732'), 0);
  assert.equal(d('7145732', '7145733'), 1);   // last digit wrong
  assert.equal(d('7145732', '714573'), 1);    // digit dropped
  assert.equal(d('7145732', '7145723'), 2);   // transposed — two edits
  assert.ok(d('7145732', '9000001') >= 2);
});

test('scopesFor grants only what the listed screens read', () => {
  const scopesFor = lift(api, 'scopesFor', `
    const TAB_NEEDS = ${api.match(/const TAB_NEEDS = \{[\s\S]*?\n\};/)[0].replace('const TAB_NEEDS = ', '')}
  `);
  assert.deepEqual([...scopesFor('["veh"]')], ['vault']);
  assert.deepEqual([...scopesFor('["pending"]')], ['records']);
  assert.deepEqual([...scopesFor('["faults"]')], ['reports']);
  // the overview reads everything, so granting it grants everything
  assert.equal(scopesFor('["over"]').size, 3);
  assert.equal(scopesFor('*').size, 3);
  // malformed input must fail closed, not open
  assert.equal(scopesFor('not json').size, 0);
  assert.equal(scopesFor('[]').size, 0);
});

test('csvCell quotes and escapes for Excel', () => {
  const csvCell = new Function(`return ${app.match(/const csvCell = [^;]+;/)[0].replace('const csvCell = ', '').replace(/;$/, '')}`)();
  assert.equal(csvCell('abc'), '"abc"');
  assert.equal(csvCell('a"b'), '"a""b"');       // embedded quote doubled
  assert.equal(csvCell('a,b'), '"a,b"');        // comma stays inside quotes
  assert.equal(csvCell(null), '""');
  assert.equal(csvCell(0), '"0"');              // zero is not empty
});

test('isUsername rejects anything that could become a wildcard', () => {
  const isUsername = new Function(`return ${api.match(/const isUsername = [^;]+;/)[0].replace('const isUsername = ', '').replace(/;$/, '')}`)();
  assert.ok(isUsername('admin.951'));
  assert.ok(isUsername('sagan_a-1'));
  assert.ok(!isUsername('*'));
  assert.ok(!isUsername('Admin'));          // uppercase would break comparison
  assert.ok(!isUsername('a'));              // too short
  assert.ok(!isUsername('a'.repeat(32)));   // too long
  assert.ok(!isUsername("bob'; DROP--"));
});

test('every mutating admin route is behind the viewer guard', () => {
  // The guard is a single check before the routes; if it ever moves below one,
  // that route becomes writable by a read-only account.
  const guard = api.indexOf("session.role === 'viewer' && method !== 'GET'");
  assert.notEqual(guard, -1, 'viewer write guard missing');
  for (const route of ["seg[1] === 'vault'", "seg[1] === 'records'", "seg[1] === 'users'"]) {
    assert.ok(api.indexOf(route) > guard, `${route} is routed before the viewer guard`);
  }
});

test('soldier submissions all spend a ticket', () => {
  // Every write reachable without signing in must present a ticket, or the
  // endpoint is open to scripted injection. Counting the calls against each
  // other rather than against a fixed number means adding a public form
  // cannot quietly skip it — which is exactly what adding the refuelling
  // report would otherwise have done.
  const publicWrites = (app.match(/await api\('\/(reports|records)'/g) || []).length;
  const tickets = (app.match(/ticket: await getTicket\(\)/g) || []).length;
  assert.ok(publicWrites >= 4, `the public forms should still be there, found ${publicWrites}`);
  assert.equal(tickets, publicWrites, 'a public write path is not spending a ticket');
  assert.ok(api.includes('spendTicket(db, b.ticket, now)'));

  // /docs is the exception and is bounded differently: it creates no row of
  // its own, so it can only attach to a record that already exists and is
  // still pending — and that record cost a ticket. Both guards must stay.
  const docs = api.slice(api.indexOf("seg[0] === 'docs'"));
  assert.ok(docs.includes('doc:${ip}'), 'the photo endpoint lost its rate limit');
  assert.ok(docs.includes('אין רשומה לצרף אליה צילום'), 'the photo endpoint no longer requires a record');
  assert.ok(docs.includes("owner.status === 'approved'"), 'the photo endpoint accepts writes after approval');
});

test('a register never accepts another register\'s kinds or places', () => {
  // The vault is written by whoever holds the public key, so an item arriving
  // with a foreign kind or a foreign location is an expected input, not an
  // impossible one. Two properties matter: it is coerced rather than kept,
  // and it never lands at home — an item that was out must not come back
  // reading as present on the shelf.
  const consts = app.match(/const LIFECYCLE = [\s\S]*?const NAMED_LOCS = \{[\s\S]*?\n\};/)[0];
  const regs = app.match(/const REGISTERS = \{[\s\S]*?\n\};/)[0];
  const helpers = `
    ${consts}
    ${regs}
    ${app.match(/const kindLocs = [\s\S]*?\n\};/)[0]}
    const asText = (v, n) => (typeof v === 'string' ? v.slice(0, n) : '');
    const asTime = (v) => (Number.isFinite(v) ? v : 0);
    const asDate = (v) => (typeof v === 'string' && /^\\d{4}-\\d{2}-\\d{2}$/.test(v) ? v : '');
    const rndId = () => 'id';
  `;
  const cleanRegItem = new Function(
    `${helpers}\n${app.match(/const cleanRegItem = [\s\S]*?\n\};/)[0]}\nreturn cleanRegItem;`
  )();
  const REGISTERS = new Function(`${helpers}\nreturn REGISTERS;`)();

  const comms = cleanRegItem(REGISTERS.comms);
  const armon = cleanRegItem(REGISTERS.armon);

  // a weapon smuggled into the signals store becomes the store's first kind
  assert.equal(comms({ kind: 'weapon', loc: 'armon' }).kind, 'radio');
  assert.equal(comms({ kind: 'weapon', loc: 'armon' }).loc, 'soldier');
  // and a radio smuggled into the armoury becomes a weapon
  assert.equal(armon({ kind: 'radio', loc: 'store' }).kind, 'weapon');
  assert.equal(armon({ kind: 'radio', loc: 'store' }).loc, 'soldier');
  // a weapon may not be sent on a mission even inside its own register
  assert.equal(armon({ kind: 'weapon', loc: 'mission' }).loc, 'soldier');
  // each register's own values survive untouched
  assert.equal(comms({ kind: 'battery', loc: 'vehicle' }).loc, 'vehicle');
  assert.equal(armon({ kind: 'tzelem', loc: 'mission' }).loc, 'mission');
  // an empty item rests at home, which is where a newly registered item is
  assert.equal(comms({}).loc, 'store');
  assert.equal(armon({}).loc, 'armon');
});

test('the client and the Worker agree on what each screen reads', () => {
  // The client hides a screen; the Worker refuses the data. If the two lists
  // ever drift, a screen is either unreachable or reachable without the
  // permission it needs.
  const clientTabs = [...app.match(/const TABS = \[[\s\S]*?\n\];/)[0]
    .matchAll(/\{ id: '(\w+)',\s*name: '[^']*',\s*needs: \[([^\]]*)\]/g)]
    .map(([, id, needs]) => [id, needs.replace(/['\s]/g, '').split(',').filter(Boolean).sort().join(',')]);
  const workerNeeds = new Function(
    `return ${api.match(/const TAB_NEEDS = \{[\s\S]*?\n\};/)[0].replace('const TAB_NEEDS = ', '').replace(/;$/, '')}`
  )();
  assert.equal(clientTabs.length, Object.keys(workerNeeds).length);
  for (const [id, needs] of clientTabs) {
    assert.ok(id in workerNeeds, `${id} is offered by the client but unknown to the Worker`);
    assert.equal(needs, [...workerNeeds[id]].sort().join(','), `${id} needs different data on each side`);
  }
});

test('a guarded action never calls another guarded action', () => {
  // withBusy refuses to run while another action is running — that is what
  // stops a double click from approving twice. The cost is that a guarded
  // helper called from inside a guarded action does not run either: it
  // returns as though it had worked, having done nothing. That is how filing
  // a refuelling report took the litres off the card on screen and never
  // saved the vault, which the next refresh then undid.
  //
  // So the rule is: inside withBusy, call the plain function (saveInv,
  // fetchTrash), never the wrapped one (invSave, loadTrash).
  const decls = [...app.matchAll(/const (\w+) = \([^)]*\) =>\n\s*withBusy\(async \(\) => \{/g)];
  const wrapped = new Set(decls.map(([, name]) => name));
  assert.ok(wrapped.size > 20, 'the guarded actions were not found — has the shape changed?');

  const offenders = [];
  for (const m of decls) {
    const start = m.index;
    // the body ends where the next top-level declaration begins
    const rest = app.slice(start + m[0].length);
    const end = rest.search(/\n(?:const|function|async function|\/\* ──) /);
    const body = rest.slice(0, end === -1 ? undefined : end);
    for (const other of wrapped) {
      if (other !== m[1] && new RegExp(`\\b${other}\\(`).test(body)) {
        offenders.push(`${m[1]} calls ${other}, which will decline to run`);
      }
    }
  }
  assert.deepEqual(offenders, []);
});

test('every part of the vault has a home, on both sides', () => {
  // The vault is stored one row per domain, and which keys go in which row is
  // declared once in the client. A key added to the inventory without being
  // added to that map is a key that is silently never saved: it would be
  // edited on screen, survive until the next reload, and then be gone.
  const invKeys = [...app.match(/const emptyInv = \(\) => \(\{[\s\S]*?\n\}\);/)[0]
    .matchAll(/(\w+):/g)].map(([, k]) => k);
  const parts = new Function(
    `return ${app.match(/const VAULT_PARTS = \[[\s\S]*?\n\];/)[0]
      .replace('const VAULT_PARTS = ', '').replace(/;$/, '')}`
  )();
  const housed = new Set(parts.flatMap(([, keys]) => keys));

  for (const key of invKeys) {
    assert.ok(housed.has(key), `${key} is in the vault but belongs to no part — it would never be saved`);
  }
  for (const key of housed) {
    assert.ok(invKeys.includes(key), `part map claims ${key}, which the vault does not have`);
  }

  // And the Worker only accepts the parts the client actually writes: an
  // unknown name would be stored and never read back.
  const serverParts = new Function(
    `return ${api.match(/const VAULT_PARTS = \[[\s\S]*?\n\];/)[0]
      .replace('const VAULT_PARTS = ', '').replace(/;$/, '')}`
  )();
  assert.deepEqual(
    parts.map(([p]) => p).sort(),
    [...serverParts].sort(),
    'the client and the Worker disagree about which parts exist'
  );
});

test('an incremental refresh merges without losing or duplicating a row', () => {
  // The console asks every few seconds for what changed rather than for
  // everything. Merging is where that can go wrong: a row updated twice must
  // not appear twice, a deleted one must actually leave, and rows nobody
  // touched must survive untouched.
  const mergeRows = new Function(
    `${app.match(/function mergeRows\(list, incoming, gone, key\) \{[\s\S]*?\n\}/)[0]}\nreturn mergeRows;`
  )();
  const highWater = new Function(
    `${app.match(/const highWater = [\s\S]*?;\n/)[0]}\nreturn highWater;`
  )();

  const held = [
    { rid: 'a', updated_at: 10, data: { name: 'א' } },
    { rid: 'b', updated_at: 20, data: { name: 'ב' } },
    { rid: 'c', updated_at: 30, data: { name: 'ג' } },
  ];

  // one row changed, one was deleted
  const after = mergeRows(held, [{ rid: 'b', updated_at: 40, data: { name: 'ב שונה' } }], ['c'], 'rid');
  assert.deepEqual(after.map((r) => r.rid), ['a', 'b']);
  assert.equal(after.find((r) => r.rid === 'b').data.name, 'ב שונה');
  assert.equal(after.find((r) => r.rid === 'a').data.name, 'א', 'an untouched row was disturbed');

  // a row that is new to us is added, once, even if the answer repeats it
  const grown = mergeRows(after, [{ rid: 'd', updated_at: 50 }, { rid: 'd', updated_at: 50 }], [], 'rid');
  assert.equal(grown.filter((r) => r.rid === 'd').length, 1);

  // the watermark is the newest thing we hold, and never goes backwards
  assert.equal(highWater(grown), 50);
  assert.equal(highWater([]), 0, 'an empty answer must not reset the watermark to nothing');

  // deleting something we never had is not an error
  assert.equal(mergeRows(grown, [], ['zzz'], 'rid').length, grown.length);
});

test('no module reaches for a name it cannot see', () => {
  // This is the test that was missing. openRecord took `clean = cleanRecord`
  // as a default, which was fine while everything was one file; once it moved
  // to crypto.js the default named something that module cannot see, so every
  // call relying on it threw. The console catches a failed open and marks the
  // row, so the screen said nine records were damaged on the server — while
  // the data was untouched and only the browser could not read it.
  //
  // An earlier check looked for `name(` and so saw calls but never a default
  // argument, a bare reference, or a value in an object. This one takes every
  // identifier a module mentions and insists it be defined there, imported, or
  // a global.
  const GLOBALS = new Set([
    'crypto', 'window', 'document', 'console', 'Math', 'JSON', 'Object', 'Array', 'String',
    'Number', 'Boolean', 'Date', 'Promise', 'Error', 'Set', 'Map', 'RegExp', 'Symbol',
    'TextEncoder', 'TextDecoder', 'Uint8Array', 'ArrayBuffer', 'Blob', 'File', 'FileReader',
    'Image', 'URL', 'atob', 'btoa', 'fetch', 'setTimeout', 'clearTimeout', 'setInterval',
    'clearInterval', 'isNaN', 'parseInt', 'parseFloat', 'undefined', 'null', 'true', 'false',
    'this', 'arguments', 'globalThis', 'Infinity', 'NaN', 'DataTransfer', 'PointerEvent', 'Event',
  ]);
  const KEYWORDS = new Set([
    'const', 'let', 'var', 'function', 'async', 'await', 'return', 'if', 'else', 'for', 'of',
    'in', 'while', 'do', 'break', 'continue', 'new', 'typeof', 'instanceof', 'try', 'catch',
    'finally', 'throw', 'switch', 'case', 'default', 'class', 'extends', 'super', 'import',
    'export', 'from', 'as', 'delete', 'void', 'yield', 'static', 'get', 'set',
  ]);

  for (const rel of ['public/lib/catalog.js', 'public/lib/crypto.js', 'public/lib/clean.js']) {
    const src = read(rel);
    const code = src
      .replace(/\/\*[\s\S]*?\*\//g, ' ')            // block comments
      .replace(/\/\/.*$/gm, ' ')                    // line comments, trailing ones included
      .replace(/`(?:[^`\\]|\\.)*`/g, '``')          // template literals, and what is in them
      .replace(/'(?:[^'\\]|\\.)*'/g, "''")
      .replace(/"(?:[^"\\]|\\.)*"/g, '""')
      // regex literals, whose flags would otherwise read as identifiers
      .replace(/(?<=[=(,:[!&|?{};]\s*)\/(?:[^/\\\n[]|\\.|\[(?:[^\]\\]|\\.)*\])+\/[gimsuy]*/g, ' ');

    const declared = new Set();
    for (const m of code.matchAll(/(?:const|let|var|function|class)\s+([A-Za-z_$][\w$]*)/g)) declared.add(m[1]);
    // parameters, destructuring and loop variables, roughly but generously
    for (const m of code.matchAll(/\(([^()]*)\)\s*(?:=>|\{)/g)) {
      for (const p of m[1].split(',')) {
        const n = p.trim().split(/[=:\s]/)[0].replace(/[{}[\].]/g, '');
        if (/^[A-Za-z_$][\w$]*$/.test(n)) declared.add(n);
      }
    }
    for (const m of code.matchAll(/(?:for\s*\(\s*(?:const|let|var)\s+|catch\s*\(\s*)([A-Za-z_$][\w$]*)/g)) declared.add(m[1]);
    // array destructuring: const [a, b] = … and for (const [a, b] of …)
    for (const m of code.matchAll(/(?:const|let|var)\s*\[([^\]]*)\]/g)) {
      for (const n of m[1].split(',')) {
        const id = n.trim().replace(/^\.\.\./, '').split(/[=\s]/)[0];
        if (/^[A-Za-z_$][\w$]*$/.test(id)) declared.add(id);
      }
    }
    for (const m of code.matchAll(/\{([^{}]*)\}\s*=/g)) {
      for (const p of m[1].split(',')) {
        const n = p.trim().split(/[:\s]/).pop();
        if (/^[A-Za-z_$][\w$]*$/.test(n)) declared.add(n);
      }
    }

    const imported = new Set();
    for (const m of code.matchAll(/import\s*\{([^}]*)\}/g)) {
      for (const n of m[1].split(',')) if (n.trim()) imported.add(n.trim());
    }

    const unknown = new Set();
    for (const m of code.matchAll(/(?<![.\w$])([A-Za-z_$][\w$]*)/g)) {
      const name = m[1];
      if (KEYWORDS.has(name) || GLOBALS.has(name) || declared.has(name) || imported.has(name)) continue;
      // `name:` is a key in an object literal, not a reference to anything
      if (/^\s*:/.test(code.slice(m.index + name.length))) continue;
      unknown.add(name);
    }
    assert.deepEqual([...unknown], [],
      `${rel} mentions ${[...unknown].join(', ')} — not defined there, not imported`);
  }
});

// The trust boundary works by omission: cleanRecord and cleanReport return a
// new object holding only the fields they name, so a field they do not name is
// silently dropped no matter who sent it. That is the point — but it cuts both
// ways, and it cut us. The refuelling form sealed `cardLabel` next to the card
// id so the office could read "דיזל · ••1111" without opening the vault; the
// cleaner had never heard of the field, dropped it on every single report, and
// the console fell back to printing thirty-two hex digits where a card number
// belonged. Nothing failed, nothing was logged; it simply read wrong.
//
// So: whatever the client seals, the cleaner must keep. This reads the payload
// literals the submit paths hand to seal() — the three report forms directly,
// and the sign-out form through `payload`, which is built up a field at a time.
test('every field the client seals is a field the cleaners keep', () => {
  const clean = read('public/lib/clean.js');
  const keys = new Set();

  // the object literals handed straight to seal(…, { … })
  for (const m of app.matchAll(/\bseal\((?:[^,()]|\([^()]*\))*,\s*\{/g)) {
    let i = m.index + m[0].length - 1;
    let depth = 0;
    const start = i;
    for (; i < app.length; i += 1) {
      if (app[i] === '{') depth += 1;
      else if (app[i] === '}' && (depth -= 1) === 0) break;
    }
    const body = app.slice(start + 1, i);
    // top level only: a nested `{ a: …, t: … }` inside a log entry is not a
    // field of the payload and has no business being whitelisted.
    let d = 0;
    for (const part of body.split(/,(?![^[{(]*[\]})])/)) {
      const k = part.trim().match(/^([A-Za-z_$][\w$]*)\s*:/);
      if (!d && k) keys.add(k[1]);
      for (const ch of part) d += ch === '{' || ch === '[' ? 1 : (ch === '}' || ch === ']' ? -1 : 0);
    }
  }

  // and the sign-out payload, which is a literal plus later assignments
  const lit = app.slice(app.indexOf('const payload = {'));
  for (const m of lit.slice(0, lit.indexOf('};')).matchAll(/^\s{6}([A-Za-z_$][\w$]*)[:,]/gm)) keys.add(m[1]);
  for (const m of app.matchAll(/\bpayload\.([A-Za-z_$][\w$]*)\s*=/g)) keys.add(m[1]);

  assert.ok(keys.has('cardLabel'), 'the scan found no payload fields — the regex has drifted');
  // `field:` names it; `{ field }` is the shorthand the optional licence block
  // is spread through. Either one counts as keeping it.
  const dropped = [...keys].filter(
    (k) => !new RegExp(`\\b${k}\\s*:|\\{\\s*${k}\\s*\\}`).test(clean)
  );
  assert.deepEqual(dropped, [],
    `sealed but not whitelisted in clean.js, so dropped on arrival: ${dropped.join(', ')}`);
});

test('a session never seals to a public key it has not just verified', () => {
  // Sealing needs only the public key, so using a stale one fails silently:
  // the ciphertext is well formed, the server takes it, and the loss surfaces
  // only when somebody reloads and a whole domain of the vault comes back
  // undecryptable. A tab left open across a key rotation is enough to do it,
  // and signing in again from that tab is what every auto-lock asks for.
  const login = app.slice(
    app.indexOf('async function loginSubmit'),
    app.indexOf('/* — admin record mutations — */')
  );
  assert.match(login, /S\.config = await api\('\/config'\)/,
               'login re-reads the public key from the server rather than trusting the page');
  assert.match(login, /keysAgree\(S\.pubKey, S\.priv\)/,
               'login proves the two halves are one pair');
  assert.ok(login.indexOf('keysAgree') < login.indexOf('loadInv('),
            'the pair is proven before the vault is opened or written');
});

test('a register movement is recorded wherever the move came from', () => {
  // The location is edited in place, so there is no single call site to hang a
  // log entry on. The save compares against the last saved state instead —
  // which is also why a new way to move an item cannot forget to log itself.
  const fn = app.slice(app.indexOf('function logMoves()'), app.indexOf('async function saveInv()'));
  assert.match(fn, /S\.invBase\[reg\.key\]/, 'it diffs against what was last written');
  assert.match(fn, /action: home \? 'return' : 'move'/, 'coming home is a return, not another move');
  assert.match(fn, /LOAN_LOCS\.has\(it\.loc\)/, 'a handover between two holders counts as a movement');
  // and the save must not be able to skip it
  const save = app.slice(app.indexOf('async function saveInv()'));
  assert.ok(save.indexOf('logMoves();') < save.indexOf('const dirty'),
            'movements are logged before the parts to write are chosen');
});

/* ── Kit signed by mistake ────────────────────────────────────────────
   Removing kit is not crediting it. A credit says the item went out and came
   back, and both movements are true. A removal says the line should never
   have existed — so it reduces what was taken, and the movement disappears
   from the store's arithmetic instead of being cancelled out by a return
   that never happened.

   Checked against the real function lifted out of app.js. */

function liftGearRemoved() {
  const src = readFileSync(join(root, 'public/app.js'), 'utf8');
  const from = src.indexOf('function gearRemoved(');
  const to = src.indexOf('const gearDelSave =');
  if (from < 0 || to < 0 || to < from) throw new Error('gearRemoved not found in app.js');
  return new Function(`${src.slice(from, to)}\n return gearRemoved;`)();
}

test('removing kit reduces what was taken, not what came back', () => {
  const gearRemoved = liftGearRemoved();
  const out = gearRemoved({ vest: { t: 3, r: 0 } }, [['vest', 1]]);
  assert.deepEqual(out, { vest: { t: 2, r: 0 } });
});

test('a line that never should have existed disappears entirely', () => {
  const gearRemoved = liftGearRemoved();
  const out = gearRemoved({ uniform: { t: 1, r: 0 }, vest: { t: 2, r: 0 } }, [['uniform', 1]]);
  assert.deepEqual(out, { vest: { t: 2, r: 0 } }, 'not a holding of zero — gone');
});

test('kit that has already come back cannot be un-taken', () => {
  const gearRemoved = liftGearRemoved();
  // two went out, two came back: there is nothing left to correct
  const out = gearRemoved({ mags: { t: 2, r: 2 } }, [['mags', 2]]);
  assert.deepEqual(out, { mags: { t: 2, r: 2 } }, 'a return with nothing to return is not reachable');
});

test('a partial credit leaves only the uncredited part removable', () => {
  const gearRemoved = liftGearRemoved();
  // three out, one back — at most two can have been a mistake
  const out = gearRemoved({ helmet: { t: 3, r: 1 } }, [['helmet', 3]]);
  assert.deepEqual(out, { helmet: { t: 1, r: 1 } });
});

test('an item with a credit against it is kept even when taken drops to it', () => {
  const gearRemoved = liftGearRemoved();
  const out = gearRemoved({ knee: { t: 2, r: 1 } }, [['knee', 5]]);
  assert.deepEqual(out, { knee: { t: 1, r: 1 } }, 'the credit still needs something to have gone out');
});

test('the original holding is left untouched, so a failed save can put it back', () => {
  const gearRemoved = liftGearRemoved();
  const before = { vest: { t: 3, r: 0 } };
  const out = gearRemoved(before, [['vest', 3]]);
  assert.deepEqual(before, { vest: { t: 3, r: 0 } }, 'edited a copy, not the record');
  assert.deepEqual(out, {});
});

test('an item that is not held, or a nonsense count, changes nothing', () => {
  const gearRemoved = liftGearRemoved();
  const before = { vest: { t: 1, r: 0 } };
  assert.deepEqual(gearRemoved(before, [['helmet', 2]]), before);
  assert.deepEqual(gearRemoved(before, [['vest', 0]]), before);
  assert.deepEqual(gearRemoved(before, [['vest', -3]]), before);
});

/* ── Completing a shortage request from the roster ────────────────────
   The shortage form never asks for a personal number, so the column is empty
   on most requests and somebody looks the soldier up by hand. The console
   holds the roster decrypted and can do it instead — but matching on a name
   is a guess, and the guess is only safe when it is unambiguous. Two soldiers
   with the same name must fill nothing: a wrong phone number sends the
   store-keeper to the wrong person with more confidence than the data
   deserves. */

function liftRoster() {
  const src = readFileSync(join(root, 'public/app.js'), 'utf8');
  const from = src.indexOf('const nameKey =');
  const to = src.indexOf('const REPORTS = {');
  if (from < 0 || to < 0 || to < from) throw new Error('roster helpers not found in app.js');
  const make = new Function('S', 'deptName',
    `${src.slice(from, to)}\n return { nameKey, rosterByName, fillFromRoster };`);
  return (recs) => make({ recs }, (id) => `מחלקה ${id}`);
}

const rec = (name, pn, phone, dept) => ({ data: { name, pn, phone, dept } });

test('a request missing its personal number is completed from the roster', () => {
  const R = liftRoster()([rec('דוד לוי', '8000001', '0501112222', 'p1')]);
  const out = R.fillFromRoster({ name: 'דוד לוי', text: 'חסר' }, R.rosterByName());
  assert.equal(out.pn, '8000001');
  assert.equal(out.phone, '0501112222');
  assert.equal(out.source, 'הושלם לפי שם');
});

test('what the soldier wrote himself is never overwritten', () => {
  const R = liftRoster()([rec('דוד לוי', '8000001', '0501112222', 'p1')]);
  const out = R.fillFromRoster({ name: 'דוד לוי', pn: '9999999', phone: '0509998888' }, R.rosterByName());
  assert.equal(out.pn, '9999999');
  assert.equal(out.phone, '0509998888');
  assert.equal(out.source, 'מהבקשה');
});

test('two soldiers with the same name fill nothing, and the sheet says so', () => {
  const R = liftRoster()([
    rec('דוד לוי', '8000001', '0501112222', 'p1'),
    rec('דוד לוי', '8000002', '0503334444', 'p2'),
  ]);
  const out = R.fillFromRoster({ name: 'דוד לוי' }, R.rosterByName());
  assert.equal(out.pn, '', 'a guess between two people is not made');
  assert.equal(out.phone, '');
  assert.match(out.source, /2 חיילים בשם הזה/);
});

test('a name with no record says so rather than looking complete', () => {
  const R = liftRoster()([rec('דוד לוי', '8000001', '0501112222', 'p1')]);
  const out = R.fillFromRoster({ name: 'מישהו אחר' }, R.rosterByName());
  assert.equal(out.source, 'לא נמצא ברישומים');
});

test('the same name spelled with a hyphen or a geresh still matches', () => {
  const R = liftRoster()([rec('ליאור בן־שושן', '8000011', '0501234567', 'p3')]);
  const idx = R.rosterByName();
  for (const written of ['ליאור בן שושן', 'ליאור בן-שושן', 'ליאור בן־שושן', '  ליאור   בן שושן ']) {
    const out = R.fillFromRoster({ name: written }, idx);
    assert.equal(out.pn, '8000011', `did not match: ${written}`);
  }
});

test('a partial request with no matching record keeps what it has', () => {
  const R = liftRoster()([]);
  const out = R.fillFromRoster({ name: 'לא במאגר', phone: '0501112222' }, R.rosterByName());
  assert.equal(out.phone, '0501112222');
  assert.equal(out.source, 'מהבקשה · חלקי');
});

test('a damaged or nameless record cannot poison the index', () => {
  const R = liftRoster()([
    { damaged: true, data: { name: 'דוד לוי', pn: 'X' } },
    { data: null },
    rec('', '8000003', '0505556666', 'p1'),
    rec('דוד לוי', '8000001', '0501112222', 'p1'),
  ]);
  const out = R.fillFromRoster({ name: 'דוד לוי' }, R.rosterByName());
  assert.equal(out.pn, '8000001', 'the damaged duplicate was not counted as a second soldier');
  assert.equal(out.source, 'הושלם לפי שם');
});
