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
