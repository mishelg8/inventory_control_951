// A migration that exists but is not registered in schema_migrations will be
// re-run on the next deploy and throw on a duplicate column. Catch it here.
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const dir = join(root, 'migrations');
const files = readdirSync(dir).filter((f) => f.endsWith('.sql')).sort();
const latest = readFileSync(join(dir, files[files.length - 1]), 'utf8');

const missing = files
  .map((f) => f.replace(/\.sql$/, ''))
  .filter((name) => !latest.includes(`'${name}'`));

if (missing.length) {
  console.error(
    'These migrations are not registered in schema_migrations in the latest migration:\n' +
    missing.map((m) => '  ' + m).join('\n')
  );
  process.exit(1);
}
console.log(`All ${files.length} migrations registered`);
