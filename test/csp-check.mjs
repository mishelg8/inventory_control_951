// The app ships under a strict CSP: no inline style attributes, no inline
// event handlers, no remote origins. Each of these has been introduced by
// accident at least once, so the build refuses them rather than the browser.
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
// Every file the browser actually loads. A module added under lib/ without
// being listed here would be the one place an inline style could slip back in.
const files = [
  'public/app.js', 'public/index.html', 'public/styles.css', 'public/sw.js',
  ...readdirSync(join(root, 'public/lib')).filter((f) => f.endsWith('.js')).map((f) => `public/lib/${f}`),
];
const problems = [];

for (const rel of files) {
  const src = readFileSync(join(root, rel), 'utf8');
  src.split('\n').forEach((line, i) => {
    const at = `${rel}:${i + 1}`;
    if (/\sstyle\s*=\s*["']/.test(line)) problems.push(`${at} inline style attribute`);
    if (/\son(click|load|error|change|submit)\s*=/.test(line)) problems.push(`${at} inline event handler`);
    if (/https?:\/\/(?!wa\.me|github\.com|tzayad\.pages\.dev)[a-z]/i.test(line) &&
        !line.trimStart().startsWith('//') && !line.trimStart().startsWith('*')) {
      problems.push(`${at} external origin: ${line.trim().slice(0, 70)}`);
    }
  });
}

if (problems.length) {
  console.error('CSP violations:\n' + problems.map((p) => '  ' + p).join('\n'));
  process.exit(1);
}
console.log(`CSP check passed across ${files.length} files`);
