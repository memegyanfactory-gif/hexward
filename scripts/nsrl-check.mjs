// Weekly known-good check: is any hash Hexward flags as malware actually a known-good file?
//
// NIST's NSRL sets are tens of gigabytes, too big for the free CI runner, so this asks CIRCL's free
// hashlookup service (https://hashlookup.circl.lu), which includes the NSRL and other known-good
// sources, about every hash Hexward ships: the built-in list (rules/hashes.txt) and the confirmed
// community database. A hit means a false alarm waiting to happen; the run fails and lists it.
//
// Usage: node scripts/nsrl-check.mjs [--out report.md]
import { readFileSync, writeFileSync } from 'node:fs';

const COMMUNITY = 'https://hexward.onurilabs.com/shared/db/hexward-db.json';
const LOOKUP = 'https://hashlookup.circl.lu/lookup/sha256/';
const MAX = 5000;
const out = process.argv.includes('--out') ? process.argv[process.argv.indexOf('--out') + 1] : null;

const hashes = new Map(); // sha256 -> where it comes from
for (const line of readFileSync(new URL('../rules/hashes.txt', import.meta.url), 'utf8').split(/\r?\n/)) {
  const m = line.match(/^\s*([a-fA-F0-9]{64})\s*(?:,(.*))?$/);
  if (m) hashes.set(m[1].toLowerCase(), `rules/hashes.txt: ${m[2] || ''}`.trim());
}
try {
  const db = await (await fetch(COMMUNITY)).json();
  for (const h of db.hashes || []) if (/^[a-f0-9]{64}$/i.test(h.sha256)) hashes.set(h.sha256.toLowerCase(), `community v${db.version}: ${h.name}`);
} catch (e) {
  console.error(`Community database not reachable (${e.message}); checking the built-in list only.`);
}

const list = [...hashes.keys()].slice(0, MAX);
const known = [];
let errors = 0;
async function check(h) {
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const r = await fetch(LOOKUP + h, { headers: { accept: 'application/json', 'user-agent': 'hexward-nsrl-check' } });
      if (r.status === 404) return;
      if (r.ok) {
        const j = await r.json();
        if (!j.message) known.push({ h, from: hashes.get(h), name: j.FileName || j['FileName'] || '?', source: j.source || (j.ProductCode ? 'NSRL' : 'hashlookup'), trust: j['hashlookup:trust'] });
        return;
      }
    } catch {}
    await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
  }
  errors++;
}
for (let i = 0; i < list.length; i += 4) await Promise.all(list.slice(i, i + 4).map(check));

const lines = [
  '# Known-good check',
  '',
  `Checked ${list.length} malware hashes Hexward ships against CIRCL hashlookup (includes the NSRL) on ${new Date().toISOString().slice(0, 10)}.`,
  '',
  known.length ? '| SHA-256 | Hexward calls it | Known-good as | Source |\n|---|---|---|---|\n' + known.map(k => `| \`${k.h}\` | ${k.from} | ${k.name} | ${k.source} |`).join('\n') : 'No hash Hexward flags is a known-good file.',
  errors ? `\n${errors} lookups failed after retries.` : ''
];
if (out) writeFileSync(out, lines.join('\n') + '\n');
console.log(lines.join('\n'));
// Hits fail the run; lookup errors alone don't (the service may be busy).
process.exit(known.length ? 1 : 0);
