#!/usr/bin/env node
// Python merge gate, dead-minion rule: a ledgered EQUIVALENT mutant that a test KILLED in this run
// is evidence of a nondeterministic killer (the equivalence proof says no test can tell it from the original), not a gap in the
// ledger. mutation-merge.mjs fails such an entry as STALE; this wraps it:
//   node stale-killed.mjs <merge.log> <reports-dir> <merge exit code>     (exit code 0: nothing to do)
// Fails (exit 1) unless the merge failed ONLY by STALE ("no survivor at this site") lines, none of its survivors was unlisted, and
// every one of those lines is a mutant in a shard's killed-equivalents-<k>.json (site records written by mutmut-survivors.py).
// A stale entry whose mutant was not generated, or was generated but not killed, still fails. Each excused entry is a ::notice::
// naming it; the shards' decided.tsv (mut-results artifact) names the killing test.
//   node stale-killed.mjs --selftest        both cases on a small fixture (the merge runs it first: a control that must hold)
import fs from 'node:fs';
import path from 'node:path';

const STALE = /^STALE \(no survivor at this site; killed or changed, remove it\): (\S+?)\/(\S+?\.py):(\S+) (?:\(#(\d+)\) )?in (\S+): (.*)$/; // the rest is `<mutant[0..90]> | <line[0..70]>`, compared whole (either part can contain ' | ')

export function judge(log, killed, code) {
  if (code === 0) return { ok: true, notices: [], errors: [] };
  const lines = log.split('\n').map((l) => l.replace(/^\S+Z /, '').replace(/^##\[error\]/, '')); // CI timestamps / annotations
  const stale = lines.map((l) => STALE.exec(l)).filter(Boolean);
  const tally = /unlisted survivors: (\d+); stale entries: (\d+)/.exec(log);
  const fail = /^FAIL: (\d+) problem\(s\); \d+ entries$/m.exec(log);
  const errors = [];
  if (!tally || !fail) errors.push('no ledger tally / FAIL count in the merge log (the merge failed before the ledger check)');
  else {
    if (Number(tally[1]) !== 0) errors.push(`${tally[1]} unlisted survivor(s)`);
    // every problem the checker counted must be one of the STALE lines excused here: any other error shape (survivor site matches N
    // entries, UNPLACEABLE SURVIVOR, source file gone, multiplicity, ...) raises the count above them
    if (Number(fail[1]) !== stale.length || Number(tally[2]) !== stale.length || stale.length === 0) {
      errors.push(`the checker counted ${fail[1]} problem(s) and ${tally[2]} stale entr(ies), but ${stale.length} STALE line(s) are excusable`);
    }
  }
  const notices = [];
  for (const m of stale) {
    const [, , file, , occ, fn, rest] = m;
    const hit = killed.find((k) => k.file === file && k.fn === fn && `${k.mutant.slice(0, 90)} | ${k.line.slice(0, 70)}` === rest && (!occ || String(k.occurrence) === occ));
    if (hit) notices.push(`::notice::equivalent entry killed this run (nondeterministic killer): ${file} ${fn}: ${rest} (${hit.name})`);
    else errors.push(`stale entry, no such mutant killed this run: ${file} ${fn}: ${rest}`);
  }
  return { ok: errors.length === 0, notices, errors };
}

function selftest() {
  const rec = { crate: 'python-pca', file: 'atlas_pca/pca.py', fn: 'f', mutant: 'f: x = 2', line: 'x = 1', occurrence: 1, name: 'atlas_pca.pca.x_f__mutmut_3' };
  const stale = (rest) => `STALE (no survivor at this site; killed or changed, remove it): python-pca/atlas_pca/pca.py:9 (#1) in f: ${rest}`;
  const one = stale('f: x = 2 | x = 1');
  // the merge log's tail: the checker's lines, then its FAIL count and the tally
  const tail = (problems, u, s) => `FAIL: ${problems} problem(s); 5 entries\nledger entries for python-pca: 5; unlisted survivors: ${u}; stale entries: ${s}\n`;
  const t = (name, r, ok) => { if (r.ok !== ok) { console.error(`stale-killed selftest FAILED: ${name}: ${JSON.stringify(r)}`); process.exit(1); } return r; };
  const r1 = t('killed equivalent is a notice', judge(`${one}\n${tail(1, 0, 1)}`, [rec], 1), true);
  if (r1.notices.length !== 1 || !r1.notices[0].startsWith('::notice::equivalent entry killed this run (nondeterministic killer)')) { console.error('selftest: no notice'); process.exit(1); }
  t('not killed (not generated / survived elsewhere) stays stale', judge(`${one}\n${tail(1, 0, 1)}`, [], 1), false);
  t('another mutant killed does not excuse it', judge(`${one}\n${tail(1, 0, 1)}`, [{ ...rec, mutant: 'f: x = 3' }], 1), false);
  t('an unlisted survivor still fails', judge(`${one}\nUNLISTED SURVIVOR: a\n${tail(2, 1, 1)}`, [rec], 1), false);
  t('a source-line-gone stale still fails', judge(`STALE (source line gone): python-pca/atlas_pca/pca.py:9 in f: m | l\n${tail(1, 0, 1)}`, [rec], 1), false);
  // any error shape the checker counts beyond the excused STALE lines: FAIL count above the STALE lines fails
  for (const other of ['survivor site matches 2 ledger entries: x', 'UNPLACEABLE SURVIVOR: y', 'source file gone: z', 'multiplicity 3 but 2 survivors: w']) {
    t(`stale + "${other}" fails`, judge(`${one}\n${other}\n${tail(2, 0, 1)}`, [rec], 1), false);
  }
  t('no FAIL count fails', judge(`${one}\nledger entries for python-pca: 5; unlisted survivors: 0; stale entries: 1\n`, [rec], 1), false);
  // ' | ' inside the mutant or the line text: matched whole, not split
  const pipe = { ...rec, mutant: 'f: a = b | c | d', line: 'a = b | c' };
  t("' | ' in the source text is excused when killed", judge(`${stale('f: a = b | c | d | a = b | c')}\n${tail(1, 0, 1)}`, [pipe], 1), true);
  t("' | ' text of a different mutant is not excused", judge(`${stale('f: a = b | c | d | a = b | c')}\n${tail(1, 0, 1)}`, [{ ...pipe, mutant: 'f: a = b | c' }], 1), false);
  t('exit 0 passes', judge('', [], 0), true);
  console.log('stale-killed selftest ok');
}

if (process.argv[2] === '--selftest') selftest();
else if (process.argv[1] && import.meta.url === new URL(`file://${path.resolve(process.argv[1])}`).href) {
  selftest(); // the control first
  const [logFile, reports, code] = process.argv.slice(2);
  const killed = [];
  const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) walk(p); else if (/^killed-equivalents-\d+\.json$/.test(e.name)) killed.push(...JSON.parse(fs.readFileSync(p, 'utf8'))); } };
  if (fs.existsSync(reports)) walk(reports);
  const r = judge(fs.readFileSync(logFile, 'utf8'), killed, Number(code));
  for (const n of r.notices) console.log(n);
  for (const e of r.errors) console.log(`::error::${e}`);
  if (r.ok && Number(code) !== 0) {
    const f = path.join(reports, 'mutation-summary.json');
    try { const s = JSON.parse(fs.readFileSync(f, 'utf8')); s.verdict = 'pass'; s.excused_killed_equivalents = r.notices.length; fs.writeFileSync(f, JSON.stringify(s, null, 1) + '\n'); } catch { /* summary is evidence only */ }
  }
  process.exit(r.ok ? 0 : 1);
}
