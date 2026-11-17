import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, mkdir, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { collect, parseArgs, probe, save } from './collect-baseline.mjs';

const cli = fileURLToPath(new URL('./collect-baseline.mjs', import.meta.url));
async function temporary(t) {
  const dir = await mkdtemp(path.join(tmpdir(), 'kvm-baseline-test-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}
test('arguments have a safe stdout default and reject ambiguous requests', () => {
  assert.deepEqual(parseArgs([]), {});
  assert.deepEqual(parseArgs(['--stdout']), {});
  assert.equal(parseArgs(['--output', 'some space/file.json']).output, 'some space/file.json');
  for (const args of [['--output'], ['--unknown'], ['--stdout', '--output', 'x'], ['--output', '--help']]) assert.throws(() => parseArgs(args));
});
test('missing tools produce unknown git state and explicit unmeasured values', async () => {
  const commands = [];
  const data = await collect(async (cmd, args) => {
    commands.push([cmd, args]);
    return { status: 'unavailable', value: null, reason: 'ENOENT' };
  });
  assert.equal(data.git.dirty, null);
  for (const metric of Object.values(data.measurements)) {
    assert.equal(metric.status, 'unmeasured'); assert.equal(metric.value, null);
  }
  assert.equal(data.measurements.physicalLatency.status, 'unmeasured');
  assert.equal(data.measurements.pointerJitter.status, 'unmeasured');
  assert.equal(data.measurements.energy.status, 'unmeasured');
  assert.ok(commands.every(([cmd]) => ['git', 'rustup'].includes(cmd)));
  assert.ok(!commands.some(([, args]) => args.includes('run')));
});
test('installed toolchains are explicitly selected, and dirty state is retained without filenames', async () => {
  const calls = [];
  const data = await collect(async (cmd, args) => {
    calls.push([cmd, args]);
    let value = 'version';
    if (args[0] === 'toolchain') value = 'stable-test-host (default)';
    if (args[0] === 'status') value = ' M private-file';
    return { status: 'available', value };
  });
  assert.equal(data.git.dirty, true);
  assert.ok(!JSON.stringify(data).includes('private-file'));
  assert.equal(calls.filter(([, args]) => args[0] === 'run' && args[1] === 'stable-test-host').length, 2);
});
test('file output preserves JSON, rejects source destinations and never replaces files', async t => {
  const dir = await temporary(t);
  const root = path.join(dir, 'repo'); await mkdir(root);
  await assert.rejects(save(path.join(root, 'source.json'), {}, root), /restricted/);
  await assert.rejects(save(path.join(root, 'target/performance/source.mjs'), {}, root), /json/);
  const output = path.join(root, 'target/performance/results with spaces.json');
  await save(output, { test: true }, root);
  assert.deepEqual(JSON.parse(await readFile(output, 'utf8')), { test: true });
  await assert.rejects(save(output, { changed: true }, root), { code: 'EEXIST' });
  assert.deepEqual(JSON.parse(await readFile(output, 'utf8')), { test: true });
  await save(path.join(dir, 'explicit-external.json'), {}, root);
});
test('symlinked output directory cannot bypass repository protection', async t => {
  const dir = await temporary(t);
  const root = path.join(dir, 'repo'); await mkdir(root);
  const alias = path.join(dir, 'alias');
  try { await symlink(root, alias, process.platform === 'win32' ? 'junction' : 'dir'); }
  catch (error) { if (error.code === 'EPERM') { t.skip('Symlink privilege unavailable'); return; } throw error; }
  await assert.rejects(save(path.join(alias, 'source.json'), {}, root), /restricted/);
});
test('probe reports missing commands without requiring native toolchains', async () => {
  assert.equal((await probe('kvm-nonexistent-tool-192749', [])).status, 'unavailable');
});
test('CLI help and errors work with no tools on PATH', () => {
  const env = { ...process.env, PATH: '' };
  assert.match(execFileSync(process.execPath, [cli, '--help'], { env, encoding: 'utf8' }), /Usage:/);
  assert.throws(() => execFileSync(process.execPath, [cli, '--bad'], { env, stdio: 'pipe' }), error => {
    assert.equal(error.status, 1); assert.equal(String(error.stdout), ''); assert.match(String(error.stderr), /baseline:/); return true;
  });
  const data = JSON.parse(execFileSync(process.execPath, [cli, '--stdout'], { env, encoding: 'utf8' }));
  assert.equal(data.schemaVersion, 1);
  assert.equal(data.git.dirty, null);
});
