#!/usr/bin/env node
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { cpus, platform, arch, release, totalmem } from 'node:os';
import { mkdir, realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const exec = promisify(execFile);
export const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
export const help = `Usage: node scripts/performance/collect-baseline.mjs [--output PATH.json | --stdout]
Default: JSON on stdout. Files must be new .json files. Within this repository,
only target/performance is allowed. No capture, benchmark, installation or configuration changes.
`;

export function parseArgs(args) {
  if (args.length === 1 && ['--help', '-h'].includes(args[0])) return { help: true };
  if (!args.length || (args.length === 1 && args[0] === '--stdout')) return {};
  if (args.length === 2 && args[0] === '--output' && args[1] && !args[1].startsWith('-')) return { output: args[1] };
  throw new Error('Expected --stdout, --output PATH.json, or --help');
}

// No shell, bounded time/output, and no command output containing local paths in errors.
export async function probe(command, args, cwd = repository) {
  try {
    const { stdout } = await exec(command, args, {
      cwd, timeout: 3000, maxBuffer: 1024 * 1024, windowsHide: true,
      env: { ...process.env, GIT_OPTIONAL_LOCKS: '0' },
    });
    return { status: 'available', value: stdout.trim() };
  } catch (error) {
    return { status: 'unavailable', value: null, reason: error.killed ? 'timeout' : String(error.code ?? 'command_failed') };
  }
}

const unmeasured = (reason) => ({ status: 'unmeasured', value: null, reason });
export async function collect(run = probe) {
  const [sha, branch, changes, git, rustup, installed] = await Promise.all([
    run('git', ['rev-parse', 'HEAD']), run('git', ['branch', '--show-current']),
    run('git', ['status', '--porcelain=v1', '--untracked-files=normal']),
    run('git', ['--version']), run('rustup', ['--version']), run('rustup', ['toolchain', 'list']),
  ]);
  // Explicit installed toolchain selection avoids rustup's project override auto-install.
  const toolchain = installed.status === 'available'
    ? installed.value.split(/\r?\n/).map(line => line.split(/\s+/)[0]).find(name => /^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(name))
    : undefined;
  const skipped = { status: 'unavailable', value: null, reason: 'no_installed_rustup_toolchain; direct shims not invoked' };
  const [rustc, cargo] = toolchain ? await Promise.all([
    run('rustup', ['run', toolchain, 'rustc', '--version', '--verbose']),
    run('rustup', ['run', toolchain, 'cargo', '--version']),
  ]) : [skipped, skipped];
  const cpu = cpus();
  return {
    schemaVersion: 1, collectedAt: new Date().toISOString(),
    git: { sha, branch, dirty: changes.status === 'available' ? changes.value.length > 0 : null, status: changes.status },
    machine: { os: platform(), osRelease: release(), arch: arch(), cpuModels: [...new Set(cpu.map(c => c.model))], logicalCpus: cpu.length, totalMemoryBytes: totalmem() },
    runtime: { node: process.version, v8: process.versions.v8 },
    toolchains: { git, rustup, installedRustToolchains: installed, probedRustToolchain: toolchain ?? null, rustc, cargo },
    benchmarks: Object.fromEntries(['frame_codec', 'frame_roundtrip', 'pointer_datagram_codec', 'tls_record', 'outbound_queue'].map(name => [name, unmeasured('Collector does not run benchmarks')])),
    measurements: Object.fromEntries(['physicalLatency', 'pointerJitter', 'energy', 'releaseLatency', 'queueAge', 'cpuUsage', 'memoryUsage', 'allocations', 'wakeups', 'widgetActivation'].map(name => [name, unmeasured('Requires a separate controlled measurement run')])),
  };
}

function inside(parent, child) {
  const relative = path.relative(parent, child);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

async function canonicalDestination(destination) {
  let ancestor = path.dirname(destination);
  const suffix = [path.basename(destination)];
  for (;;) {
    try { return path.join(await realpath(ancestor), ...suffix); }
    catch (error) {
      if (error.code !== 'ENOENT') throw error;
      suffix.unshift(path.basename(ancestor));
      const parent = path.dirname(ancestor);
      if (parent === ancestor) throw error;
      ancestor = parent;
    }
  }
}

export async function save(output, data, root = repository) {
  const destination = path.resolve(output);
  if (path.extname(destination).toLowerCase() !== '.json' || /[:]/.test(path.basename(destination))) throw new Error('Output must be a new .json file');
  const canonicalRoot = await realpath(root);
  const canonical = await canonicalDestination(destination);
  const allowed = path.join(canonicalRoot, 'target', 'performance');
  if ((inside(root, destination) && !inside(path.join(root, 'target', 'performance'), destination)) ||
      (inside(canonicalRoot, canonical) && !inside(allowed, canonical))) {
    throw new Error('Repository output is restricted to target/performance');
  }
  await mkdir(path.dirname(destination), { recursive: true });
  // Exclusive creation also rejects existing files, hardlinks and final symlinks.
  await writeFile(destination, `${JSON.stringify(data, null, 2)}\n`, { flag: 'wx' });
}

export async function main(args = process.argv.slice(2)) {
  const options = parseArgs(args);
  if (options.help) { process.stdout.write(help); return; }
  const data = await collect();
  if (options.output) await save(options.output, data);
  else process.stdout.write(`${JSON.stringify(data, null, 2)}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { process.stderr.write(`baseline: ${error.message}\n`); process.exitCode = 1; });
}
