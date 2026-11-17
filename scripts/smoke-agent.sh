#!/bin/sh
# Python supplies bounded subprocess waits and strict JSON validation.
set -eu
case "${1-}" in
  -h|--help) [ "$#" -eq 1 ] || exit 2
    echo 'Usage: sh scripts/smoke-agent.sh --run [--binary PATH]'
    echo 'Uses an already-built development binary and existing python3. No build/install/capture/UI. Private TMPDIR; two status queries; own child SIGINT with a five-second graceful deadline.'
    exit 0 ;;
  --run) shift ;;
  *) echo 'Explicit opt-in required: --run. Use --help for usage.' >&2; exit 2 ;;
esac
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
binary=$script_dir/../target/debug/kvm-agent
if [ "$#" -ne 0 ]; then
  [ "$#" -eq 2 ] && [ "$1" = --binary ] || { echo 'Invalid arguments.' >&2; exit 2; }
  binary=$2
fi
exec python3 - "$binary" <<'PY'
import json, os, pathlib, signal, stat, subprocess, sys, tempfile, time, uuid
binary = pathlib.Path(sys.argv[1]).resolve(strict=True)
if not binary.is_file() or not os.access(binary, os.X_OK):
    sys.exit('Binary must be an existing executable file.')
# Resolve system aliases before the native endpoint validates ancestors.
private = pathlib.Path(tempfile.mkdtemp(prefix='kvm-smoke-', dir='/tmp')).resolve()
identity = private.stat()
env = dict(os.environ, TMPDIR=str(private))
server = None
success = False

def interrupted(signum, frame):
    raise RuntimeError('Smoke interrupted')

signal.signal(signal.SIGINT, interrupted)
signal.signal(signal.SIGTERM, interrupted)

def live():
    if server.poll() is not None:
        raise RuntimeError('Own serve child exited; refusing foreign status')

def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result

try:
    with (private / 'serve.out').open('wb') as stdout, (private / 'serve.err').open('wb') as stderr:
        server = subprocess.Popen([str(binary), 'serve'], env=env, stdout=stdout, stderr=stderr,
                                  start_new_session=True)
    deadline = time.monotonic() + 10
    while True:
        live()
        if b'Development agent ready; input unavailable' in (private / 'serve.err').read_bytes():
            break
        if time.monotonic() >= deadline:
            raise RuntimeError('Own serve readiness timed out')
        time.sleep(.05)
    instance = None
    for query in range(2):
        live()
        reply = subprocess.run([str(binary), 'status'], env=env, capture_output=True,
                               timeout=5, check=True)
        live()
        data = json.loads(reply.stdout, object_pairs_hook=pairs)
        if type(data) is not dict or data['type'] != 'snapshot':
            raise ValueError('Expected snapshot object')
        s = data['snapshot']
        if (s['lifecycle'] != 'idle' or s['user_intent'] != 'paused'
                or s['input_destination'] != {'destination': 'unknown'}):
            raise ValueError('Unexpected idle state')
        expected = dict.fromkeys(('pause', 'resume', 'failsafe', 'quit'), 'unsupported')
        expected['snapshot'] = 'supported'
        if s['capabilities'] != expected:
            raise ValueError('Unexpected capabilities')
        current = s['instance']
        if type(current) is not str or uuid.UUID(current).int == 0:
            raise ValueError('Invalid instance UUID')
        if instance is not None and instance != current:
            raise ValueError('Instance changed')
        instance = current
    server.send_signal(signal.SIGINT)
    if server.wait(timeout=5) != 0:
        raise RuntimeError('Own serve child failed graceful shutdown')
    success = True
    print('PASS: two idle/paused snapshots from instance', instance, '; own child exited zero after SIGINT')
finally:
    if server is not None and server.poll() is None:
        server.kill()
        server.wait(timeout=5)
        print('Cleanup forcibly stopped own PID; graceful shutdown not proved.', file=sys.stderr)
    # Never recursively delete a supplied path. Check the private directory identity
    # and unlink only known, owned, non-symlink artifact/socket/lock paths.
    now = private.lstat()
    if (now.st_dev, now.st_ino, now.st_uid) != (identity.st_dev, identity.st_ino, os.getuid()) or not stat.S_ISDIR(now.st_mode):
        raise RuntimeError('Private directory identity changed; retained artifacts')
    runtime = private / 'software-kvm-agent'
    if runtime.exists() or runtime.is_symlink():
        st = runtime.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
            raise RuntimeError('Unsafe runtime cleanup path')
        for name, kind in [('control.sock', stat.S_ISSOCK), ('agent.lock', stat.S_ISREG)]:
            path = runtime / name
            try:
                st = path.lstat()
            except FileNotFoundError:
                continue
            if st.st_uid != os.getuid() or not kind(st.st_mode):
                raise RuntimeError('Unsafe runtime artifact')
            path.unlink()
        runtime.rmdir()
    for name in ('serve.out', 'serve.err'):
        path = private / name
        if path.exists() or path.is_symlink():
            st = path.lstat()
            if st.st_uid != os.getuid() or not stat.S_ISREG(st.st_mode):
                raise RuntimeError('Unsafe log artifact')
            path.unlink()
    private.rmdir()
PY
