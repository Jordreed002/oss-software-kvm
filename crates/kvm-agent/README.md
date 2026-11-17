# Replacement agent development host

This process provides read-only status. It starts no input capture, injection,
discovery or legacy runtime. Pause, Resume, Failsafe and Quit commands are rejected.
An idle snapshot has unknown input destination and unconfirmed prerequisites.

Build from the repository root with `cargo build --locked -p kvm-agent`.
Run `target/debug/kvm-agent serve` in one terminal and
`target/debug/kvm-agent status` in another, adding `.exe` on Windows.
Status prints a bounded JSON snapshot reply and exits nonzero on failure.
Ctrl+C stops the development server. There is no installed background service,
login item or detached graceful shutdown mechanism in this increment.

Windows uses a session-scoped named pipe. Unix uses a private directory under
the process's temporary directory, or `serve --runtime-dir /absolute/path` for
an explicit server directory. The status command uses the default directory;
set the same `TMPDIR` for both processes when isolating a Unix test. Endpoint
checks establish user/session identity, not signed application identity.

Each client verifies the native endpoint before Hello, learns the instance ID
from Hello and binds its snapshot request to that ID. It checks the returned
instance and request ID. The server permits eight requests and a two-second
total connection lifetime. Requests must follow request/reply lockstep.
Repeated Hello or excess requests close without a reply, and unread pipelined
responses can be discarded. Failure never produces a fabricated idle snapshot.

Current evidence covers software tests, native Windows/Linux/macOS endpoint round
trips and separate-process Windows/Linux status smoke checks. The Darwin ACL fixture
also passed on native Apple Silicon. Installed lifecycle, physical input and
performance acceptance remain pending.
