# Native control endpoint security checkpoint

These endpoints are prototypes. Do not expose mutating commands until the remaining authorization and protocol gates below are satisfied. User identity is not installed-application identity.

## Native Darwin verification at f0a6321

The linked Apple Silicon Mac executed the exact source archive for `f0a632102168d5f8203f92772f8b7832bb99565f`, SHA-256 `10a4db911e41b80759ce0ab903dbe992445ab9e2b5f3b102a4c4e08611ec2fd1`, on macOS 27.0.1 and Rust/Cargo 1.97.1. All 107 focused tests passed, including `private_fixture_acl_policy` and `status_roundtrip_uses_verified_native_socket`; strict all-target clippy passed offline. The canonical status socket was 90 bytes. No dependencies downloaded, and the source artifact's 413 files remained unchanged. The original Mac checkout and its four modified files were preserved byte-for-byte.

This supersedes earlier pending-native-Darwin notes for these ACL/socket tests. It does not certify signed application identity, hostile-user access policies, installed lifecycle, native capture/injection, physical latency or a release. Final Opus review accepted the API and owner for read-only prototype status; mutating command exposure remains gated.

## Windows review and corrections

Follow-up Opus review of `6ccda8d` accepted the account/session checks for read-only status integration. It did not accept mutating commands or claim process-signature, elevation, Low-IL or second-user acceptance. Coordinator subsequently normalized peer-verification failures to `PermissionDenied` while retaining the native error source, disconnected clients on listener-replacement failures, forced disconnect on listener Drop, and strengthened the PID-zero error test. A new slow-reader regression proves that an owner waiting for client EOF preserves the final reply before forced disconnect. This is a required owner protocol pattern, not an automatic guarantee supplied by writing a frame.

Current coordinator Windows evidence after these corrections: fourteen IPC tests and strict all-target clippy pass. Rebind/backoff, logon-token policy, integrity read-back and physical/elevated-client evidence remain outstanding. The reviewed read-only route must impose per-connection deadlines and finite lifetime and must represent lost replies as unknown.

Opus reviewed `windows.rs` at `dcd1466` and local Tokio/mio implementation details. It accepted FFI lifetimes/alignment, token/SID/descriptor ownership, the protected user/SYSTEM DACL and fail-closed first-instance collision behavior for the stated prototype. No additional native tests were run by that review.

Coordinator corrections after review:

- A connection's Drop explicitly disconnects before releasing its stream, preventing a stalled pending write from indefinitely pinning a server instance. A regression test keeps the nonreading client's handle live while a replacement client completes a frame roundtrip.
- A listener becomes poisoned before awaiting connection/rotation. Any cancellation or terminal error requires recreation; a later accept cannot reuse a half-completed client. The timeout regression test verifies rejection after cancellation.
- The descriptor explicitly names its owner and includes a Medium integrity no-read-up/no-write-up mandatory label. Creation succeeds on this Windows process. Low-integrity denial has not yet been tested.

Current Windows evidence: nine IPC tests pass; strict all-target clippy passes. This is not proof of every ACL principal, session policy or signed client identity.

Remaining before mutation exposure:

1. Client verifies server process/user/session and rejects foreign endpoint owners before sending sensitive messages.
2. Server validates client process/session and the approved integrity policy beyond the current DACL.
3. Session-scoped namespace/logon-SID policy and explicit collision diagnostics.
4. API first-message/busy behavior and bounded client/server deadlines.
5. Read-back ACL/owner/label checks; low-integrity and second-user/squatter tests; loopback remote rejection; connection churn and cancellation/retry tests.
6. Clear process-identity policy. Same-user malicious code is not excluded by an account SID or predictable pipe name.

## Unix and macOS prototype

### Canonical path and ACL review, 2026-11-17

Opus accepted the current canonical ancestor checks, direct symlink refusal and lifetime-lock/stale-recovery ordering for Linux read-only prototype status. The new path checks operate on canonical absolute paths and reject untrusted writable ancestors. Same-UID malicious replacement remains outside this prototype boundary.

The review found that Darwin returns NULL with ENOENT for an existing object without an extended ACL. The initial guard incorrectly rejected that normal case. Coordinator corrected retrieval to clear thread-local errno, accept only NULL/ENOENT as absent ACL, and keep other failures closed. Path checks take metadata before retrieval and recheck device/inode and symlink status afterward, so a vanished path cannot pass as an absent ACL. The lock-file descriptor remains open through its ACL check. The macOS fixture now covers absent directory and descriptor ACLs and missing-path refusal as well as deny/allow policy.

Primary source for absent-ACL behavior: Apple's [ACL retrieval implementation](https://github.com/apple-oss-distributions/Libc/blob/main/posix1e/acl_file.c) and [FILESEC_ACL property lookup](https://github.com/apple-oss-distributions/Libc/blob/main/gen/filesec.c).

After correction, focused Windows tests and strict host/Apple Silicon all-target clippy passed. Linux's fifteen IPC tests and the lifecycle/foundation tests passed again. This does not close native macOS acceptance: execute the ACL fixture and bind/connect tests under the real Darwin temporary directory before claiming macOS runtime support. No mutation exposure is accepted by this checkpoint.

Current integration addendum: `6ccda8d` implements Windows client/server peer PID-to-SID/session checks, session-scoped endpoint names and a bounded verified connector. Coordinator actual-workspace Windows tests pass with 12 cases and strict clippy; the macOS cross-target check also passes. These changes have not yet received the follow-up Opus security review. They establish the implemented account/session checks, not signed binary identity or second-user/Low-IL acceptance. The numbered Windows gates above record the original review and remain open where additional evidence is required.

The Unix listener creates or validates a user-owned directory without group/other permissions, binds a 0600 socket, checks accepted peer UID, limits accepted connections and deletes only its own matching socket inode on Drop. Existing socket paths are never unlinked to obtain ownership.

The caller must select a stable application-owned directory beneath trusted ancestors. The prototype does not validate the entire ancestor chain against concurrent rename or identify a signed application. `19f54d8` adds a connector checking directory/socket type, user ownership, permissions, server peer UID and unchanged socket inode across connection, with an asynchronous connect deadline. This is user-boundary validation, not cryptographic application authentication. Stale socket recovery and user-session policy need owner-level design.

Installed the Rust standard library target `aarch64-apple-darwin` and cross-checked this crate with `cargo check -p kvm-agent-ipc --target aarch64-apple-darwin --tests` and strict cross-target clippy. This checks source/tests against macOS types; it does not link, launch or run them on macOS.

Actual Linux execution is now verified under the existing Ubuntu WSL distribution. An isolated Rust installation and build output live beneath ignored `target/wsl-tools` and `target/wsl-check`; the shell PATH was not permanently modified. Linux rustc is 1.100.0, versus Windows rustc 1.97.1, so these are correctness checks and cannot support controlled cross-platform performance comparisons. With the new Rust toolchain, one test assertion needed updating for a newly enforced clippy lint in `ac748d8`.

The coordinator ran locked tests for `kvm-agent-ipc`, `kvm-agent-model` and `kvm-foundation`: nine Linux IPC tests, fourteen lifecycle tests, twenty-three foundation tests and one allocation integration test passed. Strict all-target clippy for the same packages passed after the test-only correction. Unix tests execute actual local socket connections, private-directory rejection, collision refusal, connector symlink/budget rejection and replacement-file preservation. They do not exercise different-user access, native input or macOS runtime behavior.
