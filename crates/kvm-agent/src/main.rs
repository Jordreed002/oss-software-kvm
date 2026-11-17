//! Development process host. No capture, injection or legacy runtime is started.

use std::{io, time::Duration};

const CONNECTION_LIFETIME: Duration = Duration::from_secs(2);
const REBIND_LIMIT: u32 = 5;

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    match run(&arguments).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            // Paths, SIDs, payloads and native error strings stay out of logs.
            eprintln!("Agent command failed: {:?}", error.kind());
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run(arguments: &[std::ffi::OsString]) -> io::Result<()> {
    if arguments.len() == 1 && arguments[0] == "status" {
        let snapshot = kvm_agent::client::query_native().await.map_err(|error| {
            use kvm_agent::client::StatusError;
            let kind = match error {
                StatusError::NotFound => io::ErrorKind::NotFound,
                StatusError::PermissionDenied => io::ErrorKind::PermissionDenied,
                StatusError::TimedOut => io::ErrorKind::TimedOut,
                StatusError::Incompatible | StatusError::InvalidReply => io::ErrorKind::InvalidData,
                StatusError::Transport => io::ErrorKind::ConnectionAborted,
            };
            io::Error::new(kind, "status query failed")
        })?;
        let reply = kvm_agent_api::ServerMessage::Snapshot(kvm_agent_api::SnapshotReply {
            correlation_id: kvm_agent_api::CorrelationId::new(1),
            snapshot,
        });
        let bytes = kvm_agent_api::encode_server(&reply)
            .map_err(|_| io::Error::other("status encoding failed"))?;
        let text =
            std::str::from_utf8(&bytes).map_err(|_| io::Error::other("status encoding invalid"))?;
        println!("{text}");
        return Ok(());
    }
    if arguments.first().is_none_or(|arg| arg != "serve") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "serve required",
        ));
    }
    #[cfg(windows)]
    {
        if arguments.len() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unexpected arguments",
            ));
        }
        serve().await
    }
    #[cfg(unix)]
    {
        if arguments.len() == 1 {
            return serve(&kvm_agent::client::runtime_directory()).await;
        }
        if arguments.len() != 3 || arguments[1] != "--runtime-dir" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime directory required",
            ));
        }
        serve(std::path::Path::new(&arguments[2])).await
    }
}

#[cfg(windows)]
async fn serve() -> io::Result<()> {
    use kvm_agent_ipc::windows::UserPipe;
    let agent = kvm_agent::Agent::new();
    let mut listener = UserPipe::bind("control")?;
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);
    let mut failures = 0;
    eprintln!("Development agent ready; input unavailable");
    loop {
        let accepted = tokio::select! {
            result = &mut shutdown => return result,
            result = listener.accept() => result,
        };
        if let Ok(mut connection) = accepted {
            failures = 0;
            let completed = tokio::select! {
                result = &mut shutdown => return result,
                result = agent.serve_connection(connection.stream(), CONNECTION_LIFETIME) => result,
            };
            if completed.is_ok() {
                failures = 0;
            }
            // Drop disconnects even stalled writers before the next accept.
            drop(connection);
        } else {
            // Windows accept errors poison the listener. Retire it before
            // bounded rebinding, including deferred overlapped close time.
            drop(listener);
            loop {
                failures += 1;
                if failures > REBIND_LIMIT {
                    return Err(io::Error::other("endpoint recovery exhausted"));
                }
                tokio::select! {
                    result = &mut shutdown => return result,
                    () = tokio::time::sleep(Duration::from_millis(50 * u64::from(failures))) => {}
                }
                if let Ok(replacement) = UserPipe::bind("control") {
                    listener = replacement;
                    failures = 0;
                    break;
                }
            }
        }
    }
}

#[cfg(unix)]
async fn serve(directory: &std::path::Path) -> io::Result<()> {
    let agent = kvm_agent::Agent::new();
    let listener = kvm_agent_ipc::unix::UserSocket::bind(directory).await?;
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);
    let mut failures = 0;
    eprintln!("Development agent ready; input unavailable");
    loop {
        let accepted = tokio::select! {
            result = &mut shutdown => return result,
            result = listener.accept() => result,
        };
        if let Ok(mut connection) = accepted {
            failures = 0;
            let completed = tokio::select! {
                result = &mut shutdown => return result,
                result = agent.serve_connection(connection.stream(), CONNECTION_LIFETIME) => result,
            };
            if completed.is_ok() {
                failures = 0;
            }
        } else {
            failures += 1;
            if failures > REBIND_LIMIT {
                return Err(io::Error::other("endpoint admission exhausted"));
            }
            // Unix accept is recoverable; keep the lifetime lock held.
            tokio::select! {
                result = &mut shutdown => return result,
                () = tokio::time::sleep(Duration::from_millis(50 * u64::from(failures))) => {}
            }
        }
    }
}
