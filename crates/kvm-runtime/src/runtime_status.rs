//! Redacted, advisory status publication for the local control panel.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::Serialize;

// Only the macOS/Windows platform binaries construct a publisher and write the
// status file; on other targets these would be dead code (clippy `-D warnings`
// under `dead-code`). Gate them to the platforms that actually use them.
#[cfg(any(target_os = "macos", windows))]
pub(crate) const RUNTIME_STATUS_FILE: &str = "runtime.status";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuntimeServicePhase {
    Starting,
    Running,
    Stopping,
    Faulted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuntimeInputOwner {
    Local,
    Peer,
    Transitioning,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuntimeRoutingState {
    Enabled,
    Gated,
    WaitingForWorkspace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct RuntimeStatusSnapshot {
    schema_version: u16,
    service: RuntimeServicePhase,
    input_owner: RuntimeInputOwner,
    routing: RuntimeRoutingState,
    session_active: bool,
}

impl RuntimeStatusSnapshot {
    pub(crate) const fn starting() -> Self {
        Self {
            schema_version: 1,
            service: RuntimeServicePhase::Starting,
            input_owner: RuntimeInputOwner::Local,
            routing: RuntimeRoutingState::WaitingForWorkspace,
            session_active: false,
        }
    }

    pub(crate) const fn running(
        input_owner: RuntimeInputOwner,
        routing: RuntimeRoutingState,
        session_active: bool,
    ) -> Self {
        Self {
            schema_version: 1,
            service: RuntimeServicePhase::Running,
            input_owner,
            routing,
            session_active,
        }
    }

    pub(crate) const fn stopping() -> Self {
        Self {
            schema_version: 1,
            service: RuntimeServicePhase::Stopping,
            input_owner: RuntimeInputOwner::Local,
            routing: RuntimeRoutingState::Gated,
            session_active: false,
        }
    }

    pub(crate) const fn faulted() -> Self {
        Self {
            schema_version: 1,
            service: RuntimeServicePhase::Faulted,
            input_owner: RuntimeInputOwner::Local,
            routing: RuntimeRoutingState::Gated,
            session_active: false,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RuntimeStatusPublisher {
    inner: Arc<RuntimeStatusPublisherInner>,
}

#[derive(Debug)]
struct RuntimeStatusPublisherInner {
    path: PathBuf,
    previous: Mutex<Option<RuntimeStatusSnapshot>>,
}

impl RuntimeStatusPublisher {
    #[cfg(any(target_os = "macos", windows))]
    pub(crate) fn for_profile(profile_path: &Path) -> Self {
        Self {
            inner: Arc::new(RuntimeStatusPublisherInner {
                path: profile_path.with_file_name(RUNTIME_STATUS_FILE),
                previous: Mutex::new(None),
            }),
        }
    }

    pub(crate) fn publish(&self, snapshot: RuntimeStatusSnapshot) {
        let Ok(mut previous) = self.inner.previous.lock() else {
            return;
        };
        if *previous == Some(snapshot) {
            return;
        }
        let Ok(serialized) = toml::to_string(&snapshot) else {
            return;
        };
        if write_status(&self.inner.path, serialized.as_bytes()).is_ok() {
            *previous = Some(snapshot);
        }
    }
}

fn write_status(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let temporary = path.with_extension("status.tmp");
    match fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(contents)?;
    file.flush()?;
    drop(file);

    if fs::rename(&temporary, path).is_err() {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        fs::rename(&temporary, path)?;
    }
    Ok(())
}

#[cfg(all(test, any(target_os = "macos", windows)))]
mod tests {
    use super::*;

    #[test]
    fn status_is_redacted_and_replaced_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let publisher = RuntimeStatusPublisher::for_profile(&directory.path().join("runtime.toml"));
        publisher.publish(RuntimeStatusSnapshot::starting());
        publisher.publish(RuntimeStatusSnapshot::running(
            RuntimeInputOwner::Peer,
            RuntimeRoutingState::Enabled,
            true,
        ));

        let status = fs::read_to_string(directory.path().join(RUNTIME_STATUS_FILE)).unwrap();
        assert!(status.contains("input_owner = \"peer\""));
        assert!(status.contains("session_active = true"));
        assert!(!status.contains("host"));
        assert!(!directory.path().join("runtime.status.tmp").exists());
    }
}
