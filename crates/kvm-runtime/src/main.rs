use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;
use std::{fs::OpenOptions, io::Read, path::Path};

use kvm_runtime::{execute_with_shutdown, RuntimeCommandOutcome};

#[tokio::main]
async fn main() -> ExitCode {
    let mut arguments: Vec<_> = std::env::args().skip(1).collect();
    let managed_control = if arguments
        .first()
        .is_some_and(|command| command == "run-managed")
        && arguments.len() == 3
    {
        let control = PathBuf::from(arguments.pop().expect("managed control path exists"));
        let profile = arguments.pop().expect("managed profile path exists");
        arguments = vec!["run".to_owned(), profile];
        Some(control)
    } else {
        None
    };
    let _managed_lock = match managed_control.as_deref() {
        Some(control) => {
            if let Ok(lock) = acquire_managed_lock(control) {
                Some(lock)
            } else {
                eprintln!("managed runtime is already active or unavailable");
                return ExitCode::FAILURE;
            }
        }
        None => None,
    };
    if arguments.first().is_some_and(|command| command == "run") {
        eprintln!(
            "warning: whole-host keyboard and pointer capture will activate; keep the configured emergency shortcut available"
        );
    }
    let (shutdown, receiver) = tokio::sync::watch::channel(false);
    let interrupt_shutdown = shutdown.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = interrupt_shutdown.send(true);
    });
    if let Some(control) = managed_control {
        let managed_shutdown = shutdown;
        tokio::spawn(async move {
            loop {
                if managed_stop_requested(&control) {
                    let _ = managed_shutdown.send(true);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        });
    }
    match execute_with_shutdown(arguments, receiver).await {
        Ok(RuntimeCommandOutcome::Valid) => {
            println!("runtime profile is valid");
            ExitCode::SUCCESS
        }
        Ok(RuntimeCommandOutcome::Stopped) => {
            println!("runtime stopped safely");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn acquire_managed_lock(control: &Path) -> Result<std::fs::File, ()> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(control.with_extension("lock"))
        .map_err(|_| ())?;
    fs2::FileExt::try_lock_exclusive(&file).map_err(|_| ())?;
    Ok(file)
}

fn managed_stop_requested(control: &Path) -> bool {
    let Ok(mut file) = std::fs::File::open(control) else {
        return false;
    };
    let mut bytes = [0_u8; 6];
    let Ok(length) = file.read(&mut bytes) else {
        return false;
    };
    matches!(&bytes[..length], b"stop" | b"stop\n")
}

#[cfg(test)]
mod tests {
    use super::{acquire_managed_lock, managed_stop_requested};

    #[test]
    fn managed_runtime_lock_allows_only_one_owner() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let control = directory.path().join("runtime.control");
        let first = acquire_managed_lock(&control).expect("first runtime should acquire the lock");
        assert!(acquire_managed_lock(&control).is_err());
        drop(first);
        assert!(acquire_managed_lock(&control).is_ok());
    }

    #[test]
    fn managed_stop_control_is_exact_and_bounded() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let control = directory.path().join("runtime.control");
        std::fs::write(&control, b"stop\n").expect("control should be written");
        assert!(managed_stop_requested(&control));
        std::fs::write(&control, b"stop\nextra").expect("control should be replaced");
        assert!(!managed_stop_requested(&control));
    }
}
