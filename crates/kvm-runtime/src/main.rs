use std::process::ExitCode;

use kvm_runtime::{execute_with_shutdown, RuntimeCommandOutcome};

#[tokio::main]
async fn main() -> ExitCode {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments.first().is_some_and(|command| command == "run") {
        eprintln!(
            "warning: whole-host keyboard and pointer capture will activate; keep the configured emergency shortcut available"
        );
    }
    let (shutdown, receiver) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = shutdown.send(true);
    });
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
