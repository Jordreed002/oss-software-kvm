use std::error::Error;
use std::time::{Duration, Instant};

use kvm_config::Config;
use kvm_daemon::DaemonCore;
use kvm_types::{DisplayId, HostId, LogicalPointer, WorkspaceState};
use tokio::time::MissedTickBehavior;
use tracing::{debug, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    // Persistent identity/config loading and native backends are wired in later
    // milestones. Random IDs keep this binary safe and operational as a daemon
    // lifecycle skeleton without claiming stable hardware identity.
    let local_host = HostId::new();
    let workspace = WorkspaceState::new(
        local_host,
        local_host,
        LogicalPointer::new(DisplayId::new(), 0.0, 0.0),
    );
    let mut core = DaemonCore::new(Config::default(), workspace)?;
    let started = Instant::now();
    let mut lifecycle_timer = tokio::time::interval(Duration::from_millis(50));
    lifecycle_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

    info!("daemon started");
    loop {
        tokio::select! {
            _ = lifecycle_timer.tick() => {
                if core.tick(monotonic_ns(started)) {
                    debug!(routing_active = core.is_routing_active(), "routing timer state changed");
                }
            }
            signal = tokio::signal::ctrl_c() => {
                signal?;
                break;
            }
        }
    }
    info!("shutdown signal received");

    core.shutdown(monotonic_ns(started))?;
    info!("daemon stopped gracefully");
    Ok(())
}

fn monotonic_ns(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}
