//! Host-local synchronous calls only. Samples are batch averages, not
//! individual-event tail latency. Setup/assertions remain outside timing.
use kvm_agent_model::{
    DrainTicket, Effect, Lifecycle, Phase, Prerequisite, Readiness, Rejected, Ticket,
};
use std::{hint::black_box, time::Instant};

const WARMUP: usize = 100;
const SAMPLES: usize = 1_000;
const BATCH: usize = 128;
const READY: Readiness = Readiness {
    configuration: Prerequisite::Confirmed,
    permissions: Prerequisite::Confirmed,
    authenticated_peer: Prerequisite::Confirmed,
    topology: Prerequisite::Confirmed,
};
struct Context {
    model: Lifecycle,
    ticket: Option<Ticket>,
    drain: Option<DrainTicket>,
}
fn paused() -> Context {
    Context {
        model: Lifecycle::new(1),
        ticket: None,
        drain: None,
    }
}
fn preparing() -> Context {
    let mut c = paused();
    let Effect::Prepare(ticket) = c.model.resume(READY).unwrap() else {
        panic!("prepare")
    };
    c.ticket = Some(ticket);
    c
}
fn sharing() -> Context {
    let mut c = preparing();
    assert_eq!(
        c.model.prepared(c.ticket.unwrap(), true, READY),
        Ok(Effect::None)
    );
    c
}
fn draining() -> Context {
    let mut c = sharing();
    let Effect::Drain(drain) = c.model.pause() else {
        panic!("drain")
    };
    c.drain = Some(drain);
    c
}
fn latched_drain() -> Context {
    let mut c = sharing();
    let Effect::Drain(drain) = c.model.failsafe() else {
        panic!("drain")
    };
    c.drain = Some(drain);
    c
}
fn failed_drain() -> Context {
    let mut c = draining();
    c.model.drained(c.drain.unwrap(), false).unwrap();
    c
}
fn cancelled_prepare() -> Context {
    let mut c = preparing();
    assert_eq!(c.model.pause(), Effect::CancelPrepare(c.ticket.unwrap()));
    c
}

fn measure(
    name: &str,
    setup: fn() -> Context,
    operation: fn(&mut Context) -> Result<Effect, Rejected>,
    phase: Phase,
    effect_kind: &str,
) {
    let mut samples = Vec::with_capacity(SAMPLES);
    let mut results = [Ok(Effect::None); BATCH];
    for index in 0..WARMUP + SAMPLES {
        let mut contexts: Vec<_> = (0..BATCH).map(|_| black_box(setup())).collect();
        let before = Instant::now();
        for (context, result) in contexts.iter_mut().zip(&mut results) {
            *result = black_box(operation(black_box(context)));
        }
        let elapsed = before.elapsed().as_nanos();
        for (context, result) in contexts.iter_mut().zip(&results) {
            let effect = (*result).expect("transition must succeed");
            match (effect_kind, effect) {
                ("prepare", Effect::Prepare(_))
                | ("none", Effect::None)
                | ("drain", Effect::Drain(_))
                | ("cancel", Effect::CancelPrepare(_)) => {}
                _ => panic!("unexpected effect for {name}: {effect:?}"),
            }
            assert_eq!(context.model.phase(), phase);
            assert_eq!(context.model.permits_admission(), phase == Phase::Sharing);
            if phase == Phase::SafetyLatched {
                assert!(context.model.is_latched());
                assert_eq!(context.model.resume(READY), Err(Rejected::SafetyLatched));
            }
        }
        if index >= WARMUP {
            samples.push(elapsed);
        }
        black_box(contexts);
    }
    samples.sort_unstable();
    // Report raw batch durations to avoid implying sub-clock-resolution
    // per-call measurements or individual-event latency percentiles.
    println!(
        "{name}: batch_min={} ns batch_median={} ns batch_p95={} ns calls_per_batch={BATCH}",
        samples[0],
        samples[SAMPLES / 2 - 1],
        samples[SAMPLES * 95 / 100 - 1]
    );
}
fn main() {
    println!("Host-local lifecycle batches: warmup={WARMUP}, samples={SAMPLES}, batch={BATCH}");
    println!("Batch durations include dispatch/timing overhead; NOT individual-call tail latency.");
    measure(
        "resume_ready",
        paused,
        |c| c.model.resume(black_box(READY)),
        Phase::Preparing,
        "prepare",
    );
    measure(
        "prepared_success",
        preparing,
        |c| c.model.prepared(c.ticket.unwrap(), black_box(true), READY),
        Phase::Sharing,
        "none",
    );
    measure(
        "pause_sharing",
        sharing,
        |c| Ok(c.model.pause()),
        Phase::Draining,
        "drain",
    );
    measure(
        "drained_success",
        draining,
        |c| c.model.drained(c.drain.unwrap(), black_box(true)),
        Phase::Paused,
        "none",
    );
    measure(
        "prepared_failure",
        preparing,
        |c| c.model.prepared(c.ticket.unwrap(), black_box(false), READY),
        Phase::Draining,
        "drain",
    );
    measure(
        "drained_failure",
        draining,
        |c| c.model.drained(c.drain.unwrap(), black_box(false)),
        Phase::Draining,
        "none",
    );
    measure(
        "retry_cleanup",
        failed_drain,
        |c| c.model.retry_cleanup(),
        Phase::Draining,
        "drain",
    );
    measure(
        "failsafe_sharing",
        sharing,
        |c| Ok(c.model.failsafe()),
        Phase::Draining,
        "drain",
    );
    measure(
        "failsafe_preparing",
        preparing,
        |c| Ok(c.model.failsafe()),
        Phase::Draining,
        "cancel",
    );
    measure(
        "cancelled_preparation_fenced",
        cancelled_prepare,
        |c| c.model.prepared(c.ticket.unwrap(), true, READY),
        Phase::Draining,
        "drain",
    );
    measure(
        "failsafe_paused",
        paused,
        |c| Ok(c.model.failsafe()),
        Phase::SafetyLatched,
        "none",
    );
    measure(
        "failsafe_drain_completion",
        latched_drain,
        |c| c.model.drained(c.drain.unwrap(), true),
        Phase::SafetyLatched,
        "none",
    );
    println!("All batch state/effect assertions passed. No native or cross-host measurements.");
}
