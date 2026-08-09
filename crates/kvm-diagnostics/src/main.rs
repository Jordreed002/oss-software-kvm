use std::error::Error;
use std::process::ExitCode;
#[cfg(any(windows, target_os = "macos"))]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(any(windows, target_os = "macos"))]
use std::sync::Arc;
#[cfg(any(windows, target_os = "macos"))]
use std::thread;
#[cfg(any(windows, target_os = "macos"))]
use std::time::Instant;

#[cfg(any(windows, target_os = "macos"))]
use kvm_daemon::{
    CaptureCallback, CaptureDisposition, CapturedInput, DisplayBackend, EventClassification,
    InputCaptureBackend,
};
#[cfg(any(windows, target_os = "macos"))]
use kvm_diagnostics::{format_observation, payload_category, ObserveOptions};
use kvm_diagnostics::{help_text, parse_args, Command, ParseOutcome};
#[cfg(any(windows, target_os = "macos"))]
use kvm_types::{Display, HostId, InputDevice};

type DiagnosticResult<T = ()> = Result<T, Box<dyn Error + Send + Sync + 'static>>;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> DiagnosticResult {
    let parsed = parse_args(std::env::args().skip(1))?;
    let ParseOutcome::Run(command) = parsed else {
        println!("{}", help_text());
        return Ok(());
    };

    run_native(command)
}

#[cfg(windows)]
fn run_native(command: Command) -> DiagnosticResult {
    use kvm_windows::{probe_capabilities, WindowsDisplayBackend, WindowsInputBackend};

    match command {
        Command::Probe => print_windows_probe(&probe_capabilities()),
        Command::Devices(options) => print_devices(
            WindowsInputBackend::new(options.host_id.unwrap_or_else(diagnostic_host_id))
                .enumerate_devices()?,
        ),
        Command::Displays(options) => print_displays(
            WindowsDisplayBackend::new(options.host_id.unwrap_or_else(diagnostic_host_id))
                .enumerate_displays()?,
        ),
        Command::Observe(options) => {
            let mut input = WindowsInputBackend::new(diagnostic_host_id());
            observe_windows(&mut input, options)?;
        }
        Command::All(options) => {
            let host_id = diagnostic_host_id();
            let mut input = WindowsInputBackend::new(host_id);
            let display = WindowsDisplayBackend::new(host_id);
            print_windows_probe(&probe_capabilities());
            print_devices(input.enumerate_devices()?);
            print_displays(display.enumerate_displays()?);
            observe_windows(&mut input, options)?;
        }
    }
    Ok(())
}

#[cfg(windows)]
fn print_windows_probe(capabilities: &kvm_windows::WindowsCapabilities) {
    println!("platform=windows");
    println!("device_enumeration={:?}", capabilities.device_enumeration);
    println!("input_injection={:?}", capabilities.input_injection);
    println!("display_enumeration={:?}", capabilities.display_enumeration);
    println!(
        "device_aware_capture={:?}",
        capabilities.device_aware_capture
    );
    println!(
        "per_device_suppression={:?}",
        capabilities.per_device_suppression
    );
    for diagnostic in &capabilities.diagnostics {
        println!("diagnostic={diagnostic}");
    }
}

#[cfg(windows)]
fn observe_windows(
    backend: &mut kvm_windows::WindowsInputBackend,
    options: ObserveOptions,
) -> DiagnosticResult {
    observe(backend, options)?;
    let statistics = backend.capture_statistics();
    println!("native_captured={}", statistics.captured_events);
    println!("native_dropped={}", statistics.dropped_events);
    println!("native_untranslated={}", statistics.untranslated_packets);
    println!("native_keyboard_packets={}", statistics.keyboard_packets);
    println!("native_mouse_packets={}", statistics.mouse_packets);
    println!(
        "native_untranslated_keyboard_packets={}",
        statistics.untranslated_keyboard_packets
    );
    println!(
        "native_untranslated_mouse_packets={}",
        statistics.untranslated_mouse_packets
    );
    println!("native_callback_panics={}", statistics.callback_panics);
    println!(
        "native_suppression_requests_ignored={}",
        statistics.suppression_requests_ignored
    );
    println!(
        "native_capture_discontinuities={}",
        statistics.capture_discontinuities
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_native(command: Command) -> DiagnosticResult {
    use kvm_macos::{probe_permissions, MacDisplayBackend, MacInputBackend};

    match command {
        Command::Probe => print_macos_probe(probe_permissions()?),
        Command::Devices(options) => print_devices(
            MacInputBackend::new(options.host_id.unwrap_or_else(diagnostic_host_id))
                .enumerate_devices()?,
        ),
        Command::Displays(options) => print_displays(
            MacDisplayBackend::new(options.host_id.unwrap_or_else(diagnostic_host_id))
                .enumerate_displays()?,
        ),
        Command::Observe(options) => {
            let mut input = MacInputBackend::new(diagnostic_host_id());
            observe_macos(&mut input, options)?;
        }
        Command::All(options) => {
            let host_id = diagnostic_host_id();
            let mut input = MacInputBackend::new(host_id);
            let display = MacDisplayBackend::new(host_id);
            print_macos_probe(probe_permissions()?);
            print_devices(input.enumerate_devices()?);
            print_displays(display.enumerate_displays()?);
            observe_macos(&mut input, options)?;
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn print_macos_probe(status: kvm_macos::PermissionStatus) {
    println!("platform=macos");
    println!("accessibility={}", status.accessibility);
    println!("input_monitoring={}", status.input_monitoring);
    println!("device_aware_capture=available_when_input_monitoring_granted");
    println!("per_device_suppression=not_implemented");
}

#[cfg(target_os = "macos")]
fn observe_macos(
    backend: &mut kvm_macos::MacInputBackend,
    options: ObserveOptions,
) -> DiagnosticResult {
    observe(backend, options)?;
    let statistics = backend.capture_statistics();
    println!("native_delivered={}", statistics.delivered_events);
    println!("native_dropped={}", statistics.dropped_events);
    println!(
        "native_transition_discontinuities={}",
        statistics.transition_discontinuities
    );
    println!(
        "native_delivery_disconnects={}",
        statistics.delivery_disconnects
    );
    println!("native_capture_health={:?}", statistics.health);
    println!(
        "native_suppression_requests_ignored={}",
        statistics.ignored_suppression_requests
    );
    Ok(())
}

#[cfg(not(any(windows, target_os = "macos")))]
fn run_native(_command: Command) -> DiagnosticResult {
    Err("unsupported host: native diagnostics require Windows or macOS".into())
}

#[cfg(any(windows, target_os = "macos"))]
fn diagnostic_host_id() -> HostId {
    // This process-local identity intentionally avoids reading or writing the user's config.
    HostId::from_bytes([0x44; 16])
}

#[cfg(any(windows, target_os = "macos"))]
#[derive(Debug, Default)]
struct ObservationCounters {
    total: AtomicU64,
    physical: AtomicU64,
    injected: AtomicU64,
    unknown: AtomicU64,
    key: AtomicU64,
    pointer_move: AtomicU64,
    pointer_button: AtomicU64,
    scroll: AtomicU64,
}

#[cfg(any(windows, target_os = "macos"))]
impl ObservationCounters {
    fn record(&self, captured: CapturedInput) -> u64 {
        match captured.classification {
            EventClassification::Physical => &self.physical,
            EventClassification::InjectedByKvm => &self.injected,
            EventClassification::Unknown => &self.unknown,
        }
        .fetch_add(1, Ordering::Relaxed);

        // F-12: payload_category covers every InputPayload variant today, but a
        // future variant must not crash the diagnostics tool. Unknown categories
        // are still counted in `total`; only the per-category bucket is skipped.
        let category_counter = match payload_category(captured.event.payload) {
            "key" => Some(&self.key),
            "pointer_move" => Some(&self.pointer_move),
            "pointer_button" => Some(&self.pointer_button),
            "scroll" => Some(&self.scroll),
            _ => None,
        };
        if let Some(counter) = category_counter {
            counter.fetch_add(1, Ordering::Relaxed);
        }

        self.total.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn print(&self, elapsed_ms: u128) {
        println!("summary_elapsed_ms={elapsed_ms}");
        println!("summary_total={}", self.total.load(Ordering::Relaxed));
        println!("summary_physical={}", self.physical.load(Ordering::Relaxed));
        println!(
            "summary_injected_by_kvm={}",
            self.injected.load(Ordering::Relaxed)
        );
        println!("summary_unknown={}", self.unknown.load(Ordering::Relaxed));
        println!("summary_key={}", self.key.load(Ordering::Relaxed));
        println!(
            "summary_pointer_move={}",
            self.pointer_move.load(Ordering::Relaxed)
        );
        println!(
            "summary_pointer_button={}",
            self.pointer_button.load(Ordering::Relaxed)
        );
        println!("summary_scroll={}", self.scroll.load(Ordering::Relaxed));
    }
}

#[cfg(any(windows, target_os = "macos"))]
fn observe<B>(backend: &mut B, options: ObserveOptions) -> DiagnosticResult
where
    B: InputCaptureBackend,
{
    if options.show_payload {
        eprintln!(
            "warning: --show-payload exposes physical key codes, button states, and motion values"
        );
    }
    println!("capture_mode=observation_only");
    println!("local_disposition=always_allow");
    println!("duration_seconds={}", options.duration.as_secs());

    let started = Instant::now();
    let counters = Arc::new(ObservationCounters::default());
    let callback_counters = Arc::clone(&counters);
    let callback: CaptureCallback = Arc::new(move |captured| {
        let number = callback_counters.record(captured);
        println!(
            "{}",
            format_observation(number, started.elapsed(), captured, options.show_payload)
        );
        CaptureDisposition::AllowLocal
    });

    backend.start_capture(callback)?;
    thread::sleep(options.duration);
    backend.stop_capture()?;
    counters.print(started.elapsed().as_millis());
    Ok(())
}

#[cfg(any(windows, target_os = "macos"))]
fn print_devices(devices: Vec<InputDevice>) {
    println!("device_count={}", devices.len());
    for device in devices {
        println!(
            "device id={} kind={:?} name={:?} vendor_id={:?} product_id={:?} keyboard={} pointer={} vertical_scroll={} horizontal_scroll={} extra_buttons={}",
            device.id,
            device.kind,
            device.name,
            device.vendor_id,
            device.product_id,
            device.capabilities.keyboard,
            device.capabilities.pointer,
            device.capabilities.vertical_scroll,
            device.capabilities.horizontal_scroll,
            device.capabilities.extra_buttons
        );
    }
}

#[cfg(any(windows, target_os = "macos"))]
fn print_displays(displays: Vec<Display>) {
    println!("display_count={}", displays.len());
    for display in displays {
        println!(
            "display id={} name={:?} logical={}x{} physical={:?} scale={} refresh_hz={:?} native_bounds={},{} {}x{} primary={}",
            display.id,
            display.name,
            display.logical_size.width,
            display.logical_size.height,
            display.physical_size,
            display.scale_factor,
            display.refresh_rate,
            display.native_bounds.x,
            display.native_bounds.y,
            display.native_bounds.width,
            display.native_bounds.height,
            display.primary
        );
    }
}
