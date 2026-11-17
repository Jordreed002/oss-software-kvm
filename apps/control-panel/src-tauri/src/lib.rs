mod control;
mod nearby;
mod setup;
mod utility_preview;

use setup::SetupService;
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
/// Starts the desktop control panel.
///
/// # Panics
///
/// Panics if Tauri cannot initialize its native application runtime.
pub fn run() {
    let context = tauri::generate_context!();

    // Development-only utility shells. Without an explicit flag the legacy
    // console below starts exactly as before.
    match utility_preview::select(std::env::args()) {
        utility_preview::Selection::Legacy => {}
        utility_preview::Selection::Conflict => {
            eprintln!(
                "software-kvm-control-panel: {}",
                utility_preview::CONFLICT_REASON
            );
            std::process::exit(2);
        }
        utility_preview::Selection::Utility(mode) => {
            if let Some(reason) =
                utility_preview::unavailable_reason(mode, cfg!(debug_assertions), tauri::is_dev())
            {
                eprintln!("software-kvm-control-panel: {reason}");
                std::process::exit(2);
            }
            #[cfg(debug_assertions)]
            {
                utility_preview::run(context, mode);
                return;
            }
        }
    }

    tauri::Builder::default()
        .setup(|app| {
            app.manage(SetupService::open(app.handle())?);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            setup::setup_status,
            setup::fetch_diagnostics,
            setup::create_local_identity,
            setup::import_peer_bundle,
            setup::request_nearby_pairing,
            setup::accept_nearby_pairing,
            setup::confirm_nearby_pairing,
            setup::decline_nearby_pairing,
            setup::forget_paired_computer,
            setup::repair_lan_binding,
            setup::finalize_setup,
            setup::validate_setup,
            setup::start_runtime,
            setup::stop_runtime,
            control::control_status,
        ])
        .run(context)
        .expect("control-panel runtime failed");
}
