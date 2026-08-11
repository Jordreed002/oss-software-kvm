mod nearby;
mod setup;

use setup::SetupService;
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
/// Starts the desktop control panel.
///
/// # Panics
///
/// Panics if Tauri cannot initialize its native application runtime.
pub fn run() {
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
        ])
        .run(tauri::generate_context!())
        .expect("control-panel runtime failed");
}
