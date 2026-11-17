//! Development-only native tray/menu-bar shell for the replacement utility UI.
//!
//! Opt-in via `--utility-preview` on a debug build served by the Vite dev
//! server (`tauri dev`). This mode deliberately owns nothing:
//!
//! - no legacy `SetupService`, nearby discovery, runtime or input capture is
//!   instantiated and no IPC commands are registered;
//! - the webview shows the fixture/unavailable utility UI (`?surface=utility`);
//! - native Pause/Resume are shown disabled because the agent API is not
//!   integrated, and nothing claims sharing state;
//! - "Quit preview" exits only this process. A separately running legacy
//!   control panel or runtime is a different process and is never signalled.
//!
//! Known limitations are documented on [`native::run`].

#[cfg(debug_assertions)]
mod native;
#[cfg(debug_assertions)]
pub(crate) use native::run;

/// Command-line flag that selects this preview.
pub(crate) const FLAG: &str = "--utility-preview";

/// Whether the explicit preview flag is present in the given arguments.
pub(crate) fn requested<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    args.into_iter().any(|arg| arg.as_ref() == FLAG)
}

/// Why the preview cannot start in this build, if it cannot.
///
/// The fixture UI is only compiled into Vite development bundles, so a debug
/// binary packaged with built assets (`tauri build --debug`) would silently
/// render the legacy console instead. Refuse rather than mislead.
pub(crate) fn unavailable_reason(debug_build: bool, dev_server: bool) -> Option<&'static str> {
    if !debug_build {
        Some("--utility-preview is a development-only flag and is not available in release builds")
    } else if !dev_server {
        Some(
            "--utility-preview requires the Vite dev server; run `npm run tauri -- dev -- -- --utility-preview`",
        )
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_must_be_explicit() {
        assert!(requested(["app", "--utility-preview"]));
        assert!(!requested(["app"]));
        assert!(!requested([
            "app",
            "--utility-preview=1",
            "utility-preview"
        ]));
    }

    #[test]
    fn release_and_packaged_builds_refuse() {
        assert!(unavailable_reason(false, true).is_some());
        assert!(unavailable_reason(false, false).is_some());
        assert!(unavailable_reason(true, false).is_some());
        assert_eq!(unavailable_reason(true, true), None);
    }
}
