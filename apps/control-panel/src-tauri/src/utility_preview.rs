//! Development-only native tray/menu-bar shells for the replacement utility UI.
//!
//! Two explicit, mutually exclusive modes, each opt-in on a debug build served
//! by the Vite dev server (`tauri dev`). Without a flag the legacy console
//! starts exactly as before.
//!
//! `--utility-preview` (fixture preview) deliberately owns nothing:
//!
//! - no legacy `SetupService`, nearby discovery, runtime or input capture is
//!   instantiated and no IPC commands are registered;
//! - the webview shows the fixture/unavailable utility UI (`?surface=utility`);
//! - native Pause/Resume are shown disabled and nothing claims sharing state.
//!
//! `--utility-agent` (read-only agent status) also instantiates none of the
//! legacy services. It registers exactly one read-only command,
//! `agent_status`, which only the `utility-agent` window may call, and shows
//! `?surface=utility-agent`: real agent snapshots or a distinct failure,
//! never fixtures. Every mutation stays disabled.
//!
//! In both modes "Quit" exits only this process. A separately running legacy
//! control panel, runtime or agent is a different process and is never
//! signalled. Known limitations are documented on [`native::run`].

#[cfg(debug_assertions)]
mod agent;
#[cfg(debug_assertions)]
mod native;
#[cfg(debug_assertions)]
pub(crate) use native::run;

/// Command-line flag that selects the fixture preview.
pub(crate) const FLAG: &str = "--utility-preview";
/// Command-line flag that selects the read-only agent status shell.
pub(crate) const AGENT_FLAG: &str = "--utility-agent";

/// Which development utility shell to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Fixture-only preview; no IPC.
    Preview,
    /// Read-only native agent status.
    Agent,
}

#[cfg(test)]
impl Mode {
    const fn flag(self) -> &'static str {
        match self {
            Self::Preview => FLAG,
            Self::Agent => AGENT_FLAG,
        }
    }
}

/// Result of parsing the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Selection {
    /// No utility flag: the legacy console.
    Legacy,
    /// Exactly one utility flag.
    Utility(Mode),
    /// Both flags: refuse rather than guess which mode was meant.
    Conflict,
}

/// Selects the mode from exact flag matches only (`--utility-agent=1` and
/// similar spellings do not count).
pub(crate) fn select<I, S>(args: I) -> Selection
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let (mut preview, mut agent) = (false, false);
    for arg in args {
        match arg.as_ref() {
            FLAG => preview = true,
            AGENT_FLAG => agent = true,
            _ => {}
        }
    }
    match (preview, agent) {
        (false, false) => Selection::Legacy,
        (true, false) => Selection::Utility(Mode::Preview),
        (false, true) => Selection::Utility(Mode::Agent),
        (true, true) => Selection::Conflict,
    }
}

/// Message for [`Selection::Conflict`].
pub(crate) const CONFLICT_REASON: &str =
    "--utility-preview and --utility-agent are separate modes; pass only one";

/// Why the selected mode cannot start in this build, if it cannot.
///
/// The utility UI is only compiled into Vite development bundles, so a debug
/// binary packaged with built assets (`tauri build --debug`) would silently
/// render the legacy console instead. Refuse rather than mislead.
pub(crate) fn unavailable_reason(
    mode: Mode,
    debug_build: bool,
    dev_server: bool,
) -> Option<&'static str> {
    match (mode, debug_build, dev_server) {
        (Mode::Preview, false, _) => Some(
            "--utility-preview is a development-only flag and is not available in release builds",
        ),
        (Mode::Agent, false, _) => Some(
            "--utility-agent is a development-only flag and is not available in release builds",
        ),
        (Mode::Preview, true, false) => Some(
            "--utility-preview requires the Vite dev server; run `npm run tauri -- dev -- -- --utility-preview`",
        ),
        (Mode::Agent, true, false) => Some(
            "--utility-agent requires the Vite dev server; run `npm run tauri -- dev -- -- --utility-agent`",
        ),
        (_, true, true) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_must_be_explicit() {
        assert_eq!(
            select(["app", "--utility-preview"]),
            Selection::Utility(Mode::Preview)
        );
        assert_eq!(
            select(["app", "--utility-agent"]),
            Selection::Utility(Mode::Agent)
        );
        assert_eq!(select(["app"]), Selection::Legacy);
        assert_eq!(
            select([
                "app",
                "--utility-preview=1",
                "utility-preview",
                "--utility-agent=1",
                "utility-agent",
                "--UTILITY-AGENT",
            ]),
            Selection::Legacy
        );
    }

    #[test]
    fn both_flags_conflict() {
        assert_eq!(
            select(["app", "--utility-agent", "--utility-preview"]),
            Selection::Conflict
        );
    }

    #[test]
    fn release_and_packaged_builds_refuse_each_mode() {
        for mode in [Mode::Preview, Mode::Agent] {
            assert!(unavailable_reason(mode, false, true).is_some());
            assert!(unavailable_reason(mode, false, false).is_some());
            let reason = unavailable_reason(mode, true, false).unwrap();
            assert!(reason.contains(mode.flag()), "{reason}");
            assert_eq!(unavailable_reason(mode, true, true), None);
        }
    }
}
