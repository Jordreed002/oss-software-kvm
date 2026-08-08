//! Parsing and privacy-preserving presentation for the native diagnostics CLI.

use core::fmt;
use std::time::Duration;

use kvm_daemon::{CapturedInput, EventClassification};
use kvm_input::InputPayload;

pub const DEFAULT_OBSERVE_SECONDS: u64 = 15;
pub const MAX_OBSERVE_SECONDS: u64 = 300;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    Probe,
    Devices,
    Displays,
    Observe(ObserveOptions),
    All(ObserveOptions),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObserveOptions {
    pub duration: Duration,
    pub show_payload: bool,
}

impl Default for ObserveOptions {
    fn default() -> Self {
        Self {
            duration: Duration::from_secs(DEFAULT_OBSERVE_SECONDS),
            show_payload: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseOutcome {
    Run(Command),
    Help,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseError(String);

impl ParseError {
    #[must_use]
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for ParseError {}

/// Parses arguments after the executable name.
///
/// # Errors
///
/// Returns a descriptive error for unknown commands or invalid options.
pub fn parse_args<I, S>(args: I) -> Result<ParseOutcome, ParseError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut args = args.into_iter().map(Into::into);
    let Some(command) = args.next() else {
        return Ok(ParseOutcome::Help);
    };

    if matches!(command.as_str(), "help" | "-h" | "--help") {
        ensure_empty(args)?;
        return Ok(ParseOutcome::Help);
    }

    match command.as_str() {
        "probe" => parse_without_options(args, Command::Probe),
        "devices" => parse_without_options(args, Command::Devices),
        "displays" => parse_without_options(args, Command::Displays),
        "observe" => {
            parse_observe(args).map(|options| ParseOutcome::Run(Command::Observe(options)))
        }
        "all" => parse_observe(args).map(|options| ParseOutcome::Run(Command::All(options))),
        _ => Err(ParseError(format!(
            "unknown command `{command}`; expected probe, devices, displays, observe, or all"
        ))),
    }
}

fn parse_without_options<I>(args: I, command: Command) -> Result<ParseOutcome, ParseError>
where
    I: Iterator<Item = String>,
{
    ensure_empty(args)?;
    Ok(ParseOutcome::Run(command))
}

fn ensure_empty<I>(mut args: I) -> Result<(), ParseError>
where
    I: Iterator<Item = String>,
{
    args.next().map_or(Ok(()), |argument| {
        Err(ParseError(format!("unexpected argument `{argument}`")))
    })
}

fn parse_observe<I>(mut args: I) -> Result<ObserveOptions, ParseError>
where
    I: Iterator<Item = String>,
{
    let mut options = ObserveOptions::default();
    let mut duration_seen = false;
    let mut payload_seen = false;

    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--duration-seconds" => {
                if duration_seen {
                    return Err(ParseError("--duration-seconds was supplied twice".into()));
                }
                let value = args.next().ok_or_else(|| {
                    ParseError("--duration-seconds requires an integer value".into())
                })?;
                let seconds = value.parse::<u64>().map_err(|_| {
                    ParseError(format!("invalid duration `{value}`; expected an integer"))
                })?;
                if !(1..=MAX_OBSERVE_SECONDS).contains(&seconds) {
                    return Err(ParseError(format!(
                        "duration must be between 1 and {MAX_OBSERVE_SECONDS} seconds"
                    )));
                }
                options.duration = Duration::from_secs(seconds);
                duration_seen = true;
            }
            "--show-payload" => {
                if payload_seen {
                    return Err(ParseError("--show-payload was supplied twice".into()));
                }
                options.show_payload = true;
                payload_seen = true;
            }
            _ => return Err(ParseError(format!("unknown observe option `{argument}`"))),
        }
    }

    Ok(options)
}

#[must_use]
pub const fn payload_category(payload: InputPayload) -> &'static str {
    match payload {
        InputPayload::Key { .. } => "key",
        InputPayload::PointerMove { .. } => "pointer_move",
        InputPayload::PointerButton { .. } => "pointer_button",
        InputPayload::Scroll { .. } => "scroll",
    }
}

#[must_use]
pub const fn classification_label(classification: EventClassification) -> &'static str {
    match classification {
        EventClassification::Physical => "physical",
        EventClassification::InjectedByKvm => "injected_by_kvm",
        EventClassification::Unknown => "unknown",
    }
}

/// Formats one observation. Detailed payload values are omitted unless explicitly requested.
#[must_use]
pub fn format_observation(
    event_number: u64,
    elapsed: Duration,
    captured: CapturedInput,
    show_payload: bool,
) -> String {
    let event = captured.event;
    let base = format!(
        "event={event_number} elapsed_ms={} classification={} device={} category={} sequence={} source_timestamp_ns={}",
        elapsed.as_millis(),
        classification_label(captured.classification),
        event.source_device,
        payload_category(event.payload),
        event.sequence,
        event.timestamp_ns
    );
    if show_payload {
        format!("{base} payload={:?}", event.payload)
    } else {
        base
    }
}

#[must_use]
pub const fn help_text() -> &'static str {
    "Software KVM physical-host diagnostics (observation only)\n\
\n\
Usage:\n\
  kvm-diagnostics probe\n\
  kvm-diagnostics devices\n\
  kvm-diagnostics displays\n\
  kvm-diagnostics observe [--duration-seconds N] [--show-payload]\n\
  kvm-diagnostics all [--duration-seconds N] [--show-payload]\n\
\n\
Observation always allows input to remain local. N must be 1..=300 (default 15).\n\
Payload values are hidden by default; --show-payload exposes physical key codes and motion values."
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvm_input::{InputEvent, KeyCode, KeyState};
    use kvm_types::{DeviceId, HostId};

    #[test]
    fn parses_observation_options_in_either_order() {
        let parsed = parse_args(["observe", "--show-payload", "--duration-seconds", "27"]);
        assert_eq!(
            parsed,
            Ok(ParseOutcome::Run(Command::Observe(ObserveOptions {
                duration: Duration::from_secs(27),
                show_payload: true,
            })))
        );
    }

    #[test]
    fn rejects_unbounded_or_ambiguous_observation_options() {
        assert!(parse_args(["observe", "--duration-seconds", "0"]).is_err());
        assert!(parse_args(["observe", "--duration-seconds", "301"]).is_err());
        assert!(parse_args(["observe", "--show-payload", "--show-payload"]).is_err());
        assert!(parse_args(["probe", "extra"]).is_err());
    }

    #[test]
    fn no_arguments_and_help_request_help() {
        assert_eq!(parse_args(Vec::<String>::new()), Ok(ParseOutcome::Help));
        assert_eq!(parse_args(["--help"]), Ok(ParseOutcome::Help));
    }

    fn key_observation() -> CapturedInput {
        CapturedInput::new(
            InputEvent::new(
                9,
                123_456,
                HostId::from_bytes([1; 16]),
                DeviceId::from_bytes([2; 16]),
                InputPayload::Key {
                    code: KeyCode::KeyA,
                    state: KeyState::Pressed,
                },
            ),
            EventClassification::Physical,
        )
    }

    #[test]
    fn default_presentation_redacts_payload_values() {
        let output = format_observation(4, Duration::from_millis(12), key_observation(), false);
        assert!(output.contains("classification=physical"));
        assert!(output.contains("category=key"));
        assert!(output.contains("device=02020202-0202-0202-0202-020202020202"));
        assert!(!output.contains("KeyA"));
        assert!(!output.contains("Pressed"));
        assert!(!output.contains("payload="));
    }

    #[test]
    fn detailed_presentation_is_an_explicit_payload_view() {
        let output = format_observation(1, Duration::ZERO, key_observation(), true);
        assert!(output.contains("payload=Key"));
        assert!(output.contains("KeyA"));
    }
}
