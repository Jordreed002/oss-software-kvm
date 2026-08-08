use kvm_types::DeviceId;
use sha2::{Digest, Sha256};

/// Derives a stable application device ID from a durable Windows identity.
///
/// Callers should supply the Raw Input device-interface name, not a transient
/// `HANDLE`. Windows normally keeps that path stable across daemon restarts.
/// It may still change after a driver reinstall, device re-pairing, or moving a
/// device to a USB topology that Windows treats as a new instance.
/// The truncated, domain-separated digest is an opaque identity key, not an
/// authentication or integrity mechanism.
#[must_use]
pub fn derive_device_id(durable_identity: &str) -> DeviceId {
    let normalized = durable_identity.trim().to_ascii_lowercase();
    let mut hasher = Sha256::new();
    hasher.update(b"software-kvm/windows-device/v1\0");
    hasher.update(normalized.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    DeviceId::from_bytes(bytes)
}

/// Extracts USB-style VID/PID metadata embedded in a Raw Input device path.
#[cfg(any(windows, test))]
pub(crate) fn usb_ids_from_device_path(path: &str) -> (Option<u16>, Option<u16>) {
    let uppercase = path.to_ascii_uppercase();
    (
        parse_hex_component(&uppercase, "VID_"),
        parse_hex_component(&uppercase, "PID_"),
    )
}

#[cfg(any(windows, test))]
fn parse_hex_component(value: &str, marker: &str) -> Option<u16> {
    let start = value.find(marker)? + marker.len();
    let digits = value.get(start..start + 4)?;
    digits
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit())
        .then(|| u16::from_str_radix(digits, 16).ok())
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_identity_is_case_and_surrounding_whitespace_insensitive() {
        let path = r"\\?\HID#VID_046D&PID_C548&MI_00#device";
        assert_eq!(
            derive_device_id(path),
            derive_device_id(&format!("  {}  ", path.to_ascii_lowercase()))
        );
    }

    #[test]
    fn different_device_instances_have_different_ids() {
        assert_ne!(
            derive_device_id(r"\\?\HID#VID_046D&PID_C548#first"),
            derive_device_id(r"\\?\HID#VID_046D&PID_C548#second")
        );
    }

    #[test]
    fn parses_usb_ids_without_assuming_path_case() {
        assert_eq!(
            usb_ids_from_device_path(r"\\?\hid#vid_046d&pid_c548&mi_01#abc"),
            (Some(0x046d), Some(0xc548))
        );
        assert_eq!(
            usb_ids_from_device_path(r"\??\Root#RDP_MOU#0000"),
            (None, None)
        );
    }
}
