use kvm_types::{DeviceId, HostId};
use sha2::{Digest, Sha256};

/// Native properties used to derive a repeatable device identifier.
///
/// Serial number is preferred. A location ID is normally stable for a device
/// connected to the same port. `IORegistry` entry IDs only last for the current
/// boot. The final property fingerprint cannot distinguish identical devices.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeviceIdentityMaterial {
    pub vendor_id: Option<u16>,
    pub product_id: Option<u16>,
    pub serial_number: Option<String>,
    pub location_id: Option<u32>,
    pub registry_entry_id: Option<u64>,
    pub transport: Option<String>,
    pub product_name: Option<String>,
    pub built_in: bool,
    pub primary_usage_page: Option<u16>,
    pub primary_usage: Option<u16>,
}

/// Expected persistence of a derived physical identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityStability {
    /// Stable across ports and restarts when the device reports a unique serial.
    Hardware,
    /// Stable while the same device remains at the same built-in/USB location.
    Location,
    /// Stable only during the current macOS boot.
    Session,
    /// Best effort; identical devices with the same properties can collide.
    AmbiguousFingerprint,
}

/// Derives a host-scoped identifier and reports its persistence guarantee.
#[must_use]
pub fn derive_device_id(
    host_id: HostId,
    material: &DeviceIdentityMaterial,
) -> (DeviceId, IdentityStability) {
    let mut hasher = Sha256::new();
    hasher.update(b"software-kvm/device/v1\0");
    hasher.update(host_id.into_bytes());

    let stability = if let Some(serial) = non_empty(material.serial_number.as_deref()) {
        hasher.update([1]);
        update_framed(&mut hasher, serial.as_bytes());
        IdentityStability::Hardware
    } else if let Some(location) = material.location_id {
        hasher.update([2]);
        hasher.update(location.to_be_bytes());
        hasher.update([u8::from(material.built_in)]);
        IdentityStability::Location
    } else if material.built_in {
        hasher.update([3]);
        update_framed(
            &mut hasher,
            material.transport.as_deref().unwrap_or_default().as_bytes(),
        );
        update_framed(
            &mut hasher,
            material
                .product_name
                .as_deref()
                .unwrap_or_default()
                .as_bytes(),
        );
        IdentityStability::Location
    } else if let Some(entry) = material.registry_entry_id {
        hasher.update([4]);
        hasher.update(entry.to_be_bytes());
        IdentityStability::Session
    } else {
        hasher.update([5]);
        hasher.update([u8::from(material.built_in)]);
        update_framed(
            &mut hasher,
            material.transport.as_deref().unwrap_or_default().as_bytes(),
        );
        update_framed(
            &mut hasher,
            material
                .product_name
                .as_deref()
                .unwrap_or_default()
                .as_bytes(),
        );
        IdentityStability::AmbiguousFingerprint
    };

    update_optional_u16(&mut hasher, material.vendor_id);
    update_optional_u16(&mut hasher, material.product_id);
    update_optional_u16(&mut hasher, material.primary_usage_page);
    update_optional_u16(&mut hasher, material.primary_usage);

    // SHA-256 makes an untrusted-property fingerprint resistant to easy chosen
    // collisions. The truncated digest is a database identity, not an
    // authenticator; peer trust is handled by the security crate.
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    (DeviceId::from_bytes(bytes), stability)
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn update_framed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

fn update_optional_u16(hasher: &mut Sha256, value: Option<u16>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hasher.update(value.to_be_bytes());
        }
        None => hasher.update([0]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn material() -> DeviceIdentityMaterial {
        DeviceIdentityMaterial {
            vendor_id: Some(0x046d),
            product_id: Some(0xb034),
            serial_number: Some("mouse-123".into()),
            location_id: Some(0x1420_0000),
            registry_entry_id: Some(99),
            transport: Some("USB".into()),
            product_name: Some("MX Master".into()),
            built_in: false,
            primary_usage_page: Some(1),
            primary_usage: Some(2),
        }
    }

    #[test]
    fn serial_identity_is_repeatable_and_ignores_location_changes() {
        let host = HostId::from_bytes([7; 16]);
        let first = derive_device_id(host, &material());
        let mut moved = material();
        moved.location_id = Some(123);
        moved.registry_entry_id = Some(456);

        assert_eq!(first, derive_device_id(host, &moved));
        assert_eq!(first.1, IdentityStability::Hardware);
    }

    #[test]
    fn identity_is_scoped_to_the_host() {
        let first = derive_device_id(HostId::from_bytes([1; 16]), &material()).0;
        let second = derive_device_id(HostId::from_bytes([2; 16]), &material()).0;

        assert_ne!(first, second);
    }

    #[test]
    fn fallback_order_and_limits_are_reported() {
        let host = HostId::from_bytes([3; 16]);
        let mut value = material();
        value.serial_number = Some("  ".into());
        assert_eq!(
            derive_device_id(host, &value).1,
            IdentityStability::Location
        );

        value.location_id = None;
        assert_eq!(derive_device_id(host, &value).1, IdentityStability::Session);

        value.registry_entry_id = None;
        assert_eq!(
            derive_device_id(host, &value).1,
            IdentityStability::AmbiguousFingerprint
        );
    }

    #[test]
    fn built_in_device_has_a_restart_stable_fallback_without_registry_id() {
        let host = HostId::from_bytes([5; 16]);
        let mut value = material();
        value.serial_number = None;
        value.location_id = None;
        value.built_in = true;
        let first = derive_device_id(host, &value);
        value.registry_entry_id = Some(123_456);

        assert_eq!(first, derive_device_id(host, &value));
        assert_eq!(first.1, IdentityStability::Location);
    }
}
