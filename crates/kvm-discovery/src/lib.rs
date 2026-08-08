//! Bounded DNS-SD/mDNS reachability hints for Software KVM.
//!
//! Discovery output is always untrusted. A candidate cannot authorize a peer
//! or bypass sealed TLS, exporter admission, pairing, or canonical direction.

mod adapter;
mod cache;
mod model;

pub use adapter::{MdnsAdapterConfig, MdnsAdapterError, MdnsAdvertisement, MdnsDiscoveryAdapter};
pub use cache::{DiscoveryCache, DiscoveryCacheChange, DiscoveryCacheConfig, DiscoveryCacheError};
pub use model::{
    is_supported_lan_address, DiscoveryCandidate, DiscoverySnapshot, RawDiscoveryRecord,
    RawTxtProperty, DISCOVERY_PROTOCOL_VERSION, MAX_ADDRESSES_PER_SERVICE,
    MAX_DISCOVERY_CANDIDATES, MAX_DISCOVERY_SERVICES, MAX_FULLNAME_BYTES, MAX_HOSTNAME_BYTES,
    MAX_INSTANCE_NAME_BYTES, MAX_TXT_KEY_BYTES, MAX_TXT_PROPERTIES, MAX_TXT_VALUE_BYTES,
    SOFTWARE_KVM_SERVICE_TYPE,
};
