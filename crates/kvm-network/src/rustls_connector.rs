use crate::{
    connector::sealed, AuthenticatedConnector, AuthenticatedLanConnector, ConnectionDirection,
    DevelopmentAddress, LanPeerAddress, SecurePeerStream, TransportPeerIdentity,
};
use sha2::{Digest, Sha256};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::rustls::client::Resumption;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName,
};
use tokio_rustls::rustls::{ClientConfig, NoKeyLog, RootCertStore};
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

const KVM_ALPN: &[u8] = b"software-kvm/1";
const MAX_CERTIFICATE_CHAIN_LENGTH: usize = 8;
const MAX_CERTIFICATE_DER_BYTES: usize = 64 * 1024;
const MAX_CERTIFICATE_CHAIN_DER_BYTES: usize = 256 * 1024;
const MAX_PRIVATE_KEY_DER_BYTES: usize = 16 * 1024;
const MAX_TRUST_ROOTS: usize = 64;
const MAX_TRUST_ROOT_DER_BYTES: usize = 64 * 1024;
const MAX_TRUST_ROOTS_DER_BYTES: usize = 1024 * 1024;
const MAX_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Public certificate chain and PKCS#8 private key presented for TLS client
/// authentication when requested by the server. Debug output is fully redacted.
pub struct RustlsClientCredentials {
    certificate_chain_der: Vec<Vec<u8>>,
    private_key_pkcs8_der: Zeroizing<Vec<u8>>,
}

impl RustlsClientCredentials {
    #[must_use]
    pub fn new(certificate_chain_der: Vec<Vec<u8>>, private_key_pkcs8_der: Vec<u8>) -> Self {
        Self {
            certificate_chain_der,
            private_key_pkcs8_der: Zeroizing::new(private_key_pkcs8_der),
        }
    }
}

impl std::fmt::Debug for RustlsClientCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RustlsClientCredentials([REDACTED])")
    }
}

/// Explicit certificate authorities trusted for the remote TLS server.
pub struct RustlsServerTrust {
    root_certificates_der: Vec<Vec<u8>>,
}

impl RustlsServerTrust {
    #[must_use]
    pub fn new(root_certificates_der: Vec<Vec<u8>>) -> Self {
        Self {
            root_certificates_der,
        }
    }
}

impl std::fmt::Debug for RustlsServerTrust {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RustlsServerTrust([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RustlsConnectorConfig {
    pub connect_timeout: Duration,
    pub handshake_timeout: Duration,
}

impl Default for RustlsConnectorConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(3),
            handshake_timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RustlsConnectorConfigError {
    #[error("TCP connect or TLS handshake timeout is outside the permitted range")]
    InvalidTimeout,
    #[error("a client certificate chain is required")]
    MissingClientCertificate,
    #[error("a PKCS#8 client private key is required")]
    MissingClientPrivateKey,
    #[error("at least one server trust root is required")]
    MissingServerTrustRoot,
    #[error("client credential input exceeds its permitted bound")]
    ClientCredentialsTooLarge,
    #[error("server trust input exceeds its permitted bound")]
    ServerTrustTooLarge,
    #[error("server name is invalid")]
    InvalidServerName,
    #[error("server trust root is malformed")]
    InvalidServerTrustRoot,
    #[error("client certificate or private key is malformed")]
    InvalidClientCredentials,
}

/// Outbound TCP/TLS connector that authenticates and pins the remote server.
///
/// A returned stream proves that this client completed encrypted TLS 1.3 with
/// the exact ALPN and authenticated remote leaf fingerprint. The connector also
/// presents its configured client credentials, but TLS 1.3 client-side
/// completion can precede receipt of a server rejection alert. Reciprocal
/// acceptance is therefore established by successful bidirectional application
/// admission, not by `connect` alone.
pub struct RustlsTcpConnector {
    client_config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    expected_peer: TransportPeerIdentity,
    config: RustlsConnectorConfig,
}

impl RustlsTcpConnector {
    /// Builds a TLS 1.3-only client configuration from explicit client
    /// credentials and server trust inputs.
    ///
    /// The configuration requires and presents the supplied client certificate;
    /// a future server acceptor enforces it directly, while the outbound side
    /// learns reciprocal acceptance only through bidirectional application
    /// admission.
    ///
    /// # Errors
    ///
    /// Returns a redacted configuration error for empty, malformed, or unsafe
    /// inputs.
    pub fn new(
        credentials: RustlsClientCredentials,
        server_trust: RustlsServerTrust,
        server_name: String,
        expected_peer: TransportPeerIdentity,
        config: RustlsConnectorConfig,
    ) -> Result<Self, RustlsConnectorConfigError> {
        validate_inputs(&credentials, &server_trust, config)?;

        let server_name = ServerName::try_from(server_name)
            .map_err(|_| RustlsConnectorConfigError::InvalidServerName)?;
        let mut roots = RootCertStore::empty();
        for root in server_trust.root_certificates_der {
            roots
                .add(CertificateDer::from(root))
                .map_err(|_| RustlsConnectorConfigError::InvalidServerTrustRoot)?;
        }
        let certificate_chain = credentials
            .certificate_chain_der
            .into_iter()
            .map(CertificateDer::from)
            .collect();
        // The caller-provided allocation remains under `Zeroizing` on every
        // return path. The one necessary copy is consumed by rustls' owned
        // private-key type, whose contents are redacted and implement
        // `Zeroize`; the configured signing key must remain live for future
        // handshakes.
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            credentials.private_key_pkcs8_der.to_vec(),
        ));
        let provider = Arc::new(ring::default_provider());
        let mut client_config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13])
            .map_err(|_| RustlsConnectorConfigError::InvalidClientCredentials)?
            .with_root_certificates(roots)
            .with_client_auth_cert(certificate_chain, private_key)
            .map_err(|_| RustlsConnectorConfigError::InvalidClientCredentials)?;
        client_config.alpn_protocols = vec![KVM_ALPN.to_vec()];
        client_config.enable_early_data = false;
        client_config.resumption = Resumption::disabled();
        client_config.key_log = Arc::new(NoKeyLog {});

        Ok(Self {
            client_config: Arc::new(client_config),
            server_name,
            expected_peer,
            config,
        })
    }

    async fn connect_socket(&self, address: SocketAddr) -> io::Result<RustlsPeerStream> {
        let tcp = timeout_io(
            self.config.connect_timeout,
            TcpStream::connect(address),
            "TCP connection timed out",
        )
        .await?;
        tcp.set_nodelay(true)?;

        let connector = TlsConnector::from(Arc::clone(&self.client_config));
        let tls = timeout_io(
            self.config.handshake_timeout,
            async {
                connector
                    .connect(self.server_name.clone(), tcp)
                    .await
                    .map_err(|_| authentication_failed())
            },
            "TLS handshake timed out",
        )
        .await?;

        let connection = tls.get_ref().1;
        if connection.alpn_protocol() != Some(KVM_ALPN) {
            return Err(authentication_failed());
        }
        let certificates = connection
            .peer_certificates()
            .ok_or_else(authentication_failed)?;
        validate_authenticated_chain_bounds(certificates)?;
        let leaf = certificates.first().ok_or_else(authentication_failed)?;
        let fingerprint: [u8; 32] = Sha256::digest(leaf.as_ref()).into();
        if !bool::from(fingerprint.ct_eq(&self.expected_peer.credential_fingerprint)) {
            return Err(authentication_failed());
        }

        Ok(RustlsPeerStream {
            inner: tls,
            identity: self.expected_peer.clone(),
        })
    }
}

impl std::fmt::Debug for RustlsTcpConnector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RustlsTcpConnector([REDACTED])")
    }
}

impl sealed::Connector for RustlsTcpConnector {}

impl AuthenticatedConnector for RustlsTcpConnector {
    type Stream = RustlsPeerStream;

    fn connect<'a>(
        &'a mut self,
        address: DevelopmentAddress,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::Stream>> + Send + 'a>> {
        Box::pin(self.connect_socket(address.socket_addr()))
    }
}

impl AuthenticatedLanConnector for RustlsTcpConnector {
    type Stream = RustlsPeerStream;

    fn connect_lan(
        &mut self,
        address: LanPeerAddress,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::Stream>> + Send + '_>> {
        Box::pin(self.connect_socket(address.socket_addr()))
    }
}

/// TLS stream created after local TLS 1.3 completion plus remote certificate,
/// ALPN, and fingerprint checks.
///
/// It carries configured client credentials in the handshake, but does not by
/// itself prove that the remote server accepted them. No `AdmittedPeer` is
/// minted until the subsequent bidirectional application exchange succeeds.
pub struct RustlsPeerStream {
    inner: tokio_rustls::client::TlsStream<TcpStream>,
    identity: TransportPeerIdentity,
}

impl std::fmt::Debug for RustlsPeerStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RustlsPeerStream([REDACTED])")
    }
}

fn validate_inputs(
    credentials: &RustlsClientCredentials,
    server_trust: &RustlsServerTrust,
    config: RustlsConnectorConfig,
) -> Result<(), RustlsConnectorConfigError> {
    if config.connect_timeout == Duration::ZERO
        || config.connect_timeout > MAX_CONNECT_TIMEOUT
        || config.handshake_timeout == Duration::ZERO
        || config.handshake_timeout > MAX_HANDSHAKE_TIMEOUT
    {
        return Err(RustlsConnectorConfigError::InvalidTimeout);
    }
    if credentials.certificate_chain_der.is_empty() {
        return Err(RustlsConnectorConfigError::MissingClientCertificate);
    }
    if credentials.private_key_pkcs8_der.is_empty() {
        return Err(RustlsConnectorConfigError::MissingClientPrivateKey);
    }
    if server_trust.root_certificates_der.is_empty() {
        return Err(RustlsConnectorConfigError::MissingServerTrustRoot);
    }
    if credentials.certificate_chain_der.len() > MAX_CERTIFICATE_CHAIN_LENGTH
        || credentials.private_key_pkcs8_der.len() > MAX_PRIVATE_KEY_DER_BYTES
        || !bounded_der_input(
            &credentials.certificate_chain_der,
            MAX_CERTIFICATE_DER_BYTES,
            MAX_CERTIFICATE_CHAIN_DER_BYTES,
        )
    {
        return Err(RustlsConnectorConfigError::ClientCredentialsTooLarge);
    }
    if server_trust.root_certificates_der.len() > MAX_TRUST_ROOTS
        || !bounded_der_input(
            &server_trust.root_certificates_der,
            MAX_TRUST_ROOT_DER_BYTES,
            MAX_TRUST_ROOTS_DER_BYTES,
        )
    {
        return Err(RustlsConnectorConfigError::ServerTrustTooLarge);
    }
    Ok(())
}

fn bounded_der_input(items: &[Vec<u8>], maximum_item: usize, maximum_total: usize) -> bool {
    let mut total = 0_usize;
    for item in items {
        if item.is_empty() || item.len() > maximum_item {
            return false;
        }
        let Some(next) = total.checked_add(item.len()) else {
            return false;
        };
        total = next;
    }
    total <= maximum_total
}

fn validate_authenticated_chain_bounds(certificates: &[CertificateDer<'_>]) -> io::Result<()> {
    if certificates.is_empty() || certificates.len() > MAX_CERTIFICATE_CHAIN_LENGTH {
        return Err(authentication_failed());
    }
    let mut total = 0_usize;
    for certificate in certificates {
        if certificate.is_empty() || certificate.len() > MAX_CERTIFICATE_DER_BYTES {
            return Err(authentication_failed());
        }
        total = total
            .checked_add(certificate.len())
            .ok_or_else(authentication_failed)?;
    }
    if total > MAX_CERTIFICATE_CHAIN_DER_BYTES {
        return Err(authentication_failed());
    }
    Ok(())
}

impl sealed::SecureStream for RustlsPeerStream {}

impl SecurePeerStream for RustlsPeerStream {
    fn authenticated_peer_identity(&self) -> &TransportPeerIdentity {
        &self.identity
    }

    fn connection_direction(&self) -> ConnectionDirection {
        ConnectionDirection::Outbound
    }

    fn socket_endpoints(&self) -> Option<(std::net::SocketAddr, std::net::SocketAddr)> {
        let tcp = self.inner.get_ref().0;
        Some((tcp.local_addr().ok()?, tcp.peer_addr().ok()?))
    }

    fn export_keying_material(&self, label: &[u8], context: &[u8]) -> io::Result<[u8; 32]> {
        self.inner
            .get_ref()
            .1
            .export_keying_material([0_u8; 32], label, Some(context))
            .map_err(|_| authentication_failed())
    }
}

impl AsyncRead for RustlsPeerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for RustlsPeerStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

fn authentication_failed() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "TLS peer authentication failed",
    )
}

fn timed_out(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, message)
}

async fn timeout_io<T>(
    duration: Duration,
    future: impl Future<Output = io::Result<T>>,
    message: &'static str,
) -> io::Result<T> {
    timeout(duration, future)
        .await
        .map_err(|_| timed_out(message))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FrameReader, FrameWriter};
    use kvm_protocol::{PingV1, PongV1, WireHostId, WireMessage, WirePeerId};
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair,
    };
    use tokio_rustls::rustls::server::WebPkiClientVerifier;
    use tokio_rustls::rustls::{RootCertStore, ServerConfig};
    use tokio_rustls::TlsAcceptor;

    struct TestPki {
        root: Vec<u8>,
        server_certificate: Vec<u8>,
        server_private_key: Vec<u8>,
        client_certificate: Vec<u8>,
        client_private_key: Vec<u8>,
    }

    impl TestPki {
        fn generate() -> Self {
            let mut root_params = CertificateParams::default();
            root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let root_key = KeyPair::generate().unwrap();
            let root = CertifiedIssuer::self_signed(root_params, root_key).unwrap();
            let server_key = KeyPair::generate().unwrap();
            let mut server_params = CertificateParams::new(vec!["kvm.test".to_owned()]).unwrap();
            server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            let server = server_params.signed_by(&server_key, &root).unwrap();
            let client_key = KeyPair::generate().unwrap();
            let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
            client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            let client = client_params.signed_by(&client_key, &root).unwrap();
            Self {
                root: root.der().to_vec(),
                server_certificate: server.der().to_vec(),
                server_private_key: server_key.serialize_der(),
                client_certificate: client.der().to_vec(),
                client_private_key: client_key.serialize_der(),
            }
        }

        fn identity(&self) -> TransportPeerIdentity {
            TransportPeerIdentity {
                host_id: WireHostId([1; 16]),
                peer_id: WirePeerId([2; 16]),
                credential_fingerprint: Sha256::digest(&self.server_certificate).into(),
            }
        }

        fn connector(
            &self,
            expected_peer: TransportPeerIdentity,
            config: RustlsConnectorConfig,
        ) -> RustlsTcpConnector {
            RustlsTcpConnector::new(
                RustlsClientCredentials::new(
                    vec![self.client_certificate.clone()],
                    self.client_private_key.clone(),
                ),
                RustlsServerTrust::new(vec![self.root.clone()]),
                "kvm.test".to_owned(),
                expected_peer,
                config,
            )
            .unwrap()
        }

        fn server_config(&self, alpn: &[u8]) -> Arc<ServerConfig> {
            let mut client_roots = RootCertStore::empty();
            client_roots
                .add(CertificateDer::from(self.root.clone()))
                .unwrap();
            let client_verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
                .build()
                .unwrap();
            let provider = Arc::new(ring::default_provider());
            let mut config = ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13])
                .unwrap()
                .with_client_cert_verifier(client_verifier)
                .with_single_cert(
                    vec![CertificateDer::from(self.server_certificate.clone())],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.server_private_key.clone())),
                )
                .unwrap();
            config.alpn_protocols = vec![alpn.to_vec()];
            config.max_early_data_size = 0;
            config.send_tls13_tickets = 0;
            config.key_log = Arc::new(NoKeyLog {});
            Arc::new(config)
        }
    }

    async fn spawn_tls_server(
        server_config: Arc<ServerConfig>,
    ) -> (
        DevelopmentAddress,
        tokio::task::JoinHandle<io::Result<tokio_rustls::server::TlsStream<TcpStream>>>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = DevelopmentAddress::new(listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            TlsAcceptor::from(server_config)
                .accept(tcp)
                .await
                .map_err(io::Error::other)
        });
        (address, server)
    }

    #[test]
    fn credential_and_configuration_debug_output_is_redacted() {
        let secret_marker = b"distinct-private-key-marker".to_vec();
        let credentials = RustlsClientCredentials::new(vec![vec![1, 2, 3]], secret_marker.clone());
        let trust = RustlsServerTrust::new(vec![b"distinct-certificate-marker".to_vec()]);

        let credential_debug = format!("{credentials:?}");
        let trust_debug = format!("{trust:?}");
        assert!(!credential_debug.contains("private-key-marker"));
        assert!(!trust_debug.contains("certificate-marker"));
        assert!(credential_debug.contains("REDACTED"));
        assert!(trust_debug.contains("REDACTED"));

        let pki = TestPki::generate();
        let connector = RustlsTcpConnector::new(
            RustlsClientCredentials::new(
                vec![pki.client_certificate.clone()],
                pki.client_private_key.clone(),
            ),
            RustlsServerTrust::new(vec![pki.root.clone()]),
            "stable-server-name-marker.test".to_owned(),
            pki.identity(),
            RustlsConnectorConfig::default(),
        )
        .unwrap();
        assert_eq!(format!("{connector:?}"), "RustlsTcpConnector([REDACTED])");
    }

    #[test]
    fn constructor_rejects_empty_malformed_and_unbounded_inputs() {
        let pki = TestPki::generate();
        let identity = pki.identity();
        let valid_credentials = || {
            RustlsClientCredentials::new(
                vec![pki.client_certificate.clone()],
                pki.client_private_key.clone(),
            )
        };
        let valid_trust = || RustlsServerTrust::new(vec![pki.root.clone()]);

        assert!(matches!(
            RustlsTcpConnector::new(
                RustlsClientCredentials::new(Vec::new(), pki.client_private_key.clone()),
                valid_trust(),
                "kvm.test".into(),
                identity.clone(),
                RustlsConnectorConfig::default(),
            ),
            Err(RustlsConnectorConfigError::MissingClientCertificate)
        ));
        assert!(matches!(
            RustlsTcpConnector::new(
                RustlsClientCredentials::new(vec![pki.client_certificate.clone()], Vec::new()),
                valid_trust(),
                "kvm.test".into(),
                identity.clone(),
                RustlsConnectorConfig::default(),
            ),
            Err(RustlsConnectorConfigError::MissingClientPrivateKey)
        ));
        assert!(matches!(
            RustlsTcpConnector::new(
                valid_credentials(),
                RustlsServerTrust::new(Vec::new()),
                "kvm.test".into(),
                identity.clone(),
                RustlsConnectorConfig::default(),
            ),
            Err(RustlsConnectorConfigError::MissingServerTrustRoot)
        ));
        assert!(matches!(
            RustlsTcpConnector::new(
                valid_credentials(),
                RustlsServerTrust::new(vec![vec![1, 2, 3]]),
                "kvm.test".into(),
                identity.clone(),
                RustlsConnectorConfig::default(),
            ),
            Err(RustlsConnectorConfigError::InvalidServerTrustRoot)
        ));
        assert!(matches!(
            RustlsTcpConnector::new(
                valid_credentials(),
                valid_trust(),
                "not a dns name".into(),
                identity.clone(),
                RustlsConnectorConfig::default(),
            ),
            Err(RustlsConnectorConfigError::InvalidServerName)
        ));
        assert!(matches!(
            RustlsTcpConnector::new(
                valid_credentials(),
                valid_trust(),
                "kvm.test".into(),
                identity.clone(),
                RustlsConnectorConfig {
                    connect_timeout: Duration::ZERO,
                    ..RustlsConnectorConfig::default()
                },
            ),
            Err(RustlsConnectorConfigError::InvalidTimeout)
        ));
    }

    #[test]
    fn constructor_rejects_every_timeout_above_or_below_its_hard_bound() {
        let pki = TestPki::generate();
        for config in [
            RustlsConnectorConfig {
                connect_timeout: Duration::ZERO,
                ..RustlsConnectorConfig::default()
            },
            RustlsConnectorConfig {
                handshake_timeout: Duration::ZERO,
                ..RustlsConnectorConfig::default()
            },
            RustlsConnectorConfig {
                connect_timeout: MAX_CONNECT_TIMEOUT + Duration::from_nanos(1),
                ..RustlsConnectorConfig::default()
            },
            RustlsConnectorConfig {
                handshake_timeout: MAX_HANDSHAKE_TIMEOUT + Duration::from_nanos(1),
                ..RustlsConnectorConfig::default()
            },
        ] {
            assert!(matches!(
                RustlsTcpConnector::new(
                    RustlsClientCredentials::new(
                        vec![pki.client_certificate.clone()],
                        pki.client_private_key.clone(),
                    ),
                    RustlsServerTrust::new(vec![pki.root.clone()]),
                    "kvm.test".into(),
                    pki.identity(),
                    config,
                ),
                Err(RustlsConnectorConfigError::InvalidTimeout)
            ));
        }
    }

    #[test]
    fn constructor_rejects_every_credential_and_trust_size_bound() {
        let pki = TestPki::generate();
        let identity = pki.identity();
        let valid_credentials = || {
            RustlsClientCredentials::new(
                vec![pki.client_certificate.clone()],
                pki.client_private_key.clone(),
            )
        };
        let valid_trust = || RustlsServerTrust::new(vec![pki.root.clone()]);
        for credentials in [
            RustlsClientCredentials::new(
                vec![vec![1]; MAX_CERTIFICATE_CHAIN_LENGTH + 1],
                pki.client_private_key.clone(),
            ),
            RustlsClientCredentials::new(
                vec![vec![1; MAX_CERTIFICATE_DER_BYTES + 1]],
                pki.client_private_key.clone(),
            ),
            RustlsClientCredentials::new(
                vec![vec![1; MAX_CERTIFICATE_CHAIN_DER_BYTES / 5 + 1]; 5],
                pki.client_private_key.clone(),
            ),
            RustlsClientCredentials::new(
                vec![pki.client_certificate.clone()],
                vec![1; MAX_PRIVATE_KEY_DER_BYTES + 1],
            ),
        ] {
            assert!(matches!(
                RustlsTcpConnector::new(
                    credentials,
                    valid_trust(),
                    "kvm.test".into(),
                    identity.clone(),
                    RustlsConnectorConfig::default(),
                ),
                Err(RustlsConnectorConfigError::ClientCredentialsTooLarge)
            ));
        }
        for trust in [
            RustlsServerTrust::new(vec![vec![1]; MAX_TRUST_ROOTS + 1]),
            RustlsServerTrust::new(vec![vec![1; MAX_TRUST_ROOT_DER_BYTES + 1]]),
            RustlsServerTrust::new(vec![vec![1; MAX_TRUST_ROOTS_DER_BYTES / 17 + 1]; 18]),
        ] {
            assert!(matches!(
                RustlsTcpConnector::new(
                    valid_credentials(),
                    trust,
                    "kvm.test".into(),
                    identity.clone(),
                    RustlsConnectorConfig::default(),
                ),
                Err(RustlsConnectorConfigError::ServerTrustTooLarge)
            ));
        }
    }

    #[tokio::test]
    async fn accepted_client_credentials_enable_export_and_framed_traffic() {
        let pki = TestPki::generate();
        let expected = pki.identity();
        let (address, server) = spawn_tls_server(pki.server_config(KVM_ALPN)).await;
        let mut connector = pki.connector(expected.clone(), RustlsConnectorConfig::default());
        let mut client = connector.connect(address).await.unwrap();
        assert_eq!(client.authenticated_peer_identity(), &expected);
        assert_eq!(format!("{client:?}"), "RustlsPeerStream([REDACTED])");
        assert!(client.inner.get_ref().0.nodelay().unwrap());

        let context = b"exporter-test-context";
        let client_export = client
            .export_keying_material(b"EXPORTER-software-kvm-test", context)
            .unwrap();
        let server = server.await.unwrap().unwrap();
        let server_export = server
            .get_ref()
            .1
            .export_keying_material([0_u8; 32], b"EXPORTER-software-kvm-test", Some(context))
            .unwrap();
        assert_eq!(client_export, server_export);

        let (server_read, server_write) = tokio::io::split(server);
        let server_task = tokio::spawn(async move {
            let mut reader = FrameReader::new_authenticated(server_read);
            let mut writer = FrameWriter::new_authenticated(server_write);
            assert_eq!(
                reader.read_message().await.unwrap(),
                WireMessage::Ping(PingV1 {
                    nonce: 7,
                    sent_at_ns: 9
                })
            );
            writer
                .write_message(&WireMessage::Pong(PongV1 {
                    nonce: 7,
                    ping_sent_at_ns: 9,
                    received_at_ns: 11,
                }))
                .await
                .unwrap();
            writer.flush().await.unwrap();
        });
        let (client_read, client_write) = tokio::io::split(&mut client);
        let mut reader = FrameReader::new_authenticated(client_read);
        let mut writer = FrameWriter::new_authenticated(client_write);
        writer
            .write_message(&WireMessage::Ping(PingV1 {
                nonce: 7,
                sent_at_ns: 9,
            }))
            .await
            .unwrap();
        writer.flush().await.unwrap();
        assert!(matches!(
            reader.read_message().await.unwrap(),
            WireMessage::Pong(PongV1 { nonce: 7, .. })
        ));
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn wrong_fingerprint_is_rejected_after_a_valid_handshake() {
        let pki = TestPki::generate();
        let mut wrong = pki.identity();
        wrong.credential_fingerprint[0] ^= 0xff;
        let (address, server) = spawn_tls_server(pki.server_config(KVM_ALPN)).await;
        let mut connector = pki.connector(wrong, RustlsConnectorConfig::default());

        let error = connector.connect(address).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!error.to_string().contains("fingerprint"));
        assert!(server.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn wrong_server_name_is_rejected_despite_a_trusted_root() {
        let pki = TestPki::generate();
        let (address, server) = spawn_tls_server(pki.server_config(KVM_ALPN)).await;
        let mut connector = RustlsTcpConnector::new(
            RustlsClientCredentials::new(
                vec![pki.client_certificate.clone()],
                pki.client_private_key.clone(),
            ),
            RustlsServerTrust::new(vec![pki.root.clone()]),
            "different.test".to_owned(),
            pki.identity(),
            RustlsConnectorConfig::default(),
        )
        .unwrap();

        let error = connector.connect(address).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let _ = server.await;
    }

    #[tokio::test]
    async fn plaintext_and_wrong_alpn_endpoints_are_rejected() {
        let pki = TestPki::generate();
        let plaintext = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let plaintext_address = DevelopmentAddress::new(plaintext.local_addr().unwrap());
        let plaintext_task = tokio::spawn(async move {
            let (mut stream, _) = plaintext.accept().await.unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut stream, b"not tls")
                .await
                .unwrap();
        });
        let mut connector = pki.connector(pki.identity(), RustlsConnectorConfig::default());
        assert_eq!(
            connector
                .connect(plaintext_address)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        plaintext_task.await.unwrap();

        let (address, server) = spawn_tls_server(pki.server_config(b"wrong-protocol")).await;
        let mut connector = pki.connector(pki.identity(), RustlsConnectorConfig::default());
        assert_eq!(
            connector.connect(address).await.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        let _ = server.await;
    }

    #[tokio::test]
    async fn unknown_server_is_rejected_and_unknown_client_is_not_accepted_by_server() {
        let trusted = TestPki::generate();
        let untrusted_server = TestPki::generate();
        let (address, server) = spawn_tls_server(untrusted_server.server_config(KVM_ALPN)).await;
        let mut connector = trusted.connector(trusted.identity(), RustlsConnectorConfig::default());
        assert_eq!(
            connector.connect(address).await.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        let _ = server.await;

        let untrusted_client = TestPki::generate();
        let (address, server) = spawn_tls_server(trusted.server_config(KVM_ALPN)).await;
        let mut connector = RustlsTcpConnector::new(
            RustlsClientCredentials::new(
                vec![untrusted_client.client_certificate],
                untrusted_client.client_private_key,
            ),
            RustlsServerTrust::new(vec![trusted.root.clone()]),
            "kvm.test".to_owned(),
            trusted.identity(),
            RustlsConnectorConfig::default(),
        )
        .unwrap();
        let client_result = connector.connect(address).await;
        assert!(server.await.unwrap().is_err());
        // `connect` proves local TLS completion and remote-server authentication,
        // not that the server accepted this client's certificate. TLS 1.3 allows
        // the client to finish its local flight before receiving the server's
        // rejection alert. If that race occurs, the first application read
        // surfaces the alert, so bidirectional admission cannot complete.
        if let Ok(mut stream) = client_result {
            let mut byte = [0_u8; 1];
            let read = tokio::time::timeout(
                Duration::from_secs(1),
                tokio::io::AsyncReadExt::read_exact(&mut stream, &mut byte),
            )
            .await
            .unwrap();
            assert!(read.is_err());
        }
    }

    #[tokio::test]
    async fn tls_handshake_timeout_is_separate_and_redacted() {
        let pki = TestPki::generate();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = DevelopmentAddress::new(listener.local_addr().unwrap());
        let hold = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        let mut connector = pki.connector(
            pki.identity(),
            RustlsConnectorConfig {
                connect_timeout: Duration::from_secs(1),
                handshake_timeout: Duration::from_millis(20),
            },
        );
        let error = connector.connect(address).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(error.to_string(), "TLS handshake timed out");
        hold.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn bounded_connect_operation_reports_its_own_timeout() {
        let error = timeout_io(
            Duration::from_secs(2),
            std::future::pending::<io::Result<()>>(),
            "TCP connection timed out",
        )
        .await
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(error.to_string(), "TCP connection timed out");
    }
}
