use crate::{
    connector::sealed, AuthenticatedAcceptor, ClientIdentityResolutionError, ConnectionDirection,
    PairedClientIdentityResolver, SecurePeerStream, TransportPeerIdentity,
};
use sha2::{Digest, Sha256};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::server::{NoServerSessionStorage, WebPkiClientVerifier};
use tokio_rustls::rustls::{NoKeyLog, RootCertStore, ServerConfig};
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroizing;

const KVM_ALPN: &[u8] = b"software-kvm/1";
const MAX_CERTIFICATE_CHAIN_LENGTH: usize = 8;
const MAX_CERTIFICATE_DER_BYTES: usize = 64 * 1024;
const MAX_CERTIFICATE_CHAIN_DER_BYTES: usize = 256 * 1024;
const MAX_PRIVATE_KEY_DER_BYTES: usize = 16 * 1024;
const MAX_TRUST_ROOTS: usize = 64;
const MAX_TRUST_ROOT_DER_BYTES: usize = 64 * 1024;
const MAX_TRUST_ROOTS_DER_BYTES: usize = 1024 * 1024;
const MAX_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Public certificate chain and PKCS#8 private key used by the inbound TLS
/// endpoint. Debug output is fully redacted.
pub struct RustlsServerCredentials {
    certificate_chain_der: Vec<Vec<u8>>,
    private_key_pkcs8_der: Zeroizing<Vec<u8>>,
}

impl RustlsServerCredentials {
    #[must_use]
    pub fn new(certificate_chain_der: Vec<Vec<u8>>, private_key_pkcs8_der: Vec<u8>) -> Self {
        Self {
            certificate_chain_der,
            private_key_pkcs8_der: Zeroizing::new(private_key_pkcs8_der),
        }
    }
}

impl std::fmt::Debug for RustlsServerCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RustlsServerCredentials([REDACTED])")
    }
}

/// Explicit certificate authorities trusted for inbound TLS clients.
pub struct RustlsClientTrust {
    root_certificates_der: Vec<Vec<u8>>,
}

impl RustlsClientTrust {
    #[must_use]
    pub fn new(root_certificates_der: Vec<Vec<u8>>) -> Self {
        Self {
            root_certificates_der,
        }
    }
}

impl std::fmt::Debug for RustlsClientTrust {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RustlsClientTrust([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RustlsAcceptorConfig {
    pub handshake_timeout: Duration,
}

impl Default for RustlsAcceptorConfig {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RustlsAcceptorConfigError {
    #[error("TLS handshake timeout is outside the permitted range")]
    InvalidHandshakeTimeout,
    #[error("a server certificate chain is required")]
    MissingServerCertificate,
    #[error("a PKCS#8 server private key is required")]
    MissingServerPrivateKey,
    #[error("at least one client trust root is required")]
    MissingClientTrustRoot,
    #[error("server credential input exceeds its permitted bound")]
    ServerCredentialsTooLarge,
    #[error("client trust input exceeds its permitted bound")]
    ClientTrustTooLarge,
    #[error("client trust root is malformed")]
    InvalidClientTrustRoot,
    #[error("server certificate or private key is malformed")]
    InvalidServerCredentials,
}

/// TLS 1.3 server adapter for an already-accepted TCP stream.
///
/// The adapter builds its rustls configuration internally, requires a
/// WebPKI-validated client certificate, verifies the exact KVM ALPN, and maps
/// the authenticated leaf fingerprint through a caller-owned paired identity
/// resolver before returning a sealed stream.
pub struct RustlsTcpAcceptor<R> {
    server_config: Arc<ServerConfig>,
    resolver: Arc<R>,
    config: RustlsAcceptorConfig,
}

impl<R> RustlsTcpAcceptor<R>
where
    R: PairedClientIdentityResolver,
{
    /// Builds a TLS 1.3-only server configuration from bounded explicit
    /// credentials and client trust roots.
    ///
    /// # Errors
    ///
    /// Returns a redacted configuration error for empty, malformed, unbounded,
    /// or unsafe inputs.
    pub fn new(
        credentials: RustlsServerCredentials,
        client_trust: RustlsClientTrust,
        resolver: R,
        config: RustlsAcceptorConfig,
    ) -> Result<Self, RustlsAcceptorConfigError> {
        validate_inputs(&credentials, &client_trust, config)?;

        let mut client_roots = RootCertStore::empty();
        for root in client_trust.root_certificates_der {
            client_roots
                .add(CertificateDer::from(root))
                .map_err(|_| RustlsAcceptorConfigError::InvalidClientTrustRoot)?;
        }
        let client_verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
            .build()
            .map_err(|_| RustlsAcceptorConfigError::InvalidClientTrustRoot)?;

        let certificate_chain = credentials
            .certificate_chain_der
            .into_iter()
            .map(CertificateDer::from)
            .collect();
        // The caller allocation remains under `Zeroizing` on all return paths.
        // rustls' owned private-key type zeroizes its necessary configured copy.
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            credentials.private_key_pkcs8_der.to_vec(),
        ));
        let provider = Arc::new(ring::default_provider());
        let mut server_config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13])
            .map_err(|_| RustlsAcceptorConfigError::InvalidServerCredentials)?
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(certificate_chain, private_key)
            .map_err(|_| RustlsAcceptorConfigError::InvalidServerCredentials)?;
        server_config.alpn_protocols = vec![KVM_ALPN.to_vec()];
        server_config.max_early_data_size = 0;
        server_config.send_tls13_tickets = 0;
        server_config.session_storage = Arc::new(NoServerSessionStorage {});
        server_config.key_log = Arc::new(NoKeyLog {});

        Ok(Self {
            server_config: Arc::new(server_config),
            resolver: Arc::new(resolver),
            config,
        })
    }

    async fn accept_inner(&self, stream: TcpStream) -> io::Result<RustlsAcceptedPeerStream> {
        stream
            .set_nodelay(true)
            .map_err(|_| authentication_failed())?;
        let tls = timeout(
            self.config.handshake_timeout,
            TlsAcceptor::from(Arc::clone(&self.server_config)).accept(stream),
        )
        .await
        .map_err(|_| tls_handshake_timed_out())?
        .map_err(|_| authentication_failed())?;

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
        let identity = self
            .resolver
            .resolve(&fingerprint)
            .map_err(redact_resolution_error)?;
        if !bool::from(fingerprint.ct_eq(&identity.credential_fingerprint)) {
            return Err(authentication_failed());
        }

        Ok(RustlsAcceptedPeerStream {
            inner: tls,
            identity,
        })
    }
}

impl<R> std::fmt::Debug for RustlsTcpAcceptor<R> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RustlsTcpAcceptor")
            .field("server_config", &"[REDACTED]")
            .field("resolver", &"[REDACTED]")
            .field("config", &self.config)
            .finish()
    }
}

impl<R> sealed::Acceptor for RustlsTcpAcceptor<R> where R: PairedClientIdentityResolver {}

impl<R> AuthenticatedAcceptor for RustlsTcpAcceptor<R>
where
    R: PairedClientIdentityResolver + 'static,
{
    type Stream = RustlsAcceptedPeerStream;

    fn accept(
        &self,
        stream: TcpStream,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::Stream>> + Send + '_>> {
        Box::pin(self.accept_inner(stream))
    }
}

/// Server-side TLS stream returned only after client authentication, exact
/// ALPN validation, bounded leaf hashing, and paired identity resolution.
pub struct RustlsAcceptedPeerStream {
    inner: tokio_rustls::server::TlsStream<TcpStream>,
    identity: TransportPeerIdentity,
}

impl std::fmt::Debug for RustlsAcceptedPeerStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RustlsAcceptedPeerStream([REDACTED])")
    }
}

impl sealed::SecureStream for RustlsAcceptedPeerStream {}

impl SecurePeerStream for RustlsAcceptedPeerStream {
    fn authenticated_peer_identity(&self) -> &TransportPeerIdentity {
        &self.identity
    }

    fn connection_direction(&self) -> ConnectionDirection {
        ConnectionDirection::Inbound
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

impl AsyncRead for RustlsAcceptedPeerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for RustlsAcceptedPeerStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

fn validate_inputs(
    credentials: &RustlsServerCredentials,
    client_trust: &RustlsClientTrust,
    config: RustlsAcceptorConfig,
) -> Result<(), RustlsAcceptorConfigError> {
    if config.handshake_timeout == Duration::ZERO
        || config.handshake_timeout > MAX_HANDSHAKE_TIMEOUT
    {
        return Err(RustlsAcceptorConfigError::InvalidHandshakeTimeout);
    }
    if credentials.certificate_chain_der.is_empty() {
        return Err(RustlsAcceptorConfigError::MissingServerCertificate);
    }
    if credentials.private_key_pkcs8_der.is_empty() {
        return Err(RustlsAcceptorConfigError::MissingServerPrivateKey);
    }
    if client_trust.root_certificates_der.is_empty() {
        return Err(RustlsAcceptorConfigError::MissingClientTrustRoot);
    }
    if credentials.certificate_chain_der.len() > MAX_CERTIFICATE_CHAIN_LENGTH
        || credentials.private_key_pkcs8_der.len() > MAX_PRIVATE_KEY_DER_BYTES
        || !bounded_der_input(
            &credentials.certificate_chain_der,
            MAX_CERTIFICATE_DER_BYTES,
            MAX_CERTIFICATE_CHAIN_DER_BYTES,
        )
    {
        return Err(RustlsAcceptorConfigError::ServerCredentialsTooLarge);
    }
    if client_trust.root_certificates_der.len() > MAX_TRUST_ROOTS
        || !bounded_der_input(
            &client_trust.root_certificates_der,
            MAX_TRUST_ROOT_DER_BYTES,
            MAX_TRUST_ROOTS_DER_BYTES,
        )
    {
        return Err(RustlsAcceptorConfigError::ClientTrustTooLarge);
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

fn redact_resolution_error(_: ClientIdentityResolutionError) -> io::Error {
    authentication_failed()
}

fn authentication_failed() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "TLS peer authentication failed",
    )
}

fn tls_handshake_timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuthenticatedConnector, DevelopmentAddress, FrameReader, FrameWriter,
        RustlsClientCredentials, RustlsConnectorConfig, RustlsServerTrust, RustlsTcpConnector,
    };
    use kvm_protocol::{PingV1, PongV1, WireHostId, WireMessage, WirePeerId};
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::rustls::{ClientConfig, NoKeyLog};
    use tokio_rustls::TlsConnector;

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

        fn client_identity(&self) -> TransportPeerIdentity {
            TransportPeerIdentity {
                host_id: WireHostId([1; 16]),
                peer_id: WirePeerId([2; 16]),
                credential_fingerprint: Sha256::digest(&self.client_certificate).into(),
            }
        }

        fn server_identity(&self) -> TransportPeerIdentity {
            TransportPeerIdentity {
                host_id: WireHostId([3; 16]),
                peer_id: WirePeerId([4; 16]),
                credential_fingerprint: Sha256::digest(&self.server_certificate).into(),
            }
        }

        fn acceptor<R>(&self, resolver: R, config: RustlsAcceptorConfig) -> RustlsTcpAcceptor<R>
        where
            R: PairedClientIdentityResolver,
        {
            RustlsTcpAcceptor::new(
                RustlsServerCredentials::new(
                    vec![self.server_certificate.clone()],
                    self.server_private_key.clone(),
                ),
                RustlsClientTrust::new(vec![self.root.clone()]),
                resolver,
                config,
            )
            .unwrap()
        }

        fn connector(&self) -> RustlsTcpConnector {
            RustlsTcpConnector::new(
                RustlsClientCredentials::new(
                    vec![self.client_certificate.clone()],
                    self.client_private_key.clone(),
                ),
                RustlsServerTrust::new(vec![self.root.clone()]),
                "kvm.test".to_owned(),
                self.server_identity(),
                RustlsConnectorConfig::default(),
            )
            .unwrap()
        }

        fn direct_client_config(
            &self,
            certificate: Option<(&[u8], &[u8])>,
            alpn: &[u8],
        ) -> Arc<ClientConfig> {
            let mut roots = RootCertStore::empty();
            roots.add(CertificateDer::from(self.root.clone())).unwrap();
            let provider = Arc::new(ring::default_provider());
            let builder = ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(roots);
            let mut config = match certificate {
                Some((certificate, private_key)) => builder
                    .with_client_auth_cert(
                        vec![CertificateDer::from(certificate.to_vec())],
                        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key.to_vec())),
                    )
                    .unwrap(),
                None => builder.with_no_client_auth(),
            };
            config.alpn_protocols = vec![alpn.to_vec()];
            config.enable_early_data = false;
            config.key_log = Arc::new(NoKeyLog {});
            Arc::new(config)
        }
    }

    #[derive(Clone)]
    struct FixedResolver {
        expected_fingerprint: [u8; 32],
        result: Result<TransportPeerIdentity, ClientIdentityResolutionError>,
    }

    impl FixedResolver {
        fn accepted(identity: TransportPeerIdentity) -> Self {
            Self {
                expected_fingerprint: identity.credential_fingerprint,
                result: Ok(identity),
            }
        }

        fn rejected(expected_fingerprint: [u8; 32], error: ClientIdentityResolutionError) -> Self {
            Self {
                expected_fingerprint,
                result: Err(error),
            }
        }
    }

    impl PairedClientIdentityResolver for FixedResolver {
        fn resolve(
            &self,
            credential_fingerprint: &[u8; 32],
        ) -> Result<TransportPeerIdentity, ClientIdentityResolutionError> {
            if !bool::from(credential_fingerprint.ct_eq(&self.expected_fingerprint)) {
                return Err(ClientIdentityResolutionError::Unknown);
            }
            self.result.clone()
        }
    }

    async fn bind_server<R>(
        acceptor: RustlsTcpAcceptor<R>,
    ) -> (
        DevelopmentAddress,
        tokio::task::JoinHandle<io::Result<RustlsAcceptedPeerStream>>,
    )
    where
        R: PairedClientIdentityResolver + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = DevelopmentAddress::new(listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            acceptor.accept(stream).await
        });
        (address, server)
    }

    #[test]
    fn credentials_trust_acceptor_identity_and_resolver_errors_are_redacted() {
        let marker = "e551a3bb065a-secret-marker";
        let credentials = RustlsServerCredentials::new(
            vec![marker.as_bytes().to_vec()],
            marker.as_bytes().to_vec(),
        );
        let trust = RustlsClientTrust::new(vec![marker.as_bytes().to_vec()]);
        assert_eq!(
            format!("{credentials:?}"),
            "RustlsServerCredentials([REDACTED])"
        );
        assert_eq!(format!("{trust:?}"), "RustlsClientTrust([REDACTED])");
        for error in [
            ClientIdentityResolutionError::Unavailable,
            ClientIdentityResolutionError::Unknown,
            ClientIdentityResolutionError::Ambiguous,
            ClientIdentityResolutionError::InvalidIdentity,
        ] {
            assert_eq!(
                error.to_string(),
                "paired client identity could not be resolved"
            );
            assert!(!format!("{error:?}").contains(marker));
        }

        let pki = TestPki::generate();
        let acceptor = pki.acceptor(
            FixedResolver::accepted(pki.client_identity()),
            RustlsAcceptorConfig::default(),
        );
        let debug = format!("{acceptor:?}");
        assert!(debug.contains("resolver: \"[REDACTED]\""));
        assert!(!debug.contains(&hex_marker(&pki.client_identity().credential_fingerprint)));
    }

    #[test]
    fn constructor_rejects_empty_malformed_unbounded_and_unsafe_inputs() {
        let pki = TestPki::generate();
        let resolver = || FixedResolver::accepted(pki.client_identity());
        let credentials = || {
            RustlsServerCredentials::new(
                vec![pki.server_certificate.clone()],
                pki.server_private_key.clone(),
            )
        };
        let trust = || RustlsClientTrust::new(vec![pki.root.clone()]);

        assert!(matches!(
            RustlsTcpAcceptor::new(
                RustlsServerCredentials::new(Vec::new(), pki.server_private_key.clone()),
                trust(),
                resolver(),
                RustlsAcceptorConfig::default(),
            ),
            Err(RustlsAcceptorConfigError::MissingServerCertificate)
        ));
        assert!(matches!(
            RustlsTcpAcceptor::new(
                RustlsServerCredentials::new(vec![pki.server_certificate.clone()], Vec::new()),
                trust(),
                resolver(),
                RustlsAcceptorConfig::default(),
            ),
            Err(RustlsAcceptorConfigError::MissingServerPrivateKey)
        ));
        assert!(matches!(
            RustlsTcpAcceptor::new(
                credentials(),
                RustlsClientTrust::new(Vec::new()),
                resolver(),
                RustlsAcceptorConfig::default(),
            ),
            Err(RustlsAcceptorConfigError::MissingClientTrustRoot)
        ));
        assert!(matches!(
            RustlsTcpAcceptor::new(
                RustlsServerCredentials::new(
                    vec![vec![1; MAX_CERTIFICATE_DER_BYTES + 1]],
                    pki.server_private_key.clone(),
                ),
                trust(),
                resolver(),
                RustlsAcceptorConfig::default(),
            ),
            Err(RustlsAcceptorConfigError::ServerCredentialsTooLarge)
        ));
        assert!(matches!(
            RustlsTcpAcceptor::new(
                credentials(),
                RustlsClientTrust::new(vec![vec![1; MAX_TRUST_ROOT_DER_BYTES + 1]]),
                resolver(),
                RustlsAcceptorConfig::default(),
            ),
            Err(RustlsAcceptorConfigError::ClientTrustTooLarge)
        ));
        assert!(matches!(
            RustlsTcpAcceptor::new(
                credentials(),
                RustlsClientTrust::new(vec![vec![1, 2, 3]]),
                resolver(),
                RustlsAcceptorConfig::default(),
            ),
            Err(RustlsAcceptorConfigError::InvalidClientTrustRoot)
        ));
        assert!(matches!(
            RustlsTcpAcceptor::new(
                RustlsServerCredentials::new(vec![vec![1, 2, 3]], vec![4, 5, 6]),
                trust(),
                resolver(),
                RustlsAcceptorConfig::default(),
            ),
            Err(RustlsAcceptorConfigError::InvalidServerCredentials)
        ));
        for handshake_timeout in [
            Duration::ZERO,
            MAX_HANDSHAKE_TIMEOUT + Duration::from_nanos(1),
        ] {
            assert!(matches!(
                RustlsTcpAcceptor::new(
                    credentials(),
                    trust(),
                    resolver(),
                    RustlsAcceptorConfig { handshake_timeout },
                ),
                Err(RustlsAcceptorConfigError::InvalidHandshakeTimeout)
            ));
        }
    }

    #[tokio::test]
    async fn authenticated_loopback_exports_equal_material_and_frames_traffic() {
        let pki = TestPki::generate();
        let client_identity = pki.client_identity();
        let acceptor = pki.acceptor(
            FixedResolver::accepted(client_identity.clone()),
            RustlsAcceptorConfig::default(),
        );
        let (address, server) = bind_server(acceptor).await;
        let mut connector = pki.connector();
        let client = connector.connect(address).await.unwrap();
        let mut accepted = server.await.unwrap().unwrap();

        assert_eq!(accepted.authenticated_peer_identity(), &client_identity);
        assert_eq!(
            format!("{accepted:?}"),
            "RustlsAcceptedPeerStream([REDACTED])"
        );
        assert!(accepted.inner.get_ref().0.nodelay().unwrap());
        let context = b"accepted-session-context";
        assert_eq!(
            client
                .export_keying_material(b"EXPORTER-software-kvm-test", context)
                .unwrap(),
            accepted
                .export_keying_material(b"EXPORTER-software-kvm-test", context)
                .unwrap()
        );

        let (mut client_read, mut client_write) = tokio::io::split(client);
        let server_task = tokio::spawn(async move {
            let (accepted_read, accepted_write) = tokio::io::split(&mut accepted);
            let mut reader = FrameReader::new_authenticated(accepted_read);
            let mut writer = FrameWriter::new_authenticated(accepted_write);
            assert!(matches!(
                reader.read_message().await.unwrap(),
                WireMessage::Ping(PingV1 { nonce: 7, .. })
            ));
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
        let mut writer = FrameWriter::new_authenticated(&mut client_write);
        writer
            .write_message(&WireMessage::Ping(PingV1 {
                nonce: 7,
                sent_at_ns: 9,
            }))
            .await
            .unwrap();
        writer.flush().await.unwrap();
        let mut reader = FrameReader::new_authenticated(&mut client_read);
        assert!(matches!(
            reader.read_message().await.unwrap(),
            WireMessage::Pong(PongV1 { nonce: 7, .. })
        ));
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn self_signed_dual_purpose_peers_authenticate_each_other() {
        fn peer(name: &str, host: u8, peer: u8) -> (Vec<u8>, Vec<u8>, TransportPeerIdentity) {
            let key = KeyPair::generate().unwrap();
            let mut parameters = CertificateParams::new(vec![name.to_owned()]).unwrap();
            parameters.is_ca = IsCa::NoCa;
            parameters.extended_key_usages = vec![
                ExtendedKeyUsagePurpose::ServerAuth,
                ExtendedKeyUsagePurpose::ClientAuth,
            ];
            let certificate = parameters.self_signed(&key).unwrap().der().to_vec();
            let identity = TransportPeerIdentity {
                host_id: WireHostId([host; 16]),
                peer_id: WirePeerId([peer; 16]),
                credential_fingerprint: Sha256::digest(&certificate).into(),
            };
            (certificate, key.serialize_der(), identity)
        }

        let (server_certificate, server_key, server_identity) = peer("server.kvm.test", 1, 2);
        let (client_certificate, client_key, client_identity) = peer("client.kvm.test", 3, 4);
        let acceptor = RustlsTcpAcceptor::new(
            RustlsServerCredentials::new(vec![server_certificate.clone()], server_key),
            RustlsClientTrust::new(vec![client_certificate.clone()]),
            FixedResolver::accepted(client_identity),
            RustlsAcceptorConfig::default(),
        )
        .unwrap();
        let mut connector = RustlsTcpConnector::new(
            RustlsClientCredentials::new(vec![client_certificate.clone()], client_key),
            RustlsServerTrust::new(vec![server_certificate]),
            "server.kvm.test".to_owned(),
            server_identity,
            RustlsConnectorConfig::default(),
        )
        .unwrap();
        let (address, server) = bind_server(acceptor).await;

        assert!(connector.connect(address).await.is_ok());
        assert!(server.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn ca_certificates_without_tls_purposes_cannot_authenticate_as_peers() {
        fn peer(name: &str, host: u8, peer: u8) -> (Vec<u8>, Vec<u8>, TransportPeerIdentity) {
            let key = KeyPair::generate().unwrap();
            let mut parameters = CertificateParams::new(vec![name.to_owned()]).unwrap();
            parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let certificate = parameters.self_signed(&key).unwrap().der().to_vec();
            let identity = TransportPeerIdentity {
                host_id: WireHostId([host; 16]),
                peer_id: WirePeerId([peer; 16]),
                credential_fingerprint: Sha256::digest(&certificate).into(),
            };
            (certificate, key.serialize_der(), identity)
        }

        let (server_certificate, server_key, server_identity) = peer("server.kvm.test", 1, 2);
        let (client_certificate, client_key, client_identity) = peer("client.kvm.test", 3, 4);
        let acceptor = RustlsTcpAcceptor::new(
            RustlsServerCredentials::new(vec![server_certificate.clone()], server_key),
            RustlsClientTrust::new(vec![client_certificate.clone()]),
            FixedResolver::accepted(client_identity),
            RustlsAcceptorConfig::default(),
        )
        .unwrap();
        let mut connector = RustlsTcpConnector::new(
            RustlsClientCredentials::new(vec![client_certificate], client_key),
            RustlsServerTrust::new(vec![server_certificate]),
            "server.kvm.test".to_owned(),
            server_identity,
            RustlsConnectorConfig::default(),
        )
        .unwrap();
        let (address, server) = bind_server(acceptor).await;

        let _ = connector.connect(address).await;
        assert!(server.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn resolver_failures_and_identity_mismatch_are_coarsely_rejected() {
        for resolution_error in [
            ClientIdentityResolutionError::Unavailable,
            ClientIdentityResolutionError::Unknown,
            ClientIdentityResolutionError::Ambiguous,
            ClientIdentityResolutionError::InvalidIdentity,
        ] {
            let pki = TestPki::generate();
            let resolver = FixedResolver::rejected(
                pki.client_identity().credential_fingerprint,
                resolution_error,
            );
            let (address, server) =
                bind_server(pki.acceptor(resolver, RustlsAcceptorConfig::default())).await;
            let mut connector = pki.connector();
            let _ = connector.connect(address).await;
            let error = server.await.unwrap().unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(error.to_string(), "TLS peer authentication failed");
        }

        let pki = TestPki::generate();
        let mut mismatched = pki.client_identity();
        mismatched.credential_fingerprint[0] ^= 0xff;
        let resolver = FixedResolver {
            expected_fingerprint: pki.client_identity().credential_fingerprint,
            result: Ok(mismatched),
        };
        let (address, server) =
            bind_server(pki.acceptor(resolver, RustlsAcceptorConfig::default())).await;
        let mut connector = pki.connector();
        let _ = connector.connect(address).await;
        let error = server.await.unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(error.to_string(), "TLS peer authentication failed");
    }

    #[tokio::test]
    async fn missing_unknown_and_wrong_purpose_client_credentials_are_rejected() {
        let trusted = TestPki::generate();

        let acceptor = trusted.acceptor(
            FixedResolver::accepted(trusted.client_identity()),
            RustlsAcceptorConfig::default(),
        );
        let (address, server) = bind_server(acceptor).await;
        let client = connect_direct(address, trusted.direct_client_config(None, KVM_ALPN)).await;
        assert!(server.await.unwrap().is_err());
        if let Ok(mut client) = client {
            let mut byte = [0_u8; 1];
            assert!(client.read_exact(&mut byte).await.is_err());
        }

        let untrusted = TestPki::generate();
        let acceptor = trusted.acceptor(
            FixedResolver::accepted(trusted.client_identity()),
            RustlsAcceptorConfig::default(),
        );
        let (address, server) = bind_server(acceptor).await;
        let client = connect_direct(
            address,
            trusted.direct_client_config(
                Some((&untrusted.client_certificate, &untrusted.client_private_key)),
                KVM_ALPN,
            ),
        )
        .await;
        assert!(server.await.unwrap().is_err());
        if let Ok(mut client) = client {
            let mut byte = [0_u8; 1];
            assert!(client.read_exact(&mut byte).await.is_err());
        }

        let acceptor = trusted.acceptor(
            FixedResolver::accepted(trusted.client_identity()),
            RustlsAcceptorConfig::default(),
        );
        let (address, server) = bind_server(acceptor).await;
        let client = connect_direct(
            address,
            trusted.direct_client_config(
                Some((&trusted.server_certificate, &trusted.server_private_key)),
                KVM_ALPN,
            ),
        )
        .await;
        assert!(server.await.unwrap().is_err());
        if let Ok(mut client) = client {
            let mut byte = [0_u8; 1];
            assert!(client.read_exact(&mut byte).await.is_err());
        }
    }

    #[tokio::test]
    async fn wrong_alpn_plaintext_and_handshake_stall_are_rejected() {
        let pki = TestPki::generate();
        let acceptor = pki.acceptor(
            FixedResolver::accepted(pki.client_identity()),
            RustlsAcceptorConfig::default(),
        );
        let (address, server) = bind_server(acceptor).await;
        let _ = connect_direct(
            address,
            pki.direct_client_config(
                Some((&pki.client_certificate, &pki.client_private_key)),
                b"wrong-protocol",
            ),
        )
        .await;
        let error = server.await.unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);

        let acceptor = pki.acceptor(
            FixedResolver::accepted(pki.client_identity()),
            RustlsAcceptorConfig::default(),
        );
        let (address, server) = bind_server(acceptor).await;
        let mut plaintext = TcpStream::connect(address.socket_addr()).await.unwrap();
        plaintext.write_all(b"not tls").await.unwrap();
        plaintext.shutdown().await.unwrap();
        let error = server.await.unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);

        let acceptor = pki.acceptor(
            FixedResolver::accepted(pki.client_identity()),
            RustlsAcceptorConfig {
                handshake_timeout: Duration::from_millis(20),
            },
        );
        let (address, server) = bind_server(acceptor).await;
        let stalled = TcpStream::connect(address.socket_addr()).await.unwrap();
        let error = server.await.unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(error.to_string(), "TLS handshake timed out");
        drop(stalled);
    }

    #[tokio::test]
    async fn authenticated_clean_eof_is_exposed_without_reusing_identity() {
        let pki = TestPki::generate();
        let acceptor = pki.acceptor(
            FixedResolver::accepted(pki.client_identity()),
            RustlsAcceptorConfig::default(),
        );
        let (address, server) = bind_server(acceptor).await;
        let mut connector = pki.connector();
        let mut client = connector.connect(address).await.unwrap();
        let mut accepted = server.await.unwrap().unwrap();
        client.shutdown().await.unwrap();
        let mut byte = [0_u8; 1];
        assert_eq!(accepted.read(&mut byte).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn abrupt_tcp_reset_during_handshake_is_coarsely_rejected() {
        let pki = TestPki::generate();
        let acceptor = pki.acceptor(
            FixedResolver::accepted(pki.client_identity()),
            RustlsAcceptorConfig::default(),
        );
        let (address, server) = bind_server(acceptor).await;
        let stream = TcpStream::connect(address.socket_addr()).await.unwrap();
        stream.set_zero_linger().unwrap();
        drop(stream);

        let error = server.await.unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(error.to_string(), "TLS peer authentication failed");
    }

    async fn connect_direct(
        address: DevelopmentAddress,
        config: Arc<ClientConfig>,
    ) -> io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let tcp = TcpStream::connect(address.socket_addr()).await?;
        let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from("kvm.test")
            .unwrap()
            .to_owned();
        TlsConnector::from(config)
            .connect(server_name, tcp)
            .await
            .map_err(io::Error::other)
    }

    fn hex_marker(bytes: &[u8]) -> String {
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use std::fmt::Write as _;
            write!(&mut output, "{byte:02x}").unwrap();
        }
        output
    }
}
