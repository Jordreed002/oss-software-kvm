//! TLS record-encryption throughput benchmark for the outbound hot path.
//!
//! These measure the CPU cost of encrypting and writing input frames through a
//! real rustls TLS 1.3 session — the work that bounds events/sec on the
//! *outbound* direction after the queue and codec, and the last unmeasured CPU
//! cost on the end-to-end path. The sibling `outbound_queue` and `frame_codec`
//! benches already covered enqueue/coalescing and serialization; this one
//! confirms whether TLS record encryption is the bottleneck the audits
//! inferred, or has the same orders of magnitude of 175 Hz headroom as the rest
//! of the user-space path.
//!
//! The session mirrors the production crypto stack exactly — TLS 1.3, the ring
//! AEAD provider, mutual certificate authentication via a self-signed rcgen
//! PKI, and the same ALPN marker — but runs over an in-memory `duplex` rather
//! than a TCP socket, to isolate the encrypt/AEAD cost from kernel networking
//! noise. Two scenarios bracket the iter-2 outbound write-batching work:
//!
//!   1. **per-frame encrypt+flush** — one frame written and flushed per
//!      iteration (the unbatched baseline): one TLS record (one AEAD
//!      seal) per frame.
//!   2. **batched encrypt (64 frames, one flush)** — 64 frames written then a
//!      single flush (the production `OUTBOUND_BATCH_MAX_FRAMES` path from
//!      iter 2): far fewer, larger records.
//!
//! Run with `cargo bench -p kvm-network`. Bench targets are not built by
//! `cargo test`, so these never run in CI and add no test-suite flakiness.
//!
//! `clippy::pedantic` is relaxed here because benchmark ergonomics (async
//! setup, float percentile math) routinely trip style lints that are not
//! meaningful for measurement code; `clippy::all` correctness lints stay on.

#![allow(clippy::pedantic)]

use std::cmp::Ordering;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use kvm_protocol::{
    encode_frame_for_version_into, InputEventV1, WireDeviceId, WireHostId, WireInputPayloadV1,
    WireMessage, CURRENT_PROTOCOL_VERSION,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName,
};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{ClientConfig, NoKeyLog, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// A decrypted, encrypted client-side TLS stream over an in-memory duplex.
type ClientTls = tokio_rustls::client::TlsStream<tokio::io::DuplexStream>;

/// Target sustained event rate: a single 175 Hz display (spec §37).
const DISPLAY_HZ: f64 = 175.0;
/// Wall-clock warmup before sampling, to stabilize caches / branch prediction.
const WARMUP: Duration = Duration::from_millis(300);
/// Number of timed samples per scenario; drives the median / p95 estimates.
const SAMPLE_RUNS: usize = 31;
/// Frames written per timed sample. Smaller than the sync benches because each
/// frame here crosses an await point (the async TLS write).
const FRAMES_PER_RUN: usize = 10_000;
/// Frames coalesced into a single TLS record in the batched scenario. Mirrors
/// the production `OUTBOUND_BATCH_MAX_FRAMES` cap (iter 2).
const BATCH_FRAMES: usize = 64;
/// Backing buffer for the in-memory duplex pipe (large enough that the writer
/// only blocks on genuine backpressure, not buffer capacity).
const DUPLEX_BUFFER: usize = 256 * 1024;
/// ALPN marker for the bench session (exercises the same negotiation path).
const ALPN: &[u8] = b"software-kvm/bench";

#[tokio::main(flavor = "current_thread")]
async fn main() {
    println!(
        "kvm-network TLS record-encryption throughput  ({} frames/sample, {} samples, TLS 1.3/ring)\n",
        FRAMES_PER_RUN, SAMPLE_RUNS
    );
    println!(
        "{:<32} {:>15}   {:>15}   {:>9}   scenario",
        "path", "median fr/s", "p95 fr/s", "x175Hz"
    );
    println!("{}", "-".repeat(108));

    let pki = Pki::generate();
    let server_config = server_config(&pki);
    let client_config = client_config(&pki);
    let frame = encoded_pointer_move();

    // 1. Unbatched baseline: one AEAD record per frame. This is what the iter-2
    //    write batching exists to avoid; it bounds the worst-case per-frame TLS
    //    cost (encrypt + flush + await yield per frame).
    measure(
        "encrypt: per-frame flush",
        "one frame written then flushed per iteration (unbatched baseline)",
        &server_config,
        &client_config,
        &frame,
        |mut client, bytes| async move {
            for _ in 0..FRAMES_PER_RUN {
                client.write_all(bytes).await.unwrap();
                client.flush().await.unwrap();
            }
        },
    )
    .await;

    // 2. Production batched path: BATCH_FRAMES frames buffered then one flush,
    //    so the burst crosses the transport as a few large TLS records (iter 2).
    measure(
        "encrypt: batched (64/frame record)",
        "64 frames written then a single flush (iter-2 production batching)",
        &server_config,
        &client_config,
        &frame,
        |mut client, bytes| async move {
            let batches = FRAMES_PER_RUN / BATCH_FRAMES;
            for _ in 0..batches {
                for _ in 0..BATCH_FRAMES {
                    client.write_all(bytes).await.unwrap();
                }
                client.flush().await.unwrap();
            }
        },
    )
    .await;

    println!(
        "\nBoth paths should show multiple orders of magnitude of headroom above\n\
         {DISPLAY_HZ:.0} Hz. If the batched path approaches the wire rate, TLS encryption\n\
         is the real remaining cost; otherwise the user-space path (queue + codec + TLS)\n\
         is nowhere near a 175 Hz bottleneck and residual latency is transport-bound."
    );
}

/// Runs one benchmark scenario and prints median / p95 throughput in frames/s.
///
/// Each timed sample handshakes a fresh session (handshake cost is excluded —
/// only `body` is timed), then writes `FRAMES_PER_RUN` frames through it. The
/// `body` closure receives the pre-encoded frame bytes and a freshly
/// handshaked client stream; it owns the stream for the run and dropping it
/// tears the session down.
async fn measure<'a, F, Fut>(
    name: &str,
    scenario: &str,
    server_config: &Arc<ServerConfig>,
    client_config: &Arc<ClientConfig>,
    frame: &'a [u8],
    body: F,
) where
    F: FnMut(ClientTls, &'a [u8]) -> Fut,
    Fut: Future<Output = ()> + 'a,
{
    let mut body = body;
    // Warmup: run the body until WARMUP elapses, handshaking a fresh session
    // each run.
    let warmup_start = Instant::now();
    while warmup_start.elapsed() < WARMUP {
        let client = make_session(server_config, client_config).await;
        body(client, frame).await;
    }

    // Sample: timed runs.
    let mut samples: Vec<f64> = Vec::with_capacity(SAMPLE_RUNS);
    for _ in 0..SAMPLE_RUNS {
        let client = make_session(server_config, client_config).await;
        let start = Instant::now();
        body(client, frame).await;
        let elapsed = start.elapsed().as_secs_f64();
        samples.push(FRAMES_PER_RUN as f64 / elapsed.max(f64::MIN_POSITIVE));
    }

    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
    let median = samples[SAMPLE_RUNS / 2];
    let p95_idx = (((SAMPLE_RUNS as f64) * 0.95).ceil() as usize)
        .saturating_sub(1)
        .min(SAMPLE_RUNS - 1);
    let p95 = samples[p95_idx];

    println!(
        "{name:<32} {median:>15.0}   {p95:>15.0}   {headroom:>8.0}x   {scenario}",
        headroom = median / DISPLAY_HZ
    );
}

/// Handshakes a fresh TLS 1.3 client/server pair over an in-memory duplex and
/// spawns a detached background task that drains the decrypted server side so
/// the client's writes never stall on backpressure. Returns the client stream;
/// the drain task ends naturally when the client side is dropped.
async fn make_session(
    server_config: &Arc<ServerConfig>,
    client_config: &Arc<ClientConfig>,
) -> ClientTls {
    let (client_io, server_io) = tokio::io::duplex(DUPLEX_BUFFER);

    let server_config = Arc::clone(server_config);
    let server = tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(server_config);
        let mut stream = acceptor.accept(server_io).await.unwrap();
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });

    let connector = TlsConnector::from(Arc::clone(client_config));
    let domain = ServerName::try_from("kvm.test").unwrap();
    let client = connector.connect(domain, client_io).await.unwrap();

    // Detach the drain task so it lives as long as the connection.
    std::mem::forget(server);

    client
}

/// A minimal self-signed PKI (root CA + server + client certs), generated with
/// rcgen. Mirrors the test-harness PKI so the session exercises the same
/// mutual-certificate authentication as production.
struct Pki {
    root: Vec<u8>,
    server_certificate: Vec<u8>,
    server_private_key: Vec<u8>,
    client_certificate: Vec<u8>,
    client_private_key: Vec<u8>,
}

impl Pki {
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
}

/// Builds the server-side rustls config (TLS 1.3, ring, mutual client-cert
/// auth against the root, no session storage / key log). Mirrors the production
/// `RustlsTcpAcceptor` builder. The provider is passed explicitly so no
/// process-default crypto provider needs to be installed.
fn server_config(pki: &Pki) -> Arc<ServerConfig> {
    let mut client_roots = RootCertStore::empty();
    client_roots
        .add(CertificateDer::from(pki.root.clone()))
        .unwrap();
    let provider = Arc::new(ring::default_provider());
    let client_verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(client_roots), Arc::clone(&provider))
            .build()
            .unwrap();
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(
            vec![CertificateDer::from(pki.server_certificate.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.server_private_key.clone())),
        )
        .unwrap();
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.max_early_data_size = 0;
    config.send_tls13_tickets = 0;
    config.key_log = Arc::new(NoKeyLog {});
    Arc::new(config)
}

/// Builds the client-side rustls config (TLS 1.3, ring, root trust, client
/// cert auth). Mirrors the production connector builder.
fn client_config(pki: &Pki) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(pki.root.clone())).unwrap();
    let provider = Arc::new(ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            vec![CertificateDer::from(pki.client_certificate.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.client_private_key.clone())),
        )
        .unwrap();
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.enable_early_data = false;
    config.key_log = Arc::new(NoKeyLog {});
    Arc::new(config)
}

/// Constructs the benchmark `PointerMove` input frame, pre-encoded once so the
/// timed loop measures only TLS cost (the codec is covered by the sibling
/// `frame_codec` bench).
fn encoded_pointer_move() -> Vec<u8> {
    let message = WireMessage::Input(InputEventV1 {
        sequence: 1,
        timestamp_ns: 1,
        source_host: WireHostId([1; 16]),
        source_device: WireDeviceId([2; 16]),
        payload: WireInputPayloadV1::PointerMove { dx: 1.0, dy: 0.0 },
    });
    let mut buf = Vec::with_capacity(4 * 1024);
    encode_frame_for_version_into(&message, CURRENT_PROTOCOL_VERSION, &mut buf)
        .expect("benchmark message encodes");
    buf
}
