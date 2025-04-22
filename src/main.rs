// This example demonstrates how to use the Prover to acquire an attestation for
// an HTTP request sent to example.com. The attestation and secrets are saved to
// disk.

use std::{env, time::Duration};

use http_body_util::Empty;
use hyper::{Request, StatusCode, Version, body::Bytes};
use hyper_util::rt::TokioIo;
use spansy::Spanned;
use tls_core::verify::WebPkiVerifier;
use tls_server_fixture::CA_CERT_DER;
use tokio::task::JoinSet;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use notary_client::{Accepted, NotarizationRequest, NotaryClient};
use tlsn_common::config::ProtocolConfig;
use tlsn_core::{request::RequestConfig, transcript::TranscriptCommitConfig, CryptoProvider};
use tlsn_formats::http::{DefaultHttpCommitter, HttpCommit, HttpTranscript};
use tlsn_prover::{Prover, ProverConfig};
use tracing::{Instrument, Level, debug, instrument, span};

// Maximum number of bytes that can be sent from prover to server
pub const MAX_SENT_DATA: usize = 1 << 10;
// Maximum number of bytes that can be received by prover from server
pub const MAX_RECV_DATA: usize = 1 << 12;

// Setting of the application server
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36";

const SERVER_DOMAIN: &str = "test-server.io";
const SERVER_PORT: u16 = 3000;
const URI: &str = "/formats/json";

const THREADS: usize = 16;
const ITERATIONS: u16 = 500;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // threads.join_all().await;

    let mut threads = JoinSet::new();
    for thread in 1..=THREADS {
        threads.spawn(
            async move {
                for iteration in 1..=ITERATIONS {
                    // let span = span!(Level::INFO, "", iteration);
                    // let _enter = span.enter();

                    let _ = notarize(URI).await.map_err(|e| {
                        eprintln!("{}", e);
                    });

                    println!("Iteration {iteration} completed on thread {thread}",);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        );
    }
    threads.join_all().await;

    // tokio::time::sleep(Duration::from_secs(15)).await;

    Ok(())
}

/// crypto provider accepting the server-fixture's self-signed certificate
///
/// This is only required for offline testing with the server-fixture. In
/// production, use `CryptoProvider::default()` instead.
pub fn get_crypto_provider_with_server_fixture() -> CryptoProvider {
    // custom root store with server-fixture
    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    CryptoProvider {
        cert: WebPkiVerifier::new(root_store, None),
        ..Default::default()
    }
}


#[instrument()]
async fn notarize(uri: &str) -> Result<(), Box<dyn std::error::Error>> {
    let notary_host: String = env::var("NOTARY_HOST").unwrap_or("127.0.0.1".into());
    let notary_port: u16 = env::var("NOTARY_PORT")
        .map(|port| port.parse().expect("port should be valid integer"))
        .unwrap_or(7047);
    let server_host: String = "127.0.0.1".into();
    let server_port: u16 = SERVER_PORT;

    // Build a client to connect to the notary server.
    let notary_client = NotaryClient::builder()
        .host(notary_host)
        .port(notary_port)
        // WARNING: Always use TLS to connect to notary server, except if notary is running locally
        // e.g. this example, hence `enable_tls` is set to False (else it always defaults to True).
        .enable_tls(false)
        .build()
        .unwrap();

    // Send requests for configuration and notarization to the notary server.
    let notarization_request = NotarizationRequest::builder()
        // We must configure the amount of data we expect to exchange beforehand, which will
        // be preprocessed prior to the connection. Reducing these limits will improve
        // performance.
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA)
        .build()?;

    let Accepted {
        io: notary_connection,
        id: _session_id,
        ..
    } = notary_client
        .request_notarization(notarization_request)
        .await
        .expect("Could not connect to notary. Make sure it is running.");

    // Set up protocol configuration for prover.
    // Prover configuration.
    let prover_config = ProverConfig::builder()
        .server_name(SERVER_DOMAIN)
        .protocol_config(
            ProtocolConfig::builder()
                // We must configure the amount of data we expect to exchange beforehand, which will
                // be preprocessed prior to the connection. Reducing these limits will improve
                // performance.
                .max_sent_data(MAX_SENT_DATA)
                .max_recv_data(MAX_RECV_DATA)
                .build()?,
        )
        // .crypto_provider(CryptoProvider::default())
        .crypto_provider(get_crypto_provider_with_server_fixture())
        .build()?;

    // Create a new prover and perform necessary setup.
    let prover = Prover::new(prover_config)
        .setup(notary_connection.compat())
        .await?;

    // Open a TCP connection to the server.
    let client_socket = tokio::net::TcpStream::connect((server_host, server_port)).await?;

    // Bind the prover to the server connection.
    // The returned `mpc_tls_connection` is an MPC TLS connection to the server: all
    // data written to/read from it will be encrypted/decrypted using MPC with
    // the notary.
    let (mpc_tls_connection, prover_fut) = prover.connect(client_socket.compat()).await?;
    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());

    // Spawn the prover task to be run concurrently in the background.
    let prover_task = tokio::spawn(prover_fut);

    // Attach the hyper HTTP client to the connection.
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection).await?;

    // Spawn the HTTP task to be run concurrently in the background.
    tokio::spawn(connection);

    // Build a simple HTTP request with common headers
    let request_builder = Request::builder()
        .version(Version::HTTP_10)
        .uri(uri)
        .header("Host", SERVER_DOMAIN)
        .header("Accept", "*/*")
        // Using "identity" instructs the Server not to use compression for its HTTP response.
        // TLSNotary tooling does not support compression.
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header("User-Agent", USER_AGENT);
    // let mut request_builder = request_builder;

    let request = request_builder.body(Empty::<Bytes>::new())?;

    // tracing::info!("Starting an MPC TLS connection with the server");

    // Send the request to the server and wait for the response.
    let response = request_sender.send_request(request).await?;

    // tracing::info!("Got a response from the server: {}", response.status());

    assert!(response.status() == StatusCode::OK);

    // The prover task should be done now, so we can await it.
    let prover = prover_task.await??;

    // Prepare for notarization.
    let mut prover = prover.start_notarize();

    // Parse the HTTP transcript.
    let transcript = HttpTranscript::parse(prover.transcript())?;
    // dbg!(&transcript);

    let body_content = &transcript.responses[0].body.as_ref().unwrap().content;
    let body = String::from_utf8_lossy(body_content.span().as_bytes());

    match body_content {
        tlsn_formats::http::BodyContent::Json(_json) => {
            let parsed = serde_json::from_str::<serde_json::Value>(&body)?;
            debug!("{}", serde_json::to_string_pretty(&parsed)?);
        }
        tlsn_formats::http::BodyContent::Unknown(_span) => {
            debug!("{}", &body);
        }
        _ => {}
    }

    // Commit to the transcript.
    let mut builder = TranscriptCommitConfig::builder(prover.transcript());

    DefaultHttpCommitter::default().commit_transcript(&mut builder, &transcript)?;

    prover.transcript_commit(builder.build()?);

    // Request an attestation.
    let request_config = RequestConfig::default();

    let (attestation, secrets) = prover.finalize(&request_config).await?;

    // tracing::info!("Notarization complete!");

    // Write the attestation to disk.
    let attestation_path = "example-attestation.tlsn";
    let secrets_path = "example-secrets.tlsn";

    tokio::fs::write(&attestation_path, bincode::serialize(&attestation)?).await?;

    // Write the secrets to disk.
    tokio::fs::write(&secrets_path, bincode::serialize(&secrets)?).await?;

    // tracing::info!("Notarization completed successfully!");
    // tracing::info!(
    //     "The attestation has been written to `{attestation_path}` and the \
    //     corresponding secrets to `{secrets_path}`."
    // );

    Ok(())
}
