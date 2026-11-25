//! MoQ stream subscriber.

use anyhow::{Context, Result};
use moq_native_ietf::{quic, tls};
use moq_transport::{serve, session::Subscriber};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncWrite;
use tracing::{Level, event};
use url::Url;

/// Connects to a MoQ publisher over raw QUIC, subscribes to its announced stream,
/// and writes the received fragmented MP4 bytes into `output`.
///
/// The future runs until the stream or session ends. Callers that want interactive
/// cancellation (such as Ctrl+C in a CLI or a stop button in a GUI) should cancel
/// or `tokio::select!` this future.
///
/// # Examples
/// ```no_run
/// # async fn run(ticket: &str) -> anyhow::Result<()> {
/// let addr = halo::parse_ticket(ticket)?;
/// halo::subscribe(addr, tokio::io::stdout()).await
/// # }
/// ```
pub async fn subscribe<W>(addr: SocketAddr, output: W) -> Result<()>
where
    W: AsyncWrite + Send + Unpin + 'static,
{
    // Disable TLS verification so throwaway self-signed publisher certs are accepted.
    let tls = tls::Args {
        disable_verify: true,
        ..Default::default()
    }
    .load()?;

    let bind: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let quic_config = quic::Config::new(bind, None, tls).context("QUIC config creation failed")?;
    let endpoint = quic::Endpoint::new(quic_config).context("QUIC endpoint creation failed")?;

    // moqt:// is for raw QUIC, https:// would be for WebTransport
    let url = Url::parse(&format!("moqt://{addr}"))?;
    event!(Level::INFO, "connecting to {url}");

    let (session, cid, transport) = endpoint
        .client
        .connect(&url, None)
        .await
        .context("failed to connect")?;
    event!(Level::INFO, "connected, cid={cid}");

    let (session, subscriber) = Subscriber::connect(session, transport)
        .await
        .context("MoQ setup failed")?;

    let receive = async move {
        // The publisher announces its namespace right after setup. Wait for it, accept it,
        // and subscribe to that namespace.
        let mut announces = subscriber.clone();
        let mut announced =
            tokio::time::timeout(Duration::from_secs(10), announces.published_namespace())
                .await
                .context("timed out waiting for the publisher to announce a stream")?
                .context("connection closed before the publisher announced a stream")?;
        announced.ok().context("failed to accept the announce")?;

        let namespace = announced.info.namespace.clone();
        tracing::info!(%namespace, "publisher announced stream; receiving");

        let tracks = serve::Tracks::new(namespace);
        let mut media = moq_sub::media::Media::new(subscriber, tracks, output, false).await?;
        let res = media.run().await.context("media error");
        drop(announced); // held until here so the announce stays accepted
        res
    };

    tokio::select! {
        res = session.run() => res.context("session error"),
        res = receive => res,
    }
}
